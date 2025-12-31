import jwt
import smtplib
from typing import Annotated, Optional
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import lru_cache

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from jwt.exceptions import InvalidTokenError

from utils.schema import Token
from utils.config import Settings
from utils.db_helper import connect_to_db

router = APIRouter(prefix="/auth", tags=["Auth"])

# --- Configuration ---

@lru_cache
def get_settings():
    return Settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# --- Schemas ---

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str

# --- Utils ---

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_user(email: str):
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s;", (email,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(settings: Settings, data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def send_reset_email(email_to: str, settings: Settings):
    msg = EmailMessage()
    reset_link = f"http://localhost:3000/reset-password?email={email_to}"

    msg.set_content(
        f"Bonjour,\n\nCliquez sur ce lien pour modifier votre mot de passe :\n{reset_link}\n\n"
        f"Si vous n'avez pas demandé cela, ignorez cet e-mail."
    )
    msg["Subject"] = "Réinitialisation de votre mot de passe"
    msg["From"] = settings.GOOGLE_EMAIL
    msg["To"] = email_to

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(settings.GOOGLE_EMAIL, settings.GOOGLE_APP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Erreur SMTP : {e}")
        return False

# --- Dependencies ---

async def get_current_user(
    settings: Annotated[Settings, Depends(get_settings)],
    token: Annotated[str, Depends(oauth2_scheme)]
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str | None = payload.get("sub")
        if not email:
            raise credentials_exception
        user = get_user(email)
        if not user:
            raise credentials_exception
        return user
    except InvalidTokenError:
        raise credentials_exception

# --- Routes ---

@router.post("/token", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        settings, data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    settings: Annotated[Settings, Depends(get_settings)]
):
    # ✅ Bonne pratique: ne pas révéler si l'email existe
    user = get_user(payload.email)

    if user:
        send_reset_email(payload.email, settings)

    return {"message": "Si votre e-mail existe, une notification a été envoyée !"}

@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    hashed_pwd = get_password_hash(payload.new_password)

    conn = connect_to_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET hashed_password = %s WHERE email = %s",
            (hashed_pwd, payload.email),
        )
        conn.commit()

        # même logique: pas de leak d'existence
        return {"message": "Si votre compte existe, le mot de passe a été mis à jour."}
    except Exception:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Erreur lors de la mise à jour en base de données")
    finally:
        cursor.close()
        conn.close()


from pydantic import BaseModel
from datetime import datetime, timedelta
from utils.magic_link import hash_token

class ConsumeMagicLink(BaseModel):
    token: str

@router.post("/magic/consume", response_model=Token)
def consume_magic_link(
    payload: ConsumeMagicLink,
    settings: Annotated[Settings, Depends(get_settings)]
):
    token_hash = hash_token(payload.token)

    conn = connect_to_db()
    cursor = conn.cursor()  # ولا get_db_cursor إذا بغيتي dict
    try:
        cursor.execute(
            """
            SELECT id, email, expires_at, used_at
            FROM login_links
            WHERE token_hash=%s
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid link")

        link_id, email, expires_at, used_at = row

        if used_at is not None:
            raise HTTPException(status_code=400, detail="Link already used")

        # expires_at جاية كـ datetime من postgres
        if expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Link expired")

        # mark used
        cursor.execute("UPDATE login_links SET used_at=NOW() WHERE id=%s", (link_id,))
        conn.commit()

        # create JWT
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            settings, data={"sub": email}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
