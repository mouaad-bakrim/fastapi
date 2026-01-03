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
from utils.db_helper import connect_to_db, get_db_cursor
from utils.magic_link import hash_token

router = APIRouter(prefix="/auth", tags=["Auth"])


# -------------------------
# Settings
# -------------------------
@lru_cache
def get_settings():
    return Settings()


# ✅ أنت خدام بـ argon2، إذن ماكاناش limit 72 bytes ديال bcrypt
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


# -------------------------
# Schemas
# -------------------------
class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str


class ConsumeMagicLink(BaseModel):
    token: str


# -------------------------
# Utils
# -------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    try:
        return pwd_context.hash(password)
    except Exception:
        raise HTTPException(status_code=400, detail="Mot de passe invalide")


def get_user(email: str):
    conn = connect_to_db()
    cur = get_db_cursor(conn)  # ✅ Postgres dict rows
    try:
        cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
        return cur.fetchone()
    finally:
        cur.close()
        conn.close()


def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not user.get("hashed_password"):
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
    reset_link = f"{settings.FRONTEND_URL}/reset-password?email={email_to}"

    msg.set_content(
        "Bonjour,\n\n"
        "Cliquez sur ce lien pour modifier votre mot de passe :\n"
        f"{reset_link}\n\n"
        "Si vous n'avez pas demandé cela, ignorez cet e-mail."
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


# -------------------------
# Dependency: current user
# -------------------------
async def get_current_user(
    settings: Annotated[Settings, Depends(get_settings)],
    token: Annotated[str, Depends(oauth2_scheme)],
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


# -------------------------
# Routes
# -------------------------
@router.post("/token", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ✅ منع login إذا الحساب pending (اختياري ولكن مفيد)
    if user.get("status") == "PENDING":
        raise HTTPException(status_code=403, detail="Compte en attente de validation")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        settings,
        data={"sub": user["email"]},
        expires_delta=access_token_expires,
    )

    # ✅ نرجعو role/status باش front يقرر مباشرة admin/user
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.get("role"),
        "status": user.get("status"),
    }


@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    settings: Annotated[Settings, Depends(get_settings)],
):
    user = get_user(payload.email)
    if user:
        send_reset_email(payload.email, settings)
    return {"message": "Si votre e-mail existe, une notification a été envoyée !"}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    hashed_pwd = get_password_hash(payload.new_password)

    conn = connect_to_db()
    cur = get_db_cursor(conn)
    try:
        cur.execute(
            "UPDATE users SET hashed_password = %s WHERE email = %s",
            (hashed_pwd, payload.email),
        )
        conn.commit()
        return {"message": "Si votre compte existe, le mot de passe a été mis à jour."}
    except Exception:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Erreur lors de la mise à jour en base de données")
    finally:
        cur.close()
        conn.close()


@router.post("/magic/consume", response_model=Token)
def consume_magic_link(
    payload: ConsumeMagicLink,
    settings: Annotated[Settings, Depends(get_settings)],
):
    token_h = hash_token(payload.token)

    conn = connect_to_db()
    cur = get_db_cursor(conn)
    try:
        cur.execute(
            """
            SELECT id, email, expires_at, used_at
            FROM login_links
            WHERE token_hash=%s
            """,
            (token_h,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid link")

        if row["used_at"] is not None:
            raise HTTPException(status_code=400, detail="Link already used")

        # ✅ expires_at من Postgres غالباً naive UTC -> نقارن بـ utcnow() naive
        if row["expires_at"] < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Link expired")

        cur.execute("UPDATE login_links SET used_at=NOW() WHERE id=%s", (row["id"],))
        conn.commit()

        email = row["email"]
        user = get_user(email)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        # ✅ إذا مازال pending ما نخليهوش يدخل
        if user.get("status") == "PENDING":
            raise HTTPException(status_code=403, detail="Compte en attente de validation")

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            settings,
            data={"sub": email},
            expires_delta=access_token_expires,
        )

        return {"access_token": access_token, "token_type": "bearer"}
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
