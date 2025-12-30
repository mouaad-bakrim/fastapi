from datetime import timedelta
from typing import Annotated
from fastapi import Depends, Request, APIRouter
from authlib.integrations.starlette_client import OAuth
from utils.config import Settings
from utils.db_helper import connect_to_db, get_db_cursor
from .auth import create_access_token
from functools import lru_cache
import os

router = APIRouter()

@lru_cache
def get_settings():
    return Settings()

oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)

@router.get("/auth/google")
async def auth_google(request: Request):
    # استخدام الرابط المعرف في .env
    return await oauth.google.authorize_redirect(request, os.getenv('GOOGLE_REDIRECT_URI'))

@router.get("/auth/google/callback")
async def google_callback(request: Request, settings: Annotated[Settings, Depends(get_settings)]):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo") or {}
        email = user_info.get("email")
        full_name = user_info.get("name")

        # حفظ أو تحديث المستخدم في PostgreSQL
        conn = connect_to_db()
        cursor = get_db_cursor(conn)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            cursor.execute(
                "INSERT INTO users (username, email, full_name) VALUES (%s, %s, %s)",
                (email, email, full_name)
            )
            conn.commit()
        
        cursor.close()
        conn.close()

        # إنشاء JWT توكن
        access_token = create_access_token(
            settings, 
            data={"sub": email}, 
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            auth_method="google"
        )

        return {"access_token": access_token, "token_type": "bearer", "user": user_info}
    except Exception as e:
        return {"error": str(e)}