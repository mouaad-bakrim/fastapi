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

from fastapi import HTTPException
from datetime import datetime, timedelta
import secrets
from utils.magic_link import create_magic_token, send_magic_link
@router.get("/auth/google/callback")
async def google_callback(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)]
):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get("userinfo") or {}

    email = user_info.get("email")
    full_name = user_info.get("name")

    if not email:
        raise HTTPException(status_code=400, detail="Google email not found")

    conn = connect_to_db()
    cursor = get_db_cursor(conn)
    try:
        cursor.execute(
            """
            INSERT INTO users (username, email, full_name)
            VALUES (%s, %s, %s)
            ON CONFLICT (email) DO UPDATE SET full_name=EXCLUDED.full_name
            """,
            (email, email, full_name),
        )
        conn.commit()

        # ✅ هنا الحل
        raw_token, token_hash = create_magic_token()
        expires_at = datetime.utcnow() + timedelta(minutes=15)

        cursor.execute(
            "INSERT INTO login_links (email, token_hash, expires_at) VALUES (%s, %s, %s)",
            (email, token_hash, expires_at),
        )
        conn.commit()

        send_magic_link(settings, email, raw_token)

        return {"message": "✅ Magic link envoyé par email."}
    finally:
        cursor.close()
        conn.close()