# utils/magic_link.py
import secrets
import hashlib
from utils.emailer import send_email

def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def create_magic_token():
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)

def send_magic_link(settings, email: str, raw_token: str):
    link = f"{settings.FRONTEND_URL}/magic?token={raw_token}"

    body = (
        "🎉 Félicitations !\n\n"
        "Votre connexion à l’application a été validée avec succès.\n\n"
        "👉 Cliquez sur le lien ci-dessous pour accéder à l’application :\n"
        f"{link}\n\n"
        "⏱️ Ce lien est valable pendant 15 minutes.\n\n"
        "Si vous n’êtes pas à l’origine de cette demande, vous pouvez ignorer cet email.\n\n"
        "— L’équipe MyApp 🚀"
    )

    return send_email(
        settings=settings,
        to_email=email,
        subject="🎉 Connexion réussie à MyApp",
        body=body,
    )
