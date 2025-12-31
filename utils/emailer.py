import smtplib
from email.message import EmailMessage
from utils.config import Settings

def send_email(
    settings: Settings,
    to_email: str,
    subject: str,
    body: str,
):
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print("SMTP ERROR:", e)
        return False
