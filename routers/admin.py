# routers/admin.py
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Optional, Annotated

from fastapi import APIRouter, Depends, HTTPException

from utils.config import Settings
from utils.db_helper import connect_to_db, get_db_cursor
from utils.magic_link import create_magic_token, send_magic_link
from utils.emailer import send_email

# ✅ مهم: استورد get_current_user من auth
from routers.auth import get_current_user

router = APIRouter(prefix="/admin", tags=["Admin"])


@lru_cache
def get_settings():
    return Settings()


def require_admin(current_user=Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return current_user


@router.get("/users")
def list_users(
    status: Optional[str] = None,
    admin=Depends(require_admin)
):
    conn = connect_to_db()
    cur = get_db_cursor(conn)
    try:
        if status:
            cur.execute(
                """
                SELECT id, email, full_name, status, role, approved_at, created_at
                FROM users
                WHERE status=%s
                ORDER BY id DESC
                """,
                (status,),
            )
        else:
            cur.execute(
                """
                SELECT id, email, full_name, status, role, approved_at, created_at
                FROM users
                ORDER BY id DESC
                """
            )
        return {"users": cur.fetchall()}
    finally:
        cur.close()
        conn.close()


@router.post("/users/{user_id}/approve")
def approve_user(
    user_id: int,
    admin=Depends(require_admin),
    settings: Annotated[Settings, Depends(get_settings)] = None,
):
    conn = connect_to_db()
    cur = get_db_cursor(conn)
    try:
        cur.execute("SELECT id, email, status FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # update status
        cur.execute(
            "UPDATE users SET status='ACTIVE', approved_at=NOW() WHERE id=%s",
            (user_id,),
        )
        conn.commit()

        # create magic link token (valid 15 min)
        raw_token, token_hash = create_magic_token()
        expires_at = datetime.utcnow() + timedelta(minutes=15)

        cur.execute(
            "INSERT INTO login_links (email, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user["email"], token_hash, expires_at),
        )
        conn.commit()

        # send email with magic link
        send_magic_link(settings, user["email"], raw_token)

        return {"message": "User approved + email sent"}
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


@router.post("/users/{user_id}/reject")
def reject_user(
    user_id: int,
    admin=Depends(require_admin),
    settings: Annotated[Settings, Depends(get_settings)] = None,
):
    conn = connect_to_db()
    cur = get_db_cursor(conn)
    try:
        cur.execute("SELECT id, email FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        cur.execute("UPDATE users SET status='REJECTED' WHERE id=%s", (user_id,))
        conn.commit()

        # optional reject email
        body = (
            "Bonjour,\n\n"
            "Votre demande d’accès a été refusée.\n"
            "Si vous pensez qu'il s'agit d'une erreur, contactez l’administrateur.\n\n"
            "— MyApp"
        )
        send_email(settings, user["email"], "Décision sur votre demande", body)

        return {"message": "User rejected"}
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
