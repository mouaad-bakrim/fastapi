# routers/users.py

from fastapi import APIRouter, Depends
from routers.auth import get_current_user
from utils.db_helper import connect_to_db, get_db_cursor

router = APIRouter(tags=["Users"])


# =========================================================
# ✅ USER CONNECTÉ (me)
# =========================================================
@router.get("/users/me/")
async def read_me(current_user=Depends(get_current_user)):
    """
    Return ONLY the authenticated user from JWT
    """
    return {"user": current_user}


# =========================================================
# ✅ LIST USERS (PUBLIC - POUR TEST SEULEMENT)
# ⚠️ À supprimer ou protéger en prod
# =========================================================
@router.get("/users/public")
def list_users_public():
    conn = connect_to_db()
    cur = get_db_cursor(conn)
    try:
        cur.execute(
            """
            SELECT id, email, full_name, status, role
            FROM users
            ORDER BY id DESC
            """
        )
        return {"users": cur.fetchall()}
    finally:
        cur.close()
        conn.close()
