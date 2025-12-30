from typing import Annotated
from utils.schema import  User
from fastapi import Depends,APIRouter
from utils.db_helper import connect_to_db

from .auth import get_current_active_user

router = APIRouter()


# Endpoint to get items belonging to current authenticated user
# Returns a list containing a sample item with the user's username
@router.get("/users/me/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    conn = connect_to_db()
    cursor = conn.cursor()

    query = "SELECT * FROM users;"
    cursor.execute(query)
    users = cursor.fetchall()

    cursor.close()
    conn.close()
    
    return {"users": users}




@router.get("/users/me/public")
async def read_own_items():
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)

    query = "SELECT * FROM users;"
    cursor.execute(query)
    users = cursor.fetchall()

    cursor.close()
    conn.close()
    
    return {"users": users}


@router.get("/users/auth")
async def read_own_items(
    current_user_data: Annotated[dict, Depends(get_current_active_user)]
):
    user = current_user_data["user"]
    auth_method = current_user_data["auth_method"]

    return {
        "message": f"Authenticated via {auth_method}",
        "user": user
    }
