# utils/db_helper.py
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

def connect_to_db():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is missing in environment/.env")

    try:
        conn = psycopg2.connect(db_url)
        return conn
    except Exception as e:
        # خليه يطلع فـ logs
        raise RuntimeError(f"PostgreSQL Connection Error: {e}")

def get_db_cursor(conn):
    return conn.cursor(cursor_factory=RealDictCursor)
