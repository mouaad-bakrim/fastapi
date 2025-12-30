import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

load_dotenv()

def connect_to_db():
    try:
        # الاتصال باستخدام رابط DATABASE_URL
        conn = psycopg2.connect(os.environ['DATABASE_URL'])
        return conn
    except Exception as e:
        print(f"PostgreSQL Connection Error: {e}")
        return None

def get_db_cursor(conn):
    # إرجاع النتائج على شكل قاموس (Dictionary)
    return conn.cursor(cursor_factory=RealDictCursor)