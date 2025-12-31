# manage.py
from utils.db_helper import connect_to_db
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
SQL = """
-- 1) Create base users table if missing
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  full_name VARCHAR(255),
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- 2) Add missing columns safely (works even if table already exists)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
  ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP NULL,
  ADD COLUMN IF NOT EXISTS google_id VARCHAR(255),
  ADD COLUMN IF NOT EXISTS hashed_password TEXT,
  ADD COLUMN IF NOT EXISTS role VARCHAR(30) NOT NULL DEFAULT 'user',
  ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN NOT NULL DEFAULT FALSE;

-- 3) login_links
CREATE TABLE IF NOT EXISTS login_links (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_links_token_hash
ON login_links(token_hash);
"""


def get_password_hash(password: str) -> str:
    # bcrypt limit safety
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password too long for bcrypt (max 72 bytes).")
    return pwd_context.hash(password)

def migrate():
    conn = connect_to_db()
    cur = conn.cursor()
    try:
        cur.execute(SQL)
        conn.commit()
        print("✅ Migration OK (tables created)")
    except Exception as e:
        conn.rollback()
        print("❌ Migration failed:", e)
        raise
    finally:
        cur.close()
        conn.close()

def create_superadmin():
    email = "admin@gmail.com"
    password = "Admin123!"  # ✅ قصير وآمن للتست (بدّلو لاحقاً)

    conn = connect_to_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            # تأكد الدور/status ديالو
            cur.execute(
                """
                UPDATE users
                SET role='superadmin', is_superadmin=TRUE, status='ACTIVE'
                WHERE email=%s
                """,
                (email,),
            )
            conn.commit()
            print("ℹ️ Super admin already exists (updated role/status)")
            return

        hashed = get_password_hash(password)
        cur.execute(
            """
            INSERT INTO users (username, email, full_name, hashed_password, role, is_superadmin, status)
            VALUES (%s, %s, %s, %s, 'superadmin', TRUE, 'ACTIVE')
            """,
            (email, email, "Super Admin", hashed),
        )
        conn.commit()
        print("✅ Super admin created:", email)
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    migrate()
    create_superadmin()
