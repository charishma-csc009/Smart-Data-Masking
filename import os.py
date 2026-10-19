import os
import sqlite3
import bcrypt
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("MASKING_DB_PATH", "masking.db")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@financial.org")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "AdminSecurePass123!")

def init_admin():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database {DB_PATH} does not exist. Run app.py first to initialize database schema.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM users WHERE email = ?", (ADMIN_EMAIL,))
    existing = cursor.fetchone()

    hashed_password = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    if existing:
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, role = 'Admin', account_status = 'ACTIVE', updated_at = CURRENT_TIMESTAMP
            WHERE email = ?
        """, (hashed_password, ADMIN_EMAIL))
        print(f"[SUCCESS] Existing Admin account updated for {ADMIN_EMAIL}.")
    else:
        cursor.execute("""
            INSERT INTO users (full_name, email, password_hash, role, account_status)
            VALUES (?, ?, ?, 'Admin', 'ACTIVE')
        """, ("System Administrator", ADMIN_EMAIL, hashed_password))
        print(f"[SUCCESS] Created initial Admin account for {ADMIN_EMAIL}.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_admin()
