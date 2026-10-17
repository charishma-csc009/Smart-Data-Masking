import os
import sqlite3
import bcrypt
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("MASKING_DB_PATH", "masking.db")

# Helper function to auto-determine role by email domain/pattern
def determine_role(email):
    email = email.lower().strip()
    if "admin" in email or email.endswith("@admin.financial.org"):
        return "Admin"
    elif "analyst" in email or email.endswith("@analytics.financial.org"):
        return "Analyst"
    else:
        return "Support"

def seed_accounts():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database {DB_PATH} does not exist. Run app.py first.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    default_password = "Password123!"
    hashed_pw = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Base list of 50 users across Admin, Support, and Analyst roles
    users_data = [
        # --- 10 ADMIN ACCOUNTS ---
        ("System Administrator", "admin@financial.org", "Admin"),
        ("Chief Security Officer", "cso@admin.financial.org", "Admin"),
        ("IT Lead Admin", "it.admin@financial.org", "Admin"),
        ("Charishma Challagolla", "charishmachallagolla2008@gmail.com", "Admin"),
        ("Compliance Manager", "compliance.admin@financial.org", "Admin"),
        ("Operations Head", "ops.admin@financial.org", "Admin"),
        ("Database Admin", "dba@financial.org", "Admin"),
        ("Security Auditor", "auditor.admin@financial.org", "Admin"),
        ("Infrastructure Admin", "infra.admin@financial.org", "Admin"),
        ("Executive Admin", "exec.admin@financial.org", "Admin"),

        # --- 20 SUPPORT STAFF ACCOUNTS ---
        ("Ravi Kumar", "ravi.support@financial.org", "Support"),
        ("Priya Sharma", "priya.support@financial.org", "Support"),
        ("Amit Patel", "patel.support@financial.org", "Support"),
        ("Sneha Reddy", "sneha.support@financial.org", "Support"),
        ("Vikram Singh", "vikram.support@financial.org", "Support"),
        ("Ananya Das", "ananya.support@financial.org", "Support"),
        ("Rohan Verma", "rohan.support@financial.org", "Support"),
        ("Kavya Joshi", "kavya.support@financial.org", "Support"),
        ("Siddharth Nair", "sid.support@financial.org", "Support"),
        ("Pooja Mehta", "pooja.support@financial.org", "Support"),
        ("Arjun Rao", "arjun.support@financial.org", "Support"),
        ("Neha Gupta", "neha.support@financial.org", "Support"),
        ("Manoj Tiwari", "tiwari.support@financial.org", "Support"),
        ("Divya Iyer", "divya.support@financial.org", "Support"),
        ("Karan Kapoor", "karan.support@financial.org", "Support"),
        ("Deepika Malhotra", "deepika.support@financial.org", "Support"),
        ("Suresh Sen", "suresh.support@financial.org", "Support"),
        ("Meera Bhat", "meera.support@financial.org", "Support"),
        ("Tarun Roy", "tarun.support@financial.org", "Support"),
        ("Swati Kulkarni", "swati.support@financial.org", "Support"),

        # --- 20 ANALYST ACCOUNTS ---
        ("Rajesh Khanna", "rajesh.analyst@financial.org", "Analyst"),
        ("Sunita Williams", "sunita.analyst@financial.org", "Analyst"),
        ("Aarav Sundaram", "aarav.analytics@financial.org", "Analyst"),
        ("Bhavna Saxena", "bhavna.analyst@financial.org", "Analyst"),
        ("Chetan Bhagat", "chetan.analyst@financial.org", "Analyst"),
        ("Dipti Jain", "dipti.analyst@financial.org", "Analyst"),
        ("Eshwar Chawla", "eshwar.analyst@financial.org", "Analyst"),
        ("Farhan Akhtar", "farhan.analyst@financial.org", "Analyst"),
        ("Gita Phogat", "gita.analyst@financial.org", "Analyst"),
        ("Harish Salve", "harish.analyst@financial.org", "Analyst"),
        ("Ishita Dutta", "ishita.analyst@financial.org", "Analyst"),
        ("Jatin Sarna", "jatin.analyst@financial.org", "Analyst"),
        ("Kirti Kulhari", "kirti.analyst@financial.org", "Analyst"),
        ("Lokesh Rahul", "lokesh.analyst@financial.org", "Analyst"),
        ("Monika Bedi", "monika.analyst@financial.org", "Analyst"),
        ("Nikhil D'Souza", "nikhil.analyst@financial.org", "Analyst"),
        ("Omkar Nath", "omkar.analyst@financial.org", "Analyst"),
        ("Payal Rajput", "payal.analyst@financial.org", "Analyst"),
        ("Qasim Khan", "qasim.analyst@financial.org", "Analyst"),
        ("Radhika Apte", "radhika.analyst@financial.org", "Analyst"),
    ]

    count = 0
    for name, email, role in users_data:
        cursor.execute("SELECT user_id FROM users WHERE email = ?", (email,))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO users (full_name, email, password_hash, role, account_status)
                VALUES (?, ?, ?, ?, 'ACTIVE')
            """, (name, email, hashed_pw, role))
            count += 1

    conn.commit()
    conn.close()
    print(f"[SUCCESS] Seeded {count} new accounts. Total accounts in system: 50+.")

if __name__ == "__main__":
    seed_accounts()