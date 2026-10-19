import sqlite3
import bcrypt
import os

DB_PATH = os.getenv("MASKING_DB_PATH", "masking.db")

def hash_pw(pw):
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Create Tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        account_status TEXT DEFAULT 'ACTIVE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        card_number TEXT NOT NULL,
        ssn TEXT NOT NULL,
        balance TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user_email TEXT,
        role TEXT,
        action TEXT,
        status TEXT
    )
    """)

    # Default password for all generated demo users
    default_pw_hash = hash_pw("SecurePass123!")

    # 2. Seed 50+ Diverse System Users
    users_data = [
        # Admins (5)
        ("admin@financial.org", default_pw_hash, "ADMIN", "ACTIVE"),
        ("security.admin@financial.org", default_pw_hash, "ADMIN", "ACTIVE"),
        ("devops.lead@financial.org", default_pw_hash, "ADMIN", "ACTIVE"),
        ("sys.governance@financial.org", default_pw_hash, "ADMIN", "ACTIVE"),
        ("backup.admin@financial.org", default_pw_hash, "ADMIN", "ACTIVE"),

        # Support Representatives (20)
        ("ravi.kumar@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("ananya.roy@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("vikram.singh@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("priya.sharma@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("amit.patel@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("sneh.gupta@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("karan.verma@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("meera.nair@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("rohit.joshi@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("pooja.reddy@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("siddharth.rao@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("divya.mishra@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("suresh.menon@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("neha.kulkarni@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("tarun.bhatia@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("aarti.saxena@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("varun.chopra@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("kavita.deshmukh@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("manish.pandey@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("simran.kaur@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),

        # Data Analysts & BI Team (20)
        ("rajesh.khanna@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("deepak.mehta@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("sunita.chawla@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("arjun.kapoor@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("shweta.tiwari@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("alok.banerjee@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("rishi.sen@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("monica.geller@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("nikhil.dutta@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("shruthi.hegde@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("pranav.shah@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("tanvi.agrawal@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("gaurav.tripathi@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("bhavna.rathore@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("harish.nambiar@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("pallavi.kashyap@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("yash.vanguard@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("nisha.pillai@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("chinmay.desai@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("ritika.choudhury@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),

        # Auditors & Inactive/Testing Accounts (8)
        ("compliance.audit@financial.org", default_pw_hash, "ADMIN", "ACTIVE"),
        ("external.reviewer@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("former.employee@financial.org", default_pw_hash, "SUPPORT", "INACTIVE"),
        ("test.analyst1@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("test.analyst2@financial.org", default_pw_hash, "ANALYST", "ACTIVE"),
        ("test.support1@financial.org", default_pw_hash, "SUPPORT", "ACTIVE"),
        ("suspended.user@financial.org", default_pw_hash, "ANALYST", "INACTIVE"),
        ("temp.contractor@financial.org", default_pw_hash, "SUPPORT", "ACTIVE")
    ]

    for email, pw_hash, role, status in users_data:
        cursor.execute(
            "INSERT OR IGNORE INTO users (email, password_hash, role, account_status) VALUES (?, ?, ?, ?)",
            (email, pw_hash, role, status)
        )

    # 3. Seed 50+ Sample Customer Financial Records
    customers_data = [
        ("Rahul Sharma", "rahul.s@gmail.com", "+91 98765 43210", "4111-2222-3333-1111", "123-45-6789", "₹2,50,000"),
        ("Priya Patel", "priya.p@yahoo.com", "+91 91234 56788", "5244-1111-8888-8821", "987-65-4321", "₹1,85,000"),
        ("Aarav Gupta", "aarav.g@outlook.com", "+91 99887 76655", "3782-0000-1111-4432", "456-78-1234", "₹5,10,000"),
        ("Sneha Kulkarni", "sneha.k@gmail.com", "+91 98112 23344", "4532-9988-7766-5544", "321-65-9870", "₹3,40,000"),
        ("Rohan Joshi", "rohan.j@hotmail.com", "+91 97223 34455", "5105-1234-5678-9012", "654-98-3210", "₹72,000"),
        ("Ananya Das", "ananya.d@gmail.com", "+91 96334 45566", "4000-1234-5678-9010", "789-12-3456", "₹4,15,000"),
        ("Karan Verma", "karan.v@yahoo.com", "+91 95445 56677", "5399-8877-6655-4433", "234-56-7890", "₹1,20,000"),
        ("Diya Reddy", "diya.r@gmail.com", "+91 94556 67788", "4111-9988-1122-3344", "876-54-3210", "₹8,90,000"),
        ("Aditya Nair", "aditya.n@outlook.com", "+91 93667 78899", "5200-4433-2211-0099", "345-67-8901", "₹95,000"),
        ("Isha Malhotra", "isha.m@gmail.com", "+91 92778 89900", "3714-5566-7788-9900", "901-23-4567", "₹6,30,000"),
        ("Vikram Singh", "vikram.s@yahoo.com", "+91 91889 90011", "4222-3333-4444-5555", "567-89-0123", "₹2,10,000"),
        ("Kavya Rao", "kavya.r@gmail.com", "+91 90990 01122", "5500-6677-8899-0011", "123-89-4567", "₹3,80,000"),
        ("Kabir Bhatia", "kabir.b@outlook.com", "+91 98001 12233", "4012-8899-7766-5544", "789-45-1230", "₹1,50,000"),
        ("Riya Saxena", "riya.s@gmail.com", "+91 97112 23344", "5412-3322-1100-9988", "456-12-7890", "₹4,75,000"),
        ("Siddharth Roy", "siddharth.r@yahoo.com", "+91 96223 34455", "3782-4455-6677-8899", "234-89-0123", "₹11,20,000"),
        ("Meera Iyer", "meera.i@gmail.com", "+91 95334 45566", "4311-5544-3322-1100", "890-12-3456", "₹85,000"),
        ("Arjun Kapoor", "arjun.k@hotmail.com", "+91 94445 56677", "5244-9988-0011-2233", "567-12-8901", "₹5,60,000"),
        ("Pooja Hegde", "pooja.h@gmail.com", "+91 93556 67788", "4000-8877-6655-4433", "123-67-4589", "₹2,95,000"),
        ("Varun Dhawan", "varun.d@yahoo.com", "+91 92667 78899", "5105-9988-7766-1122", "987-12-3456", "₹6,40,000"),
        ("Neha Sharma", "neha.s@gmail.com", "+91 91778 89900", "3714-0011-2233-4455", "345-89-0123", "₹1,10,000"),
        ("Gaurav Pandey", "gaurav.p@outlook.com", "+91 90889 90011", "4111-5566-7788-9900", "678-90-1234", "₹3,15,000"),
        ("Tanvi Shah", "tanvi.s@gmail.com", "+91 98990 01122", "5399-1122-3344-5566", "234-56-1234", "₹8,20,000"),
        ("Nikhil Sen", "nikhil.s@yahoo.com", "+91 97001 12233", "4222-8899-0011-2233", "890-56-7890", "₹1,65,000"),
        ("Shweta Mishra", "shweta.m@gmail.com", "+91 96112 23344", "5500-1122-4455-6677", "456-89-0123", "₹4,30,000"),
        ("Alok Verma", "alok.v@hotmail.com", "+91 95223 34455", "3782-9900-1122-3344", "123-45-8901", "₹2,05,000"),
        ("Kavita Pillai", "kavita.p@gmail.com", "+91 94334 45566", "4012-3344-5566-7788", "789-01-2345", "₹7,80,000"),
        ("Manish Choudhury", "manish.c@yahoo.com", "+91 93445 56677", "5412-8899-1100-2233", "345-12-6789", "₹92,000"),
        ("Ritika Seth", "ritika.s@gmail.com", "+91 92556 67788", "4311-0011-2233-4455", "901-56-7890", "₹5,40,000"),
        ("Harish Menon", "harish.m@outlook.com", "+91 91667 78899", "5105-3344-5566-7788", "567-89-4567", "₹3,25,000"),
        ("Pallavi Deshmukh", "pallavi.d@gmail.com", "+91 90778 89900", "4000-5566-7788-9900", "123-90-1234", "₹6,10,000"),
        ("Yash Rathore", "yash.r@yahoo.com", "+91 98889 90011", "5244-1122-3344-5566", "789-34-5678", "₹1,90,000"),
        ("Nisha Kashyap", "nisha.k@gmail.com", "+91 97990 01122", "3714-8899-0011-2233", "456-78-9012", "₹4,05,000"),
        ("Chinmay Bhat", "chinmay.b@hotmail.com", "+91 96001 12233", "4111-0022-3344-5566", "234-12-3456", "₹8,50,000"),
        ("Aarti Chawla", "aarti.c@gmail.com", "+91 95112 23344", "5399-4455-6677-8899", "890-34-5678", "₹1,40,000"),
        ("Tarun Agrawal", "tarun.a@yahoo.com", "+91 94223 34455", "4222-1122-3344-5566", "345-67-1234", "₹3,70,000"),
        ("Simran Saxena", "simran.s@gmail.com", "+91 93334 45566", "5500-8899-0011-2233", "901-23-8901", "₹6,90,000"),
        ("Pranav Tripathi", "pranav.t@outlook.com", "+91 92445 56677", "3782-1122-3344-5566", "567-89-1234", "₹2,30,000"),
        ("Bhavna Kulkarni", "bhavna.k@gmail.com", "+91 91556 67788", "4012-5566-7788-9900", "123-45-6780", "₹5,80,000"),
        ("Gaurav Nambiar", "gaurav.n@yahoo.com", "+91 90667 78899", "5412-0011-2233-4455", "789-01-4567", "₹1,15,000"),
        ("Shruthi Banerjee", "shruthi.b@gmail.com", "+91 98778 89900", "4311-8899-0011-2233", "345-89-2345", "₹4,60,000"),
        ("Rishi Hegde", "rishi.h@hotmail.com", "+91 97889 90011", "5105-1122-3344-5566", "901-45-6789", "₹7,30,000"),
        ("Monica Shah", "monica.s@gmail.com", "+91 96990 01122", "4000-2233-4455-6677", "567-12-3456", "₹2,80,000"),
        ("Suresh Pillai", "suresh.p@yahoo.com", "+91 95001 12233", "5244-8899-0011-2233", "123-78-9012", "₹3,95,000"),
        ("Divya Reddy", "divya.reddy@gmail.com", "+91 94112 23344", "3714-3344-5566-7788", "789-23-4567", "₹9,10,000"),
        ("Siddharth Rao", "siddharth.rao@gmail.com", "+91 93223 34455", "4111-8899-0011-2233", "456-90-1234", "₹1,75,000"),
        ("Pooja Joshi", "pooja.j@outlook.com", "+91 92334 45566", "5399-0011-2233-4455", "234-56-8901", "₹6,50,000"),
        ("Rohit Verma", "rohit.v@gmail.com", "+91 91445 56677", "4222-5566-7788-9900", "890-12-4567", "₹2,20,000"),
        ("Meera Sharma", "meera.s@yahoo.com", "+91 90556 67788", "5500-3344-5566-7788", "345-67-8902", "₹4,40,000"),
        ("Amit Saxena", "amit.s@gmail.com", "+91 98667 78899", "3782-8899-0011-2233", "901-23-5678", "₹8,00,000"),
        ("Sneh Patel", "sneh.p@hotmail.com", "+91 97778 89900", "4012-0011-2233-4455", "567-89-2345", "₹1,30,000"),
        ("Karan Malhotra", "karan.m@gmail.com", "+91 96889 90011", "5412-5566-7788-9900", "123-45-9012", "₹5,20,000"),
        ("Ananya Nair", "ananya.n@yahoo.com", "+91 95990 01122", "4311-2233-4455-6677", "789-01-6789", "₹3,60,000")
    ]

    for name, email, phone, card, ssn, bal in customers_data:
        cursor.execute(
            "INSERT OR IGNORE INTO customers (full_name, email, phone, card_number, ssn, balance) VALUES (?, ?, ?, ?, ?, ?)",
            (name, email, phone, card, ssn, bal)
        )

    conn.commit()
    conn.close()
    print("Successfully initialized masking.db with 53 Users and 52 Customer Records!")

if __name__ == "__main__":
    init_db()
