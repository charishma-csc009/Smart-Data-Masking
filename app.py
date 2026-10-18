import os
import re
import sqlite3
import hashlib
import functools
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder="../frontend/build", static_url_path="")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-random-key-change-in-production")

# Configure Session Security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ['true', '1']
)

CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

DB_PATH = os.getenv("MASKING_DB_PATH", "masking.db")

# Failed login attempt tracking for rate limiting (ip -> {"count": int, "lockout_until": datetime})
failed_login_attempts = {}

# --- DATABASE SETUP & INITIALIZATION ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('Admin', 'Support', 'Analyst')) NOT NULL,
            account_status TEXT CHECK(account_status IN ('ACTIVE', 'INACTIVE')) DEFAULT 'ACTIVE',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    """)

    # 2. Audit Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            user_email TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Sample Customer Data Table (Original Raw Un-altered Storage)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            card_number TEXT NOT NULL,
            ssn TEXT NOT NULL,
            account_balance REAL NOT NULL,
            credit_score INTEGER NOT NULL
        )
    """)

    # Populate Sample Data if empty
    cursor.execute("SELECT COUNT(*) FROM customers")
    if cursor.fetchone()[0] == 0:
        sample_customers = [
            ("Ravi Kumar", "ravi.kumar@example.com", "+91 98765 43210", "4111222233331111", "987-65-4321", 54000.50, 750),
            ("Priya Sharma", "priya.sharma@domain.io", "+91 87654 32109", "5500111122223333", "654-32-1098", 128500.00, 810),
            ("Amit Patel", "apatel@corporate.org", "+91 76543 21098", "378282246310005", "456-78-9012", 3200.75, 680),
            ("Sneha Reddy", "sneha.reddy@tech.com", "+91 65432 10987", "6011000990139424", "123-45-6789", 89400.20, 790),
            ("Vikram Singh", "vsingh@finance.net", "+91 91234 56789", "4012888899992222", "321-65-9870", 215000.00, 840),
            ("Ananya Das", "ananya.das@example.com", "+91 98111 22233", "4012888899993333", "999-88-7777", 67000.00, 780),
            ("Rohan Verma", "rohan.verma@example.com", "+91 98222 33344", "5105105105105105", "888-77-6666", 45000.00, 720),
            ("Kavya Joshi", "kavya.j@example.com", "+91 98333 44455", "371234567890123", "777-66-5555", 112000.00, 830),
            ("Siddharth Nair", "sid.nair@example.com", "+91 98444 55566", "6011222233334444", "666-55-4444", 31000.00, 690),
            ("Pooja Mehta", "pooja.m@example.com", "+91 98555 66677", "4111555566667777", "555-44-3333", 95000.00, 800),
            ("Arjun Rao", "arjun.rao@example.com", "+91 98666 77788", "4111666677778888", "444-33-2222", 52000.00, 740),
            ("Neha Gupta", "neha.gupta@example.com", "+91 98777 88899", "5200111122224444", "333-22-1111", 143000.00, 820),
            ("Manoj Tiwari", "manoj.t@example.com", "+91 98888 99900", "378200001111222", "222-11-0000", 18500.25, 650),
            ("Divya Iyer", "divya.iyer@example.com", "+91 98999 00011", "6011333344445555", "111-00-9999", 76000.00, 795),
            ("Karan Kapoor", "karan.k@example.com", "+91 97000 11122", "4012777788889999", "000-99-8888", 230000.00, 850),
            ("Deepika Malhotra", "deepika.m@example.com", "+91 97111 22233", "4111888899990000", "998-87-7665", 81000.00, 770),
            ("Suresh Sen", "suresh.sen@example.com", "+91 97222 33344", "5300222233334444", "887-76-6554", 39000.00, 710),
            ("Meera Bhat", "meera.b@example.com", "+91 97333 44455", "371299998888777", "776-65-5443", 105000.00, 815),
            ("Tarun Roy", "tarun.roy@example.com", "+91 97444 55566", "6011444455556666", "665-54-4332", 28000.00, 675),
            ("Swati Kulkarni", "swati.k@example.com", "+91 97555 66677", "4111999900001111", "554-43-3221", 88000.00, 785),
            ("Rajesh Khanna", "rajesh.k@example.com", "+91 97666 77788", "4111000011112222", "443-32-2110", 62000.00, 760),
            ("Sunita Williams", "sunita.w@example.com", "+91 97777 88899", "5400333344445555", "332-21-1009", 155000.00, 835),
            ("Aarav Sundaram", "aarav.s@example.com", "+91 97888 99900", "378233334444555", "221-10-0998", 41000.00, 730),
            ("Bhavna Saxena", "bhavna.s@example.com", "+91 97999 00011", "6011555566667777", "110-09-9887", 92000.00, 805),
            ("Chetan Bhagat", "chetan.b@example.com", "+91 96000 11122", "4012666677778888", "009-98-8776", 210000.00, 845),
            ("Dipti Jain", "dipti.j@example.com", "+91 96111 22233", "4111111122223333", "987-12-3456", 73000.00, 775),
            ("Eshwar Chawla", "eshwar.c@example.com", "+91 96222 33344", "5500444455556666", "876-23-4567", 34000.00, 700),
            ("Farhan Akhtar", "farhan.a@example.com", "+91 96333 44455", "371255556666777", "765-34-5678", 118000.00, 825),
            ("Gita Phogat", "gita.p@example.com", "+91 96444 55566", "6011666677778888", "654-45-6789", 49000.00, 735),
            ("Harish Salve", "harish.s@example.com", "+91 96555 66677", "4111222244446666", "543-56-7890", 99000.00, 810),
            ("Ishita Dutta", "ishita.d@example.com", "+91 96666 77788", "4111333355557777", "432-67-8901", 58000.00, 755),
            ("Jatin Sarna", "jatin.s@example.com", "+91 96777 88899", "5105222233334444", "321-78-9012", 137000.00, 828),
            ("Kirti Kulhari", "kirti.k@example.com", "+91 96888 99900", "378266667777888", "210-89-0123", 26000.00, 665),
            ("Lokesh Rahul", "lokesh.r@example.com", "+91 96999 00011", "6011777788889999", "109-90-1234", 84000.00, 790),
            ("Monika Bedi", "monika.b@example.com", "+91 95000 11122", "4012555566667777", "098-01-2345", 245000.00, 855),
            ("Nikhil D'Souza", "nikhil.d@example.com", "+91 95111 22233", "4111444466668888", "987-90-1234", 69000.00, 765),
            ("Omkar Nath", "omkar.n@example.com", "+91 95222 33344", "5200555566667777", "876-89-0123", 38000.00, 705),
            ("Payal Rajput", "payal.r@example.com", "+91 95333 44455", "371277778888999", "765-78-9012", 110000.00, 818),
            ("Qasim Khan", "qasim.k@example.com", "+91 95444 55566", "6011888899990000", "654-67-8901", 30000.00, 685),
            ("Radhika Apte", "radhika.a@example.com", "+91 95555 66677", "4111555577779999", "543-56-7890", 91000.00, 802),
            ("Sachin Tendulkar", "sachin.t@example.com", "+91 95666 77788", "4111666688880000", "432-45-6789", 175000.00, 840),
            ("Tanvi Azmi", "tanvi.a@example.com", "+91 95777 88899", "5300666677778888", "321-34-5678", 51000.00, 745),
            ("Uday Chopra", "uday.c@example.com", "+91 95888 99900", "378288889999000", "210-23-4567", 22000.00, 660),
            ("Varun Dhawan", "varun.d@example.com", "+91 95999 00011", "6011999900001111", "109-12-3456", 86000.00, 788),
            ("Yami Gautam", "yami.g@example.com", "+91 94000 11122", "4012444455556666", "098-01-9876", 198000.00, 848),
            ("Zoya Akhtar", "zoya.a@example.com", "+91 94111 22233", "4111777799991111", "987-10-9876", 74000.00, 778),
            ("Abhinav Bindra", "abhinav.b@example.com", "+91 94222 33344", "5400777788889999", "876-09-8765", 42000.00, 715),
            ("Bipasha Basu", "bipasha.b@example.com", "+91 94333 44455", "371200001111222", "765-98-7654", 125000.00, 822),
            ("Chitrangada Singh", "chitrangada.s@example.com", "+91 94444 55566", "6011000011112222", "654-87-6543", 33000.00, 695),
            ("Dharmendra Singh", "dharmendra.s@example.com", "+91 94555 66677", "4111888800002222", "543-76-5432", 97000.00, 808)
        ]
        cursor.executemany("""
            INSERT INTO customers (full_name, email, phone_number, card_number, ssn, account_balance, credit_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, sample_customers)

    conn.commit()
    conn.close()

init_db()

# --- HELPER FUNCTIONS & MIDDLEWARE ---
def log_audit(action, details="", user_id=None, user_email=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (user_id, user_email, action, details, ip_address)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id or session.get("user_id"),
            user_email or session.get("email"),
            action,
            details,
            request.remote_addr
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log audit event: {e}")

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*allowed_roles):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "Authentication required"}), 401
            user_role = session.get("role")
            if user_role not in allowed_roles:
                log_audit("UNAUTHORIZED_ACCESS_ATTEMPT", f"User tried accessing {request.path}")
                return jsonify({"error": "Forbidden: Insufficient privileges"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- DYNAMIC MASKING LOGIC ---
def mask_card_number(card, role):
    if role == "Admin":
        return card
    elif role == "Support":
        if len(card) >= 15:
            return f"{card[:4]}-XXXX-XXXX-{card[-4:]}"
        return "XXXX-XXXX-XXXX-" + card[-4:] if len(card) >= 4 else "XXXX"
    elif role == "Analyst":
        return "X" * len(card)
    return "X" * len(card)

def mask_email(email, role):
    if role == "Admin":
        return email
    elif role == "Support":
        parts = email.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + "***" if len(name) > 0 else "***"
            return f"{masked_name}@{domain}"
        return "***@***.com"
    elif role == "Analyst":
        return hashlib.sha256((email + "ANALYST_SALT").encode()).hexdigest()[:16] + "@pseudo.anon"
    return "***@***.com"

def mask_phone(phone, role):
    if role == "Admin":
        return phone
    elif role == "Support":
        return phone[:4] + " XXX-XX" + phone[-2:] if len(phone) >= 8 else "XXX-XXX-XXXX"
    elif role == "Analyst":
        return "[PSEUDONYMIZED]"
    return "[REDACTED]"

def mask_ssn(ssn, role):
    if role == "Admin":
        return ssn
    elif role == "Support":
        return "XXX-XX-" + ssn[-4:] if len(ssn) >= 4 else "XXX-XX-XXXX"
    elif role == "Analyst":
        return "[REDACTED]"
    return "[REDACTED]"

def mask_balance(balance, role):
    if role == "Admin":
        return f"${balance:,.2f}"
    elif role in ["Support", "Analyst"]:
        return "[REDACTED]"
    return "[REDACTED]"

# --- AUTHENTICATION ENDPOINTS ---
@app.route("/api/auth/check-role", methods=["POST"])
def check_role_by_email():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"role": None})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE lower(email) = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({"role": row["role"], "found": True})
    
    if "admin" in email:
        return jsonify({"role": "Admin", "found": False})
    elif "analyst" in email:
        return jsonify({"role": "Analyst", "found": False})
    else:
        return jsonify({"role": "Support", "found": False})

@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = request.remote_addr
    now = datetime.now()

    if ip in failed_login_attempts:
        attempt_data = failed_login_attempts[ip]
        if attempt_data["lockout_until"] and now < attempt_data["lockout_until"]:
            time_left = int((attempt_data["lockout_until"] - now).total_seconds())
            return jsonify({"error": f"Too many failed login attempts. Try again in {time_left} seconds."}), 429
        elif attempt_data["lockout_until"] and now >= attempt_data["lockout_until"]:
            failed_login_attempts[ip] = {"count": 0, "lockout_until": None}

    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE lower(email) = ?", (email,))
    user = cursor.fetchone()

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        if ip not in failed_login_attempts:
            failed_login_attempts[ip] = {"count": 1, "lockout_until": None}
        else:
            failed_login_attempts[ip]["count"] += 1

        if failed_login_attempts[ip]["count"] >= 5:
            failed_login_attempts[ip]["lockout_until"] = now + timedelta(minutes=15)
            log_audit("LOGIN_LOCKOUT", f"IP {ip} locked out due to repeated failures", user_email=email)
            conn.close()
            return jsonify({"error": "Account temporarily locked due to 5 consecutive failed attempts. Try again in 15 minutes."}), 429

        log_audit("LOGIN_FAILED", f"Invalid credentials attempt for email: {email}")
        conn.close()
        return jsonify({"error": "Invalid email or password"}), 401

    if user["account_status"] != "ACTIVE":
        log_audit("LOGIN_BLOCKED", f"Inactive account attempt: {email}", user_id=user["user_id"], user_email=email)
        conn.close()
        return jsonify({"error": "Account is inactive. Contact your Administrator."}), 403

    failed_login_attempts.pop(ip, None)

    session.clear()
    session["user_id"] = user["user_id"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    session["role"] = user["role"]

    cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?", (user["user_id"],))
    conn.commit()
    conn.close()

    log_audit("LOGIN_SUCCESS", f"User logged in with role {user['role']}", user_id=user["user_id"], user_email=user["email"])

    return jsonify({
        "message": "Login successful",
        "user": {
            "user_id": user["user_id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user["role"]
        }
    })

@app.route("/api/auth/me", methods=["GET"])
@login_required
def get_current_user():
    return jsonify({
        "user_id": session["user_id"],
        "full_name": session["full_name"],
        "email": session["email"],
        "role": session["role"]
    })

@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout():
    log_audit("LOGOUT", "User logged out")
    session.clear()
    return jsonify({"message": "Logged out successfully"})

# --- CUSTOMER DATA & DYNAMIC MASKING API ---
@app.route("/api/customers", methods=["GET"])
@login_required
def get_customers():
    user_role = session["role"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers")
    rows = cursor.fetchall()
    conn.close()

    masked_records = []
    for r in rows:
        masked_records.append({
            "customer_id": r["customer_id"],
            "full_name": r["full_name"],
            "email": mask_email(r["email"], user_role),
            "phone_number": mask_phone(r["phone_number"], user_role),
            "card_number": mask_card_number(r["card_number"], user_role),
            "ssn": mask_ssn(r["ssn"], user_role),
            "account_balance": mask_balance(r["account_balance"], user_role),
            "credit_score": r["credit_score"] if user_role in ["Admin", "Analyst"] else "[HIDDEN]"
        })

    log_audit("DATA_ACCESS", f"Retrieved customer records under role: {user_role}")
    return jsonify({"role_applied": user_role, "data": masked_records})

# --- AUTOMATED PII SCANNER API ---
@app.route("/api/scanner/run", methods=["POST"])
@roles_required("Admin", "Analyst")
def run_pii_scanner():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers LIMIT 10")
    columns = [description[0] for description in cursor.description]
    rows = cursor.fetchall()
    conn.close()

    patterns = {
        "card_number": (r"^\d{13,19}$", "PII_HIGH", "Credit Card Number"),
        "ssn": (r"^\d{3}-\d{2}-\d{4}$", "PII_HIGH", "Social Security Number"),
        "email": (r"^[\w\.-]+@[\w\.-]+\.\w+$", "PII_MEDIUM", "Email Address"),
        "phone_number": (r"^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$", "PII_MEDIUM", "Phone Number"),
        "account_balance": (r"^\d+(\.\d{1,2})?$", "FINANCIAL_CONFIDENTIAL", "Financial Account Balance")
    }

    scan_results = []
    for col in columns:
        col_lower = col.lower()
        classification = "PUBLIC"
        detected_type = "Standard Data"
        confidence = "100%"

        if col_lower in patterns:
            pattern, pii_tag, desc = patterns[col_lower]
            matches = 0
            for r in rows:
                val = str(r[col])
                if re.match(pattern, val):
                    matches += 1
            if matches > 0:
                classification = pii_tag
                detected_type = desc

        scan_results.append({
            "column_name": col,
            "classification": classification,
            "detected_type": detected_type,
            "confidence": confidence
        })

    log_audit("PII_SCAN_EXECUTED", f"PII Scanner executed. Identified {len(scan_results)} columns.")
    return jsonify({"status": "SUCCESS", "results": scan_results})

# --- USER MANAGEMENT ENDPOINTS (ADMIN ONLY) ---
@app.route("/api/users", methods=["GET"])
@roles_required("Admin")
def list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, full_name, email, role, account_status, created_at, last_login FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route("/api/users/create", methods=["POST"])
@roles_required("Admin")
def create_user():
    data = request.get_json() or {}
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip().lower()
    role = data.get("role", "Support")
    password = data.get("password", "")

    if not full_name or not email or not password:
        return jsonify({"error": "Full name, email, and password are required"}), 400

    if role not in ["Admin", "Support", "Analyst"]:
        return jsonify({"error": "Invalid role specified"}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (full_name, email, password_hash, role, account_status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        """, (full_name, email, hashed_pw, role))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()

        log_audit("USER_CREATED", f"Created user {email} with role {role}")
        return jsonify({"message": f"User {email} created successfully", "user_id": new_id}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "An account with this email already exists"}), 400

@app.route("/api/users/<int:user_id>/status", methods=["PATCH"])
@roles_required("Admin")
def update_user_status(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "Cannot deactivate your own logged-in Admin account"}), 400

    data = request.get_json() or {}
    status = data.get("account_status")
    if status not in ["ACTIVE", "INACTIVE"]:
        return jsonify({"error": "Invalid status value"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET account_status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (status, user_id))
    conn.commit()
    conn.close()

    log_audit("USER_STATUS_UPDATED", f"Updated user {user_id} status to {status}")
    return jsonify({"message": "User status updated successfully"})

@app.route("/api/users/<int:user_id>/reset-password", methods=["POST"])
@roles_required("Admin")
def reset_user_password(user_id):
    data = request.get_json() or {}
    new_password = data.get("new_password", "")
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    hashed_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (hashed_pw, user_id))
    conn.commit()
    conn.close()

    log_audit("PASSWORD_RESET", f"Reset password for user_id {user_id}")
    return jsonify({"message": "Password reset successfully"})

# --- AUDIT LOGS ENDPOINT (ADMIN ONLY) ---
@app.route("/api/audit-logs", methods=["GET"])
@roles_required("Admin")
def get_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(logs)

# --- SERVE FRONTEND STATIC FILES ---
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
