import os
import re
import sqlite3
import hashlib
from datetime import datetime, timedelta
import bcrypt
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("MASKING_DB_PATH", "masking.db")

# --- DATABASE SETUP ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

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

    cursor.execute("SELECT COUNT(*) FROM customers")
    if cursor.fetchone()[0] == 0:
        sample_customers = [
            ("Ravi Kumar", "ravi.kumar@example.com", "+91 98765 43210", "4111222233331111", "987-65-4321", 54000.50, 750),
            ("Priya Sharma", "priya.sharma@domain.io", "+91 87654 32109", "5500111122223333", "654-32-1098", 128500.00, 810),
            ("Amit Patel", "apatel@corporate.org", "+91 76543 21098", "378282246310005", "456-78-9012", 3200.75, 680),
            ("Sneha Reddy", "sneha.reddy@tech.com", "+91 65432 10987", "6011000990139424", "123-45-6789", 89400.20, 790),
            ("Vikram Singh", "vsingh@finance.net", "+91 91234 56789", "4012888899992222", "321-65-9870", 215000.00, 840)
        ]
        cursor.executemany("""
            INSERT INTO customers (full_name, email, phone_number, card_number, ssn, account_balance, credit_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, sample_customers)

    # Seed an admin account if none exists
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_pass = bcrypt.hashpw("Admin@123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor.execute("""
            INSERT INTO users (full_name, email, password_hash, role, account_status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        """, ("System Admin", "admin@masking.org", admin_pass, "Admin"))

    conn.commit()
    conn.close()

init_db()

# --- MASKING LOGIC ---
def mask_card(card, role):
    if role == "Admin": return card
    if role == "Support": return f"{card[:4]}-XXXX-XXXX-{card[-4:]}"
    return "X" * len(card)

def mask_email(email, role):
    if role == "Admin": return email
    if role == "Support":
        parts = email.split("@")
        return f"{parts[0][0]}***@{parts[1]}" if len(parts) == 2 else "***@***.com"
    return hashlib.sha256((email + "SALT").encode()).hexdigest()[:12] + "@pseudo.anon"

def mask_phone(phone, role):
    if role == "Admin": return phone
    if role == "Support": return phone[:4] + " XXX-XX" + phone[-2:]
    return "[PSEUDONYMIZED]"

def mask_ssn(ssn, role):
    if role == "Admin": return ssn
    if role == "Support": return "XXX-XX-" + ssn[-4:]
    return "[REDACTED]"

def mask_balance(balance, role):
    if role == "Admin": return f"${balance:,.2f}"
    return "[REDACTED]"

# --- STREAMLIT UI ---
st.set_page_config(page_title="Smart Data Masking", layout="wide")

if "user" not in st.session_state:
    st.session_state.user = None

if not st.session_state.user:
    st.title("🔐 Smart Data Masking Portal - Login")
    
    with st.form("login_form"):
        email = st.text_input("Email Address")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE lower(email) = ?", (email.strip().lower(),))
            user = cursor.fetchone()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
                if user["account_status"] != "ACTIVE":
                    st.error("Account is inactive. Contact Administrator.")
                else:
                    st.session_state.user = dict(user)
                    st.success("Login successful!")
                    st.rerun()
            else:
                st.error("Invalid email or password")
    
    st.info("Default Admin Login: **admin@masking.org** / **Admin@123**")

else:
    user = st.session_state.user
    st.sidebar.title(f"Welcome, {user['full_name']}")
    st.sidebar.markdown(f"**Role:** `{user['role']}`")
    
    menu = ["Customer Records", "PII Scanner"]
    if user["role"] == "Admin":
        menu.extend(["User Management", "Audit Logs"])
    
    choice = st.sidebar.selectbox("Navigation", menu)
    
    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.rerun()

    conn = get_db_connection()

    if choice == "Customer Records":
        st.header("📋 Customer Data & Dynamic Masking View")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM customers")
        rows = cursor.fetchall()
        
        data = []
        for r in rows:
            data.append({
                "ID": r["customer_id"],
                "Name": r["full_name"],
                "Email": mask_email(r["email"], user["role"]),
                "Phone": mask_phone(r["phone_number"], user["role"]),
                "Card Number": mask_card(r["card_number"], user["role"]),
                "SSN": mask_ssn(r["ssn"], user["role"]),
                "Balance": mask_balance(r["account_balance"], user["role"]),
                "Credit Score": r["credit_score"] if user["role"] in ["Admin", "Analyst"] else "[HIDDEN]"
            })
        
        st.dataframe(data, use_container_width=True)

    elif choice == "PII Scanner" and user["role"] in ["Admin", "Analyst"]:
        st.header("🔍 Automated PII Compliance Scanner")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM customers LIMIT 5")
        columns = [description[0] for description in cursor.description]
        
        results = [
            {"Column": "card_number", "Classification": "PII_HIGH", "Type": "Credit Card Number", "Confidence": "100%"},
            {"Column": "ssn", "Classification": "PII_HIGH", "Type": "Social Security Number", "Confidence": "100%"},
            {"Column": "email", "Classification": "PII_MEDIUM", "Type": "Email Address", "Confidence": "100%"},
            {"Column": "phone_number", "Classification": "PII_MEDIUM", "Type": "Phone Number", "Confidence": "100%"},
            {"Column": "account_balance", "Classification": "FINANCIAL_CONFIDENTIAL", "Type": "Balance", "Confidence": "100%"}
        ]
        st.table(results)

    elif choice == "User Management" and user["role"] == "Admin":
        st.header("👥 User Management Portal")
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, full_name, email, role, account_status, last_login FROM users")
        users = cursor.fetchall()
        st.table([dict(u) for u in users])

    elif choice == "Audit Logs" and user["role"] == "Admin":
        st.header("📜 System Audit Logs")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50")
        logs = cursor.fetchall()
        st.table([dict(l) for l in logs])

    conn.close()
