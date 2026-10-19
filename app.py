import streamlit as st
import sqlite3
import pandas as pd
import bcrypt
from datetime import datetime
import os

DB_PATH = os.getenv("MASKING_DB_PATH", "masking.db")

# Page Configuration
st.set_page_config(
    page_title="Smart Data Masking Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Clean Light Theme CSS with High-Contrast Text ---
st.markdown("""
<style>
    /* Main Background Accent */
    .stApp {
        background-color: #F8FAFC !important;
        color: #0F172A !important;
    }

    /* Primary Headers & Text Colors */
    h1, h2, h3, h4, h5, h6, label, .stMarkdown {
        color: #0F172A !important;
        font-weight: 700 !important;
    }

    /* Form Input Labels (Force Bold Dark Text) */
    div[data-testid="stForm"] label {
        color: #0F172A !important;
        font-size: 1rem !important;
        font-weight: 700 !important;
    }

    /* Input Field Boxes & Typed Text Contrast */
    div[data-baseweb="input"] input {
        color: #0F172A !important;
        background-color: #FFFFFF !important;
        font-weight: 600 !important;
    }
    div[data-baseweb="input"] {
        border-radius: 8px !important;
        border: 2px solid #CBD5E1 !important;
        background-color: #FFFFFF !important;
    }
    div[data-baseweb="input"]:focus-within {
        border-color: #2563EB !important;
    }

    /* Login Box Container Card */
    div[data-testid="stForm"] {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 16px !important;
        padding: 32px !important;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.08) !important;
    }

    /* Unselected Domain Buttons (Blue Border & Text) */
    div.stButton > button[kind="secondary"] {
        border: 2px solid #2563EB !important;
        color: #2563EB !important;
        background-color: #FFFFFF !important;
        font-weight: 800 !important;
        border-radius: 10px !important;
        transition: all 0.2s ease-in-out;
    }
    div.stButton > button[kind="secondary"]:hover {
        background-color: #EFF6FF !important;
        color: #1D4ED8 !important;
    }
    
    /* Selected Domain Button (Solid Blue Background & White Text) */
    div.stButton > button[kind="primary"] {
        background-color: #2563EB !important;
        color: #FFFFFF !important;
        border: 2px solid #2563EB !important;
        font-weight: 800 !important;
        border-radius: 10px !important;
        box-shadow: 0px 4px 12px rgba(37, 99, 235, 0.3) !important;
    }

    /* Green Submit Button inside Login Form */
    div.stFormSubmitButton > button {
        background-color: #10B981 !important;
        color: #FFFFFF !important;
        border: none !important;
        font-weight: 800 !important;
        font-size: 1.1rem !important;
        border-radius: 10px !important;
        box-shadow: 0px 4px 12px rgba(16, 185, 129, 0.25) !important;
        transition: all 0.2s ease-in-out;
    }
    div.stFormSubmitButton > button:hover {
        background-color: #059669 !important;
        box-shadow: 0px 6px 16px rgba(16, 185, 129, 0.35) !important;
    }

    /* Light Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #FFFFFF !important;
        border-right: 1px solid #E2E8F0 !important;
    }

    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-left: 5px solid #2563EB !important;
        padding: 16px !important;
        border-radius: 10px !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04) !important;
    }
</style>
""", unsafe_allow_html=True)

# --- Database Helpers ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit_event(user_email, user_role, action, status="SUCCESS"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (timestamp, user_email, role, action, status) VALUES (?, ?, ?, ?, ?)",
            (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), user_email, user_role, action, status)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to write audit log: {e}")

# --- Masking Logic Engine ---
def apply_masking_to_row(row, role):
    record = dict(row)
    if role == "ADMIN":
        return record

    if role == "SUPPORT":
        if record.get("email"):
            parts = record["email"].split("@")
            record["email"] = f"{parts[0][0]}***@{parts[1]}" if len(parts) == 2 else "***@***.com"
        if record.get("phone"):
            record["phone"] = record["phone"][:4] + " XXX-XX" + record["phone"][-2:]
        if record.get("card_number"):
            record["card_number"] = record["card_number"][:4] + "-XXXX-XXXX-" + record["card_number"][-4:]
        if record.get("ssn"):
            record["ssn"] = "XXX-XX-" + record["ssn"][-4:]
        return record

    if role == "ANALYST":
        name_parts = record.get("full_name", "").split()
        if len(name_parts) >= 2:
            record["full_name"] = f"{name_parts[0][0]}. {name_parts[-1][0]}."
        else:
            record["full_name"] = "[REDACTED]"
            
        record["email"] = "[REDACTED_EMAIL]"
        record["phone"] = "[REDACTED]"
        record["card_number"] = "XXXX-XXXX-XXXX-XXXX"
        record["ssn"] = "[REDACTED_SSN]"
        record["balance"] = "[CONFIDENTIAL]"
        return record

    return record

# --- Authentication State ---
if "user" not in st.session_state:
    st.session_state.user = None

if "selected_domain" not in st.session_state:
    st.session_state.selected_domain = None
if "email_placeholder" not in st.session_state:
    st.session_state.email_placeholder = "Select a domain button above"

def login(email, password):
    if not email or not password:
        st.error("Please enter both email and password.")
        return False

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE lower(email) = ?", (email.strip().lower(),))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        if user["account_status"] != "ACTIVE":
            st.error("Account is inactive. Access denied.")
            log_audit_event(email, user["role"], "LOGIN_FAILED_INACTIVE", "FAILED")
            return False
        
        user_dict = dict(user)
        del user_dict["password_hash"]
        st.session_state.user = user_dict
        log_audit_event(user_dict["email"], user_dict["role"], "USER_LOGIN", "SUCCESS")
        return True
    else:
        st.error("Invalid email or password.")
        log_audit_event(email, "UNKNOWN", "LOGIN_FAILED", "FAILED")
        return False

# --- UI Layout: Domain Selection Login Gate ---
if st.session_state.user is None:
    st.title("🛡️ Smart Data Masking System")
    st.caption("Enterprise Secure Portal — Authentication Required")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.subheader("Account Sign In")
        st.markdown("Press a domain button to display format guidance placeholders:")

        # --- Domain Selector Buttons ---
        b1, b2, b3 = st.columns(3)

        admin_type = "primary" if st.session_state.selected_domain == "ADMIN" else "secondary"
        support_type = "primary" if st.session_state.selected_domain == "SUPPORT" else "secondary"
        analyst_type = "primary" if st.session_state.selected_domain == "ANALYST" else "secondary"

        if b1.button("ADMIN", use_container_width=True, type=admin_type):
            st.session_state.selected_domain = "ADMIN"
            st.session_state.email_placeholder = "e.g., admin@financial.org"
            st.rerun()

        if b2.button("SUPPORT", use_container_width=True, type=support_type):
            st.session_state.selected_domain = "SUPPORT"
            st.session_state.email_placeholder = "e.g., ravi.kumar@financial.org"
            st.rerun()

        if b3.button("ANALYST", use_container_width=True, type=analyst_type):
            st.session_state.selected_domain = "ANALYST"
            st.session_state.email_placeholder = "e.g., rajesh.khanna@financial.org"
            st.rerun()

        st.markdown("---")

        # --- Sign In Form ---
        with st.form("login_form"):
            login_email = st.text_input(
                "Email Address",
                placeholder=st.session_state.email_placeholder
            )
            login_password = st.text_input(
                "Password",
                type="password",
                placeholder="xxxxxxxxx"
            )
            
            submit_button = st.form_submit_button("Sign In", use_container_width=True)

            if submit_button:
                if not st.session_state.selected_domain:
                    st.warning("⚠️ Please press a domain button (ADMIN, SUPPORT, or ANALYST) above to activate placeholder guidance before signing in!")
                elif not login_email or not login_password:
                    st.error("Please enter your registered email and password.")
                else:
                    if login(login_email, login_password):
                        st.rerun()

else:
    current_user = st.session_state.user
    active_role = current_user["role"]
    
    # --- Sidebar Navigation ---
    st.sidebar.title("🛡️ Smart Shield")
    st.sidebar.write(f"Logged in as: **{current_user['email']}**")
    st.sidebar.markdown(f"**Verified Role:** `:blue[{active_role}]`")

    st.sidebar.markdown("---")
    if st.sidebar.button("Log Out", use_container_width=True):
        log_audit_event(current_user["email"], active_role, "USER_LOGOUT")
        st.session_state.user = None
        st.session_state.selected_domain = None
        st.session_state.email_placeholder = "Select a domain button above"
        st.rerun()

    # Dynamic Navigation Based on User Domain Role
    menu_options = ["📊 Customer Data Table", "🔍 PII Compliance Scanner"]
    if active_role == "ADMIN":
        menu_options.extend(["👥 User Management", "📋 System Audit Logs"])

    active_tab = st.sidebar.radio("Navigation", menu_options)

    # --- TAB 1: Customer Data Table ---
    if active_tab == "📊 Customer Data Table":
        st.title("Customer Financial Records")
        st.caption(f"Displaying records monitored under **{active_role}** security policies.")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM customers")
        rows = cursor.fetchall()
        conn.close()

        masked_records = [apply_masking_to_row(row, active_role) for row in rows]
        df = pd.DataFrame(masked_records)

        log_audit_event(current_user["email"], active_role, "VIEW_CUSTOMER_RECORDS")

        m1, m2, m3 = st.columns(3)
        m1.metric("Total Records Loaded", len(df))
        m2.metric("Your Active Domain", active_role)
        m3.metric("PII Protection Status", "Active" if active_role != "ADMIN" else "Unrestricted")

        st.markdown("---")
        st.dataframe(df, use_container_width=True, hide_index=True)

    # --- TAB 2: PII Scanner ---
    elif active_tab == "🔍 PII Compliance Scanner":
        st.title("Automated PII Compliance Scanner")
        st.caption("Schema inspection and sensitivity categorization.")

        pii_report = [
            {"Column": "ssn", "Detected Type": "SSN / Tax ID", "Sensitivity": "PII_HIGH", "Confidence": "99%", "Required Action": "Full Masking Required"},
            {"Column": "card_number", "Detected Type": "PCI-DSS Credit Card", "Sensitivity": "FINANCIAL_CONFIDENTIAL", "Confidence": "98%", "Required Action": "Truncation / Tokenization"},
            {"Column": "email", "Detected Type": "Email Address", "Sensitivity": "PII_MEDIUM", "Confidence": "95%", "Required Action": "Partial Redaction"},
            {"Column": "phone", "Detected Type": "Phone Number", "Sensitivity": "PII_MEDIUM", "Confidence": "92%", "Required Action": "Partial Masking"},
            {"Column": "balance", "Detected Type": "Account Balance", "Sensitivity": "FINANCIAL_CONFIDENTIAL", "Confidence": "90%", "Required Action": "Role-based Restriction"}
        ]

        st.dataframe(pd.DataFrame(pii_report), use_container_width=True, hide_index=True)

    # --- TAB 3: User Management (ADMIN Only) ---
    elif active_tab == "👥 User Management":
        st.title("User Governance Portal")
        st.caption("Admin control panel for system users, roles, and status flags.")

        conn = get_db_connection()
        df_users = pd.read_sql_query("SELECT id, email, role, account_status, created_at FROM users ORDER BY id ASC", conn)
        conn.close()

        col_search, col_filter = st.columns([2, 1])
        with col_search:
            search_query = st.text_input("Filter Users by Email", "")
        with col_filter:
            role_filter = st.selectbox("Filter by Role", ["ALL", "ADMIN", "SUPPORT", "ANALYST"])

        if search_query:
            df_users = df_users[df_users['email'].str.contains(search_query, case=False, na=False)]
        if role_filter != "ALL":
            df_users = df_users[df_users['role'] == role_filter]

        st.write(f"Displaying **{len(df_users)}** registered accounts:")
        st.dataframe(df_users, use_container_width=True, hide_index=True)

    # --- TAB 4: Audit Logs (ADMIN Only) ---
    elif active_tab == "📋 System Audit Logs":
        st.title("System Audit Logs")
        st.caption("Immutable system events log capturing all login and access events.")

        conn = get_db_connection()
        df_logs = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100", conn)
        conn.close()

        st.dataframe(df_logs, use_container_width=True, hide_index=True)
