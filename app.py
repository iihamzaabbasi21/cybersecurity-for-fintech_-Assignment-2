"""
streamlit_app.py
Secure FinTech mini-app for CY4053 Assignment 2 (Final student submission)
Author: Hamza Abbasi (adapted & hardened)
Implements: registration, login, profile update, wallets, encrypted storage,
transactions, audit logs, file upload validation, encryption tool, and test export.
"""

import os
import re
import time
import sqlite3
import random
import string
import bcrypt
import pandas as pd
from io import BytesIO
from datetime import datetime
from cryptography.fernet import Fernet
import streamlit as st

# ---------------------------
# Config / Paths
# ---------------------------
DB_PATH = os.getenv("SECURE_FINTECH_DB", "secure_fintech.db")
KEY_PATH = os.getenv("SECURE_FINTECH_KEYFILE", "secret.key")
ALLOWED_UPLOAD_EXTS = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

# ---------------------------
# Small helpers
# ---------------------------
def safe_now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ---------------------------
# UI theme (streamlined but different from sample)
# ---------------------------
def inject_css():
    st.markdown(
        """
        <style>
        .stApp { background: linear-gradient(180deg,#041428 0%, #051225 100%); color: #e6f7ff; font-family: Inter, sans-serif; }
        .card { background: rgba(6,12,20,0.6); border-radius:12px; padding:14px; border:1px solid rgba(120,220,255,0.06); box-shadow: 0 8px 30px rgba(0,0,0,0.6); }
        .accent { color:#8ef0ff; font-weight:700; }
        h1,h2,h3 { color: #cfefff }
        .stButton>button { border-radius:8px; padding:8px 12px; font-weight:600; }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------
# DB / Key helpers
# ---------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        wallet_name TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id INTEGER NOT NULL,
        transaction_id TEXT NOT NULL,
        transaction_number TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(wallet_id) REFERENCES wallets(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()
    # ensure DB file permissions are not world-readable
    try:
        os.chmod(DB_PATH, 0o600)
    except Exception:
        pass

# ---------------------------
# Key management
# ---------------------------
def load_or_create_key():
    # allow override by env var (preferred for deployment)
    env_key = os.getenv("SECRET_KEY_BASE64")
    if env_key:
        return env_key.encode()
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            key = f.read()
        try:
            os.chmod(KEY_PATH, 0o600)
        except Exception:
            pass
        return key
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    try:
        os.chmod(KEY_PATH, 0o600)
    except Exception:
        pass
    return key

fernet = None
def init_crypto():
    global fernet
    key = load_or_create_key()
    fernet = Fernet(key)

def encrypt_data(text: str) -> bytes:
    return fernet.encrypt(text.encode())

def decrypt_data(token: bytes) -> str:
    return fernet.decrypt(token).decode()

# ---------------------------
# Validation & sanitization
# ---------------------------
PASSWORD_REGEX = re.compile(r"^(?=.{8,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).*$")
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

def is_strong_password(pw: str) -> bool:
    return bool(PASSWORD_REGEX.match(pw))

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def sanitize_text(s, max_len=2000, tight=False):
    """
    Safer sanitization:
      - strips whitespace
      - removes HTML tags
      - rejects most control chars
      - optionally apply a tight whitelist (alnum and a few safe punct)
    """
    if s is None:
        return ""
    s = str(s).strip()
    if not s:
        return s
    s = re.sub(r"(?i)<.*?>", "", s)  # strip tags
    if any(ord(ch) < 32 and ch not in ("\n", "\t", "\r") for ch in s):
        raise ValueError("Invalid characters in input.")
    if len(s) > max_len:
        st.warning("⚠️ Input too long — trimmed.")
        s = s[:max_len]
    if tight:
        if not re.match(r'^[\w\s\-\._@]+$', s):
            raise ValueError("Invalid characters in input.")
    return s

def validate_uploaded_file(f) -> (bool, str):
    name = getattr(f, "name", "")
    ext = name.split(".")[-1].lower() if name and "." in name else ""
    if ext not in ALLOWED_UPLOAD_EXTS:
        return False, f".{ext} not allowed."
    try:
        size = getattr(f, "size", None)
        if size is None:
            # fallback to buffer length
            buf = f.getbuffer()
            size = len(buf)
    except Exception:
        return False, "Failed to read file size."
    if size > MAX_UPLOAD_BYTES:
        return False, "File >5 MB."
    return True, "OK"

# ---------------------------
# Password helpers
# ---------------------------
def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def verify_password(pw: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed)
    except Exception:
        return False

# ---------------------------
# Audit logging
# ---------------------------
def log_action(user_id, action, details=None):
    try:
        conn = get_db_connection(); c = conn.cursor()
        c.execute("INSERT INTO audit_logs(user_id,action,details,timestamp) VALUES(?,?,?,?)",
                  (user_id, action, details, safe_now()))
        conn.commit(); conn.close()
    except Exception:
        # keep silent in production but useful during dev to print
        try:
            print("audit log failed", action)
        except Exception:
            pass

# ---------------------------
# User operations
# ---------------------------
def register_user(username: str, email: str, password: str):
    try:
        username = sanitize_text(username, tight=True)
        email = sanitize_text(email, tight=True)
    except ValueError as e:
        return False, str(e)
    if not (username and email and password):
        return False, "All fields required."
    if not is_valid_email(email):
        return False, "Invalid email."
    if not is_strong_password(password):
        return False, "Weak password. Use upper, lower, number and special char (min 8)."
    try:
        conn = get_db_connection(); c = conn.cursor()
        pw_hash = hash_password(password)
        c.execute("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                  (username, email, pw_hash, safe_now()))
        conn.commit(); uid = c.lastrowid; conn.close()
        log_action(uid, "register", f"user:{username}")
        return True, "Registration successful."
    except sqlite3.IntegrityError:
        return False, "Username or email already exists."
    except Exception:
        return False, "Registration failed."

def get_user_by_username(u):
    try:
        u = sanitize_text(u, tight=True)
    except Exception:
        return None
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (u,))
    row = c.fetchone(); conn.close()
    return row

def get_user_by_id(uid):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (uid,))
    r = c.fetchone(); conn.close(); return r

def update_user_email(uid, new_email):
    if not is_valid_email(new_email):
        return False, "Invalid email."
    try:
        conn = get_db_connection(); c = conn.cursor()
        c.execute("UPDATE users SET email=? WHERE id=?", (new_email, uid))
        conn.commit(); conn.close()
        log_action(uid, "email_update", new_email)
        return True, "Email updated."
    except sqlite3.IntegrityError:
        return False, "Email already in use."
    except Exception:
        return False, "Update failed."

def change_user_password(uid, old_pw, new_pw):
    if not is_strong_password(new_pw):
        return False, "Weak new password."
    user = get_user_by_id(uid)
    if not user or not verify_password(old_pw, user["password_hash"]):
        return False, "Old password incorrect."
    try:
        conn = get_db_connection(); c = conn.cursor()
        c.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_pw), uid))
        conn.commit(); conn.close()
        log_action(uid, "password_change")
        return True, "Password changed."
    except Exception:
        return False, "Failed."

# ---------------------------
# Wallets / Transactions
# ---------------------------
def create_wallet(uid, name, data):
    try:
        name = sanitize_text(name, tight=True)
        # data may include free-form characters but limit length
        data = sanitize_text(data, max_len=1500)
    except ValueError as e:
        return False, str(e)
    try:
        enc = encrypt_data(data)
        conn = get_db_connection(); c = conn.cursor()
        c.execute("INSERT INTO wallets(owner_id,wallet_name,encrypted_data,created_at) VALUES(?,?,?,?)",
                  (uid, name, enc, safe_now()))
        conn.commit(); conn.close()
        log_action(uid, "create_wallet", name)
        return True, "Wallet created."
    except Exception:
        return False, "Creation failed."

def get_wallets_for_user(uid):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT id, wallet_name, encrypted_data, created_at FROM wallets WHERE owner_id=?", (uid,))
    rows = c.fetchall(); conn.close(); return rows

def create_transaction(wallet_id, number, acting_user_id=None):
    try:
        number = str(number).strip()
        if not re.match(r"^[0-9]+$", number):
            return False, "Transaction number must be numeric."
        conn = get_db_connection(); c = conn.cursor()
        c.execute("SELECT owner_id FROM wallets WHERE id=?", (wallet_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return False, "Wallet not found."
        owner_id = row["owner_id"]
        txid = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        enc = encrypt_data(f"Transaction {txid}-{number}")
        c.execute("INSERT INTO transactions(wallet_id,transaction_id,transaction_number,encrypted_data,created_at) VALUES(?,?,?,?,?)",
                  (wallet_id, txid, number, enc, safe_now()))
        conn.commit(); conn.close()
        log_action(acting_user_id or owner_id, "create_transaction", f"{txid}")
        return True, "Transaction added."
    except Exception:
        return False, "Transaction failed."

def get_transactions(wallet_id):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT transaction_id,transaction_number,created_at FROM transactions WHERE wallet_id=?", (wallet_id,))
    r = c.fetchall(); conn.close(); return r

# ---------------------------
# UI pages
# ---------------------------
def show_home():
    st.title("🔐 Secure FinTech Playground")
    st.markdown("This mini-app demonstrates secure coding concepts required for CY4053 Assignment 2.")
    st.caption("Features: secure registration, login, encrypted storage, audit logs, file validation and manual test export.")
    st.divider()

def show_register():
    st.header("Create an account")
    with st.form("register_form"):
        u = st.text_input("Choose a username", max_chars=30)
        e = st.text_input("Email address", placeholder="name@example.com")
        p = st.text_input("Password", type="password")
        c = st.text_input("Confirm password", type="password")
        if st.form_submit_button("Register"):
            if p != c:
                st.warning("Passwords do not match.")
            else:
                ok, msg = register_user(u, e, p)
                if ok:
                    st.success(msg); st.experimental_rerun()
                else:
                    st.error(msg)

def show_login():
    st.header("Sign in")
    if "failed_attempts" not in st.session_state: st.session_state["failed_attempts"] = 0
    if "lockout_time" not in st.session_state: st.session_state["lockout_time"] = None

    if st.session_state["lockout_time"]:
        elapsed = time.time() - st.session_state["lockout_time"]
        if elapsed < 60:
            st.error(f"🚫 Locked — try again in {int(60-elapsed)} s.")
            return
        st.session_state["lockout_time"] = None
        st.session_state["failed_attempts"] = 0

    with st.form("login_form"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            if not u.strip() or not p.strip():
                st.warning("Enter both fields."); return
            # basic input check to avoid naive payloads
            if re.search(r"('|--|;|=)", u):
                st.error("⚠️ Unsafe input detected."); log_action(None, "login_blocked", u); return
            user = get_user_by_username(u)
            if user and verify_password(p, user["password_hash"]):
                st.session_state["user_id"] = user["id"]
                st.session_state["username"] = user["username"]
                st.session_state["failed_attempts"] = 0
                st.success("✅ Login successful."); log_action(user["id"], "login")
            else:
                st.session_state["failed_attempts"] += 1
                remaining = 5 - st.session_state["failed_attempts"]
                if remaining > 0:
                    st.error(f"Invalid credentials. {remaining} attempts left.")
                else:
                    st.session_state["lockout_time"] = time.time()
                    st.error("🚫 Too many attempts — locked 1 min.")
                    log_action(None, "lockout_attempt", u)

def require_login():
    return "user_id" in st.session_state and st.session_state["user_id"]

def show_profile():
    st.header("My Profile")
    user = get_user_by_id(st.session_state["user_id"])
    if not user:
        st.error("User not found."); return
    st.write(f"**Username:** {user['username']}")
    st.write(f"**Email:** {user['email']}")
    st.divider()
    st.subheader("Update Email")
    with st.form("email_form"):
        new = st.text_input("New email", value=user["email"])
        if st.form_submit_button("Update Email"):
            ok, msg = update_user_email(user["id"], new)
            st.success(msg) if ok else st.error(msg)
    st.divider()
    st.subheader("Change Password")
    with st.form("pw_form"):
        old = st.text_input("Old password", type="password")
        new = st.text_input("New password", type="password")
        conf = st.text_input("Confirm new password", type="password")
        if st.form_submit_button("Change Password"):
            if new != conf:
                st.warning("Passwords don’t match.")
            else:
                ok, msg = change_user_password(user["id"], old, new)
                st.success(msg) if ok else st.error(msg)

def show_wallets():
    st.header("Wallets & Transactions")
    st.caption("Store private wallet data encrypted and add simple transactions.")
    st.divider()
    with st.form("create_wallet"):
        name = st.text_input("Wallet name", max_chars=50)
        data = st.text_area("Private data (will be encrypted)")
        if st.form_submit_button("Create"):
            if not name or not data:
                st.error("All fields required.")
            else:
                try:
                    ok, msg = create_wallet(st.session_state["user_id"], name, data)
                    st.success(msg) if ok else st.error(msg)
                except ValueError as e:
                    st.error(str(e))

    st.divider()
    wallets = get_wallets_for_user(st.session_state["user_id"])
    if not wallets:
        st.info("No wallets created yet."); return

    for w in wallets:
        st.markdown(f"### 🔒 {w['wallet_name']}  •  <small>{w['created_at']}</small>", unsafe_allow_html=True)
        cols = st.columns([1, 1, 2])
        if cols[0].button("Decrypt", key=f"d{w['id']}"):
            try:
                st.code(decrypt_data(w["encrypted_data"]))
            except Exception:
                st.error("Decryption failed.")
        with cols[1].expander("Add Transaction"):
            with st.form(f"txn_form_{w['id']}"):
                num = st.text_input("Transaction Number (numeric only)", key=f"n{w['id']}")
                if st.form_submit_button("Add"):
                    ok, msg = create_transaction(w["id"], num, acting_user_id=st.session_state.get("user_id"))
                    st.success(msg) if ok else st.error(msg)
        if cols[2].button("View Transactions", key=f"v{w['id']}"):
            tx = get_transactions(w["id"])
            if not tx:
                st.info("No transactions yet.")
            else:
                df = pd.DataFrame([dict(r) for r in tx])
                df = df.rename(columns={"transaction_id": "Transaction ID", "transaction_number": "Number", "created_at": "Created At"})
                st.dataframe(df[["Transaction ID", "Number", "Created At"]], use_container_width=True)

def show_file_upload():
    st.header("Secure File Upload")
    st.caption("Allowed: png, jpg, jpeg, pdf, csv, txt — max 5 MB.")
    file = st.file_uploader("Choose a file", type=list(ALLOWED_UPLOAD_EXTS))
    if file:
        ok, msg = validate_uploaded_file(file)
        if ok:
            st.success("✅ File accepted.")
            log_action(st.session_state.get("user_id"), "file_upload", getattr(file, "name", "unknown"))
        else:
            st.error(msg)
            log_action(st.session_state.get("user_id"), "file_upload_blocked", getattr(file, "name", "unknown"))

def show_encryption_tool():
    st.header("Quick Encryption / Decryption")
    st.markdown("Encrypt text for storage or paste ciphertext to decrypt (Streamlit users only).")
    txt = st.text_area("Text to encrypt")
    if st.button("Encrypt"):
        if not txt.strip(): st.warning("Enter text"); 
        else: 
            try:
                st.code(encrypt_data(sanitize_text(txt, max_len=1500)).decode())
            except Exception:
                st.error("Encryption failed.")
    token = st.text_area("Ciphertext to decrypt")
    if st.button("Decrypt"):
        tok = token.strip()
        if not tok:
            st.warning("Enter ciphertext.")
        else:
            try:
                st.code(decrypt_data(tok.encode()))
            except Exception:
                st.error("Invalid token.")

def show_audit_logs():
    st.header("My Activity Logs")
    uid = st.session_state["user_id"]
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT id,user_id,action,details,timestamp FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 200", (uid,))
    rows = c.fetchall(); conn.close()
    if not rows:
        st.info("No activity yet."); return
    df = pd.DataFrame([dict(r) for r in rows])
    df = df.rename(columns={"id": "ID", "user_id": "User ID", "action": "Action", "details": "Details", "timestamp": "Timestamp"})
    st.dataframe(df[["ID", "User ID", "Action", "Details", "Timestamp"]], use_container_width=True)
    b = BytesIO(); df.to_excel(b, index=False, sheet_name="logs"); b.seek(0)
    st.download_button("⬇️ Download Activity Logs (Excel)", data=b, file_name="audit_logs.xlsx")

def export_testcases_excel():
    st.header("Prepared Manual Testcase Template")
    # Provide 25 test-case rows as starter for manual testing (user must fill Observed and Pass/Fail + attach screenshots)
    tests = [{"No.": i, "Test Case": f"Security Test {i}", "Action Performed": "", "Expected Outcome": "", "Observed Result": "", "Pass/Fail": ""} for i in range(1, 26)]
    df = pd.DataFrame(tests); bio = BytesIO(); df.to_excel(bio, index=False, sheet_name="testcases"); bio.seek(0)
    st.download_button("Download manual_testcases_template.xlsx", data=bio, file_name="manual_testcases_template.xlsx")

def show_error_test():
    st.header("Error Handling Demo")
    if st.button("Trigger Controlled Error"):
        try:
            _ = 1 / 0
        except Exception:
            st.error("⚠️ Controlled exception handled (no sensitive info revealed).")
            log_action(st.session_state.get("user_id"), "error_test")

# ---------------------------
# Main app
# ---------------------------
def main():
    inject_css(); init_db(); init_crypto()
    st.sidebar.markdown("<div class='card'><h3 class='accent'>Secure FinTech — CY4053</h3></div>", unsafe_allow_html=True)

    if "user_id" not in st.session_state: st.session_state["user_id"] = None
    if "username" not in st.session_state: st.session_state["username"] = None

    # Navigation items are intentionally ordered differently from example
    page = st.sidebar.selectbox("Navigate", ["Home", "Register", "Login", "Wallets", "Profile", "File Upload", "Encryption", "Audit Logs", "Export Tests", "Error Demo"])

    if require_login():
        st.sidebar.markdown(f"**Signed in:** {st.session_state['username']}")
        if st.sidebar.button("Logout"):
            try:
                log_action(st.session_state.get("user_id"), "logout", "User logged out")
            except Exception:
                pass
            # clear session and rerun
            st.session_state.clear()
            st.experimental_rerun()

    try:
        if page == "Home":
            show_home()
        elif page == "Register":
            show_register()
        elif page == "Login":
            show_login()
        elif page == "Profile":
            if require_login(): show_profile()
            else: st.warning("Please login first.")
        elif page == "Wallets":
            if require_login(): show_wallets()
            else: st.warning("Please login first.")
        elif page == "File Upload":
            if require_login(): show_file_upload()
            else: st.warning("Please login first.")
        elif page == "Encryption":
            if require_login(): show_encryption_tool()
            else: st.warning("Please login first.")
        elif page == "Audit Logs":
            if require_login(): show_audit_logs()
            else: st.warning("Please login first.")
        elif page == "Export Tests":
            export_testcases_excel()
        elif page == "Error Demo":
            show_error_test()
    except Exception:
        st.error("Unexpected error occurred."); log_action(st.session_state.get("user_id"), "error_generic", "App exception")

if __name__ == "__main__":
    main()
