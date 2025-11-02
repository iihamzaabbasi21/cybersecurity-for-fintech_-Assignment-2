"""
streamlit_app.py
CY4053 Secure FinTech Assignment 2
Final version — Hamza Abbasi
Completely restyled (light blue / silver theme) with secure functionality
"""

import os
import re
import time
import sqlite3
import bcrypt
import pandas as pd
import random, string
from io import BytesIO
from datetime import datetime
from cryptography.fernet import Fernet
import streamlit as st

# ---------------------------
# Config
# ---------------------------
DB_PATH = "secure_fintech.db"
KEY_PATH = "secret.key"
ALLOWED_TYPES = ["png", "jpg", "jpeg", "pdf", "csv", "txt"]
MAX_SIZE = 5 * 1024 * 1024

# ---------------------------
# Style / Theme
# ---------------------------
def inject_style():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');
        .stApp {
            background: linear-gradient(145deg, #e8f1ff, #f6f9fc);
            color: #1a1a1a;
            font-family: "Poppins", sans-serif;
        }
        h1,h2,h3 { color:#2a4b8d; font-weight:600; }
        .stButton>button {
            background-color:#2a6be0;
            color:white;
            border:none;
            border-radius:8px;
            padding:8px 16px;
            font-weight:600;
            box-shadow:0 4px 10px rgba(42,107,224,0.25);
        }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background:#fff;
            color:#222;
            border-radius:6px;
            border:1px solid #bcd0f7;
            padding:6px;
        }
        .section {
            background:rgba(255,255,255,0.8);
            border-radius:12px;
            padding:16px;
            margin-top:10px;
            box-shadow:0 4px 10px rgba(0,0,0,0.05);
        }
        </style>
    """, unsafe_allow_html=True)

# ---------------------------
# DB / Encryption setup
# ---------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn(); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS wallets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        wallet_name TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id INTEGER NOT NULL,
        transaction_id TEXT NOT NULL,
        transaction_number TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        timestamp TEXT
    )""")
    conn.commit(); conn.close()

def load_or_create_key():
    if os.path.exists(KEY_PATH):
        return open(KEY_PATH,"rb").read()
    key = Fernet.generate_key()
    open(KEY_PATH,"wb").write(key)
    return key

fernet = None
def init_crypto():
    global fernet
    fernet = Fernet(load_or_create_key())

# ---------------------------
# Helpers
# ---------------------------
def log_action(uid, action, detail=""):
    try:
        conn=get_conn();c=conn.cursor()
        c.execute("INSERT INTO logs(user_id,action,details,timestamp) VALUES(?,?,?,?)",
                  (uid, action, detail, datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
    except: pass

def encrypt_data(txt): return fernet.encrypt(txt.encode())
def decrypt_data(t): return fernet.decrypt(t).decode()

def hash_pw(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
def check_pw(pw, h): 
    try: return bcrypt.checkpw(pw.encode(), h)
    except: return False

EMAIL_RE = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PASS_RE  = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$")

def valid_email(e): return bool(EMAIL_RE.match(e))
def strong_pw(p): return bool(PASS_RE.match(p))

# ---------------------------
# Core Operations
# ---------------------------
def register(username,email,pw):
    if not (username and email and pw):
        return False,"All fields required."
    if not valid_email(email):
        return False,"Invalid email."
    if not strong_pw(pw):
        return False,"Weak password."
    try:
        conn=get_conn();c=conn.cursor()
        c.execute("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                  (username,email,hash_pw(pw),datetime.utcnow().isoformat()))
        conn.commit();conn.close()
        return True,"Registration successful."
    except sqlite3.IntegrityError:
        return False,"Username or email already exists."

def login_user(u,p):
    conn=get_conn();c=conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?",(u,))
    row=c.fetchone();conn.close()
    if row and check_pw(p,row["password_hash"]): return row
    return None

def create_wallet(uid,name,data):
    enc=encrypt_data(data)
    conn=get_conn();c=conn.cursor()
    c.execute("INSERT INTO wallets(owner_id,wallet_name,encrypted_data,created_at) VALUES(?,?,?,?)",
              (uid,name,enc,datetime.utcnow().isoformat()))
    conn.commit();conn.close();log_action(uid,"wallet_created",name)
    return True,"Wallet added."

def list_wallets(uid):
    conn=get_conn();c=conn.cursor()
    c.execute("SELECT * FROM wallets WHERE owner_id=?",(uid,))
    r=c.fetchall();conn.close();return r

def add_txn(wallet_id,number):
    if not number.isdigit(): return False,"Transaction must be numeric."
    txid="TX-"+''.join(random.choices(string.ascii_uppercase+string.digits,k=8))
    enc=encrypt_data(f"{txid}:{number}")
    conn=get_conn();c=conn.cursor()
    c.execute("INSERT INTO transactions(wallet_id,transaction_id,transaction_number,encrypted_data,created_at) VALUES(?,?,?,?,?)",
              (wallet_id,txid,number,enc,datetime.utcnow().isoformat()))
    conn.commit();conn.close()
    return True,"Transaction recorded."

def get_txns(wallet_id):
    conn=get_conn();c=conn.cursor()
    c.execute("SELECT transaction_id,transaction_number,created_at FROM transactions WHERE wallet_id=?",(wallet_id,))
    r=c.fetchall();conn.close();return r

# ---------------------------
# UI Pages
# ---------------------------
def show_home():
    st.title("🔐 Secure FinTech Mini-App")
    st.markdown("This lightweight app demonstrates **secure coding** practices for CY4053 Assignment 2.")
    st.info("Use the sidebar to navigate through secure features — registration, login, wallets, encryption, and logs.")

def show_auth():
    st.header("User Access")
    tab1, tab2 = st.tabs(["🔑 Login","📝 Register"])
    with tab1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            user = login_user(u,p)
            if user:
                st.session_state["uid"]=user["id"]; st.session_state["uname"]=user["username"]
                st.success("Login successful!"); log_action(user["id"],"login")
            else:
                st.error("Invalid credentials.")
    with tab2:
        u = st.text_input("Username", key="ruser")
        e = st.text_input("Email", key="remail")
        p = st.text_input("Password", type="password", key="rpw")
        if st.button("Register"):
            ok,msg = register(u,e,p)
            st.success(msg) if ok else st.error(msg)

def show_wallets():
    st.header("💼 Wallets & Transactions")
    if "uid" not in st.session_state or not st.session_state["uid"]:
        st.warning("Please login first."); return
    with st.form("wform"):
        name=st.text_input("Wallet Name")
        data=st.text_area("Private Data (Encrypted)")
        if st.form_submit_button("Add Wallet"):
            ok,msg=create_wallet(st.session_state["uid"],name,data)
            st.success(msg) if ok else st.error(msg)

    wallets=list_wallets(st.session_state["uid"])
    for w in wallets:
        st.markdown(f"**{w['wallet_name']}**  — *{w['created_at']}*")
        if st.button(f"Decrypt {w['wallet_name']}",key=w["id"]):
            try: st.code(decrypt_data(w["encrypted_data"]))
            except: st.error("Decryption failed.")
        with st.expander("Add Transaction"):
            num=st.text_input("Transaction Number",key=f"tx{w['id']}")
            if st.button("Add",key=f"b{w['id']}"):
                ok,msg=add_txn(w["id"],num); st.success(msg) if ok else st.error(msg)
        if st.button(f"View Txns {w['wallet_name']}",key=f"v{w['id']}"):
            tx=get_txns(w["id"])
            if not tx: st.info("No transactions.")
            else:
                df=pd.DataFrame(tx,columns=["Transaction ID","Number","Created"])
                st.dataframe(df,use_container_width=True)

def show_logs():
    st.header("Activity Logs")
    if "uid" not in st.session_state: st.warning("Login to view logs."); return
    conn=get_conn();c=conn.cursor()
    c.execute("SELECT action,details,timestamp FROM logs WHERE user_id=? ORDER BY id DESC",(st.session_state["uid"],))
    r=c.fetchall();conn.close()
    if not r: st.info("No logs yet."); return
    df=pd.DataFrame(r,columns=["Action","Details","Time"])
    st.dataframe(df,use_container_width=True)

def show_file_upload():
    st.header("Secure File Upload")
    f=st.file_uploader("Upload File",type=ALLOWED_TYPES)
    if f:
        if f.size>MAX_SIZE:
            st.error("File too large (>5 MB).")
        else:
            st.success("✅ File accepted securely.")

# ---------------------------
# Main
# ---------------------------
def main():
    inject_style(); init_db(); init_crypto()
    st.sidebar.title("🔷 Navigation")
    page=st.sidebar.radio("Go to:",["Home","Authentication","Wallets","File Upload","Logs"])
    st.sidebar.markdown("---")
    if "uid" in st.session_state and st.session_state["uid"]:
        st.sidebar.success(f"Logged in as {st.session_state['uname']}")
        if st.sidebar.button("Logout"):
            st.session_state.clear(); st.experimental_rerun()

    if page=="Home": show_home()
    elif page=="Authentication": show_auth()
    elif page=="Wallets": show_wallets()
    elif page=="File Upload": show_file_upload()
    elif page=="Logs": show_logs()

if __name__=="__main__":
    main()

