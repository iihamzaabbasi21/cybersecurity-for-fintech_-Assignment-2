# 🛡 Cyber Guard — FinTech Application

**Course:** CY4053 — Cybersecurity for FinTech  
**Instructor:** Dr. Usama Arshad  
**Student:** Hamza Abbasi  
**Reg. No:** i226169  
**University:** FAST – National University of Computer and Emerging Sciences  

---

## 💡 Overview

**Cyber Guard — FinTech Application** is a secure web-based system developed for **CY4053 Assignment 2**.  
It demonstrates **secure coding practices**, focusing on the implementation of confidentiality, integrity, and authentication using modern cybersecurity techniques.

The app is built using **Streamlit** and **Python**, simulating a FinTech platform that securely handles user data, encrypted wallet information, and transactions.

---

## ⚙️ Features

✅ **Secure Authentication**  
- Passwords hashed with `bcrypt`  
- Validation against weak and common passwords  
- Input sanitization to prevent SQL injection  

✅ **Encrypted Wallet Management**  
- Create wallets that store encrypted financial data  
- Add transactions linked to specific wallets  
- Use `cryptography.Fernet` for symmetric encryption  

✅ **Audit Logging**  
- Records user actions (registration, login, wallet creation, etc.)  
- Logs stored in a local SQLite database for traceability  

✅ **File Upload Validation**  
- Accepts limited file types (`png, jpg, jpeg, pdf, csv, txt`)  
- Rejects files larger than **5 MB**  
- Prevents malicious file uploads  

✅ **Modern Green Cyber Theme**  
- Aesthetic and professional green cyber interface  
- Built using **Streamlit custom CSS** and **Poppins font**  

---

## 🧠 Security Highlights

- **Input Sanitization:** Prevents injection attacks and malicious inputs  
- **Password Policy Enforcement:** Requires uppercase, lowercase, number, and special character  
- **Secure Hashing:** Uses `bcrypt` for non-reversible password storage  
- **Encryption:** Protects sensitive wallet and transaction data with `Fernet` keys  
- **Error Handling:** Gracefully manages exceptions to avoid data leaks  

---

## 📦 Installation Guide

1. **Clone the Repository**
   ```bash
   git clone https://github.com/<your-username>/cyber-guard-fintech.git
   cd cyber-guard-fintech
