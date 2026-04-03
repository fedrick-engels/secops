"""
Vulnerable Banking Application
PURPOSE: Demonstrate DevSecOps security scanning
This file INTENTIONALLY contains security vulnerabilities
to show how Bandit (SAST) detects them.
"""

import sqlite3
import pickle
import subprocess
import hashlib
import os

# ================================================================
# VULNERABILITY 1: HARDCODED CREDENTIALS (Bandit: B105, B106)
# TruffleHog and Bandit will detect these
# ================================================================
DB_PASSWORD = "admin123"
SECRET_KEY = "mysecretkey123"
API_KEY = "sk-1234567890abcdef"
ADMIN_PASSWORD = "password123"
DATABASE_URL = "postgresql://admin:admin123@localhost/bankdb"

# ================================================================
# VULNERABILITY 2: WEAK HASHING (Bandit: B303, B324)
# MD5 is cryptographically broken
# ================================================================
def hash_password_weak(password):
    """INSECURE: Uses MD5 which is broken"""
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_weak2(password):
    """INSECURE: Uses SHA1 which is weak"""
    return hashlib.sha1(password.encode()).hexdigest()

# ================================================================
# VULNERABILITY 3: SQL INJECTION (Bandit: B608)
# User input directly in SQL query
# ================================================================
def get_account_balance(username):
    """INSECURE: SQL injection vulnerability"""
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    # DANGEROUS: Direct string formatting in SQL
    query = "SELECT balance FROM accounts WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def login_user(username, password):
    """INSECURE: SQL injection in login"""
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    # DANGEROUS: f-string in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

# ================================================================
# VULNERABILITY 4: COMMAND INJECTION (Bandit: B602, B603)
# Shell injection via user input
# ================================================================
def generate_report(account_id):
    """INSECURE: Command injection vulnerability"""
    # DANGEROUS: shell=True with user input
    subprocess.call("echo Generating report for " + account_id, shell=True)

def get_account_statement(account_id):
    """INSECURE: OS command injection"""
    os.system("cat /reports/" + account_id + ".txt")

# ================================================================
# VULNERABILITY 5: INSECURE DESERIALIZATION (Bandit: B301, B403)
# Pickle can execute arbitrary code
# ================================================================
def load_user_session(session_data):
    """INSECURE: Pickle deserialization"""
    return pickle.loads(session_data)  # DANGEROUS

def save_transaction(transaction):
    """INSECURE: Using pickle to serialize"""
    return pickle.dumps(transaction)

# ================================================================
# VULNERABILITY 6: INSECURE RANDOM (Bandit: B311)
# Using random instead of secrets for tokens
# ================================================================
import random
def generate_otp():
    """INSECURE: Using random instead of secrets"""
    return random.randint(100000, 999999)

def generate_token():
    """INSECURE: Predictable token generation"""
    return str(random.random())

# ================================================================
# VULNERABILITY 7: HARDCODED IP/DEBUG MODE
# ================================================================
DEBUG = True
HOST = "0.0.0.0"
ALLOWED_HOSTS = ["*"]

class BankAccount:
    def __init__(self, account_number, balance):
        self.account_number = account_number
        self.balance = balance
        self.pin = "1234"           # Hardcoded PIN
        self.admin_code = "0000"    # Hardcoded admin code

    def transfer(self, amount, to_account):
        """INSECURE: No authentication check"""
        self.balance -= amount
        print(f"Transferred {amount} to {to_account}")

    def reset_password(self, new_password):
        """INSECURE: No password strength check"""
        self.pin = new_password  # Accepts any password including "1"

if __name__ == "__main__":
    # Demo of vulnerabilities
    print("=== Vulnerable Banking App ===")
    
    # Weak password hashing
    hashed = hash_password_weak("password123")
    print(f"Weak hash: {hashed}")
    
    # Hardcoded credentials used
    print(f"Admin login: admin / {ADMIN_PASSWORD}")
    
    # Insecure OTP
    otp = generate_otp()
    print(f"OTP: {otp}")
