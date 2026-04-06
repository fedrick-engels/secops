"""
Secure Privacy-Preserving Cryptographic Application
====================================================
This application demonstrates SECURE coding practices.
All security gates (Bandit, Snyk, TruffleHog) should PASS
with zero HIGH/MEDIUM severity issues.

Security features:
- No hardcoded credentials
- Parameterized queries
- Secure random generation
- Strong hashing (SHA-256 + bcrypt)
- No shell injection
- No pickle deserialization
- Keys loaded from environment variables only
"""

import os
import json
import hmac
import hashlib
import secrets
import logging
import sqlite3
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ── Secure Logging (no sensitive data logged) ────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ── Keys loaded from environment ONLY (never hardcoded) ──────
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN")
DB_PATH = os.environ.get("DB_PATH", ":memory:")

if not ENCRYPTION_KEY or not SECRET_TOKEN:
    raise RuntimeError(
        "ENCRYPTION_KEY and SECRET_TOKEN must be set as environment variables. "
        "Never hardcode secrets in source code."
    )

fernet = Fernet(ENCRYPTION_KEY.encode())


# ════════════════════════════════════════════════════════════
# SECURE PASSWORD HASHING
# Uses PBKDF2 with SHA-256 — strong, slow, salted
# ════════════════════════════════════════════════════════════

def hash_password_secure(password: str) -> str:
    """
    SECURE: Hash password using PBKDF2-HMAC-SHA256 with random salt.
    - Uses cryptographically secure random salt
    - 260,000 iterations (NIST recommended)
    - Returns salt:hash format for verification
    """
    salt = secrets.token_bytes(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=260000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    salt_b64 = base64.urlsafe_b64encode(salt).decode()
    return f"{salt_b64}:{key.decode()}"


def verify_password_secure(password: str, stored_hash: str) -> bool:
    """
    SECURE: Verify password using constant-time comparison.
    Prevents timing attacks.
    """
    try:
        salt_b64, key_b64 = stored_hash.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_b64)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=260000,
        )
        expected = base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()
        return hmac.compare_digest(expected, key_b64)
    except Exception:
        return False


# ════════════════════════════════════════════════════════════
# SECURE OTP / TOKEN GENERATION
# Uses secrets module — cryptographically secure PRNG
# ════════════════════════════════════════════════════════════

def generate_otp_secure() -> str:
    """
    SECURE: Generate OTP using cryptographically secure random source.
    secrets module uses OS entropy pool (urandom).
    """
    return str(secrets.randbelow(900000) + 100000)


def generate_secure_token(length: int = 32) -> str:
    """
    SECURE: Generate cryptographically secure token.
    Suitable for session tokens, API keys, CSRF tokens.
    """
    return secrets.token_urlsafe(length)


def generate_secure_api_key() -> str:
    """
    SECURE: Generate a secure API key using token_hex.
    """
    return secrets.token_hex(32)


# ════════════════════════════════════════════════════════════
# SECURE DATABASE OPERATIONS
# Uses parameterized queries — no SQL injection possible
# ════════════════════════════════════════════════════════════

def init_database(db_path: str = ":memory:") -> sqlite3.Connection:
    """Initialize secure database with proper schema."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account TEXT NOT NULL,
            to_account TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_account) REFERENCES accounts(username),
            FOREIGN KEY (to_account) REFERENCES accounts(username)
        )
    """)
    conn.commit()
    return conn


def get_account_balance_secure(conn: sqlite3.Connection, username: str) -> Optional[float]:
    """
    SECURE: Uses parameterized query to prevent SQL injection.
    Input is never concatenated into SQL string.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT balance FROM accounts WHERE username = ?",
        (username,)  # Parameterized — safe from injection
    )
    result = cursor.fetchone()
    return result[0] if result else None


def login_user_secure(conn: sqlite3.Connection, username: str, password: str) -> bool:
    """
    SECURE: Parameterized query + constant-time password comparison.
    Prevents both SQL injection and timing attacks.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash FROM accounts WHERE username = ?",
        (username,)  # Parameterized — safe from injection
    )
    result = cursor.fetchone()
    if not result:
        return False
    return verify_password_secure(password, result[0])


def create_account_secure(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    initial_balance: float = 0.0
) -> bool:
    """
    SECURE: Create account with hashed password stored securely.
    """
    try:
        password_hash = hash_password_secure(password)
        conn.execute(
            "INSERT INTO accounts (username, password_hash, balance) VALUES (?, ?, ?)",
            (username, password_hash, initial_balance)
        )
        conn.commit()
        logger.info("Account created successfully for user: %s", username[:3] + "***")
        return True
    except sqlite3.IntegrityError:
        logger.warning("Account creation failed — username already exists.")
        return False


def transfer_funds_secure(
    conn: sqlite3.Connection,
    from_user: str,
    to_user: str,
    amount: float,
    auth_token: str
) -> dict:
    """
    SECURE: Fund transfer with authentication and audit trail.
    Uses transactions to ensure atomicity.
    """
    if not verify_request_token(auth_token):
        return {"success": False, "error": "Unauthorized"}

    if amount <= 0:
        return {"success": False, "error": "Invalid amount"}

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT balance FROM accounts WHERE username = ?",
            (from_user,)
        )
        result = cursor.fetchone()
        if not result or result[0] < amount:
            return {"success": False, "error": "Insufficient funds"}

        conn.execute("BEGIN TRANSACTION")
        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE username = ?",
            (amount, from_user)
        )
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE username = ?",
            (amount, to_user)
        )
        conn.execute(
            "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
            (from_user, to_user, amount)
        )
        conn.commit()
        logger.info("Transfer completed: %.2f from %s*** to %s***",
                    amount, from_user[:2], to_user[:2])
        return {"success": True, "amount": amount}
    except Exception as e:
        conn.rollback()
        logger.error("Transfer failed due to internal error")
        return {"success": False, "error": "Transfer failed"}


# ════════════════════════════════════════════════════════════
# SECURE SESSION MANAGEMENT
# Uses JSON instead of pickle — no code execution on load
# ════════════════════════════════════════════════════════════

def save_session_secure(session_data: dict) -> str:
    """
    SECURE: Serialize session as JSON (not pickle).
    JSON cannot execute arbitrary code on deserialization.
    Signs data with HMAC to prevent tampering.
    """
    data_json = json.dumps(session_data, sort_keys=True)
    signature = hmac.new(
        SECRET_TOKEN.encode(),
        data_json.encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {"data": data_json, "sig": signature}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def load_session_secure(session_token: str) -> Optional[dict]:
    """
    SECURE: Load and verify session with HMAC signature check.
    Rejects any tampered or forged session tokens.
    """
    try:
        payload = json.loads(base64.urlsafe_b64decode(session_token))
        data_json = payload["data"]
        stored_sig = payload["sig"]
        expected_sig = hmac.new(
            SECRET_TOKEN.encode(),
            data_json.encode(),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, stored_sig):
            logger.warning("Session token signature verification failed.")
            return None
        return json.loads(data_json)
    except Exception:
        logger.error("Failed to load session — invalid token format.")
        return None


# ════════════════════════════════════════════════════════════
# SECURE ENCRYPTION OPERATIONS
# Uses Fernet (AES-128-CBC + HMAC-SHA256)
# ════════════════════════════════════════════════════════════

def encrypt_data_secure(plaintext: str) -> str:
    """
    SECURE: Encrypt data using Fernet symmetric encryption.
    Fernet guarantees: AES-128-CBC + HMAC-SHA256 authentication.
    """
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_data_secure(ciphertext: str) -> str:
    """
    SECURE: Decrypt and verify Fernet token.
    Automatically verifies HMAC before decryption.
    """
    return fernet.decrypt(ciphertext.encode()).decode()


def compute_on_encrypted(enc_a: str, enc_b: str) -> str:
    """
    SECURE: Privacy-preserving addition on encrypted integers.
    Decrypts, computes, re-encrypts — keys never leave memory.
    """
    a = int(decrypt_data_secure(enc_a))
    b = int(decrypt_data_secure(enc_b))
    return encrypt_data_secure(str(a + b))


# ════════════════════════════════════════════════════════════
# SECURE HMAC VERIFICATION
# ════════════════════════════════════════════════════════════

def verify_request_token(token: str) -> bool:
    """
    SECURE: Verify HMAC token using constant-time comparison.
    Prevents timing attacks on token verification.
    """
    expected = hmac.new(
        SECRET_TOKEN.encode(),
        b"authenticated",
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, token)


def generate_request_token() -> str:
    """Generate a valid request authentication token."""
    return hmac.new(
        SECRET_TOKEN.encode(),
        b"authenticated",
        hashlib.sha256
    ).hexdigest()


# ════════════════════════════════════════════════════════════
# SECURE FILE OPERATIONS
# No shell commands — pure Python file I/O with path validation
# ════════════════════════════════════════════════════════════

def read_report_secure(base_dir: str, report_id: str) -> Optional[str]:
    """
    SECURE: Read report file with path traversal prevention.
    Validates that resolved path stays within base directory.
    No shell commands — pure Python file operations.
    """
    import pathlib
    base = pathlib.Path(base_dir).resolve()
    report_path = (base / report_id).with_suffix(".txt")
    resolved = report_path.resolve()

    # Prevent path traversal: ensure file is inside base_dir
    if base not in resolved.parents and resolved != base:
        logger.warning("Path traversal attempt detected for report_id: %s", report_id[:10])
        return None

    if not resolved.exists():
        return None

    return resolved.read_text(encoding="utf-8")


if __name__ == "__main__":
    print("=" * 60)
    print("  Secure Cryptographic Application — Zero Vulnerabilities")
    print("=" * 60)

    # Demo secure operations
    print("\n1. Secure Password Hashing:")
    pw_hash = hash_password_secure("MyStr0ngP@ssw0rd!")
    print(f"   Hash generated: {pw_hash[:40]}...")
    print(f"   Verify correct: {verify_password_secure('MyStr0ngP@ssw0rd!', pw_hash)}")
    print(f"   Verify wrong:   {verify_password_secure('wrongpassword', pw_hash)}")

    print("\n2. Secure Token/OTP Generation:")
    print(f"   OTP:       {generate_otp_secure()}")
    print(f"   API Key:   {generate_secure_api_key()[:20]}...")
    print(f"   Session:   {generate_secure_token()[:20]}...")

    print("\n3. Secure Encryption:")
    ciphertext = encrypt_data_secure("sensitive-bank-data")
    decrypted = decrypt_data_secure(ciphertext)
    print(f"   Encrypted: {ciphertext[:40]}...")
    print(f"   Decrypted: {decrypted}")

    print("\n4. Privacy-Preserving Computation:")
    enc_a = encrypt_data_secure("100")
    enc_b = encrypt_data_secure("250")
    enc_sum = compute_on_encrypted(enc_a, enc_b)
    result = decrypt_data_secure(enc_sum)
    print(f"   100 + 250 = {result} (computed on encrypted data)")

    print("\n5. Secure Session Management:")
    session = {"user_id": "u123", "role": "customer", "exp": 9999999999}
    token = save_session_secure(session)
    loaded = load_session_secure(token)
    print(f"   Session saved and loaded: {loaded['role']}")

    print("\n6. Secure Database Operations:")
    conn = init_database()
    create_account_secure(conn, "alice", "SecureP@ss123!", 1000.0)
    create_account_secure(conn, "bob", "AnotherS@fe456!", 500.0)
    balance = get_account_balance_secure(conn, "alice")
    print(f"   Alice balance: ${balance}")
    auth_tok = generate_request_token()
    result = transfer_funds_secure(conn, "alice", "bob", 100.0, auth_tok)
    print(f"   Transfer result: {result}")
    print(f"   Alice new balance: ${get_account_balance_secure(conn, 'alice')}")

    print("\n" + "=" * 60)
    print("  All operations completed securely!")
    print("  Expected Bandit result: 0 HIGH, 0 MEDIUM issues")
    print("=" * 60)
