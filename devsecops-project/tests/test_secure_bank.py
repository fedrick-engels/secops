"""
Unit tests for Secure Cryptographic Application
All tests should PASS with zero security issues
"""

import os
import pytest
from cryptography.fernet import Fernet

# Set environment variables before importing
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["SECRET_TOKEN"] = "test-secret-token-for-ci-only-not-production"

from secure_bank import (
    hash_password_secure,
    verify_password_secure,
    generate_otp_secure,
    generate_secure_token,
    generate_secure_api_key,
    encrypt_data_secure,
    decrypt_data_secure,
    compute_on_encrypted,
    save_session_secure,
    load_session_secure,
    init_database,
    create_account_secure,
    get_account_balance_secure,
    login_user_secure,
    transfer_funds_secure,
    generate_request_token,
    verify_request_token,
)


# ── Password Hashing Tests ────────────────────────────────────

def test_password_hash_not_plaintext():
    """Stored hash must not contain the original password."""
    pw = "MySecurePassword123!"
    hashed = hash_password_secure(pw)
    assert pw not in hashed


def test_password_verify_correct():
    """Correct password must verify successfully."""
    pw = "CorrectPassword456!"
    hashed = hash_password_secure(pw)
    assert verify_password_secure(pw, hashed) is True


def test_password_verify_wrong():
    """Wrong password must fail verification."""
    hashed = hash_password_secure("RealPassword789!")
    assert verify_password_secure("WrongPassword000!", hashed) is False


def test_password_hashes_are_unique():
    """Same password must produce different hashes (random salt)."""
    pw = "SamePassword123!"
    hash1 = hash_password_secure(pw)
    hash2 = hash_password_secure(pw)
    assert hash1 != hash2


# ── Token Generation Tests ────────────────────────────────────

def test_otp_is_6_digits():
    """OTP must be exactly 6 digits."""
    otp = generate_otp_secure()
    assert len(otp) == 6
    assert otp.isdigit()


def test_otp_range():
    """OTP must be between 100000 and 999999."""
    for _ in range(20):
        otp = int(generate_otp_secure())
        assert 100000 <= otp <= 999999


def test_tokens_are_unique():
    """Generated tokens must be unique."""
    tokens = {generate_secure_token() for _ in range(50)}
    assert len(tokens) == 50


def test_api_keys_are_unique():
    """API keys must be unique."""
    keys = {generate_secure_api_key() for _ in range(50)}
    assert len(keys) == 50


def test_token_length():
    """Token must meet minimum length requirement."""
    token = generate_secure_token(32)
    assert len(token) >= 40


# ── Encryption Tests ──────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    """Encrypted data must decrypt back to original."""
    plaintext = "sensitive-financial-data-123"
    ciphertext = encrypt_data_secure(plaintext)
    assert decrypt_data_secure(ciphertext) == plaintext


def test_ciphertext_not_plaintext():
    """Ciphertext must not contain the original plaintext."""
    plaintext = "my-secret-data"
    ciphertext = encrypt_data_secure(plaintext)
    assert plaintext not in ciphertext


def test_encryption_is_unique():
    """Same plaintext must produce different ciphertext (IV randomness)."""
    plaintext = "same-data"
    enc1 = encrypt_data_secure(plaintext)
    enc2 = encrypt_data_secure(plaintext)
    assert enc1 != enc2


def test_privacy_preserving_computation():
    """Encrypted addition must produce correct result."""
    enc_a = encrypt_data_secure("42")
    enc_b = encrypt_data_secure("58")
    enc_sum = compute_on_encrypted(enc_a, enc_b)
    assert decrypt_data_secure(enc_sum) == "100"


def test_privacy_preserving_large_numbers():
    """Privacy-preserving computation works with large numbers."""
    enc_a = encrypt_data_secure("99999")
    enc_b = encrypt_data_secure("1")
    enc_sum = compute_on_encrypted(enc_a, enc_b)
    assert decrypt_data_secure(enc_sum) == "100000"


# ── Session Management Tests ──────────────────────────────────

def test_session_save_and_load():
    """Session must save and load correctly."""
    session = {"user_id": "u123", "role": "customer"}
    token = save_session_secure(session)
    loaded = load_session_secure(token)
    assert loaded["user_id"] == "u123"
    assert loaded["role"] == "customer"


def test_tampered_session_rejected():
    """Tampered session token must be rejected."""
    token = save_session_secure({"user_id": "u123"})
    tampered = token[:-5] + "XXXXX"
    result = load_session_secure(tampered)
    assert result is None


def test_invalid_session_rejected():
    """Invalid session token must be rejected."""
    result = load_session_secure("not-a-valid-token")
    assert result is None


# ── Database Tests ────────────────────────────────────────────

@pytest.fixture
def db():
    """Create in-memory test database."""
    conn = init_database()
    yield conn
    conn.close()


def test_create_account(db):
    """Account creation must succeed."""
    result = create_account_secure(db, "testuser", "SecureP@ss123!", 1000.0)
    assert result is True


def test_duplicate_account_rejected(db):
    """Duplicate account creation must fail."""
    create_account_secure(db, "alice", "Pass123!", 500.0)
    result = create_account_secure(db, "alice", "Pass456!", 200.0)
    assert result is False


def test_get_balance(db):
    """Balance retrieval must return correct amount."""
    create_account_secure(db, "bob", "BobP@ss123!", 750.0)
    balance = get_account_balance_secure(db, "bob")
    assert balance == 750.0


def test_nonexistent_account_balance(db):
    """Balance for nonexistent account must return None."""
    balance = get_account_balance_secure(db, "nonexistent")
    assert balance is None


def test_login_correct_password(db):
    """Login with correct password must succeed."""
    create_account_secure(db, "carol", "C@rolPass123!", 0.0)
    result = login_user_secure(db, "carol", "C@rolPass123!")
    assert result is True


def test_login_wrong_password(db):
    """Login with wrong password must fail."""
    create_account_secure(db, "dave", "D@vePass123!", 0.0)
    result = login_user_secure(db, "dave", "wrongpassword")
    assert result is False


def test_transfer_funds(db):
    """Fund transfer must update balances correctly."""
    create_account_secure(db, "sender", "S@nderPass1!", 1000.0)
    create_account_secure(db, "receiver", "R@ceiver1!", 0.0)
    auth_token = generate_request_token()
    result = transfer_funds_secure(db, "sender", "receiver", 300.0, auth_token)
    assert result["success"] is True
    assert get_account_balance_secure(db, "sender") == 700.0
    assert get_account_balance_secure(db, "receiver") == 300.0


def test_transfer_insufficient_funds(db):
    """Transfer with insufficient funds must fail."""
    create_account_secure(db, "poor", "P0orP@ss1!", 100.0)
    create_account_secure(db, "rich", "R1chP@ss1!", 0.0)
    auth_token = generate_request_token()
    result = transfer_funds_secure(db, "poor", "rich", 500.0, auth_token)
    assert result["success"] is False


def test_transfer_unauthorized(db):
    """Transfer without valid auth token must fail."""
    create_account_secure(db, "userA", "P@ssA123!", 1000.0)
    create_account_secure(db, "userB", "P@ssB123!", 0.0)
    result = transfer_funds_secure(db, "userA", "userB", 100.0, "invalid-token")
    assert result["success"] is False


def test_transfer_negative_amount(db):
    """Transfer with negative amount must fail."""
    create_account_secure(db, "userC", "P@ssC123!", 1000.0)
    create_account_secure(db, "userD", "P@ssD123!", 0.0)
    auth_token = generate_request_token()
    result = transfer_funds_secure(db, "userC", "userD", -100.0, auth_token)
    assert result["success"] is False


# ── HMAC Token Tests ──────────────────────────────────────────

def test_valid_request_token():
    """Valid request token must be accepted."""
    token = generate_request_token()
    assert verify_request_token(token) is True


def test_invalid_request_token():
    """Invalid request token must be rejected."""
    assert verify_request_token("fake-token-12345") is False


def test_forged_request_token():
    """Forged token must be rejected."""
    assert verify_request_token("0" * 64) is False
