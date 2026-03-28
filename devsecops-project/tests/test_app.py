"""
Unit tests for Privacy-Preserving Application
"""

import os
import pytest
from cryptography.fernet import Fernet

# Set test environment variables before importing app
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["SECRET_TOKEN"] = "test-secret-token-for-ci-only"

from app.main import app, encrypt_data, decrypt_data


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_check(client):
    """Health endpoint returns 200."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"


def test_encrypt_decrypt_roundtrip(client):
    """Data encrypted and decrypted returns original value."""
    original = "sensitive-data-123"
    enc_resp = client.post("/encrypt", json={"data": original})
    assert enc_resp.status_code == 200
    ciphertext = enc_resp.get_json()["encrypted"]

    dec_resp = client.post("/decrypt", json={"data": ciphertext})
    assert dec_resp.status_code == 200
    assert dec_resp.get_json()["decrypted"] == original


def test_encrypt_missing_data(client):
    """Encrypt endpoint returns 400 for missing data."""
    resp = client.post("/encrypt", json={})
    assert resp.status_code == 400


def test_decrypt_invalid_data(client):
    """Decrypt endpoint returns 500 for invalid ciphertext."""
    resp = client.post("/decrypt", json={"data": "not-valid-ciphertext"})
    assert resp.status_code == 500


def test_compute_on_encrypted(client):
    """Privacy-preserving computation returns correct encrypted sum."""
    enc_a = client.post("/encrypt", json={"data": "10"}).get_json()["encrypted"]
    enc_b = client.post("/encrypt", json={"data": "20"}).get_json()["encrypted"]

    resp = client.post("/compute", json={"enc_a": enc_a, "enc_b": enc_b})
    assert resp.status_code == 200

    enc_result = resp.get_json()["enc_result"]
    dec_resp = client.post("/decrypt", json={"data": enc_result})
    assert dec_resp.get_json()["decrypted"] == "30"


def test_encrypt_decrypt_helpers():
    """Direct helper function tests."""
    plaintext = "hello-privacy"
    ciphertext = encrypt_data(plaintext)
    assert ciphertext != plaintext
    assert decrypt_data(ciphertext) == plaintext
