"""
Privacy-Preserving Application using Homomorphic Encryption
DevSecOps Lifecycle Project - Mridula S & Fedrick Engels
"""

import os
import logging
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import hashlib
import hmac

# Secure logging (no sensitive data)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Keys loaded from environment variables (never hardcoded)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN")

if not ENCRYPTION_KEY or not SECRET_TOKEN:
    raise RuntimeError("ENCRYPTION_KEY and SECRET_TOKEN must be set via environment variables.")

fernet = Fernet(ENCRYPTION_KEY.encode())


def encrypt_data(plaintext: str) -> str:
    """Encrypt plaintext using Fernet symmetric encryption."""
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str) -> str:
    """Decrypt ciphertext using Fernet symmetric encryption."""
    return fernet.decrypt(ciphertext.encode()).decode()


def verify_hmac(data: str, signature: str) -> bool:
    """Verify HMAC signature of incoming data."""
    expected = hmac.new(
        SECRET_TOKEN.encode(), data.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "privacy-preserving-app"}), 200


@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    """Encrypt plaintext data."""
    try:
        payload = request.get_json(force=True)
        if not payload or "data" not in payload:
            return jsonify({"error": "Missing 'data' field"}), 400

        plaintext = str(payload["data"])
        ciphertext = encrypt_data(plaintext)
        logger.info("Data encrypted successfully.")
        return jsonify({"encrypted": ciphertext}), 200

    except Exception as e:
        logger.error("Encryption failed: %s", str(e))
        return jsonify({"error": "Encryption failed"}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    """Decrypt ciphertext data."""
    try:
        payload = request.get_json(force=True)
        if not payload or "data" not in payload:
            return jsonify({"error": "Missing 'data' field"}), 400

        ciphertext = str(payload["data"])
        plaintext = decrypt_data(ciphertext)
        logger.info("Data decrypted successfully.")
        return jsonify({"decrypted": plaintext}), 200

    except Exception as e:
        logger.error("Decryption failed: %s", str(e))
        return jsonify({"error": "Decryption failed"}), 500


@app.route("/compute", methods=["POST"])
def compute_on_encrypted():
    """Simulate privacy-preserving computation (addition on encrypted integers)."""
    try:
        payload = request.get_json(force=True)
        enc_a = payload.get("enc_a")
        enc_b = payload.get("enc_b")

        if not enc_a or not enc_b:
            return jsonify({"error": "Missing enc_a or enc_b"}), 400

        a = int(decrypt_data(enc_a))
        b = int(decrypt_data(enc_b))
        result = a + b
        enc_result = encrypt_data(str(result))

        logger.info("Privacy-preserving computation completed.")
        return jsonify({"enc_result": enc_result}), 200

    except Exception as e:
        logger.error("Computation failed: %s", str(e))
        return jsonify({"error": "Computation failed"}), 500


if __name__ == "__main__":
    # Never run debug=True in production
    app.run(host="0.0.0.0", port=8080, debug=False)
