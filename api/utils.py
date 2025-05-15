import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from api.conf import AES_KEY


def hash_password(password: str, salt: bytes = None) -> dict:
    """Hash a password with PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return {
        'salt': base64.b64encode(salt).decode(),
        'hash': base64.b64encode(key).decode()
    }


def verify_password(stored_hash: str, stored_salt: str, input_password: str) -> bool:
    """Verify a password against the stored hash and salt."""
    salt = base64.b64decode(stored_salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    try:
        kdf.verify(input_password.encode(), base64.b64decode(stored_hash))
        return True
    except Exception:
        return False


def hash_email(email: str) -> str:
    """Return a SHA-256 hash of the email (lowercased and stripped)."""
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()


def encrypt_field(plaintext: str) -> dict:
    """Encrypt a field using AES-GCM."""
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(AES_KEY),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return {
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(encryptor.tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }


def decrypt_field(data: dict) -> bytes:
    """Decrypt a field that was encrypted with AES-GCM."""
    iv = base64.b64decode(data['iv'])
    tag = base64.b64decode(data['tag'])
    ciphertext = base64.b64decode(data['ciphertext'])
    decryptor = Cipher(
        algorithms.AES(AES_KEY),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()