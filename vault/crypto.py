import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt(data: bytes, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Fernet(key)

    encrypted = cipher.encrypt(data)

    # ALWAYS return STRINGS for JSON safety
    return (
        base64.b64encode(salt).decode(),
        base64.b64encode(encrypted).decode()
    )


def decrypt(encrypted_b64: str, password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    encrypted = base64.b64decode(encrypted_b64)

    key = derive_key(password, salt)
    cipher = Fernet(key)

    # IMPORTANT: return BYTES only
    return cipher.decrypt(encrypted)