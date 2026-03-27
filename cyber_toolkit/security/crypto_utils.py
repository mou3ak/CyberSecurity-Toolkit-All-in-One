import base64
import os
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KDF_ITERATIONS = 390_000
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> Dict[str, Any]:
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": KDF_ITERATIONS,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }


def decrypt_bytes(payload: Dict[str, Any], password: str) -> bytes:
    salt = _b64decode(payload["salt"])
    nonce = _b64decode(payload["nonce"])
    ciphertext = _b64decode(payload["ciphertext"])
    iterations = int(payload.get("iterations", KDF_ITERATIONS))
    key = derive_key(password, salt, iterations=iterations)
    return AESGCM(key).decrypt(nonce, ciphertext, None)

