"""
FileCipher — encrypts / decrypts files using the professional FileEncryptionEngine.

Encryption always uses V2 (Argon2id + ChaCha20-Poly1305 + AES-256-GCM, binary format).
Decryption auto-detects V1 (legacy JSON) or V2 (new binary) format.
"""
import json
from pathlib import Path

from cyber_toolkit.config import FILE_MAGIC
from cyber_toolkit.security.crypto_utils import decrypt_bytes  # legacy V1
from cyber_toolkit.security.file_engine import MAGIC as V2_MAGIC, FileEncryptionEngine

_engine = FileEncryptionEngine()


class FileCipher:
    def encrypt_file(self, source_path: str, password: str, output_path: str | None = None) -> Path:
        source = Path(source_path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError("Source file was not found")

        plaintext = FILE_MAGIC + source.read_bytes()
        ciphertext = _engine.encrypt(plaintext, password)

        target = Path(output_path) if output_path else source.with_suffix(source.suffix + ".cstk")
        target.write_bytes(ciphertext)
        return target

    def decrypt_file(self, encrypted_path: str, password: str, output_path: str | None = None) -> Path:
        source = Path(encrypted_path)
        raw = source.read_bytes()

        # Auto-detect format
        if raw.startswith(V2_MAGIC):
            plaintext = _engine.decrypt(raw, password)
        else:
            # Legacy V1: JSON-encoded encrypted payload
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                raise ValueError("Unrecognised file format — cannot decrypt.")
            plaintext = decrypt_bytes(payload, password)

        if not plaintext.startswith(FILE_MAGIC):
            raise ValueError("Wrong password or corrupted file.")

        file_bytes = plaintext[len(FILE_MAGIC):]

        if output_path:
            target = Path(output_path)
        elif source.suffix == ".cstk":
            target = source.with_suffix("")
        else:
            target = source.with_name(source.name + ".dec")

        target.write_bytes(file_bytes)
        return target

