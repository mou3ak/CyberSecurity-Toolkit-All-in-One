import json
from pathlib import Path

from cyber_toolkit.config import FILE_MAGIC
from cyber_toolkit.security.crypto_utils import decrypt_bytes, encrypt_bytes


class FileCipher:
    def encrypt_file(self, source_path: str, password: str, output_path: str | None = None) -> Path:
        source = Path(source_path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError("Source file was not found")

        plaintext = FILE_MAGIC + source.read_bytes()
        payload = encrypt_bytes(plaintext, password)
        target = Path(output_path) if output_path else source.with_suffix(source.suffix + ".cstk")
        target.write_text(json.dumps(payload), encoding="utf-8")
        return target

    def decrypt_file(self, encrypted_path: str, password: str, output_path: str | None = None) -> Path:
        source = Path(encrypted_path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        plaintext = decrypt_bytes(payload, password)
        if not plaintext.startswith(FILE_MAGIC):
            raise ValueError("Invalid key or corrupted file")

        raw = plaintext[len(FILE_MAGIC):]
        if output_path:
            target = Path(output_path)
        elif source.suffix == ".cstk":
            target = source.with_suffix("")
        else:
            target = source.with_name(source.name + ".dec")

        target.write_bytes(raw)
        return target

