"""User-controlled file encryption with metadata-aware restore.

New files are encrypted with V4 (PBKDF2-HMAC-SHA256 + AES-256-GCM).
Legacy V2/V3 (Argon2id) files are automatically detected and decrypted.
"""

import json
import os
import struct
import uuid
from pathlib import Path

from cyber_toolkit.config import FILE_MAGIC
from cyber_toolkit.security.crypto_utils import decrypt_bytes                       # legacy V1
from cyber_toolkit.security.file_engine import (
    LEGACY_MAGIC as V2_MAGIC,
    MAGIC        as V3_MAGIC,
    V4_MAGIC,
    FileEncryptionEngineV4,
)

# Active engine – V4 (PBKDF2-HMAC-SHA256).  Decryption auto-falls back to V2/V3.
_engine = FileEncryptionEngineV4()
MANIFEST_MAGIC = b"FM01"


class FileCipher:
    def encrypt_file(self, source_path: str, password: str, output_path: str | None = None) -> Path:
        source = Path(source_path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError("Source file was not found")

        plaintext  = self._pack_payload(source)
        ciphertext = _engine.encrypt(plaintext, password)

        target = Path(output_path) if output_path else self._build_encrypted_target(source)
        self._write_bytes_atomic(target, ciphertext)
        return target

    def decrypt_file(self, encrypted_path: str, password: str, output_path: str | None = None) -> Path:
        source = Path(encrypted_path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError("Encrypted file was not found")
        raw = source.read_bytes()

        # Auto-detect format: V4 / V3 / V2 all handled by the V4 engine
        if raw.startswith(V4_MAGIC) or raw.startswith(V3_MAGIC) or raw.startswith(V2_MAGIC):
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

        metadata, file_bytes = self._unpack_payload(plaintext)

        target = Path(output_path) if output_path else self._build_decrypted_target(source, metadata)
        self._write_bytes_atomic(target, file_bytes)
        return target

    @staticmethod
    def _pack_payload(source: Path) -> bytes:
        file_bytes = source.read_bytes()
        metadata = {
            "version": 2,
            "original_name": source.name,
            "original_suffix": source.suffix,
            "size": len(file_bytes),
            "mtime_ns": source.stat().st_mtime_ns,
        }
        metadata_blob = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
        return FILE_MAGIC + MANIFEST_MAGIC + struct.pack(">I", len(metadata_blob)) + metadata_blob + file_bytes

    @staticmethod
    def _unpack_payload(plaintext: bytes) -> tuple[dict, bytes]:
        body = plaintext[len(FILE_MAGIC):]
        if not body.startswith(MANIFEST_MAGIC):
            return {}, body
        if len(body) < len(MANIFEST_MAGIC) + 4:
            raise ValueError("Encrypted payload metadata is truncated.")
        offset = len(MANIFEST_MAGIC)
        metadata_len = struct.unpack(">I", body[offset:offset + 4])[0]; offset += 4
        metadata_raw = body[offset:offset + metadata_len]
        if len(metadata_raw) != metadata_len:
            raise ValueError("Encrypted payload metadata is incomplete.")
        try:
            metadata = json.loads(metadata_raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Encrypted payload metadata is invalid.") from exc
        return metadata, body[offset + metadata_len:]

    def _build_encrypted_target(self, source: Path) -> Path:
        return self._make_unique_path(source.with_name(source.name + ".cstk"), label="encrypted")

    def _build_decrypted_target(self, source: Path, metadata: dict) -> Path:
        original_name = metadata.get("original_name") if metadata else None
        if original_name:
            return self._make_unique_path(source.with_name(original_name), label="decrypted")
        if source.suffix == ".cstk":
            return self._make_unique_path(source.with_suffix(""), label="decrypted")
        return self._make_unique_path(source.with_name(source.name + ".dec"), label="decrypted")

    @staticmethod
    def _make_unique_path(target: Path, label: str) -> Path:
        if not target.exists():
            return target
        base_name = f"{target.stem}.{label}{target.suffix}" if target.suffix else f"{target.name}.{label}"
        candidate = target.with_name(base_name)
        if not candidate.exists():
            return candidate
        for index in range(1, 1000):
            numbered = (
                candidate.with_name(f"{candidate.stem}-{index}{candidate.suffix}")
                if candidate.suffix else candidate.with_name(f"{candidate.name}-{index}")
            )
            if not numbered.exists():
                return numbered
        raise FileExistsError("Could not find a free output filename.")

    @staticmethod
    def _write_bytes_atomic(target: Path, payload: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_target = target.with_name(f"{target.name}.tmp-{uuid.uuid4().hex}")
        temp_target.write_bytes(payload)
        try:
            os.replace(temp_target, target)
        finally:
            if temp_target.exists():
                temp_target.unlink(missing_ok=True)

