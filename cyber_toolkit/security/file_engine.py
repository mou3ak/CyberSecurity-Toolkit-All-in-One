"""Professional authenticated file-encryption engine with legacy compatibility."""

import os
import secrets
import struct
import zlib

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as _hashes

# ── V2 / V3  (Argon2id, legacy) ───────────────────────────────────────────────
LEGACY_MAGIC = b"\x89CSTK\x02\r\n"
MAGIC = b"\x89CSTK\x03\r\n"
LEGACY_VERSION = 0x02
VERSION = 0x03
SALT_LEN = 32
NONCE_AES = 12
NONCE_CHA = 12
HEADER_LEN = len(MAGIC) + 1 + 1 + 3 + 1 + SALT_LEN + SALT_LEN + NONCE_AES + NONCE_CHA

DEFAULT_TIME_COST = 4
DEFAULT_MEMORY_COST = 65536
DEFAULT_PARALLELISM = 2
KEY_LEN = 32

# ── V4  (PBKDF2-HMAC-SHA256 + AES-256-GCM) ────────────────────────────────────
V4_MAGIC = b"\x89CSTK\x04\r\n"
V4_VERSION = 0x04
V4_SALT_LEN = 16   # 16-byte random salt
V4_IV_LEN = 12     # 12-byte random IV  (GCM nonce)
PBKDF2_ITERATIONS = 600_000


class FileEncryptionEngine:
    """Two-pass authenticated encryption for user-selected files (V2/V3, Argon2id)."""

    def __init__(
        self,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> None:
        if time_cost < 1 or memory_cost < 8 * 1024 or parallelism < 1:
            raise ValueError("Invalid Argon2id parameters.")
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

    def encrypt(self, plaintext: bytes, password: str) -> bytes:
        """Return a V3 encrypted blob ready to be written to disk."""
        compressed = zlib.compress(plaintext, level=9)

        pad_len = 32 + secrets.randbelow(224)
        padded = struct.pack(">H", pad_len) + secrets.token_bytes(pad_len) + compressed

        salt1 = os.urandom(SALT_LEN)
        salt2 = os.urandom(SALT_LEN)
        nonce_aes = os.urandom(NONCE_AES)
        nonce_cha = os.urandom(NONCE_CHA)

        key_aes = self._derive(password, salt1)
        key_cha = self._derive(password, salt2)
        header = self._build_header(MAGIC, VERSION, self.time_cost, self.memory_cost, self.parallelism, salt1, salt2, nonce_aes, nonce_cha)

        inner_ct = ChaCha20Poly1305(key_cha).encrypt(nonce_cha, padded, header)
        outer_ct = AESGCM(key_aes).encrypt(nonce_aes, inner_ct, header)
        return header + outer_ct

    def decrypt(self, data: bytes, password: str) -> bytes:
        """Decrypt V3 files and keep V2 compatibility for older encrypted files."""
        if data.startswith(MAGIC):
            return self._decrypt_current(data, password)
        if data.startswith(LEGACY_MAGIC):
            return self._decrypt_legacy(data, password)
        raise ValueError("Invalid magic bytes — not a supported .cstk encrypted file.")

    def _decrypt_current(self, data: bytes, password: str) -> bytes:
        if len(data) < HEADER_LEN:
            raise ValueError("File is too short to be a valid .cstk encrypted file.")

        magic, version, time_cost, memory_cost, parallelism, salt1, salt2, nonce_aes, nonce_cha, header_len = self._unpack_header(data)
        if magic != MAGIC or version != VERSION:
            raise ValueError("Unsupported encryption version. Please update the toolkit.")

        outer_ct = data[header_len:]
        key_aes = self._derive(password, salt1, time_cost, memory_cost, parallelism)
        key_cha = self._derive(password, salt2, time_cost, memory_cost, parallelism)
        aad = data[:header_len]

        try:
            inner_ct = AESGCM(key_aes).decrypt(nonce_aes, outer_ct, aad)
        except InvalidTag as exc:
            raise ValueError("Wrong password or file corrupted (outer AES-256-GCM layer).") from exc

        try:
            padded = ChaCha20Poly1305(key_cha).decrypt(nonce_cha, inner_ct, aad)
        except InvalidTag as exc:
            raise ValueError("Wrong password or file corrupted (inner ChaCha20-Poly1305 layer).") from exc

        return self._unpack_plaintext(padded)

    def _decrypt_legacy(self, data: bytes, password: str) -> bytes:
        if len(data) < HEADER_LEN:
            raise ValueError("File is too short to be a valid legacy .cstk encrypted file.")

        _magic, version, time_cost, memory_cost, parallelism, salt1, salt2, nonce_aes, nonce_cha, header_len = self._unpack_header(data)
        if version != LEGACY_VERSION:
            raise ValueError("Unsupported legacy encryption version.")

        outer_ct = data[header_len:]
        key_aes = self._derive(password, salt1, time_cost, memory_cost, parallelism)
        key_cha = self._derive(password, salt2, time_cost, memory_cost, parallelism)

        try:
            inner_ct = AESGCM(key_aes).decrypt(nonce_aes, outer_ct, None)
        except InvalidTag as exc:
            raise ValueError("Wrong password or file corrupted (outer AES-256-GCM layer).") from exc

        try:
            padded = ChaCha20Poly1305(key_cha).decrypt(nonce_cha, inner_ct, None)
        except InvalidTag as exc:
            raise ValueError("Wrong password or file corrupted (inner ChaCha20-Poly1305 layer).") from exc

        return self._unpack_plaintext(padded)

    @staticmethod
    def _build_header(
        magic: bytes,
        version: int,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        salt1: bytes,
        salt2: bytes,
        nonce_aes: bytes,
        nonce_cha: bytes,
    ) -> bytes:
        memory_cost_bytes = struct.pack(">I", memory_cost)[1:]
        return (
            magic
            + struct.pack("B", version)
            + struct.pack("B", time_cost)
            + memory_cost_bytes
            + struct.pack("B", parallelism)
            + salt1
            + salt2
            + nonce_aes
            + nonce_cha
        )

    @staticmethod
    def _unpack_header(data: bytes) -> tuple[bytes, int, int, int, int, bytes, bytes, bytes, bytes, int]:
        off = len(MAGIC)
        magic = data[:off]
        version = data[off]
        off += 1
        time_cost = data[off]
        off += 1
        memory_cost = struct.unpack(">I", b"\x00" + data[off:off + 3])[0]
        off += 3
        parallelism = data[off]
        off += 1
        salt1 = data[off: off + SALT_LEN]
        off += SALT_LEN
        salt2 = data[off: off + SALT_LEN]
        off += SALT_LEN
        nonce_aes = data[off: off + NONCE_AES]
        off += NONCE_AES
        nonce_cha = data[off: off + NONCE_CHA]
        off += NONCE_CHA
        return magic, version, time_cost, memory_cost, parallelism, salt1, salt2, nonce_aes, nonce_cha, off

    @staticmethod
    def _unpack_plaintext(padded: bytes) -> bytes:
        if len(padded) < 2:
            raise ValueError("Encrypted payload is truncated.")

        pad_len = struct.unpack_from(">H", padded, 0)[0]
        if len(padded) < 2 + pad_len:
            raise ValueError("Encrypted payload padding is invalid.")

        compressed = padded[2 + pad_len:]
        try:
            return zlib.decompress(compressed)
        except zlib.error as exc:
            raise ValueError(f"Decompression failed — file may be corrupted: {exc}") from exc

    def _derive(
        self,
        password: str,
        salt: bytes,
        time_cost: int | None = None,
        memory_cost: int | None = None,
        parallelism: int | None = None,
    ) -> bytes:
        if not password:
            raise ValueError("Password cannot be empty.")
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost if time_cost is not None else self.time_cost,
            memory_cost=memory_cost if memory_cost is not None else self.memory_cost,
            parallelism=parallelism if parallelism is not None else self.parallelism,
            hash_len=KEY_LEN,
            type=Type.ID,
        )


# ── V4 engine — PBKDF2-HMAC-SHA256 + AES-256-GCM ─────────────────────────────

class FileEncryptionEngineV4:
    """
    V4 file encryption engine.

    Encryption format (binary, concatenated):
        MAGIC   (8 bytes)  — b"\\x89CSTK\\x04\\r\\n"
        VERSION (1 byte)   — 0x04
        SALT    (16 bytes) — random, used for PBKDF2 key derivation
        IV      (12 bytes) — random nonce for AES-256-GCM
        CIPHERTEXT+TAG     — AES-256-GCM output (plaintext length + 16-byte tag)

    Key derivation: PBKDF2-HMAC-SHA256, 600 000 iterations, 32-byte output.

    Legacy V2/V3 files (Argon2id) are automatically detected and decrypted via
    the ``FileEncryptionEngine`` fallback.
    """

    def encrypt(self, plaintext: bytes, password: str) -> bytes:
        """Encrypt *plaintext* and return the complete V4 binary blob."""
        if not password:
            raise ValueError("Password cannot be empty.")
        salt = os.urandom(V4_SALT_LEN)
        iv   = os.urandom(V4_IV_LEN)
        key  = self._derive_key(password, salt)
        ciphertext_and_tag = AESGCM(key).encrypt(iv, plaintext, None)
        return V4_MAGIC + bytes([V4_VERSION]) + salt + iv + ciphertext_and_tag

    def decrypt(self, data: bytes, password: str) -> bytes:
        """Decrypt *data*.  Handles V4 natively; delegates V2/V3 to legacy engine."""
        if data.startswith(V4_MAGIC):
            return self._decrypt_v4(data, password)
        # Fallback: V3 / V2 Argon2id format
        return FileEncryptionEngine().decrypt(data, password)

    # ── internals ──────────────────────────────────────────────────────────────

    def _decrypt_v4(self, data: bytes, password: str) -> bytes:
        min_len = len(V4_MAGIC) + 1 + V4_SALT_LEN + V4_IV_LEN + 16  # +16 GCM tag
        if len(data) < min_len:
            raise ValueError("File too short to be a valid V4 .cstk encrypted file.")
        off  = len(V4_MAGIC) + 1          # skip MAGIC + VERSION byte
        salt = data[off: off + V4_SALT_LEN]; off += V4_SALT_LEN
        iv   = data[off: off + V4_IV_LEN];   off += V4_IV_LEN
        ciphertext_and_tag = data[off:]
        key  = self._derive_key(password, salt)
        try:
            return AESGCM(key).decrypt(iv, ciphertext_and_tag, None)
        except InvalidTag as exc:
            raise ValueError(
                "Authentication failed — wrong password or file is corrupted."
            ) from exc

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Return a 256-bit key via PBKDF2-HMAC-SHA256 (600 000 iterations)."""
        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))
