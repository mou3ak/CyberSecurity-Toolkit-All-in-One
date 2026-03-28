"""
FileEncryptionEngine — Professional double-layer authenticated encryption.

Encryption pipeline:
    plaintext
      │
      ▼ zlib compress (level 9)
      │
      ▼ prepend 2-byte big-endian pad_len + random_pad_len_bytes
      │
      ▼ Inner:  ChaCha20-Poly1305  (key = Argon2id(password, salt2))
      │
      ▼ Outer:  AES-256-GCM        (key = Argon2id(password, salt1))
      │
      ▼ binary blob written to disk

Binary file format
──────────────────
 offset   len  field
 0        8    MAGIC  = b'\\x89CSTK\\x02\\r\\n'
 8        1    VERSION (0x02)
 9        1    Argon2id time_cost   (uint8)
 10       3    Argon2id memory_cost (uint24, big-endian, value in KiB)
 13       1    Argon2id parallelism (uint8)
 14       32   SALT1  (outer AES key)
 46       32   SALT2  (inner ChaCha20 key)
 78       12   NONCE_AES
 90       12   NONCE_CHA
 102      …    CIPHERTEXT  (double-encrypted blob, includes two AEAD auth tags)
"""
import os
import struct
import zlib
import secrets

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ── File format constants ──────────────────────────────────────────────────────
MAGIC        = b"\x89CSTK\x02\r\n"   # 8 bytes
VERSION      = 0x02
SALT_LEN     = 32
NONCE_AES    = 12
NONCE_CHA    = 12
HEADER_LEN   = len(MAGIC) + 1 + 1 + 3 + 1 + SALT_LEN + SALT_LEN + NONCE_AES + NONCE_CHA  # = 102

# ── Default Argon2id parameters ────────────────────────────────────────────────
# These make each derivation ~1–2 s on modern hardware → brute-force is infeasible.
DEFAULT_TIME_COST   = 4          # iterations
DEFAULT_MEMORY_COST = 65536      # 64 MB (in KiB)
DEFAULT_PARALLELISM = 2          # threads
KEY_LEN             = 32         # 256-bit keys


class FileEncryptionEngine:
    """
    Two-pass authenticated encryption for arbitrary files.

    Security properties:
    • Argon2id KDF  — memory-hard (64 MB), GPU/ASIC-resistant, side-channel safe
    • ChaCha20-Poly1305 inner layer — 256-bit, AEAD, immune to timing attacks
    • AES-256-GCM  outer layer — 256-bit, AEAD, hardware-accelerated
    • Two independent keys derived from two independent salts
    • Random padding prevents file-size pattern analysis
    • zlib compression breaks known-plaintext statistical patterns
    • Both layers carry their own authentication tag — any bit flip is detected
    """

    def __init__(
        self,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> None:
        self.time_cost   = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

    # ── Public API ─────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes, password: str) -> bytes:
        """Return the fully encrypted binary blob ready to be written to disk."""
        # 1. Compress
        compressed = zlib.compress(plaintext, level=9)

        # 2. Random padding  (0–255 random bytes)
        pad_len = secrets.randbelow(256)
        padded  = struct.pack(">H", pad_len) + secrets.token_bytes(pad_len) + compressed

        # 3. Generate independent salts & nonces
        salt1     = os.urandom(SALT_LEN)
        salt2     = os.urandom(SALT_LEN)
        nonce_aes = os.urandom(NONCE_AES)
        nonce_cha = os.urandom(NONCE_CHA)

        # 4. Derive two independent keys (separate Argon2id calls, different salts)
        key_aes = self._derive(password, salt1)
        key_cha = self._derive(password, salt2)

        # 5. Inner encryption: ChaCha20-Poly1305
        inner_ct = ChaCha20Poly1305(key_cha).encrypt(nonce_cha, padded, None)

        # 6. Outer encryption: AES-256-GCM
        outer_ct = AESGCM(key_aes).encrypt(nonce_aes, inner_ct, None)

        # 7. Pack header
        # memory_cost fits in 3 bytes (max ~16 GB in KiB); use big-endian uint24
        mc_b = struct.pack(">I", self.memory_cost)[1:]  # drop MSB, keep 3 bytes
        header = (
            MAGIC
            + struct.pack("B", VERSION)
            + struct.pack("B", self.time_cost)
            + mc_b
            + struct.pack("B", self.parallelism)
            + salt1
            + salt2
            + nonce_aes
            + nonce_cha
        )
        return header + outer_ct

    def decrypt(self, data: bytes, password: str) -> bytes:
        """Decrypt and return the original plaintext bytes."""
        if len(data) < HEADER_LEN:
            raise ValueError("File is too short to be a valid .cstk encrypted file.")
        if not data.startswith(MAGIC):
            raise ValueError("Invalid magic bytes — not a .cstk V2 encrypted file.")

        off = len(MAGIC)

        version = data[off]; off += 1
        if version != VERSION:
            raise ValueError(f"Unsupported encryption version: {version}. Please update the toolkit.")

        # Read Argon2id params stored in the file (forward-compatible)
        time_cost   = data[off]; off += 1
        memory_cost = struct.unpack(">I", b"\x00" + data[off:off + 3])[0]; off += 3
        parallelism = data[off]; off += 1

        salt1     = data[off: off + SALT_LEN];  off += SALT_LEN
        salt2     = data[off: off + SALT_LEN];  off += SALT_LEN
        nonce_aes = data[off: off + NONCE_AES]; off += NONCE_AES
        nonce_cha = data[off: off + NONCE_CHA]; off += NONCE_CHA
        outer_ct  = data[off:]

        # Derive keys using parameters recorded in the file
        key_aes = self._derive(password, salt1, time_cost, memory_cost, parallelism)
        key_cha = self._derive(password, salt2, time_cost, memory_cost, parallelism)

        # Outer decrypt: AES-256-GCM
        try:
            inner_ct = AESGCM(key_aes).decrypt(nonce_aes, outer_ct, None)
        except InvalidTag:
            raise ValueError("Wrong password or file corrupted (outer AES-256-GCM layer).")

        # Inner decrypt: ChaCha20-Poly1305
        try:
            padded = ChaCha20Poly1305(key_cha).decrypt(nonce_cha, inner_ct, None)
        except InvalidTag:
            raise ValueError("Wrong password or file corrupted (inner ChaCha20-Poly1305 layer).")

        # Strip padding
        pad_len    = struct.unpack_from(">H", padded, 0)[0]
        compressed = padded[2 + pad_len:]

        # Decompress
        try:
            return zlib.decompress(compressed)
        except zlib.error as exc:
            raise ValueError(f"Decompression failed — file may be corrupted: {exc}") from exc

    # ── Internal ───────────────────────────────────────────────────────────────

    def _derive(
        self,
        password: str,
        salt: bytes,
        time_cost: int   = None,
        memory_cost: int = None,
        parallelism: int = None,
    ) -> bytes:
        return hash_secret_raw(
            secret      = password.encode("utf-8"),
            salt        = salt,
            time_cost   = time_cost   if time_cost   is not None else self.time_cost,
            memory_cost = memory_cost if memory_cost is not None else self.memory_cost,
            parallelism = parallelism if parallelism is not None else self.parallelism,
            hash_len    = KEY_LEN,
            type        = Type.ID,
        )


