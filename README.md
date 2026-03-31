# ⚡ CyberSecurity Toolkit — All in One

> **A professional, dark-themed defensive security workspace built with Python + Tkinter.**
> Made by **Sami Zi** · © 2026

---

## Features

| Module | Description |
|---|---|
| **Dashboard** | Live metric cards (connections · devices · vault entries) with one-click refresh |
| **Local Scanner** | Advanced /24 subnet scan — IP, MAC, hostname, manufacturer, open ports. nmap-powered when available; ARP/ping fallback. Filter, sort, export CSV. |
| **Connections** | Live list of active network connections with process names and risk flags |
| **Password Vault** | AES-256-GCM encrypted vault. Save, generate, delete, export (TXT/CSV/JSON) and **import** (JSON/CSV) password entries |
| **File Encryptor** | AES-256-GCM + PBKDF2-HMAC-SHA256 (600 000 iter). Drag-and-drop file selector. Show/hide password. Full backward-compatibility with legacy files. |

---

## Requirements

- Python 3.11+
- `cryptography` ≥ 42
- `psutil` ≥ 5.9
- `argon2-cffi` ≥ 23.1 *(legacy file decryption)*
- `python-nmap` ≥ 0.7.1 *(optional — enhanced scanning)*
- `tkinterdnd2` ≥ 0.3.0 *(optional — drag & drop)*

Install all at once:

```bash
pip install -r requirements.txt
```

> **nmap binary** (optional): For advanced port scanning, install [nmap](https://nmap.org/download.html) and make sure it is in your `PATH`.

---

## Quick Start

```bash
python Toolkit-All-in-One.py
```

---

## File Encryption Format (V4)

| Field | Size | Description |
|---|---|---|
| Magic | 8 bytes | `\x89CSTK\x04\r\n` |
| Version | 1 byte | `0x04` |
| Salt | 16 bytes | Random — used for PBKDF2 key derivation |
| IV | 12 bytes | Random nonce — AES-256-GCM |
| Ciphertext + Tag | variable | AES-256-GCM output |

**KDF:** PBKDF2-HMAC-SHA256, 600 000 iterations, 32-byte output.
**Legacy files** (V2 / V3, Argon2id) are automatically detected and decrypted.

---

## Password Vault Import Format

**JSON** (list or object with `entries` key):
```json
[
  { "service": "github", "username": "user", "password": "secret" }
]
```

**CSV** (requires `service`, `username`, `password` columns):
```csv
service,username,password,notes
github,user,secret,
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Project Structure

```
Toolkit-All-in-One.py          Entry point
cyber_toolkit/
  config.py                    App constants & paths
  modules/
    scanner.py                 Network scanner (nmap / ARP)
    monitor.py                 Connection monitor
    password_manager.py        Encrypted password vault
    file_crypto.py             File encrypt / decrypt
  security/
    crypto_utils.py            AES-256-GCM primitives (vault KDF)
    file_engine.py             File encryption engines (V4 + legacy V2/V3)
  ui/
    main_window.py             Tkinter application window
tests/                         Unit tests
```

---

*© 2026 Sami Zi — For defensive and educational use only.*
