# CyberSecurity Toolkit - All in One

A desktop cybersecurity toolkit built with Python and a dark "hacker-style" interface for defensive learning, lab use, and authorized security practice.

## Highlights

- Wi-Fi scanner for nearby networks
- Local device discovery (IP / MAC)
- Live connection monitor with basic risk indicators
- Encrypted password vault with a master password
- Password generator, delete action, and export-to-file support
- Professional file encryptor / decryptor for user-selected files
- Ethical password attack simulator (estimation only)
- Unified dashboard with quick metrics
- Custom interface branding with **Sami Zi 👨‍💻**

## Project Structure

```text
CyberSecurity-Toolkit-All-in-One/
├── Toolkit-All-in-One.py
├── requirements.txt
├── cyber_toolkit/
│   ├── config.py
│   ├── modules/
│   ├── security/
│   └── ui/
└── tests/
```

## Requirements

- Python 3.10+
- Windows recommended
- Wi-Fi scanning uses `netsh`, so some features are Windows-specific

## Installation

```powershell
pip install -r requirements.txt
```

## Run the App

```powershell
python Toolkit-All-in-One.py
```

## Main Features

### Password Vault

- Create and unlock a vault with a master password
- Generate strong passwords
- Save service credentials
- Load saved entries into the table
- Delete selected entries
- Export entries to `.txt`, `.csv`, or `.json`

> Important: exported vault files are readable on disk. Store them carefully.

### File Encryptor

The encryptor is designed for **files you explicitly choose**.

- Authenticated encryption using **AES-256-GCM** and **ChaCha20-Poly1305**
- **Argon2id** key derivation (memory-hard, 64 MB default)
- Compressed binary `.cstk` format
- Original filename metadata stored securely for safer restore
- Backward-compatible decryption for older encrypted toolkit files
- Safer output handling to avoid overwriting an existing file by default

### Ethical Simulator

The simulator does **not** perform real attacks.
It only estimates:

- total combinations
- entropy
- expected cracking time
- 24-hour success probability
- rough password strength label

## Security and Ethical Scope

This project is intended for:

- defensive education
- personal security practice
- lab environments
- authorized testing only

It is **not** intended for intrusive activity, unauthorized access, or destructive use.

## Run Tests

```powershell
python -m unittest discover -s tests -v
```

## Notes

- The UI is built with `tkinter`
- Cryptographic features rely on `cryptography` and `argon2-cffi`
- Some network details depend on the host operating system and available permissions

