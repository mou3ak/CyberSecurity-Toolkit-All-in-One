# 🔐 CyberSecurity Toolkit - All in One

This toolkit was created by **Sami Zi 👨‍💻**

A powerful and easy-to-use **desktop cybersecurity toolkit** built with Python, designed for learning, testing, and improving personal security skills.

---

## Features

### 🌐 Network Tools
- Wi-Fi scanner for nearby networks
- Local device discovery (IP / MAC)
- Live connection monitor with basic risk indicators

### 🔑 Password Vault
- Secure vault protected with a master password
- Generate strong passwords
- Save and manage credentials
- Delete stored entries
- Export data to `.txt`, `.csv`, or `.json`

> ⚠️ **Warning:** Exported files are not encrypted. Store them securely.

### 🔐 File Encryptor / Decryptor
- Encrypt and decrypt selected files safely
- Uses **Argon2id** (memory-hard key derivation, 64 MB default)
- Compressed `.cstk` file format
- Stores original filename securely for safe restoration
- Prevents accidental file overwriting

### 🧠 Ethical Password Simulator
- No real attacks are performed ❌
- Estimates:
  - Total combinations
  - Entropy
  - Expected cracking time
  - 24-hour success probability
  - Password strength rating

---

## ⚙️ Requirements

- Python **3.10+**
- Windows (recommended)
- Wi-Fi scanning uses `netsh` → Windows-specific features

---

## 📦 Installation

```bash
pip install -r requirements.txt
