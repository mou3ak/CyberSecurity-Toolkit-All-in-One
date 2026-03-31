# ⚡ CyberSecurity Toolkit — All in One 🔐

> **A professional, dark-themed defensive security workspace built with Python + Tkinter.**
> Developed by **Sami Zi** 👨‍💻 · © 2026

---

## 👋 About This Project

Hi, I'm Sami Zi.

I developed this desktop cybersecurity toolkit as a personal project to combine multiple defensive security tools into one clean and user-friendly application.

My goal is to:

* simplify common cybersecurity tasks
* improve my practical skills
* provide a useful tool for both beginners and advanced users

---

## 🚀 Features

### 📊 Dashboard

* Live metric cards (connections · devices · vault entries)
* One-click refresh

---

### 🌐 Network Tools

* Advanced /24 subnet scanning
* Shows IP, MAC, hostname, manufacturer
* Detects open ports *(nmap if available)*
* ARP / ping fallback scanning
* Filter, sort, export results (CSV)

---

### 🔌 Connections Monitor

* Live list of active network connections
* Displays process names
* Basic risk indicators

---

### 🗝 Password Vault

* AES-256-GCM encrypted vault
* Secure storage with master password
* Password generator
* Add, delete, manage entries
* Export: `.txt`, `.csv`, `.json`
* Import: `.json`, `.csv`

⚠️ Exported files are **not encrypted** — store them securely.

---

### 🔒 File Encryptor / Decryptor

* AES-256-GCM encryption
* PBKDF2-HMAC-SHA256 (600,000 iterations)
* Drag & drop support
* Show / hide password
* Prevents file overwrite
* Backward compatibility with legacy encrypted files

---

## ⚙️ Requirements

* Python 3.11+
* `cryptography` ≥ 42
* `psutil` ≥ 5.9
* `argon2-cffi` ≥ 23.1 *(legacy support)*
* `python-nmap` ≥ 0.7.1 *(optional)*
* `tkinterdnd2` ≥ 0.3.0 *(optional)*

Install dependencies:

```bash
pip install -r requirements.txt
```

> Optional: Install **nmap** → https://nmap.org/download.html

---

## ⚡ Quick Start

```bash
python Toolkit-All-in-One.py
```

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## 🔐 Security & Ethical Use

This project is intended for:

* Defensive cybersecurity learning
* Personal use
* Lab environments
* Authorized testing

**Not intended for:**

* Unauthorized access
* Malicious activity

Use responsibly.

---

## 📝 Notes

* Some features depend on system permissions
* Network scanning may vary depending on OS
* Exported vault files are not encrypted

---

## 🙋 Author

**Sami Zi**
Cybersecurity Enthusiast | Developer

I built this project to learn, improve, and create something practical.
More updates coming soon 🚀

---

⭐ If you like this project, consider giving it a star on GitHub!
