# CyberSecurity Toolkit - All in One 🔐

Hi, I'm Sami Zi 👨‍💻.

I developed this desktop cybersecurity toolkit as a personal project to streamline various security tasks and deepen my understanding of defensive techniques. My goal is to provide a reliable and user-friendly app both for beginners wanting to learn and for seasoned users seeking a handy toolkit.

---

## 🚀 Features

### 🌐 Network Tools
- Local device discovery (IP / MAC)
- Live connection monitor with basic risk indicators
- *(Note: The Wi-Fi scanner feature has been removed and is no longer supported.)*

### 🗝 Password Vault
- Secure vault protected with a master password
- Generate strong passwords
- Save, manage, and delete credentials
- Export data to `.txt`, `.csv`, or `.json` *(Warning: Exported files are **not encrypted**; please store them securely.)*

### 🔒 File Encryptor / Decryptor
- Encrypt and decrypt selected files safely using AES-256 GCM
- Uses Argon2id (memory-hard key derivation, 64 MB default)
- Compressed `.cstk` file format
- Securely stores original filename for safe restoration
- Prevents accidental file overwriting
- Supports drag & drop and file browsing

---

## ⚙️ Requirements

- Python 3.10+
- Windows (recommended)  
  *(Note: Wi-Fi scanning uses `netsh`, which is Windows-specific)*

---

## 📦 Installation & Run

```bash
git clone "https://github.com/mou3ak/CyberSecurity-Toolkit-All-in-One.git"
cd CyberSecurity-Toolkit-All-in-One
py "Toolkit-All-in-One.py"
```

---

## 🔐 Security & Ethical Use

This project is intended for:

- Defensive cybersecurity education  
- Personal security practice  
- Lab environments  
- Authorized testing only  

**Not intended for:**

- Unauthorized access  
- Intrusive activities  
- Malicious use  

Please always use this toolkit responsibly and ethically.

---

## 📝 Notes

- Some network features depend on your system permissions and OS configuration.  
- Exported password vault files are not encrypted; handle them with care.

---

## ⭐ Future Improvements

- Cross-platform support (Linux / macOS)  
- GUI improvements with enhanced themes  
- Real-time alert system  
- Encrypted cloud sync for password vault  

---

## 🙋 About the Author

**Sami Zi**  
Cybersecurity Enthusiast | Software Developer  

I created this project to combine learning and practical cybersecurity tools in one place. I’m continuously working on improvements, so stay tuned for updates!

Feel free to connect with me on [LinkedIn](https://www.linkedin.com/in/tu-perfil) or email me at tuemail@example.com

---

⭐ *If you find this project useful, please give it a star on GitHub!*
