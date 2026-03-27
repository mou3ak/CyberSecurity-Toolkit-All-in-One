from pathlib import Path

APP_NAME = "CyberSecurity Toolkit"
DATA_DIR = Path.home() / ".cybersecurity_toolkit"
VAULT_FILE = DATA_DIR / "vault.json"

# Magic bytes to quickly validate decrypted file payloads.
FILE_MAGIC = b"CSTK1\0"

