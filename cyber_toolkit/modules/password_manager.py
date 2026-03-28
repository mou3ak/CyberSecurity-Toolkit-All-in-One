import csv
import json
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from cryptography.exceptions import InvalidTag

from cyber_toolkit.security.crypto_utils import decrypt_bytes, encrypt_bytes


class PasswordVault:
    def __init__(self, vault_path: Path):
        self.vault_path = vault_path
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)

    def exists(self) -> bool:
        return self.vault_path.exists()

    def initialize(self, master_password: str) -> None:
        if self.exists():
            raise FileExistsError("Vault already exists")
        self._write_entries(master_password, [])

    def list_entries(self, master_password: str) -> List[Dict[str, str]]:
        return self._read_entries(master_password)

    def delete_entry(self, master_password: str, service: str, username: str, created_at: str) -> bool:
        """Remove the entry that matches service + username + created_at.  Returns True if found and deleted."""
        rows = self._read_entries(master_password)
        new_rows = [
            r for r in rows
            if not (r["service"] == service and r["username"] == username and r["created_at"] == created_at)
        ]
        if len(new_rows) == len(rows):
            return False
        self._write_entries(master_password, new_rows)
        return True

    def export_entries(self, master_password: str, destination: str | Path, export_format: str | None = None) -> Path:
        rows = self._read_entries(master_password)
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)

        fmt = (export_format or target.suffix.lstrip(".") or "txt").lower()
        if fmt not in {"txt", "csv", "json"}:
            raise ValueError("Unsupported export format. Use txt, csv or json.")

        with target.open("w", encoding="utf-8", newline="" if fmt == "csv" else None) as handle:
            if fmt == "csv":
                writer = csv.DictWriter(handle, fieldnames=["service", "username", "password", "notes", "created_at"])
                writer.writeheader()
                writer.writerows(rows)
            elif fmt == "json":
                json.dump({"version": 1, "entries": rows}, handle, indent=2)
            else:
                handle.write("=" * 60 + "\n")
                handle.write("  CyberSecurity Toolkit - Password Vault Export\n")
                handle.write("=" * 60 + "\n\n")
                for index, row in enumerate(rows, 1):
                    handle.write(f"[{index}] Service  : {row['service']}\n")
                    handle.write(f"    Username : {row['username']}\n")
                    handle.write(f"    Password : {row['password']}\n")
                    handle.write(f"    Notes    : {row.get('notes', '')}\n")
                    handle.write(f"    Created  : {row['created_at']}\n")
                    handle.write("-" * 60 + "\n")

        return target

    def add_entry(self, master_password: str, service: str, username: str, password: str, notes: str = "") -> None:
        rows = self._read_entries(master_password)
        rows.append(
            {
                "service": service,
                "username": username,
                "password": password,
                "notes": notes,
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )
        self._write_entries(master_password, rows)

    def _read_entries(self, master_password: str) -> List[Dict[str, str]]:
        if not self.exists():
            raise FileNotFoundError("Vault does not exist")
        encrypted = json.loads(self.vault_path.read_text(encoding="utf-8"))
        try:
            payload = decrypt_bytes(encrypted["payload"], master_password)
        except InvalidTag as exc:
            raise ValueError("Invalid master password") from exc
        data = json.loads(payload.decode("utf-8"))
        return data["entries"]

    def _write_entries(self, master_password: str, entries: List[Dict[str, str]]) -> None:
        data = {"entries": entries, "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        payload = encrypt_bytes(json.dumps(data).encode("utf-8"), master_password)
        wrapped = {"version": 1, "payload": payload}
        self.vault_path.write_text(json.dumps(wrapped, indent=2), encoding="utf-8")

    @staticmethod
    def generate_password(length: int = 18) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for _ in range(length))
