import tempfile
import unittest
from pathlib import Path

from cyber_toolkit.modules.password_manager import PasswordVault


class TestPasswordVault(unittest.TestCase):
    def test_initialize_add_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = PasswordVault(Path(tmp) / "vault.json")
            master = "TopSecret!"
            vault.initialize(master)
            vault.add_entry(master, "email", "user@example.com", "pass-123")
            rows = vault.list_entries(master)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["service"], "email")

    def test_delete_entry_and_export_text_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = PasswordVault(Path(tmp) / "vault.json")
            master = "TopSecret!"
            vault.initialize(master)
            vault.add_entry(master, "email", "user@example.com", "pass-123")
            vault.add_entry(master, "github", "sami", "GH-pass-456")

            rows = vault.list_entries(master)
            self.assertEqual(len(rows), 2)

            deleted = vault.delete_entry(master, "email", "user@example.com", rows[0]["created_at"])
            self.assertTrue(deleted)

            remaining = vault.list_entries(master)
            self.assertEqual(len(remaining), 1)
            self.assertEqual(remaining[0]["service"], "github")

            export_path = vault.export_entries(master, Path(tmp) / "vault_export.txt")
            export_text = export_path.read_text(encoding="utf-8")
            self.assertIn("github", export_text)
            self.assertIn("GH-pass-456", export_text)


if __name__ == "__main__":
    unittest.main()

