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


if __name__ == "__main__":
    unittest.main()

