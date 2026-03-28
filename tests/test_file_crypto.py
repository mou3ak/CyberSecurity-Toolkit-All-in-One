import tempfile
import unittest
from pathlib import Path

from cyber_toolkit.modules.file_crypto import FileCipher


class TestFileCipher(unittest.TestCase):
    def test_encrypt_decrypt_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "example.txt"
            source.write_text("secret content", encoding="utf-8")

            cipher = FileCipher()
            encrypted = cipher.encrypt_file(str(source), "Password123!")
            decrypted = cipher.decrypt_file(str(encrypted), "Password123!", output_path=str(Path(tmp) / "plain.txt"))

            self.assertTrue(encrypted.exists())
            self.assertEqual(decrypted.read_text(encoding="utf-8"), "secret content")

    def test_decrypt_uses_unique_restore_path_when_original_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "example.txt"
            source.write_text("secret content", encoding="utf-8")

            cipher = FileCipher()
            encrypted = cipher.encrypt_file(str(source), "Password123!")
            restored = cipher.decrypt_file(str(encrypted), "Password123!")

            self.assertEqual(restored.name, "example.decrypted.txt")
            self.assertEqual(restored.read_text(encoding="utf-8"), "secret content")
            self.assertEqual(source.read_text(encoding="utf-8"), "secret content")

    def test_wrong_password_raises_value_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "example.txt"
            source.write_text("secret content", encoding="utf-8")

            cipher = FileCipher()
            encrypted = cipher.encrypt_file(str(source), "Password123!")

            with self.assertRaises(ValueError):
                cipher.decrypt_file(str(encrypted), "WrongPassword!")


if __name__ == "__main__":
    unittest.main()

