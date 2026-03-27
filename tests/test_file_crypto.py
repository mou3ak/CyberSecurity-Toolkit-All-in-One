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


if __name__ == "__main__":
    unittest.main()

