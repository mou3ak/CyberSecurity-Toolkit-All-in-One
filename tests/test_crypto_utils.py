import unittest

from cyber_toolkit.security.crypto_utils import decrypt_bytes, encrypt_bytes


class TestCryptoUtils(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        secret = b"hello toolkit"
        password = "master123!"
        payload = encrypt_bytes(secret, password)
        decoded = decrypt_bytes(payload, password)
        self.assertEqual(decoded, secret)


if __name__ == "__main__":
    unittest.main()

