"""Tests for the new scanner CSV export and vault import_file functionality."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from cyber_toolkit.modules.scanner import NetworkScanner, _lookup_vendor, _resolve_hostname
from cyber_toolkit.modules.password_manager import PasswordVault


class TestScannerCsvExport(unittest.TestCase):
    """Tests that do not require network access or nmap binary."""

    def _sample_rows(self):
        return [
            {"ip": "192.168.1.1",  "mac": "aa:bb:cc:dd:ee:ff",
             "hostname": "router.local", "vendor": "Cisco", "ports": "80, 443"},
            {"ip": "192.168.1.10", "mac": "00:11:43:22:33:44",
             "hostname": "desktop.local", "vendor": "Dell", "ports": "-"},
        ]

    def test_export_csv_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scan.csv"
            result = NetworkScanner.export_csv(self._sample_rows(), str(out))
            self.assertTrue(result.exists())
            text = result.read_text(encoding="utf-8")
            self.assertIn("192.168.1.1", text)
            self.assertIn("router.local", text)

    def test_export_csv_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scan.csv"
            NetworkScanner.export_csv(self._sample_rows(), str(out))
            with out.open(encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                self.assertIn("ip", reader.fieldnames)
                self.assertIn("vendor", reader.fieldnames)
                self.assertIn("ports", reader.fieldnames)

    def test_export_csv_raises_on_empty(self):
        with self.assertRaises(ValueError):
            NetworkScanner.export_csv([], "/tmp/empty.csv")

    def test_oui_lookup_known(self):
        self.assertEqual(_lookup_vendor("00:50:56:12:34:56"), "VMware")
        self.assertEqual(_lookup_vendor("dc:a6:32:ab:cd:ef"), "Raspberry Pi Foundation")

    def test_oui_lookup_unknown(self):
        self.assertEqual(_lookup_vendor("ff:ff:ff:ff:ff:ff"), "Unknown")


class TestVaultImportFile(unittest.TestCase):
    """Tests for PasswordVault.import_file."""

    def test_import_json_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault_path = Path(tmp) / "vault.json"
            vault = PasswordVault(vault_path)
            master = "TestMaster123!"
            vault.initialize(master)

            import_data = [
                {"service": "github",  "username": "sami", "password": "gh-pass"},
                {"service": "twitter", "username": "sz",   "password": "tw-pass"},
            ]
            import_file = Path(tmp) / "import.json"
            import_file.write_text(json.dumps(import_data), encoding="utf-8")

            count = vault.import_file(master, import_file)
            self.assertEqual(count, 2)

            entries = vault.list_entries(master)
            services = [e["service"] for e in entries]
            self.assertIn("github", services)
            self.assertIn("twitter", services)

    def test_import_json_with_entries_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = PasswordVault(Path(tmp) / "vault.json")
            master = "Master456!"
            vault.initialize(master)

            data = {"version": 1, "entries": [
                {"service": "email", "username": "user@x.com", "password": "secret"},
            ]}
            f = Path(tmp) / "export.json"
            f.write_text(json.dumps(data), encoding="utf-8")

            count = vault.import_file(master, f)
            self.assertEqual(count, 1)

    def test_import_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = PasswordVault(Path(tmp) / "vault.json")
            master = "CsvMaster!"
            vault.initialize(master)

            csv_path = Path(tmp) / "import.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=["service", "username", "password", "notes"])
                writer.writeheader()
                writer.writerow({"service": "linkedin", "username": "sami",
                                 "password": "li-pass", "notes": ""})

            count = vault.import_file(master, csv_path)
            self.assertEqual(count, 1)
            entries = vault.list_entries(master)
            self.assertEqual(entries[0]["service"], "linkedin")

    def test_import_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = PasswordVault(Path(tmp) / "vault.json")
            master = "Master!"
            vault.initialize(master)
            bad = Path(tmp) / "bad.json"
            bad.write_text('{"wrong_key": 123}', encoding="utf-8")
            with self.assertRaises(ValueError):
                vault.import_file(master, bad)

    def test_import_unsupported_format_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = PasswordVault(Path(tmp) / "vault.json")
            master = "Master!"
            vault.initialize(master)
            f = Path(tmp) / "data.xml"
            f.write_text("<data/>", encoding="utf-8")
            with self.assertRaises(ValueError):
                vault.import_file(master, f)


if __name__ == "__main__":
    unittest.main()
