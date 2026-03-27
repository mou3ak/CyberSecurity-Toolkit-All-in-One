import ipaddress
import re
import socket
import subprocess
from typing import Dict, List


class NetworkScanner:
    def scan_wifi_networks(self) -> List[Dict[str, str]]:
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

        results: List[Dict[str, str]] = []
        current: Dict[str, str] = {}

        for line in output.splitlines():
            cleaned = line.strip()
            if cleaned.startswith("SSID") and ":" in cleaned:
                if current:
                    results.append(current)
                current = {
                    "ssid": cleaned.split(":", 1)[1].strip(),
                    "bssid": "-",
                    "security": "Unknown",
                    "signal": "-",
                }
            elif cleaned.startswith("BSSID") and ":" in cleaned:
                current["bssid"] = cleaned.split(":", 1)[1].strip()
            elif cleaned.startswith("Authentication") and ":" in cleaned:
                current["security"] = cleaned.split(":", 1)[1].strip()
            elif cleaned.startswith("Signal") and ":" in cleaned:
                current["signal"] = cleaned.split(":", 1)[1].strip()

        if current:
            results.append(current)
        return results

    def scan_local_devices(self) -> List[Dict[str, str]]:
        subnet = self._guess_local_subnet()
        if subnet is None:
            return []

        # Ping a subset quickly to warm ARP cache on local /24.
        for ip in list(subnet.hosts())[:64]:
            subprocess.run(
                ["ping", "-n", "1", "-w", "60", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        arp_table = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8", errors="ignore")
        ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+")
        rows: List[Dict[str, str]] = []
        for match in ip_re.finditer(arp_table):
            ip_addr, mac_addr = match.group(1), match.group(2)
            try:
                if ipaddress.ip_address(ip_addr) in subnet:
                    rows.append({"ip": ip_addr, "mac": mac_addr})
            except ValueError:
                continue
        return rows

    @staticmethod
    def _guess_local_subnet() -> ipaddress.IPv4Network | None:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return network
        except OSError:
            return None

