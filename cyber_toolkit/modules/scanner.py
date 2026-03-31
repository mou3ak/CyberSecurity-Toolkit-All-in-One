"""Advanced local-network scanner.

Uses python-nmap when the nmap binary is available; falls back to an
ARP/ping sweep otherwise.  Provides: IP, MAC, hostname, manufacturer,
and open ports.  Results can be exported to CSV.
"""

import csv
import ipaddress
import re
import socket
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional

# ── Optional nmap ─────────────────────────────────────────────────────────────
try:
    import nmap as _nmap_lib   # type: ignore[import]
    NMAP_AVAILABLE = True
except ImportError:
    _nmap_lib = None           # type: ignore[assignment]
    NMAP_AVAILABLE = False

# ── OUI / MAC-vendor table (top manufacturers) ────────────────────────────────
_OUI: Dict[str, str] = {
    "00:50:56": "VMware",   "00:0c:29": "VMware",   "00:05:69": "VMware",
    "00:1a:4b": "Intel",    "8c:8d:28": "Intel",    "f4:4d:30": "Intel",
    "dc:a6:32": "Raspberry Pi Foundation",
    "b8:27:eb": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "18:66:da": "Apple",    "ac:de:48": "Apple",    "3c:22:fb": "Apple",
    "00:17:f2": "Apple",    "00:1b:63": "Apple",    "a4:83:e7": "Apple",
    "a4:c3:f0": "Google",   "54:60:09": "Google",   "f4:f5:e8": "Google",
    "3c:5a:b4": "Google",
    "00:1e:8c": "ASUSTek",  "04:92:26": "ASUSTek",  "14:da:e9": "ASUSTek",
    "e0:3f:49": "Huawei",   "e8:cd:2d": "Huawei",   "00:18:82": "Huawei",
    "00:0d:3a": "Microsoft","00:15:5d": "Microsoft","28:18:78": "Samsung",
    "5c:49:7d": "Samsung",  "00:16:6b": "Samsung",  "d8:c4:97": "TP-Link",
    "50:c7:bf": "TP-Link",  "e8:de:27": "TP-Link",  "ec:08:6b": "TP-Link",
    "00:1d:0f": "Netgear",  "c0:ff:d4": "Netgear",  "00:26:b9": "Netgear",
    "00:24:b2": "Cisco",    "00:1e:bd": "Cisco",    "84:78:ac": "Cisco",
    "fc:fb:fb": "Cisco",    "00:11:43": "Dell",     "18:03:73": "Dell",
}

_COMMON_PORTS = "21,22,23,25,53,80,135,139,443,445,3389,8080,8443"


def _lookup_vendor(mac: str) -> str:
    normalized = mac.upper().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3]).lower()
    return _OUI.get(prefix, "Unknown")


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"


def _cb(callback: Optional[Callable[[str, int], None]], message: str, percent: int) -> None:
    if callback:
        try:
            callback(message, percent)
        except Exception:
            pass


class NetworkScanner:
    """Scan the local /24 subnet and return a list of device dicts."""

    def scan_local_devices(
        self,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> List[Dict[str, str]]:
        """
        Scan for local devices.  Returns list of dicts:
            ip, mac, hostname, vendor, ports
        """
        if NMAP_AVAILABLE:
            try:
                return self._scan_nmap(progress_callback)
            except Exception:
                pass
        return self._scan_arp(progress_callback)

    # ── nmap path ─────────────────────────────────────────────────────────────

    def _scan_nmap(self, cb: Optional[Callable]) -> List[Dict[str, str]]:
        subnet = self._guess_local_subnet()
        if subnet is None:
            return []
        nm = _nmap_lib.PortScanner()
        _cb(cb, "Discovering hosts (ping sweep)…", 5)
        try:
            nm.scan(hosts=str(subnet), arguments="-sn --host-timeout 3s -T4")
        except _nmap_lib.PortScannerError:
            raise RuntimeError("nmap binary not available")

        hosts = nm.all_hosts()
        rows: List[Dict[str, str]] = []
        total = max(len(hosts), 1)

        for i, host in enumerate(hosts):
            _cb(cb, f"Scanning {host}  ({i + 1}/{total})…", 10 + int(70 * i / total))
            info   = nm[host]
            mac    = info.get("addresses", {}).get("mac", "-") or "-"
            vendor = info.get("vendor", {}).get(mac, "") or _lookup_vendor(mac)
            host_names = info.get("hostnames", [])
            hostname = (host_names[0].get("name", "") if host_names else "") or _resolve_hostname(host)
            open_ports: List[str] = []
            try:
                nm.scan(hosts=host, arguments=f"-p {_COMMON_PORTS} --host-timeout 5s -T4")
                tcp_data = nm[host].get("tcp", {})
                open_ports = [str(p) for p, d in tcp_data.items() if d.get("state") == "open"]
            except Exception:
                pass
            rows.append({
                "ip":       host,
                "mac":      mac,
                "hostname": hostname or "-",
                "vendor":   vendor or "Unknown",
                "ports":    ", ".join(str(p) for p in sorted(open_ports)) if open_ports else "-",
            })

        _cb(cb, f"Scan complete — {len(rows)} device(s) found", 100)
        return rows

    # ── ARP/ping fallback ─────────────────────────────────────────────────────

    def _scan_arp(self, cb: Optional[Callable]) -> List[Dict[str, str]]:
        subnet = self._guess_local_subnet()
        if subnet is None:
            return []
        hosts_list = list(subnet.hosts())[:64]
        total = max(len(hosts_list), 1)
        _cb(cb, "Pinging hosts…", 5)
        for i, ip in enumerate(hosts_list):
            if i % 8 == 0:
                _cb(cb, f"Pinging {ip}…", 5 + int(55 * i / total))
            subprocess.run(
                ["ping", "-n", "1", "-w", "80", str(ip)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        _cb(cb, "Reading ARP table…", 65)
        try:
            arp_out = subprocess.check_output(
                ["arp", "-a"], text=True, encoding="utf-8", errors="ignore"
            )
        except subprocess.CalledProcessError:
            return []

        ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([\w:-]+)\s+")
        rows: List[Dict[str, str]] = []
        seen: set = set()
        for match in ip_re.finditer(arp_out):
            ip_addr, mac_addr = match.group(1), match.group(2)
            if ip_addr in seen:
                continue
            try:
                if ipaddress.ip_address(ip_addr) not in subnet:
                    continue
            except ValueError:
                continue
            seen.add(ip_addr)
            rows.append({
                "ip":       ip_addr,
                "mac":      mac_addr,
                "hostname": _resolve_hostname(ip_addr),
                "vendor":   _lookup_vendor(mac_addr),
                "ports":    "-",
            })
        _cb(cb, f"Scan complete — {len(rows)} device(s) found", 100)
        return rows

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _guess_local_subnet() -> Optional[ipaddress.IPv4Network]:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            return ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        except OSError:
            return None

    @staticmethod
    def export_csv(rows: List[Dict[str, str]], filepath: str) -> Path:
        """Write *rows* to a CSV file and return the Path."""
        if not rows:
            raise ValueError("No data to export.")
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["ip", "mac", "hostname", "vendor", "ports"])
            writer.writeheader()
            writer.writerows(rows)
        return target
