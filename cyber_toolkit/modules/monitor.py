from typing import Dict, List

import psutil


SUSPICIOUS_PORTS = {23, 4444, 1337, 6667, 31337}


class ConnectionMonitor:
    def list_connections(self, limit: int = 250) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for connection in psutil.net_connections(kind="inet")[:limit]:
            pid = connection.pid
            process_name = "N/A"
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "<restricted>"

            local_address = f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else "-"
            remote_address = f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else "-"
            remote_port = connection.raddr.port if connection.raddr else 0
            risk = "High" if remote_port in SUSPICIOUS_PORTS else "Normal"

            rows.append(
                {
                    "pid": str(pid or "-"),
                    "process": process_name,
                    "local": local_address,
                    "remote": remote_address,
                    "status": connection.status,
                    "risk": risk,
                }
            )
        return rows

