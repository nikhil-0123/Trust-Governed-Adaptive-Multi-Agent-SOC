import os
import socket
import struct
import logging
from typing import List, Dict, Any, Optional

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING"
}

class NetworkCollector:
    """
    Collects network socket metadata and listening ports on Linux/Ubuntu.
    Parses /proc/net/tcp safely with zero network overhead.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("NetworkCollector")

    @staticmethod
    def _hex_to_ip_port(hex_addr: str) -> tuple[str, int]:
        """Converts hex address:port to standard IPv4 or IPv6 and integer port."""
        try:
            ip_hex, port_hex = hex_addr.split(":")
            port = int(port_hex, 16)
            ip_bytes = bytes.fromhex(ip_hex)
            if len(ip_bytes) == 4:
                # /proc/net/tcp IPv4 stored in little-endian
                ip = socket.inet_ntop(socket.AF_INET, ip_bytes[::-1])
                return ip, port
            elif len(ip_bytes) == 16:
                # /proc/net/tcp6 IPv6 stored as 4 little-endian 32-bit words
                words = struct.unpack("<4I", ip_bytes)
                ip = socket.inet_ntop(socket.AF_INET6, struct.pack(">4I", *words))
                return ip, port
            return "0.0.0.0", port
        except Exception:
            return "0.0.0.0", 0

    def collect_sockets(self, tcp_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Parses active and listening sockets from /proc/net/tcp and /proc/net/tcp6."""
        if tcp_paths is None:
            tcp_paths = ["/proc/net/tcp", "/proc/net/tcp6"]

        sockets = []
        for path in tcp_paths:
            if not os.path.exists(path):
                continue
            proto = "tcp6" if "tcp6" in path else "tcp"
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        local_ip, local_port = self._hex_to_ip_port(parts[1])
                        remote_ip, remote_port = self._hex_to_ip_port(parts[2])
                        state_code = parts[3].upper()
                        state_name = TCP_STATES.get(state_code, "UNKNOWN")

                        sockets.append({
                            "protocol": proto,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "state": state_name
                        })
            except Exception as e:
                self.logger.warning(f"Error inspecting {path}: {e}")

        return sockets
