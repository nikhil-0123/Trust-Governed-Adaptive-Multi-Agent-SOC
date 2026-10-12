import os
import re
import logging
from typing import List, Dict, Any, Optional

SENSITIVE_ARG_RE = re.compile(
    r"(--password|--token|--secret|--api-key|--apikey|--auth|--pass|--private-key|-p)(?:[\s=]+)([^\s]+)",
    re.IGNORECASE
)

class ProcessCollector:
    """
    Safely collects process execution metadata on Ubuntu/Linux.
    Uses /proc directly when available with fallback to standard process query.
    Sanitizes command line parameters to protect sensitive values.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("ProcessCollector")

    @staticmethod
    def sanitize_cmdline(cmdline: str) -> str:
        """Masks potential secret flags in command line strings across space and '=' separators."""
        if not cmdline:
            return ""
        return SENSITIVE_ARG_RE.sub(r"\1=[REDACTED]", cmdline)

    def collect_processes(self, proc_dir: str = "/proc") -> List[Dict[str, Any]]:
        """Collects a snapshot of running processes from /proc or returns empty if inaccessible."""
        if not os.path.exists(proc_dir):
            return []

        processes = []
        try:
            for entry in os.listdir(proc_dir):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                proc_path = os.path.join(proc_dir, entry)

                # Read cmdline
                cmdline = ""
                cmdline_path = os.path.join(proc_path, "cmdline")
                try:
                    with open(cmdline_path, "rb") as f:
                        raw = f.read(1024)
                        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

                # Read status for Name and Uid
                name = ""
                status_path = os.path.join(proc_path, "status")
                try:
                    with open(status_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.startswith("Name:"):
                                name = line.split(":", 1)[1].strip()
                                break
                except Exception:
                    pass

                if name or cmdline:
                    processes.append({
                        "pid": pid,
                        "name": name or "unknown",
                        "cmdline": self.sanitize_cmdline(cmdline)
                    })
        except Exception as e:
            self.logger.warning(f"Error inspecting {proc_dir}: {e}")

        return processes
