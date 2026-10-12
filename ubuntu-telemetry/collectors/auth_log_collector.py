import os
import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from config.settings import config
from core.checkpoint import CheckpointManager

# Regex patterns for Ubuntu authentication log lines
# RFC 3164: "Oct 11 21:00:00 myhost sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 4444 ssh2"
# RFC 5424: "2026-10-11T21:00:00.123456+00:00 myhost sshd[1234]: ..."
SYSLOG_LINE_RE = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?))\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# SSH Authentication regexes
SSH_FAILED_RE = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)"
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)"
)

# Sudo regexes
SUDO_FAILURE_RE = re.compile(
    r"authentication failure;.*user=(?P<user>\S*)"
)
SUDO_COMMAND_RE = re.compile(
    r"(?P<caller>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target_user>\S*)\s*;\s*COMMAND=(?P<command>.*)"
)

def parse_syslog_timestamp(ts_str: str) -> str:
    """Parses legacy syslog or ISO syslog timestamp to UTC ISO-8601 string."""
    try:
        # Check ISO first
        if "T" in ts_str:
            clean = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    # Legacy syslog format: "Oct 11 21:00:00"
    try:
        current_year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        pass

    # Fallback to current UTC time if unparseable
    return datetime.now(timezone.utc).isoformat()


class AuthLogCollector:
    """
    Incrementally collects and parses Ubuntu authentication logs (/var/log/auth.log).
    Preserves byte offsets, handles log rotation, and treats log records as untrusted.
    """
    def __init__(self, log_path: Optional[str] = None, logger: Optional[logging.Logger] = None, enable_journald_fallback: bool = True):
        self.logger = logger or logging.getLogger("AuthLogCollector")
        self.log_path = log_path or config.auth_log_path
        self.batch_size = config.ubuntu_event_batch_size
        self.enable_journald_fallback = enable_journald_fallback
        self.checkpoint_manager = CheckpointManager(config.checkpoint_dir, "auth_log", self.logger)
        self.current_offset = 0
        self.current_inode = 0
        self.current_record_id = 0

    def initialize(self):
        """Loads checkpoint state."""
        self.logger.info(f"Initializing AuthLogCollector for log: {self.log_path}")
        state = self.checkpoint_manager.load_checkpoint()
        self.current_offset = state.get("last_offset", 0)
        self.current_inode = state.get("last_inode", 0)
        self.current_record_id = state.get("last_record_id", 0)
        self.logger.info(f"Loaded checkpoint: offset={self.current_offset}, inode={self.current_inode}, record_id={self.current_record_id}")

    def _collect_journald(self) -> List[Dict[str, Any]]:
        """Collects authentication events using journalctl when auth.log is absent (e.g. Ubuntu 24.04)."""
        import shutil
        import subprocess

        journalctl_bin = shutil.which("journalctl")
        if not journalctl_bin:
            return []

        cmd = [
            journalctl_bin,
            "-u", "ssh.service",
            "-u", "sudo.service",
            "-n", str(self.batch_size),
            "--output=short-iso",
            "--no-pager"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=True)
            lines = res.stdout.strip().splitlines()
            events = []
            for line in lines:
                if not line.strip():
                    continue
                self.current_record_id += 1
                ev = self._parse_line(line, self.current_record_id, byte_offset=0)
                if ev:
                    events.append(ev)
            return events
        except Exception as e:
            self.logger.debug(f"journalctl query skipped or failed: {e}")
            return []

    def collect_once(self) -> List[Dict[str, Any]]:
        """
        Reads a batch of new lines from the log file starting from the current offset.
        Detects log rotation and parses lines safely. Falls back to journald if file is absent.
        """
        if not os.path.exists(self.log_path):
            self.logger.debug(f"Auth log path does not exist: {self.log_path}")
            if self.enable_journald_fallback:
                return self._collect_journald()
            return []

        try:
            stat_res = os.stat(self.log_path)
            file_size = stat_res.st_size
            file_inode = getattr(stat_res, "st_ino", 0)
        except PermissionError as e:
            self.logger.error(f"Permission denied accessing {self.log_path}. Ensure agent user belongs to 'adm' group. Error: {e}")
            raise PermissionError(f"Permission denied accessing {self.log_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error checking {self.log_path}: {e}")
            return []

        # Check for rotation
        if CheckpointManager.is_rotated(file_inode, file_size, self.current_inode, self.current_offset):
            self.logger.info(f"Log rotation detected for {self.log_path}. Resetting offset from {self.current_offset} to 0.")
            self.current_offset = 0
            self.current_inode = file_inode

        if self.current_offset >= file_size:
            # No new data
            return []

        parsed_events = []
        try:
            with open(self.log_path, "rb") as f:
                f.seek(self.current_offset)
                count = 0
                while count < self.batch_size:
                    line_bytes = f.readline()
                    if not line_bytes:
                        break  # EOF reached
                    self.current_offset = f.tell()
                    self.current_inode = file_inode
                    self.current_record_id += 1
                    count += 1

                    line_str = line_bytes.decode("utf-8", errors="replace").strip("\r\n")
                    if not line_str:
                        continue

                    parsed = self._parse_line(line_str, self.current_record_id, self.current_offset)
                    if parsed:
                        parsed_events.append(parsed)

        except PermissionError as e:
            self.logger.error(f"Permission denied reading {self.log_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error reading {self.log_path}: {e}")

        return parsed_events

    def update_checkpoint(self, record_id: int, offset: int):
        """Advances the checkpoint following successful downstream processing."""
        if offset > 0:
            self.current_offset = offset
            self.current_record_id = record_id
            self.checkpoint_manager.save_checkpoint(
                offset=self.current_offset,
                inode=self.current_inode,
                record_id=self.current_record_id
            )

    def _parse_line(self, line: str, record_id: int, byte_offset: int) -> Optional[Dict[str, Any]]:
        """Parses a single syslog line into a structured event dict."""
        match = SYSLOG_LINE_RE.match(line)
        if not match:
            # Unstructured or malformed line - capture minimal provenance
            return {
                "record_id": record_id,
                "byte_offset": byte_offset,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": None,
                "process": "unknown",
                "pid": None,
                "raw_message": line[:500],  # Bound length
                "auth_status": "unknown",
                "username": None,
                "source_ip": None,
                "port": None,
                "auth_method": None,
                "event_subtype": "unstructured_log"
            }

        groups = match.groupdict()
        timestamp = parse_syslog_timestamp(groups["timestamp"])
        hostname = groups["hostname"]
        process = groups["process"]
        pid = int(groups["pid"]) if groups["pid"] else None
        message = groups["message"]

        # Default extracted fields
        auth_status = "info"
        username = None
        source_ip = None
        port = None
        auth_method = None
        event_subtype = "system_log"

        # Check SSH Failed
        m_ssh_fail = SSH_FAILED_RE.search(message)
        if m_ssh_fail:
            auth_status = "failed"
            auth_method = m_ssh_fail.group("method")
            username = m_ssh_fail.group("user")
            source_ip = m_ssh_fail.group("ip")
            port = int(m_ssh_fail.group("port"))
            event_subtype = "ssh_login_failure"
        else:
            # Check SSH Accepted
            m_ssh_acc = SSH_ACCEPTED_RE.search(message)
            if m_ssh_acc:
                auth_status = "accepted"
                auth_method = m_ssh_acc.group("method")
                username = m_ssh_acc.group("user")
                source_ip = m_ssh_acc.group("ip")
                port = int(m_ssh_acc.group("port"))
                event_subtype = "ssh_login_success"
            else:
                # Check SSH Invalid User
                m_ssh_inv = SSH_INVALID_USER_RE.search(message)
                if m_ssh_inv:
                    auth_status = "failed"
                    username = m_ssh_inv.group("user")
                    source_ip = m_ssh_inv.group("ip")
                    event_subtype = "ssh_invalid_user"
                else:
                    # Check Sudo failure
                    m_sudo_fail = SUDO_FAILURE_RE.search(message)
                    if m_sudo_fail:
                        auth_status = "failed"
                        username = m_sudo_fail.group("user") or None
                        event_subtype = "sudo_auth_failure"
                    else:
                        m_sudo_cmd = SUDO_COMMAND_RE.search(message)
                        if m_sudo_cmd:
                            auth_status = "accepted"
                            username = m_sudo_cmd.group("caller")
                            event_subtype = "sudo_command_execution"

        return {
            "record_id": record_id,
            "byte_offset": byte_offset,
            "timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "raw_message": message[:500],
            "auth_status": auth_status,
            "username": username,
            "source_ip": source_ip,
            "port": port,
            "auth_method": auth_method,
            "event_subtype": event_subtype
        }
