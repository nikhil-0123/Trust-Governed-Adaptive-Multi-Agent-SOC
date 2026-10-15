import ipaddress
import logging
import os
import re
import signal
import subprocess
import urllib.parse
from typing import Dict, Any, Optional, Set

PROTECTED_LINUX_PROCESSES: Set[str] = {
    "systemd", "init", "sshd", "kthreadd",
    "systemd-journald", "systemd-udevd", "bash", "sh"
}

PROTECTED_LINUX_ACCOUNTS: Set[str] = {
    "root", "daemon", "bin", "sys", "sync", "games", "man"
}


class LinuxResponseExecutor:
    """
    Executes governed mitigation actions on Linux/Ubuntu endpoints.
    Supported actions:
      - BLOCK_SOURCE / BLOCK_SOURCE_IP
      - UNBLOCK_SOURCE
      - KILL_PROCESS
      - ISOLATE_HOST
      - RESTORE_HOST
      - DISABLE_ACCOUNT
    """

    def __init__(self, soc_base_url: str = "", logger: Optional[logging.Logger] = None):
        self.soc_base_url = soc_base_url
        self.logger = logger or logging.getLogger("LinuxResponseExecutor")

    def execute(self, command_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches mitigation command to specific handler."""
        norm_type = command_type.upper()
        self.logger.info(f"Executing Linux mitigation: {norm_type} with parameters: {parameters}")

        if norm_type in ("BLOCK_SOURCE", "BLOCK_SOURCE_IP"):
            return self.block_source(parameters)
        elif norm_type == "UNBLOCK_SOURCE":
            return self.unblock_source(parameters)
        elif norm_type == "KILL_PROCESS":
            return self.kill_process(parameters)
        elif norm_type == "ISOLATE_HOST":
            return self.isolate_host(parameters)
        elif norm_type == "RESTORE_HOST":
            return self.restore_host(parameters)
        elif norm_type == "DISABLE_ACCOUNT":
            return self.disable_account(parameters)
        else:
            raise ValueError(f"Unsupported Linux mitigation command: {command_type}")

    def block_source(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Blocks an attacker IP using iptables.
        """
        raw_ip = parameters.get("ip")
        if not raw_ip:
            raise ValueError("Target IP address ('ip') is required for BLOCK_SOURCE")

        ip_obj = ipaddress.ip_address(raw_ip.strip())
        if ip_obj.is_loopback:
            raise ValueError(f"Cannot block loopback IP: {raw_ip}")

        ip_str = str(ip_obj)
        comment = f"TGAM-SOC-Block-{ip_str}"
        simulate = parameters.get("simulate", False)

        cmd = ["iptables", "-A", "INPUT", "-s", ip_str, "-m", "comment", "--comment", comment, "-j", "DROP"]

        if simulate:
            self.logger.info(f"[SIMULATION] Would execute: {' '.join(cmd)}")
            return {
                "action": "BLOCK_SOURCE",
                "target_ip": ip_str,
                "comment": comment,
                "simulated": True,
                "command": " ".join(cmd)
            }

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode != 0:
                err_msg = res.stderr.strip() or res.stdout.strip()
                self.logger.warning(f"Failed to add iptables rule: {err_msg}")
                return {
                    "action": "BLOCK_SOURCE",
                    "target_ip": ip_str,
                    "applied": False,
                    "error": err_msg or "Failed to add iptables rule (Root privileges required)."
                }
            return {
                "action": "BLOCK_SOURCE",
                "target_ip": ip_str,
                "applied": True,
                "output": res.stdout.strip()
            }
        except Exception as e:
            self.logger.error(f"Error executing BLOCK_SOURCE for {ip_str}: {e}")
            raise

    def unblock_source(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Removes previously applied iptables DROP rule for an IP.
        """
        raw_ip = parameters.get("ip")
        if not raw_ip:
            raise ValueError("Target IP address ('ip') is required for UNBLOCK_SOURCE")

        ip_str = str(ipaddress.ip_address(raw_ip.strip()))
        comment = f"TGAM-SOC-Block-{ip_str}"
        simulate = parameters.get("simulate", False)

        cmd = ["iptables", "-D", "INPUT", "-s", ip_str, "-m", "comment", "--comment", comment, "-j", "DROP"]

        if simulate:
            return {
                "action": "UNBLOCK_SOURCE",
                "target_ip": ip_str,
                "simulated": True,
                "command": " ".join(cmd)
            }

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return {
                "action": "UNBLOCK_SOURCE",
                "target_ip": ip_str,
                "removed": res.returncode == 0,
                "output": (res.stdout or res.stderr).strip()
            }
        except Exception as e:
            self.logger.error(f"Error executing UNBLOCK_SOURCE for {ip_str}: {e}")
            raise

    def kill_process(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Terminates a malicious process by PID or name on Linux with safety checks.
        """
        raw_pid = parameters.get("process_id") or parameters.get("pid")
        process_name = parameters.get("process_name")
        simulate = parameters.get("simulate", False)

        if not raw_pid and not process_name:
            raise ValueError("Either 'process_id' or 'process_name' is required for KILL_PROCESS")

        # 1. PID-based termination
        if raw_pid is not None:
            try:
                pid = int(raw_pid)
            except ValueError:
                raise ValueError(f"Invalid process_id: {raw_pid}")

            current_pid = os.getpid()
            parent_pid = os.getppid() if hasattr(os, "getppid") else -1
            if pid <= 1 or pid == current_pid or pid == parent_pid:
                raise PermissionError(f"Target PID {pid} is a protected system or agent process.")

            cmd = ["kill", "-9", str(pid)]
            if simulate:
                return {
                    "action": "KILL_PROCESS",
                    "target_pid": pid,
                    "simulated": True,
                    "command": " ".join(cmd)
                }

            try:
                sig = getattr(signal, "SIGKILL", 9)
                os.kill(pid, sig)
                return {
                    "action": "KILL_PROCESS",
                    "target_pid": pid,
                    "terminated": True,
                    "output": f"Sent SIGKILL to PID {pid}"
                }
            except ProcessLookupError:
                return {
                    "action": "KILL_PROCESS",
                    "target_pid": pid,
                    "terminated": False,
                    "output": f"PID {pid} not found (may have already exited)"
                }
            except PermissionError as pe:
                return {
                    "action": "KILL_PROCESS",
                    "target_pid": pid,
                    "terminated": False,
                    "error": str(pe)
                }

        # 2. Process Name termination
        clean_name = str(process_name).strip()
        if clean_name.lower() in PROTECTED_LINUX_PROCESSES:
            raise PermissionError(f"Process '{clean_name}' is in the protected Linux process list.")

        cmd = ["pkill", "-9", "-f", clean_name]
        if simulate:
            return {
                "action": "KILL_PROCESS",
                "target_process_name": clean_name,
                "simulated": True,
                "command": " ".join(cmd)
            }

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        success = res.returncode == 0
        return {
            "action": "KILL_PROCESS",
            "target_process_name": clean_name,
            "terminated": success,
            "output": (res.stdout if success else res.stderr).strip()
        }

    def isolate_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Isolates Linux host from the network while preserving SOC connectivity and loopback.
        """
        simulate = parameters.get("simulate", False)
        preserve_soc = parameters.get("preserve_soc_communication", True)

        soc_ip = parameters.get("soc_ip")
        if not soc_ip and self.soc_base_url:
            parsed = urllib.parse.urlparse(self.soc_base_url)
            soc_ip = parsed.hostname

        if not soc_ip or soc_ip in ("localhost", "127.0.0.1"):
            soc_ip = "127.0.0.1"

        cmds = []
        # Allow loopback
        cmds.append(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        cmds.append(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])

        if preserve_soc and soc_ip != "127.0.0.1":
            cmds.append(["iptables", "-A", "OUTPUT", "-d", soc_ip, "-j", "ACCEPT"])
            cmds.append(["iptables", "-A", "INPUT", "-s", soc_ip, "-j", "ACCEPT"])

        # Block everything else
        cmds.append(["iptables", "-A", "OUTPUT", "-j", "DROP"])

        if simulate:
            return {
                "action": "ISOLATE_HOST",
                "preserved_soc_ip": soc_ip,
                "simulated": True,
                "commands": [" ".join(c) for c in cmds]
            }

        results = []
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            results.append({"command": " ".join(cmd), "code": r.returncode, "msg": (r.stdout or r.stderr).strip()})

        all_ok = all(r["code"] == 0 for r in results)
        return {
            "action": "ISOLATE_HOST",
            "preserved_soc_ip": soc_ip,
            "applied": all_ok,
            "details": results
        }

    def restore_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reverts host isolation by clearing isolation rules.
        """
        simulate = parameters.get("simulate", False)
        cmds = [
            ["iptables", "-D", "OUTPUT", "-j", "DROP"]
        ]

        if simulate:
            return {
                "action": "RESTORE_HOST",
                "simulated": True,
                "commands": [" ".join(c) for c in cmds]
            }

        details = []
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            details.append({"command": " ".join(cmd), "code": r.returncode, "msg": (r.stdout or r.stderr).strip()})

        return {
            "action": "RESTORE_HOST",
            "restored": True,
            "details": details
        }

    def disable_account(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Locks a user account on Linux using usermod -L.
        """
        raw_user = parameters.get("username")
        if not raw_user:
            raise ValueError("Target 'username' is required for DISABLE_ACCOUNT")

        username = str(raw_user).strip()
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
            raise ValueError(f"Invalid username format: {username}")

        if username.lower() in PROTECTED_LINUX_ACCOUNTS:
            raise PermissionError(f"Account '{username}' is protected and cannot be disabled.")

        simulate = parameters.get("simulate", False)
        cmd = ["usermod", "-L", username]

        if simulate:
            return {
                "action": "DISABLE_ACCOUNT",
                "target_user": username,
                "simulated": True,
                "command": " ".join(cmd)
            }

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        success = res.returncode == 0
        return {
            "action": "DISABLE_ACCOUNT",
            "target_user": username,
            "disabled": success,
            "output": (res.stdout if success else res.stderr).strip()
        }
