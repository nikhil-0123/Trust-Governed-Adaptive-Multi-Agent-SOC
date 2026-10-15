import threading
import time
import socket
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from response.executor import WindowsResponseExecutor

DEFAULT_WINDOWS_CAPABILITIES = [
    "EventLog_4625", "EventLog_4688",
    "BLOCK_SOURCE", "KILL_PROCESS", "ISOLATE_HOST", "DISABLE_ACCOUNT"
]

class HeartbeatWorker(threading.Thread):
    """
    Background worker that sends periodic heartbeats to Central SOC
    and polls/executes management and mitigation commands.
    """
    def __init__(
        self,
        agent_id: str,
        os_type: str,
        soc_api_url: str,
        api_token: str,
        logger: logging.Logger,
        capabilities: Optional[List[str]] = None,
        heartbeat_interval: float = 15.0
    ):
        super().__init__(name="HeartbeatWorker", daemon=True)
        self.agent_id = agent_id
        self.os_type = os_type
        if "/api/v1" in soc_api_url:
            self.base_url = soc_api_url.split("/api/v1")[0]
        else:
            self.base_url = soc_api_url.rstrip("/")
        self.api_token = api_token
        self.logger = logger
        self.capabilities = capabilities or list(DEFAULT_WINDOWS_CAPABILITIES)
        self.heartbeat_interval = heartbeat_interval
        self._stop_event = threading.Event()
        self._start_time = time.time()
        self.executor = WindowsResponseExecutor(soc_base_url=self.base_url, logger=self.logger)

    def run(self):
        self.logger.info(f"HeartbeatWorker started for agent {self.agent_id} (interval={self.heartbeat_interval}s).")
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
            except Exception as e:
                self.logger.debug(f"Heartbeat check failed: {e}")
            self._stop_event.wait(self.heartbeat_interval)
        self.logger.info("HeartbeatWorker stopped.")

    def stop(self):
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=5.0)

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _send_heartbeat(self):
        url = f"{self.base_url}/api/v1/endpoints/heartbeat"
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os": self.os_type,
            "ip_address": self._get_local_ip(),
            "agent_version": "1.0.0",
            "capabilities": self.capabilities
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_token}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    commands = body.get("commands", [])
                    for cmd in commands:
                        self._handle_command(cmd)
        except Exception as e:
            self.logger.debug(f"Heartbeat dispatch failed to {url}: {e}")

    def _handle_command(self, cmd: Dict[str, Any]):
        cmd_id = cmd.get("command_id")
        cmd_type = cmd.get("command_type", "").upper()
        if not cmd_id:
            return

        self.logger.info(f"Executing remote command {cmd_type} (id: {cmd_id})")
        result: Dict[str, Any] = {}
        status = "EXECUTED"

        try:
            if cmd_type == "PING":
                result = {
                    "pong": True,
                    "agent_id": self.agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            elif cmd_type == "GET_HEALTH":
                result = {
                    "status": "HEALTHY",
                    "hostname": socket.gethostname(),
                    "os": self.os_type,
                    "uptime_seconds": round(time.time() - self._start_time, 2),
                    "local_ip": self._get_local_ip()
                }
            elif cmd_type == "GET_STATUS":
                result = {
                    "status": "RUNNING",
                    "agent_id": self.agent_id,
                    "capabilities": self.capabilities,
                    "agent_version": "1.0.0"
                }
            elif cmd_type in (
                "BLOCK_SOURCE", "BLOCK_SOURCE_IP", "UNBLOCK_SOURCE",
                "KILL_PROCESS", "ISOLATE_HOST", "RESTORE_HOST", "DISABLE_ACCOUNT"
            ):
                raw_params = cmd.get("parameters") or {}
                if isinstance(raw_params, str):
                    try:
                        raw_params = json.loads(raw_params)
                    except Exception:
                        raw_params = {}
                result = self.executor.execute(cmd_type, raw_params)
                if (result.get("applied") is False or
                    result.get("terminated") is False or
                    result.get("disabled") is False or
                    "error" in result):
                    status = "FAILED"
            else:
                status = "FAILED"
                result = {"error": f"Unknown command type: {cmd_type}"}
        except Exception as err:
            status = "FAILED"
            result = {"error": str(err)}

        self._report_command_result(cmd_id, status, result)

    def _report_command_result(self, cmd_id: str, status: str, result: Dict[str, Any]):
        url = f"{self.base_url}/api/v1/endpoints/{self.agent_id}/commands/{cmd_id}/result"
        payload = {"status": status, "result": result}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_token}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self.logger.info(f"Command {cmd_id} result reported: status={resp.status}")
        except Exception as e:
            self.logger.warning(f"Failed to report command result for {cmd_id}: {e}")
