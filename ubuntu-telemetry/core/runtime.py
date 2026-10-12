import platform
import time
from typing import Optional

from config.settings import config
from .logger import setup_logger
from .agent_identity import AgentIdentity
from .health import HealthMonitor

class TelemetryRuntime:
    def __init__(self):
        self.start_time = time.time()
        self.logger = setup_logger(config.app_name, config.log_level, config.data_dir)
        self.identity: Optional[AgentIdentity] = None
        self.health: Optional[HealthMonitor] = None

    def validate_environment(self, enforce_linux: bool = False):
        current_os = platform.system()
        if enforce_linux and current_os != "Linux":
            self.logger.error(f"Unsupported OS: {current_os}. This telemetry agent is designed for Ubuntu/Linux.")
            raise RuntimeError(f"Unsupported OS: {current_os}. This telemetry agent is designed for Ubuntu/Linux.")
        self.logger.info(f"Environment validation completed. OS: {current_os}")

    def start(self, enforce_linux: bool = False):
        self.logger.info(f"Starting {config.app_name} v{config.version}")
        self.validate_environment(enforce_linux=enforce_linux)

        self.identity = AgentIdentity(config.data_dir)
        self.logger.info(f"Agent Identity initialized: {self.identity.agent_id}")

        self.health = HealthMonitor(self.identity, config.version, self.start_time)
        health_status = self.health.get_status()
        self.logger.info(f"Health Status: {health_status}")

    def stop(self):
        self.logger.info("Initiating clean shutdown...")
        self.logger.info("Shutdown complete.")
