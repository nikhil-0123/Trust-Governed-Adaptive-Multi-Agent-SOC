import platform
import sys
import time
from typing import Optional
import logging

from config.settings import config
from .logger import setup_logger
from .agent_identity import AgentIdentity
from .health import HealthMonitor

class TelemetryRuntime:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.start_time = time.time()
        self._owns_logger = logger is None
        self.logger = logger or setup_logger(config.app_name, config.log_level, config.data_dir)
        self.identity: Optional[AgentIdentity] = None
        self.health: Optional[HealthMonitor] = None

    def validate_environment(self):
        current_os = platform.system()
        if current_os != "Windows":
            self.logger.error(f"Unsupported OS: {current_os}. This telemetry agent is for Windows only.")
            raise RuntimeError(f"Unsupported OS: {current_os}. This telemetry agent is for Windows only.")
        self.logger.info(f"Environment validation passed. OS: {current_os}")

    def start(self):
        self.logger.info(f"Starting {config.app_name} v{config.version}")
        self.validate_environment()
        config.ensure_directories()

        self.identity = AgentIdentity(config.data_dir)
        self.logger.info(f"Agent Identity initialized: {self.identity.agent_id}")

        self.health = HealthMonitor(self.identity, config.version, self.start_time)

        health_status = self.health.get_status()
        self.logger.info(f"Health Status: {health_status}")

        self.logger.info("Foundation initialized successfully. Ready for future collectors.")

    def stop(self):
        self.logger.info("Initiating clean shutdown...")
        # Future shutdown hooks for collectors will go here
        self.logger.info("Shutdown complete.")

        # Only close handlers owned by a logger created by this runtime.
        if not self._owns_logger:
            return
        for handler in list(self.logger.handlers):
            try:
                handler.flush()
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                self.logger.removeHandler(handler)
            except Exception:
                pass
