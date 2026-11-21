import platform
import threading
import time
from typing import Optional
import logging

from config.settings import config
from .logger import setup_logger
from .agent_identity import AgentIdentity
from .health import HealthMonitor

class TelemetryRuntime:
    _logger_lock = threading.Lock()
    _logger_users: dict[logging.Logger, int] = {}
    _owned_handlers: dict[logging.Logger, set[logging.Handler]] = {}

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.start_time = time.time()
        self._owns_logger = logger is None
        self._logger_released = False
        with self._logger_lock:
            if self._owns_logger:
                configured = logging.getLogger(config.app_name)
                previous_handlers = set(configured.handlers)
                self.logger = setup_logger(config.app_name, config.log_level, config.data_dir)
                added = set(self.logger.handlers) - previous_handlers
                if added:
                    self._owned_handlers.setdefault(self.logger, set()).update(added)
            else:
                self.logger = logger
            self._logger_users[self.logger] = self._logger_users.get(self.logger, 0) + 1
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

        with self._logger_lock:
            if self._logger_released:
                return
            self._logger_released = True

            self._logger_users[self.logger] -= 1
            if self._logger_users[self.logger]:
                return
            del self._logger_users[self.logger]

            for handler in self._owned_handlers.pop(self.logger, ()):
                self.logger.removeHandler(handler)
                try:
                    handler.flush()
                except Exception:
                    pass
                try:
                    handler.close()
                except Exception:
                    pass
