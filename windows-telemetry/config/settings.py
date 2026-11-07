import os

def _load_env_file():
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        os.path.join(os.getcwd(), ".env")
    ]
    for env_path in candidates:
        if os.path.isfile(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass

_load_env_file()

class Settings:
    def __init__(self):
        self.app_name = os.getenv("APP_NAME", "TGAM-SOC Windows Telemetry")
        self.version = os.getenv("APP_VERSION", "0.1.0")
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")

        # Step 2: Collector Configuration
        self.windows_security_log_name = os.getenv("WINDOWS_SECURITY_LOG_NAME", "Security")
        self.windows_event_batch_size = int(os.getenv("WINDOWS_EVENT_BATCH_SIZE", "100"))
        self.windows_event_poll_interval = int(os.getenv("WINDOWS_EVENT_POLL_INTERVAL_SECONDS", "5"))
        self.windows_initial_lookback_minutes = int(os.getenv("WINDOWS_INITIAL_LOOKBACK_MINUTES", "10"))

        # Default data directory to local user profile if not explicitly set
        default_data_dir = os.path.join(os.path.expanduser("~"), ".tgam_soc", "telemetry")
        self.data_dir = os.getenv("DATA_DIR", default_data_dir)

        # Internal backing attributes for dynamically resolved directory paths
        self._checkpoint_dir = os.getenv("WINDOWS_CHECKPOINT_DIR")
        self._detection_output_dir = os.getenv("DETECTION_OUTPUT_DIR")
        self._outbox_db_path = os.getenv("OUTBOX_DB_PATH")

        # Step 4: Detection Engine Configuration (Phase 1)
        val_max_keys = int(os.getenv("WINDOWS_DETECTION_MAX_STATE_KEYS", "10000"))
        if val_max_keys < 2:
            raise ValueError(f"WINDOWS_DETECTION_MAX_STATE_KEYS must be an integer >= 2, got {val_max_keys}")
        self.windows_detection_max_state_keys = val_max_keys

        val_cleanup_sec = float(os.getenv("WINDOWS_DETECTION_CLEANUP_INTERVAL_SECONDS", "5.0"))
        import math
        if not math.isfinite(val_cleanup_sec) or val_cleanup_sec <= 0:
            raise ValueError(f"WINDOWS_DETECTION_CLEANUP_INTERVAL_SECONDS must be finite and > 0, got {val_cleanup_sec}")
        self.windows_detection_cleanup_interval_seconds = val_cleanup_sec

        # Step 6: Central SOC Transport
        self.soc_api_url = os.getenv("SOC_API_URL", "http://127.0.0.1:8000/api/v1/detection-events")
        self.soc_api_token = os.getenv("SOC_API_TOKEN", "dev-token-123")
        self.medium_confidence_threshold = float(os.getenv("MEDIUM_CONFIDENCE_THRESHOLD", "0.8"))

        # Step 7: Outbox Storage & WAL Configuration (WP-2-D)
        val_sync = os.getenv("OUTBOX_SYNCHRONOUS_MODE", "NORMAL").strip().upper()
        if val_sync not in ("NORMAL", "FULL"):
            raise ValueError(f"OUTBOX_SYNCHRONOUS_MODE must be 'NORMAL' or 'FULL', got '{val_sync}'")
        self.outbox_synchronous_mode = val_sync

        val_busy_timeout = int(os.getenv("OUTBOX_BUSY_TIMEOUT_MS", "5000"))
        if val_busy_timeout < 1000:
            raise ValueError(f"OUTBOX_BUSY_TIMEOUT_MS must be an integer >= 1000, got {val_busy_timeout}")
        self.outbox_busy_timeout_ms = val_busy_timeout

        val_autocheckpoint = int(os.getenv("OUTBOX_WAL_AUTOCHECKPOINT", "1000"))
        if val_autocheckpoint < 10:
            raise ValueError(f"OUTBOX_WAL_AUTOCHECKPOINT must be an integer >= 10, got {val_autocheckpoint}")
        self.outbox_wal_autocheckpoint = val_autocheckpoint

    @property
    def checkpoint_dir(self) -> str:
        return self._checkpoint_dir or os.path.join(self.data_dir, "state")

    @checkpoint_dir.setter
    def checkpoint_dir(self, value: str):
        self._checkpoint_dir = value

    @property
    def detection_output_dir(self) -> str:
        return self._detection_output_dir or os.path.join(self.data_dir, "detections")

    @detection_output_dir.setter
    def detection_output_dir(self, value: str):
        self._detection_output_dir = value

    @property
    def outbox_db_path(self) -> str:
        return self._outbox_db_path or os.path.join(self.data_dir, "outbox.db")

    @outbox_db_path.setter
    def outbox_db_path(self, value: str):
        self._outbox_db_path = value

    def ensure_directories(self):
        """Explicitly provisions required application directories without side effects during initialization."""
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        os.makedirs(self.detection_output_dir, exist_ok=True)
        outbox_dir = os.path.dirname(os.path.abspath(self.outbox_db_path))
        if outbox_dir:
            os.makedirs(outbox_dir, exist_ok=True)

config = Settings()
