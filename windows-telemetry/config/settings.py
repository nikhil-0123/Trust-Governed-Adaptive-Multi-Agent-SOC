import os
import math
import re

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
        self.execution_mode = os.getenv("TGAM_EXECUTION_MODE", os.getenv("EXECUTION_MODE", "PRODUCTION")).strip().upper()
        self.log_level = os.getenv("LOG_LEVEL", "INFO")

        # Step 2: Collector Configuration
        self.windows_security_log_name = os.getenv("WINDOWS_SECURITY_LOG_NAME", "Security")
        self.windows_system_log_name = os.getenv("WINDOWS_SYSTEM_LOG_NAME", "System")
        self.windows_sysmon_log_name = os.getenv("WINDOWS_SYSMON_LOG_NAME", "Microsoft-Windows-Sysmon/Operational")
        self.enable_system_collection = os.getenv("ENABLE_SYSTEM_COLLECTION", "true").lower() == "true"
        self.enable_sysmon_collection = os.getenv("ENABLE_SYSMON_COLLECTION", "true").lower() == "true"
        val_batch = int(os.getenv("WINDOWS_EVENT_BATCH_SIZE", "100"))
        if val_batch < 1 or val_batch > 1000:
            raise ValueError(f"WINDOWS_EVENT_BATCH_SIZE must be an integer between 1 and 1000, got {val_batch}")
        self.windows_event_batch_size = val_batch
        self.windows_event_poll_interval = int(os.getenv("WINDOWS_EVENT_POLL_INTERVAL_SECONDS", "5"))
        self.windows_initial_lookback_minutes = int(os.getenv("WINDOWS_INITIAL_LOOKBACK_MINUTES", "10"))

        # Step 2a: Per-Channel Scheduling & Resilience Configuration (Phase 2.2)
        val_sec_poll = float(os.getenv("WINDOWS_SECURITY_POLL_INTERVAL_SECONDS", str(self.windows_event_poll_interval)))
        if not math.isfinite(val_sec_poll) or val_sec_poll < 0.1 or val_sec_poll > 300.0:
            raise ValueError(f"WINDOWS_SECURITY_POLL_INTERVAL_SECONDS must be finite and between 0.1 and 300.0, got {val_sec_poll}")
        self.windows_security_poll_interval = val_sec_poll

        val_sys_poll = float(os.getenv("WINDOWS_SYSTEM_POLL_INTERVAL_SECONDS", str(self.windows_event_poll_interval)))
        if not math.isfinite(val_sys_poll) or val_sys_poll < 0.1 or val_sys_poll > 300.0:
            raise ValueError(f"WINDOWS_SYSTEM_POLL_INTERVAL_SECONDS must be finite and between 0.1 and 300.0, got {val_sys_poll}")
        self.windows_system_poll_interval = val_sys_poll

        val_sysmon_poll = float(os.getenv("WINDOWS_SYSMON_POLL_INTERVAL_SECONDS", str(self.windows_event_poll_interval)))
        if not math.isfinite(val_sysmon_poll) or val_sysmon_poll < 0.1 or val_sysmon_poll > 300.0:
            raise ValueError(f"WINDOWS_SYSMON_POLL_INTERVAL_SECONDS must be finite and between 0.1 and 300.0, got {val_sysmon_poll}")
        self.windows_sysmon_poll_interval = val_sysmon_poll

        val_sec_batch = int(os.getenv("WINDOWS_SECURITY_BATCH_SIZE", str(self.windows_event_batch_size)))
        if val_sec_batch < 1 or val_sec_batch > 1000:
            raise ValueError(f"WINDOWS_SECURITY_BATCH_SIZE must be an integer between 1 and 1000, got {val_sec_batch}")
        self.windows_security_batch_size = val_sec_batch

        val_sys_batch = int(os.getenv("WINDOWS_SYSTEM_BATCH_SIZE", str(self.windows_event_batch_size)))
        if val_sys_batch < 1 or val_sys_batch > 1000:
            raise ValueError(f"WINDOWS_SYSTEM_BATCH_SIZE must be an integer between 1 and 1000, got {val_sys_batch}")
        self.windows_system_batch_size = val_sys_batch

        val_sysmon_batch = int(os.getenv("WINDOWS_SYSMON_BATCH_SIZE", str(self.windows_event_batch_size)))
        if val_sysmon_batch < 1 or val_sysmon_batch > 1000:
            raise ValueError(f"WINDOWS_SYSMON_BATCH_SIZE must be an integer between 1 and 1000, got {val_sysmon_batch}")
        self.windows_sysmon_batch_size = val_sysmon_batch

        val_timeout = float(os.getenv("WEVTUTIL_SUBPROCESS_TIMEOUT_SECONDS", "30.0"))
        if not math.isfinite(val_timeout) or val_timeout < 5.0 or val_timeout > 120.0:
            raise ValueError(f"WEVTUTIL_SUBPROCESS_TIMEOUT_SECONDS must be finite and between 5.0 and 120.0, got {val_timeout}")
        self.wevtutil_subprocess_timeout_seconds = val_timeout

        val_max_failures = int(os.getenv("CHANNEL_MAX_CONSECUTIVE_FAILURES", "5"))
        if val_max_failures < 1 or val_max_failures > 50:
            raise ValueError(f"CHANNEL_MAX_CONSECUTIVE_FAILURES must be an integer between 1 and 50, got {val_max_failures}")
        self.channel_max_consecutive_failures = val_max_failures

        val_backoff_base = float(os.getenv("CHANNEL_RETRY_BACKOFF_BASE_SECONDS", "2.0"))
        if not math.isfinite(val_backoff_base) or val_backoff_base < 0.5 or val_backoff_base > 60.0:
            raise ValueError(f"CHANNEL_RETRY_BACKOFF_BASE_SECONDS must be finite and between 0.5 and 60.0, got {val_backoff_base}")
        self.channel_retry_backoff_base_seconds = val_backoff_base

        val_backoff_max = float(os.getenv("CHANNEL_RETRY_BACKOFF_MAX_SECONDS", "60.0"))
        if not math.isfinite(val_backoff_max) or val_backoff_max < 1.0 or val_backoff_max > 300.0 or val_backoff_max < val_backoff_base:
            raise ValueError(f"CHANNEL_RETRY_BACKOFF_MAX_SECONDS must be finite, between 1.0 and 300.0, and >= base ({val_backoff_base}), got {val_backoff_max}")
        self.channel_retry_backoff_max_seconds = val_backoff_max

        # Default data directory to local user profile if not explicitly set
        default_data_dir = os.path.join(os.path.expanduser("~"), ".tgam_soc", "telemetry")
        self.data_dir = os.getenv("DATA_DIR", default_data_dir)

        # Internal backing attributes for dynamically resolved directory paths
        self._checkpoint_dir = os.getenv("WINDOWS_CHECKPOINT_DIR")
        self._detection_output_dir = os.getenv("DETECTION_OUTPUT_DIR")
        self._outbox_db_path = os.getenv("OUTBOX_DB_PATH")

        # Step 4: Detection Engine Configuration (Phase 1 & Phase 2)
        raw_det_ver = os.getenv("WINDOWS_DETECTOR_VERSION")
        if raw_det_ver is not None:
            stripped = raw_det_ver.strip()
            if not stripped:
                self.detector_version = "1.1.0"
            elif not re.match(r"^\d+\.\d+\.\d+$", stripped):
                raise ValueError(f"WINDOWS_DETECTOR_VERSION must be valid SemVer 'X.Y.Z', got '{raw_det_ver}'")
            else:
                self.detector_version = stripped
        else:
            self.detector_version = "1.1.0"
        val_max_keys = int(os.getenv("WINDOWS_DETECTION_MAX_STATE_KEYS", "10000"))
        if val_max_keys < 2:
            raise ValueError(f"WINDOWS_DETECTION_MAX_STATE_KEYS must be an integer >= 2, got {val_max_keys}")
        self.windows_detection_max_state_keys = val_max_keys

        val_cleanup_sec = float(os.getenv("WINDOWS_DETECTION_CLEANUP_INTERVAL_SECONDS", "5.0"))
        if not math.isfinite(val_cleanup_sec) or val_cleanup_sec <= 0:
            raise ValueError(f"WINDOWS_DETECTION_CLEANUP_INTERVAL_SECONDS must be finite and > 0, got {val_cleanup_sec}")
        self.windows_detection_cleanup_interval_seconds = val_cleanup_sec

        # Step 6: Central SOC Transport
        self.soc_api_url = os.getenv("SOC_API_URL", "http://127.0.0.1:8000/api/v1/detection-events")
        self.soc_transition_api_url = os.getenv("SOC_TRANSITION_API_URL", "http://127.0.0.1:8000/api/v1/events/transition")
        self.soc_api_token = os.getenv("SOC_API_TOKEN", "dev-token-123")
        self.soc_agent_api_token = os.getenv("SOC_AGENT_API_TOKEN", "").strip()
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

        # Step 8: Outbox Retention & Compaction (Phase 1)
        val_retention = int(os.getenv("OUTBOX_RETENTION_HOURS", "72"))
        if val_retention < 1:
            raise ValueError(f"OUTBOX_RETENTION_HOURS must be an integer >= 1, got {val_retention}")
        self.outbox_retention_hours = val_retention

        val_purge_interval = float(os.getenv("OUTBOX_PURGE_INTERVAL_SECONDS", "3600.0"))
        if not math.isfinite(val_purge_interval) or val_purge_interval < 1.0:
            raise ValueError(f"OUTBOX_PURGE_INTERVAL_SECONDS must be finite and >= 1.0, got {val_purge_interval}")
        self.outbox_purge_interval_seconds = val_purge_interval

        val_freelist_thresh = int(os.getenv("OUTBOX_VACUUM_FREELIST_THRESHOLD", "50"))
        if val_freelist_thresh < 1:
            raise ValueError(f"OUTBOX_VACUUM_FREELIST_THRESHOLD must be an integer >= 1, got {val_freelist_thresh}")
        self.outbox_vacuum_freelist_threshold = val_freelist_thresh

        val_vacuum_interval = float(os.getenv("OUTBOX_VACUUM_MIN_INTERVAL_SECONDS", "86400.0"))
        if not math.isfinite(val_vacuum_interval) or val_vacuum_interval < 60.0:
            raise ValueError(f"OUTBOX_VACUUM_MIN_INTERVAL_SECONDS must be finite and >= 60.0, got {val_vacuum_interval}")
        self.outbox_vacuum_min_interval_seconds = val_vacuum_interval

        self.outbox_vacuum_enabled = os.getenv("OUTBOX_VACUUM_ENABLED", "true").lower() == "true"

        # Step 9: Outbox Backpressure Quotas & Auto-Vacuum Policy (Phase 1 Remediation)
        val_max_pending = int(os.getenv("OUTBOX_MAX_PENDING_RECORDS", "50000"))
        if val_max_pending < 100:
            raise ValueError(f"OUTBOX_MAX_PENDING_RECORDS must be an integer >= 100, got {val_max_pending}")
        self.outbox_max_pending_records = val_max_pending

        val_disk_watermark = int(os.getenv("OUTBOX_DISK_WATERMARK_MB", "500"))
        if val_disk_watermark < 10:
            raise ValueError(f"OUTBOX_DISK_WATERMARK_MB must be an integer >= 10, got {val_disk_watermark}")
        self.outbox_disk_watermark_mb = val_disk_watermark

        self.outbox_backpressure_enabled = os.getenv("OUTBOX_BACKPRESSURE_ENABLED", "true").lower() == "true"

        val_auto_vacuum = os.getenv("OUTBOX_AUTO_VACUUM_MODE", "NONE").strip().upper()
        if val_auto_vacuum not in ("NONE", "FULL", "INCREMENTAL"):
            raise ValueError(f"OUTBOX_AUTO_VACUUM_MODE must be NONE, FULL, or INCREMENTAL, got {val_auto_vacuum}")
        self.outbox_auto_vacuum_mode = val_auto_vacuum

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
