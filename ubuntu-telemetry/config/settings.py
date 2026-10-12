import os

class Settings:
    def __init__(self):
        self.app_name = os.getenv("APP_NAME", "TGAM-SOC Ubuntu Telemetry")
        self.version = os.getenv("APP_VERSION", "0.1.0")
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")

        # Collector Configuration
        self.auth_log_path = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
        self.ubuntu_event_batch_size = int(os.getenv("UBUNTU_EVENT_BATCH_SIZE", "100"))
        self.ubuntu_event_poll_interval = int(os.getenv("UBUNTU_EVENT_POLL_INTERVAL_SECONDS", "5"))

        # State and Data directories
        default_data_dir = os.path.join(os.path.expanduser("~"), ".tgam_soc", "ubuntu_telemetry")
        self.data_dir = os.getenv("DATA_DIR", default_data_dir)

        default_checkpoint_dir = os.path.join(self.data_dir, "state")
        self.checkpoint_dir = os.getenv("UBUNTU_CHECKPOINT_DIR", default_checkpoint_dir)

        # Detection Output
        default_detection_output_dir = os.path.join(self.data_dir, "detections")
        self.detection_output_dir = os.getenv("DETECTION_OUTPUT_DIR", default_detection_output_dir)

        # Central SOC Transport
        self.soc_api_url = os.getenv("SOC_API_URL", "http://127.0.0.1:8000/api/v1/detection-events")
        self.soc_api_token = os.getenv("SOC_API_TOKEN", "dev-token-123")
        self.outbox_db_path = os.getenv("OUTBOX_DB_PATH", os.path.join(self.data_dir, "outbox.db"))
        self.medium_confidence_threshold = float(os.getenv("MEDIUM_CONFIDENCE_THRESHOLD", "0.8"))

config = Settings()
