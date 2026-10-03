import os

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

        default_checkpoint_dir = os.path.join(self.data_dir, "state")
        self.checkpoint_dir = os.getenv("WINDOWS_CHECKPOINT_DIR", default_checkpoint_dir)
        
        # Step 5: Detection Output
        default_detection_output_dir = os.path.join(self.data_dir, "detections")
        self.detection_output_dir = os.getenv("DETECTION_OUTPUT_DIR", default_detection_output_dir)

config = Settings()
