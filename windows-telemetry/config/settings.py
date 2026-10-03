import os

class Settings:
    def __init__(self):
        self.app_name = os.getenv("APP_NAME", "TGAM-SOC Windows Telemetry")
        self.version = os.getenv("APP_VERSION", "0.1.0")
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        
        # Default data directory to local user profile if not explicitly set
        default_data_dir = os.path.join(os.path.expanduser("~"), ".tgam_soc", "telemetry")
        self.data_dir = os.getenv("DATA_DIR", default_data_dir)

config = Settings()
