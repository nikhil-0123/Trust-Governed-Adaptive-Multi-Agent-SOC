import unittest
import os
import tempfile
from config.settings import Settings

class TestConfig(unittest.TestCase):
    def test_default_config(self):
        settings = Settings()
        self.assertTrue(settings.app_name)
        self.assertTrue(settings.version)
        self.assertTrue(settings.log_level)
        self.assertTrue(settings.data_dir)
        self.assertIsInstance(settings.data_dir, str)
        self.assertGreater(len(settings.data_dir), 0)
        self.assertEqual(settings.medium_confidence_threshold, 0.8)
        self.assertEqual(settings.windows_detection_max_state_keys, 10000)
        self.assertEqual(settings.windows_detection_cleanup_interval_seconds, 5.0)

    def test_settings_initialization_has_no_filesystem_side_effects(self):
        with tempfile.TemporaryDirectory() as base_tmp:
            dummy_target = os.path.join(base_tmp, "non_existent_telemetry_dir")
            os.environ["DATA_DIR"] = dummy_target
            try:
                settings = Settings()
                self.assertEqual(settings.data_dir, dummy_target)
                self.assertFalse(os.path.exists(dummy_target), "Settings.__init__ must not create directories")
            finally:
                os.environ.pop("DATA_DIR", None)

    def test_ensure_directories_with_temp_dir(self):
        with tempfile.TemporaryDirectory() as base_tmp:
            settings = Settings()
            settings.data_dir = os.path.join(base_tmp, "telemetry")
            settings.checkpoint_dir = os.path.join(settings.data_dir, "state")
            settings.detection_output_dir = os.path.join(settings.data_dir, "detections")
            settings.outbox_db_path = os.path.join(settings.data_dir, "outbox.db")

            self.assertFalse(os.path.exists(settings.data_dir))
            settings.ensure_directories()
            self.assertTrue(os.path.exists(settings.data_dir))
            self.assertTrue(os.path.exists(settings.checkpoint_dir))
            self.assertTrue(os.path.exists(settings.detection_output_dir))
            self.assertTrue(os.path.exists(os.path.dirname(os.path.abspath(settings.outbox_db_path))))

    def test_invalid_max_state_keys_env_var(self):
        os.environ["WINDOWS_DETECTION_MAX_STATE_KEYS"] = "1"
        try:
            with self.assertRaises(ValueError):
                Settings()
        finally:
            os.environ.pop("WINDOWS_DETECTION_MAX_STATE_KEYS", None)

    def test_invalid_cleanup_interval_env_var(self):
        os.environ["WINDOWS_DETECTION_CLEANUP_INTERVAL_SECONDS"] = "0"
        try:
            with self.assertRaises(ValueError):
                Settings()
        finally:
            os.environ.pop("WINDOWS_DETECTION_CLEANUP_INTERVAL_SECONDS", None)

if __name__ == "__main__":
    unittest.main()
