import unittest
import platform
import tempfile
import shutil
import os
import logging
from core.runtime import TelemetryRuntime
from config.settings import config

class TestRuntime(unittest.TestCase):
    def test_runtime_startup_shutdown(self):
        if platform.system() != "Windows":
            self.skipTest("Skipping runtime test on non-Windows platform")

        test_dir = tempfile.mkdtemp()
        orig_data_dir = config.data_dir
        orig_checkpoint = config.checkpoint_dir
        orig_detection = config.detection_output_dir
        orig_outbox = config.outbox_db_path

        config.data_dir = test_dir
        config.checkpoint_dir = os.path.join(test_dir, "state")
        config.detection_output_dir = os.path.join(test_dir, "detections")
        config.outbox_db_path = os.path.join(test_dir, "outbox.db")

        runtime = TelemetryRuntime()

        try:
            runtime.start()
            self.assertIsNotNone(runtime.identity)
            self.assertIsNotNone(runtime.health)
            runtime.stop()
        finally:
            config.data_dir = orig_data_dir
            config.checkpoint_dir = orig_checkpoint
            config.detection_output_dir = orig_detection
            config.outbox_db_path = orig_outbox
            for handler in runtime.logger.handlers[:]:
                handler.close()
                runtime.logger.removeHandler(handler)
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_logging_handlers_closed_and_removed_on_stop(self):
        if platform.system() != "Windows":
            self.skipTest("Skipping runtime test on non-Windows platform")

        test_dir = tempfile.mkdtemp()
        orig_data_dir = config.data_dir
        orig_checkpoint = config.checkpoint_dir
        orig_detection = config.detection_output_dir
        orig_outbox = config.outbox_db_path

        config.data_dir = test_dir
        config.checkpoint_dir = os.path.join(test_dir, "state")
        config.detection_output_dir = os.path.join(test_dir, "detections")
        config.outbox_db_path = os.path.join(test_dir, "outbox.db")

        # Create isolated custom logger to test lifecycle
        isolated_logger = logging.getLogger("TestIsolatedRuntimeLogger")
        isolated_logger.handlers.clear()

        log_dir = os.path.join(test_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "test_telemetry.log")
        fh = logging.FileHandler(log_file, encoding="utf-8")
        ch = logging.StreamHandler()
        isolated_logger.addHandler(fh)
        isolated_logger.addHandler(ch)

        runtime = TelemetryRuntime(logger=isolated_logger)

        try:
            runtime.start()
            runtime.stop()

            # Verify FileHandler was safely closed and removed
            self.assertNotIn(fh, runtime.logger.handlers)
            self.assertNotIn(ch, runtime.logger.handlers)
            self.assertTrue(fh.stream is None or fh.stream.closed)

            # File should not be locked by the OS; rmtree must succeed cleanly
            shutil.rmtree(test_dir)
            self.assertFalse(os.path.exists(test_dir))
        finally:
            config.data_dir = orig_data_dir
            config.checkpoint_dir = orig_checkpoint
            config.detection_output_dir = orig_detection
            config.outbox_db_path = orig_outbox
            if os.path.exists(test_dir):
                shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
