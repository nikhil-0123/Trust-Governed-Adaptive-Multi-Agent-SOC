import unittest
import platform
import tempfile
import shutil
import os
import logging
import io
from pathlib import Path
from unittest.mock import patch
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

    def test_supplied_logging_handlers_remain_attached_and_usable_on_stop(self):
        with tempfile.TemporaryDirectory() as test_dir, io.StringIO() as stream:
            logger = logging.Logger("TestIsolatedRuntimeLogger", logging.INFO)
            log_file = Path(test_dir) / "telemetry.log"
            handlers = (logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler(stream))
            for handler in handlers:
                logger.addHandler(handler)

            try:
                TelemetryRuntime(logger=logger).stop()

                self.assertEqual(tuple(logger.handlers), handlers)
                self.assertIsNotNone(handlers[0].stream)
                logger.info("after stop")
                self.assertIn("after stop", stream.getvalue())
                self.assertIn("after stop", log_file.read_text(encoding="utf-8"))
            finally:
                for handler in handlers:
                    logger.removeHandler(handler)
                    handler.close()

    def test_shared_runtime_handlers_close_after_last_user_stops(self):
        with tempfile.TemporaryDirectory() as test_dir, patch.multiple(
            config, app_name="TestSharedRuntimeLogger", data_dir=test_dir
        ):
            owner = TelemetryRuntime()
            second = TelemetryRuntime()
            supplied = TelemetryRuntime(logger=owner.logger)
            file_handler = next(h for h in owner.logger.handlers if isinstance(h, logging.FileHandler))
            external = logging.NullHandler()
            owner.logger.addHandler(external)
            try:
                owner.stop()
                second.stop()
                second.stop()
                self.assertIn(file_handler, supplied.logger.handlers)
                supplied.logger.info("after owner stopped")
                self.assertIn("after owner stopped", Path(file_handler.baseFilename).read_text(encoding="utf-8"))

                supplied.stop()
                self.assertEqual(supplied.logger.handlers, [external])
                self.assertIsNone(file_handler.stream)

                # A runtime that finds existing handlers must leave them attached.
                TelemetryRuntime().stop()
                self.assertEqual(owner.logger.handlers, [external])
            finally:
                owner.stop()
                second.stop()
                supplied.stop()
                owner.logger.removeHandler(external)
                external.close()

if __name__ == "__main__":
    unittest.main()
