import unittest
import os
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock

from config.settings import config
from pipeline import UbuntuDetectionPipeline

class TestUbuntuMainAndPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "outbox.db")
        self.state_dir = os.path.join(self.test_dir, "state")
        self.det_dir = os.path.join(self.test_dir, "detections")

        config.data_dir = self.test_dir
        config.outbox_db_path = self.db_path
        config.checkpoint_dir = self.state_dir
        config.detection_output_dir = self.det_dir

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pipeline_shutdown_attempts_outbox_flush(self):
        logger = MagicMock()
        pipeline = UbuntuDetectionPipeline(logger)
        with patch.object(pipeline.delivery_manager, "process_outbox") as mock_flush:
            pipeline.shutdown()
            mock_flush.assert_called_once()

    @patch("main.UbuntuDetectionPipeline")
    @patch("main.TelemetryRuntime")
    def test_main_with_once_flag_processes_single_batch_and_exits(self, mock_runtime_cls, mock_pipeline_cls):
        mock_runtime = MagicMock()
        mock_runtime_cls.return_value = mock_runtime

        mock_pipeline = MagicMock()
        mock_pipeline_cls.return_value = mock_pipeline

        import main
        with patch.object(sys, "argv", ["main.py", "--once"]):
            with self.assertRaises(SystemExit) as cm:
                main.main()
            self.assertEqual(cm.exception.code, 0)

        mock_runtime.start.assert_called_once()
        mock_pipeline.initialize.assert_called_once()
        mock_pipeline.process_batch.assert_called_once()
        mock_pipeline.shutdown.assert_called_once()
        mock_runtime.stop.assert_called_once()

if __name__ == "__main__":
    unittest.main()
