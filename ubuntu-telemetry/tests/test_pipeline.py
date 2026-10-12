import unittest
import os
import shutil
import tempfile
import json
import logging

from config.settings import config
from pipeline import UbuntuDetectionPipeline

class TestUbuntuPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, "auth.log")
        self.state_dir = os.path.join(self.test_dir, "state")
        self.det_dir = os.path.join(self.test_dir, "detections")
        self.outbox_db = os.path.join(self.test_dir, "outbox.db")

        # Override config paths for clean testing
        config.data_dir = self.test_dir
        config.auth_log_path = self.log_path
        config.checkpoint_dir = self.state_dir
        config.detection_output_dir = self.det_dir
        config.outbox_db_path = self.outbox_db

        self.logger = logging.getLogger("TestPipeline")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pipeline_full_detection_flow(self):
        # Write 5 failed SSH login attempts for admin from 192.168.10.99
        lines = []
        for i in range(5):
            lines.append(f"Oct 11 21:00:0{i} ubuntu-srv sshd[{1000+i}]: Failed password for admin from 192.168.10.99 port 55555 ssh2\n")

        with open(self.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        pipeline = UbuntuDetectionPipeline(self.logger)
        pipeline.initialize()

        # Run process_batch
        pipeline.process_batch()

        # 1. Verify detection event written locally
        jsonl_path = os.path.join(self.det_dir, "detections.jsonl")
        self.assertTrue(os.path.exists(jsonl_path))
        with open(jsonl_path, "r", encoding="utf-8") as f:
            written_lines = f.readlines()
        self.assertEqual(len(written_lines), 1)

        det_data = json.loads(written_lines[0])
        self.assertEqual(det_data["detection_type"], "brute_force")
        self.assertEqual(det_data["severity"], "HIGH")
        self.assertEqual(det_data["os"], "Linux")
        self.assertEqual(det_data["evidence"]["username"], "admin")
        self.assertEqual(det_data["evidence"]["source_ip"], "192.168.10.99")

        # 2. Verify event queued in Outbox for Central SOC delivery
        pending = pipeline.outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["detection_event_id"], det_data["detection_event_id"])

        # 3. Verify checkpoint was advanced
        state = pipeline.collector.checkpoint_manager.load_checkpoint()
        self.assertGreater(state["last_offset"], 0)
        self.assertEqual(state["last_record_id"], 5)

        pipeline.shutdown()

    def test_pipeline_non_detection_events_advance_checkpoint(self):
        # 1 successful login event (low severity, no detection)
        line = "Oct 11 21:00:00 ubuntu-srv sshd[123]: Accepted publickey for bob from 10.0.0.1 port 4000 ssh2\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        pipeline = UbuntuDetectionPipeline(self.logger)
        pipeline.initialize()
        pipeline.process_batch()

        # No detections written
        jsonl_path = os.path.join(self.det_dir, "detections.jsonl")
        self.assertFalse(os.path.exists(jsonl_path))

        # Outbox empty
        self.assertEqual(len(pipeline.outbox.get_pending_events()), 0)

        # Checkpoint advanced
        state = pipeline.collector.checkpoint_manager.load_checkpoint()
        self.assertGreater(state["last_offset"], 0)
        self.assertEqual(state["last_record_id"], 1)

        pipeline.shutdown()

if __name__ == "__main__":
    unittest.main()
