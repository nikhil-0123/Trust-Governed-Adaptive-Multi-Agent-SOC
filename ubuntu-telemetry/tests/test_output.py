import unittest
import os
import shutil
import tempfile
import json
from detection.models import DetectionResult
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter

class TestOutput(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.norm_event = {
            "event_id": "raw-evt-100",
            "timestamp": "2026-10-11T21:00:00+00:00",
            "agent_id": "test-agent-ubuntu",
            "hostname": "ubuntu-host",
            "os": "Linux"
        }
        self.det_result = DetectionResult(
            detected=True,
            detection_type="brute_force",
            confidence=1.0,
            severity="high",
            detector_name="linux_ssh_bruteforce_rule",
            source_event_id="raw-evt-100",
            evidence={"attempts": 5}
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_builder_success_and_deterministic_id(self):
        evt1 = DetectionEventBuilder.build(self.norm_event, self.det_result)
        evt2 = DetectionEventBuilder.build(self.norm_event, self.det_result)

        self.assertIsNotNone(evt1)
        self.assertEqual(evt1.detection_event_id, evt2.detection_event_id)
        self.assertEqual(evt1.os, "Linux")
        self.assertEqual(evt1.detection_type, "brute_force")
        self.assertEqual(evt1.severity, "HIGH")

    def test_builder_non_detected_returns_none(self):
        non_det = DetectionResult(detected=False)
        self.assertIsNone(DetectionEventBuilder.build(self.norm_event, non_det))

    def test_builder_missing_required_keys_raises(self):
        bad_norm = {"hostname": "ubuntu-host"}  # Missing agent_id, timestamp, os
        with self.assertRaises(ValueError):
            DetectionEventBuilder.build(bad_norm, self.det_result)

    def test_writer_appends_jsonl(self):
        writer = DetectionEventWriter(self.test_dir)
        evt = DetectionEventBuilder.build(self.norm_event, self.det_result)
        writer.write(evt)

        jsonl_path = os.path.join(self.test_dir, "detections.jsonl")
        self.assertTrue(os.path.exists(jsonl_path))

        with open(jsonl_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        data = json.loads(lines[0])
        self.assertEqual(data["detection_event_id"], evt.detection_event_id)

if __name__ == "__main__":
    unittest.main()
