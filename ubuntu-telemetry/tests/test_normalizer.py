import unittest
import os
import shutil
import tempfile
import json
from core.agent_identity import AgentIdentity
from normalizer.ubuntu_event_normalizer import UbuntuEventNormalizer

class TestUbuntuNormalizer(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.identity = AgentIdentity(self.test_dir)
        self.normalizer = UbuntuEventNormalizer(self.identity)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_normalize_valid_event(self):
        raw = {
            "record_id": 101,
            "timestamp": "2026-10-11T21:00:00+00:00",
            "hostname": "ubuntu-test",
            "process": "sshd",
            "pid": 1234,
            "raw_message": "Failed password for admin from 192.168.1.50 port 2222",
            "auth_status": "failed",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "port": 2222,
            "auth_method": "password",
            "event_subtype": "ssh_login_failure"
        }
        norm = self.normalizer.normalize(raw)

        # Verify contract schema v1 required fields
        required_keys = [
            "event_id", "timestamp", "agent_id", "hostname", "os",
            "event_type", "source_ip", "username", "severity",
            "detection_type", "confidence", "evidence"
        ]
        for k in required_keys:
            self.assertIn(k, norm)

        self.assertEqual(norm["os"], "Linux")
        self.assertEqual(norm["event_type"], "linux_auth_event")
        self.assertEqual(norm["username"], "admin")
        self.assertEqual(norm["source_ip"], "192.168.1.50")
        self.assertEqual(norm["severity"], "medium")
        self.assertEqual(norm["evidence"]["process"], "sshd")

    def test_stable_event_id(self):
        raw = {
            "record_id": 555,
            "timestamp": "2026-10-11T21:00:00+00:00",
            "hostname": "ubuntu-test"
        }
        norm1 = self.normalizer.normalize(raw)
        norm2 = self.normalizer.normalize(raw)
        self.assertEqual(norm1["event_id"], norm2["event_id"])

    def test_missing_required_fields_raises(self):
        with self.assertRaises(ValueError):
            self.normalizer.normalize({"timestamp": "2026-10-11T21:00:00+00:00"})  # missing record_id

        with self.assertRaises(ValueError):
            self.normalizer.normalize({"record_id": 1})  # missing timestamp

    def test_batch_normalization(self):
        raw_list = [
            {"record_id": 1, "timestamp": "2026-10-11T21:00:00+00:00", "auth_status": "failed"},
            {"record_id": 2, "timestamp": "2026-10-11T21:00:01+00:00", "auth_status": "accepted"}
        ]
        norm_list = self.normalizer.normalize_batch(raw_list)
        self.assertEqual(len(norm_list), 2)
        self.assertEqual(norm_list[0]["severity"], "medium")
        self.assertEqual(norm_list[1]["severity"], "low")

if __name__ == "__main__":
    unittest.main()
