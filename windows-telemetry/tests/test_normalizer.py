import unittest
import logging
import json
import os
import tempfile
import jsonschema
from core.agent_identity import AgentIdentity
from normalizer.windows_event_normalizer import WindowsEventNormalizer

class TestWindowsEventNormalizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger("TestNormalizer")
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.identity = AgentIdentity(data_dir=cls.temp_dir.name)
        
        # Load schema
        schema_path = os.path.join(
            os.path.dirname(__file__), 
            "..", "..", "docs", "contracts", "normalized_event_contract_v1.schema.json"
        )
        with open(schema_path, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.normalizer = WindowsEventNormalizer(self.identity, self.logger)

    def test_normalize_valid_event(self):
        raw_event = {
            "record_id": 12345,
            "event_id": 4625,
            "timestamp": "2026-10-03T10:00:00.000Z",
            "provider": "Microsoft-Windows-Security-Auditing",
            "computer": "TEST-PC",
            "level": 4,
            "task": 12288,
            "keywords": "0x8020000000000000",
            "raw_xml": "<Event>...</Event>"
        }
        
        normalized = self.normalizer.normalize(raw_event, log_name="Security")
        
        # Validate against schema
        jsonschema.validate(instance=normalized, schema=self.schema)
        
        self.assertEqual(normalized["agent_id"], self.identity.agent_id)
        self.assertEqual(normalized["hostname"], "TEST-PC")
        self.assertEqual(normalized["os"], "Windows")
        self.assertEqual(normalized["severity"], "low")
        self.assertIsNone(normalized["detection_type"])
        self.assertIsNone(normalized["confidence"])
        self.assertIsNone(normalized["source_ip"])
        self.assertIsNone(normalized["username"])
        self.assertEqual(normalized["evidence"]["record_id"], 12345)
        self.assertEqual(normalized["evidence"]["windows_event_id"], 4625)
        
    def test_missing_required_fields(self):
        with self.assertRaises(ValueError):
            self.normalizer.normalize({"timestamp": "2026-10-03T10:00:00.000Z"})
            
        with self.assertRaises(ValueError):
            self.normalizer.normalize({"record_id": 123})

    def test_stable_event_id(self):
        raw_event = {
            "record_id": 999,
            "timestamp": "2026-10-03T10:00:00.000Z",
            "computer": "TEST-PC"
        }
        
        event1 = self.normalizer.normalize(raw_event, log_name="System")
        event2 = self.normalizer.normalize(raw_event, log_name="System")
        
        self.assertEqual(event1["event_id"], event2["event_id"])
        
        # Changing record_id changes event_id
        raw_event3 = raw_event.copy()
        raw_event3["record_id"] = 1000
        event3 = self.normalizer.normalize(raw_event3, log_name="System")
        
        self.assertNotEqual(event1["event_id"], event3["event_id"])
        
    def test_severity_mapping(self):
        event_crit = self.normalizer.normalize({"record_id": 1, "timestamp": "T", "level": 1})
        self.assertEqual(event_crit["severity"], "critical")
        
        event_high = self.normalizer.normalize({"record_id": 2, "timestamp": "T", "level": 2})
        self.assertEqual(event_high["severity"], "high")
        
        event_med = self.normalizer.normalize({"record_id": 3, "timestamp": "T", "level": 3})
        self.assertEqual(event_med["severity"], "medium")
        
        event_low = self.normalizer.normalize({"record_id": 4, "timestamp": "T", "level": 4})
        self.assertEqual(event_low["severity"], "low")
        
        event_none = self.normalizer.normalize({"record_id": 5, "timestamp": "T"})
        self.assertEqual(event_none["severity"], "low")
        
    def test_batch_normalization(self):
        raw_batch = [
            {"record_id": 1, "timestamp": "T1", "computer": "PC1", "event_id": 4624},
            {"record_id": 2}, # malformed, missing timestamp
            {"record_id": 3, "timestamp": "T3", "computer": "PC1", "event_id": 4625}
        ]
        
        normalized_batch = self.normalizer.normalize_batch(raw_batch)
        
        # Should process 2 successful events, skip 1 malformed
        self.assertEqual(len(normalized_batch), 2)
        
        # Check ordering is preserved
        self.assertEqual(normalized_batch[0]["evidence"]["record_id"], 1)
        self.assertEqual(normalized_batch[1]["evidence"]["record_id"], 3)
        self.assertEqual(normalized_batch[0]["evidence"]["windows_event_id"], 4624)
        self.assertEqual(normalized_batch[1]["evidence"]["windows_event_id"], 4625)
        
    def test_empty_batch(self):
        self.assertEqual(self.normalizer.normalize_batch([]), [])
        
    def test_input_immutability(self):
        raw_event = {
            "record_id": 999,
            "timestamp": "2026-10-03T10:00:00.000Z",
            "computer": "TEST-PC",
            "level": 2
        }
        raw_copy = raw_event.copy()
        self.normalizer.normalize(raw_event, log_name="System")
        self.assertEqual(raw_event, raw_copy)
        
    def test_different_log_name_changes_id(self):
        raw_event = {
            "record_id": 999,
            "timestamp": "2026-10-03T10:00:00.000Z",
            "computer": "TEST-PC"
        }
        event1 = self.normalizer.normalize(raw_event, log_name="System")
        event2 = self.normalizer.normalize(raw_event, log_name="Security")
        self.assertNotEqual(event1["event_id"], event2["event_id"])
