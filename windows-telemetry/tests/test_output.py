import unittest
import os
import json
import tempfile
import copy
from typing import Dict, Any
from output.models import DetectionEvent
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter
from detection.models import DetectionResult
from pipeline import WindowsDetectionPipeline

class TestOutputPipeline(unittest.TestCase):
    def setUp(self):
        import logging
        self.logger = logging.getLogger("TestOutput")
        self.logger.setLevel(logging.CRITICAL)
        
        self.temp_dir = tempfile.TemporaryDirectory()
        self.writer = DetectionEventWriter(self.temp_dir.name, self.logger)
        
        self.valid_normalized = {
            "event_id": "test-source-id",
            "timestamp": "2026-10-03T15:00:00Z",
            "agent_id": "agent-1",
            "hostname": "TEST-PC",
            "os": "Windows",
            "event_type": "windows_security_event",
            "evidence": {"test_key": "test_val"}
        }
        
        self.valid_result = DetectionResult(
            detected=True,
            detection_type="test_rule",
            confidence=1.0,
            severity="high",
            detector_name="test_detector",
            evidence={"detector_key": "val"}
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_builder_success(self):
        event = DetectionEventBuilder.build(self.valid_normalized, self.valid_result)
        self.assertIsNotNone(event)
        self.assertEqual(event.agent_id, "agent-1")
        self.assertEqual(event.source_event_id, "test-source-id")
        self.assertEqual(event.detection_type, "test_rule")
        self.assertEqual(event.confidence, 1.0)
        self.assertEqual(event.evidence, {"detector_key": "val"})
        self.assertTrue(len(event.detection_event_id) == 64) # SHA256

    def test_builder_no_detection(self):
        neg_result = copy.deepcopy(self.valid_result)
        neg_result.detected = False
        self.assertIsNone(DetectionEventBuilder.build(self.valid_normalized, neg_result))

    def test_builder_missing_fields(self):
        bad_normalized = copy.deepcopy(self.valid_normalized)
        del bad_normalized["timestamp"]
        with self.assertRaises(ValueError):
            DetectionEventBuilder.build(bad_normalized, self.valid_result)
            
        bad_result = copy.deepcopy(self.valid_result)
        bad_result.confidence = None
        with self.assertRaises(ValueError):
            DetectionEventBuilder.build(self.valid_normalized, bad_result)

    def test_deterministic_id(self):
        event1 = DetectionEventBuilder.build(self.valid_normalized, self.valid_result)
        event2 = DetectionEventBuilder.build(self.valid_normalized, self.valid_result)
        self.assertEqual(event1.detection_event_id, event2.detection_event_id)
        
        # Change source id
        mod_norm = copy.deepcopy(self.valid_normalized)
        mod_norm["event_id"] = "different-id"
        event3 = DetectionEventBuilder.build(mod_norm, self.valid_result)
        self.assertNotEqual(event1.detection_event_id, event3.detection_event_id)
        
        # Change type
        mod_result = copy.deepcopy(self.valid_result)
        mod_result.detection_type = "other_rule"
        event4 = DetectionEventBuilder.build(self.valid_normalized, mod_result)
        self.assertNotEqual(event1.detection_event_id, event4.detection_event_id)

    def test_input_immutability(self):
        norm_copy = copy.deepcopy(self.valid_normalized)
        res_copy = copy.deepcopy(self.valid_result)
        DetectionEventBuilder.build(self.valid_normalized, self.valid_result)
        self.assertEqual(self.valid_normalized, norm_copy)
        self.assertEqual(self.valid_result, res_copy)

    def test_writer_success(self):
        event = DetectionEventBuilder.build(self.valid_normalized, self.valid_result)
        self.writer.write(event)
        self.writer.write(event) # Write twice
        
        output_file = os.path.join(self.temp_dir.name, "detections.jsonl")
        self.assertTrue(os.path.exists(output_file))
        
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 2)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["detection_event_id"], event.detection_event_id)
            
    def test_writer_failure(self):
        # Point to a file that is actually a directory to force an IO error
        bad_writer = DetectionEventWriter(self.temp_dir.name, self.logger)
        os.makedirs(bad_writer.output_file, exist_ok=True) 
        
        event = DetectionEventBuilder.build(self.valid_normalized, self.valid_result)
        with self.assertRaises(RuntimeError):
            bad_writer.write(event)

class MockCollector:
    def __init__(self):
        self.events = []
        self.checkpoint = 0
    def initialize(self): pass
    def shutdown(self): pass
    def collect_once(self): return self.events
    def update_checkpoint(self, rec_id): self.checkpoint = rec_id
class TestPipelineIntegration(unittest.TestCase):
    def setUp(self):
        import logging
        self.logger = logging.getLogger("TestPipeline")
        self.logger.setLevel(logging.CRITICAL)
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Override config output dir and outbox db path for complete test isolation
        import config.settings
        self._orig_output_dir = config.settings.config.detection_output_dir
        self._orig_outbox_db_path = config.settings.config.outbox_db_path

        config.settings.config.detection_output_dir = self.temp_dir.name
        config.settings.config.outbox_db_path = os.path.join(self.temp_dir.name, "test_outbox.db")
        
        self.pipeline = WindowsDetectionPipeline(self.logger)
        # Mock collector to inject custom raw events
        self.pipeline.collector = MockCollector()

    def tearDown(self):
        import config.settings
        config.settings.config.detection_output_dir = self._orig_output_dir
        config.settings.config.outbox_db_path = self._orig_outbox_db_path
        self.temp_dir.cleanup()

    def test_pipeline_flow_valid_non_detection(self):
        # Valid events with no detection should advance checkpoint fully
        self.pipeline.collector.events = [
            {"record_id": 100, "event_id": 4624, "timestamp": "2026-10-03T10:00:00.000Z", "provider": "p", "computer": "c"},
            {"record_id": 101, "event_id": 4624, "timestamp": "2026-10-03T10:00:01.000Z", "provider": "p", "computer": "c"}
        ]
        self.pipeline.process_batch()
        self.assertEqual(self.pipeline.collector.checkpoint, 101)
        
    def test_pipeline_normalization_failure_halts_checkpoint(self):
        # 100 success, 101 malformed (normalization fails), 102 success
        # Checkpoint MUST halt at 100
        self.pipeline.collector.events = [
            {"record_id": 100, "event_id": 4624, "timestamp": "2026-10-03T10:00:00.000Z", "provider": "p", "computer": "c"},
            {"record_id": 101}, # Malformed
            {"record_id": 102, "event_id": 4624, "timestamp": "2026-10-03T10:00:02.000Z", "provider": "p", "computer": "c"}
        ]
        self.pipeline.process_batch()
        self.assertEqual(self.pipeline.collector.checkpoint, 100)

    def test_pipeline_detection_failure_halts_checkpoint(self):
        # 100 success, 101 success, 102 detection engine fails, 103 success
        self.pipeline.collector.events = [
            {"record_id": 100, "event_id": 4624, "timestamp": "2026-10-03T10:00:00.000Z", "provider": "p", "computer": "c"},
            {"record_id": 101, "event_id": 4624, "timestamp": "2026-10-03T10:00:01.000Z", "provider": "p", "computer": "c"},
            {"record_id": 102, "event_id": 4624, "timestamp": "2026-10-03T10:00:02.000Z", "provider": "p", "computer": "c"},
            {"record_id": 103, "event_id": 4624, "timestamp": "2026-10-03T10:00:03.000Z", "provider": "p", "computer": "c"}
        ]
        
        # Mock engine to fail on record 102
        original_process = self.pipeline.engine.process_event
        def mock_process(event):
            if event.get("evidence", {}).get("record_id") == 102:
                raise RuntimeError("Unexpected DetectionEngine failure")
            return original_process(event)
            
        self.pipeline.engine.process_event = mock_process
        
        self.pipeline.process_batch()
        self.assertEqual(self.pipeline.collector.checkpoint, 101)
        
    def test_pipeline_writer_failure_halts_checkpoint(self):
        # 100 success
        # 101-105: Trigger detection, write fails on 105
        # checkpoint halts at 104
        bad_dir = os.path.join(self.temp_dir.name, "bad_dir")
        os.makedirs(bad_dir)
        os.makedirs(os.path.join(bad_dir, "detections.jsonl")) # Force IO error
        self.pipeline.writer = DetectionEventWriter(bad_dir, self.logger)
        
        base_time = "2026-10-03T10:00:0"
        self.pipeline.collector.events = [{"record_id": 100, "event_id": 4624, "timestamp": f"{base_time}0.000Z", "provider": "p", "computer": "c"}]
        for i in range(5):
            self.pipeline.collector.events.append({
                "record_id": 101+i, 
                "event_id": 4625, 
                "timestamp": f"{base_time}{i}.000Z", 
                "provider": "p", 
                "computer": "c",
                "username": "admin"
            })
            
        self.pipeline.process_batch()
        # 100 success.
        # 101-104 process successfully (4 failed logins, no detection).
        # 105 triggers detection (5th failed login). Output writer fails.
        # Checkpoint MUST be 104.
        self.assertEqual(self.pipeline.collector.checkpoint, 104)

    def test_pipeline_full_detection_flow(self):
        base_time = "2026-10-03T10:00:0"
        self.pipeline.collector.events = []
        for i in range(5):
            self.pipeline.collector.events.append({
                "record_id": 100+i, 
                "event_id": 4625, 
                "timestamp": f"{base_time}{i}.000Z", 
                "provider": "p", 
                "computer": "c",
                "username": "admin"
            })
            
        self.pipeline.process_batch()
        self.assertEqual(self.pipeline.collector.checkpoint, 104)
        
        output_file = os.path.join(self.temp_dir.name, "detections.jsonl")
        self.assertTrue(os.path.exists(output_file))
        
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["detection_type"], "windows_bruteforce_rule")
            expected_id = self.pipeline.normalizer._generate_event_id("104", "c", "Security")
            self.assertEqual(parsed["source_event_id"], expected_id)

    def test_pipeline_soc_outage_decoupling(self):
        import time
        from unittest.mock import patch

        # 1. Setup events that trigger a detection
        base_time = "2026-10-03T10:00:0"
        self.pipeline.collector.events = []
        for i in range(5):
            self.pipeline.collector.events.append({
                "record_id": 100+i,
                "event_id": 4625,
                "timestamp": f"{base_time}{i}.000Z",
                "provider": "p",
                "computer": "c",
                "username": "admin"
            })

        # 2. Mock HTTP call to block/timeout (simulating SOC outage)
        with patch('urllib.request.urlopen') as mock_urlopen:
            def mock_slow_request(*args, **kwargs):
                time.sleep(2.0)
                raise Exception("SOC Outage Timeout")
            mock_urlopen.side_effect = mock_slow_request

            self.pipeline.delivery_worker.poll_interval = 0.1
            self.pipeline.initialize()

            start_time = time.time()

            # 3. Process batch
            self.pipeline.process_batch()

            end_time = time.time()

            # 4. Verify batch completes instantly, NOT waiting for the 2.0s HTTP timeout
            self.assertLess(end_time - start_time, 1.0)

            # 5. Verify checkpoint advances normally
            self.assertEqual(self.pipeline.collector.checkpoint, 104)

            # 6. Verify local JSONL is written
            output_file = os.path.join(self.temp_dir.name, "detections.jsonl")
            self.assertTrue(os.path.exists(output_file))

            # 7. Verify outbox contains pending event
            pending = self.pipeline.outbox.get_pending_events()
            self.assertEqual(len(pending), 1)

            self.pipeline.shutdown()

    def test_pipeline_real_xml_parsing_triggers_bruteforce_detection(self):
        from collectors.windows_event_collector import WindowsEventCollector
        real_collector = WindowsEventCollector(self.logger)

        xml_batch = ""
        for i in range(5):
            xml_batch += f"""
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <EventRecordID>{500 + i}</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:0{i}.000Z'/>
    <Computer>WIN-CORP-PC</Computer>
    <Level>0</Level>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='TargetUserName'>security_admin</Data>
    <Data Name='IpAddress'>192.168.1.200</Data>
    <Data Name='LogonType'>3</Data>
  </EventData>
</Event>"""

        # 1. Parse through the actual XML parser
        parsed_events = real_collector._parse_wevtutil_xml(xml_batch)
        self.assertEqual(len(parsed_events), 5)
        self.assertEqual(parsed_events[0]["username"], "security_admin")
        self.assertEqual(parsed_events[0]["source_ip"], "192.168.1.200")
        self.assertEqual(parsed_events[0]["logon_type"], 3)

        # 2. Inject the real-parsed events into the pipeline
        self.pipeline.collector.events = parsed_events
        self.pipeline.process_batch()

        # 3. Verify detection output file contains the high-severity alert
        output_file = os.path.join(self.temp_dir.name, "detections.jsonl")
        self.assertTrue(os.path.exists(output_file))
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            det = json.loads(lines[0])
            self.assertEqual(det["detection_type"], "windows_bruteforce_rule")
            self.assertEqual(det["severity"], "high")
            self.assertEqual(det["confidence"], 1.0)
            self.assertEqual(det["evidence"]["username"], "security_admin")
            self.assertEqual(det["evidence"]["source_ip"], "192.168.1.200")
