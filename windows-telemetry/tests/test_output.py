import unittest
import os
import json
import hashlib
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
        self.assertEqual(event.evidence["detector_key"], "val")
        self.assertEqual(event.evidence["detector_version"], "1.0.0")
        self.assertIn("detector_revision", event.evidence)
        self.assertTrue(len(event.detection_event_id) == 64) # SHA256

    def test_builder_identity_fields_passthrough(self):
        norm = copy.deepcopy(self.valid_normalized)
        norm["evidence"] = {
            "target_account_id": "DOMAIN:CORP\\alice",
            "target_user": "alice",
            "target_domain": "CORP",
            "domain_status": "OBSERVED_DOMAIN",
            "domain_namespace": "DOMAIN:CORP",
            "caller_user": "SYSTEM",
            "caller_domain": "NT AUTHORITY"
        }
        res = DetectionResult(
            detected=True,
            detection_type="test_rule",
            confidence=1.0,
            severity="high",
            detector_name="test_detector",
            evidence={"failure_count": 5}
        )
        event = DetectionEventBuilder.build(norm, res)
        self.assertIsNotNone(event)
        self.assertEqual(event.evidence["target_account_id"], "DOMAIN:CORP\\alice")
        self.assertEqual(event.evidence["target_user"], "alice")
        self.assertEqual(event.evidence["target_domain"], "CORP")
        self.assertEqual(event.evidence["domain_status"], "OBSERVED_DOMAIN")
        self.assertEqual(event.evidence["domain_namespace"], "DOMAIN:CORP")
        self.assertEqual(event.evidence["caller_user"], "SYSTEM")
        self.assertEqual(event.evidence["caller_domain"], "NT AUTHORITY")
        self.assertEqual(event.evidence["failure_count"], 5)
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

    def test_phase5_detector_version_revision_identity(self):
        """
        WP-1E Phase 5: Verify that upgrading detector_version yields a deterministic,
        unique detection_event_id and correctly stamps detector_version and detector_revision.
        """
        v2_norm = copy.deepcopy(self.valid_normalized)
        v2_norm["evidence"] = {"schema_version": "2.0"}

        res_v1 = DetectionResult(
            detected=True,
            detection_type="test_rule",
            confidence=1.0,
            severity="high",
            detector_name="test_detector",
            detector_version="1.0.0",
            model_artifact_digest="abc123hash"
        )
        res_v2 = DetectionResult(
            detected=True,
            detection_type="test_rule",
            confidence=1.0,
            severity="high",
            detector_name="test_detector",
            detector_version="2.0.0",
            model_artifact_digest="abc123hash"
        )

        event_v1 = DetectionEventBuilder.build(v2_norm, res_v1)
        event_v2 = DetectionEventBuilder.build(v2_norm, res_v2)

        self.assertNotEqual(event_v1.detection_event_id, event_v2.detection_event_id)
        self.assertEqual(event_v1.detector_version, "1.0.0")
        self.assertEqual(event_v2.detector_version, "2.0.0")
        self.assertEqual(event_v1.evidence["detector_version"], "1.0.0")
        self.assertEqual(event_v2.evidence["detector_version"], "2.0.0")
        self.assertIsNotNone(event_v1.evidence.get("detector_revision"))
        self.assertIsNotNone(event_v2.evidence.get("detector_revision"))
        self.assertNotEqual(event_v1.evidence["detector_revision"], event_v2.evidence["detector_revision"])

    def test_phase5_detector_manifest_and_revision_hashing(self):
        """
        WP-1E Phase 5: Test canonical detector manifest hashing:
        - Same manifest produces same revision hash.
        - Threshold change produces a different revision hash.
        - Rule change produces a different revision hash.
        - Model artifact change produces a different revision hash.
        """
        from detection.manifest import build_detector_revision_manifest, compute_detector_revision_hash

        base_manifest = build_detector_revision_manifest(
            detector_name="bruteforce_detector",
            detector_version="1.0.0",
            rules_digest="rule_sha256_base",
            thresholds={"failure_threshold": 5, "window_seconds": 60},
            detector_config={"max_state_keys": 10000},
            model_artifact_digest="model_sha256_base",
        )
        base_hash = compute_detector_revision_hash(base_manifest)

        # 1. Same manifest produces same revision hash (deterministic across calls)
        manifest_copy = build_detector_revision_manifest(
            detector_name="bruteforce_detector",
            detector_version="1.0.0",
            rules_digest="rule_sha256_base",
            thresholds={"failure_threshold": 5, "window_seconds": 60},
            detector_config={"max_state_keys": 10000},
            model_artifact_digest="model_sha256_base",
        )
        self.assertEqual(compute_detector_revision_hash(manifest_copy), base_hash)

        # 2. Threshold change produces different revision hash
        thresh_manifest = build_detector_revision_manifest(
            detector_name="bruteforce_detector",
            detector_version="1.0.0",
            rules_digest="rule_sha256_base",
            thresholds={"failure_threshold": 6, "window_seconds": 60},
            detector_config={"max_state_keys": 10000},
            model_artifact_digest="model_sha256_base",
        )
        self.assertNotEqual(compute_detector_revision_hash(thresh_manifest), base_hash)

        # 3. Rule change produces different revision hash
        rule_manifest = build_detector_revision_manifest(
            detector_name="bruteforce_detector",
            detector_version="1.0.0",
            rules_digest="rule_sha256_updated",
            thresholds={"failure_threshold": 5, "window_seconds": 60},
            detector_config={"max_state_keys": 10000},
            model_artifact_digest="model_sha256_base",
        )
        self.assertNotEqual(compute_detector_revision_hash(rule_manifest), base_hash)

        # 4. Model artifact change produces different revision hash
        model_manifest = build_detector_revision_manifest(
            detector_name="bruteforce_detector",
            detector_version="1.0.0",
            rules_digest="rule_sha256_base",
            thresholds={"failure_threshold": 5, "window_seconds": 60},
            detector_config={"max_state_keys": 10000},
            model_artifact_digest="model_sha256_v2",
        )
        self.assertNotEqual(compute_detector_revision_hash(model_manifest), base_hash)

    def test_phase5_v1_legacy_vs_v2_identity_selection(self):
        """
        WP-1E Phase 5:
        - V1 historical identity preserves exact legacy formula: SHA256(agent_id|source_event_id|detection_type|detector_name)
        - V2 identity incorporates complete detector_revision_hash: SHA256(agent_id|source_event_id|detection_type|detector_revision_hash)
        """
        # V1 Event (schema_version = "1.0")
        v1_norm = copy.deepcopy(self.valid_normalized)
        v1_norm["evidence"] = {"schema_version": "1.0"}
        res_v1 = DetectionResult(True, "test_rule", 1.0, "high", "test_detector", detector_version="1.0.0")
        event_v1 = DetectionEventBuilder.build(v1_norm, res_v1)

        expected_v1_id = hashlib.sha256(
            f"{v1_norm['agent_id']}|{v1_norm['event_id']}|test_rule|test_detector".encode("utf-8")
        ).hexdigest()
        self.assertEqual(event_v1.detection_event_id, expected_v1_id)

        # V2 Event (schema_version = "2.0")
        v2_norm = copy.deepcopy(self.valid_normalized)
        v2_norm["evidence"] = {"schema_version": "2.0"}
        res_v2 = DetectionResult(True, "test_rule", 1.0, "high", "test_detector", detector_version="2.0.0")
        event_v2 = DetectionEventBuilder.build(v2_norm, res_v2)

        rev_hash = event_v2.evidence["detector_revision"]
        expected_v2_id = hashlib.sha256(
            f"{v2_norm['agent_id']}|{v2_norm['event_id']}|test_rule|{rev_hash}".encode("utf-8")
        ).hexdigest()
        self.assertEqual(event_v2.detection_event_id, expected_v2_id)
        self.assertNotEqual(event_v1.detection_event_id, event_v2.detection_event_id)

    def test_phase5_production_rule_manifest_population(self):
        """
        WP-1E Phase 5: Production Rule Manifest Population & Revision Sensitivity.
        - Default BruteForceRule metadata is populated.
        - Changing failure_threshold changes the revision hash.
        - Changing window_seconds changes the revision hash.
        - Changing rule signatures changes the revision hash.
        - Same configuration produces the same hash.
        - Other production rules populate their relevant configuration.
        - V1 identity remains unchanged.
        - Production V2 identity uses the completed revision hash.
        - Existing evaluation-mode isolation remains intact.
        """
        from detection.rules import (
            BruteForceRule,
            SuspiciousPowerShellRule,
            SuspiciousLolbinsDownloadRule,
            ReconnaissanceCommandsRule,
            DefenseEvasionRule,
        )
        from detection.detector import DetectionEngine

        # 1. Default BruteForceRule metadata is populated
        bf_default = BruteForceRule()
        self.assertEqual(bf_default.detector_name, "windows_bruteforce_rule")
        self.assertEqual(bf_default.detector_version, "1.0.0")
        self.assertEqual(bf_default.get_thresholds()["failure_threshold"], 5.0)
        self.assertEqual(bf_default.get_thresholds()["window_seconds"], 60.0)
        self.assertIn("max_state_keys", bf_default.get_detector_config())
        self.assertTrue(len(bf_default.get_rules_digest()) == 64)

        def make_failed_logon(i, username="victim"):
            return {
                "agent_id": "AGT-WIN-01",
                "hostname": "WORKSTATION-01",
                "os": "Windows",
                "timestamp": f"2026-10-03T10:00:{i:02d}Z",
                "event_id": f"src-{i}",
                "username": username,
                "evidence": {
                    "schema_version": "2.0",
                    "windows_event_id": 4625,
                    "target_account_id": f"LOCAL_SAM\\{username}",
                    "domain_status": "LOCAL_SAM"
                }
            }

        res_default = None
        for i in range(5):
            res_default = bf_default.evaluate(make_failed_logon(i))

        self.assertIsNotNone(res_default)
        self.assertEqual(res_default.detector_name, "windows_bruteforce_rule")
        self.assertEqual(res_default.detector_version, "1.0.0")
        self.assertEqual(res_default.thresholds["failure_threshold"], 5.0)
        self.assertEqual(res_default.thresholds["window_seconds"], 60.0)
        self.assertEqual(res_default.rules_digest, bf_default.get_rules_digest())
        self.assertIsNotNone(res_default.detector_config)

        # Build DetectionEvent and verify V2 identity
        norm_ev = make_failed_logon(4)
        event_default = DetectionEventBuilder.build(norm_ev, res_default)
        rev_hash_default = event_default.evidence["detector_revision"]
        self.assertTrue(len(rev_hash_default) == 64)

        src_id = res_default.source_event_id or norm_ev["event_id"]
        expected_v2_id = hashlib.sha256(
            f"{norm_ev['agent_id']}|{src_id}|windows_bruteforce_rule|{rev_hash_default}".encode("utf-8")
        ).hexdigest()
        self.assertEqual(event_default.detection_event_id, expected_v2_id)

        # 2. Same configuration produces the same hash
        bf_same = BruteForceRule()
        res_same = None
        for i in range(5):
            res_same = bf_same.evaluate(make_failed_logon(i))
        event_same = DetectionEventBuilder.build(norm_ev, res_same)
        self.assertEqual(event_same.evidence["detector_revision"], rev_hash_default)

        # 3. Changing failure_threshold changes the revision hash
        bf_t10 = BruteForceRule(failure_threshold=10)
        res_t10 = None
        for i in range(10):
            res_t10 = bf_t10.evaluate(make_failed_logon(i))
        event_t10 = DetectionEventBuilder.build(norm_ev, res_t10)
        self.assertNotEqual(event_t10.evidence["detector_revision"], rev_hash_default)

        # 4. Changing window_seconds changes the revision hash
        bf_w120 = BruteForceRule(window_seconds=120)
        res_w120 = None
        for i in range(5):
            res_w120 = bf_w120.evaluate(make_failed_logon(i))
        event_w120 = DetectionEventBuilder.build(norm_ev, res_w120)
        self.assertNotEqual(event_w120.evidence["detector_revision"], rev_hash_default)

        # 5. Other production rules populate their relevant configuration via DetectionEngine
        engine = DetectionEngine(self.logger)
        ps_ev = {
            "agent_id": "AGT-WIN-01",
            "hostname": "WORKSTATION-01",
            "os": "Windows",
            "timestamp": "2026-10-03T10:00:00Z",
            "event_id": "src-ps",
            "evidence": {
                "schema_version": "2.0",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBYAFgA"
            }
        }
        ps_results = engine.process_event(ps_ev)
        self.assertTrue(len(ps_results) >= 1)
        ps_res = ps_results[0]
        self.assertEqual(ps_res.detector_name, "windows_powershell_rule")
        self.assertEqual(ps_res.detector_version, "1.0.0")
        self.assertEqual(ps_res.thresholds["confidence"], 0.95)
        self.assertEqual(ps_res.detector_config["technique_id"], "T1059.001")
        self.assertTrue(len(ps_res.rules_digest) == 64)

        event_ps = DetectionEventBuilder.build(ps_ev, ps_res)
        rev_hash_ps = event_ps.evidence["detector_revision"]
        self.assertTrue(len(rev_hash_ps) == 64)

        # 6. Changing rule signatures changes the revision hash
        ps_rule_custom = SuspiciousPowerShellRule()
        ps_rule_custom.patterns.append((r"(?i)new_malicious_cradle", "New Cradle"))
        res_custom = ps_rule_custom.evaluate(ps_ev)
        event_custom = DetectionEventBuilder.build(ps_ev, res_custom)
        self.assertNotEqual(event_custom.evidence["detector_revision"], rev_hash_ps)

        # 7. Check Lolbins, Recon, Defense Evasion rules populate config
        lolbin_rule = SuspiciousLolbinsDownloadRule()
        self.assertEqual(lolbin_rule.detector_name, "windows_lolbin_rule")
        self.assertEqual(lolbin_rule.get_thresholds()["confidence"], 0.90)
        self.assertEqual(lolbin_rule.get_detector_config()["technique_id"], "T1105")
        self.assertTrue(len(lolbin_rule.get_rules_digest()) == 64)

        recon_rule = ReconnaissanceCommandsRule()
        self.assertEqual(recon_rule.detector_name, "windows_reconnaissance_rule")
        self.assertEqual(recon_rule.get_thresholds()["confidence"], 0.85)
        self.assertEqual(recon_rule.get_detector_config()["technique_id"], "T1082")
        self.assertTrue(len(recon_rule.get_rules_digest()) == 64)

        evasion_rule = DefenseEvasionRule()
        self.assertEqual(evasion_rule.detector_name, "windows_defense_evasion_rule")
        self.assertEqual(evasion_rule.get_thresholds()["confidence"], 0.98)
        self.assertEqual(evasion_rule.get_detector_config()["technique_id"], "T1562.001")
        self.assertTrue(len(evasion_rule.get_rules_digest()) == 64)

        # 8. V1 identity remains unchanged
        v1_norm = make_failed_logon(4)
        v1_norm["evidence"]["schema_version"] = "1.0"
        event_v1 = DetectionEventBuilder.build(v1_norm, res_default)
        src_id_v1 = res_default.source_event_id or v1_norm["event_id"]
        expected_v1_id = hashlib.sha256(
            f"{v1_norm['agent_id']}|{src_id_v1}|windows_bruteforce_rule|windows_bruteforce_rule".encode("utf-8")
        ).hexdigest()
        self.assertEqual(event_v1.detection_event_id, expected_v1_id)


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
        self._orig_data_dir = config.settings.config.data_dir
        self._orig_output_dir = config.settings.config.detection_output_dir
        self._orig_outbox_db_path = config.settings.config.outbox_db_path
        self._orig_checkpoint_dir = config.settings.config.checkpoint_dir

        config.settings.config.data_dir = self.temp_dir.name
        config.settings.config.detection_output_dir = self.temp_dir.name
        config.settings.config.outbox_db_path = os.path.join(self.temp_dir.name, "test_outbox.db")
        config.settings.config.checkpoint_dir = os.path.join(self.temp_dir.name, "state")

        self.pipeline = WindowsDetectionPipeline(self.logger)
        # Mock collector to inject custom raw events
        self.pipeline.collector = MockCollector()

    def tearDown(self):
        try:
            self.pipeline.shutdown()
        except Exception:
            pass
        import config.settings
        config.settings.config.data_dir = self._orig_data_dir
        config.settings.config.detection_output_dir = self._orig_output_dir
        config.settings.config.outbox_db_path = self._orig_outbox_db_path
        config.settings.config.checkpoint_dir = self._orig_checkpoint_dir
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
                "username": "admin",
                "target_domain": "."
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
                "username": "admin",
                "target_domain": "."
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
                "username": "admin",
                "target_domain": "."
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
    <Data Name='TargetDomainName'>.</Data>
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

    def test_phase5_evaluation_mode_bypasses_outbox(self):
        """
        WP-1E Phase 5: Verify that evaluation/replay mode routes events to detections_eval.jsonl
        and bypasses the Outbox queue to avoid polluting the central dispatch queue.
        """
        eval_temp_dir = tempfile.TemporaryDirectory()
        try:
            import config.settings as s_module
            orig_data = s_module.config.data_dir
            orig_out = s_module.config.detection_output_dir
            orig_outbox = s_module.config.outbox_db_path
            s_module.config.data_dir = eval_temp_dir.name
            s_module.config.detection_output_dir = eval_temp_dir.name
            s_module.config.outbox_db_path = os.path.join(eval_temp_dir.name, "outbox.db")
            s_module.config.ensure_directories()

            eval_pipeline = WindowsDetectionPipeline(self.logger, execution_mode="EVALUATION")
            try:
                eval_pipeline.collector = MockCollector()

                # Seed 5 brute-force failure events
                base_time = "2026-10-12T15:00:0"
                eval_pipeline.collector.events = [
                    {
                        "record_id": 100 + i,
                        "event_id": 4625,
                        "timestamp": f"{base_time}{i}.000Z",
                        "provider": "p",
                        "computer": "c",
                        "username": "eval_admin",
                        "target_domain": "."
                    }
                    for i in range(5)
                ]

                eval_pipeline.process_batch()

                # Detections should exist in detections_eval.jsonl
                eval_file = os.path.join(eval_temp_dir.name, "detections_eval.jsonl")
                prod_file = os.path.join(eval_temp_dir.name, "detections.jsonl")
                self.assertTrue(os.path.exists(eval_file))
                self.assertFalse(os.path.exists(prod_file))

                # Outbox must have ZERO pending events
                self.assertEqual(len(eval_pipeline.outbox.get_pending_events()), 0)
            finally:
                eval_pipeline.shutdown()
        finally:
            s_module.config.data_dir = orig_data
            s_module.config.detection_output_dir = orig_out
            s_module.config.outbox_db_path = orig_outbox
            eval_temp_dir.cleanup()
