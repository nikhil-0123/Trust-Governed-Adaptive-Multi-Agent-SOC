import unittest
import os
import sys
import tempfile
import shutil
import hashlib
import json
import logging
import sqlite3
from unittest.mock import patch, MagicMock

from config.settings import config
from pipeline import WindowsDetectionPipeline
from detection.models import DetectionResult
from canonical import generate_source_event_id_v2
from collectors.windows_event_collector import WindowsEventCollector
from transport.outbox import OutboxPayloadConflictError

class TestWindowsMainAndPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "outbox.db")
        self.state_dir = os.path.join(self.test_dir, "state")
        self.det_dir = os.path.join(self.test_dir, "detections")

        self.orig_data_dir = config.data_dir
        self.orig_outbox = config.outbox_db_path
        self.orig_checkpoint = config.checkpoint_dir
        self.orig_detection = config.detection_output_dir

        config.data_dir = self.test_dir
        config.outbox_db_path = self.db_path
        config.checkpoint_dir = self.state_dir
        config.detection_output_dir = self.det_dir

    def tearDown(self):
        config.data_dir = self.orig_data_dir
        config.outbox_db_path = self.orig_outbox
        config.checkpoint_dir = self.orig_checkpoint
        config.detection_output_dir = self.orig_detection
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pipeline_shutdown_is_safe_without_collector_shutdown_attribute(self):
        logger = MagicMock()
        pipeline = WindowsDetectionPipeline(logger)
        # Should not raise AttributeError when shutting down
        pipeline.shutdown()

    def test_pipeline_shutdown_attempts_outbox_flush(self):
        logger = MagicMock()
        pipeline = WindowsDetectionPipeline(logger)
        with patch.object(pipeline.delivery_manager, "process_outbox") as mock_flush:
            pipeline.shutdown()
            mock_flush.assert_called_once()

    @patch("main.WindowsDetectionPipeline")
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

    def _init_real_pipeline(self, initial_checkpoint: int = 500):
        logger = logging.getLogger(f"TestPipelineConflict_{self._testMethodName}")
        logger.setLevel(logging.INFO)
        os.makedirs(config.detection_output_dir, exist_ok=True)
        pipeline = WindowsDetectionPipeline(logger)
        pipeline.collector.initialize()
        pipeline.collector.checkpoint_manager.save_checkpoint(initial_checkpoint)
        pipeline.collector.current_checkpoint = initial_checkpoint
        return pipeline, logger

    def _write_sim_xml(self, collector, filename: str, record_id: int, event_id: int = 4625, hostname: str = "WORKSTATION-01"):
        xml_content = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>{event_id}</EventID>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>Security</Channel>
        <Computer>{hostname}</Computer>
        <TimeCreated SystemTime="2026-11-12T10:00:00Z"/>
    </System>
    <EventData><Data Name="TargetUserName">alice</Data></EventData>
</Event>"""
        filepath = os.path.join(collector.simulated_events_channel_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(xml_content)

    def _compute_expected_detection_event_id(
        self, agent_id: str, record_id: int, det_type: str, detector_name: str,
        channel: str = "Security", epoch: int = 1, hostname: str = "WORKSTATION-01"
    ) -> str:
        src_id = generate_source_event_id_v2(
            agent_id=agent_id, channel=channel, epoch=epoch, hostname=hostname, record_id=record_id
        )
        hash_input = f"{agent_id}|{src_id}|{det_type}|{detector_name}".encode("utf-8")
        return hashlib.sha256(hash_input).hexdigest()

    def test_multi_result_conflict_processes_first_and_third_persists_conflict_and_advances_checkpoint_after_all(self):
        pipeline, logger = self._init_real_pipeline(initial_checkpoint=500)
        self._write_sim_xml(pipeline.collector, "01_rec501.xml", record_id=501)

        res1 = DetectionResult(True, "rule_type_1", 0.9, "high", "detector_1", evidence={"idx": 1})
        res2 = DetectionResult(True, "rule_type_2", 0.95, "high", "detector_2", evidence={"idx": 2, "incoming": True})
        res3 = DetectionResult(True, "rule_type_3", 0.85, "critical", "detector_3", evidence={"idx": 3})

        id1 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_type_1", "detector_1")
        id2 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_type_2", "detector_2")
        id3 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_type_3", "detector_3")

        # Seed existing conflicting payload for Result 2 in pending state
        seeded_conflict_orig = {
            "detection_event_id": id2,
            "severity": "high",
            "evidence": {"idx": 2, "seeded": "original_payload"},
        }
        pipeline.outbox.add_event(seeded_conflict_orig)

        # Track persisted disk checkpoint during each add_event execution
        checkpoints_during_results = []
        real_add_event = pipeline.outbox.add_event

        def observing_add_event(event_dict):
            chk_before = pipeline.collector.checkpoint_manager.load_checkpoint()
            try:
                return real_add_event(event_dict)
            finally:
                chk_after = pipeline.collector.checkpoint_manager.load_checkpoint()
                checkpoints_during_results.append((event_dict["detection_event_id"], chk_before, chk_after))

        with patch.object(pipeline.engine, "process_event", return_value=[res1, res2, res3]):
            with patch.object(pipeline.outbox, "add_event", side_effect=observing_add_event):
                with self.assertLogs(logger, level="ERROR") as log_ctx:
                    pipeline.process_batch()

        # 1. All 3 results reached add_event in order, and persisted checkpoint NEVER advanced mid-record
        self.assertEqual([item[0] for item in checkpoints_during_results], [id1, id2, id3])
        for det_id, chk_before, chk_after in checkpoints_during_results:
            self.assertEqual(chk_before, 500, f"Checkpoint advanced prematurely before {det_id}")
            self.assertEqual(chk_after, 500, f"Checkpoint advanced prematurely after {det_id} before raw record completed")

        # 2. First and third results are processed into outbox; original Result 2 row remains untouched (pending)
        pending_ids = {row["detection_event_id"]: row for row in pipeline.outbox.get_pending_events(limit=50)}
        self.assertIn(id1, pending_ids)
        self.assertIn(id3, pending_ids)
        self.assertIn(id2, pending_ids)
        self.assertEqual(json.loads(pending_ids[id2]["event_data"])["evidence"], {"idx": 2, "seeded": "original_payload"})

        # All 3 detections were written locally to JSONL
        det_files = [f for f in os.listdir(config.detection_output_dir) if f.endswith(".jsonl")]
        self.assertEqual(len(det_files), 1)
        with open(os.path.join(config.detection_output_dir, det_files[0]), "r", encoding="utf-8") as df:
            written_ids = [json.loads(line)["detection_event_id"] for line in df if line.strip()]
        self.assertEqual(written_ids, [id1, id2, id3])

        # 3. Durable conflict evidence is persisted
        conflicts = pipeline.outbox.get_conflicts_for_event(id2)
        self.assertEqual(len(conflicts), 1)
        conflict = conflicts[0]

        # 4. Conflict log contains event_id, conflict_id, existing_hash, incoming_hash
        joined_logs = "\n".join(log_ctx.output)
        self.assertIn(id2, joined_logs)
        self.assertIn(conflict["conflict_id"], joined_logs)
        self.assertIn(conflict["payload_a_hash"], joined_logs)
        self.assertIn(conflict["payload_b_hash"], joined_logs)

        # 5. Persisted checkpoint on disk advances ONLY after all three results are handled
        self.assertEqual(pipeline.collector.current_checkpoint, 501)
        self.assertEqual(pipeline.collector.checkpoint_manager.load_checkpoint(), 501)
        reloaded_collector = WindowsEventCollector(logger)
        reloaded_collector.initialize()
        self.assertEqual(reloaded_collector.checkpoint_manager.load_checkpoint(), 501)

    def test_conflicting_delivered_event_never_marked_delivered_again_and_preserves_evidence(self):
        pipeline, logger = self._init_real_pipeline(initial_checkpoint=500)
        self._write_sim_xml(pipeline.collector, "01_rec501.xml", record_id=501)

        res_conflict = DetectionResult(True, "rule_delivered", 0.95, "high", "detector_del", evidence={"ver": "new"})
        id_conflict = self._compute_expected_detection_event_id(
            pipeline.identity.agent_id, 501, "rule_delivered", "detector_del"
        )

        # Pre-seed and mark original payload delivered
        pipeline.outbox.add_event({"detection_event_id": id_conflict, "severity": "high", "evidence": {"ver": "orig"}})
        pipeline.outbox.mark_delivered(id_conflict)

        conn = sqlite3.connect(config.outbox_db_path)
        orig_delivered_at = conn.execute(
            "SELECT delivered_at FROM outbox WHERE detection_event_id = ?", (id_conflict,)
        ).fetchone()[0]
        conn.close()

        with patch.object(pipeline.engine, "process_event", return_value=[res_conflict]):
            pipeline.process_batch()

        # Original row stays delivered with original payload; conflicting payload never overwrote it
        conn = sqlite3.connect(config.outbox_db_path)
        row = conn.execute(
            "SELECT status, event_data, delivered_at FROM outbox WHERE detection_event_id = ?", (id_conflict,)
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "delivered")
        self.assertEqual(json.loads(row[1])["evidence"], {"ver": "orig"})
        self.assertEqual(row[2], orig_delivered_at)

        # Conflict evidence preserved in outbox_conflicts
        conflicts = pipeline.outbox.get_conflicts_for_event(id_conflict)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(pipeline.collector.checkpoint_manager.load_checkpoint(), 501)

    def test_non_conflict_exception_halts_batch_and_does_not_advance_checkpoint(self):
        pipeline, logger = self._init_real_pipeline(initial_checkpoint=500)
        self._write_sim_xml(pipeline.collector, "01_rec501.xml", record_id=501)
        self._write_sim_xml(pipeline.collector, "02_rec502.xml", record_id=502)

        res1 = DetectionResult(True, "rule_1", 0.9, "high", "det_1", evidence={"n": 1})
        res2 = DetectionResult(True, "rule_2", 0.9, "high", "det_2", evidence={"n": 2})
        res3 = DetectionResult(True, "rule_3", 0.9, "high", "det_3", evidence={"n": 3})

        id1 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_1", "det_1")
        id2 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_2", "det_2")

        real_add_event = pipeline.outbox.add_event
        calls = []

        def fail_on_second_result(event_dict):
            calls.append(event_dict["detection_event_id"])
            if event_dict["detection_event_id"] == id2:
                raise IOError("Simulated SQLite disk I/O error")
            return real_add_event(event_dict)

        with patch.object(pipeline.engine, "process_event", return_value=[res1, res2, res3]):
            with patch.object(pipeline.outbox, "add_event", side_effect=fail_on_second_result):
                pipeline.process_batch()

        # Processing stopped at Result 2 of record 501; Result 3 and record 502 never ran
        self.assertEqual(calls, [id1, id2])
        # Persisted checkpoint must NOT advance past 500
        self.assertEqual(pipeline.collector.current_checkpoint, 500)
        self.assertEqual(pipeline.collector.checkpoint_manager.load_checkpoint(), 500)
        reloaded_collector = WindowsEventCollector(logger)
        reloaded_collector.initialize()
        self.assertEqual(reloaded_collector.checkpoint_manager.load_checkpoint(), 500)

    def test_conflict_followed_by_non_conflict_exception_in_same_record_halts_and_preserves_conflict(self):
        pipeline, logger = self._init_real_pipeline(initial_checkpoint=500)
        self._write_sim_xml(pipeline.collector, "01_rec501.xml", record_id=501)
        self._write_sim_xml(pipeline.collector, "02_rec502.xml", record_id=502)

        res1 = DetectionResult(True, "rule_1", 0.9, "high", "det_1", evidence={"n": 1})
        res2 = DetectionResult(True, "rule_2", 0.9, "high", "det_2", evidence={"n": 2, "incoming": True})
        res3 = DetectionResult(True, "rule_3", 0.9, "high", "det_3", evidence={"n": 3})

        id1 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_1", "det_1")
        id2 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_2", "det_2")
        id3 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_3", "det_3")

        # Seed real conflict for Result 2
        pipeline.outbox.add_event({"detection_event_id": id2, "severity": "high", "evidence": {"n": 2, "orig": True}})

        real_add_event = pipeline.outbox.add_event
        calls = []

        def conflict_then_io_error(event_dict):
            calls.append(event_dict["detection_event_id"])
            if event_dict["detection_event_id"] == id3:
                raise IOError("Simulated failure after conflict")
            return real_add_event(event_dict)

        with patch.object(pipeline.engine, "process_event", return_value=[res1, res2, res3]):
            with patch.object(pipeline.outbox, "add_event", side_effect=conflict_then_io_error):
                pipeline.process_batch()

        # Result 1, Result 2 (real OutboxPayloadConflictError caught), and Result 3 attempted; record 502 skipped
        self.assertEqual(calls, [id1, id2, id3])
        # Conflict evidence from Result 2 IS durably persisted in outbox_conflicts
        self.assertEqual(len(pipeline.outbox.get_conflicts_for_event(id2)), 1)
        # Persisted checkpoint did NOT advance past 500 because Result 3 failed
        self.assertEqual(pipeline.collector.current_checkpoint, 500)
        self.assertEqual(pipeline.collector.checkpoint_manager.load_checkpoint(), 500)

    def test_subsequent_raw_events_continue_after_recorded_conflict(self):
        pipeline, logger = self._init_real_pipeline(initial_checkpoint=500)
        self._write_sim_xml(pipeline.collector, "01_rec501.xml", record_id=501)
        self._write_sim_xml(pipeline.collector, "02_rec502.xml", record_id=502)

        res_501 = DetectionResult(True, "rule_conflict", 0.9, "high", "det_501", evidence={"rec": 501, "new": True})
        res_502 = DetectionResult(True, "rule_clean", 0.9, "high", "det_502", evidence={"rec": 502})

        id_501 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 501, "rule_conflict", "det_501")
        id_502 = self._compute_expected_detection_event_id(pipeline.identity.agent_id, 502, "rule_clean", "det_502")

        # Seed pre-existing conflicting entry for record 501
        pipeline.outbox.add_event({"detection_event_id": id_501, "severity": "high", "evidence": {"rec": 501, "orig": True}})

        def process_event_for_records(norm_event):
            rec_id = norm_event.get("evidence", {}).get("record_id")
            if rec_id == 501:
                return [res_501]
            if rec_id == 502:
                return [res_502]
            return []

        with patch.object(pipeline.engine, "process_event", side_effect=process_event_for_records):
            pipeline.process_batch()

        # Conflict for 501 durably recorded
        self.assertEqual(len(pipeline.outbox.get_conflicts_for_event(id_501)), 1)
        # Subsequent raw event 502 was processed and buffered into outbox
        pending_ids = {row["detection_event_id"] for row in pipeline.outbox.get_pending_events(limit=50)}
        self.assertIn(id_502, pending_ids)
        # Persisted checkpoint advanced cleanly to 502 (no head-of-line blocking)
        self.assertEqual(pipeline.collector.current_checkpoint, 502)
        self.assertEqual(pipeline.collector.checkpoint_manager.load_checkpoint(), 502)
        reloaded_collector = WindowsEventCollector(logger)
        reloaded_collector.initialize()
        self.assertEqual(reloaded_collector.checkpoint_manager.load_checkpoint(), 502)

if __name__ == "__main__":
    unittest.main()
