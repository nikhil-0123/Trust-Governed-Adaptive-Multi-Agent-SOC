import unittest
import os
import sys
import tempfile
import shutil
import json
import logging
import sqlite3
import socket
import threading
import time
import urllib.request
import urllib.error
from contextlib import closing
from unittest.mock import patch, MagicMock

# Allow imports from SOC/backend
soc_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "SOC", "backend"))
if soc_backend_dir not in sys.path:
    sys.path.insert(0, soc_backend_dir)

from config.settings import config, Settings
from pipeline import WindowsDetectionPipeline
from detection.models import DetectionResult
from transport.outbox import Outbox, TransitionOutbox, OutboxPayloadConflictError, OutboxLock, DeliveryLockTimeoutError
from transport.client import TransportClient, TransitionTransportClient, SendResult
from transport.delivery import DeliveryManager, evaluate_transition_delivery_outcome
from transport.worker import DeliveryWorker
from collectors.windows_event_collector import WindowsEventCollector
from collectors.mailbox import TransitionMailbox

class TestPipelineE2ECoordination(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "outbox.db")
        self.state_dir = os.path.join(self.test_dir, "state")
        self.det_dir = os.path.join(self.test_dir, "detections")

        self.orig_data_dir = config.data_dir
        self.orig_outbox = config.outbox_db_path
        self.orig_checkpoint = config.checkpoint_dir
        self.orig_detection = config.detection_output_dir
        self.orig_enable_system = config.enable_system_collection
        self.orig_enable_sysmon = config.enable_sysmon_collection
        self.orig_agent_token = getattr(config, "soc_agent_api_token", "")

        config.data_dir = self.test_dir
        config.outbox_db_path = self.db_path
        config.checkpoint_dir = self.state_dir
        config.detection_output_dir = self.det_dir
        config.enable_system_collection = True
        config.enable_sysmon_collection = False
        config.soc_agent_api_token = "token-test-agent-e2e"

        self.logger = logging.getLogger(f"TestE2ECoordination_{self._testMethodName}")
        self.logger.setLevel(logging.INFO)

    def tearDown(self):
        config.data_dir = self.orig_data_dir
        config.outbox_db_path = self.orig_outbox
        config.checkpoint_dir = self.orig_checkpoint
        config.detection_output_dir = self.orig_detection
        config.enable_system_collection = self.orig_enable_system
        config.enable_sysmon_collection = self.orig_enable_sysmon
        config.soc_agent_api_token = self.orig_agent_token
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_sim_event_104_xml(self, collector, filename: str, record_id: int, affected_channel: str = "Security"):
        xml_content = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Eventlog"/>
        <EventID>104</EventID>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>System</Channel>
        <Computer>WORKSTATION-01</Computer>
        <TimeCreated SystemTime="2026-11-21T10:00:00Z"/>
    </System>
    <UserData>
        <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
            <SubjectUserName>admin</SubjectUserName>
            <SubjectDomainName>CONTOSO</SubjectDomainName>
            <SubjectUserSid>S-1-5-21-12345-500</SubjectUserSid>
            <Channel>{affected_channel}</Channel>
        </LogFileCleared>
    </UserData>
</Event>"""
        os.makedirs(collector.simulated_events_channel_dir, exist_ok=True)
        filepath = os.path.join(collector.simulated_events_channel_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(xml_content)
        return filepath

    def _write_sim_security_event_xml(self, collector, filename: str, record_id: int, event_id: int = 4625):
        xml_content = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>{event_id}</EventID>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>Security</Channel>
        <Computer>WORKSTATION-01</Computer>
        <TimeCreated SystemTime="2026-11-21T10:05:00Z"/>
    </System>
    <EventData>
        <Data Name="TargetUserName">bob</Data>
        <Data Name="TargetDomainName">CONTOSO</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
</Event>"""
        os.makedirs(collector.simulated_events_channel_dir, exist_ok=True)
        filepath = os.path.join(collector.simulated_events_channel_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(xml_content)
        return filepath

    # -------------------------------------------------------------------------
    # Test 1: Capability Reporting and Graceful Degradation
    # -------------------------------------------------------------------------
    def test_pipeline_capabilities_with_system_collector(self):
        """When System collection is enabled and initialized, EventLog_104 is included in capabilities."""
        pipeline = WindowsDetectionPipeline(self.logger)
        caps_initial = pipeline.get_effective_capabilities()
        self.assertNotIn("EventLog_104", caps_initial)  # Not yet initialized

        pipeline.initialize()
        caps_initialized = pipeline.get_effective_capabilities()
        self.assertIn("EventLog_104", caps_initialized)
        self.assertIn("EventLog_4625", caps_initialized)
        self.assertIn("EventLog_4688", caps_initialized)
        self.assertEqual(len(caps_initialized), len(set(caps_initialized)), "Capabilities must not contain duplicates")
        pipeline.shutdown()

    def test_pipeline_system_initialization_failure_degrades_gracefully(self):
        """When System collector fails initialization, pipeline degrades gracefully without crashing."""
        pipeline = WindowsDetectionPipeline(self.logger)
        self.assertIsNotNone(pipeline.system_collector)

        with patch.object(pipeline.system_collector, "initialize", side_effect=RuntimeError("System log inaccessible")):
            pipeline.initialize()
            self.assertFalse(pipeline.system_collector.is_initialized)
            caps = pipeline.refresh_capabilities()
            self.assertNotIn("EventLog_104", caps)
            self.assertIn("EventLog_4625", caps)
            pipeline.shutdown()

    # -------------------------------------------------------------------------
    # Test 2: Polling Order Coordination
    # -------------------------------------------------------------------------
    def test_channel_batch_polling_order_system_before_security(self):
        """
        process_batch() MUST poll System events before Security events so clear witnesses
        publish transition envelopes to the mailbox before Security forward collection starts.
        """
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        execution_order = []

        orig_process_channel_batch = pipeline._process_channel_batch
        def spy_process_channel_batch(collector, channel_name):
            execution_order.append(channel_name)
            return orig_process_channel_batch(collector, channel_name)

        with patch.object(pipeline, "_process_channel_batch", side_effect=spy_process_channel_batch):
            pipeline.process_batch()

        self.assertGreaterEqual(len(execution_order), 2)
        self.assertEqual(execution_order[0], "System")
        self.assertEqual(execution_order[1], "Security")
        pipeline.shutdown()

    # -------------------------------------------------------------------------
    # Test 3: End-to-End System Event 104 -> Mailbox -> Security Epoch Advance
    # -------------------------------------------------------------------------
    def test_e2e_cross_channel_event_104_advances_security_epoch_and_drains_notification(self):
        """
        End-to-end integration test:
        1. System receives Event 104 clearing Security at record 10.
        2. System publishes transition envelope to mailbox.
        3. Security claims envelope from mailbox, advances its epoch from 1 to 2.
        4. Security normalizes post-clear event under epoch 2.
        5. Checkpoint notifications drain to transition_outbox with status 'pending'.
        """
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Seed System Event 104
        self._write_sim_event_104_xml(pipeline.system_collector, "sys_104.xml", record_id=10, affected_channel="Security")
        # Seed post-clear Security event
        self._write_sim_security_event_xml(pipeline.security_collector, "sec_post_clear.xml", record_id=1)

        # Pre-check: Security is at epoch 1
        self.assertEqual(pipeline.security_collector.get_current_epoch(), 1)

        # Execute coordinated batch
        pipeline.process_batch()

        # Verification 1: Security collector advanced to epoch 2
        sec_epoch = pipeline.security_collector.get_current_epoch()
        self.assertEqual(sec_epoch, 2, "Security collector epoch must advance to 2")

        # Verification 2: Mailbox pending transitions directory has no unclaimed files
        pending_files = [f for f in os.listdir(pipeline.security_collector.mailbox.pending_dir) if f.endswith(".json")]
        self.assertEqual(len(pending_files), 0, "Pending mailbox transitions must be claimed")

        # Verification 3: Transition was drained into transition_outbox
        pending_outbox_transitions = pipeline.transition_outbox.get_pending_transitions()
        self.assertEqual(len(pending_outbox_transitions), 1, "Transition must be durably enqueued in transition_outbox")
        t_row = pending_outbox_transitions[0]
        t_payload = json.loads(t_row["transition_data"])
        self.assertEqual(t_payload["target_channel"], "Security")
        self.assertEqual(t_payload["target_epoch"], 2)
        self.assertEqual(t_payload["transition_type"], "LOG_CLEARED_SECURITY_REMOTE")

        # Verification 4: Checkpoint pending notification marker was cleared after durable outbox commit
        sec_state = pipeline.security_collector.checkpoint_manager.load_state()
        self.assertEqual(len(sec_state.get("pending_outbox_notifications", {})), 0)

        pipeline.shutdown()

    # -------------------------------------------------------------------------
    # Test 4: evaluate_transition_delivery_outcome Matrix
    # -------------------------------------------------------------------------
    def test_evaluate_transition_delivery_outcome_all_cases(self):
        """Validates all branches of evaluate_transition_delivery_outcome."""
        tid = "trans-uuid-1"

        # 1. 200 OK APPLIED
        res = evaluate_transition_delivery_outcome(tid, 200, json.dumps({"status": "APPLIED", "transition_id": tid}), 0)
        self.assertEqual(res["action"], "DELIVER")
        self.assertFalse(res["is_duplicate"])

        # 2. 200 OK ALREADY_APPLIED (duplicate)
        res = evaluate_transition_delivery_outcome(tid, 200, json.dumps({"status": "ALREADY_APPLIED", "duplicate": True}), 0)
        self.assertEqual(res["action"], "DELIVER")
        self.assertTrue(res["is_duplicate"])

        # 3. 409 Conflict with duplicate=True ACK
        res = evaluate_transition_delivery_outcome(tid, 409, json.dumps({"duplicate": True, "detail": "Already received"}), 0)
        self.assertEqual(res["action"], "DELIVER")
        self.assertTrue(res["is_duplicate"])

        # 4. 409 Conflict payload collision
        res = evaluate_transition_delivery_outcome(tid, 409, json.dumps({"detail": "Conflicting payload", "conflict_id": "c1"}), 0)
        self.assertEqual(res["action"], "QUARANTINE")
        self.assertEqual(res["quarantine_reason"], "transition_payload_conflict")

        # 5. 400 Bad Request (schema invalid)
        res = evaluate_transition_delivery_outcome(tid, 400, "Bad Request", 0)
        self.assertEqual(res["action"], "QUARANTINE")
        self.assertEqual(res["quarantine_reason"], "invalid_transition_schema")

        # 6. 422 Unprocessable Entity
        res = evaluate_transition_delivery_outcome(tid, 422, "Validation error", 0)
        self.assertEqual(res["action"], "QUARANTINE")
        self.assertEqual(res["quarantine_reason"], "invalid_transition_schema")

        # 7. 401 Unauthorized -> RETRY_AUTH
        res = evaluate_transition_delivery_outcome(tid, 401, "Unauthorized", 0)
        self.assertEqual(res["action"], "RETRY_AUTH")
        self.assertGreater(res["retry_delay"], 0)

        # 8. 401 Unauthorized max retries -> QUARANTINE
        res = evaluate_transition_delivery_outcome(tid, 401, "Unauthorized", 10, max_retries=10)
        self.assertEqual(res["action"], "QUARANTINE")
        self.assertEqual(res["quarantine_reason"], "auth_exhausted")

        # 9. 429 Rate limited -> RETRY_429
        res = evaluate_transition_delivery_outcome(tid, 429, "Rate limit", 0, headers={"Retry-After": "15"})
        self.assertEqual(res["action"], "RETRY_429")
        self.assertTrue(15.0 <= res["retry_delay"] <= 17.0)

        # 10. 500 Internal Server Error -> RETRY_TRANSIENT
        res = evaluate_transition_delivery_outcome(tid, 500, "Server Error", 0)
        self.assertEqual(res["action"], "RETRY_TRANSIENT")

        # 11. 500 max retries -> QUARANTINE
        res = evaluate_transition_delivery_outcome(tid, 500, "Server Error", 10, max_retries=10)
        self.assertEqual(res["action"], "QUARANTINE")
        self.assertEqual(res["quarantine_reason"], "max_retries_exceeded")

    # -------------------------------------------------------------------------
    # Test 5: DeliveryManager Transition Processing
    # -------------------------------------------------------------------------
    def test_delivery_manager_process_transition_outbox_success_and_quarantine(self):
        """Verifies DeliveryManager delivers transition payloads and transitions outbox state."""
        outbox = Outbox(self.db_path, self.logger)
        t_outbox = TransitionOutbox(self.db_path, self.logger)

        client = TransportClient("http://fake", "token", self.logger)
        t_client = MagicMock(spec=TransitionTransportClient)

        manager = DeliveryManager(
            outbox, client, self.logger,
            transition_outbox=t_outbox,
            transition_client=t_client
        )

        # Enqueue transition
        t_payload = {
            "transition_id": "test-tid-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE"
        }
        t_outbox.add_transition(t_payload)

        # Mock successful delivery
        t_client.send_transition.return_value = SendResult(
            True, False, "", status_code=200, response_body=json.dumps({"status": "APPLIED"})
        )

        manager.process_transition_outbox()

        # Check pending is empty, status is delivered
        pending = t_outbox.get_pending_transitions()
        self.assertEqual(len(pending), 0)

        # Verify delivered row exists in SQLite table
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, delivered_at FROM transition_outbox WHERE transition_id = 'test-tid-001'")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "delivered")
        self.assertIsNotNone(row[1])
        conn.close()

    def test_delivery_manager_process_transition_outbox_conflict_quarantines(self):
        """Verifies DeliveryManager quarantines transition on HTTP 409 conflict."""
        outbox = Outbox(self.db_path, self.logger)
        t_outbox = TransitionOutbox(self.db_path, self.logger)
        client = TransportClient("http://fake", "token", self.logger)
        t_client = MagicMock(spec=TransitionTransportClient)

        manager = DeliveryManager(
            outbox, client, self.logger,
            transition_outbox=t_outbox,
            transition_client=t_client
        )

        t_payload = {
            "transition_id": "test-tid-conflict",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
        }
        t_outbox.add_transition(t_payload)

        # Mock conflict response
        t_client.send_transition.return_value = SendResult(
            False, False, "HTTP 409 Conflict", status_code=409,
            response_body=json.dumps({"detail": "Transition payload conflict", "conflict_id": "conf-123"})
        )

        manager.process_transition_outbox()

        # Pending should be empty
        self.assertEqual(len(t_outbox.get_pending_transitions()), 0)

        # Row should be quarantined
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, quarantine_reason FROM transition_outbox WHERE transition_id = 'test-tid-conflict'")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "quarantined")
        self.assertEqual(row[1], "transition_payload_conflict")
        conn.close()

    # -------------------------------------------------------------------------
    # Test 6: Full Coordinated Pipeline Execution with Mock Backend
    # -------------------------------------------------------------------------
    def test_full_coordinated_pipeline_with_mock_backend(self):
        """
        Validates the entire multi-channel coordination pipeline end-to-end:
        1. Event 104 in System log clears Security.
        2. Detection event in Security log occurs.
        3. process_batch() runs:
           - System emits transition.
           - Security claims transition and advances epoch.
           - Security detects event under new epoch and adds detection to outbox.
           - Checkpoints drain notifications to transition_outbox.
        4. shutdown() flushes outbox and delivers both detection and transition.
        """
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Seed events
        self._write_sim_event_104_xml(pipeline.system_collector, "sys_104.xml", record_id=50, affected_channel="Security")
        self._write_sim_security_event_xml(pipeline.security_collector, "sec_4625.xml", record_id=1)

        def mock_detect(norm_event):
            ev_id = norm_event.get("evidence", {}).get("windows_event_id")
            if ev_id == 4625:
                return [DetectionResult(True, "windows_bruteforce_rule", 0.95, "high", "rule_detector", evidence={"user": "bob"})]
            return []

        # Mock responses on transport clients
        with patch.object(pipeline.engine, "process_event", side_effect=mock_detect), \
             patch.object(pipeline.transition_client, "send_transition") as mock_send_trans, \
             patch.object(pipeline.client, "send_event") as mock_send_event:

            mock_send_trans.return_value = SendResult(
                True, False, "", status_code=200,
                response_body=json.dumps({"status": "APPLIED", "transition_id": "mock_tid"})
            )
            mock_send_event.return_value = SendResult(
                True, False, "", status_code=201,
                response_body=json.dumps({"accepted": True, "duplicate": False, "detection_event_id": "mock_eid"})
            )

            # In the spy, capture the actual detection_event_id passed to send_event
            def capture_send_event(event_data):
                eid = event_data.get("detection_event_id", "")
                return SendResult(
                    True, False, "", status_code=201,
                    response_body=json.dumps({"accepted": True, "duplicate": False, "detection_event_id": eid})
                )
            mock_send_event.side_effect = capture_send_event

            # Run batch
            pipeline.process_batch()

            # Verify epoch was advanced to 2
            self.assertEqual(pipeline.security_collector.get_current_epoch(), 2)

            # Shutdown triggers flush
            pipeline.shutdown()

            # Verify transition client was called
            mock_send_trans.assert_called_once()
            called_trans_data = mock_send_trans.call_args[0][0]
            self.assertEqual(called_trans_data["target_channel"], "Security")
            self.assertEqual(called_trans_data["target_epoch"], 2)

            # Verify detection client was called
            mock_send_event.assert_called_once()
            called_event_data = mock_send_event.call_args[0][0]
            self.assertEqual(called_event_data["evidence"]["channel_epoch"], 2)
            self.assertEqual(called_event_data["evidence"]["log_name"], "Security")

            # Verify both outboxes now have 0 pending events
            self.assertEqual(len(pipeline.outbox.get_pending_events()), 0)
            self.assertEqual(len(pipeline.transition_outbox.get_pending_transitions()), 0)


# =========================================================================
# OBJECTIVE 1: DELIVERY CONCURRENCY & SHUTDOWN SAFETY
# =========================================================================

class TestDeliveryConcurrencyAndShutdownSafety(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "outbox.db")
        self.logger = logging.getLogger(f"TestConcurrency_{self._testMethodName}")
        self.logger.setLevel(logging.INFO)
        self.orig_enable_system = config.enable_system_collection
        self.orig_enable_sysmon = config.enable_sysmon_collection
        self.orig_agent_token = getattr(config, "soc_agent_api_token", "")
        self.orig_data_dir = config.data_dir
        self.orig_outbox = config.outbox_db_path
        self.orig_checkpoint = config.checkpoint_dir
        self.orig_detection = config.detection_output_dir

    def tearDown(self):
        config.enable_system_collection = self.orig_enable_system
        config.enable_sysmon_collection = self.orig_enable_sysmon
        config.soc_agent_api_token = self.orig_agent_token
        config.data_dir = self.orig_data_dir
        config.outbox_db_path = self.orig_outbox
        config.checkpoint_dir = self.orig_checkpoint
        config.detection_output_dir = self.orig_detection
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_concurrent_worker_and_direct_process_outbox_mutual_exclusion(self):
        """
        Verify that when DeliveryWorker is holding the OutboxLock,
        a direct call to DeliveryManager.process_outbox() cannot run concurrently.
        """
        outbox = Outbox(self.db_path, self.logger)
        t_outbox = TransitionOutbox(self.db_path, self.logger)
        client = TransportClient("http://fake", "token", self.logger)
        t_client = MagicMock(spec=TransitionTransportClient)

        manager = DeliveryManager(
            outbox, client, self.logger,
            transition_outbox=t_outbox,
            transition_client=t_client
        )

        worker = DeliveryWorker(manager, self.logger, poll_interval=0.5)
        worker.start()
        time.sleep(0.15)
        self.assertTrue(worker.is_alive())

        # Direct call with raise_on_lock_failure=True must raise DeliveryLockTimeoutError
        with self.assertRaises(DeliveryLockTimeoutError):
            manager.process_outbox(timeout=0.05, raise_on_lock_failure=True)

        # Direct call without raise must safely return without error and without deadlock
        manager.process_outbox(timeout=0.05, raise_on_lock_failure=False)

        worker.stop()
        self.assertFalse(worker.is_alive())

    def test_clean_worker_termination_enables_shutdown_flush(self):
        """
        Verify that pipeline.shutdown() waits for DeliveryWorker to cleanly stop,
        releases the lock, and then successfully flushes the outbox.
        """
        config.data_dir = self.test_dir
        config.outbox_db_path = self.db_path
        config.checkpoint_dir = os.path.join(self.test_dir, "state")
        config.detection_output_dir = os.path.join(self.test_dir, "detections")
        config.enable_system_collection = False
        config.enable_sysmon_collection = False
        config.soc_agent_api_token = "valid-token"

        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Worker is alive
        self.assertTrue(pipeline.delivery_worker.is_alive())

        # Add a dummy pending transition
        pipeline.transition_outbox.add_transition({
            "transition_id": "TRANS-FLUSH-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE"
        })
        self.assertEqual(len(pipeline.transition_outbox.get_pending_transitions()), 1)

        # Mock transition delivery
        if pipeline.transition_client:
            pipeline.transition_client.send_transition = MagicMock(
                return_value=SendResult(True, False, "", status_code=200, response_body=json.dumps({"status": "APPLIED"}))
            )

        pipeline.shutdown(worker_join_timeout=5.0)

        # Worker stopped
        self.assertFalse(pipeline.delivery_worker.is_alive())
        # Pending transition was flushed during shutdown
        self.assertEqual(len(pipeline.transition_outbox.get_pending_transitions()), 0)

    def test_unclean_worker_termination_skips_shutdown_flush(self):
        """
        Verify that if the DeliveryWorker fails to terminate within timeout,
        pipeline.shutdown() skips the final flush to prevent concurrent execution races.
        """
        config.data_dir = self.test_dir
        config.outbox_db_path = self.db_path
        config.checkpoint_dir = os.path.join(self.test_dir, "state")
        config.detection_output_dir = os.path.join(self.test_dir, "detections")
        config.enable_system_collection = False
        config.enable_sysmon_collection = False

        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Simulate a hung worker whose is_alive() remains True
        pipeline.delivery_worker.is_alive = MagicMock(return_value=True)

        with patch.object(pipeline.delivery_manager, "process_outbox") as mock_flush:
            pipeline.shutdown(worker_join_timeout=0.01)
            # Final flush MUST have been aborted
            mock_flush.assert_not_called()

        pipeline.delivery_worker.stop()

    def test_late_retries_cannot_overwrite_delivered_transition_to_quarantined(self):
        """
        Verify that mark_quarantined() and mark_failed() preserve 'delivered' status
        and never allow a late retry response to overwrite an already delivered transition.
        """
        t_outbox = TransitionOutbox(self.db_path, self.logger)
        t_outbox.add_transition({
            "transition_id": "TRANS-LATE-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE"
        })

        # 1. Mark delivered
        t_outbox.mark_delivered("TRANS-LATE-001")
        conn = t_outbox._get_connection()
        row = conn.execute("SELECT status FROM transition_outbox WHERE transition_id = 'TRANS-LATE-001'").fetchone()
        self.assertEqual(row["status"], "delivered")
        conn.close()

        # 2. Simulate late retry error -> mark_failed
        t_outbox.mark_failed("TRANS-LATE-001", "Simulated late transport failure")
        conn = t_outbox._get_connection()
        row = conn.execute("SELECT status FROM transition_outbox WHERE transition_id = 'TRANS-LATE-001'").fetchone()
        self.assertEqual(row["status"], "delivered")
        conn.close()

        # 3. Simulate late quarantine response -> mark_quarantined
        t_outbox.mark_quarantined("TRANS-LATE-001", "late_quarantine_error", "Late 422 error")
        conn = t_outbox._get_connection()
        row = conn.execute("SELECT status FROM transition_outbox WHERE transition_id = 'TRANS-LATE-001'").fetchone()
        self.assertEqual(row["status"], "delivered")
        conn.close()

    def test_late_retries_cannot_overwrite_delivered_detection_event(self):
        """
        Verify that Outbox.mark_quarantined() and mark_failed() preserve 'delivered' status
        for detection events as well.
        """
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({
            "detection_event_id": "DET-LATE-001",
            "timestamp": "2026-11-21T00:00:00Z",
            "agent_id": "AGT-WIN-01",
            "hostname": "HOST-01",
            "os": "windows",
            "source_event_id": "1",
            "detection_type": "rule",
            "confidence": 0.9,
            "severity": "high",
            "detector_name": "rule",
            "evidence": {}
        })

        outbox.mark_delivered("DET-LATE-001")
        conn = outbox._get_connection()
        row = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'DET-LATE-001'").fetchone()
        self.assertEqual(row["status"], "delivered")
        conn.close()

        outbox.mark_failed("DET-LATE-001", "Late error")
        conn = outbox._get_connection()
        row = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'DET-LATE-001'").fetchone()
        self.assertEqual(row["status"], "delivered")
        conn.close()

        outbox.mark_quarantined("DET-LATE-001", "Late quarantine", "Late 422")
        conn = outbox._get_connection()
        row = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'DET-LATE-001'").fetchone()
        self.assertEqual(row["status"], "delivered")
        conn.close()

    def test_worker_internal_type_error_invoked_exactly_once(self):
        """
        Verify that an internal TypeError raised within delivery_manager.process_outbox()
        is logged cleanly and NEVER triggers a duplicate invocation during worker polling.
        """
        outbox = Outbox(self.db_path, self.logger)
        client = TransportClient("http://fake", "tok", self.logger)
        manager = DeliveryManager(outbox, client, self.logger)

        call_count = 0
        executed_event = threading.Event()

        def exploding_type_error(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            executed_event.set()
            raise TypeError("Simulated internal TypeError in delivery batch calculation")

        manager.process_outbox = exploding_type_error

        worker = DeliveryWorker(manager, self.logger, poll_interval=1.0)
        worker.start()
        self.assertTrue(executed_event.wait(timeout=2.0))
        # Ensure worker is stopped before next cycle
        worker.stop()
        self.assertFalse(worker.is_alive())

        # Operation must have been called exactly once during the cycle
        self.assertEqual(call_count, 1)


# =========================================================================
# OBJECTIVE 2: PER-AGENT TRANSITION AUTHENTICATION
# =========================================================================

class TestPerAgentTransitionAuthentication(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(f"TestAuth_{self._testMethodName}")

    def test_client_rejects_empty_token(self):
        """TransitionTransportClient must reject missing or empty tokens."""
        with self.assertRaises(ValueError) as ctx:
            TransitionTransportClient("http://fake", "", self.logger)
        self.assertIn("non-empty token", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            TransitionTransportClient("http://fake", "   ", self.logger)
        self.assertIn("non-empty token", str(ctx.exception))

    def test_client_rejects_shared_soc_token(self):
        """TransitionTransportClient must reject generic shared SOC_API_TOKEN."""
        orig = os.environ.get("SOC_API_TOKEN")
        try:
            os.environ["SOC_API_TOKEN"] = "dev-shared-endpoint-token"
            with self.assertRaises(ValueError) as ctx:
                TransitionTransportClient("http://fake", "dev-shared-endpoint-token", self.logger)
            self.assertIn("cannot use shared SOC_API_TOKEN", str(ctx.exception))
        finally:
            if orig is not None:
                os.environ["SOC_API_TOKEN"] = orig
            else:
                os.environ.pop("SOC_API_TOKEN", None)

    def test_client_validates_matching_agent_id(self):
        """TransitionTransportClient rejects payloads for other agents."""
        client = TransitionTransportClient(
            "http://fake", "token-agent-a", self.logger, agent_id="AGENT-A"
        )
        transition_b = {
            "transition_id": "t-mismatch-1",
            "agent_id": "AGENT-B",
            "source_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE"
        }
        with self.assertRaises(ValueError) as ctx:
            client.send_transition(transition_b)
        self.assertIn("does not match authenticated agent_id", str(ctx.exception))


# =========================================================================
# OBJECTIVE 3: FORMAL PYDANTIC TRANSITION REQUEST MODEL
# =========================================================================

class TestPydanticTransitionRequestModel(unittest.TestCase):
    def setUp(self):
        from app.main import ChannelTransitionRequest
        self.model_cls = ChannelTransitionRequest

    def test_valid_payload_parsing(self):
        """Valid transition dictionary parses cleanly."""
        payload = {
            "transition_id": "TRANS-PYDANTIC-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
            "witness_payload": {"record_id": 100}
        }
        model = self.model_cls(**payload)
        dump = model.model_dump() if hasattr(model, "model_dump") else model.dict()
        self.assertEqual(dump["transition_id"], "TRANS-PYDANTIC-001")
        self.assertEqual(dump["target_epoch"], 2)

    def test_missing_required_fields_rejected(self):
        """Missing required fields raises validation error."""
        with self.assertRaises(Exception):
            self.model_cls(agent_id="AGT-WIN-01", source_channel="Security", target_epoch=2)
        with self.assertRaises(Exception):
            self.model_cls(transition_id="t1", source_channel="Security", target_epoch=2)
        with self.assertRaises(Exception):
            self.model_cls(transition_id="t1", agent_id="AGT-WIN-01", target_epoch=2)
        with self.assertRaises(Exception):
            self.model_cls(transition_id="t1", agent_id="AGT-WIN-01", source_channel="Security")

    def test_invalid_target_epoch_rejected(self):
        """target_epoch < 1 raises validation error."""
        with self.assertRaises(Exception):
            self.model_cls(transition_id="t1", agent_id="A", source_channel="S", target_epoch=0)
        with self.assertRaises(Exception):
            self.model_cls(transition_id="t1", agent_id="A", source_channel="S", target_epoch=-5)

    def test_unsupported_transition_type_rejected(self):
        """Arbitrary unsupported transition_type raises validation error."""
        with self.assertRaises(Exception):
            self.model_cls(
                transition_id="t1", agent_id="A", source_channel="S", target_epoch=2,
                transition_type="MALICIOUS_UNSUPPORTED_TYPE"
            )

    def test_empty_string_fields_rejected(self):
        """Empty string fields raise validation error."""
        with self.assertRaises(Exception):
            self.model_cls(transition_id="", agent_id="A", source_channel="S", target_epoch=2)
        with self.assertRaises(Exception):
            self.model_cls(transition_id="t1", agent_id="   ", source_channel="S", target_epoch=2)


# =========================================================================
# OBJECTIVE 4: REAL HTTP END-TO-END INTEGRATION
# =========================================================================

class TestLiveHttpTransitionIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn
        import urllib.request

        cls.test_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.test_dir, "soc_test.db")
        cls.orig_env_db = os.environ.get("SOC_DB_PATH")
        cls.orig_agent_tokens = os.environ.get("SOC_AGENT_API_TOKENS")
        cls.orig_api_token = os.environ.get("SOC_API_TOKEN")
        cls.orig_disable_workers = os.environ.get("DISABLE_STARTUP_WORKERS")

        os.environ["SOC_DB_PATH"] = cls.db_path
        os.environ["DISABLE_STARTUP_WORKERS"] = "1"
        os.environ["SOC_API_TOKEN"] = "dev-shared-token-test"
        os.environ["SOC_AGENT_API_TOKENS"] = json.dumps({
            "AGT-WIN-01": "live-test-agent-token-12345",
            "AGT-WIN-02": "live-test-agent-token-67890"
        })
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        os.environ["no_proxy"] = "127.0.0.1,localhost"
        cls.orig_opener = getattr(urllib.request, "_opener", None)
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

        import app.database as database
        cls.orig_db_path = getattr(database, "DB_PATH", None)
        database.DB_PATH = cls.db_path
        database.init_db()

        from app.main import app as fastapi_app

        def find_free_port():
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.bind(('127.0.0.1', 0))
                return s.getsockname()[1]

        cls.port = find_free_port()
        u_config = uvicorn.Config(fastapi_app, host="127.0.0.1", port=cls.port, log_level="error")
        cls.server = uvicorn.Server(u_config)
        cls.server_thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.server_thread.start()

        # Wait for server readiness
        url = f"http://127.0.0.1:{cls.port}/docs"
        ready = False
        for _ in range(50):
            try:
                with urllib.request.urlopen(url, timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.1)

        if not ready:
            raise RuntimeError(f"Live FastAPI test server failed to start on port {cls.port}")

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.server_thread.join(timeout=5.0)

        if cls.orig_opener is not None:
            urllib.request.install_opener(cls.orig_opener)

        import app.database as database
        if cls.orig_db_path:
            database.DB_PATH = cls.orig_db_path
        if cls.orig_env_db:
            os.environ["SOC_DB_PATH"] = cls.orig_env_db
        else:
            os.environ.pop("SOC_DB_PATH", None)

        if cls.orig_agent_tokens:
            os.environ["SOC_AGENT_API_TOKENS"] = cls.orig_agent_tokens
        else:
            os.environ.pop("SOC_AGENT_API_TOKENS", None)

        if cls.orig_api_token:
            os.environ["SOC_API_TOKEN"] = cls.orig_api_token
        else:
            os.environ.pop("SOC_API_TOKEN", None)

        if cls.orig_disable_workers:
            os.environ["DISABLE_STARTUP_WORKERS"] = cls.orig_disable_workers
        else:
            os.environ.pop("DISABLE_STARTUP_WORKERS", None)

        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_live_http_transition_authenticated_and_idempotent_flow(self):
        """
        Exercises full live HTTP boundary:
        1. Live TransitionTransportClient sends ChannelTransition envelope over HTTP.
        2. Central FastAPI endpoint authenticates per-agent credential via SOC_AGENT_API_TOKENS.
        3. Endpoint transitions Security channel epoch from 1 to 2 in central SQLite database.
        4. Re-sending identical transition receives idempotent HTTP 200 ALREADY_APPLIED.
        5. Sending with unmapped token receives HTTP 401.
        6. Sending with another agent's token receives HTTP 403.
        7. Sending with malformed schema (e.g. target_epoch=0) receives HTTP 422.
        """
        logger = logging.getLogger("LiveHttpTest")
        endpoint_url = f"http://127.0.0.1:{self.port}/api/v1/events/transition"

        # 1. Successful authenticated transition delivery
        client = TransitionTransportClient(
            endpoint_url,
            "live-test-agent-token-12345",
            logger,
            agent_id="AGT-WIN-01"
        )
        t_payload = {
            "transition_id": "live-test-trans-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE"
        }

        res = client.send_transition(t_payload)
        self.assertTrue(res.success, f"Live send failed: {res.error}")
        self.assertFalse(res.duplicate)
        self.assertEqual(res.status_code, 200)

        resp_json = json.loads(res.response_body)
        self.assertEqual(resp_json["status"], "APPLIED")
        self.assertEqual(resp_json["active_epoch"], 2)

        # 2. Verify state mutated in central SQLite database
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = 'AGT-WIN-01' AND channel = 'Security'"
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["current_epoch"], 2)
        self.assertEqual(row["status"], "ACTIVE")

        cur_t = conn.execute("SELECT transition_id, target_epoch FROM channel_transitions WHERE transition_id = 'live-test-trans-001'")
        t_row = cur_t.fetchone()
        self.assertIsNotNone(t_row)
        self.assertEqual(t_row["target_epoch"], 2)
        conn.close()

        # 3. Idempotent re-send of identical transition
        res_dup = client.send_transition(t_payload)
        self.assertTrue(res_dup.success)
        self.assertTrue(res_dup.duplicate)
        self.assertEqual(res_dup.status_code, 200)
        dup_json = json.loads(res_dup.response_body)
        self.assertEqual(dup_json["status"], "ALREADY_APPLIED")

        # 4. Auth failure: invalid token
        bad_token_client = TransitionTransportClient(
            endpoint_url,
            "bogus-unmapped-token",
            logger,
            agent_id="AGT-WIN-01"
        )
        res_unauth = bad_token_client.send_transition({
            "transition_id": "live-test-trans-002",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 3,
            "transition_type": "EPOCH_ADVANCE"
        })
        self.assertFalse(res_unauth.success)
        self.assertEqual(res_unauth.status_code, 401)

        # 5. Auth failure: token for AGT-WIN-02 used for AGT-WIN-01 transition
        other_agent_client = TransitionTransportClient(
            endpoint_url,
            "live-test-agent-token-67890",
            logger,
            agent_id=None
        )
        res_forbidden = other_agent_client.send_transition({
            "transition_id": "live-test-trans-003",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 3,
            "transition_type": "EPOCH_ADVANCE"
        })
        self.assertFalse(res_forbidden.success)
        self.assertEqual(res_forbidden.status_code, 403)

        # 6. Schema validation failure: target_epoch=0 rejected with HTTP 422
        res_invalid = client.send_transition({
            "transition_id": "live-test-trans-004",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 0,
            "transition_type": "EPOCH_ADVANCE"
        })
        self.assertFalse(res_invalid.success)
        self.assertEqual(res_invalid.status_code, 422)

if __name__ == "__main__":
    unittest.main()
