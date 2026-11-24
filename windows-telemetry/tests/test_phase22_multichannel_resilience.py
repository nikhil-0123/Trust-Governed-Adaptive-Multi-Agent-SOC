import unittest
import os
import sys
import tempfile
import shutil
import time
import json
import logging
import subprocess
from unittest.mock import patch, MagicMock

from config.settings import config, Settings
from pipeline import WindowsDetectionPipeline, ChannelScheduleState
from collectors.windows_event_collector import (
    WindowsEventCollector,
    ChannelQueryError,
    ChannelUnavailableError,
    ChannelTimeoutError,
    UnverifiedDiscontinuityError,
)
from transport.heartbeat import HeartbeatWorker
from detection.detector import DetectionEngine
from canonical import generate_source_event_id_v2


class TestPhase22MultichannelResilience(unittest.TestCase):
    """
    Deterministic regression test suite for TGAM-SOC Phase 2.2:
    Windows Multichannel Resilience, Failure Isolation, Scheduling Fairness,
    and Observability.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.orig_data_dir = config.data_dir
        self.orig_outbox = config.outbox_db_path
        self.orig_checkpoint = config.checkpoint_dir
        self.orig_detection = config.detection_output_dir

        config.data_dir = self.test_dir
        config.outbox_db_path = os.path.join(self.test_dir, "outbox.db")
        config.checkpoint_dir = os.path.join(self.test_dir, "state")
        config.detection_output_dir = os.path.join(self.test_dir, "detections")

        self.logger = logging.getLogger("TestPhase22Resilience")
        self.logger.setLevel(logging.INFO)

    def tearDown(self):
        config.data_dir = self.orig_data_dir
        config.outbox_db_path = self.orig_outbox
        config.checkpoint_dir = self.orig_checkpoint
        config.detection_output_dir = self.orig_detection
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_sim_xml(self, collector, filename: str, record_id: int, event_id: int = 4625, channel: str = "Security"):
        xml_content = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>{event_id}</EventID>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>{channel}</Channel>
        <Computer>WORKSTATION-01</Computer>
        <TimeCreated SystemTime="2026-11-24T12:00:00Z"/>
    </System>
    <EventData><Data Name="TargetUserName">alice</Data></EventData>
</Event>"""
        os.makedirs(collector.simulated_events_channel_dir, exist_ok=True)
        filepath = os.path.join(collector.simulated_events_channel_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(xml_content)
        return filepath

    # 1. Missing Sysmon channel while Security collection continues
    def test_01_missing_sysmon_channel_security_continues(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Place a valid event into Security simulation
        self._write_sim_xml(pipeline.security_collector, "sec_1.xml", 501, event_id=4625)

        # Mock Sysmon collector raising ChannelUnavailableError
        if pipeline.sysmon_collector:
            pipeline.sysmon_collector.collect_once = MagicMock(
                side_effect=ChannelUnavailableError("Sysmon channel not found", channel="Sysmon")
            )

        pipeline.process_batch()

        # Security collection succeeded and advanced checkpoint
        self.assertEqual(pipeline.security_collector.current_checkpoint, 501)
        # Sysmon entered retry backoff without blocking Security
        if "Sysmon" in pipeline.schedules:
            self.assertGreater(pipeline.schedules["Sysmon"].consecutive_failures, 0)
            self.assertGreater(pipeline.schedules["Sysmon"].backoff_until_monotonic, time.monotonic())
        pipeline.shutdown()

    # 2. Channel permission failure and subsequent recovery
    def test_02_channel_permission_failure_and_subsequent_recovery(self):
        collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
        collector.initialize()

        # Simulate permission denied
        with patch.object(collector, "_probe_newest_record_id", return_value=(None, "COMMAND_UNAVAILABLE")):
            with self.assertRaises(ChannelUnavailableError):
                collector.collect_once(raise_on_error=True)
            self.assertEqual(collector.status, "UNAVAILABLE")
            self.assertEqual(collector.consecutive_failures, 1)

        # Simulate subsequent permission recovery and event arrival
        self._write_sim_xml(collector, "recov.xml", 200, event_id=4625)
        events = collector.collect_once(raise_on_error=True)
        self.assertEqual(len(events), 1)
        self.assertEqual(collector.status, "HEALTHY")
        self.assertEqual(collector.consecutive_failures, 0)
        self.assertIsNotNone(collector.last_successful_collection)

    # 3. Subprocess timeout without cross-channel starvation
    def test_03_subprocess_timeout_without_cross_channel_starvation(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Mock System collector query timing out
        if pipeline.system_collector:
            pipeline.system_collector.collect_once = MagicMock(
                side_effect=ChannelTimeoutError("wevtutil timed out", channel="System")
            )

        # Provide Security events
        self._write_sim_xml(pipeline.security_collector, "sec_ok.xml", 301, event_id=4625)

        pipeline.process_batch()

        # Security must NOT have been starved; it must complete successfully
        self.assertEqual(pipeline.security_collector.current_checkpoint, 301)
        if "System" in pipeline.schedules:
            self.assertGreater(pipeline.schedules["System"].consecutive_failures, 0)
        pipeline.shutdown()

    # 4. Fair polling under sustained channel load
    def test_04_fair_polling_under_sustained_channel_load(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        polled_order = []
        def mock_proc(col, name):
            polled_order.append(name)

        pipeline._process_channel_batch = mock_proc

        # Call process_batch with respect_intervals=True across simulated monotonic ticks
        t0 = 1000.0
        with patch("time.monotonic", return_value=t0):
            pipeline.process_batch(respect_intervals=True)
        self.assertIn("Security", polled_order)

        # T = +1.0s (less than 5.0s interval, no simulated files): channels should be throttled
        with patch("time.monotonic", return_value=t0 + 1.0):
            polled_order.clear()
            pipeline.process_batch(respect_intervals=True)
        self.assertEqual(len(polled_order), 0)

        # T = +6.0s (greater than 5.0s interval): channels should be polled fairly
        with patch("time.monotonic", return_value=t0 + 6.0):
            polled_order.clear()
            pipeline.process_batch(respect_intervals=True)
        self.assertIn("Security", polled_order)
        pipeline.shutdown()

    # 5. Independent channel checkpoints
    def test_05_independent_channel_checkpoints(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        # Security receives record 600
        self._write_sim_xml(pipeline.security_collector, "sec_600.xml", 600, channel="Security")
        # System receives record 50
        if pipeline.system_collector:
            self._write_sim_xml(pipeline.system_collector, "sys_50.xml", 50, event_id=7045, channel="System")

        pipeline.process_batch()

        self.assertEqual(pipeline.security_collector.current_checkpoint, 600)
        if pipeline.system_collector:
            self.assertEqual(pipeline.system_collector.current_checkpoint, 50)
            self.assertNotEqual(
                pipeline.security_collector.current_checkpoint,
                pipeline.system_collector.current_checkpoint
            )
        pipeline.shutdown()

    # 6. Channel-specific retry behavior
    def test_06_channel_specific_retry_behavior(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        sched = pipeline.schedules["Security"]
        self.assertEqual(sched.consecutive_failures, 0)
        self.assertEqual(sched.backoff_until_monotonic, 0.0)

        t_now = 5000.0
        with patch("time.monotonic", return_value=t_now):
            pipeline._record_channel_failure("Security", "query timeout")
            # Failure 1: base = 2.0s
            self.assertEqual(sched.consecutive_failures, 1)
            self.assertAlmostEqual(sched.backoff_until_monotonic, t_now + 2.0)

            pipeline._record_channel_failure("Security", "query timeout")
            # Failure 2: base * 2^1 = 4.0s
            self.assertEqual(sched.consecutive_failures, 2)
            self.assertAlmostEqual(sched.backoff_until_monotonic, t_now + 4.0)

            pipeline._record_channel_success("Security")
            self.assertEqual(sched.consecutive_failures, 0)
            self.assertEqual(sched.backoff_until_monotonic, 0.0)
        pipeline.shutdown()

    # 7. Cross-channel Event 104 witness processing
    def test_07_cross_channel_event104_witness_processing(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        self.assertEqual(pipeline.security_collector.get_current_epoch(), 1)

        # Deposit clear witness for Security into System channel
        xml_104 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>88</EventRecordID>
    <Channel>System</Channel>
    <Computer>WORKSTATION-01</Computer>
    <TimeCreated SystemTime='2026-11-24T12:00:00Z'/>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>secadmin</SubjectUserName>
      <Channel>Security</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
        if pipeline.system_collector:
            os.makedirs(pipeline.system_collector.simulated_events_channel_dir, exist_ok=True)
            with open(os.path.join(pipeline.system_collector.simulated_events_channel_dir, "clear_104.xml"), "w") as f:
                f.write(xml_104)

            pipeline.process_batch()

            # Security epoch should have advanced to 2
            self.assertEqual(pipeline.security_collector.get_current_epoch(), 2)
            self.assertEqual(pipeline.security_collector.current_checkpoint, 0)
        pipeline.shutdown()

    # 8. Duplicate and delayed epoch transition witnesses
    def test_08_duplicate_and_delayed_epoch_transition_witnesses(self):
        sec_collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        tid = "TR-AGT-WIN-01-System-EP1-REC88-EV104"
        envelope = {
            "transition_id": tid,
            "signature": "simulated_sig",
            "witness_payload": {"event_id": 104, "record_id": 88},
            "identity_manifest": {
                "agent_id": "AGT-WIN-01",
                "source_channel": "System",
                "source_epoch": 1,
                "source_record_id": 88
            }
        }
        with patch.object(sec_collector.mailbox, "claim_pending_transitions", return_value=[envelope]), \
             patch("collectors.windows_event_collector.TransitionMailbox.verify_transition", return_value=(True, None)), \
             patch.object(sec_collector.checkpoint_manager, "is_transition_applied", return_value=True), \
             patch.object(sec_collector.mailbox, "acknowledge_transition") as mock_ack:
            sec_collector.check_and_apply_pending_transitions()
            mock_ack.assert_called_once_with(tid)
            # Epoch remains 1 (duplicate acknowledged without double advance)
            self.assertEqual(sec_collector.get_current_epoch(), 1)

    # 9. Restart and shutdown behavior
    def test_09_restart_and_shutdown_behavior(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()
        self.assertTrue(pipeline.heartbeat_worker.is_alive())
        self.assertTrue(pipeline.delivery_worker.is_alive())

        # Advance checkpoint to 750
        pipeline.security_collector.checkpoint_manager.save_checkpoint(750)

        pipeline.shutdown()
        self.assertTrue(pipeline._shutdown_requested)
        self.assertFalse(pipeline.heartbeat_worker.is_alive())
        self.assertFalse(pipeline.delivery_worker.is_alive())

        # Restart in same data directory
        restarted = WindowsDetectionPipeline(self.logger)
        restarted.initialize()
        self.assertEqual(restarted.security_collector.current_checkpoint, 750)
        restarted.shutdown()

    # 10. Backpressure and recovery
    def test_10_backpressure_and_recovery(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()
        pipeline.delivery_worker.stop()  # Keep worker stopped during outbox queue limit assertion
        pipeline.max_pending_records = 2

        # Fill outbox to max_pending limit
        pipeline.outbox.add_event({"detection_event_id": "DT-1", "event_id": "ev1", "timestamp": "2026-11-24T12:00:00Z", "payload": {}})
        pipeline.outbox.add_event({"detection_event_id": "DT-2", "event_id": "ev2", "timestamp": "2026-11-24T12:00:00Z", "payload": {}})

        # Security collector has initial checkpoint 100
        pipeline.security_collector.current_checkpoint = 100
        pipeline.security_collector.checkpoint_manager.save_checkpoint(100)

        # Inject simulated event 101
        self._write_sim_xml(pipeline.security_collector, "sec_bp.xml", 101, event_id=4625)

        pipeline.process_batch()

        # Ingestion paused; checkpoint preserved at 100
        self.assertEqual(pipeline.security_collector.current_checkpoint, 100)

        # Recover by draining outbox
        conn = pipeline.outbox._get_connection()
        conn.execute("UPDATE outbox SET status = 'delivered'")
        conn.commit()
        conn.close()

        pipeline.process_batch()
        # Ingestion resumes; checkpoint advances to 101
        self.assertEqual(pipeline.security_collector.current_checkpoint, 101)
        pipeline.shutdown()

    # 11. Quarantine write failures and fault injections
    def test_11_quarantine_write_failures(self):
        collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
        collector.initialize()
        collector.current_checkpoint = 50

        # When quarantine write fails (returns empty string)
        with patch.object(collector, "quarantine_oversized_record", return_value=""), \
             patch.object(collector, "_probe_newest_record_id", return_value=(60, None)), \
             patch("subprocess.run") as mock_run:
            # Fake oversized XML batch (>10MB)
            mock_res = MagicMock()
            mock_res.stdout = "<Event><System><EventRecordID>60</EventRecordID></System></Event>" + (" " * (10 * 1024 * 1024 + 10))
            mock_run.return_value = mock_res

            collector.collect_once()

            # Checkpoint must NOT advance past record 60 when quarantine failed!
            self.assertEqual(collector.current_checkpoint, 50)

        # Fault injection 1: open() raises OSError
        with patch("builtins.open", side_effect=OSError("Disk write error")):
            res = collector.quarantine_malformed_record("<BrokenXML>", reason="test open error", record_id=55)
            self.assertEqual(res, "")

        # Fault injection 2: os.fsync() raises OSError
        with patch("os.fsync", side_effect=OSError("Sync failed")):
            res = collector.quarantine_malformed_record("<BrokenXML>", reason="test fsync error", record_id=56)
            self.assertEqual(res, "")

        # Fault injection 3: os.replace() raises OSError
        with patch("os.replace", side_effect=OSError("Atomic replacement failed")):
            res = collector.quarantine_malformed_record("<BrokenXML>", reason="test replace error", record_id=57)
            self.assertEqual(res, "")

        # Fault injection 4: available disk space below watermark
        mock_usage = MagicMock()
        mock_usage.free = 10 * 1024 * 1024  # 10 MB free (< 500 MB watermark)
        with patch("shutil.disk_usage", return_value=mock_usage):
            res = collector.quarantine_malformed_record("<BrokenXML>", reason="test low disk", record_id=58)
            self.assertEqual(res, "")
            res_over = collector.quarantine_oversized_record("<BrokenXML>", record_id=58)
            self.assertEqual(res_over, "")

    # 12. Oversized and malformed event recovery
    def test_12_oversized_and_malformed_event_recovery(self):
        collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
        collector.initialize()

        malformed_xml = "<Event><System><EventID>4625</EventID></System><Broken"
        q_path1 = collector.quarantine_malformed_record(malformed_xml, reason="XML parse error", record_id=999)
        self.assertTrue(os.path.isfile(q_path1))
        self.assertIn("malformed_999_", os.path.basename(q_path1))

        # Idempotent re-quarantine does not create an unbounded duplicate file
        q_path2 = collector.quarantine_malformed_record(malformed_xml, reason="XML parse error", record_id=999)
        self.assertEqual(q_path1, q_path2)

        # Replay across simulated date/time boundary retains exact same filename
        with patch("collectors.windows_event_collector.datetime") as mock_dt:
            mock_dt.now.return_value.isoformat.return_value = "2027-01-01T00:00:00+00:00"
            q_path3 = collector.quarantine_malformed_record(malformed_xml, reason="XML parse error", record_id=999)
            self.assertEqual(q_path1, q_path3)

        # Distinct malformed records accumulate separate files
        distinct_malformed_xml = "<Event><System><EventID>4688</EventID></System><DifferentBroken"
        q_path_distinct = collector.quarantine_malformed_record(distinct_malformed_xml, reason="XML parse error", record_id=1000)
        self.assertNotEqual(q_path1, q_path_distinct)
        self.assertTrue(os.path.isfile(q_path1))
        self.assertTrue(os.path.isfile(q_path_distinct))

        oversized_xml = "<Event><System><EventRecordID>888</EventRecordID></System></Event>"
        oq_path1 = collector.quarantine_oversized_record(oversized_xml, record_id=888)
        self.assertTrue(os.path.isfile(oq_path1))
        self.assertIn("oversized_888_", os.path.basename(oq_path1))

    # 13. Heartbeat capability consistency & health status
    def test_13_heartbeat_capability_consistency(self):
        pipeline = WindowsDetectionPipeline(self.logger)
        pipeline.initialize()

        caps = pipeline.get_effective_capabilities()
        self.assertIn("EventLog_4625", caps)
        self.assertIn("EventLog_4688", caps)
        self.assertIn("BLOCK_SOURCE", caps)

        # Health provider returns all channels
        health_summaries = pipeline.get_channel_health_summaries()
        channel_names = [h["channel"] for h in health_summaries]
        self.assertIn("Security", channel_names)

        sec_health = next(h for h in health_summaries if h["channel"] == "Security")
        self.assertIn("status", sec_health)
        self.assertIn("current_checkpoint", sec_health)
        self.assertIn("current_epoch", sec_health)
        self.assertIn("consecutive_failures", sec_health)
        self.assertIn("backpressure_active", sec_health)

        # GET_HEALTH command
        worker = pipeline.heartbeat_worker
        result_container = []
        with patch.object(worker, "_handle_command", wraps=worker._handle_command):
            cmd = {"command_id": "cmd-1", "command_type": "GET_HEALTH"}
            worker._handle_command(cmd)

        pipeline.shutdown()

    # 14. Existing detector revision and payload identity compatibility
    def test_14_existing_detector_revision_and_payload_identity_compatibility(self):
        # Settings with whitespace fallback defaults to 1.1.0
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "   "}):
            cfg = Settings()
            self.assertEqual(cfg.detector_version, "1.1.0")

        # Pipeline engine uses production detector version 1.1.0
        pipeline = WindowsDetectionPipeline(self.logger)
        self.assertEqual(pipeline.engine.detector_version, "1.1.0")
        pipeline.shutdown()

        # Canonical source event ID is deterministic across independent runs
        s_id1 = generate_source_event_id_v2(
            agent_id="AGT-WIN-01",
            channel="Security",
            epoch=1,
            hostname="WORKSTATION-01",
            record_id=1000
        )
        s_id2 = generate_source_event_id_v2(
            agent_id="AGT-WIN-01",
            channel="Security",
            epoch=1,
            hostname="WORKSTATION-01",
            record_id=1000
        )
        self.assertEqual(s_id1, s_id2)
        self.assertEqual(len(s_id1), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in s_id1))

    # 15. Scoped IPv6 backend entity isolation
    def test_15_scoped_ipv6_backend_entity_isolation(self):
        backend_dir = os.path.abspath("SOC/backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        import sqlite3
        from app.fusion import EvidenceFusionEngine
        import app.database

        test_db_fd, test_db_path = tempfile.mkstemp(suffix=".db")
        os.close(test_db_fd)
        orig_db_path = getattr(app.database, "DB_PATH", None)
        app.database.DB_PATH = test_db_path
        app.database.init_db()

        try:
            conn = sqlite3.connect(test_db_path)
            conn.row_factory = sqlite3.Row

            # Endpoint 1 reports scoped IPv6
            ev1_data = {
                "detection_event_id": "EV-01",
                "timestamp": "2026-11-24T12:00:00Z",
                "agent_id": "AGT-WIN-01",
                "hostname": "HOST-01",
                "os": "Windows",
                "source_event_id": "src-EV-01",
                "detection_type": "test_rule",
                "detector_name": "BruteForceRule",
                "severity": "HIGH",
                "confidence": 0.9,
                "evidence": {"source_ip": "fe80::1%12"}
            }
            # Endpoint 2 reports the identical scoped IPv6 address
            ev2_data = {
                "detection_event_id": "EV-02",
                "timestamp": "2026-11-24T12:00:30Z",
                "agent_id": "AGT-WIN-02",
                "hostname": "HOST-02",
                "os": "Windows",
                "source_event_id": "src-EV-02",
                "detection_type": "test_rule",
                "detector_name": "BruteForceRule",
                "severity": "HIGH",
                "confidence": 0.9,
                "evidence": {"source_ip": "fe80::1%12"}
            }

            conn.execute("INSERT INTO events (detection_event_id, data, quarantine_status) VALUES (?, ?, ?)",
                         ("EV-01", json.dumps(ev1_data), "ACTIVE_VERIFIED"))
            conn.execute("INSERT INTO events (detection_event_id, data, quarantine_status) VALUES (?, ?, ?)",
                         ("EV-02", json.dumps(ev2_data), "ACTIVE_VERIFIED"))
            conn.commit()

            engine = EvidenceFusionEngine(conn)
            engine.process_event("EV-01")
            engine.process_event("EV-02")
            conn.commit()

            # Different endpoints with identical scoped IPv6 must remain in distinct incidents
            cursor = conn.execute("SELECT incident_id FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 2)
            conn.close()
        finally:
            if orig_db_path:
                app.database.DB_PATH = orig_db_path
            try:
                os.unlink(test_db_path)
            except OSError:
                pass

    # 16. Heartbeat delivery to backend and GET_HEALTH verification
    def test_16_heartbeat_delivery_backend_compatibility(self):
        backend_dir = os.path.abspath("SOC/backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        import sqlite3
        import app.database as backend_db
        from app.main import app
        from starlette.testclient import TestClient

        test_db_fd, test_db_path = tempfile.mkstemp(suffix=".db")
        os.close(test_db_fd)
        orig_db_path = getattr(backend_db, "DB_PATH", None)
        backend_db.DB_PATH = test_db_path
        backend_db.init_db()

        try:
            client = TestClient(app)

            pipeline = WindowsDetectionPipeline(self.logger)
            pipeline.initialize()
            health_summaries = pipeline.get_channel_health_summaries()

            # Send heartbeat with channel metrics to Central SOC
            hb_payload = {
                "agent_id": "AGT-WIN-01",
                "hostname": "WORKSTATION-01",
                "os": "Windows",
                "ip_address": "192.168.1.100",
                "agent_version": "1.1.0",
                "capabilities": ["EventLog_4625", "EventLog_4688", "BLOCK_SOURCE"],
                "channels": health_summaries,
            }
            resp = client.post(
                "/api/v1/endpoints/heartbeat",
                json=hb_payload,
                headers={"Authorization": "Bearer dev-token-123"}
            )
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertTrue(body.get("acknowledged"))
            self.assertEqual(body.get("agent_id"), "AGT-WIN-01")

            # GET_HEALTH command result doesn't leak secrets
            worker = pipeline.heartbeat_worker
            cmd = {"command_id": "cmd-health-1", "command_type": "GET_HEALTH"}
            with patch.object(worker, "_report_command_result") as mock_report:
                worker._handle_command(cmd)
                mock_report.assert_called_once()
                _, status_arg, result_arg = mock_report.call_args[0]
                self.assertEqual(status_arg, "EXECUTED")
                self.assertIn("channels", result_arg)
                # Ensure no credentials leaked
                result_str = json.dumps(result_arg)
                self.assertNotIn("dev-token", result_str)
                self.assertNotIn("password", result_str.lower())

            pipeline.shutdown()
        finally:
            if orig_db_path:
                backend_db.DB_PATH = orig_db_path
            try:
                os.unlink(test_db_path)
            except OSError:
                pass

    # 17. Stale detector version and numerical risk assessment
    def test_17_stale_detector_version_and_numerical_risk_assessment(self):
        # Explicit stale detector version 1.0.0 is respected
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.0.0"}):
            cfg_stale = Settings()
            self.assertEqual(cfg_stale.detector_version, "1.0.0")
            engine_stale = DetectionEngine(self.logger, detector_version=cfg_stale.detector_version)
            self.assertEqual(engine_stale.detector_version, "1.0.0")

        # Numerical risk assessment
        backend_dir = os.path.abspath("SOC/backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        import sqlite3
        import app.database
        from app.assessment import AssessmentEngine

        test_db_fd, test_db_path = tempfile.mkstemp(suffix=".db")
        os.close(test_db_fd)
        orig_db_path = getattr(app.database, "DB_PATH", None)
        app.database.DB_PATH = test_db_path
        app.database.init_db()

        try:
            conn = sqlite3.connect(test_db_path)
            conn.row_factory = sqlite3.Row
            now = "2026-11-24T12:00:00Z"
            conn.execute(
                "INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("INC-TEST-01", now, now, now, now, "HIGH", "OPEN")
            )
            data_ev = {
                "detection_event_id": "ev_risk",
                "timestamp": now,
                "hostname": "h1",
                "severity": "HIGH",
                "confidence": 0.85,
                "agent_id": "a1",
                "detection_type": "type1"
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("ev_risk", json.dumps(data_ev)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("INC-TEST-01", "ev_risk"))
            conn.commit()

            assessment_engine = AssessmentEngine()
            status = assessment_engine.process_incident(conn, "INC-TEST-01")
            conn.commit()
            self.assertEqual(status, "COMPLETED")

            cursor = conn.execute("SELECT trust_score, risk_score, status FROM assessments WHERE incident_id = ?", ("INC-TEST-01",))
            a_row = cursor.fetchone()
            self.assertIsNotNone(a_row)
            self.assertEqual(a_row["status"], "COMPLETED")
            self.assertIsNotNone(a_row["risk_score"])
            self.assertTrue(0.0 <= a_row["risk_score"] <= 1.0)
            self.assertIsNotNone(a_row["trust_score"])
            self.assertTrue(0.0 <= a_row["trust_score"] <= 1.0)
            conn.close()
        finally:
            if orig_db_path:
                app.database.DB_PATH = orig_db_path
            try:
                os.unlink(test_db_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
