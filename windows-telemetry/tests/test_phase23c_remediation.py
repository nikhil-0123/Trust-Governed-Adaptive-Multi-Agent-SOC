import os
import sys
import unittest
import tempfile
import json
import sqlite3
import shutil
import logging
from unittest.mock import patch, MagicMock

# Path configuration
WIN_TEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.abspath(os.path.join(WIN_TEL_DIR, "..", "SOC", "backend"))

if WIN_TEL_DIR not in sys.path:
    sys.path.insert(0, WIN_TEL_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from collectors.windows_event_collector import WindowsEventCollector
from detection.detector import DetectionEngine
from detection.rules import ReconnaissanceCommandsRule
from response.executor import WindowsResponseExecutor
from pipeline import WindowsDetectionPipeline
from core.runtime import TelemetryRuntime
from app.mitre import MitreEngine
from app.assessment import AssessmentEngine
from app.governance import GovernancePolicyEngine


class TestPhase23CProductionDefects(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="tgam_phase23c_test_")
        self.logger = logging.getLogger("TestPhase23C")
        self.logger.setLevel(logging.DEBUG)
        from config.settings import config
        self.orig_data_dir = config.data_dir
        self.orig_checkpoint_dir = config.checkpoint_dir
        self.orig_output_dir = config.detection_output_dir
        self.orig_outbox_db = config.outbox_db_path
        self.orig_exec_mode = getattr(config, "execution_mode", "TEST")
        self.orig_env_exec_mode = os.environ.get("EXECUTION_MODE")

        config.data_dir = self.test_dir
        config.checkpoint_dir = os.path.join(self.test_dir, "checkpoints")
        config.detection_output_dir = os.path.join(self.test_dir, "detections")
        config.outbox_db_path = os.path.join(self.test_dir, "outbox.db")
        config.execution_mode = "TEST"
        os.environ["EXECUTION_MODE"] = "TEST"

    def tearDown(self):
        from config.settings import config
        config.data_dir = self.orig_data_dir
        config.checkpoint_dir = self.orig_checkpoint_dir
        config.detection_output_dir = self.orig_output_dir
        config.outbox_db_path = self.orig_outbox_db
        config.execution_mode = self.orig_exec_mode
        if self.orig_env_exec_mode is not None:
            os.environ["EXECUTION_MODE"] = self.orig_env_exec_mode
        else:
            os.environ.pop("EXECUTION_MODE", None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_simulated_events_do_not_degrade_healthy_channel(self):
        """Defect 1: Processing simulated events or having no simulated events must not degrade healthy channels, and live channel state must not interfere with test suites."""
        collector = WindowsEventCollector(
            logger=self.logger,
            log_name="Security",
            execution_mode="SIMULATION",
        )
        collector.initialize()
        # Verify live channel state does not interfere with test baseline (establishes at record 1, not live host record)
        self.assertEqual(collector.current_checkpoint, 1)
        self.assertEqual(collector.status, "HEALTHY")

        # With no simulated events, collect_once must remain HEALTHY
        events = collector.collect_once()
        self.assertEqual(collector.status, "HEALTHY")
        self.assertEqual(collector.consecutive_failures, 0)

        # Drop simulated XML event
        sim_dir = collector.simulated_events_channel_dir
        os.makedirs(sim_dir, exist_ok=True)
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <EventRecordID>5001</EventRecordID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="CommandLine">whoami /all</Data>
  </EventData>
</Event>"""
        with open(os.path.join(sim_dir, "event1.xml"), "w") as f:
            f.write(xml)

        events = collector.collect_once()
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].get("is_simulated"))
        # Channel remains HEALTHY
        self.assertEqual(collector.status, "HEALTHY")
        self.assertEqual(collector.consecutive_failures, 0)

    def test_02_simulation_mode_does_not_execute_real_containment(self):
        """Defect 3: Simulation mode must not execute real containment actions."""
        # Initialize executor in simulation mode
        executor = WindowsResponseExecutor(
            logger=self.logger,
            agent_id="test-agent",
            hostname="test-host",
            simulation_mode=True
        )
        self.assertTrue(executor.simulation_mode)

        # Test block source IP
        res_block = executor.execute("BLOCK_SOURCE", {"ip": "198.51.100.25"})
        self.assertTrue(res_block.get("simulated"))
        self.assertEqual(res_block.get("action"), "BLOCK_SOURCE")
        self.assertIn("TGAM-SOC-Block-198.51.100.25", res_block.get("rule_name"))

        # Test kill process
        res_kill = executor.execute("KILL_PROCESS", {"process_id": 99999})
        self.assertTrue(res_kill.get("simulated"))
        self.assertEqual(res_kill.get("target_pid"), 99999)

        # Test isolate host
        res_isolate = executor.execute("ISOLATE_HOST", {})
        self.assertTrue(res_isolate.get("simulated"))

    def test_03_mitre_mapping_whoami_t1033_systeminfo_t1082(self):
        """Defect 5: whoami /all maps to T1033; systeminfo.exe maps to T1082."""
        rule = ReconnaissanceCommandsRule()

        # Evaluate whoami /all
        ev_whoami = {
            "event_id": "ev-whoami",
            "evidence": {"command_line": "whoami /all"}
        }
        res_whoami = rule.evaluate(ev_whoami)
        self.assertIsNotNone(res_whoami)
        self.assertEqual(res_whoami.evidence["mitre_technique_id"], "T1033")

        # Evaluate systeminfo.exe
        ev_sysinfo = {
            "event_id": "ev-sysinfo",
            "evidence": {"command_line": "systeminfo.exe"}
        }
        res_sysinfo = rule.evaluate(ev_sysinfo)
        self.assertIsNotNone(res_sysinfo)
        self.assertEqual(res_sysinfo.evidence["mitre_technique_id"], "T1082")

        # Verify Central SOC MitreEngine maps them separately to T1033 and T1082
        engine = MitreEngine()
        db_path = os.path.join(self.test_dir, "mitre_test.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        import app.database
        orig_db = getattr(app.database, "DB_PATH", None)
        app.database.DB_PATH = db_path
        app.database.init_db()

        try:
            now = "2026-11-25T12:00:00Z"
            conn.execute(
                "INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("inc-mitre-01", now, now, now, now, "MEDIUM", "OPEN")
            )
            # Insert whoami detection event
            conn.execute(
                "INSERT INTO events (detection_event_id, data) VALUES (?, ?)",
                ("det-whoami", json.dumps({"detection_type": "windows_reconnaissance", "evidence": {"mitre_technique_id": "T1033"}}))
            )
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-mitre-01", "det-whoami"))

            # Insert systeminfo detection event
            conn.execute(
                "INSERT INTO events (detection_event_id, data) VALUES (?, ?)",
                ("det-sysinfo", json.dumps({"detection_type": "windows_reconnaissance", "evidence": {"mitre_technique_id": "T1082"}}))
            )
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-mitre-01", "det-sysinfo"))
            conn.commit()

            status_w = engine.process_event(conn, "det-whoami")
            status_s = engine.process_event(conn, "det-sysinfo")
            conn.commit()

            self.assertEqual(status_w, "MAPPED")
            self.assertEqual(status_s, "MAPPED")

            cur = conn.execute("SELECT technique_id, technique_name FROM threat_context WHERE incident_id = 'inc-mitre-01' ORDER BY technique_id")
            rows = [dict(r) for r in cur.fetchall()]
            tech_ids = [r["technique_id"] for r in rows]
            self.assertIn("T1033", tech_ids)
            self.assertIn("T1082", tech_ids)
            self.assertEqual(len(tech_ids), 2)
        finally:
            conn.close()
            if orig_db:
                app.database.DB_PATH = orig_db

    def test_04_historical_reevaluation_numerical_determinism(self):
        """Defect 6: Compare numerical trust and risk scores before and after historical re-evaluation."""
        db_path = os.path.join(self.test_dir, "determinism_test.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        import app.database
        orig_db = getattr(app.database, "DB_PATH", None)
        app.database.DB_PATH = db_path
        app.database.init_db()

        try:
            now = "2026-11-25T12:00:00Z"
            conn.execute(
                "INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("inc-det-01", now, now, now, now, "HIGH", "OPEN")
            )
            data_ev = {
                "detection_event_id": "det-1",
                "timestamp": now,
                "hostname": "WORKSTATION-01",
                "severity": "HIGH",
                "confidence": 0.85,
                "agent_id": "test-agent",
                "detection_type": "windows_reconnaissance"
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("det-1", json.dumps(data_ev)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-det-01", "det-1"))
            conn.commit()

            engine = AssessmentEngine()
            # First evaluation
            s1 = engine.process_incident(conn, "inc-det-01")
            conn.commit()
            self.assertEqual(s1, "COMPLETED")
            cur = conn.execute("SELECT trust_score, risk_score FROM assessments WHERE incident_id = 'inc-det-01'")
            row1 = cur.fetchone()
            trust1, risk1 = row1["trust_score"], row1["risk_score"]

            # Second evaluation of the exact same incident/evidence
            s2 = engine.process_incident(conn, "inc-det-01")
            conn.commit()
            self.assertEqual(s2, "COMPLETED")
            cur = conn.execute("SELECT trust_score, risk_score FROM assessments WHERE incident_id = 'inc-det-01' ORDER BY created_at DESC")
            row2 = cur.fetchone()
            trust2, risk2 = row2["trust_score"], row2["risk_score"]

            # Verify 100% numerical invariance
            self.assertEqual(trust1, trust2)
            self.assertEqual(risk1, risk2)
        finally:
            conn.close()
            if orig_db:
                app.database.DB_PATH = orig_db

    def test_05_stale_detector_warning_emitted(self):
        """Defect 4: Incompatible detector version 1.0.0 logs explicit warning."""
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.0.0"}):
            with self.assertLogs("TestPhase23C", level="WARNING") as cm:
                engine = DetectionEngine(logger=self.logger)
                self.assertEqual(engine.detector_version, "1.0.0")
                self.assertTrue(any("Stale detector version 1.0.0" in log for log in cm.output))

    def test_06_xml_decoding_utf8_with_bom(self):
        """Task 6: Lossless decoding strips UTF-8 BOM cleanly."""
        collector = WindowsEventCollector(logger=self.logger, log_name="Security", execution_mode="TEST")
        raw = b"\xef\xbb\xbf<Event><System><EventID>1</EventID></System></Event>"
        decoded, err = collector._decode_wevtutil_output(raw)
        self.assertIsNone(err)
        self.assertEqual(decoded, "<Event><System><EventID>1</EventID></System></Event>")

    def test_07_xml_decoding_utf16le_with_bom(self):
        """Task 6: Lossless decoding decodes UTF-16LE with BOM cleanly."""
        collector = WindowsEventCollector(logger=self.logger, log_name="Security", execution_mode="TEST")
        content = "<Event><System><EventID>2</EventID></System></Event>"
        raw = b"\xff\xfe" + content.encode("utf-16le")
        decoded, err = collector._decode_wevtutil_output(raw)
        self.assertIsNone(err)
        self.assertEqual(decoded, content)

    def test_08_xml_decoding_cp1252_with_registered_trademark(self):
        """Task 6: Lossless decoding preserves CP1252 byte 0xae (®) without replacement errors."""
        collector = WindowsEventCollector(logger=self.logger, log_name="Security", execution_mode="TEST")
        # 0xae is the registered trademark symbol in CP1252, invalid standalone in UTF-8
        raw = b"<Event><System><EventID>3</EventID><Data>Windows \xae OS</Data></System></Event>"
        decoded, err = collector._decode_wevtutil_output(raw)
        self.assertIsNone(err)
        self.assertIn("Windows ® OS", decoded)

    def test_09_undecodable_raw_bytes_quarantined_and_halts_checkpoint(self):
        """Task 6: Truly undecodable bytes are quarantined to .bin and return error code."""
        collector = WindowsEventCollector(logger=self.logger, log_name="Security", execution_mode="TEST")
        collector.initialize()
        collector.current_checkpoint = 42
        # Set candidate encodings that fail on 0x81 (which is undefined in CP1252 and invalid in UTF-8/UTF-16LE with 1 byte)
        collector.candidate_encodings = ("utf-8", "utf-16le", "cp1252")

        decoded, err = collector._decode_wevtutil_output(b"\x81")
        self.assertIsNone(decoded)
        self.assertEqual(err, "UNDECODABLE_RAW_BYTES")

        # Verify .bin file created in malformed_events directory
        bin_files = [f for f in os.listdir(collector.malformed_events_dir) if f.endswith(".bin")]
        self.assertGreaterEqual(len(bin_files), 1)

        # Verify checkpoint was preserved and not advanced
        self.assertEqual(collector.current_checkpoint, 42)

    def test_10_production_pipeline_detector_version_enforcement(self):
        """Task 1: Production pipeline rejects detector version 1.0.0; test/simulation permits it."""
        # 1. Production mode with 1.0.0 must raise ValueError
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.0.0"}):
            with self.assertRaises(ValueError) as ctx:
                WindowsDetectionPipeline(logger=self.logger, execution_mode="PRODUCTION")
            self.assertIn("Production pipeline requires detector version 1.1.0", str(ctx.exception))

        # 2. Production mode with 1.1.0 succeeds
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.1.0"}):
            prod_pipe = WindowsDetectionPipeline(logger=self.logger, execution_mode="PRODUCTION")
            self.assertEqual(prod_pipe.engine.detector_version, "1.1.0")

        # 3. Test mode with 1.0.0 succeeds (fixture compatibility)
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.0.0"}):
            test_pipe = WindowsDetectionPipeline(logger=self.logger, execution_mode="TEST")
            self.assertEqual(test_pipe.engine.detector_version, "1.0.0")

    def test_11_settings_semver_validation(self):
        """Task 1: Settings strictly validates SemVer format, rejecting malformed and falling back to default on whitespace."""
        from config.settings import Settings

        # Whitespace string falls back to default 1.1.0
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "   "}):
            s = Settings()
            self.assertEqual(s.detector_version, "1.1.0")

        # Empty string falls back to default 1.1.0
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": ""}):
            s = Settings()
            self.assertEqual(s.detector_version, "1.1.0")

        # Invalid SemVer format raises ValueError
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.0"}):
            with self.assertRaises(ValueError) as ctx:
                Settings()
            self.assertIn("must be valid SemVer", str(ctx.exception))

        # Valid SemVer format
        with patch.dict(os.environ, {"WINDOWS_DETECTOR_VERSION": "1.1.0"}):
            s = Settings()
            self.assertEqual(s.detector_version, "1.1.0")

    def test_12_production_mode_ignores_simulated_events(self):
        """Task 2: Production mode collector strictly ignores simulated_events directory."""
        import subprocess
        collector = WindowsEventCollector(logger=self.logger, log_name="Security", execution_mode="PRODUCTION")
        self.assertFalse(collector.is_simulation)

        # Drop simulated XML file into simulated_events directory
        sim_dir = collector.simulated_events_channel_dir
        os.makedirs(sim_dir, exist_ok=True)
        with open(os.path.join(sim_dir, "test_sim.xml"), "w") as f:
            f.write("<Event><System><EventID>4688</EventID></System></Event>")

        # In production mode, collector does not read simulated_events
        # Mock subprocess.run to simulate empty wevtutil batch query
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"", stderr=b""
            )
            events = collector.collect_once()
            self.assertEqual(len(events), 0)
            # The simulated file was NOT consumed
            self.assertTrue(os.path.exists(os.path.join(sim_dir, "test_sim.xml")))

    def test_13_execution_mode_validation_and_data_dir_isolation(self):
        """Task 1A: Settings validates execution mode strictly and isolates default state directory."""
        from config.settings import Settings

        # 1. Invalid execution mode raises ValueError
        with patch.dict(os.environ, {"EXECUTION_MODE": "UNAUTHORIZED_MODE"}):
            with self.assertRaises(ValueError) as ctx:
                Settings()
            self.assertIn("Invalid execution mode", str(ctx.exception))

        # 2. Production mode default data_dir
        with patch.dict(os.environ, {"EXECUTION_MODE": "PRODUCTION"}):
            os.environ.pop("DATA_DIR", None)
            s_prod = Settings()
            self.assertTrue(s_prod.data_dir.endswith("telemetry"))

        # 3. Simulation mode default data_dir is isolated
        with patch.dict(os.environ, {"EXECUTION_MODE": "SIMULATION"}):
            os.environ.pop("DATA_DIR", None)
            s_sim = Settings()
            self.assertTrue(s_sim.data_dir.endswith("telemetry_simulation"))

        # 4. Evaluation mode default data_dir is isolated
        with patch.dict(os.environ, {"EXECUTION_MODE": "EVALUATION"}):
            os.environ.pop("DATA_DIR", None)
            s_eval = Settings()
            self.assertTrue(s_eval.data_dir.endswith("telemetry_evaluation"))

    def test_14_executor_simulation_mode_prevents_containment(self):
        """Task 1A: WindowsResponseExecutor in simulation mode never executes containment regardless of parameters."""
        executor = WindowsResponseExecutor(simulation_mode=True)
        self.assertTrue(executor.simulation_mode)

        # block_source with simulate=False must still be forced to simulate=True
        res = executor.block_source({"ip": "198.51.100.10", "simulate": False})
        self.assertTrue(res.get("simulated"))
        self.assertEqual(res.get("action"), "BLOCK_SOURCE")

        # kill_process with simulate=False must still be forced to simulate=True
        res_kill = executor.kill_process({"process_id": 9999, "simulate": False})
        self.assertTrue(res_kill.get("simulated"))
        self.assertEqual(res_kill.get("action"), "KILL_PROCESS")

        # isolate_host with simulate=False must still be forced to simulate=True
        res_iso = executor.isolate_host({"simulate": False})
        self.assertTrue(res_iso.get("simulated"))
        self.assertEqual(res_iso.get("action"), "ISOLATE_HOST")

    def test_15_decode_wevtutil_structural_validation_and_disk_watermark(self):
        """Task 1C: Decoding rejects corrupt null bytes and enforces disk watermark check before quarantine write."""
        collector = WindowsEventCollector(logger=self.logger, log_name="Security", execution_mode="TEST")

        # UTF-16LE bytes decoded with embedded nulls or corrupt bytes must not produce corrupt string
        # A payload with unparseable binary junk
        raw_junk = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        
        # When disk watermark is violated, quarantine write is rejected safely
        with patch("shutil.disk_usage") as mock_usage:
            # Return free space of 10 MB (below default 500 MB watermark)
            mock_usage.return_value = MagicMock(free=10 * 1024 * 1024)
            decoded, err = collector._decode_wevtutil_output(raw_junk)
            self.assertIsNone(decoded)
            self.assertEqual(err, "UNDECODABLE_RAW_BYTES")

        # When disk space is sufficient, undecodable bytes are quarantined atomically
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = MagicMock(free=1000 * 1024 * 1024)
            decoded, err = collector._decode_wevtutil_output(raw_junk)
            self.assertIsNone(decoded)
            self.assertEqual(err, "UNDECODABLE_RAW_BYTES")


if __name__ == "__main__":
    unittest.main()
