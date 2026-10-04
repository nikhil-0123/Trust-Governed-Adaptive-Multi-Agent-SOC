import unittest
import sqlite3
import json
import time
from datetime import datetime, timezone
import threading

from app.database import get_db_connection
from app.reasoning_worker import ReasoningWorker
from app.reasoning_provider import LLMProviderTimeoutError

class TestReasoningWorker(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        
        # Setup schema
        with open("app/database.py", "r") as f:
            code = f.read()
            import ast
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "execute":
                    pass # We need to run init_db logic. Better to mock the DB path.

        # Let's override DB_PATH
        import app.database as database
        self.original_db_path = database.DB_PATH
        database.DB_PATH = ":memory:"
        database.init_db()
        self.conn = sqlite3.connect(database.DB_PATH)
        self.conn.row_factory = sqlite3.Row
        
        # Create an instance that shares this memory connection via a mock getter
        def mock_get_db():
            return self.conn
        
        # Actually in SQLite :memory: each connection is isolated unless shared cache is used.
        # Let's use a temp file for true multi-connection testing required by the worker.
        import tempfile
        import os
        self.db_fd, self.temp_db_path = tempfile.mkstemp()
        os.close(self.db_fd)
        database.DB_PATH = self.temp_db_path
        database.init_db()
        
        self.worker = ReasoningWorker()
        
    def tearDown(self):
        import app.database as database
        database.DB_PATH = self.original_db_path
        import os
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def _setup_incident(self, incident_id="inc1", assessment_id="ass1", assessment_status="COMPLETED"):
        with sqlite3.connect(self.temp_db_path) as conn:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status, latest_assessment_id) VALUES (?, ?, ?, ?, ?, 'HIGH', 'OPEN', ?)",
                        (incident_id, now_iso, now_iso, now_iso, now_iso, assessment_id))
            
            # Insert assessment
            snapshot = json.dumps({"calculation_parameters": {}})
            conn.execute("""
                INSERT INTO assessments (assessment_id, incident_id, trust_score, risk_score, status, formula_version, config_version, input_snapshot, created_at)
                VALUES (?, ?, 0.5, 0.5, ?, '1', '1', ?, ?)
            """, (assessment_id, incident_id, assessment_status, snapshot, now_iso))
            
            # Insert evidence
            ev_id = f"ev_{incident_id}"
            ev_data = json.dumps({"severity": "HIGH", "timestamp": now_iso})
            conn.execute("INSERT INTO events (detection_event_id, data, ingested_at) VALUES (?, ?, ?)", (ev_id, ev_data, now_iso))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (incident_id, ev_id))
            
            conn.commit()

    def test_discovery_and_successful_processing(self):
        self._setup_incident()
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status FROM analysis_state WHERE incident_id = 'inc1'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "COMPLETED")
            
            inc_row = conn.execute("SELECT latest_analysis_id FROM incidents WHERE incident_id = 'inc1'").fetchone()
            self.assertIsNotNone(inc_row["latest_analysis_id"])

    def test_failed_assessment_ignored(self):
        self._setup_incident(assessment_status="FAILED")
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            row = conn.execute("SELECT * FROM analysis_state WHERE incident_id = 'inc1'").fetchone()
            self.assertIsNone(row) # Never picked up

    def test_insufficient_data_with_evidence_processed(self):
        self._setup_incident(assessment_status="INSUFFICIENT_DATA")
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status FROM analysis_state WHERE incident_id = 'inc1'").fetchone()
            self.assertEqual(row["status"], "COMPLETED")

    def test_insufficient_data_no_evidence_skipped(self):
        self._setup_incident(incident_id="inc2", assessment_id="ass2", assessment_status="INSUFFICIENT_DATA")
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.execute("DELETE FROM incident_evidence WHERE incident_id = 'inc2'")
            conn.commit()
            
        self.worker.run_once()
        with sqlite3.connect(self.temp_db_path) as conn:
            row = conn.execute("SELECT * FROM analysis_state WHERE incident_id = 'inc2'").fetchone()
            self.assertIsNone(row)

    def test_evidence_severity_ordering(self):
        self._setup_incident(incident_id="inc_sev")
        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.temp_db_path) as conn:
            evs = [
                ("ev_med", {"severity": "MEDIUM", "timestamp": "2020-01-01T00:00:00Z"}),
                ("ev_crit", {"severity": "CRITICAL", "timestamp": "2020-01-01T00:00:00Z"}),
                ("ev_low", {"severity": "LOW", "timestamp": "2020-01-01T00:00:00Z"}),
                ("ev_unk", {"severity": "UNKNOWN", "timestamp": "2020-01-01T00:00:00Z"})
            ]
            for eid, data in evs:
                conn.execute("INSERT INTO events (detection_event_id, data, ingested_at) VALUES (?, ?, ?)", (eid, json.dumps(data), now_iso))
                conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc_sev", eid))
            conn.commit()
            
        # Hook into agent to verify input
        evidence_list = []
        original_gen = self.worker.analysis_agent.generate_candidate_claims
        def mock_gen(analysis_input, conn=None):
            nonlocal evidence_list
            evidence_list = analysis_input.evidence
            return original_gen(analysis_input, conn)
        self.worker.analysis_agent.generate_candidate_claims = mock_gen
        
        self.worker.run_once()
        
        # Order should be CRITICAL, HIGH (from setup), MEDIUM, LOW, UNKNOWN
        severities = [e["severity"] for e in evidence_list]
        self.assertEqual(severities[0], "CRITICAL")
        self.assertEqual(severities[1], "HIGH")
        self.assertEqual(severities[2], "MEDIUM")
        self.assertEqual(severities[3], "LOW")

    def test_provider_failure_sets_failed(self):
        self._setup_incident(incident_id="inc_fail")
        self.worker.provider.simulate_failure = LLMProviderTimeoutError("Mock Timeout")
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status, last_error FROM analysis_state WHERE incident_id = 'inc_fail'").fetchone()
            self.assertEqual(row["status"], "FAILED")
            self.assertIn("PROVIDER_ERROR", row["last_error"])
            
            inc_row = conn.execute("SELECT latest_analysis_id FROM incidents WHERE incident_id = 'inc_fail'").fetchone()
            self.assertIsNone(inc_row["latest_analysis_id"])

    def test_concurrency_race(self):
        self._setup_incident(incident_id="inc_race")
        # To test race, we run run_once in two threads. Because SQLite UPSERT is atomic, only one should process.
        # We will mock the processing function to sleep slightly.
        original_process = self.worker._process_incident
        process_count = 0
        def slow_process(*args, **kwargs):
            nonlocal process_count
            process_count += 1
            time.sleep(0.5)
            original_process(*args, **kwargs)
        self.worker._process_incident = slow_process
        
        w2 = ReasoningWorker()
        w2._process_incident = slow_process
        
        t1 = threading.Thread(target=self.worker.run_once)
        t2 = threading.Thread(target=w2.run_once)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertEqual(process_count, 1)

    def test_assessment_b_race(self):
        self._setup_incident(incident_id="inc_race2", assessment_id="ass_a")
        # While Worker A is processing, Assessment B arrives and becomes latest.
        original_process = self.worker._process_incident
        def injected_process(conn, incident_id, assessment_id):
            if assessment_id == "ass_a":
                # Inject Assessment B
                with sqlite3.connect(self.temp_db_path) as conn_b:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn_b.execute("""
                        INSERT INTO assessments (assessment_id, incident_id, trust_score, risk_score, status, formula_version, config_version, input_snapshot, created_at)
                        VALUES (?, ?, 0.5, 0.5, 'COMPLETED', '1', '1', '{}', ?)
                    """, ("ass_b", "inc_race2", now_iso))
                    conn_b.execute("UPDATE incidents SET latest_assessment_id = 'ass_b' WHERE incident_id = 'inc_race2'")
                    conn_b.commit()
            original_process(conn, incident_id, assessment_id)
            
        self.worker._process_incident = injected_process
        self.worker.run_once() # Processes Ass A
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            inc_row = conn.execute("SELECT latest_analysis_id, latest_assessment_id FROM incidents WHERE incident_id = 'inc_race2'").fetchone()
            self.assertEqual(inc_row["latest_assessment_id"], "ass_b")
            self.assertIsNone(inc_row["latest_analysis_id"]) # Ass A completed, but didn't overwrite!
            
            analyses_count = conn.execute("SELECT count(*) FROM analyses WHERE incident_id = 'inc_race2'").fetchone()[0]
            self.assertEqual(analyses_count, 1) # Ass A was persisted
            
    def test_stale_recovery(self):
        self._setup_incident(incident_id="inc_stale")
        with sqlite3.connect(self.temp_db_path) as conn:
            now_iso = datetime.now(timezone.utc).isoformat()
            stale_iso = "2000-01-01T00:00:00Z"
            conn.execute("INSERT INTO analysis_state (incident_id, assessment_id, status, updated_at, attempts) VALUES (?, ?, 'PROCESSING', ?, 1)",
                        ("inc_stale", "ass1", stale_iso))
            conn.commit()
            
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status, attempts FROM analysis_state WHERE incident_id = 'inc_stale'").fetchone()
            self.assertEqual(row["status"], "COMPLETED")
            self.assertEqual(row["attempts"], 2)

    def test_duplicate_uniqueness_protection(self):
        self._setup_incident(incident_id="inc_uniq")
        # Suppose a stale worker tries to persist AFTER another worker already finished it.
        # Insert a completed analysis directly.
        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.execute("INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at) VALUES ('an_1', 'inc_uniq', 'ass1', '{}', 'COMPLETED', 'mock', '{}', '{}', ?)", (now_iso,))
            conn.commit()
            
        # Call _process_incident directly to simulate a slow worker finishing
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            # It will hit the integrity error on idx_analyses_completed_unique but should be gracefully swallowed
            self.worker._process_incident(conn, "inc_uniq", "ass1")
            
            # Verify only 1 analysis exists
            count = conn.execute("SELECT count(*) FROM analyses WHERE incident_id = 'inc_uniq'").fetchone()[0]
            self.assertEqual(count, 1)
