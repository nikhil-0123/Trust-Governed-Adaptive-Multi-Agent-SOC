import unittest
import sqlite3
import json
import time
from datetime import datetime, timezone
import threading
import tempfile
import os

from app.governance_worker import GovernanceWorker
import app.database as database

class TestGovernanceWorker(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        self.db_fd, self.temp_db_path = tempfile.mkstemp()
        os.close(self.db_fd)
        database.DB_PATH = self.temp_db_path
        database.init_db()
        
        self.worker = GovernanceWorker()
        # Ensure we use an empty dict to fallback to the code defaults so tests aren't reliant on absolute disk path
        self.worker.config = {
            "environment": "TEST",
            "policy_version": "v1",
            "config_version": "v1",
            "autonomous_action_allowlist": ["ISOLATE"],
            "auto_approve": {
                "trust_threshold": 0.8,
                "risk_threshold": 0.3,
                "max_severity": "MEDIUM"
            }
        }
        self.worker.is_valid = True
        self.worker.engine.config = self.worker.config
        self.worker.engine.allowed_actions = set(["ISOLATE"])
        
    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def _setup_scenario(self, incident_id="inc1", assessment_id="ass1", analysis_id="ana1", assessment_status="COMPLETED", analysis_status="COMPLETED", max_severity="LOW"):
        with sqlite3.connect(self.temp_db_path) as conn:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status, latest_assessment_id, latest_analysis_id) VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)",
                        (incident_id, now_iso, now_iso, now_iso, now_iso, max_severity, assessment_id, analysis_id))
            
            # Insert assessment
            conn.execute("""
                INSERT INTO assessments (assessment_id, incident_id, trust_score, risk_score, status, formula_version, config_version, input_snapshot, created_at)
                VALUES (?, ?, 0.9, 0.1, ?, '1', '1', '{}', ?)
            """, (assessment_id, incident_id, assessment_status, now_iso))
            
            # Insert analysis
            analysis_output = json.dumps({
                "status": analysis_status,
                "recommendations": [{"type": "ISOLATE", "supporting_claims": ["c1"]}],
                "verification_results": [{"claim_id": "c1", "verification_status": "VERIFIED"}]
            })
            conn.execute("""
                INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at)
                VALUES (?, ?, ?, '{}', ?, 'mock', '{}', ?, ?)
            """, (analysis_id, incident_id, assessment_id, analysis_status, analysis_output, now_iso))
            conn.commit()

    def test_successful_decision(self):
        self._setup_scenario(max_severity="MEDIUM")
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status, approval_status, decision_id FROM governance_state WHERE incident_id = 'inc1'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "DECIDED")
            self.assertEqual(row["approval_status"], "NOT_REQUIRED")
            
            dec_row = conn.execute("SELECT decision, reason FROM governance_decisions WHERE decision_id = ?", (row["decision_id"],)).fetchone()
            self.assertEqual(dec_row["decision"], "AUTO_APPROVE", dec_row["reason"])

    def test_ab_race_analysis(self):
        self._setup_scenario(analysis_id="ana_a")
        
        # Inject a race where analysis pointer moves to ana_b during processing
        original_process = self.worker._process_incident
        def injected_process(conn, incident_id, assessment_id, analysis_id):
            if analysis_id == "ana_a":
                # Inject Analysis B with a new assessment
                with sqlite3.connect(self.temp_db_path) as conn_b:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn_b.execute("""
                        INSERT INTO assessments (assessment_id, incident_id, trust_score, risk_score, status, formula_version, config_version, input_snapshot, created_at)
                        VALUES (?, ?, 0.9, 0.1, 'COMPLETED', '1', '1', '{}', ?)
                    """, ("ass2", "inc1", now_iso))
                    conn_b.execute("""
                        INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at)
                        VALUES (?, ?, ?, '{}', 'COMPLETED', 'mock', '{}', '{}', ?)
                    """, ("ana_b", "inc1", "ass2", now_iso))
                    conn_b.execute("UPDATE incidents SET latest_analysis_id = 'ana_b', latest_assessment_id = 'ass2' WHERE incident_id = 'inc1'")
                    conn_b.commit()
            original_process(conn, incident_id, assessment_id, analysis_id)
            
        self.worker._process_incident = injected_process
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Because pointer changed, governance_state should NOT be DECIDED pointing to ana_a.
            row = conn.execute("SELECT * FROM governance_state WHERE incident_id = 'inc1'").fetchone()
            self.assertNotEqual(row["status"], "DECIDED") 
            
            # But the historical decision for ana_a should exist
            count = conn.execute("SELECT count(*) FROM governance_decisions WHERE analysis_id = 'ana_a'").fetchone()[0]
            self.assertEqual(count, 1)

    def test_concurrency_race(self):
        self._setup_scenario(incident_id="inc_race")
        process_count = 0
        original_process = self.worker._process_incident
        def slow_process(*args, **kwargs):
            nonlocal process_count
            process_count += 1
            time.sleep(0.5)
            original_process(*args, **kwargs)
            
        self.worker._process_incident = slow_process
        w2 = GovernanceWorker()
        w2._process_incident = slow_process
        
        t1 = threading.Thread(target=self.worker.run_once)
        t2 = threading.Thread(target=w2.run_once)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertEqual(process_count, 1)

    def test_upstream_failed_ignored(self):
        self._setup_scenario(analysis_status="FAILED")
        self.worker.run_once()
        
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status FROM governance_state WHERE incident_id = 'inc1'").fetchone()
            self.assertEqual(row["status"], "FAILED") # The claim happens, evaluation errors, marks failed

    def test_invalid_config_fails_closed(self):
        # 1. Missing key
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump({}, f)
            temp_path = f.name
            
        try:
            worker = GovernanceWorker(config_path=temp_path)
            self.assertFalse(worker.is_valid)
            self.assertIsNone(worker.engine)
        finally:
            os.remove(temp_path)
            
        # 2. Out of range value
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            cfg = {
                "policy_version": "v1", "config_version": "v1", "environment": "TEST",
                "trust_policy": {"auto_approve_min_trust": 1.5},
                "risk_policy": {}, "confidence_threshold": {}, "severity_policy": {"a":"b"},
                "verification_policy": {}, "autonomous_action_allowlist": [],
                "mitre_restrictions": {}, "approval_timeout_seconds": 1, "worker_settings": {}
            }
            json.dump(cfg, f)
            temp_path = f.name
            
        try:
            worker = GovernanceWorker(config_path=temp_path)
            self.assertFalse(worker.is_valid)
        finally:
            os.remove(temp_path)
            
        # 3. Malformed severity policy
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            cfg["trust_policy"] = {"auto_approve_min_trust": 0.5}
            cfg["severity_policy"] = "not_a_dict"
            json.dump(cfg, f)
            temp_path = f.name
            
        try:
            worker = GovernanceWorker(config_path=temp_path)
            self.assertFalse(worker.is_valid)
        finally:
            os.remove(temp_path)

        # 4. Valid config parses
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            cfg["severity_policy"] = {"LOW": "AUTO_APPROVE"}
            json.dump(cfg, f)
            temp_path = f.name
            
        try:
            worker = GovernanceWorker(config_path=temp_path)
            self.assertTrue(worker.is_valid)
        finally:
            os.remove(temp_path)
