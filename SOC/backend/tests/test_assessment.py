import unittest
import sqlite3
import tempfile
import os
import json
import time
import uuid
from unittest.mock import patch
import app.database as database
from app.assessment import AssessmentEngine, AssessmentConfigError
from app.assessment_worker import AssessmentWorker

class TestAssessmentEngineDB(unittest.TestCase):
    def setUp(self):
        self.fd, self.db_path = tempfile.mkstemp(suffix=".db")
        database.DB_PATH = self.db_path
        database.init_db()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.engine = AssessmentEngine()
        
    def tearDown(self):
        self.conn.close()
        os.close(self.fd)
        os.unlink(self.db_path)

    def _setup_incident(self, incident_id, max_severity="HIGH"):
        now = "2026-10-04T12:00:00Z"
        self.conn.execute("""
            INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (incident_id, now, now, now, now, max_severity, "OPEN"))
        self.conn.commit()

    def _add_event(self, incident_id, event_id, severity="HIGH", confidence=0.8):
        data = {
            "detection_event_id": event_id,
            "timestamp": "2026-10-04T12:00:00Z",
            "hostname": "h1",
            "severity": severity,
            "confidence": confidence,
            "agent_id": "a1",
            "detection_type": "type1"
        }
        self.conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", (event_id, json.dumps(data)))
        self.conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (incident_id, event_id))
        self.conn.commit()

    def _add_mitre(self, incident_id, technique_id, technique_name="T"):
        context_id = str(uuid.uuid4()) if hasattr(self, 'uuid_import') else f"ctx_{technique_id}"
        self.conn.execute("""
            INSERT INTO threat_context (context_id, incident_id, technique_id, technique_name, tactic, mitre_version, mapping_method)
            VALUES (?, ?, ?, ?, 'tactic', 'v1', 'method')
        """, (context_id, incident_id, technique_id, technique_name))
        self.conn.commit()
        
    def test_trust_e_only_calculation(self):
        import uuid
        inc_id = "inc_trust_1"
        self._setup_incident(inc_id)
        self._add_event(inc_id, "ev_1", confidence=0.9)
        self._add_event(inc_id, "ev_2", confidence=0.7)
        # Event count = 2. E_vol = min(1.0, 1 - exp(-0.1 * 2)) = 1 - exp(-0.2) = 0.181269
        # E_conf = (0.9+0.7)/2 = 0.8
        # E = 0.5*0.181269 + 0.5*0.8 = 0.0906 + 0.400 = 0.4906
        
        status = self.engine.process_incident(self.conn, inc_id)
        self.assertEqual(status, "COMPLETED")
        
        row = self.conn.execute("SELECT * FROM assessments WHERE incident_id = ?", (inc_id,)).fetchone()
        self.assertAlmostEqual(row["trust_score"], 0.4906, places=3)
        
        expl = json.loads(row["trust_explanation"])
        self.assertEqual(expl["excluded_factors"], ["V", "R", "H"])
        self.assertEqual(expl["available_factors"], ["E"])

    def test_risk_s_only(self):
        # MITRE missing
        inc_id = "inc_risk_1"
        self._setup_incident(inc_id, "CRITICAL")
        self._add_event(inc_id, "ev_3")
        
        status = self.engine.process_incident(self.conn, inc_id)
        row = self.conn.execute("SELECT * FROM assessments WHERE incident_id = ?", (inc_id,)).fetchone()
        
        self.assertEqual(row["risk_score"], 1.0) # S only
        expl = json.loads(row["risk_explanation"])
        self.assertEqual(expl["normalized_C"], None)
        self.assertIn("C", expl["excluded_factors"])

    def test_risk_s_and_c_multiple_distinct(self):
        inc_id = "inc_risk_2"
        self._setup_incident(inc_id, "MEDIUM") # S = 0.5
        self._add_event(inc_id, "ev_4")
        
        import uuid
        self.uuid_import = True
        self._add_mitre(inc_id, "T1110")
        self._add_mitre(inc_id, "T1071")
        self._add_mitre(inc_id, "T1059")
        # 3 distinct tech. C = min(1.0, 3 * 0.3) = 0.9
        # Risk = (0.5 * 1.0 + 0.9 * 1.0) / 2.0 = 0.7
        
        self.engine.process_incident(self.conn, inc_id)
        row = self.conn.execute("SELECT * FROM assessments WHERE incident_id = ?", (inc_id,)).fetchone()
        self.assertAlmostEqual(row["risk_score"], 0.7)
        expl = json.loads(row["risk_explanation"])
        self.assertAlmostEqual(expl["normalized_C"], 0.9)

    def test_append_only_persistence_and_latest(self):
        inc_id = "inc_persist"
        self._setup_incident(inc_id, "HIGH")
        self._add_event(inc_id, "ev_p1")
        
        # 1st run
        self.engine.process_incident(self.conn, inc_id)
        rows_1 = self.conn.execute("SELECT * FROM assessments WHERE incident_id = ?", (inc_id,)).fetchall()
        self.assertEqual(len(rows_1), 1)
        first_id = rows_1[0]["assessment_id"]
        
        inc = self.conn.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()
        self.assertEqual(inc["latest_assessment_id"], first_id)
        
        # 2nd run
        self._add_event(inc_id, "ev_p2")
        self.engine.process_incident(self.conn, inc_id)
        
        rows_2 = self.conn.execute("SELECT * FROM assessments WHERE incident_id = ? ORDER BY created_at ASC", (inc_id,)).fetchall()
        self.assertEqual(len(rows_2), 2)
        
        second_id = rows_2[1]["assessment_id"]
        inc2 = self.conn.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()
        self.assertNotEqual(inc2["latest_assessment_id"], first_id)
        self.assertEqual(inc2["latest_assessment_id"], second_id)
        
        # Verify calculation_parameters
        snap = json.loads(rows_2[1]["input_snapshot"])
        self.assertIn("calculation_parameters", snap)
        self.assertIn("evidence_volume_k_factor", snap["calculation_parameters"])
        
        # Verify failure does not update latest_assessment_id
        with patch('app.assessment.datetime') as mock_dt:
            mock_dt.now.side_effect = Exception("Simulated Failure")
            try:
                self.engine.process_incident(self.conn, inc_id)
            except Exception:
                pass
                
        inc_fail = self.conn.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()
        self.assertEqual(inc_fail["latest_assessment_id"], second_id)
        
    def test_malformed_config(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('{"bad": "json"}')
            temp_path = f.name
            
        try:
            with self.assertRaises(AssessmentConfigError):
                AssessmentEngine(temp_path)
        finally:
            os.unlink(temp_path)

class TestAssessmentWorkerIntegration(unittest.TestCase):
    def setUp(self):
        self.fd, self.db_path = tempfile.mkstemp(suffix=".db")
        database.DB_PATH = self.db_path
        database.init_db()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
    def tearDown(self):
        self.conn.close()
        os.close(self.fd)
        os.unlink(self.db_path)

    def test_worker_claim_and_process(self):
        # Create incident
        now = "2026-10-04T12:00:00Z"
        self.conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES ('w1', ?, ?, ?, ?, 'HIGH', 'OPEN')", (now, now, now, now))
        self.conn.execute("INSERT INTO assessment_state (incident_id, status, attempts, updated_at) VALUES ('w1', 'PENDING', 0, ?)", (now,))
        self.conn.commit()
        
        worker = AssessmentWorker()
        worker.process_batch()
        
        row = self.conn.execute("SELECT * FROM assessment_state WHERE incident_id = 'w1'").fetchone()
        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(row["attempts"], 1)
        
        ass_row = self.conn.execute("SELECT * FROM assessments WHERE incident_id = 'w1'").fetchone()
        self.assertIsNotNone(ass_row)

    def test_worker_stale_recovery(self):
        stale_time = "2020-01-01T12:00:00Z"
        self.conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES ('w2', ?, ?, ?, ?, 'HIGH', 'OPEN')", (stale_time, stale_time, stale_time, stale_time))
        self.conn.execute("INSERT INTO assessment_state (incident_id, status, attempts, updated_at) VALUES ('w2', 'PROCESSING', 0, ?)", (stale_time,))
        self.conn.commit()
        
        worker = AssessmentWorker()
        worker.process_batch()
        
        row = self.conn.execute("SELECT * FROM assessment_state WHERE incident_id = 'w2'").fetchone()
        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(row["attempts"], 1)

if __name__ == '__main__':
    unittest.main()
