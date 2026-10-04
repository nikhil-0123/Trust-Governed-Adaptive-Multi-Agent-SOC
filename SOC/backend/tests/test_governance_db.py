import unittest
import sqlite3
import tempfile
import os
import json
from datetime import datetime, timezone

import app.database as database
from app.governance_worker import GovernanceWorker

class TestGovernanceDB(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        self.db_fd, self.temp_db_path = tempfile.mkstemp()
        os.close(self.db_fd)
        database.DB_PATH = self.temp_db_path
        database.init_db()
        
    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass
                
    def test_governance_decisions_immutability(self):
        with sqlite3.connect(self.temp_db_path) as conn:
            # Setup dependencies
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES ('i1', ?, ?, ?, ?, 'LOW', 'OPEN')", (now,now,now,now))
            
            # 1. INSERT succeeds
            conn.execute("""
                INSERT INTO governance_decisions (decision_id, incident_id, assessment_id, analysis_id, decision, reason, input_snapshot, policy_version, config_version, created_at)
                VALUES ('d1', 'i1', 'a1', 'an1', 'AUTO_APPROVE', 'test', '{}', '1', '1', ?)
            """, (now,))
            conn.commit()
            
            # 2. UPDATE fails
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                conn.execute("UPDATE governance_decisions SET decision = 'REJECT' WHERE decision_id = 'd1'")
            self.assertIn("append-only", str(ctx.exception))
            
            # 3. DELETE fails
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                conn.execute("DELETE FROM governance_decisions WHERE decision_id = 'd1'")
            self.assertIn("append-only", str(ctx.exception))
            
            # 4. Value remained unchanged
            row = conn.execute("SELECT decision FROM governance_decisions WHERE decision_id = 'd1'").fetchone()
            self.assertEqual(row[0], 'AUTO_APPROVE')
            
    def test_duplicate_identity_processing(self):
        with sqlite3.connect(self.temp_db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES ('i1', ?, ?, ?, ?, 'LOW', 'OPEN')", (now,now,now,now))
            
            # Insert first time
            conn.execute("""
                INSERT INTO governance_decisions (decision_id, incident_id, assessment_id, analysis_id, decision, reason, input_snapshot, policy_version, config_version, created_at)
                VALUES ('d1', 'i1', 'a1', 'an1', 'AUTO_APPROVE', 'test', '{}', '1', '1', ?)
            """, (now,))
            
            # Insert second time with SAME identity should FAIL
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("""
                    INSERT INTO governance_decisions (decision_id, incident_id, assessment_id, analysis_id, decision, reason, input_snapshot, policy_version, config_version, created_at)
                    VALUES ('d2', 'i1', 'a1', 'an1', 'HOLD', 'test', '{}', '1', '1', ?)
                """, (now,))
                
            # Insert second time with DIFFERENT identity should SUCCEED
            conn.execute("""
                INSERT INTO governance_decisions (decision_id, incident_id, assessment_id, analysis_id, decision, reason, input_snapshot, policy_version, config_version, created_at)
                VALUES ('d2', 'i1', 'a2', 'an2', 'AUTO_APPROVE', 'test', '{}', '1', '1', ?)
            """, (now,))
            conn.commit()

            # Verify graceful worker handling of duplicate
            # Setup worker config to be valid
            worker = GovernanceWorker()
            
            # Let's insert fake dependencies:
            conn.execute("INSERT INTO assessments (assessment_id, incident_id, trust_score, risk_score, status, formula_version, config_version, input_snapshot, created_at) VALUES ('a1', 'i1', 1.0, 0.0, 'COMPLETED', '1', '1', '{}', ?)", (now,))
            conn.execute("INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at) VALUES ('an1', 'i1', 'a1', '{}', 'COMPLETED', 'mock', '{}', '{\"recommendations\":[]}', ?)", (now,))
            conn.execute("UPDATE incidents SET latest_assessment_id = 'a1', latest_analysis_id = 'an1', max_severity = 'LOW' WHERE incident_id = 'i1'")
            conn.execute("INSERT INTO governance_state (incident_id, assessment_id, analysis_id, status, approval_status, attempts, updated_at) VALUES ('i1', 'a1', 'an1', 'PROCESSING', 'NOT_REQUIRED', 1, ?)", (now,))
            conn.commit()
            
            # Worker config must be valid
            worker.is_valid = True
            worker.engine.config = worker.config
            worker.engine.allowed_actions = set(worker.config.get("autonomous_action_allowlist", []))
            
            conn.row_factory = sqlite3.Row
            # _process_incident should swallow the IntegrityError when it tries to insert duplicate governance_decisions
            worker._process_incident(conn, 'i1', 'a1', 'an1')
            
            # State should be 1 duplicate record, not 2
            count = conn.execute("SELECT count(*) FROM governance_decisions WHERE incident_id = 'i1' AND assessment_id = 'a1' AND analysis_id = 'an1'").fetchone()[0]
            self.assertEqual(count, 1)

if __name__ == '__main__':
    unittest.main()
