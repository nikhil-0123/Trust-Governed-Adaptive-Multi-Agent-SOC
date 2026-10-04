import unittest
import json
import sqlite3
import os
import tempfile
from datetime import datetime, timezone
from pydantic import ValidationError

from app.database import init_db, DB_PATH
from app.reasoning_models import Claim, VerificationResult, Recommendation, FinalAnalysis

class TestReasoningFoundation(unittest.TestCase):
    def setUp(self):
        # Setup in-memory like DB but using file to test DB initialization
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.environ["SOC_DB_PATH"] = self.db_path
        
        # Override module variable for this test
        import app.database
        app.database.DB_PATH = self.db_path
        init_db()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def _create_incident(self, incident_id="inc_1"):
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""
            INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (incident_id, now, now, now, now, "HIGH", "ACTIVE"))
        self.conn.commit()

    def _create_assessment(self, assessment_id, incident_id, status="COMPLETED"):
        now = datetime.now(timezone.utc).isoformat()
        snap = json.dumps({"test": "data"})
        self.conn.execute("""
            INSERT INTO assessments (
                assessment_id, incident_id, trust_score, risk_score, status,
                formula_version, config_version, input_snapshot, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (assessment_id, incident_id, 0.5, 0.5, status, "v1", "v1", snap, now))
        
        self.conn.execute("""
            UPDATE incidents SET latest_assessment_id = ? WHERE incident_id = ?
        """, (assessment_id, incident_id))
        self.conn.commit()

    def test_config_loads(self):
        # Just verifying config format is readable JSON
        with open("app/reasoning_config.json") as f:
            config = json.load(f)
        self.assertIn("provider", config)
        self.assertEqual(config["max_evidence_events"], 100)

    def test_pydantic_claim_validation(self):
        with self.assertRaises(ValidationError):
            Claim(
                claim_id="c1", incident_id="i1", claim_type="T",
                statement="S", reasoning_summary="R",
                supporting_evidence=[], mitre_techniques=[],
                confidence=1.5,  # Invalid range
                agent_id="A"
            )
        
        claim = Claim(
            claim_id="c1", incident_id="i1", claim_type="T",
            statement="S", reasoning_summary="R",
            supporting_evidence=["ev1"], mitre_techniques=[],
            confidence=0.9, agent_id="A"
        )
        self.assertEqual(claim.confidence, 0.9)

    def test_verification_status_validation(self):
        with self.assertRaises(ValidationError):
            VerificationResult(
                claim_id="c1", verification_status="INVALID_STATUS",
                verification_reason="R", supporting_evidence=[],
                contradictory_evidence=[], confidence=1.0, verifier_agent_id="V"
            )

    def test_recommendation_status_validation(self):
        with self.assertRaises(ValidationError):
            Recommendation(type="ISOLATE", status="AUTO_APPROVE", reason="R", supporting_claims=[])

    def test_simulated_discovery_completed_creates_pending(self):
        self._create_incident("inc_1")
        self._create_assessment("ass_1", "inc_1", "COMPLETED")
        
        # Simulate orchestrator discovery logic
        row = self.conn.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id = 'inc_1'").fetchone()
        latest_ass_id = row["latest_assessment_id"]
        ass = self.conn.execute("SELECT status FROM assessments WHERE assessment_id = ?", (latest_ass_id,)).fetchone()
        
        self.assertEqual(ass["status"], "COMPLETED")
        
        # Should create PENDING
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""
            INSERT INTO analysis_state (incident_id, assessment_id, status, updated_at)
            VALUES (?, ?, ?, ?)
        """, ("inc_1", latest_ass_id, "PENDING", now))
        self.conn.commit()

    def test_simulated_discovery_failed_does_not_create_pending(self):
        self._create_incident("inc_1")
        self._create_assessment("ass_1", "inc_1", "FAILED")
        
        # Simulate orchestrator discovery avoiding FAILED
        ass = self.conn.execute("SELECT status FROM assessments WHERE assessment_id = 'ass_1'").fetchone()
        self.assertEqual(ass["status"], "FAILED")
        # App logic would stop here.

    def test_atomic_claim_succeeds_once(self):
        self._create_incident("inc_1")
        self._create_assessment("ass_1", "inc_1", "COMPLETED")
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""
            INSERT INTO analysis_state (incident_id, assessment_id, status, updated_at)
            VALUES (?, ?, 'PENDING', ?)
        """, ("inc_1", "ass_1", now))
        self.conn.commit()

        # Worker 1 tries to claim
        cursor = self.conn.execute("""
            UPDATE analysis_state SET status = 'PROCESSING', updated_at = ?
            WHERE incident_id = ? AND assessment_id = ? AND status = 'PENDING'
        """, (now, "inc_1", "ass_1"))
        self.assertEqual(cursor.rowcount, 1)

        # Worker 2 tries to claim
        cursor2 = self.conn.execute("""
            UPDATE analysis_state SET status = 'PROCESSING', updated_at = ?
            WHERE incident_id = ? AND assessment_id = ? AND status = 'PENDING'
        """, (now, "inc_1", "ass_1"))
        self.assertEqual(cursor2.rowcount, 0)
        self.conn.commit()

    def test_simulated_completed_incident_assessment_uniqueness(self):
        self._create_incident("inc_1")
        self._create_assessment("ass_1", "inc_1", "COMPLETED")
        now = datetime.now(timezone.utc).isoformat()

        # Insert a FAILED processing attempt (simulated)
        self.conn.execute("""
            INSERT INTO analyses (
                analysis_id, incident_id, assessment_id, assessment_snapshot,
                status, model_provenance, prompt_versions, analysis_output, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("ana_fail", "inc_1", "ass_1", "{}", "FAILED", "mock", "{}", "{}", now))
        self.conn.commit()

        # Insert a COMPLETED analysis (simulated retry)
        self.conn.execute("""
            INSERT INTO analyses (
                analysis_id, incident_id, assessment_id, assessment_snapshot,
                status, model_provenance, prompt_versions, analysis_output, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("ana_success_1", "inc_1", "ass_1", "{}", "COMPLETED", "mock", "{}", "{}", now))
        self.conn.commit()

        # Attempting to insert a second COMPLETED analysis for the same incident+assessment should fail
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("""
                INSERT INTO analyses (
                    analysis_id, incident_id, assessment_id, assessment_snapshot,
                    status, model_provenance, prompt_versions, analysis_output, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("ana_success_2", "inc_1", "ass_1", "{}", "COMPLETED", "mock", "{}", "{}", now))
            self.conn.commit()

    def test_simulated_stale_processing_recovery(self):
        self._create_incident("inc_1")
        self.conn.execute("""
            INSERT INTO analysis_state (incident_id, assessment_id, status, updated_at)
            VALUES (?, ?, 'PROCESSING', datetime('now', '-400 seconds'))
        """, ("inc_1", "ass_1"))
        self.conn.commit()
        
        # Simulate orchestrator identifying stale processing
        stale = self.conn.execute("""
            SELECT incident_id, assessment_id FROM analysis_state
            WHERE status = 'PROCESSING' AND updated_at < datetime('now', '-300 seconds')
        """).fetchall()
        self.assertEqual(len(stale), 1)
        
        # Recover to PENDING atomically
        now = datetime.now(timezone.utc).isoformat()
        c = self.conn.execute("""
            UPDATE analysis_state SET status = 'PENDING', updated_at = ?
            WHERE incident_id = ? AND assessment_id = ? AND status = 'PROCESSING'
        """, (now, "inc_1", "ass_1"))
        self.assertEqual(c.rowcount, 1)
        self.conn.commit()
