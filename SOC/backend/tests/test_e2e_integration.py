import unittest
import os
import tempfile
import sqlite3
import json
import uuid
from datetime import datetime, timezone, timedelta

# Create isolated DB before importing app components
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.environ["SOC_DB_PATH"] = temp_db_path
os.close(temp_db_fd)

import app.database as database
from app.fusion import EvidenceFusionEngine
from app.worker import FusionWorker
from app.mitre_worker import MitreWorker
from app.assessment_worker import AssessmentWorker
from app.reasoning_worker import ReasoningWorker
from app.governance_worker import GovernanceWorker
from app.reasoning_provider import LLMProviderError

def make_bruteforce_event(index: int, timestamp_offset_seconds: int = 0) -> dict:
    base_time = datetime(2026, 10, 4, 10, 0, 0, tzinfo=timezone.utc)
    event_time = base_time + timedelta(seconds=timestamp_offset_seconds)
    return {
        "detection_event_id": f"e2e-bf-{index:03d}",
        "timestamp": event_time.isoformat(),
        "agent_id": "e2e-agent-win01",
        "hostname": "E2E-WIN-PC01",
        "os": "Windows",
        "source_event_id": f"evt-{4625}-{index}",
        "detection_type": "windows_bruteforce_rule",
        "confidence": 0.85,
        "severity": "HIGH",
        "detector_name": "brute_force_detector_v1",
        "evidence": {
            "source_ip": "192.168.10.50",
            "username": "admin",
            "event_id": 4625,
            "failed_count": 5 + index,
            "window_seconds": 300,
            "rule_name": "windows_bruteforce_rule"
        }
    }

def make_unmapped_event() -> dict:
    return {
        "detection_event_id": "e2e-unmapped-001",
        "timestamp": "2026-10-04T10:30:00+00:00",
        "agent_id": "e2e-agent-win01",
        "hostname": "E2E-WIN-PC01",
        "os": "Windows",
        "source_event_id": "evt-custom-001",
        "detection_type": "custom_anomaly_detector",
        "confidence": 0.7,
        "severity": "MEDIUM",
        "detector_name": "anomaly_detector_v1",
        "evidence": {"source_ip": "192.168.10.50", "username": "admin"}
    }

class TestE2EIntegration(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        
        self.original_db_path = database.DB_PATH
        database.DB_PATH = self.temp_db_path
        
        database.init_db()
        self.incident_id_cache = None

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def _insert_events(self, events: list[dict]):
        with database.get_db_connection() as conn:
            for ev in events:
                conn.execute(
                    "INSERT INTO events (detection_event_id, data) VALUES (?, ?)",
                    (ev["detection_event_id"], json.dumps(ev))
                )
            conn.commit()

    def test_e2e_bruteforce_complete(self):
        events = [make_bruteforce_event(i, i*10) for i in range(5)]
        self._insert_events(events)

        FusionWorker().process_batch()
        with database.get_db_connection() as conn:
            c = conn.execute("SELECT count(*) as c FROM incidents").fetchone()["c"]
            self.assertEqual(c, 1)

        MitreWorker().process_batch()
        with database.get_db_connection() as conn:
            c = conn.execute("SELECT count(*) as c FROM threat_context").fetchone()["c"]
            self.assertEqual(c, 1)

        AssessmentWorker().process_batch()
        with database.get_db_connection() as conn:
            a = conn.execute("SELECT status FROM assessments").fetchone()
            self.assertEqual(a["status"], "COMPLETED")

        reasoning_worker = ReasoningWorker()
        reasoning_worker.run_once()
        with database.get_db_connection() as conn:
            a = conn.execute("SELECT status FROM analyses").fetchone()
            self.assertEqual(a["status"], "COMPLETED")

        GovernanceWorker().run_once()
        with database.get_db_connection() as conn:
            gd = conn.execute("SELECT decision FROM governance_decisions").fetchone()
            self.assertIsNotNone(gd)
            self.assertEqual(gd["decision"], "HOLD") # Expected because mock provides no recommendations
            
            inc = conn.execute("SELECT incident_id FROM incidents").fetchone()
            self.incident_id_cache = inc["incident_id"]

        self.test_provenance_chain_complete()

    def test_provenance_chain_complete(self):
        if not self.incident_id_cache:
            return 
            
        with database.get_db_connection() as conn:
            incident_id = self.incident_id_cache
            events = conn.execute("SELECT detection_event_id FROM events").fetchall()
            self.assertGreater(len(events), 0)
            
            inc = conn.execute("SELECT latest_assessment_id, latest_analysis_id FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            assessment_id = inc["latest_assessment_id"]
            analysis_id = inc["latest_analysis_id"]
            self.assertIsNotNone(assessment_id)
            self.assertIsNotNone(analysis_id)
            
            ctx = conn.execute("SELECT context_id FROM threat_context WHERE incident_id=?", (incident_id,)).fetchone()
            self.assertIsNotNone(ctx)
            
            a_row = conn.execute("SELECT status FROM assessments WHERE assessment_id=?", (assessment_id,)).fetchone()
            self.assertEqual(a_row["status"], "COMPLETED")
            
            an_row = conn.execute("SELECT status FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
            self.assertEqual(an_row["status"], "COMPLETED")
            
            gd_row = conn.execute("SELECT decision_id FROM governance_state WHERE incident_id=?", (incident_id,)).fetchone()
            decision_id = gd_row["decision_id"]
            self.assertIsNotNone(decision_id)
            
            gd_detail = conn.execute("SELECT decision FROM governance_decisions WHERE decision_id=?", (decision_id,)).fetchone()
            self.assertIsNotNone(gd_detail)

    def test_e2e_multi_evidence_single_incident(self):
        events = [make_bruteforce_event(i, i*10) for i in range(3)]
        self._insert_events(events)
        
        FusionWorker().process_batch()
        with database.get_db_connection() as conn:
            inc_count = conn.execute("SELECT count(*) as c FROM incidents").fetchone()["c"]
            self.assertEqual(inc_count, 1)
            
            inc = conn.execute("SELECT incident_id FROM incidents").fetchone()
            ev_count = conn.execute("SELECT count(*) as c FROM incident_evidence WHERE incident_id=?", (inc["incident_id"],)).fetchone()["c"]
            self.assertEqual(ev_count, 3)

    def test_e2e_unmapped_detection_no_mitre(self):
        events = [make_unmapped_event()]
        self._insert_events(events)
        
        FusionWorker().process_batch()
        MitreWorker().process_batch()
        
        with database.get_db_connection() as conn:
            ctx_count = conn.execute("SELECT count(*) as c FROM threat_context").fetchone()["c"]
            self.assertEqual(ctx_count, 0)
            
            ast_state = conn.execute("SELECT status FROM assessment_state").fetchone()
            self.assertEqual(ast_state["status"], "PENDING")

        AssessmentWorker().process_batch()
        ReasoningWorker().run_once()
        GovernanceWorker().run_once()

        with database.get_db_connection() as conn:
            gd = conn.execute("SELECT decision FROM governance_decisions").fetchone()
            self.assertEqual(gd["decision"], "HOLD")

    def test_e2e_insufficient_data_hold(self):
        incident_id = str(uuid.uuid4())
        assessment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        with database.get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                         (incident_id, now, now, now, now, "LOW", "OPEN"))
            conn.execute("INSERT INTO assessments (assessment_id, incident_id, status, formula_version, config_version, input_snapshot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (assessment_id, incident_id, "INSUFFICIENT_DATA", "v1", "v1", "{}", now))
            conn.execute("UPDATE incidents SET latest_assessment_id=? WHERE incident_id=?", (assessment_id, incident_id))
            
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("ev-ins-1", "{}"))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (incident_id, "ev-ins-1"))
            
            conn.commit()

        ReasoningWorker().run_once()
        GovernanceWorker().run_once()
        
        with database.get_db_connection() as conn:
            gd = conn.execute("SELECT decision, reason FROM governance_decisions WHERE incident_id=?", (incident_id,)).fetchone()
            self.assertIsNotNone(gd)
            self.assertEqual(gd["decision"], "HOLD")
            self.assertIn("INSUFFICIENT_DATA", gd["reason"])

    def test_e2e_contradicted_claim_reject(self):
        # Scenario 5: Governance integration test using a persisted Step 10 FinalAnalysis fixture.
        incident_id = str(uuid.uuid4())
        assessment_id = str(uuid.uuid4())
        analysis_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        with database.get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status, latest_assessment_id, latest_analysis_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                         (incident_id, now, now, now, now, "HIGH", "OPEN", assessment_id, analysis_id))
            conn.execute("INSERT INTO assessments (assessment_id, incident_id, status, formula_version, config_version, input_snapshot, trust_score, risk_score, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (assessment_id, incident_id, "COMPLETED", "v1", "v1", "{}", 1.0, 0.5, now))
            
            fake_analysis = {
                "recommendations": [
                    {
                        "type": "ISOLATE_HOST",
                        "status": "RECOMMENDED",
                        "reason": "Test",
                        "supporting_claims": ["claim-1"]
                    }
                ],
                "verification_results": [
                    {
                        "claim_id": "claim-1",
                        "verification_status": "CONTRADICTED",
                        "verification_reason": "It's false."
                    }
                ]
            }
            conn.execute("INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (analysis_id, incident_id, assessment_id, "{}", "COMPLETED", "mock", "{}", json.dumps(fake_analysis), now))
            conn.commit()

        GovernanceWorker().run_once()
        
        with database.get_db_connection() as conn:
            gd = conn.execute("SELECT decision, reason FROM governance_decisions WHERE incident_id=?", (incident_id,)).fetchone()
            self.assertIsNotNone(gd)
            self.assertEqual(gd["decision"], "REJECT")
            self.assertIn("CONTRADICTED", gd["reason"])

    def test_e2e_ab_supersession(self):
        events = [make_bruteforce_event(0, 0)]
        self._insert_events(events)
        
        FusionWorker().process_batch()
        MitreWorker().process_batch()
        AssessmentWorker().process_batch()
        
        with database.get_db_connection() as conn:
            inc = conn.execute("SELECT incident_id, latest_assessment_id FROM incidents").fetchone()
            incident_id = inc["incident_id"]
            assessment_id_a = inc["latest_assessment_id"]
        
        # Trigger reassessment -> Assessment B
        with database.get_db_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO assessment_state (incident_id, status, attempts, updated_at) VALUES (?, 'PENDING', 0, ?)", 
                         (incident_id, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            
        AssessmentWorker().process_batch()
        
        with database.get_db_connection() as conn:
            inc = conn.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            assessment_id_b = inc["latest_assessment_id"]
            self.assertNotEqual(assessment_id_a, assessment_id_b)
            
        ReasoningWorker().run_once()
        
        with database.get_db_connection() as conn:
            inc = conn.execute("SELECT latest_analysis_id FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            analysis_id_b = inc["latest_analysis_id"]
            self.assertIsNotNone(analysis_id_b)
            
            an = conn.execute("SELECT assessment_id FROM analyses WHERE analysis_id=?", (analysis_id_b,)).fetchone()
            self.assertEqual(an["assessment_id"], assessment_id_b)
            
        GovernanceWorker().run_once()
        
        with database.get_db_connection() as conn:
            gs = conn.execute("SELECT assessment_id, analysis_id, status FROM governance_state WHERE incident_id=?", (incident_id,)).fetchone()
            self.assertEqual(gs["assessment_id"], assessment_id_b)
            self.assertEqual(gs["analysis_id"], analysis_id_b)
            self.assertEqual(gs["status"], "DECIDED")
            
            # Assessment A should have no governance decision
            gd_a = conn.execute("SELECT count(*) as c FROM governance_decisions WHERE incident_id=? AND assessment_id=?", (incident_id, assessment_id_a)).fetchone()
            self.assertEqual(gd_a["c"], 0)

    def test_failure_mitre_incident_survives(self):
        events = [make_bruteforce_event(0, 0)]
        self._insert_events(events)
        FusionWorker().process_batch()
        
        mw = MitreWorker()
        mw.engine = None # sabotage
        mw.process_batch()
        
        with database.get_db_connection() as conn:
            tcs = conn.execute("SELECT status FROM threat_context_state").fetchone()
            self.assertEqual(tcs["status"], "FAILED")
            
            inc = conn.execute("SELECT count(*) as c FROM incidents").fetchone()
            self.assertEqual(inc["c"], 1)

    def test_failure_assessment_mitre_survives(self):
        events = [make_bruteforce_event(0, 0)]
        self._insert_events(events)
        FusionWorker().process_batch()
        MitreWorker().process_batch()
        
        aw = AssessmentWorker()
        aw.engine = None # sabotage
        aw.process_batch()
        
        with database.get_db_connection() as conn:
            ast = conn.execute("SELECT status FROM assessment_state").fetchone()
            self.assertEqual(ast["status"], "FAILED")
            
            tc = conn.execute("SELECT count(*) as c FROM threat_context").fetchone()
            self.assertEqual(tc["c"], 1)

    def test_failure_reasoning_assessment_survives(self):
        events = [make_bruteforce_event(0, 0)]
        self._insert_events(events)
        FusionWorker().process_batch()
        MitreWorker().process_batch()
        AssessmentWorker().process_batch()
        
        rw = ReasoningWorker()
        rw.provider.simulate_failure = LLMProviderError("simulated")
        rw.run_once()
        
        with database.get_db_connection() as conn:
            an_state = conn.execute("SELECT status FROM analysis_state").fetchone()
            self.assertEqual(an_state["status"], "FAILED")
            
            inc = conn.execute("SELECT latest_assessment_id, latest_analysis_id FROM incidents").fetchone()
            self.assertIsNotNone(inc["latest_assessment_id"])
            self.assertIsNone(inc["latest_analysis_id"])

    def test_failure_governance_analysis_survives(self):
        events = [make_bruteforce_event(0, 0)]
        self._insert_events(events)
        FusionWorker().process_batch()
        MitreWorker().process_batch()
        AssessmentWorker().process_batch()
        ReasoningWorker().run_once()
        
        gw = GovernanceWorker()
        gw.is_valid = False # sabotage
        gw.run_once()
        
        with database.get_db_connection() as conn:
            gs = conn.execute("SELECT count(*) as c FROM governance_state WHERE status='DECIDED'").fetchone()
            self.assertEqual(gs["c"], 0)
            
            an = conn.execute("SELECT status FROM analyses").fetchone()
            self.assertEqual(an["status"], "COMPLETED")

if __name__ == "__main__":
    unittest.main()
