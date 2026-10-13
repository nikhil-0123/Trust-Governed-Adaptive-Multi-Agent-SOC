import unittest
import os
import tempfile
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient

# Create isolated DB before importing app components
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.environ["SOC_DB_PATH"] = temp_db_path
os.close(temp_db_fd)

import app.database as database
from app.main import app, API_TOKEN
from app.worker import FusionWorker
from app.mitre_worker import MitreWorker
from app.assessment_worker import AssessmentWorker
from app.reasoning_worker import ReasoningWorker
from app.governance_worker import GovernanceWorker

class TestUbuntuE2EIntegration(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)

        self.original_db_path = database.DB_PATH
        database.DB_PATH = self.temp_db_path

        database.init_db()
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {API_TOKEN}"}

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_ubuntu_full_soc_pipeline_flow(self):
        # 1. Create a Linux SSH Brute Force Detection Event matching Ubuntu endpoint output
        ubuntu_event = {
            "detection_event_id": "ubuntu-e2e-bf-001",
            "timestamp": "2026-10-11T21:00:00+00:00",
            "agent_id": "ubuntu-agent-emp01",
            "hostname": "UBUNTU-EMP-WS01",
            "os": "Linux",
            "source_event_id": "evt-auth-100",
            "detection_type": "brute_force",
            "confidence": 1.0,
            "severity": "HIGH",
            "detector_name": "linux_ssh_bruteforce_rule",
            "evidence": {
                "source_ip": "192.168.10.88",
                "username": "root",
                "failure_count": 5,
                "process": "sshd",
                "threshold": 5,
                "window_seconds": 60
            }
        }

        # 2. Ingest via API
        resp = self.client.post("/api/v1/detection-events", json=ubuntu_event, headers=self.headers)
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.json()["accepted"])
        self.assertFalse(resp.json()["duplicate"])

        # 3. Evidence Fusion
        FusionWorker().process_batch()
        with database.get_db_connection() as conn:
            inc = conn.execute("SELECT incident_id, max_severity, status FROM incidents").fetchone()
            self.assertIsNotNone(inc)
            incident_id = inc["incident_id"]
            self.assertEqual(inc["max_severity"], "HIGH")

            # Check entities extracted
            entities = conn.execute("SELECT entity_type, entity_value FROM incident_entities WHERE incident_id = ?", (incident_id,)).fetchall()
            ent_map = {row["entity_type"]: row["entity_value"] for row in entities}
            self.assertEqual(ent_map["hostname"], "UBUNTU-EMP-WS01")
            self.assertEqual(ent_map["source_ip"], "192.168.10.88")
            self.assertEqual(ent_map["username"], "root")

        # 4. MITRE Context Mapping (technique T1110)
        MitreWorker().process_batch()
        with database.get_db_connection() as conn:
            mitre_rows = conn.execute("SELECT technique_id, technique_name, tactic FROM threat_context WHERE incident_id = ?", (incident_id,)).fetchall()
            self.assertEqual(len(mitre_rows), 1)
            self.assertEqual(mitre_rows[0]["technique_id"], "T1110")
            self.assertEqual(mitre_rows[0]["technique_name"], "Brute Force")
            self.assertEqual(mitre_rows[0]["tactic"], "Credential Access")

        # 5. Trust and Risk Assessment
        AssessmentWorker().process_batch()
        with database.get_db_connection() as conn:
            ast = conn.execute("SELECT status, trust_score, risk_score FROM assessments WHERE incident_id = ?", (incident_id,)).fetchone()
            self.assertIsNotNone(ast)
            self.assertEqual(ast["status"], "COMPLETED")
            self.assertIsNotNone(ast["trust_score"])
            self.assertIsNotNone(ast["risk_score"])

        # 6. Multi-Agent Reasoning
        ReasoningWorker().run_once()
        with database.get_db_connection() as conn:
            an = conn.execute("SELECT status, model_provenance FROM analyses WHERE incident_id = ?", (incident_id,)).fetchone()
            self.assertIsNotNone(an)
            self.assertEqual(an["status"], "COMPLETED")

        # 7. Trust-Governed Decision
        GovernanceWorker().run_once()
        with database.get_db_connection() as conn:
            gd = conn.execute("SELECT decision, policy_version FROM governance_decisions WHERE incident_id = ?", (incident_id,)).fetchone()
            self.assertIsNotNone(gd)

        # 8. Provenance History API
        hist_resp = self.client.get(f"/api/v1/incidents/{incident_id}/history", headers=self.headers)
        self.assertEqual(hist_resp.status_code, 200)
        hist_data = hist_resp.json()
        self.assertIsNotNone(hist_data["incident"])
        self.assertIsNotNone(hist_data["assessment"])
        self.assertIsNotNone(hist_data["analysis"])
        self.assertIsNotNone(hist_data["decision"])

        # Evidence retrieval confirms Linux OS provenance
        ev_resp = self.client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=self.headers)
        self.assertEqual(ev_resp.status_code, 200)
        ev_data = ev_resp.json()
        self.assertEqual(len(ev_data), 1)
        self.assertEqual(ev_data[0]["os"], "Linux")
        self.assertEqual(ev_data[0]["detection_type"], "brute_force")

if __name__ == "__main__":
    unittest.main()
