import unittest
import os
import tempfile
import sqlite3
import json
import uuid
from datetime import datetime, timezone, timedelta
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

def make_bruteforce_event(index: int, timestamp_offset_seconds: int = 0) -> dict:
    base_time = datetime(2026, 10, 4, 10, 0, 0, tzinfo=timezone.utc)
    event_time = base_time + timedelta(seconds=timestamp_offset_seconds)
    return {
        "detection_event_id": f"api-e2e-bf-{index:03d}",
        "timestamp": event_time.isoformat(),
        "agent_id": "api-agent-win01",
        "hostname": "API-WIN-PC01",
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

class TestAPIIntegration(unittest.TestCase):
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

    def _seed_pipeline(self):
        # 1. Ingest event
        ev = make_bruteforce_event(1)
        resp = self.client.post("/api/v1/detection-events", json=ev, headers=self.headers)
        self.assertEqual(resp.status_code, 201)

        # 2. Run workers
        FusionWorker().process_batch()
        MitreWorker().process_batch()
        AssessmentWorker().process_batch()
        ReasoningWorker().run_once()
        GovernanceWorker().run_once()

        with database.get_db_connection() as conn:
            inc = conn.execute("SELECT incident_id FROM incidents").fetchone()
            self.assertIsNotNone(inc)
            return inc["incident_id"]

    def test_missing_incident(self):
        resp = self.client.get("/api/v1/incidents/fake-id", headers=self.headers)
        self.assertEqual(resp.status_code, 404)

    def test_unauthorized(self):
        resp = self.client.get("/api/v1/incidents", headers={"Authorization": "Bearer bad"})
        self.assertEqual(resp.status_code, 401)

    def test_incident_retrieval(self):
        incident_id = self._seed_pipeline()

        # List
        resp = self.client.get("/api/v1/incidents", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["incident_id"], incident_id)

        # Detail
        resp = self.client.get(f"/api/v1/incidents/{incident_id}", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["incident_id"], incident_id)

    def test_evidence_retrieval(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["detection_event_id"], "api-e2e-bf-001")

    def test_entity_retrieval(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/entities", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(len(data), 0)

    def test_mitre_retrieval(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/mitre", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(len(data), 0)

    def test_assessment_retrieval(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/assessment", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("trust_score", data)
        self.assertIn("risk_score", data)
        self.assertEqual(data["incident_id"], incident_id)

    def test_analysis_retrieval(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/analysis", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["incident_id"], incident_id)
        self.assertEqual(data["status"], "COMPLETED")

    def test_governance_retrieval(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/decision", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["incident_id"], incident_id)
        self.assertIn("decision", data)

    def test_provenance_history(self):
        incident_id = self._seed_pipeline()
        resp = self.client.get(f"/api/v1/incidents/{incident_id}/history", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("incident", data)
        self.assertIn("assessment", data)
        self.assertIn("analysis", data)
        self.assertIn("decision", data)
        self.assertIn("historical_decisions", data)

        self.assertIsNotNone(data["incident"])
        self.assertIsNotNone(data["assessment"])
        self.assertIsNotNone(data["analysis"])
        self.assertIsNotNone(data["decision"])

        # Test missing relations properly
        inc_only_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with database.get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (inc_only_id, now, now, now, now, "LOW", "OPEN"))
            conn.commit()

        resp2 = self.client.get(f"/api/v1/incidents/{inc_only_id}/history", headers=self.headers)
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertIsNotNone(data2["incident"])
        self.assertIsNone(data2["assessment"])
        self.assertIsNone(data2["analysis"])
        self.assertIsNone(data2["decision"])
        self.assertEqual(len(data2["historical_decisions"]), 0)

    def test_missing_related_records_404(self):
        inc_only_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with database.get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (inc_only_id, now, now, now, now, "LOW", "OPEN"))
            conn.commit()

        self.assertEqual(self.client.get(f"/api/v1/incidents/{inc_only_id}/assessment", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get(f"/api/v1/incidents/{inc_only_id}/analysis", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get(f"/api/v1/incidents/{inc_only_id}/decision", headers=self.headers).status_code, 404)

    def test_analyst_override_not_implemented(self):
        incident_id = self._seed_pipeline()
        payload = {"action": "AUTO_APPROVE", "reason": "Analyst verified safe."}
        resp = self.client.post(f"/api/v1/incidents/{incident_id}/governance/override", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 501)
        self.assertIn("does not support append-only analyst overrides", resp.json()["detail"])

    def test_cors_preflight_options(self):
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        }
        resp = self.client.options("/api/v1/incidents", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("access-control-allow-origin"), "http://localhost:5173")

if __name__ == "__main__":
    unittest.main()
