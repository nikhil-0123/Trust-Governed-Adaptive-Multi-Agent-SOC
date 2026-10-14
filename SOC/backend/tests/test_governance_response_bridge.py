import unittest
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import init_db, get_db_connection
from app.main import app, API_TOKEN
from app.response_bridge import (
    get_incident_endpoint_targets,
    build_endpoint_command_params,
    dispatch_governed_response
)

class TestGovernanceResponseBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {API_TOKEN}"}
        self.incident_id = str(uuid.uuid4())
        self.agent_id = str(uuid.uuid4())
        self.event_id = str(uuid.uuid4())
        self.now_iso = datetime.now(timezone.utc).isoformat()

        # Seed test incident, endpoint, event, and entity
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO endpoints (agent_id, hostname, os, ip_address, status, last_heartbeat)
                VALUES (?, 'WIN-TEST-01', 'windows', '10.0.0.50', 'ONLINE', ?)
            """, (self.agent_id, self.now_iso))

            event_data = {
                "detection_event_id": self.event_id,
                "agent_id": self.agent_id,
                "hostname": "WIN-TEST-01",
                "source_ip": "192.168.1.100",
                "evidence": {
                    "source_ip": "192.168.1.100",
                    "process_id": "4092",
                    "process_name": "powershell.exe"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data)
                VALUES (?, ?)
            """, (self.event_id, json.dumps(event_data)))

            conn.execute("""
                INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at)
                VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)
            """, (self.incident_id, self.now_iso, self.now_iso, self.now_iso, self.now_iso))

            conn.execute("""
                INSERT INTO incident_evidence (incident_id, detection_event_id)
                VALUES (?, ?)
            """, (self.incident_id, self.event_id))

            conn.execute("""
                INSERT INTO incident_entities (incident_id, entity_type, entity_value)
                VALUES (?, 'agent_id', ?)
            """, (self.incident_id, self.agent_id))

            conn.execute("""
                INSERT INTO incident_entities (incident_id, entity_type, entity_value)
                VALUES (?, 'source_ip', '192.168.1.100')
            """, (self.incident_id,))

            conn.commit()

    def test_get_incident_endpoint_targets(self):
        with get_db_connection() as conn:
            targets = get_incident_endpoint_targets(conn, self.incident_id)
            self.assertIn(self.agent_id, targets["agent_ids"])
            self.assertIn("192.168.1.100", targets["source_ips"])
            self.assertIn("4092", targets["process_ids"])
            self.assertIn("powershell.exe", targets["process_names"])

    def test_dispatch_governed_response_creates_pending_commands(self):
        with get_db_connection() as conn:
            recommendations = [
                {"type": "BLOCK_SOURCE", "reason": "Brute-force source IP identified"},
                {"type": "KILL_PROCESS", "reason": "Malicious PowerShell process detected"}
            ]
            dispatched = dispatch_governed_response(
                conn,
                self.incident_id,
                recommendations,
                approved_by="UNIT_TEST_RUNNER"
            )

            self.assertEqual(len(dispatched), 2)
            cmd_types = [c["command_type"] for c in dispatched]
            self.assertIn("BLOCK_SOURCE", cmd_types)
            self.assertIn("KILL_PROCESS", cmd_types)

            # Verify saved in endpoint_commands table
            cursor = conn.execute("SELECT * FROM endpoint_commands WHERE agent_id = ? AND status = 'PENDING'", (self.agent_id,))
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 2)

            # Verify parameters contain the incident_id and target IP
            block_row = next(r for r in rows if r["command_type"] == "BLOCK_SOURCE")
            params = json.loads(block_row["parameters"])
            self.assertEqual(params["ip"], "192.168.1.100")
            self.assertEqual(params["incident_id"], self.incident_id)

    def test_api_governance_approve_and_reject_flow(self):
        # 1. Setup governance state as DECIDED with PENDING approval
        dec_id = str(uuid.uuid4())
        assessment_id = str(uuid.uuid4())
        analysis_id = str(uuid.uuid4())

        analysis_output = {
            "analysis_id": analysis_id,
            "incident_id": self.incident_id,
            "recommendations": [
                {"type": "ISOLATE_HOST", "reason": "High severity multi-stage attack", "supporting_claims": []}
            ]
        }

        with get_db_connection() as conn:
            conn.execute("""
                UPDATE incidents SET latest_assessment_id = ?, latest_analysis_id = ? WHERE incident_id = ?
            """, (assessment_id, analysis_id, self.incident_id))

            conn.execute("""
                INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at)
                VALUES (?, ?, ?, '{}', 'COMPLETED', 'test', '{}', ?, ?)
            """, (analysis_id, self.incident_id, assessment_id, json.dumps(analysis_output), self.now_iso))

            conn.execute("""
                INSERT INTO governance_decisions (decision_id, incident_id, assessment_id, analysis_id, decision, reason, input_snapshot, policy_version, config_version, created_at)
                VALUES (?, ?, ?, ?, 'HUMAN_APPROVAL', 'High risk incident requires manual approval', '{}', 'v1.0', 'v1.0', ?)
            """, (dec_id, self.incident_id, assessment_id, analysis_id, self.now_iso))

            conn.execute("""
                INSERT INTO governance_state (incident_id, assessment_id, analysis_id, status, decision_id, approval_status, attempts, updated_at)
                VALUES (?, ?, ?, 'DECIDED', ?, 'PENDING', 0, ?)
            """, (self.incident_id, assessment_id, analysis_id, dec_id, self.now_iso))

            conn.commit()

        # 2. Check initial status
        res_get = self.client.get(f"/api/v1/incidents/{self.incident_id}/governance", headers=self.headers)
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.json()
        self.assertEqual(data_get["approval_status"], "PENDING")
        self.assertEqual(data_get["decision"], "HUMAN_APPROVAL")
        self.assertEqual(len(data_get["dispatched_commands"]), 0)

        # 3. Approve mitigation via API
        approve_payload = {
            "analyst_name": "lead_soc_analyst",
            "reason": "Threat verified, isolating endpoint"
        }
        res_approve = self.client.post(
            f"/api/v1/incidents/{self.incident_id}/governance/approve",
            json=approve_payload,
            headers=self.headers
        )
        self.assertEqual(res_approve.status_code, 200)
        approve_data = res_approve.json()
        self.assertTrue(approve_data["acknowledged"])
        self.assertEqual(approve_data["approval_status"], "APPROVED")
        self.assertEqual(approve_data["dispatched_count"], 1)

        # 4. Verify status after approval
        res_after = self.client.get(f"/api/v1/incidents/{self.incident_id}/governance", headers=self.headers)
        self.assertEqual(res_after.status_code, 200)
        after_data = res_after.json()
        self.assertEqual(after_data["approval_status"], "APPROVED")
        self.assertEqual(len(after_data["dispatched_commands"]), 1)
        self.assertEqual(after_data["dispatched_commands"][0]["command_type"], "ISOLATE_HOST")

        # 5. Test idempotency (approving again)
        res_again = self.client.post(
            f"/api/v1/incidents/{self.incident_id}/governance/approve",
            json=approve_payload,
            headers=self.headers
        )
        self.assertEqual(res_again.status_code, 200)
        self.assertEqual(res_again.json()["dispatched_count"], 0)

    def test_api_governance_reject(self):
        dec_id = str(uuid.uuid4())
        assessment_id = str(uuid.uuid4())
        analysis_id = str(uuid.uuid4())

        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO governance_decisions (decision_id, incident_id, assessment_id, analysis_id, decision, reason, input_snapshot, policy_version, config_version, created_at)
                VALUES (?, ?, ?, ?, 'HUMAN_APPROVAL', 'Test rejection', '{}', 'v1.0', 'v1.0', ?)
            """, (dec_id, self.incident_id, assessment_id, analysis_id, self.now_iso))

            conn.execute("""
                INSERT INTO governance_state (incident_id, assessment_id, analysis_id, status, decision_id, approval_status, attempts, updated_at)
                VALUES (?, ?, ?, 'DECIDED', ?, 'PENDING', 0, ?)
            """, (self.incident_id, assessment_id, analysis_id, dec_id, self.now_iso))
            conn.commit()

        reject_payload = {
            "analyst_name": "lead_soc_analyst",
            "reason": "Authorized red team exercise, false alarm"
        }
        res = self.client.post(
            f"/api/v1/incidents/{self.incident_id}/governance/reject",
            json=reject_payload,
            headers=self.headers
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["approval_status"], "REJECTED")

        # Verify no commands were dispatched
        with get_db_connection() as conn:
            row = conn.execute("SELECT count(*) as c FROM endpoint_commands WHERE agent_id = ?", (self.agent_id,)).fetchone()
            self.assertEqual(row["c"], 0)

    def test_unauthorized_access(self):
        res = self.client.get(f"/api/v1/incidents/{self.incident_id}/governance")
        self.assertEqual(res.status_code, 401)

        res2 = self.client.post(f"/api/v1/incidents/{self.incident_id}/governance/approve")
        self.assertEqual(res2.status_code, 401)

if __name__ == '__main__':
    unittest.main()
