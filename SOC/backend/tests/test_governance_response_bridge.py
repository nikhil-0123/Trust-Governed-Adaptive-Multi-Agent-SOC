import os
os.environ["DISABLE_STARTUP_WORKERS"] = "1"

import unittest
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import HTTPException
from app.models import EndpointCommandCreate

from app.database import init_db, get_db_connection
from app.main import (
    API_TOKEN,
    dispatch_command,
    get_incident_governance_status,
    approve_governance_mitigation,
    reject_governance_mitigation,
    GovernanceApprovalRequest,
    GovernanceRejectionRequest
)
from app.response_bridge import (
    AccountTargetRecord,
    select_account_target_record,
    get_incident_endpoint_targets,
    build_endpoint_command_params,
    dispatch_governed_response
)


class MockResponse:
    def __init__(self, status_code: int, data: Any):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


class DirectApiClient:
    """
    Invokes FastAPI path operations in-process without network sockets,
    avoiding loopback hanging on Windows in sandboxed test runs.
    """
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> MockResponse:
        auth = headers.get("Authorization") if headers else None
        if not auth or not auth.startswith("Bearer "):
            return MockResponse(401, {"detail": "Missing or invalid Authorization header"})
        token = auth.split(" ")[1]
        if token != API_TOKEN:
            return MockResponse(401, {"detail": "Unauthorized"})

        parts = url.strip("/").split("/")
        # /api/v1/incidents/{incident_id}/governance
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "incidents" and parts[4] == "governance":
            incident_id = parts[3]
            with get_db_connection() as conn:
                res = get_incident_governance_status(incident_id, token=token, db=conn)
                return MockResponse(200, res.model_dump())

        return MockResponse(404, {"detail": "Not found"})

    def post(self, url: str, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> MockResponse:
        auth = headers.get("Authorization") if headers else None
        if not auth or not auth.startswith("Bearer "):
            return MockResponse(401, {"detail": "Missing or invalid Authorization header"})
        token = auth.split(" ")[1]
        if token != API_TOKEN:
            return MockResponse(401, {"detail": "Unauthorized"})

        parts = url.strip("/").split("/")
        # /api/v1/incidents/{incident_id}/governance/approve
        if len(parts) == 6 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "incidents" and parts[4] == "governance":
            incident_id = parts[3]
            action = parts[5]
            with get_db_connection() as conn:
                if action == "approve":
                    req = GovernanceApprovalRequest(**(json or {}))
                    res = approve_governance_mitigation(incident_id, req=req, token=token, db=conn)
                    return MockResponse(200, res)
                elif action == "reject":
                    req = GovernanceRejectionRequest(**(json or {}))
                    res = reject_governance_mitigation(incident_id, req=req, token=token, db=conn)
                    return MockResponse(200, res)

        return MockResponse(404, {"detail": "Not found"})


class TestGovernanceResponseBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.client = DirectApiClient()
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
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (self.agent_id, self.now_iso))

            conn.execute("""
                INSERT INTO events (detection_event_id, agent_id, channel, channel_epoch, quarantine_status, data)
                VALUES (?, ?, 'Security', 1, 'ACTIVE_VERIFIED', ?)
            """, (self.event_id, self.agent_id, json.dumps(event_data)))

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

            cursor = conn.execute("SELECT * FROM endpoint_commands WHERE agent_id = ? AND status = 'PENDING'", (self.agent_id,))
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 2)

            block_row = next(r for r in rows if r["command_type"] == "BLOCK_SOURCE")
            params = json.loads(block_row["parameters"])
            self.assertEqual(params["ip"], "192.168.1.100")
            self.assertEqual(params["incident_id"], self.incident_id)

    def test_api_governance_approve_and_reject_flow(self):
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

        # Check initial status
        res_get = self.client.get(f"/api/v1/incidents/{self.incident_id}/governance", headers=self.headers)
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.json()
        self.assertEqual(data_get["approval_status"], "PENDING")
        self.assertEqual(data_get["decision"], "HUMAN_APPROVAL")
        self.assertEqual(len(data_get["dispatched_commands"]), 0)

        # Approve mitigation via API
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

        # Verify status after approval
        res_after = self.client.get(f"/api/v1/incidents/{self.incident_id}/governance", headers=self.headers)
        self.assertEqual(res_after.status_code, 200)
        after_data = res_after.json()
        self.assertEqual(after_data["approval_status"], "APPROVED")
        self.assertEqual(len(after_data["dispatched_commands"]), 1)
        self.assertEqual(after_data["dispatched_commands"][0]["command_type"], "ISOLATE_HOST")

        # Test idempotency (approving again)
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

    # =========================================================================
    # WP-1C Acceptance Test Cases: 1A, 1B, 2A, 2B, 2C, 2D
    # =========================================================================

    def test_case_1a_multiple_records_same_local_account_fails_closed(self):
        # Multiple detection records targeting the same LOCAL_SAM\admin account on the same endpoint
        r1 = AccountTargetRecord(
            target_account_id="LOCAL_SAM\\admin",
            target_user="admin",
            target_domain=None,
            domain_status="LOCAL_SAM",
            domain_namespace="LOCAL_SAM",
            target_agent_id="agent-01",
            target_hostname="WIN-TEST-01",
            originating_detection_event_id="det-001"
        )
        r2 = AccountTargetRecord(
            target_account_id="LOCAL_SAM\\admin",
            target_user="admin",
            target_domain=None,
            domain_status="LOCAL_SAM",
            domain_namespace="LOCAL_SAM",
            target_agent_id="agent-01",
            target_hostname="WIN-TEST-01",
            originating_detection_event_id="det-002"
        )
        # Without disambiguating governance filter -> strictly raises ValueError (fail closed)
        with self.assertRaises(ValueError) as ctx:
            select_account_target_record("inc-01", [r1, r2])
        self.assertIn("Ambiguous account target", str(ctx.exception))

    def test_case_1b_resolved_via_originating_detection_event_id(self):
        r1 = AccountTargetRecord(
            target_account_id="LOCAL_SAM\\admin",
            target_user="admin",
            target_domain=None,
            domain_status="LOCAL_SAM",
            domain_namespace="LOCAL_SAM",
            target_agent_id="agent-01",
            target_hostname="WIN-TEST-01",
            originating_detection_event_id="det-001"
        )
        r2 = AccountTargetRecord(
            target_account_id="LOCAL_SAM\\admin",
            target_user="admin",
            target_domain=None,
            domain_status="LOCAL_SAM",
            domain_namespace="LOCAL_SAM",
            target_agent_id="agent-01",
            target_hostname="WIN-TEST-01",
            originating_detection_event_id="det-002"
        )
        # Disambiguating parameter resolves to exactly one candidate
        selected = select_account_target_record(
            "inc-01",
            [r1, r2],
            custom_params={"originating_detection_event_id": "det-002"}
        )
        self.assertEqual(selected.originating_detection_event_id, "det-002")

    def test_direct_account_disable_requires_target_hostname(self):
        with get_db_connection() as conn:
            for params in ({}, {"target_hostname": "  "}):
                with self.subTest(params=params), self.assertRaises(HTTPException) as error:
                    dispatch_command(
                        self.agent_id, EndpointCommandCreate(command_type="disable_account", parameters=params),
                        token=API_TOKEN, db=conn,
                    )
                self.assertEqual(error.exception.status_code, 422)
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM endpoint_commands WHERE agent_id = ?", (self.agent_id,)
            ).fetchone())

    def test_case_2a_local_sam_permitted_strictly_targeted_not_broadcast(self):
        inc_id = str(uuid.uuid4())
        agent_1 = str(uuid.uuid4())
        agent_2 = str(uuid.uuid4())
        det_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at) VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)", (inc_id, now_str, now_str, now_str, now_str))
            conn.execute("INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat) VALUES (?, 'HOST-1', 'windows', 'ONLINE', ?)", (agent_1, now_str))
            conn.execute("INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat) VALUES (?, 'HOST-2', 'windows', 'ONLINE', ?)", (agent_2, now_str))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_1))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_2))

            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_1,
                "evidence": {
                    "target_user": "attacker",
                    "target_account_id": "LOCAL_SAM\\attacker",
                    "domain_status": "LOCAL_SAM",
                    "domain_namespace": "LOCAL_SAM"
                }
            }
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_1, now_str))
            conn.execute("INSERT INTO events (detection_event_id, agent_id, channel, channel_epoch, quarantine_status, data) VALUES (?, ?, 'Security', 1, 'ACTIVE_VERIFIED', ?)", (det_id, agent_1, json.dumps(ev_data)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            with self.assertRaisesRegex(ValueError, "Missing target_hostname"):
                dispatch_governed_response(
                    conn, inc_id, recommendations=[{"type": "DISABLE_ACCOUNT"}]
                )
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM endpoint_commands WHERE agent_id = ?", (agent_1,)
            ).fetchone())
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM action_leases WHERE incident_id = ?", (inc_id,)
            ).fetchone())

            ev_data["hostname"] = "HOST-1"
            conn.execute("UPDATE events SET data = ? WHERE detection_event_id = ?", (json.dumps(ev_data), det_id))
            conn.commit()

            dispatched = dispatch_governed_response(
                conn,
                inc_id,
                recommendations=[{"type": "DISABLE_ACCOUNT", "reason": "Local account compromise"}]
            )

            # Strictly 1 command dispatched, ONLY to agent_1 (never broadcast to agent_2)
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_1)
            self.assertEqual(dispatched[0]["command_type"], "DISABLE_ACCOUNT")
            self.assertEqual(dispatched[0]["parameters"]["domain"], "LOCAL_SAM")
            self.assertEqual(dispatched[0]["parameters"]["username"], "attacker")

            # Verify endpoint_commands table contains zero commands for agent_2
            r2 = conn.execute("SELECT count(*) as c FROM endpoint_commands WHERE agent_id = ?", (agent_2,)).fetchone()
            self.assertEqual(r2["c"], 0)

    def test_case_2b_domain_account_escalated_zero_dispatch(self):
        inc_id = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())
        det_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at) VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)", (inc_id, now_str, now_str, now_str, now_str))
            conn.execute("INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat) VALUES (?, 'WIN-DC-01', 'windows', 'ONLINE', ?)", (agent_id, now_str))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))

            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "hostname": "WIN-DC-01",
                "evidence": {
                    "target_user": "bob",
                    "target_domain": "CORP",
                    "target_account_id": "DOMAIN:CORP\\bob",
                    "domain_status": "OBSERVED_DOMAIN",
                    "domain_namespace": "DOMAIN:CORP"
                }
            }
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_str))
            conn.execute("INSERT INTO events (detection_event_id, agent_id, channel, channel_epoch, quarantine_status, data) VALUES (?, ?, 'Security', 1, 'ACTIVE_VERIFIED', ?)", (det_id, agent_id, json.dumps(ev_data)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            dispatched = dispatch_governed_response(
                conn,
                inc_id,
                recommendations=[{"type": "DISABLE_ACCOUNT", "reason": "Enterprise domain account compromise"}]
            )

            # Zero commands dispatched to endpoints
            self.assertEqual(len(dispatched), 0)
            rows = conn.execute("SELECT count(*) as c FROM endpoint_commands WHERE agent_id = ?", (agent_id,)).fetchone()
            self.assertEqual(rows["c"], 0)

    def test_case_2c_unverified_account_rejected(self):
        inc_id = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())
        det_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at) VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)", (inc_id, now_str, now_str, now_str, now_str))
            conn.execute("INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat) VALUES (?, 'WIN-TEST-01', 'windows', 'ONLINE', ?)", (agent_id, now_str))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))

            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "hostname": "WIN-TEST-01",
                "evidence": {
                    "target_user": "unknown_user",
                    "domain_status": "UNVERIFIED",
                    "domain_namespace": "UNVERIFIED"
                }
            }
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_str))
            conn.execute("INSERT INTO events (detection_event_id, agent_id, channel, channel_epoch, quarantine_status, data) VALUES (?, ?, 'Security', 1, 'ACTIVE_VERIFIED', ?)", (det_id, agent_id, json.dumps(ev_data)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            with self.assertRaises(ValueError) as ctx:
                dispatch_governed_response(
                    conn,
                    inc_id,
                    recommendations=[{"type": "DISABLE_ACCOUNT", "reason": "Attempting to disable unverified account"}]
                )
            self.assertIn("UNVERIFIED", str(ctx.exception))

    def test_case_2d_contradictory_identity_rejected(self):
        inc_id = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())
        det_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at) VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)", (inc_id, now_str, now_str, now_str, now_str))
            conn.execute("INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat) VALUES (?, 'WIN-TEST-01', 'windows', 'ONLINE', ?)", (agent_id, now_str))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))

            # Contradictory: domain_status is LOCAL_SAM but namespace is DOMAIN:CORP
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "hostname": "WIN-TEST-01",
                "evidence": {
                    "target_user": "admin",
                    "target_account_id": "LOCAL_SAM\\admin",
                    "domain_status": "LOCAL_SAM",
                    "domain_namespace": "DOMAIN:CORP"
                }
            }
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_str))
            conn.execute("INSERT INTO events (detection_event_id, agent_id, channel, channel_epoch, quarantine_status, data) VALUES (?, ?, 'Security', 1, 'ACTIVE_VERIFIED', ?)", (det_id, agent_id, json.dumps(ev_data)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            with self.assertRaises(ValueError) as ctx:
                dispatch_governed_response(
                    conn,
                    inc_id,
                    recommendations=[{"type": "DISABLE_ACCOUNT", "reason": "Contradictory attack"}]
                )
            self.assertIn("Contradictory", str(ctx.exception))

    def test_case_2e_contradictory_domain_prefix_rejected(self):
        inc_id = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())
        det_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            conn.execute("INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at) VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)", (inc_id, now_str, now_str, now_str, now_str))
            conn.execute("INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat) VALUES (?, 'WIN-DC-01', 'windows', 'ONLINE', ?)", (agent_id, now_str))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))

            # Contradictory: target_account_id is missing DOMAIN: prefix (e.g. CORP\bob instead of DOMAIN:CORP\bob)
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "hostname": "WIN-DC-01",
                "evidence": {
                    "target_user": "bob",
                    "target_domain": "CORP",
                    "target_account_id": "CORP\\bob",
                    "domain_status": "OBSERVED_DOMAIN",
                    "domain_namespace": "DOMAIN:CORP"
                }
            }
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_str))
            conn.execute("INSERT INTO events (detection_event_id, agent_id, channel, channel_epoch, quarantine_status, data) VALUES (?, ?, 'Security', 1, 'ACTIVE_VERIFIED', ?)", (det_id, agent_id, json.dumps(ev_data)))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            with self.assertRaises(ValueError) as ctx:
                dispatch_governed_response(
                    conn,
                    inc_id,
                    recommendations=[{"type": "DISABLE_ACCOUNT", "reason": "Malformed domain account id"}]
                )
            self.assertIn("Contradictory identity", str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
