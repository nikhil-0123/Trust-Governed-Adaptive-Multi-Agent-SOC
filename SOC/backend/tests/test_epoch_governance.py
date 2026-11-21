import os
os.environ["DISABLE_STARTUP_WORKERS"] = "1"
os.environ["SOC_ADMIN_API_TOKEN"] = "dev-admin-secret-token"

import unittest
import json
import sqlite3
import tempfile
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import HTTPException

import app.database as database
from app.database import init_db, get_db_connection
from app.worker import FusionWorker
from app.canonical import (
    canonicalize_tgam_rcc_v1,
    compute_payload_hash,
    generate_outbox_conflict_id
)
from app.main import (
    API_TOKEN,
    verify_token,
    verify_admin_token,
    ingest_event_transactional,
    process_channel_transition,
    resolve_epoch_gap,
    allocate_recovery_epoch,
    get_conflicts_query
)
from app.response_bridge import (
    check_incident_evidence_eligibility,
    dispatch_governed_response,
    IneligibleEvidenceError
)

ADMIN_API_TOKEN = os.getenv("SOC_ADMIN_API_TOKEN", "dev-admin-secret-token")


class MockResponse:
    def __init__(self, status_code: int, data: Any):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


class DirectApiClient:
    """
    Invokes FastAPI/SOC endpoints in-process without network sockets,
    avoiding Windows sandbox socketpair loopback hangs.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn

    def post(
        self,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
        raw_body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> MockResponse:
        auth = headers.get("Authorization") if headers else None

        if raw_body is not None:
            body_bytes = raw_body
        elif json_data is not None:
            body_bytes = json.dumps(json_data).encode("utf-8")
        else:
            body_bytes = b"{}"

        parts = url.strip("/").split("/")

        # /api/v1/detection-events
        if url.startswith("/api/v1/detection-events"):
            try:
                verify_token(auth)
            except HTTPException as he:
                return MockResponse(he.status_code, {"detail": he.detail})
            conn = self._get_conn()
            try:
                code, resp = ingest_event_transactional(conn, body_bytes)
                return MockResponse(code, resp)
            finally:
                conn.close()

        # /api/v1/events/transition
        if url.startswith("/api/v1/events/transition"):
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
            except Exception as e:
                return MockResponse(400, {"detail": f"Invalid JSON: {e}"})

            ttype = payload.get("transition_type", "EPOCH_ADVANCE")
            from app.response_bridge import AUTHORIZED_RECOVERY_TRANSITION_TYPES
            authenticated_actor = None
            if ttype in AUTHORIZED_RECOVERY_TRANSITION_TYPES:
                try:
                    authenticated_actor = verify_admin_token(auth)
                except HTTPException as he:
                    return MockResponse(he.status_code, {"detail": he.detail})
            else:
                try:
                    verify_token(auth)
                except HTTPException as he:
                    return MockResponse(he.status_code, {"detail": he.detail})

            conn = self._get_conn()
            try:
                code, resp = process_channel_transition(conn, payload, authenticated_actor=authenticated_actor)
                return MockResponse(code, resp)
            finally:
                conn.close()

        # /api/v1/agents/{agent_id}/channels/{channel}/allocate_epoch
        if len(parts) == 7 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "agents" and parts[4] == "channels" and parts[6] == "allocate_epoch":
            try:
                verify_token(auth)
            except HTTPException as he:
                return MockResponse(he.status_code, {"detail": he.detail})
            agent_id = parts[3]
            channel = parts[5]
            conn = self._get_conn()
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
                req_id = payload.get("recovery_request_id")
                reason = payload.get("recovery_reason")
                code, resp = allocate_recovery_epoch(conn, req_id, agent_id, channel, reason)
                return MockResponse(code, resp)
            finally:
                conn.close()

        # /api/v1/agents/{agent_id}/channels/{channel}/resolve_gap
        if len(parts) == 7 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "agents" and parts[4] == "channels" and parts[6] == "resolve_gap":
            try:
                admin_principal = verify_admin_token(auth)
            except HTTPException as he:
                return MockResponse(he.status_code, {"detail": he.detail})
            agent_id = parts[3]
            channel = parts[5]
            conn = self._get_conn()
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
                target_epoch = payload.get("target_epoch")
                reason = payload.get("resolution_reason", "Administrative gap override")
                rec_req_id = payload.get("recovery_request_id")
                code, resp = resolve_epoch_gap(
                    conn, agent_id, channel, target_epoch, reason,
                    authorized_by=admin_principal,
                    recovery_request_id=rec_req_id
                )
                return MockResponse(code, resp)
            finally:
                conn.close()

        return MockResponse(404, {"detail": "Not found"})

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> MockResponse:
        auth = headers.get("Authorization") if headers else None
        try:
            verify_token(auth)
        except HTTPException as he:
            return MockResponse(he.status_code, {"detail": he.detail})

        parts = url.strip("/").split("/")

        # /api/v1/conflicts
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "conflicts":
            conn = self._get_conn()
            try:
                res = get_conflicts_query(conn)
                return MockResponse(200, res)
            finally:
                conn.close()

        # /api/v1/conflicts/{event_id}
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "conflicts":
            event_id = parts[3]
            conn = self._get_conn()
            try:
                res = get_conflicts_query(conn, event_id=event_id)
                return MockResponse(200, res)
            finally:
                conn.close()

        return MockResponse(404, {"detail": "Not found"})


class TestEpochGovernance(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        database.DB_PATH = self.db_path
        init_db()

        self.client = DirectApiClient(self.db_path)
        self.headers = {"Authorization": f"Bearer {API_TOKEN}"}

        self.base_event = {
            "detection_event_id": "det-test-001",
            "timestamp": "2026-11-17T12:00:00Z",
            "agent_id": "AGT-WIN-01",
            "hostname": "WIN-WORKSTATION-01",
            "os": "Windows",
            "source_event_id": "src-win-001",
            "detection_type": "windows_bruteforce_rule",
            "confidence": 0.95,
            "severity": "high",
            "detector_name": "BruteForceDetector",
            "channel": "Security",
            "channel_epoch": 1,
            "evidence": {
                "target_user": "Administrator",
                "target_domain": "CORP",
                "domain_status": "OBSERVED_DOMAIN",
                "domain_namespace": "DOMAIN:CORP",
                "log_name": "Security"
            }
        }

    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    # TEST 1: Duplicate identical SOC event (idempotent, no duplicate fusion/incidents)
    def test_duplicate_identical_event_ingestion(self):
        # 1. First submission
        res1 = self.client.post("/api/v1/detection-events", json_data=self.base_event, headers=self.headers)
        self.assertEqual(res1.status_code, 201)
        data1 = res1.json()
        self.assertTrue(data1["accepted"])
        self.assertFalse(data1["duplicate"])
        self.assertEqual(data1["detection_event_id"], "det-test-001")

        # 2. Resubmission of identical event
        res2 = self.client.post("/api/v1/detection-events", json_data=self.base_event, headers=self.headers)
        self.assertEqual(res2.status_code, 201)
        data2 = res2.json()
        self.assertTrue(data2["accepted"])
        self.assertTrue(data2["duplicate"])
        self.assertEqual(data2["detection_event_id"], "det-test-001")

        # 3. Verify database storage: exactly 1 event row
        with get_db_connection() as conn:
            rows = conn.execute("SELECT * FROM events WHERE detection_event_id = ?", ("det-test-001",)).fetchall()
            self.assertEqual(len(rows), 1)

            # Process fusion
            worker = FusionWorker()
            worker.process_batch()

            # Verify fusion state has exactly 1 row
            f_rows = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = ?", ("det-test-001",)).fetchall()
            self.assertEqual(len(f_rows), 1)
            self.assertEqual(f_rows[0]["status"], "PROCESSED")

            # Verify incidents count
            inc_rows = conn.execute("SELECT * FROM incidents").fetchall()
            self.assertEqual(len(inc_rows), 1)

    # TEST 2: Duplicate conflicting SOC event (HTTP 409, durable conflict row, original preserved)
    def test_duplicate_conflicting_event_ingestion(self):
        # 1. Initial event
        res1 = self.client.post("/api/v1/detection-events", json_data=self.base_event, headers=self.headers)
        self.assertEqual(res1.status_code, 201)

        # 2. Conflicting event: same detection_event_id, modified severity & confidence
        conflicting = dict(self.base_event)
        conflicting["severity"] = "critical"
        conflicting["confidence"] = 1.0

        res2 = self.client.post("/api/v1/detection-events", json_data=conflicting, headers=self.headers)
        self.assertEqual(res2.status_code, 409)
        data2 = res2.json()
        self.assertFalse(data2["accepted"])
        self.assertIn("conflict_id", data2)
        conflict_id = data2["conflict_id"]

        # 3. Verify original event in events table is untouched
        with get_db_connection() as conn:
            ev_row = conn.execute("SELECT data FROM events WHERE detection_event_id = ?", ("det-test-001",)).fetchone()
            self.assertIsNotNone(ev_row)
            ev_data = json.loads(ev_row["data"])
            self.assertEqual(ev_data["severity"], "high")  # preserved

            # Verify durable conflict record
            c_row = conn.execute("SELECT * FROM event_conflicts WHERE conflict_id = ?", (conflict_id,)).fetchone()
            self.assertIsNotNone(c_row)
            self.assertEqual(c_row["event_id"], "det-test-001")

        # 4. Verify API queries
        conflicts_res = self.client.get("/api/v1/conflicts", headers=self.headers)
        self.assertEqual(conflicts_res.status_code, 200)
        self.assertEqual(len(conflicts_res.json()), 1)

        conflicts_filtered = self.client.get("/api/v1/conflicts/det-test-001", headers=self.headers)
        self.assertEqual(conflicts_filtered.status_code, 200)
        self.assertEqual(len(conflicts_filtered.json()), 1)

    # TEST 3: Concurrent ingestion (threads for identical vs conflicting)
    def test_concurrent_ingestion_safety(self):
        # 10 threads submit identical events
        results = []
        lock = threading.Lock()

        def submit():
            client = DirectApiClient(self.db_path)
            res = client.post("/api/v1/detection-events", json_data=self.base_event, headers=self.headers)
            with lock:
                results.append(res)

        threads = [threading.Thread(target=submit) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 10)
        for r in results:
            self.assertEqual(r.status_code, 201)

        duplicates = [r.json()["duplicate"] for r in results]
        # Exactly one thread got duplicate=False, 9 threads got duplicate=True
        self.assertEqual(duplicates.count(False), 1)
        self.assertEqual(duplicates.count(True), 9)

        # Now submit conflicting event concurrently
        conflicting = dict(self.base_event)
        conflicting["timestamp"] = "2026-11-17T12:01:00Z"

        conflict_results = []
        def submit_conflict():
            client = DirectApiClient(self.db_path)
            res = client.post("/api/v1/detection-events", json_data=conflicting, headers=self.headers)
            with lock:
                conflict_results.append(res)

        c_threads = [threading.Thread(target=submit_conflict) for _ in range(5)]
        for t in c_threads:
            t.start()
        for t in c_threads:
            t.join()

        for r in conflict_results:
            self.assertEqual(r.status_code, 409)

    # TEST 4: Epoch transition 2 -> 3 (sequential advance)
    def test_sequential_epoch_transition(self):
        # Advance 1 -> 2
        t1 = {
            "transition_id": "trans-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE"
        }
        res1 = self.client.post("/api/v1/events/transition", json_data=t1, headers=self.headers)
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.json()["status"], "APPLIED")
        self.assertEqual(res1.json()["active_epoch"], 2)

        # Advance 2 -> 3
        t2 = {
            "transition_id": "trans-002",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 3,
            "transition_type": "EPOCH_ADVANCE"
        }
        res2 = self.client.post("/api/v1/events/transition", json_data=t2, headers=self.headers)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["status"], "APPLIED")
        self.assertEqual(res2.json()["active_epoch"], 3)

        # Event at epoch 3 is accepted with quarantine_status = ACTIVE_VERIFIED
        ev = dict(self.base_event)
        ev["detection_event_id"] = "det-epoch-3"
        ev["channel_epoch"] = 3
        res_ev = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res_ev.status_code, 201)
        self.assertEqual(res_ev.json().get("quarantine_status"), "ACTIVE_VERIFIED")

        # FusionWorker processes it
        worker = FusionWorker()
        worker.process_batch()
        with get_db_connection() as conn:
            state = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'det-epoch-3'").fetchone()
            self.assertIsNotNone(state)
            self.assertEqual(state["status"], "PROCESSED")

    # TEST 5: Skipped transition 2 -> 5 (gap quarantine, held detections, Path A / Path B releases)
    def test_skipped_epoch_transition_and_path_a_resolution(self):
        # 1. Advance to epoch 2
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t-1-to-2",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2
        }, headers=self.headers)

        # 2. Skip to epoch 5 (missing 3 and 4)
        gap_res = self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t-2-to-5",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 5
        }, headers=self.headers)
        self.assertEqual(gap_res.status_code, 409)
        self.assertEqual(gap_res.json()["status"], "EPOCH_GAP_QUARANTINED")
        self.assertEqual(gap_res.json()["active_epoch"], 2)

        # 3. Submit event with epoch 5 -> must be GAP_QUARANTINED
        ev5 = dict(self.base_event)
        ev5["detection_event_id"] = "det-gap-5"
        ev5["channel_epoch"] = 5
        ev_res = self.client.post("/api/v1/detection-events", json_data=ev5, headers=self.headers)
        self.assertEqual(ev_res.status_code, 201)
        self.assertEqual(ev_res.json()["quarantine_status"], "GAP_QUARANTINED")

        # 4. FusionWorker must NOT pick up quarantined event
        worker = FusionWorker()
        worker.process_batch()
        with get_db_connection() as conn:
            f_row = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = 'det-gap-5'").fetchone()
            self.assertIsNone(f_row)

        # 5. Path A Resolution: Replay intermediate transitions 2->3, 3->4, 4->5
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t-2-to-3", "agent_id": "AGT-WIN-01", "source_channel": "Security", "target_epoch": 3
        }, headers=self.headers)
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t-3-to-4", "agent_id": "AGT-WIN-01", "source_channel": "Security", "target_epoch": 4
        }, headers=self.headers)
        final_trans = self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t-4-to-5", "agent_id": "AGT-WIN-01", "source_channel": "Security", "target_epoch": 5
        }, headers=self.headers)
        self.assertEqual(final_trans.status_code, 200)
        self.assertEqual(final_trans.json()["status"], "APPLIED")
        self.assertEqual(final_trans.json()["active_epoch"], 5)

        # Verify event was released
        with get_db_connection() as conn:
            ev_row = conn.execute("SELECT quarantine_status FROM events WHERE detection_event_id = 'det-gap-5'").fetchone()
            self.assertEqual(ev_row["quarantine_status"], "RELEASED")

            # FusionWorker now processes it
            worker.process_batch()
            f_row = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'det-gap-5'").fetchone()
            self.assertIsNotNone(f_row)
            self.assertEqual(f_row["status"], "PROCESSED")

    def test_epoch_gap_path_b_administrative_resolution(self):
        # Trigger gap quarantine
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t-1-to-5",
            "agent_id": "AGT-WIN-02",
            "source_channel": "Security",
            "target_epoch": 5
        }, headers=self.headers)

        # Ingest event while quarantined
        ev = dict(self.base_event)
        ev["agent_id"] = "AGT-WIN-02"
        ev["detection_event_id"] = "det-admin-gap"
        ev["channel_epoch"] = 5
        self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)

        # Path B: Administrative resolution to epoch 5
        resolve_res = self.client.post(
            "/api/v1/agents/AGT-WIN-02/channels/Security/resolve_gap",
            json_data={
                "target_epoch": 5,
                "resolution_reason": "SOC Administrator validated intermediate checkpoints offline",
                "authorized_by": "SOC-LEAD-ANALYST"
            },
            headers={"Authorization": f"Bearer {ADMIN_API_TOKEN}"}
        )
        self.assertEqual(resolve_res.status_code, 200)
        self.assertEqual(resolve_res.json()["status"], "RESOLVED")
        self.assertEqual(resolve_res.json()["active_epoch"], 5)
        self.assertGreaterEqual(resolve_res.json()["released_events_count"], 1)

        # Verify event released and processed
        with get_db_connection() as conn:
            ev_row = conn.execute("SELECT quarantine_status FROM events WHERE detection_event_id = 'det-admin-gap'").fetchone()
            self.assertEqual(ev_row["quarantine_status"], "RELEASED")

            worker = FusionWorker()
            worker.process_batch()
            f_row = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'det-admin-gap'").fetchone()
            self.assertIsNotNone(f_row)
            self.assertEqual(f_row["status"], "PROCESSED")

    # TEST 6: Delayed event from retired epoch (E < E_active tagged RETIRED_EPOCH_DELAYED)
    def test_delayed_event_from_retired_epoch(self):
        # Advance channel to epoch 3
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t1", "agent_id": "AGT-WIN-01", "source_channel": "Security", "target_epoch": 2
        }, headers=self.headers)
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": "t2", "agent_id": "AGT-WIN-01", "source_channel": "Security", "target_epoch": 3
        }, headers=self.headers)

        # Delayed event arrives from epoch 1
        ev_old = dict(self.base_event)
        ev_old["detection_event_id"] = "det-delayed-epoch-1"
        ev_old["channel_epoch"] = 1

        res = self.client.post("/api/v1/detection-events", json_data=ev_old, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["quarantine_status"], "RETIRED_EPOCH_DELAYED")

        # FusionWorker must NOT process it
        worker = FusionWorker()
        worker.process_batch()
        with get_db_connection() as conn:
            f_row = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = 'det-delayed-epoch-1'").fetchone()
            self.assertIsNone(f_row)

    # TEST 7: Duplicate recovery allocation (idempotent return)
    def test_duplicate_recovery_allocation_idempotency(self):
        payload = {
            "recovery_request_id": "rec-uuid-101",
            "recovery_reason": "CORRUPTED_LOCAL_CHECKPOINT"
        }
        res1 = self.client.post(
            "/api/v1/agents/AGT-WIN-01/channels/Security/allocate_epoch",
            json_data=payload,
            headers=self.headers
        )
        self.assertEqual(res1.status_code, 200)
        epoch1 = res1.json()["allocated_epoch"]
        self.assertEqual(res1.json()["status"], "ALLOCATED")

        # Resubmit exact same request
        res2 = self.client.post(
            "/api/v1/agents/AGT-WIN-01/channels/Security/allocate_epoch",
            json_data=payload,
            headers=self.headers
        )
        self.assertEqual(res2.status_code, 200)
        epoch1_again = res2.json()["allocated_epoch"]
        self.assertEqual(epoch1_again, epoch1)
        self.assertEqual(res2.json()["status"], "ALREADY_ALLOCATED")

    # TEST 8: Recovery request reused across channels/scopes (HTTP 409)
    def test_recovery_request_scope_mismatch(self):
        payload = {
            "recovery_request_id": "rec-uuid-102",
            "recovery_reason": "HOST_UNEXPECTED_REBOOT"
        }
        res1 = self.client.post(
            "/api/v1/agents/AGT-WIN-01/channels/Security/allocate_epoch",
            json_data=payload,
            headers=self.headers
        )
        self.assertEqual(res1.status_code, 200)

        # Reusing recovery_request_id for different channel
        res2 = self.client.post(
            "/api/v1/agents/AGT-WIN-01/channels/System/allocate_epoch",
            json_data=payload,
            headers=self.headers
        )
        self.assertEqual(res2.status_code, 409)
        self.assertEqual(res2.json()["detail"], "ALLOCATION_REQUEST_ID_SCOPE_MISMATCH")

    # TEST 9: Transaction rollback on crash during conflict handling
    def test_conflict_recording_transactional_boundary(self):
        # Submit initial event
        self.client.post("/api/v1/detection-events", json_data=self.base_event, headers=self.headers)

        # Verify that uncommitted conflict is not durable, while committed is durable
        with get_db_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
                INSERT INTO event_conflicts 
                (conflict_id, event_id, payload_a, payload_a_hash, payload_b, payload_b_hash, detected_at)
                VALUES ('temp-conflict', 'det-test-001', 'a', 'ha', 'b', 'hb', 'now')
            """)
            conn.rollback()

            # Confirm rollback discarded uncommitted row
            row = conn.execute("SELECT * FROM event_conflicts WHERE conflict_id = 'temp-conflict'").fetchone()
            self.assertIsNone(row)

    # TEST 10: Strict duplicate key rejection in raw JSON
    def test_duplicate_key_rejection(self):
        # Raw bytes containing duplicate key 'detection_event_id'
        raw_duplicate = b'{"detection_event_id": "test-dup", "detection_event_id": "smuggled", "agent_id": "a", "confidence": 1.0}'
        res = self.client.post(
            "/api/v1/detection-events",
            raw_body=raw_duplicate,
            headers=self.headers
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Duplicate key rejected", res.json()["detail"])

    # =========================================================================
    # WP-1E.4 TARGETED SECURITY CORRECTIONS TESTS (Issues 1 & 2)
    # =========================================================================

    # REQUIRED TEST 1: Legacy events with NULL status cannot enter autonomous processing
    def test_legacy_event_with_null_status_cannot_enter_autonomous_processing(self):
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES ('det-legacy-null', '{}', NULL, 'AGT-WIN-01', 'Security', NULL)
            """)
            conn.commit()

        worker = FusionWorker()
        worker.process_batch()

        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = 'det-legacy-null'").fetchone()
            self.assertIsNone(row, "Event with NULL quarantine_status must NOT enter fusion_event_state")

    # Also test legacy event ingested via API without epoch metadata is explicitly classified as LEGACY_UNVERIFIED and cannot enter fusion
    def test_legacy_event_classified_as_legacy_unverified_and_blocked(self):
        legacy_event = dict(self.base_event)
        legacy_event["detection_event_id"] = "det-legacy-unverified"
        del legacy_event["channel_epoch"]  # No epoch metadata

        res = self.client.post("/api/v1/detection-events", json_data=legacy_event, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["quarantine_status"], "LEGACY_UNVERIFIED")

        with get_db_connection() as conn:
            ev_row = conn.execute("SELECT quarantine_status, channel_epoch FROM events WHERE detection_event_id = 'det-legacy-unverified'").fetchone()
            self.assertEqual(ev_row["quarantine_status"], "LEGACY_UNVERIFIED")
            self.assertIsNone(ev_row["channel_epoch"], "Epoch must NOT be invented for legacy events")

        worker = FusionWorker()
        worker.process_batch()

        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = 'det-legacy-unverified'").fetchone()
            self.assertIsNone(row, "LEGACY_UNVERIFIED event must NOT enter fusion_event_state")

    # REQUIRED TEST 2: Verified active-epoch events remain eligible
    def test_verified_active_epoch_events_remain_eligible(self):
        active_event = dict(self.base_event)
        active_event["detection_event_id"] = "det-active-verified"
        active_event["channel_epoch"] = 1

        res = self.client.post("/api/v1/detection-events", json_data=active_event, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["quarantine_status"], "ACTIVE_VERIFIED")

        worker = FusionWorker()
        worker.process_batch()

        with get_db_connection() as conn:
            row = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'det-active-verified'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "PROCESSED")

    # REQUIRED TEST 3: Explicitly released events remain eligible
    def test_explicitly_released_events_remain_eligible(self):
        released_event = dict(self.base_event)
        released_event["detection_event_id"] = "det-released-01"
        with get_db_connection() as conn:
            data = json.dumps(released_event)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES ('det-released-01', ?, 'RELEASED', 'AGT-WIN-01', 'Security', 1)
            """, (data,))
            conn.commit()

        worker = FusionWorker()
        worker.process_batch()

        with get_db_connection() as conn:
            row = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'det-released-01'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "PROCESSED")

    # REQUIRED TEST 4: Retired and gap-quarantined events remain blocked
    def test_retired_and_gap_quarantined_events_remain_blocked(self):
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES ('det-blocked-gap', '{}', 'GAP_QUARANTINED', 'AGT-WIN-01', 'Security', 5)
            """)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES ('det-blocked-ret', '{}', 'RETIRED_EPOCH_DELAYED', 'AGT-WIN-01', 'Security', 1)
            """)
            conn.commit()

        worker = FusionWorker()
        worker.process_batch()

        with get_db_connection() as conn:
            row_gap = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = 'det-blocked-gap'").fetchone()
            self.assertIsNone(row_gap)
            row_ret = conn.execute("SELECT * FROM fusion_event_state WHERE detection_event_id = 'det-blocked-ret'").fetchone()
            self.assertIsNone(row_ret)

    # REQUIRED TEST 5: GovernanceWorker rejects an incident containing ineligible evidence
    def test_governance_worker_rejects_incident_with_ineligible_evidence(self):
        from app.governance_worker import GovernanceWorker
        inc_id = "inc-gov-ineligible"
        ass_id = "ass-gov-ineligible"
        ana_id = "ana-gov-ineligible"
        det_id = "det-gov-ineligible"
        now_iso = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            # Seed incident with LEGACY_UNVERIFIED evidence
            conn.execute("""
                INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at, latest_assessment_id, latest_analysis_id)
                VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?, ?, ?)
            """, (inc_id, now_iso, now_iso, now_iso, now_iso, ass_id, ana_id))

            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'LEGACY_UNVERIFIED', 'AGT-WIN-01', 'Security', NULL)
            """, (det_id,))

            conn.execute("""
                INSERT INTO incident_evidence (incident_id, detection_event_id)
                VALUES (?, ?)
            """, (inc_id, det_id))

            # Assessment
            conn.execute("""
                INSERT INTO assessments (assessment_id, incident_id, trust_score, risk_score, status, formula_version, config_version, input_snapshot, created_at)
                VALUES (?, ?, 0.9, 0.1, 'COMPLETED', '1', '1', '{}', ?)
            """, (ass_id, inc_id, now_iso))

            # Analysis
            ana_output = json.dumps({
                "status": "COMPLETED",
                "recommendations": [{"type": "ISOLATE_HOST", "reason": "High risk detected", "supporting_claims": ["c1"]}],
                "verification_results": [{"claim_id": "c1", "verification_status": "VERIFIED"}]
            })
            conn.execute("""
                INSERT INTO analyses (analysis_id, incident_id, assessment_id, assessment_snapshot, status, model_provenance, prompt_versions, analysis_output, created_at)
                VALUES (?, ?, ?, '{}', 'COMPLETED', 'mock', '{}', ?, ?)
            """, (ana_id, inc_id, ass_id, ana_output, now_iso))

            conn.commit()

        gov_worker = GovernanceWorker()
        gov_worker.run_once()

        with get_db_connection() as conn:
            state = conn.execute("SELECT status, approval_status, decision_id FROM governance_state WHERE incident_id = ?", (inc_id,)).fetchone()
            self.assertIsNotNone(state)
            self.assertEqual(state["status"], "DECIDED")
            self.assertEqual(state["approval_status"], "NOT_REQUIRED")

            decision = conn.execute("SELECT decision, reason FROM governance_decisions WHERE decision_id = ?", (state["decision_id"],)).fetchone()
            self.assertIsNotNone(decision)
            self.assertEqual(decision["decision"], "REJECT")
            self.assertIn("ineligible evidence", decision["reason"])

            # Zero endpoint commands dispatched
            cmds = conn.execute("SELECT count(*) as c FROM endpoint_commands WHERE parameters LIKE ?", (f'%"{inc_id}"%',)).fetchone()
            self.assertEqual(cmds["c"], 0)

    # REQUIRED TEST 6: response_bridge independently rejects ineligible evidence before dispatch
    def test_response_bridge_independently_rejects_ineligible_evidence(self):
        from app.response_bridge import dispatch_governed_response, IneligibleEvidenceError
        inc_id = "inc-rb-ineligible"
        det_id = "det-rb-ineligible"
        now_iso = datetime.now(timezone.utc).isoformat()

        for bad_status in ("LEGACY_UNVERIFIED", "GAP_QUARANTINED", "RETIRED_EPOCH_DELAYED"):
            with get_db_connection() as conn:
                conn.execute("DELETE FROM incident_evidence WHERE incident_id = ?", (inc_id,))
                conn.execute("DELETE FROM events WHERE detection_event_id = ?", (det_id,))
                conn.execute("DELETE FROM incidents WHERE incident_id = ?", (inc_id,))

                conn.execute("""
                    INSERT INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at)
                    VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)
                """, (inc_id, now_iso, now_iso, now_iso, now_iso))

                conn.execute("""
                    INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                    VALUES (?, '{}', ?, 'AGT-WIN-01', 'Security', 1)
                """, (det_id, bad_status))

                conn.execute("""
                    INSERT INTO incident_evidence (incident_id, detection_event_id)
                    VALUES (?, ?)
                """, (inc_id, det_id))
                conn.commit()

                # Call dispatch_governed_response -> must raise IneligibleEvidenceError
                with self.assertRaises(IneligibleEvidenceError) as ctx:
                    dispatch_governed_response(
                        conn,
                        inc_id,
                        recommendations=[{"type": "ISOLATE_HOST", "reason": "test"}],
                        approved_by="AUTONOMOUS_GOVERNANCE"
                    )
                self.assertIn("ineligible", str(ctx.exception).lower())

    # =========================================================================
    # WP-1E.4 Targeted Security Verification: Evidence Eligibility Tests (1-10)
    # =========================================================================

    def _seed_test_incident(self, conn, inc_id: str):
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT OR REPLACE INTO incidents (incident_id, status, max_severity, first_seen, last_seen, created_at, updated_at)
            VALUES (?, 'OPEN', 'HIGH', ?, ?, ?, ?)
        """, (inc_id, now_iso, now_iso, now_iso, now_iso))

    def _seed_test_endpoint(self, conn, agent_id: str, hostname: str = "WIN-TEST-01"):
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT OR REPLACE INTO endpoints (agent_id, hostname, os, ip_address, status, last_heartbeat)
            VALUES (?, ?, 'windows', '10.0.0.50', 'ONLINE', ?)
        """, (agent_id, hostname, now_iso))

    # Test 1: NULL quarantine_status with NULL epoch and missing identity
    def test_eligibility_null_quarantine_status_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-null-status-{uuid.uuid4()}"
        det_id = f"det-null-status-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', NULL, NULL, NULL, NULL)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("NULL quarantine_status", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("NULL quarantine_status", str(ctx.exception))

    # Test 2: Unknown status
    def test_eligibility_unknown_status_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-unknown-status-{uuid.uuid4()}"
        det_id = f"det-unknown-status-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'SOME_UNKNOWN_STATUS', 'AGT-WIN-01', 'Security', 1)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("ineligible or unknown status 'SOME_UNKNOWN_STATUS'", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("ineligible or unknown status", str(ctx.exception))

    # Test 3: ACTIVE_VERIFIED with missing channel record
    def test_eligibility_active_verified_missing_channel_record_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-no-ch-rec-{uuid.uuid4()}"
        det_id = f"det-no-ch-rec-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'ACTIVE_VERIFIED', 'AGT-UNKNOWN-CHANNEL', 'Security', 1)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("no authoritative channel epoch record", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("no authoritative channel epoch record", str(ctx.exception))

    # Test 4: ACTIVE_VERIFIED with mismatched epoch
    def test_eligibility_active_verified_mismatched_epoch_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-mismatched-{uuid.uuid4()}"
        det_id = f"det-mismatched-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            # Channel is active on epoch 2
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-WIN-01', 'Security', 2, 'ACTIVE', ?)
            """, (now_iso,))
            # Event has retired epoch 1
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'ACTIVE_VERIFIED', 'AGT-WIN-01', 'Security', 1)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("retired epoch 1 (active: 2)", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("retired epoch 1", str(ctx.exception))

    # Test 5: RELEASED with missing epoch
    def test_eligibility_released_missing_epoch_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-rel-no-ep-{uuid.uuid4()}"
        det_id = f"det-rel-no-ep-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-WIN-01', 'Security', 1, 'ACTIVE', ?)
            """, (now_iso,))
            # RELEASED with NULL channel_epoch
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', 'AGT-WIN-01', 'Security', NULL)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("missing channel_epoch", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("missing channel_epoch", str(ctx.exception))

    # Test 6: RELEASED on a quarantined channel
    def test_eligibility_released_quarantined_channel_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-rel-quar-ch-{uuid.uuid4()}"
        det_id = f"det-rel-quar-ch-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-WIN-01', 'Security', 2, 'EPOCH_GAP_QUARANTINED', ?)
            """, (now_iso,))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', 'AGT-WIN-01', 'Security', 1)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("quarantined channel 'Security'", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("quarantined channel", str(ctx.exception))

    # Test 7: RELEASED with invalid/future epoch
    def test_eligibility_released_invalid_or_future_epoch_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-rel-future-ep-{uuid.uuid4()}"
        det_id = f"det-rel-future-ep-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-WIN-01', 'Security', 2, 'ACTIVE', ?)
            """, (now_iso,))
            # RELEASED with future epoch 5 > active epoch 2
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', 'AGT-WIN-01', 'Security', 5)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("future epoch 5 exceeding active channel epoch 2", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("future epoch 5", str(ctx.exception))

    # Test 8: Valid ACTIVE_VERIFIED evidence
    def test_eligibility_valid_active_verified_accepted(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        inc_id = f"inc-valid-active-{uuid.uuid4()}"
        det_id = f"det-valid-active-{uuid.uuid4()}"
        agent_id = "AGT-WIN-VALID"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "evidence": {"process_name": "malicious.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            # Verification of autonomous response dispatch
            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Threat verified"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)
            self.assertEqual(dispatched[0]["command_type"], "ISOLATE_HOST")

    # Test 9: Valid RELEASED evidence
    def test_eligibility_valid_released_accepted(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        inc_id = f"inc-valid-released-{uuid.uuid4()}"
        det_id = f"det-valid-released-{uuid.uuid4()}"
        agent_id = "AGT-WIN-REL-VALID"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            # Active channel is at epoch 3
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Seed valid recovery provenance in channel_transitions with watermark 1
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions 
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-valid-rel', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "watermark": 1, "authorized_by": "ADMIN"})))

            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "transition_id": "t-valid-rel",
                "evidence": {"process_name": "malicious.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-valid-rel')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            # Verification of autonomous response dispatch
            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Released threat verified"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)
            self.assertEqual(dispatched[0]["command_type"], "ISOLATE_HOST")

    # Test 10: Incident with no evidence records
    def test_eligibility_zero_evidence_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-zero-ev-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn(f"incident {inc_id} has zero associated evidence records", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("zero associated evidence records", str(ctx.exception))

    # =========================================================================
    # WP-1E.4 Release Provenance & Watermark Verification Tests (1 - 5)
    # =========================================================================

    # Required Test 1: RELEASED retired epoch without valid recovery provenance is rejected
    def test_released_retired_epoch_without_valid_recovery_provenance_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-ret-no-prov-{uuid.uuid4()}"
        det_id = f"det-ret-no-prov-{uuid.uuid4()}"
        agent_id = "AGT-WIN-RET-01"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            # Channel is at epoch 3, status ACTIVE
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Standard EPOCH_ADVANCE transitions only (no recovery allocation, no recovery transition)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions 
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('trans-adv-2', ?, 'Security', 'Security', 2, 'EPOCH_ADVANCE', ?, '{}')
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions 
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('trans-adv-3', ?, 'Security', 'Security', 3, 'EPOCH_ADVANCE', ?, '{}')
            """, (agent_id, now_iso))
            # Event has retired epoch 1, marked RELEASED
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 1)
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("lacks valid approved recovery provenance", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("lacks valid approved recovery provenance", str(ctx.exception))

    # Required Test 2: RELEASED retired epoch with valid approved recovery provenance follows watermark rules
    def test_released_retired_epoch_with_valid_recovery_provenance_follows_watermark_rules(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-WM-01"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            # Channel is active at epoch 3
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Recovery transition has watermark threshold = 1
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions 
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-rec-wm', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "watermark": 1, "authorized_by": "ADMIN"})))

            # Subcase 2A: Event at epoch 2 > watermark 1 (within valid recovery scope) -> ACCEPTED
            inc_id_ok = f"inc-wm-ok-{uuid.uuid4()}"
            det_id_ok = f"det-wm-ok-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_ok)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-rec-wm')
            """, (det_id_ok, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_ok, det_id_ok))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_ok, agent_id))

            # Subcase 2B: Event at epoch 1 <= watermark 1 (retired by watermark) -> REJECTED
            inc_id_bad = f"inc-wm-bad-{uuid.uuid4()}"
            det_id_bad = f"det-wm-bad-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_bad)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 1, 't-rec-wm')
            """, (det_id_bad, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_bad, det_id_bad))

            conn.commit()

            # Verify 2A accepted
            is_ok, reason_ok = check_incident_evidence_eligibility(conn, inc_id_ok)
            self.assertTrue(is_ok)
            self.assertIsNone(reason_ok)

            # Verify 2B rejected
            is_bad, reason_bad = check_incident_evidence_eligibility(conn, inc_id_bad)
            self.assertFalse(is_bad)
            self.assertIn("retired by watermark threshold 1", reason_bad)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id_bad, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("retired by watermark threshold 1", str(ctx.exception))

    # Required Test 3: RELEASED event with mismatched agent/channel recovery scope is rejected
    def test_released_event_with_mismatched_agent_channel_recovery_scope_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-scope-mismatch-{uuid.uuid4()}"
        det_id = f"det-scope-mismatch-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            # Channel is active for AGT-WIN-01 on Security
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-WIN-01', 'Security', 3, 'ACTIVE', ?)
            """, (now_iso,))
            # Recovery record exists ONLY for a different agent (AGT-WIN-OTHER) on Security
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger 
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-diff-agent', 'AGT-WIN-OTHER', 'Security', 'CRASH_RECOVERY', 3, ?)
            """, (now_iso,))
            # Event belongs to AGT-WIN-01 on Security
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', 'AGT-WIN-01', 'Security', 2)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("has no approved recovery or transition record for AGT-WIN-01/Security", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("has no approved recovery or transition record", str(ctx.exception))

    # Required Test 4: RELEASED event with no recovery/transition record is rejected
    def test_released_event_with_no_recovery_transition_record_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        inc_id = f"inc-no-rec-trans-{uuid.uuid4()}"
        det_id = f"det-no-rec-trans-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-NO-TRANS', 'Security', 2, 'ACTIVE', ?)
            """, (now_iso,))
            # No rows in channel_transitions and no rows in epoch_allocation_ledger
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', 'AGT-NO-TRANS', 'Security', 2)
            """, (det_id,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("has no approved recovery or transition record for AGT-NO-TRANS/Security", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("has no approved recovery or transition record", str(ctx.exception))

    # Required Test 5: Invalid current_epoch or unknown channel status is rejected
    def test_invalid_current_epoch_or_unknown_channel_status_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            # Subcase 5A: Invalid current_epoch (0 or <= 0)
            inc_id_inv_ep = f"inc-inv-ep-{uuid.uuid4()}"
            det_id_inv_ep = f"det-inv-ep-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_inv_ep)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-INV-EP', 'Security', 0, 'ACTIVE', ?)
            """, (now_iso,))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'ACTIVE_VERIFIED', 'AGT-INV-EP', 'Security', 1)
            """, (det_id_inv_ep,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_inv_ep, det_id_inv_ep))

            # Subcase 5B: Unknown channel status (e.g. 'UNKNOWN' or 'CORRUPTED')
            inc_id_unk_st = f"inc-unk-st-{uuid.uuid4()}"
            det_id_unk_st = f"det-unk-st-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_unk_st)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES ('AGT-UNK-ST', 'Security', 1, 'CORRUPTED', ?)
            """, (now_iso,))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'ACTIVE_VERIFIED', 'AGT-UNK-ST', 'Security', 1)
            """, (det_id_unk_st,))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_unk_st, det_id_unk_st))

            conn.commit()

            # Verify 5A rejected
            is_inv, reason_inv = check_incident_evidence_eligibility(conn, inc_id_inv_ep)
            self.assertFalse(is_inv)
            self.assertIn("invalid current_epoch '0'", reason_inv)
            with self.assertRaises(IneligibleEvidenceError):
                dispatch_governed_response(conn, inc_id_inv_ep, [{"type": "ISOLATE_HOST", "reason": "test"}])

            # Verify 5B rejected
            is_unk, reason_unk = check_incident_evidence_eligibility(conn, inc_id_unk_st)
            self.assertFalse(is_unk)
            self.assertIn("invalid or unaccepted status 'CORRUPTED'", reason_unk)
            with self.assertRaises(IneligibleEvidenceError):
                dispatch_governed_response(conn, inc_id_unk_st, [{"type": "ISOLATE_HOST", "reason": "test"}])

    # =========================================================================
    # WP-1E.4 Targeted Hardening: Adversarial Tests
    # =========================================================================

    # 1. Unrelated allocation for the same agent/channel
    def test_adversarial_unrelated_allocation_same_agent_channel_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-ADV-01"
        inc_id = f"inc-unrel-alloc-{uuid.uuid4()}"
        det_id = f"det-unrel-alloc-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 5, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Allocation exists for epoch 4, but event is at retired epoch 2
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-other-req', ?, 'Security', 'CRASH_RECOVERY', 4, ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2)
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("lacks valid approved recovery provenance", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("lacks valid approved recovery provenance", str(ctx.exception))

    # 2. Invalid or unauthorized recovery reason/status
    def test_adversarial_invalid_or_unauthorized_recovery_reason_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        now_iso = datetime.now(timezone.utc).isoformat()

        # 2A: Unauthorized recovery reason in allocation
        agent_id_a = "AGT-WIN-ADV-02A"
        inc_id_alloc = f"inc-unauth-alloc-{uuid.uuid4()}"
        det_id_alloc = f"det-unauth-alloc-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id_alloc)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id_a, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-unauth-01', ?, 'Security', 'UNAUTHORIZED_RECOVERY_ATTEMPT', 2, ?)
            """, (agent_id_a, now_iso))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id_alloc, json.dumps({"recovery_request_id": "rec-unauth-01"}), agent_id_a))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_alloc, det_id_alloc))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id_alloc)
            self.assertFalse(is_eligible)
            self.assertIn("unauthorized or invalid recovery_reason", reason)

            with self.assertRaises(IneligibleEvidenceError):
                dispatch_governed_response(conn, inc_id_alloc, [{"type": "ISOLATE_HOST", "reason": "test"}])

        # 2B: Unauthorized reason in transition payload
        agent_id_b = "AGT-WIN-ADV-02B"
        inc_id_trans = f"inc-unauth-trans-{uuid.uuid4()}"
        det_id_trans = f"det-unauth-trans-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id_trans)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id_b, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-unauth-trans', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id_b, now_iso, json.dumps({"reason": "UNAUTHORIZED_ADMIN_OVERRIDE"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-unauth-trans')
            """, (det_id_trans, agent_id_b))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_trans, det_id_trans))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id_trans)
            self.assertFalse(is_eligible)
            self.assertIn("unauthorized recovery reason", reason)

            with self.assertRaises(IneligibleEvidenceError):
                dispatch_governed_response(conn, inc_id_trans, [{"type": "ISOLATE_HOST", "reason": "test"}])

    # 3. Wrong source epoch with matching target epoch
    def test_adversarial_wrong_source_epoch_with_matching_target_epoch_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-ADV-03"
        inc_id = f"inc-wrong-src-ep-{uuid.uuid4()}"
        det_id = f"det-wrong-src-ep-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 4, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition covers target_epoch 3, but source_epoch is 2 (so scope is epochs 2..3)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-src-scope', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 2, "authorized_by": "ADMIN"})))
            # Event has retired epoch 1 (< source_epoch 2)
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 1, 't-src-scope')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("outside transition t-src-scope source scope", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("outside transition", str(ctx.exception))

    # 4. EPOCH_ADVANCE attempting to authorize retired evidence
    def test_adversarial_epoch_advance_attempting_to_authorize_retired_evidence_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-ADV-04"
        inc_id = f"inc-adv-ret-{uuid.uuid4()}"
        det_id = f"det-adv-ret-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Target epoch is 3, but transition_type is EPOCH_ADVANCE
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-adv-3', ?, 'Security', 'Security', 3, 'EPOCH_ADVANCE', ?, '{}')
            """, (agent_id, now_iso))
            # Retired epoch 1
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 1, 't-adv-3')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("lacks valid approved recovery provenance", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("lacks valid approved recovery provenance", str(ctx.exception))

    # 5. Malformed JSON and watermark
    def test_adversarial_malformed_json_and_watermark_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        now_iso = datetime.now(timezone.utc).isoformat()

        # 5A: Malformed JSON payload string in transition
        agent_id_a = "AGT-WIN-ADV-05A"
        inc_id_json = f"inc-bad-json-{uuid.uuid4()}"
        det_id_json = f"det-bad-json-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id_json)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id_a, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-bad-json', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, '{invalid json')
            """, (agent_id_a, now_iso))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-bad-json')
            """, (det_id_json, agent_id_a))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_json, det_id_json))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id_json)
            self.assertFalse(is_eligible)
            self.assertIn("malformed JSON payload", reason)

            with self.assertRaises(IneligibleEvidenceError):
                dispatch_governed_response(conn, inc_id_json, [{"type": "ISOLATE_HOST", "reason": "test"}])

        # 5B: Malformed watermark structure (missing required scope)
        agent_id_b = "AGT-WIN-ADV-05B"
        inc_id_wm = f"inc-bad-wm-{uuid.uuid4()}"
        det_id_wm = f"det-bad-wm-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id_wm)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id_b, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-bad-wm', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id_b, now_iso, json.dumps({"watermark": {"other_agent:System": 1}})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-bad-wm')
            """, (det_id_wm, agent_id_b))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_wm, det_id_wm))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id_wm)
            self.assertFalse(is_eligible)
            self.assertIn("missing required source scope", reason)

            with self.assertRaises(IneligibleEvidenceError):
                dispatch_governed_response(conn, inc_id_wm, [{"type": "ISOLATE_HOST", "reason": "test"}])

    # 6. Boolean watermark rejected
    def test_adversarial_boolean_watermark_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-ADV-06"
        inc_id = f"inc-bool-wm-{uuid.uuid4()}"
        det_id = f"det-bool-wm-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-bool-wm', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"watermark": True})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-bool-wm')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("invalid boolean watermark", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("invalid boolean watermark", str(ctx.exception))

    # 7. Cross-source recovery scope rejected
    def test_adversarial_cross_source_recovery_scope_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-ADV-07"
        inc_id = f"inc-cross-src-{uuid.uuid4()}"
        det_id = f"det-cross-src-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition payload explicitly scopes source_agent_id to a different agent
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-cross-src', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_agent_id": "AGT-WIN-DIFFERENT"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-cross-src')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("cross-source agent mismatch", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("cross-source agent mismatch", str(ctx.exception))

    # =========================================================================
    # WP-1E.4 ROUND 4/4: FINAL FOCUSED ADVERSARIAL TESTS (1-10)
    # =========================================================================

    # Test 1: Active-epoch RELEASED event with unauthorized allocation
    def test_r4_adversarial_1_active_epoch_released_unauthorized_allocation_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-01"
        inc_id = f"inc-r4-unauth-alloc-{uuid.uuid4()}"
        det_id = f"det-r4-unauth-alloc-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-r4-unauth', ?, 'Security', 'UNAUTHORIZED_RECOVERY_ATTEMPT', 2, ?)
            """, (agent_id, now_iso))
            ev_data = {"recovery_request_id": "rec-r4-unauth"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("unauthorized or invalid recovery_reason", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("unauthorized or invalid recovery_reason", str(ctx.exception))

    # Test 2: Active-epoch RELEASED event with unrelated transition
    def test_r4_adversarial_2_active_epoch_released_unrelated_transition_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-02"
        inc_id = f"inc-r4-unrel-trans-{uuid.uuid4()}"
        det_id = f"det-r4-unrel-trans-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Only EPOCH_ADVANCE exists (disqualified from recovery authorization)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-r4-adv', ?, 'Security', 'Security', 2, 'EPOCH_ADVANCE', ?, '{}')
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-r4-adv')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("lacks valid approved recovery provenance", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("lacks valid approved recovery provenance", str(ctx.exception))

    # Test 3: Allocation authorization with missing recovery_request_id
    def test_r4_adversarial_3_allocation_missing_recovery_request_id_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-03"
        inc_id = f"inc-r4-no-req-id-{uuid.uuid4()}"
        det_id = f"det-r4-no-req-id-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-r4-valid', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Event has NO recovery_request_id
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2)
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("allocation authorization requires non-empty recovery_request_id", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("allocation authorization requires non-empty recovery_request_id", str(ctx.exception))

    # Test 4: Allocation authorization with mismatched recovery_request_id
    def test_r4_adversarial_4_allocation_mismatched_recovery_request_id_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-04"
        inc_id = f"inc-r4-mis-req-id-{uuid.uuid4()}"
        det_id = f"det-r4-mis-req-id-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-r4-expected', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Event has mismatched recovery_request_id
            ev_data = {"recovery_request_id": "rec-r4-different"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("does not match allocation", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("does not match allocation", str(ctx.exception))

    # Test 5: Transition authorization missing required source epoch or source identity
    def test_r4_adversarial_5_transition_missing_source_epoch_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-05"
        inc_id = f"inc-r4-no-src-ep-{uuid.uuid4()}"
        det_id = f"det-r4-no-src-ep-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition missing source_epoch in payload
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-r4-no-src-ep', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"authorized_by": "SOC_ADMIN"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-r4-no-src-ep')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("missing required source_epoch", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("missing required source_epoch", str(ctx.exception))

    # Test 6: Transition with invalid or missing authorization state
    def test_r4_adversarial_6_transition_unauthorized_auth_state_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-06"
        inc_id = f"inc-r4-unauth-trans-{uuid.uuid4()}"
        det_id = f"det-r4-unauth-trans-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition has unauthorized actor in authorized_by
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-r4-bad-auth', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "authorized_by": "UNAUTHORIZED_OPERATOR"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-r4-bad-auth')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("unauthorized recovery authorization state", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("unauthorized recovery authorization state", str(ctx.exception))

    # Test 7: Allocation-based authorization attempting to bypass source watermark
    def test_r4_adversarial_7_allocation_cannot_bypass_source_watermark_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-R4-07"
        inc_id = f"inc-r4-wm-bypass-{uuid.uuid4()}"
        det_id = f"det-r4-wm-bypass-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Allocation exists with valid reason and matching request ID for epoch 2
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-r4-wm', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Channel transition establishes source watermark threshold = 2 (retiring epoch 2)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-r4-wm-threshold', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "watermark": 2, "authorized_by": "SOC_LEAD"})))

            ev_data = {"recovery_request_id": "rec-r4-wm", "transition_id": "t-r4-wm-threshold"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-r4-wm-threshold')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("retired by watermark threshold 2", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("retired by watermark threshold 2", str(ctx.exception))

    # Test 8: Valid active-epoch RELEASED evidence under the approved authorization contract
    def test_r4_adversarial_8_valid_active_epoch_released_evidence_accepted(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        agent_id = "AGT-WIN-R4-08"
        inc_id = f"inc-r4-valid-active-{uuid.uuid4()}"
        det_id = f"det-r4-valid-active-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-r4-active-ok', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))

            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "recovery_request_id": "rec-r4-active-ok",
                "evidence": {"process_name": "malicious_active.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Threat verified on active epoch"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)
            self.assertEqual(dispatched[0]["command_type"], "ISOLATE_HOST")

    # Test 9: Valid retired-epoch recovery evidence under the approved authorization contract
    def test_r4_adversarial_9_valid_retired_epoch_recovery_evidence_accepted(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        agent_id = "AGT-WIN-R4-09"
        inc_id = f"inc-r4-valid-ret-{uuid.uuid4()}"
        det_id = f"det-r4-valid-ret-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-r4-ret-valid', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "watermark": 1, "authorized_by": "SOC_ADMIN"})))

            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "transition_id": "t-r4-ret-valid",
                "evidence": {"process_name": "malicious_retired.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-r4-ret-valid')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Released threat verified"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)
            self.assertEqual(dispatched[0]["command_type"], "ISOLATE_HOST")

    # Test 10: WP-1C Local SAM versus domain-account dispatch regression
    def test_r4_adversarial_10_wp1c_local_sam_vs_domain_account_dispatch_regression(self):
        from app.response_bridge import (
            dispatch_governed_response,
            validate_account_target_record,
            AccountTargetRecord
        )
        agent_id = "AGT-WIN-R4-10"
        inc_id = f"inc-r4-wp1c-{uuid.uuid4()}"
        det_id = f"det-r4-wp1c-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))

            # 10A: LOCAL_SAM account on matching endpoint succeeds
            ev_data_local = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "hostname": "WIN-TEST-01",
                "channel": "Security",
                "channel_epoch": 1,
                "evidence": {
                    "target_account_id": "LOCAL_SAM\\baduser",
                    "target_user": "baduser",
                    "domain_status": "LOCAL_SAM",
                    "domain_namespace": "LOCAL_SAM"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 1)
            """, (det_id, json.dumps(ev_data_local), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "DISABLE_ACCOUNT", "reason": "Local brute force attack"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["command_type"], "DISABLE_ACCOUNT")
            self.assertEqual(dispatched[0]["agent_id"], agent_id)
            self.assertEqual(dispatched[0]["parameters"]["username"], "baduser")
            self.assertEqual(dispatched[0]["parameters"]["domain"], "LOCAL_SAM")

            # 10B: DOMAIN account is escalated with ZERO local endpoint commands dispatched
            inc_id_domain = f"inc-r4-domain-{uuid.uuid4()}"
            det_id_domain = f"det-r4-domain-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_domain)
            ev_data_dom = {
                "detection_event_id": det_id_domain,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 1,
                "evidence": {
                    "target_account_id": "DOMAIN:CORP\\corpadmin",
                    "target_user": "corpadmin",
                    "domain_status": "OBSERVED_DOMAIN",
                    "domain_namespace": "DOMAIN:CORP",
                    "target_domain": "CORP"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 1)
            """, (det_id_domain, json.dumps(ev_data_dom), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_domain, det_id_domain))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_domain, agent_id))
            conn.commit()

            dispatched_dom = dispatch_governed_response(conn, inc_id_domain, [{"type": "DISABLE_ACCOUNT", "reason": "Domain account test"}])
            self.assertEqual(len(dispatched_dom), 0)
            rows = conn.execute("SELECT count(*) as c FROM endpoint_commands WHERE agent_id = ?", (agent_id,)).fetchone()
            self.assertEqual(rows["c"], 1)  # Only the previous LOCAL_SAM command, 0 for DOMAIN

            # 10C: Contradictory account target raises ValueError
            with self.assertRaises(ValueError):
                validate_account_target_record(AccountTargetRecord(
                    target_account_id="LOCAL_SAM\\contradictory",
                    target_user="contradictory",
                    target_domain=None,
                    domain_status="LOCAL_SAM",
                    domain_namespace="DOMAIN:CORP",
                    target_agent_id=agent_id,
                    target_hostname="WIN-TEST",
                    originating_detection_event_id=det_id
                ))

    # =========================================================================
    # WP-1E.4R: BOUNDED P0 SECURITY REMEDIATION TESTS (12 Required Tests)
    # =========================================================================

    # 1. Arbitrary authorization status rejected
    def test_wp1e4r_1_arbitrary_authorization_status_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-01"
        inc_id = f"inc-1e4r-arb-{uuid.uuid4()}"
        det_id = f"det-1e4r-arb-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition with arbitrary authorization status 'FOOBAR'
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-foobar', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "status": "FOOBAR", "reason": "CRASH_RECOVERY"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-1e4r-foobar')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("unapproved status 'FOOBAR'", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("unapproved status 'FOOBAR'", str(ctx.exception))

    # 2. Missing authorization status rejected
    def test_wp1e4r_2_missing_authorization_status_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-02"
        inc_id = f"inc-1e4r-missing-{uuid.uuid4()}"
        det_id = f"det-1e4r-missing-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition completely missing authorization status and actor
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-missing', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "reason": "CRASH_RECOVERY"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-1e4r-missing')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("missing authorization state or trusted actor", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("missing authorization state or trusted actor", str(ctx.exception))

    # 3. Actor identity cannot substitute for authorization status
    def test_wp1e4r_3_actor_identity_cannot_substitute_for_authorization_status(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-03"
        inc_id = f"inc-1e4r-actor-as-status-{uuid.uuid4()}"
        det_id = f"det-1e4r-actor-as-status-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Actor identity 'SOC_ADMIN' supplied as authorization_status
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-actor-as-status', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "authorization_status": "SOC_ADMIN", "reason": "CRASH_RECOVERY"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-1e4r-actor-as-status')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("actor identity 'SOC_ADMIN' supplied as authorization_status", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("actor identity 'SOC_ADMIN' supplied as authorization_status", str(ctx.exception))

    # 4. Untrusted actor rejected
    def test_wp1e4r_4_untrusted_actor_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-04"
        inc_id = f"inc-1e4r-untrusted-{uuid.uuid4()}"
        det_id = f"det-1e4r-untrusted-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Untrusted actor in authorized_by
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-untrusted', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "authorized_by": "UNTRUSTED_OPERATOR", "reason": "CRASH_RECOVERY"})))
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, '{}', 'RELEASED', ?, 'Security', 2, 't-1e4r-untrusted')
            """, (det_id, agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("untrusted actor 'UNTRUSTED_OPERATOR'", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("untrusted actor 'UNTRUSTED_OPERATOR'", str(ctx.exception))

    # 5. Valid approved authorization accepted
    def test_wp1e4r_5_valid_approved_authorization_accepted(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        agent_id = "AGT-WIN-1E4R-05"
        inc_id = f"inc-1e4r-valid-auth-{uuid.uuid4()}"
        det_id = f"det-1e4r-valid-auth-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Valid approved authorization with trusted actor and approved status
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-valid-auth', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({
                "source_epoch": 1,
                "watermark": 1,
                "authorized_by": "SOC_ADMIN",
                "status": "APPROVED",
                "reason": "CRASH_RECOVERY"
            })))
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "transition_id": "t-1e4r-valid-auth",
                "evidence": {"process_name": "malware.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-1e4r-valid-auth')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Mitigation verified"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)

    # 6. Retired-epoch allocation without authoritative transition rejected
    def test_wp1e4r_6_retired_epoch_allocation_without_authoritative_transition_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-06"
        inc_id = f"inc-1e4r-ret-alloc-no-trans-{uuid.uuid4()}"
        det_id = f"det-1e4r-ret-alloc-no-trans-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Scoped allocation exists for retired epoch 2
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-1e4r-alloc-alone', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # No channel transition exists!
            ev_data = {"recovery_request_id": "rec-1e4r-alloc-alone"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("cannot be authorized by allocation alone; requires authoritative recovery transition", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("cannot be authorized by allocation alone; requires authoritative recovery transition", str(ctx.exception))

    # 7. Retired-epoch allocation with unrelated transition rejected
    def test_wp1e4r_7_retired_epoch_allocation_with_unrelated_transition_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-07"
        inc_id = f"inc-1e4r-ret-alloc-unrel-{uuid.uuid4()}"
        det_id = f"det-1e4r-ret-alloc-unrel-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-1e4r-unrel', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Transition exists, but is a normal EPOCH_ADVANCE (unrelated to recovery)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-epoch-adv', ?, 'Security', 'Security', 3, 'EPOCH_ADVANCE', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 2, "authorized_by": "ADMIN"})))
            ev_data = {"recovery_request_id": "rec-1e4r-unrel"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("cannot be authorized by allocation alone; requires authoritative recovery transition", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("cannot be authorized by allocation alone; requires authoritative recovery transition", str(ctx.exception))

    # 8. Retired-epoch allocation with valid matching recovery transition accepted
    def test_wp1e4r_8_retired_epoch_allocation_with_valid_matching_recovery_transition_accepted(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        agent_id = "AGT-WIN-1E4R-08"
        inc_id = f"inc-1e4r-ret-alloc-valid-{uuid.uuid4()}"
        det_id = f"det-1e4r-ret-alloc-valid-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-1e4r-both-ok', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Authoritative matching recovery transition with watermark 1 (retires epoch 1, admitting epoch 2)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-rec-match', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({
                "source_epoch": 1,
                "watermark": 1,
                "authorized_by": "SOC_ADMIN",
                "status": "APPROVED",
                "reason": "CRASH_RECOVERY"
            })))
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "recovery_request_id": "rec-1e4r-both-ok",
                "transition_id": "t-1e4r-rec-match",
                "evidence": {"process_name": "recovered_incident.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-1e4r-rec-match')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Test response"}])
            self.assertEqual(len(dispatched), 1)

    # 9. Retired evidence below or at the retirement watermark rejected
    def test_wp1e4r_9_retired_evidence_below_or_at_retirement_watermark_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-09"
        inc_id = f"inc-1e4r-at-watermark-{uuid.uuid4()}"
        det_id = f"det-1e4r-at-watermark-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 4, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-1e4r-wm-rej', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Transition sets watermark = 2 (explicitly retiring epoch 2 and below)
            conn.execute("""
                INSERT OR REPLACE INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-1e4r-wm-retires-2', ?, 'Security', 'Security', 4, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({
                "source_epoch": 1,
                "watermark": 2,
                "authorized_by": "SOC_ADMIN",
                "status": "APPROVED",
                "reason": "CRASH_RECOVERY"
            })))
            ev_data = {"recovery_request_id": "rec-1e4r-wm-rej", "transition_id": "t-1e4r-wm-retires-2"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-1e4r-wm-retires-2')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("retired by watermark threshold 2", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("retired by watermark threshold 2", str(ctx.exception))

    # 10. Active-epoch evidence with invalid provenance rejected
    def test_wp1e4r_10_active_epoch_evidence_with_invalid_provenance_rejected(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response, IneligibleEvidenceError
        agent_id = "AGT-WIN-1E4R-10"
        inc_id = f"inc-1e4r-active-inv-prov-{uuid.uuid4()}"
        det_id = f"det-1e4r-active-inv-prov-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-1e4r-expected-req', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            # Event supplies mismatched recovery_request_id
            ev_data = {"recovery_request_id": "rec-1e4r-wrong-req"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("does not match allocation 'rec-1e4r-expected-req'", reason)

            with self.assertRaises(IneligibleEvidenceError) as ctx:
                dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "test"}])
            self.assertIn("does not match allocation", str(ctx.exception))

    # 11. Valid active-epoch evidence preserved
    def test_wp1e4r_11_valid_active_epoch_evidence_preserved(self):
        from app.response_bridge import check_incident_evidence_eligibility, dispatch_governed_response
        agent_id = "AGT-WIN-1E4R-11"
        inc_id = f"inc-1e4r-valid-active-{uuid.uuid4()}"
        det_id = f"det-1e4r-valid-active-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 2, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT OR REPLACE INTO epoch_allocation_ledger
                (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
                VALUES ('rec-1e4r-valid-act', ?, 'Security', 'CRASH_RECOVERY', 2, ?)
            """, (agent_id, now_iso))
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "recovery_request_id": "rec-1e4r-valid-act",
                "evidence": {"process_name": "active_exploit.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Active threat response"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)

    # 12. WP-1C Local SAM versus domain-account dispatch regression preserved
    def test_wp1e4r_12_wp1c_local_sam_vs_domain_account_dispatch_regression_preserved(self):
        from app.response_bridge import (
            check_incident_evidence_eligibility,
            dispatch_governed_response,
            validate_account_target_record,
            AccountTargetRecord
        )
        agent_id = "AGT-WIN-1E4R-12"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            # 12A: LOCAL_SAM account generates local endpoint command
            inc_id_local = f"inc-1e4r-sam-{uuid.uuid4()}"
            det_id_local = f"det-1e4r-sam-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_local)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            ev_data_local = {
                "detection_event_id": det_id_local,
                "agent_id": agent_id,
                "hostname": "WIN-TEST-01",
                "channel": "Security",
                "channel_epoch": 1,
                "evidence": {
                    "target_account_id": "LOCAL_SAM\\alice",
                    "target_user": "alice",
                    "domain_status": "LOCAL_SAM",
                    "domain_namespace": "LOCAL_SAM"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 1)
            """, (det_id_local, json.dumps(ev_data_local), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_local, det_id_local))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_local, agent_id))
            conn.commit()

            dispatched = dispatch_governed_response(conn, inc_id_local, [{"type": "DISABLE_ACCOUNT", "reason": "Local compromise"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["command_type"], "DISABLE_ACCOUNT")
            self.assertEqual(dispatched[0]["parameters"]["username"], "alice")
            self.assertEqual(dispatched[0]["parameters"]["domain"], "LOCAL_SAM")

            # 12B: DOMAIN account generates zero local endpoint commands
            inc_id_domain = f"inc-1e4r-domain-{uuid.uuid4()}"
            det_id_domain = f"det-1e4r-domain-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_domain)
            ev_data_domain = {
                "detection_event_id": det_id_domain,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 1,
                "evidence": {
                    "target_account_id": "DOMAIN:CORP\\bob",
                    "target_user": "bob",
                    "domain_status": "OBSERVED_DOMAIN",
                    "domain_namespace": "DOMAIN:CORP",
                    "target_domain": "CORP"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 1)
            """, (det_id_domain, json.dumps(ev_data_domain), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_domain, det_id_domain))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_domain, agent_id))
            conn.commit()

            dispatched_dom = dispatch_governed_response(conn, inc_id_domain, [{"type": "DISABLE_ACCOUNT", "reason": "Domain compromise"}])
            self.assertEqual(len(dispatched_dom), 0)

            # 12C: Contradictory account target raises ValueError
            with self.assertRaises(ValueError):
                validate_account_target_record(AccountTargetRecord(
                    target_account_id="LOCAL_SAM\\contradictory",
                    target_user="contradictory",
                    target_domain=None,
                    domain_status="LOCAL_SAM",
                    domain_namespace="DOMAIN:CORP",
                    target_agent_id=agent_id,
                    target_hostname="WIN-TEST",
                    originating_detection_event_id=det_id_local
                ))

    # =========================================================================
    # WP-1E.4S: AUTHORIZATION TRUST BOUNDARY & INTEGRITY TESTS (15 Required Tests)
    # =========================================================================

    # Test 1: Endpoint API token cannot perform administrative gap resolution (403)
    def test_wp1e4s_1_endpoint_token_cannot_perform_admin_gap_resolution(self):
        # Ingest event to quarantined channel
        agent_id = "AGT-WIN-1E4S-01"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'EPOCH_GAP_QUARANTINED', ?)
            """, (agent_id, now_iso))
            conn.commit()

        # Attempt A: Calling /resolve_gap with endpoint token (self.headers)
        res_gap = self.client.post(
            f"/api/v1/agents/{agent_id}/channels/Security/resolve_gap",
            json_data={"target_epoch": 2, "resolution_reason": "Attacker gap override"},
            headers=self.headers
        )
        self.assertEqual(res_gap.status_code, 403)
        self.assertIn("Endpoint credentials cannot perform administrative operations", res_gap.json()["detail"])

        # Attempt B: Calling /api/v1/events/transition with recovery transition type using endpoint token
        res_trans = self.client.post(
            "/api/v1/events/transition",
            json_data={
                "transition_id": "trans-forged-admin",
                "agent_id": agent_id,
                "source_channel": "Security",
                "target_channel": "Security",
                "target_epoch": 2,
                "transition_type": "ADMINISTRATIVE_GAP_RESOLUTION",
                "payload": {"source_epoch": 1, "authorized_by": "SOC_ADMIN"}
            },
            headers=self.headers
        )
        self.assertEqual(res_trans.status_code, 403)
        self.assertIn("Endpoint credentials cannot perform administrative operations", res_trans.json()["detail"])

    # Test 2: Missing administrator credential is rejected (401 / 500 fail closed)
    def test_wp1e4s_2_missing_admin_credential_rejected(self):
        agent_id = "AGT-WIN-1E4S-02"
        # 2A: Calling without Authorization header
        res_no_auth = self.client.post(
            f"/api/v1/agents/{agent_id}/channels/Security/resolve_gap",
            json_data={"target_epoch": 2},
            headers={}
        )
        self.assertEqual(res_no_auth.status_code, 401)
        self.assertIn("Missing or invalid Authorization header", res_no_auth.json()["detail"])

        # 2B: Administrative token not configured in server environment fails closed
        old_token = os.environ.get("SOC_ADMIN_API_TOKEN")
        try:
            os.environ.pop("SOC_ADMIN_API_TOKEN", None)
            os.environ.pop("SOC_ADMIN_TOKEN", None)
            with self.assertRaises(HTTPException) as ctx:
                verify_admin_token(f"Bearer {ADMIN_API_TOKEN}")
            self.assertEqual(ctx.exception.status_code, 500)
            self.assertIn("failing closed", ctx.exception.detail)
        finally:
            if old_token is not None:
                os.environ["SOC_ADMIN_API_TOKEN"] = old_token

    # Test 3: Invalid administrator credential is rejected (401)
    def test_wp1e4s_3_invalid_admin_credential_rejected(self):
        agent_id = "AGT-WIN-1E4S-03"
        res = self.client.post(
            f"/api/v1/agents/{agent_id}/channels/Security/resolve_gap",
            json_data={"target_epoch": 2},
            headers={"Authorization": "Bearer invalid-admin-token-xyz"}
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid administrator credentials", res.json()["detail"])

    # Test 4: Valid administrator credential permits approved administrative workflow (200)
    def test_wp1e4s_4_valid_admin_credential_permits_approved_workflow(self):
        agent_id = "AGT-WIN-1E4S-04"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'EPOCH_GAP_QUARANTINED', ?)
            """, (agent_id, now_iso))
            conn.commit()

        res = self.client.post(
            f"/api/v1/agents/{agent_id}/channels/Security/resolve_gap",
            json_data={
                "target_epoch": 3,
                "resolution_reason": "Authorized SOC lead remediation",
                "recovery_request_id": "rec-1e4s-04"
            },
            headers={"Authorization": f"Bearer {ADMIN_API_TOKEN}"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(data["active_epoch"], 3)

        # Verify DB transition record has server-derived SOC_ADMIN
        with get_db_connection() as conn:
            t_row = conn.execute(
                "SELECT * FROM channel_transitions WHERE agent_id = ? AND target_epoch = 3",
                (agent_id,)
            ).fetchone()
            self.assertIsNotNone(t_row)
            p = json.loads(t_row["payload"])
            self.assertEqual(p["authorized_by"], "SOC_ADMIN")
            self.assertEqual(p["status"], "RESOLVED")

    # Test 5: Caller-supplied SOC_ADMIN actor cannot override authenticated actor identity
    def test_wp1e4s_5_caller_supplied_actor_cannot_override_authenticated_identity(self):
        agent_id = "AGT-WIN-1E4S-05"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.commit()

        # Endpoint attempts to advance epoch while claiming authorized_by: "SOC_ADMIN" and status: "APPROVED"
        res = self.client.post(
            "/api/v1/events/transition",
            json_data={
                "transition_id": "trans-spoofed-actor",
                "agent_id": agent_id,
                "source_channel": "Security",
                "target_channel": "Security",
                "target_epoch": 2,
                "transition_type": "EPOCH_ADVANCE",
                "payload": {
                    "source_epoch": 1,
                    "authorized_by": "SOC_ADMIN",
                    "status": "APPROVED",
                    "reason": "CRASH_RECOVERY"
                }
            },
            headers=self.headers  # endpoint token
        )
        self.assertEqual(res.status_code, 200)

        # Inspect stored payload: caller-supplied administrative fields MUST have been stripped
        with get_db_connection() as conn:
            t_row = conn.execute(
                "SELECT payload FROM channel_transitions WHERE transition_id = 'trans-spoofed-actor'"
            ).fetchone()
            self.assertIsNotNone(t_row)
            stored_p = json.loads(t_row["payload"])
            self.assertNotIn("authorized_by", stored_p)
            self.assertNotIn("status", stored_p)

    # Test 6: Caller-supplied APPROVED status cannot establish authorization
    def test_wp1e4s_6_caller_supplied_approved_status_cannot_establish_authorization(self):
        agent_id = "AGT-WIN-1E4S-06"
        inc_id = f"inc-wp1e4s-6-{uuid.uuid4()}"
        det_id = f"det-wp1e4s-6-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition submitted by non-admin with stripped status
            conn.execute("""
                INSERT INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('trans-no-admin-auth', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, '{}')
            """, (agent_id, now_iso))
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "transition_id": "trans-no-admin-auth"
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 'trans-no-admin-auth')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("missing required source_epoch", reason)

    # Test 7: Existing transition cannot be overwritten using same transition ID (409)
    def test_wp1e4s_7_existing_transition_cannot_be_overwritten(self):
        agent_id = "AGT-WIN-1E4S-07"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.commit()

        # Step 1: Initial transition
        trans_body_1 = {
            "transition_id": "trans-immutable-01",
            "agent_id": agent_id,
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
            "payload": {"source_epoch": 1, "note": "initial transition"}
        }
        res1 = self.client.post("/api/v1/events/transition", json_data=trans_body_1, headers=self.headers)
        self.assertEqual(res1.status_code, 200)
        self.assertFalse(res1.json().get("duplicate", False))

        # Step 2: Attempt to overwrite with different target epoch and payload
        trans_body_2 = {
            "transition_id": "trans-immutable-01",
            "agent_id": agent_id,
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 5,
            "transition_type": "EPOCH_ADVANCE",
            "payload": {"source_epoch": 1, "note": "malicious overwrite"}
        }
        res2 = self.client.post("/api/v1/events/transition", json_data=trans_body_2, headers=self.headers)
        self.assertEqual(res2.status_code, 409)
        self.assertIn("Transition payload conflict detected", res2.json()["detail"])

        # Step 3: Verify original transition was preserved
        with get_db_connection() as conn:
            t_row = conn.execute(
                "SELECT target_epoch, payload FROM channel_transitions WHERE transition_id = 'trans-immutable-01'"
            ).fetchone()
            self.assertEqual(t_row["target_epoch"], 2)
            self.assertIn("initial transition", t_row["payload"])

    # Test 8: Same transition ID with identical canonical payload is idempotent duplicate (200)
    def test_wp1e4s_8_same_id_same_payload_is_idempotent(self):
        agent_id = "AGT-WIN-1E4S-08"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.commit()

        trans_body = {
            "transition_id": "trans-idem-01",
            "agent_id": agent_id,
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
            "payload": {"source_epoch": 1}
        }
        # First submission
        res1 = self.client.post("/api/v1/events/transition", json_data=trans_body, headers=self.headers)
        self.assertEqual(res1.status_code, 200)

        # Resubmission of identical payload
        res2 = self.client.post("/api/v1/events/transition", json_data=trans_body, headers=self.headers)
        self.assertEqual(res2.status_code, 200)
        self.assertTrue(res2.json().get("duplicate"))
        self.assertEqual(res2.json().get("status"), "ALREADY_APPLIED")

    # Test 9: Same ID with different payload creates durable conflict
    def test_wp1e4s_9_same_id_different_payload_creates_durable_conflict(self):
        agent_id = "AGT-WIN-1E4S-09"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.commit()

        trans_a = {
            "transition_id": "trans-conflict-durable",
            "agent_id": agent_id,
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
            "payload": {"source_epoch": 1, "val": "A"}
        }
        trans_b = {
            "transition_id": "trans-conflict-durable",
            "agent_id": agent_id,
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 3,
            "transition_type": "EPOCH_ADVANCE",
            "payload": {"source_epoch": 1, "val": "B"}
        }

        self.client.post("/api/v1/events/transition", json_data=trans_a, headers=self.headers)
        res_b = self.client.post("/api/v1/events/transition", json_data=trans_b, headers=self.headers)
        self.assertEqual(res_b.status_code, 409)

        # Verify durable conflict recorded in transition_conflicts and event_conflicts
        with get_db_connection() as conn:
            t_conf = conn.execute(
                "SELECT * FROM transition_conflicts WHERE transition_id = 'trans-conflict-durable'"
            ).fetchone()
            self.assertIsNotNone(t_conf)
            self.assertIn('"val": "A"', t_conf["payload_a"])
            self.assertIn('"val": "B"', t_conf["payload_b"])

            e_conf = conn.execute(
                "SELECT * FROM event_conflicts WHERE event_id = 'trans-conflict-durable'"
            ).fetchone()
            self.assertIsNotNone(e_conf)

    # Test 10: Missing event transition_id is rejected for recovery authorization
    def test_wp1e4s_10_missing_event_transition_id_rejected(self):
        agent_id = "AGT-WIN-1E4S-10"
        inc_id = f"inc-wp1e4s-10-{uuid.uuid4()}"
        det_id = f"det-wp1e4s-10-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-valid-gap-trans', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "authorized_by": "SOC_ADMIN", "status": "APPROVED"})))

            # Event is from retired epoch 2, but has NO transition_id
            ev_data = {"detection_event_id": det_id, "agent_id": agent_id, "channel": "Security", "channel_epoch": 2}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2)
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("missing mandatory transition_id for recovery authorization", reason)

    # Test 11: Mismatched transition_id is rejected
    def test_wp1e4s_11_mismatched_transition_id_rejected(self):
        agent_id = "AGT-WIN-1E4S-11"
        inc_id = f"inc-wp1e4s-11-{uuid.uuid4()}"
        det_id = f"det-wp1e4s-11-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            conn.execute("""
                INSERT INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-real-trans-id', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "authorized_by": "SOC_ADMIN", "status": "APPROVED"})))

            # Event specifies a bogus transition_id
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "transition_id": "t-bogus-non-existent"
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-bogus-non-existent')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("references non-existent or mismatched transition", reason)

    # Test 12: Mismatched recovery_request_id is rejected
    def test_wp1e4s_12_mismatched_recovery_request_id_rejected(self):
        agent_id = "AGT-WIN-1E4S-12"
        inc_id = f"inc-wp1e4s-12-{uuid.uuid4()}"
        det_id = f"det-wp1e4s-12-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 3, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition bound to recovery_request_id "rec-expected-12"
            conn.execute("""
                INSERT INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload, recovery_request_id)
                VALUES ('t-bound-rec-id', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?, 'rec-expected-12')
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "authorized_by": "SOC_ADMIN", "status": "APPROVED", "recovery_request_id": "rec-expected-12"})))

            # Event supplies mismatched recovery_request_id
            ev_data = {
                "detection_event_id": det_id,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 2,
                "transition_id": "t-bound-rec-id",
                "recovery_request_id": "rec-forged-or-mismatched"
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id, recovery_request_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-bound-rec-id', 'rec-forged-or-mismatched')
            """, (det_id, json.dumps(ev_data), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id, det_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertFalse(is_eligible)
            self.assertIn("does not match transition recovery_request_id", reason)

    # Test 13: Multiple candidate transitions do not result in arbitrary selection
    def test_wp1e4s_13_multiple_candidate_transitions_no_arbitrary_selection(self):
        agent_id = "AGT-WIN-1E4S-13"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 4, 'ACTIVE', ?)
            """, (agent_id, now_iso))
            # Transition 1: watermark = 2 (retires epoch 2)
            conn.execute("""
                INSERT INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-trans-one', ?, 'Security', 'Security', 3, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "watermark": 2, "authorized_by": "SOC_ADMIN", "status": "APPROVED"})))
            # Transition 2: watermark = 1 (admits epoch 2)
            conn.execute("""
                INSERT INTO channel_transitions
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload)
                VALUES ('t-trans-two', ?, 'Security', 'Security', 4, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?)
            """, (agent_id, now_iso, json.dumps({"source_epoch": 1, "watermark": 1, "authorized_by": "SOC_ADMIN", "status": "APPROVED"})))

            # Event A bound to Transition 1: MUST evaluate against Transition 1 (rejected by watermark 2)
            inc_id_a = f"inc-wp1e4s-13a-{uuid.uuid4()}"
            det_id_a = f"det-wp1e4s-13a-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_a)
            ev_data_a = {"detection_event_id": det_id_a, "agent_id": agent_id, "channel": "Security", "channel_epoch": 2, "transition_id": "t-trans-one"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-trans-one')
            """, (det_id_a, json.dumps(ev_data_a), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_a, det_id_a))

            # Event B bound to Transition 2: MUST evaluate against Transition 2 (accepted by watermark 1)
            inc_id_b = f"inc-wp1e4s-13b-{uuid.uuid4()}"
            det_id_b = f"det-wp1e4s-13b-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_b)
            ev_data_b = {"detection_event_id": det_id_b, "agent_id": agent_id, "channel": "Security", "channel_epoch": 2, "transition_id": "t-trans-two"}
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch, transition_id)
                VALUES (?, ?, 'RELEASED', ?, 'Security', 2, 't-trans-two')
            """, (det_id_b, json.dumps(ev_data_b), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_b, det_id_b))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_b, agent_id))
            conn.commit()

            # Event A rejected strictly according to Transition 1 rules
            is_a, reason_a = check_incident_evidence_eligibility(conn, inc_id_a)
            self.assertFalse(is_a)
            self.assertIn("retired by watermark threshold 2", reason_a)

            # Event B accepted strictly according to Transition 2 rules
            is_b, reason_b = check_incident_evidence_eligibility(conn, inc_id_b)
            self.assertTrue(is_b)
            self.assertIsNone(reason_b)

    # Test 14: Existing valid recovery behavior is preserved
    def test_wp1e4s_14_existing_valid_recovery_behavior_preserved(self):
        agent_id = "AGT-WIN-1E4S-14"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'EPOCH_GAP_QUARANTINED', ?)
            """, (agent_id, now_iso))
            # Ingest event while quarantined
            ev_data = {
                "detection_event_id": "det-valid-rec-14",
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 3,
                "evidence": {"process_name": "malicious.exe"}
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES ('det-valid-rec-14', ?, 'EPOCH_GAP_QUARANTINED', ?, 'Security', 3)
            """, (json.dumps(ev_data), agent_id))
            conn.commit()

        # Resolve gap with admin credentials
        res = self.client.post(
            f"/api/v1/agents/{agent_id}/channels/Security/resolve_gap",
            json_data={"target_epoch": 3, "resolution_reason": "Offline audit approved", "recovery_request_id": "rec-14-ok"},
            headers={"Authorization": f"Bearer {ADMIN_API_TOKEN}"}
        )
        self.assertEqual(res.status_code, 200)

        # Confirm event was released and bound to the transition
        inc_id = f"inc-wp1e4s-14-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id)
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, 'det-valid-rec-14')", (inc_id,))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id, agent_id))
            conn.commit()

            is_eligible, reason = check_incident_evidence_eligibility(conn, inc_id)
            self.assertTrue(is_eligible)
            self.assertIsNone(reason)

            # Response dispatch succeeds
            dispatched = dispatch_governed_response(conn, inc_id, [{"type": "ISOLATE_HOST", "reason": "Verified threat"}])
            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0]["agent_id"], agent_id)

    # Test 15: WP-1C Local SAM vs domain dispatch regression passes
    def test_wp1e4s_15_wp1c_local_sam_vs_domain_dispatch_regression(self):
        agent_id = "AGT-WIN-1E4S-15"
        now_iso = datetime.now(timezone.utc).isoformat()
        inc_id_local = f"inc-wp1e4s-15-loc-{uuid.uuid4()}"
        det_id_local = f"det-wp1e4s-15-loc-{uuid.uuid4()}"
        with get_db_connection() as conn:
            self._seed_test_incident(conn, inc_id_local)
            self._seed_test_endpoint(conn, agent_id)
            conn.execute("""
                INSERT OR REPLACE INTO agent_channel_epochs (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, 'Security', 1, 'ACTIVE', ?)
            """, (agent_id, now_iso))

            # 15A: LOCAL_SAM account dispatches to local agent
            ev_data_local = {
                "detection_event_id": det_id_local,
                "agent_id": agent_id,
                "hostname": "WIN-TEST-01",
                "channel": "Security",
                "channel_epoch": 1,
                "evidence": {
                    "target_account_id": "LOCAL_SAM\\analyst",
                    "target_user": "analyst",
                    "domain_status": "LOCAL_SAM",
                    "domain_namespace": "LOCAL_SAM"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 1)
            """, (det_id_local, json.dumps(ev_data_local), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_local, det_id_local))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_local, agent_id))
            conn.commit()

            dispatched_local = dispatch_governed_response(conn, inc_id_local, [{"type": "DISABLE_ACCOUNT", "reason": "Local compromise"}])
            self.assertEqual(len(dispatched_local), 1)
            self.assertEqual(dispatched_local[0]["command_type"], "DISABLE_ACCOUNT")
            self.assertEqual(dispatched_local[0]["parameters"]["username"], "analyst")
            self.assertEqual(dispatched_local[0]["parameters"]["domain"], "LOCAL_SAM")

            # 15B: DOMAIN account escalated, 0 commands dispatched
            inc_id_domain = f"inc-wp1e4s-15-dom-{uuid.uuid4()}"
            det_id_domain = f"det-wp1e4s-15-dom-{uuid.uuid4()}"
            self._seed_test_incident(conn, inc_id_domain)
            ev_data_domain = {
                "detection_event_id": det_id_domain,
                "agent_id": agent_id,
                "channel": "Security",
                "channel_epoch": 1,
                "evidence": {
                    "target_account_id": "DOMAIN:CORP\\analyst",
                    "target_user": "analyst",
                    "domain_status": "OBSERVED_DOMAIN",
                    "domain_namespace": "DOMAIN:CORP",
                    "target_domain": "CORP"
                }
            }
            conn.execute("""
                INSERT INTO events (detection_event_id, data, quarantine_status, agent_id, channel, channel_epoch)
                VALUES (?, ?, 'ACTIVE_VERIFIED', ?, 'Security', 1)
            """, (det_id_domain, json.dumps(ev_data_domain), agent_id))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", (inc_id_domain, det_id_domain))
            conn.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_value) VALUES (?, 'agent_id', ?)", (inc_id_domain, agent_id))
            conn.commit()

            dispatched_domain = dispatch_governed_response(conn, inc_id_domain, [{"type": "DISABLE_ACCOUNT", "reason": "Domain account"}])
            self.assertEqual(len(dispatched_domain), 0)

    # =========================================================================
    # PR #1 WP-1E CRITICAL CORRECTNESS REGRESSION TESTS
    # =========================================================================

    def test_corrupt_stored_event_fails_closed_and_preserves_row(self):
        """
        1. Corrupted stored-event handling:
        Never assume unreadable stored payload has the same hash as incoming payload.
        Fail closed with HTTP 500, refuse to acknowledge as duplicate, preserve DB row.
        """
        ev_id = f"det-corrupt-{uuid.uuid4()}"
        ev = dict(self.base_event)
        ev["detection_event_id"] = ev_id

        # 1. Ingest valid event
        res1 = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res1.status_code, 201)

        # 2. Simulate database payload corruption: corrupt data and clear cached payload_hash
        corrupt_raw_str = "{this is not valid json! bad bytes"
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE events SET data = ?, payload_hash = NULL WHERE detection_event_id = ?",
                (corrupt_raw_str, ev_id)
            )
            conn.commit()

        # 3. Resubmit incoming event -> MUST FAIL CLOSED (HTTP 500), never return 201 duplicate
        res2 = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res2.status_code, 500)
        self.assertFalse(res2.json().get("accepted", True))
        self.assertIn("corrupted or unverifiable", res2.json()["detail"])

        # 4. Verify original stored DB row was preserved and NOT overwritten
        with get_db_connection() as conn:
            row = conn.execute("SELECT data, payload_hash FROM events WHERE detection_event_id = ?", (ev_id,)).fetchone()
            self.assertEqual(row["data"], corrupt_raw_str)
            self.assertIsNone(row["payload_hash"])

    def test_strict_epoch_validation_rejects_malformed_and_conflicts(self):
        """
        2. Strict epoch validation:
        Explicit field presence checks, reject zero/negative/bool/float/string,
        reject conflicting values, never silently substitute another field.
        """
        ev_id = f"det-epoch-val-{uuid.uuid4()}"
        ev = dict(self.base_event)
        ev["detection_event_id"] = ev_id

        # 2A: Reject explicit zero
        ev["channel_epoch"] = 0
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)

        # 2B: Reject explicit negative
        ev["channel_epoch"] = -5
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)

        # 2C: Reject explicit booleans (False and True)
        ev["channel_epoch"] = False
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)
        ev["channel_epoch"] = True
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)

        # 2D: Reject float
        ev["channel_epoch"] = 2.5
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)

        # 2E: Reject string integer representation
        ev["channel_epoch"] = "2"
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)

        # 2F: Never silently substitute another field when higher-priority field is invalid
        ev["channel_epoch"] = 0  # Invalid!
        ev["evidence"] = {"channel_epoch": 1}  # Valid fallback candidate, MUST NOT BE USED!
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)
        self.assertIn("Invalid channel_epoch in parsed_dict['channel_epoch']", res.json()["detail"])

        # 2G: Multiple supported fields with conflicting values must be rejected
        del ev["channel_epoch"]
        ev["epoch"] = 1
        ev["evidence"] = {"channel_epoch": 2}  # Conflicting!
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 422)
        self.assertIn("Conflicting epoch values", res.json()["detail"])

    def test_channel_identity_no_security_default_and_legacy_unverified(self):
        """
        3. Channel identity:
        Remove unconditional default of 'Security'. Events without trustworthy channel
        remain LEGACY_UNVERIFIED and do NOT create agent_channel_epochs rows.
        """
        agent_id = f"AGT-CH-TEST-{uuid.uuid4().hex[:6]}"
        ev_id = f"det-no-ch-{uuid.uuid4()}"
        ev = {
            "detection_event_id": ev_id,
            "timestamp": "2026-11-19T12:00:00Z",
            "agent_id": agent_id,
            "hostname": "TEST-HOST",
            "confidence": 0.9,
            "severity": "medium",
            "detection_type": "generic_rule",
            "evidence": {}  # No channel, no log_name, no source_manifest
        }

        # 3A: Submit event with no channel identity
        res = self.client.post("/api/v1/detection-events", json_data=ev, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["quarantine_status"], "LEGACY_UNVERIFIED")

        # Verify NO record was created in agent_channel_epochs for this agent
        with get_db_connection() as conn:
            ch_row = conn.execute("SELECT * FROM agent_channel_epochs WHERE agent_id = ?", (agent_id,)).fetchone()
            self.assertIsNone(ch_row, "Authoritative agent/channel epoch record must NOT be created for missing channel!")
            ev_row = conn.execute("SELECT channel, channel_epoch, quarantine_status FROM events WHERE detection_event_id = ?", (ev_id,)).fetchone()
            self.assertIsNone(ev_row["channel"])
            self.assertIsNone(ev_row["channel_epoch"])
            self.assertEqual(ev_row["quarantine_status"], "LEGACY_UNVERIFIED")

        # 3B: Ambiguous/conflicting channels must remain LEGACY_UNVERIFIED without authoritative record
        agent_id_ambig = f"AGT-AMBIG-{uuid.uuid4().hex[:6]}"
        ev_ambig = dict(ev)
        ev_ambig["agent_id"] = agent_id_ambig
        ev_ambig["detection_event_id"] = f"det-ambig-{uuid.uuid4()}"
        ev_ambig["channel"] = "Security"
        ev_ambig["evidence"] = {"log_name": "System"}  # Conflicting channels!
        res_ambig = self.client.post("/api/v1/detection-events", json_data=ev_ambig, headers=self.headers)
        self.assertEqual(res_ambig.status_code, 201)
        self.assertEqual(res_ambig.json()["quarantine_status"], "LEGACY_UNVERIFIED")
        with get_db_connection() as conn:
            ch_ambig = conn.execute("SELECT * FROM agent_channel_epochs WHERE agent_id = ?", (agent_id_ambig,)).fetchone()
            self.assertIsNone(ch_ambig, "Authoritative record must NOT be created for ambiguous channel!")

        # 3C: Explicit source_manifest channel is recognized
        agent_id_sysmon = f"AGT-SYSMON-{uuid.uuid4().hex[:6]}"
        ev_sysmon = dict(ev)
        ev_sysmon["agent_id"] = agent_id_sysmon
        ev_sysmon["detection_event_id"] = f"det-sysmon-{uuid.uuid4()}"
        ev_sysmon["evidence"] = {
            "source_manifest": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "epoch": 1
            }
        }
        res_sys = self.client.post("/api/v1/detection-events", json_data=ev_sysmon, headers=self.headers)
        self.assertEqual(res_sys.status_code, 201)
        self.assertEqual(res_sys.json()["quarantine_status"], "ACTIVE_VERIFIED")
        with get_db_connection() as conn:
            ch_sys = conn.execute("SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
                                  (agent_id_sysmon, "Microsoft-Windows-Sysmon/Operational")).fetchone()
            self.assertIsNotNone(ch_sys)
            self.assertEqual(ch_sys["status"], "ACTIVE")

    def test_future_epoch_gap_freezes_channel_and_quarantines_subsequent_events(self):
        """
        4. Future-epoch gap freeze:
        Once future-epoch gap is detected, freeze agent/channel (status='EPOCH_GAP_QUARANTINED').
        Subsequent events CANNOT become ACTIVE_VERIFIED until resolved via Path A or Path B.
        """
        agent_id = f"AGT-GAP-FREEZE-{uuid.uuid4().hex[:6]}"
        ch = "Security"

        # Initialize channel at Epoch 1 with an active event
        ev1 = dict(self.base_event)
        ev1["agent_id"] = agent_id
        ev1["channel"] = ch
        ev1["channel_epoch"] = 1
        ev1["detection_event_id"] = f"det-1-{uuid.uuid4()}"
        res1 = self.client.post("/api/v1/detection-events", json_data=ev1, headers=self.headers)
        self.assertEqual(res1.status_code, 201)
        self.assertEqual(res1.json()["quarantine_status"], "ACTIVE_VERIFIED")

        # 4A: Ingest event with future epoch 4 (gap! active is 1, received 4)
        ev_future = dict(self.base_event)
        ev_future["agent_id"] = agent_id
        ev_future["channel"] = ch
        ev_future["channel_epoch"] = 4
        ev_future["detection_event_id"] = f"det-future-4-{uuid.uuid4()}"
        res_fut = self.client.post("/api/v1/detection-events", json_data=ev_future, headers=self.headers)
        self.assertEqual(res_fut.status_code, 201)
        self.assertEqual(res_fut.json()["quarantine_status"], "GAP_QUARANTINED")

        # Verify channel status is now FROZEN in EPOCH_GAP_QUARANTINED
        with get_db_connection() as conn:
            ch_state = conn.execute("SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
                                    (agent_id, ch)).fetchone()
            self.assertEqual(ch_state["status"], "EPOCH_GAP_QUARANTINED")
            self.assertEqual(ch_state["current_epoch"], 1)

        # 4B: Subsequent event claiming epoch 1 arrives while channel is frozen -> MUST BE QUARANTINED!
        ev_subsequent_1 = dict(self.base_event)
        ev_subsequent_1["agent_id"] = agent_id
        ev_subsequent_1["channel"] = ch
        ev_subsequent_1["channel_epoch"] = 1
        ev_subsequent_1["detection_event_id"] = f"det-subsequent-1-{uuid.uuid4()}"
        res_sub1 = self.client.post("/api/v1/detection-events", json_data=ev_subsequent_1, headers=self.headers)
        self.assertEqual(res_sub1.status_code, 201)
        self.assertEqual(res_sub1.json()["quarantine_status"], "GAP_QUARANTINED",
                         "Subsequent event must NOT become ACTIVE_VERIFIED while channel is frozen!")

        # 4C: Path A sequential recovery: Replay transitions 1->2, 2->3, 3->4
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": f"t-1-2-{uuid.uuid4()}", "agent_id": agent_id, "source_channel": ch, "target_epoch": 2
        }, headers=self.headers)
        self.client.post("/api/v1/events/transition", json_data={
            "transition_id": f"t-2-3-{uuid.uuid4()}", "agent_id": agent_id, "source_channel": ch, "target_epoch": 3
        }, headers=self.headers)
        res_t4 = self.client.post("/api/v1/events/transition", json_data={
            "transition_id": f"t-3-4-{uuid.uuid4()}", "agent_id": agent_id, "source_channel": ch, "target_epoch": 4
        }, headers=self.headers)
        self.assertEqual(res_t4.status_code, 200)
        self.assertEqual(res_t4.json()["status"], "APPLIED")
        self.assertEqual(res_t4.json()["active_epoch"], 4)

        # Verify channel status is now restored to ACTIVE and events are RELEASED
        with get_db_connection() as conn:
            ch_restored = conn.execute("SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
                                       (agent_id, ch)).fetchone()
            self.assertEqual(ch_restored["status"], "ACTIVE")
            self.assertEqual(ch_restored["current_epoch"], 4)

            # Future event (epoch 4) was released
            row_fut = conn.execute("SELECT quarantine_status FROM events WHERE detection_event_id = ?",
                                   (ev_future["detection_event_id"],)).fetchone()
            self.assertEqual(row_fut["quarantine_status"], "RELEASED")

    def test_administrative_credential_separation_and_fail_closed(self):
        """
        Administrative credential separation and fail-closed verification:
        1. Endpoint ingestion works with a valid SOC_API_TOKEN when SOC_ADMIN_API_TOKEN is absent.
        2. Endpoint ingestion fails when SOC_API_TOKEN is absent.
        3. Administrative operations fail when the admin token is absent.
        4. Administrative operations fail when endpoint and admin tokens are identical.
        5. Endpoint token cannot authorize administrative operations (HTTP 403 Forbidden).
        6. Invalid admin token is rejected (HTTP 401 Unauthorized).
        7. Distinct valid admin credentials permit authorized recovery (HTTP 200 OK).
        """
        orig_admin = os.environ.get("SOC_ADMIN_API_TOKEN")
        orig_admin_alt = os.environ.get("SOC_ADMIN_TOKEN")
        orig_endpoint = os.environ.get("SOC_API_TOKEN")

        try:
            # 1. Endpoint ingestion works with a valid SOC_API_TOKEN when SOC_ADMIN_API_TOKEN is absent
            os.environ["SOC_API_TOKEN"] = "ep-valid-token-case1"
            os.environ.pop("SOC_ADMIN_API_TOKEN", None)
            os.environ.pop("SOC_ADMIN_TOKEN", None)
            ev1 = dict(self.base_event)
            ev1["detection_event_id"] = "det-auth-sep-1"
            res1 = self.client.post(
                "/api/v1/detection-events",
                json_data=ev1,
                headers={"Authorization": "Bearer ep-valid-token-case1"}
            )
            self.assertEqual(res1.status_code, 201)
            self.assertTrue(res1.json()["accepted"])
            self.assertFalse(res1.json()["duplicate"])
            self.assertEqual(res1.json()["detection_event_id"], "det-auth-sep-1")

            # 2. Endpoint ingestion fails when SOC_API_TOKEN is absent
            os.environ["SOC_API_TOKEN"] = ""
            ev2 = dict(self.base_event)
            ev2["detection_event_id"] = "det-auth-sep-2"
            res2 = self.client.post(
                "/api/v1/detection-events",
                json_data=ev2,
                headers={"Authorization": "Bearer some-token"}
            )
            self.assertEqual(res2.status_code, 500)
            self.assertIn("Endpoint credentials not configured", res2.json()["detail"])

            # 3. Administrative operations fail when the admin token is absent
            os.environ["SOC_API_TOKEN"] = "ep-valid-token"
            os.environ.pop("SOC_ADMIN_API_TOKEN", None)
            os.environ.pop("SOC_ADMIN_TOKEN", None)
            res3 = self.client.post(
                "/api/v1/agents/AGT-01/channels/Security/resolve_gap",
                json_data={"target_epoch": 2, "resolution_reason": "test"},
                headers={"Authorization": "Bearer ep-valid-token"}
            )
            self.assertEqual(res3.status_code, 500)
            self.assertIn("Administrative credentials not configured", res3.json()["detail"])

            # 4. Administrative operations fail when endpoint and admin tokens are identical
            os.environ["SOC_API_TOKEN"] = "identical-secret-token"
            os.environ["SOC_ADMIN_API_TOKEN"] = "identical-secret-token"
            res4 = self.client.post(
                "/api/v1/agents/AGT-01/channels/Security/resolve_gap",
                json_data={"target_epoch": 2, "resolution_reason": "test"},
                headers={"Authorization": "Bearer identical-secret-token"}
            )
            self.assertEqual(res4.status_code, 500)
            self.assertIn("cannot be identical", res4.json()["detail"])

            # 5. Endpoint token cannot authorize administrative operations (HTTP 403 Forbidden)
            os.environ["SOC_API_TOKEN"] = "endpoint-secret-abc"
            os.environ["SOC_ADMIN_API_TOKEN"] = "admin-secret-xyz"
            res5 = self.client.post(
                "/api/v1/agents/AGT-01/channels/Security/resolve_gap",
                json_data={"target_epoch": 2, "resolution_reason": "test"},
                headers={"Authorization": "Bearer endpoint-secret-abc"}
            )
            self.assertEqual(res5.status_code, 403)
            self.assertIn("Endpoint credentials cannot perform administrative operations", res5.json()["detail"])

            # 6. Invalid admin token is rejected (HTTP 401 Unauthorized)
            res6 = self.client.post(
                "/api/v1/agents/AGT-01/channels/Security/resolve_gap",
                json_data={"target_epoch": 2, "resolution_reason": "test"},
                headers={"Authorization": "Bearer invalid-admin-token"}
            )
            self.assertEqual(res6.status_code, 401)
            self.assertIn("Invalid administrator credentials", res6.json()["detail"])

            # 7. Distinct valid admin credentials permit authorized recovery (HTTP 200 OK)
            res7 = self.client.post(
                "/api/v1/agents/AGT-01/channels/Security/resolve_gap",
                json_data={"target_epoch": 2, "resolution_reason": "Authorized recovery"},
                headers={"Authorization": "Bearer admin-secret-xyz"}
            )
            self.assertEqual(res7.status_code, 200)
            self.assertEqual(res7.json()["status"], "RESOLVED")
            self.assertEqual(res7.json()["active_epoch"], 2)

        finally:
            if orig_admin is not None:
                os.environ["SOC_ADMIN_API_TOKEN"] = orig_admin
            else:
                os.environ.pop("SOC_ADMIN_API_TOKEN", None)
            if orig_admin_alt is not None:
                os.environ["SOC_ADMIN_TOKEN"] = orig_admin_alt
            else:
                os.environ.pop("SOC_ADMIN_TOKEN", None)
            if orig_endpoint is not None:
                os.environ["SOC_API_TOKEN"] = orig_endpoint
            else:
                os.environ.pop("SOC_API_TOKEN", None)


if __name__ == "__main__":
    unittest.main()
