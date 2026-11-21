import unittest
import os
import tempfile
import logging
import json
import sqlite3
import threading
from unittest.mock import patch

from transport.outbox import (
    Outbox,
    OutboxPayloadConflictError,
    build_outbox_conflict_manifest,
    generate_outbox_conflict_id,
)
from canonical import canonicalize_tgam_rcc_v1


class TestOutboxIdempotency(unittest.TestCase):
    """
    WP-1E.3: Comprehensive Acceptance and Regression Tests for Endpoint Outbox Idempotency.
    
    Verifies:
    1. Identical pending, delivered, and quarantined event replay is an idempotent no-op.
    2. TGAM-RCC-v1 canonicalization ensures key-ordering invariance for identical events.
    3. Conflicting payload while pending raises OutboxPayloadConflictError and preserves pending status.
    4. Conflicting payload after delivery raises OutboxPayloadConflictError and preserves delivered status.
    5. Condition 3: Deterministic conflict evidence (submitting A->B or B->A produces identical stored row contents).
    6. Condition 1: Conflict durability and crash semantics (committed evidence survives restart; uncommitted evidence is rolled back on crash).
    7. Multi-conflict tracking and replay idempotency of conflicting events.
    8. Multi-threaded concurrency for identical and conflicting submissions.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_outbox_idempotency.db")
        self.logger = logging.getLogger("TestOutboxIdempotency")
        self.logger.setLevel(logging.CRITICAL)

        self.event_base = {
            "detection_event_id": "evt-idem-001",
            "timestamp": "2026-11-11T12:00:00Z",
            "agent_id": "AGT-WIN-01",
            "hostname": "WORKSTATION-01",
            "os": "Windows",
            "source_event_id": "src-seq-100",
            "detection_type": "bruteforce_rule",
            "confidence": 0.95,
            "severity": "HIGH",
            "evidence": {"logon_type": 3, "failure_count": 5}
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_identical_pending_event_replay_is_idempotent_noop(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        orig_created_at = pending[0]["created_at"]
        orig_attempts = pending[0]["attempts"]

        # Duplicate submission with identical payload
        outbox.add_event(self.event_base)

        pending_after = outbox.get_pending_events()
        self.assertEqual(len(pending_after), 1)
        self.assertEqual(pending_after[0]["created_at"], orig_created_at)
        self.assertEqual(pending_after[0]["attempts"], orig_attempts)
        self.assertEqual(len(outbox.get_conflicts_for_event("evt-idem-001")), 0)

    def test_identical_delivered_event_replay_is_idempotent_noop(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)
        outbox.mark_delivered("evt-idem-001")

        # Verify delivered status in db
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = 'evt-idem-001'").fetchone()
        conn.close()
        self.assertEqual(row[0], "delivered")
        orig_delivered_at = row[1]
        self.assertIsNotNone(orig_delivered_at)

        # Re-submit identical event
        outbox.add_event(self.event_base)

        conn = sqlite3.connect(self.db_path)
        row_after = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = 'evt-idem-001'").fetchone()
        conn.close()
        self.assertEqual(row_after[0], "delivered")
        self.assertEqual(row_after[1], orig_delivered_at)
        self.assertEqual(len(outbox.get_conflicts_for_event("evt-idem-001")), 0)

    def test_identical_quarantined_event_replay_is_idempotent_noop(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)
        outbox.mark_quarantined("evt-idem-001", "Simulated unprocessable payload")

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-idem-001'").fetchone()
        conn.close()
        self.assertEqual(row[0], "quarantined")
        self.assertEqual(row[1], "Simulated unprocessable payload")

        # Re-submit identical event
        outbox.add_event(self.event_base)

        conn = sqlite3.connect(self.db_path)
        row_after = conn.execute("SELECT status, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-idem-001'").fetchone()
        conn.close()
        self.assertEqual(row_after[0], "quarantined")
        self.assertEqual(row_after[1], "Simulated unprocessable payload")
        self.assertEqual(len(outbox.get_conflicts_for_event("evt-idem-001")), 0)

    def test_key_ordering_variation_is_treated_as_identical(self):
        outbox = Outbox(self.db_path, self.logger)
        event_a = {
            "detection_event_id": "evt-order-001",
            "zeta": 100,
            "alpha": "first",
            "nested": {"z": 9, "a": 1}
        }
        event_b = {
            "nested": {"a": 1, "z": 9},
            "alpha": "first",
            "detection_event_id": "evt-order-001",
            "zeta": 100
        }

        outbox.add_event(event_a)
        # Adding event_b with different key ordering must be recognized as identical via TGAM-RCC-v1
        outbox.add_event(event_b)

        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(len(outbox.get_conflicts_for_event("evt-order-001")), 0)

    def test_conflicting_payload_while_pending_raises_and_preserves_pending(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        conflicting_event = dict(self.event_base)
        conflicting_event["severity"] = "CRITICAL"
        conflicting_event["evidence"] = {"logon_type": 10, "injected": True}

        with self.assertRaises(OutboxPayloadConflictError) as ctx:
            outbox.add_event(conflicting_event)

        err = ctx.exception
        self.assertEqual(err.event_id, "evt-idem-001")
        self.assertIsNotNone(err.conflict_id)
        self.assertNotEqual(err.existing_hash, err.incoming_hash)

        # Verify original row in outbox table is untouched and still pending
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        stored_dict = json.loads(pending[0]["event_data"])
        self.assertEqual(stored_dict["severity"], "HIGH")

        # Verify conflict evidence was durably recorded
        conflicts = outbox.get_conflicts_for_event("evt-idem-001")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["conflict_id"], err.conflict_id)
        self.assertEqual(conflicts[0]["detection_event_id"], "evt-idem-001")

    def test_conflicting_payload_after_delivery_raises_and_preserves_delivered(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)
        outbox.mark_delivered("evt-idem-001")

        conflicting_event = dict(self.event_base)
        conflicting_event["confidence"] = 0.40

        with self.assertRaises(OutboxPayloadConflictError) as ctx:
            outbox.add_event(conflicting_event)

        err = ctx.exception
        self.assertEqual(err.event_id, "evt-idem-001")

        # Verify outbox table still shows status 'delivered'
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'evt-idem-001'").fetchone()
        conn.close()
        self.assertEqual(row[0], "delivered")

        # Verify conflict recorded
        conflicts = outbox.get_conflicts_for_event("evt-idem-001")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["conflict_id"], err.conflict_id)

    def test_deterministic_conflict_evidence_permutation_invariance(self):
        """
        Condition 3: Submitting A then B or B then A produces the exact same
        conflict record contents - not merely the same conflict ID.
        """
        event_a = {
            "detection_event_id": "evt-perm-001",
            "field": "Alpha_Payload",
            "weight": 10
        }
        event_b = {
            "detection_event_id": "evt-perm-001",
            "field": "Beta_Payload",
            "weight": 20
        }

        # Sequence 1: DB1 receives A then B
        db_path_1 = os.path.join(self.temp_dir.name, "seq1.db")
        outbox_1 = Outbox(db_path_1, self.logger)
        outbox_1.add_event(event_a)
        with self.assertRaises(OutboxPayloadConflictError) as ctx1:
            outbox_1.add_event(event_b)
        cid_1 = ctx1.exception.conflict_id
        record_1 = outbox_1.get_conflict(cid_1)

        # Sequence 2: DB2 receives B then A
        db_path_2 = os.path.join(self.temp_dir.name, "seq2.db")
        outbox_2 = Outbox(db_path_2, self.logger)
        outbox_2.add_event(event_b)
        with self.assertRaises(OutboxPayloadConflictError) as ctx2:
            outbox_2.add_event(event_a)
        cid_2 = ctx2.exception.conflict_id
        record_2 = outbox_2.get_conflict(cid_2)

        # Assert conflict_id equality
        self.assertEqual(cid_1, cid_2)

        # Assert complete row contents equality (Condition 3)
        self.assertEqual(record_1["conflict_id"], record_2["conflict_id"])
        self.assertEqual(record_1["detection_event_id"], record_2["detection_event_id"])
        self.assertEqual(record_1["payload_a"], record_2["payload_a"])
        self.assertEqual(record_1["payload_a_hash"], record_2["payload_a_hash"])
        self.assertEqual(record_1["payload_b"], record_2["payload_b"])
        self.assertEqual(record_1["payload_b_hash"], record_2["payload_b_hash"])

    def test_conflict_durability_committed_survives_process_restart(self):
        """
        Condition 1: Committed conflict evidence is durable and survives process restart.
        """
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        conflicting_event = dict(self.event_base)
        conflicting_event["detection_type"] = "alt_rule"

        conflict_id = None
        with self.assertRaises(OutboxPayloadConflictError) as ctx:
            outbox.add_event(conflicting_event)
        conflict_id = ctx.exception.conflict_id
        self.assertIsNotNone(conflict_id)

        # Simulate complete crash/restart by dropping outbox reference
        del outbox

        # Reopen database with fresh Outbox instance
        fresh_outbox = Outbox(self.db_path, self.logger)
        conflict_row = fresh_outbox.get_conflict(conflict_id)
        self.assertIsNotNone(conflict_row)
        self.assertEqual(conflict_row["conflict_id"], conflict_id)
        self.assertEqual(conflict_row["detection_event_id"], "evt-idem-001")

    def test_conflict_rollback_boundary_uncommitted_does_not_survive_crash(self):
        """
        Condition 1: An uncommitted conflict record does NOT survive a crash.
        Rollback is clean and no phantom conflict record is committed.
        """
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        conflicting_event = dict(self.event_base)
        conflicting_event["detection_type"] = "uncommitted_rule"

        # Intercept connection execute to simulate a crash/failure right before COMMIT
        orig_execute_transaction = outbox._execute_transaction_with_retry

        def crashing_transaction(fn, max_retries=5):
            conn = outbox._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                fn(conn)
                # Crash simulation before COMMIT:
                raise sqlite3.OperationalError("Simulated disk error or crash before COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                conn.close()

        with patch.object(outbox, "_execute_transaction_with_retry", side_effect=crashing_transaction):
            with self.assertRaises(sqlite3.OperationalError):
                outbox.add_event(conflicting_event)

        # Verify that uncommitted conflict record was NOT persisted
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT COUNT(*) FROM outbox_conflicts")
        count = cur.fetchone()[0]
        conn.close()
        self.assertEqual(count, 0, "Uncommitted conflict record must not exist after pre-commit rollback")

    def test_re_submitting_same_conflicting_payload_is_idempotent(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        conflicting_event = dict(self.event_base)
        conflicting_event["confidence"] = 0.10

        # First conflicting submission
        with self.assertRaises(OutboxPayloadConflictError) as ctx1:
            outbox.add_event(conflicting_event)

        # Second conflicting submission with identical conflict
        with self.assertRaises(OutboxPayloadConflictError) as ctx2:
            outbox.add_event(conflicting_event)

        self.assertEqual(ctx1.exception.conflict_id, ctx2.exception.conflict_id)
        conflicts = outbox.get_conflicts_for_event("evt-idem-001")
        self.assertEqual(len(conflicts), 1)

    def test_multiple_distinct_conflicts_for_same_event_id(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        conflicting_1 = dict(self.event_base)
        conflicting_1["severity"] = "LOW"

        conflicting_2 = dict(self.event_base)
        conflicting_2["severity"] = "CRITICAL"

        with self.assertRaises(OutboxPayloadConflictError) as ctx1:
            outbox.add_event(conflicting_1)

        with self.assertRaises(OutboxPayloadConflictError) as ctx2:
            outbox.add_event(conflicting_2)

        self.assertNotEqual(ctx1.exception.conflict_id, ctx2.exception.conflict_id)
        conflicts = outbox.get_conflicts_for_event("evt-idem-001")
        self.assertEqual(len(conflicts), 2)

    def test_concurrent_duplicate_insertion_thread_safety(self):
        outbox = Outbox(self.db_path, self.logger)
        errors = []

        def worker():
            try:
                outbox.add_event(self.event_base)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent duplicate insertions failed: {errors}")
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(len(outbox.get_conflicts_for_event("evt-idem-001")), 0)

    def test_concurrent_conflicting_insertion_thread_safety(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event_base)

        conflicting_event = dict(self.event_base)
        conflicting_event["severity"] = "CRITICAL"

        caught_conflicts = []
        unexpected_errors = []

        def worker():
            try:
                outbox.add_event(conflicting_event)
            except OutboxPayloadConflictError as e:
                caught_conflicts.append(e)
            except Exception as e:
                unexpected_errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(unexpected_errors), 0, f"Unexpected errors: {unexpected_errors}")
        self.assertEqual(len(caught_conflicts), 5, "All 5 concurrent workers must receive OutboxPayloadConflictError")
        conflicts = outbox.get_conflicts_for_event("evt-idem-001")
        self.assertEqual(len(conflicts), 1, "Exactly one durable conflict record must be stored")

    def test_missing_detection_event_id_raises_value_error(self):
        outbox = Outbox(self.db_path, self.logger)
        with self.assertRaises(ValueError):
            outbox.add_event({"timestamp": "2026-11-11T12:00:00Z"})

    def test_canonical_conflict_manifest_serialization_and_id(self):
        """
        Verifies TGAM-RCC-v1 canonical manifest generation, serialization bytes,
        and SHA-256 conflict_id computation.
        """
        event_id = "evt-canonical-001"
        h_min = "1111111111111111111111111111111111111111111111111111111111111111"
        h_max = "9999999999999999999999999999999999999999999999999999999999999999"

        manifest = build_outbox_conflict_manifest(event_id, h_min, h_max)
        self.assertEqual(manifest["conflict_type"], "outbox_payload_collision")
        self.assertEqual(manifest["event_id"], event_id)
        self.assertEqual(manifest["hash_min"], h_min)
        self.assertEqual(manifest["hash_max"], h_max)

        canonical_bytes = canonicalize_tgam_rcc_v1(manifest)
        expected_json = (
            '{"conflict_type":"outbox_payload_collision",'
            f'"event_id":"{event_id}",'
            f'"hash_max":"{h_max}",'
            f'"hash_min":"{h_min}"}}'
        )
        self.assertEqual(canonical_bytes.decode("utf-8"), expected_json)

        import hashlib
        expected_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        actual_cid = generate_outbox_conflict_id(event_id, h_min, h_max)
        self.assertEqual(actual_cid, expected_sha256)

        # Validation assertions
        with self.assertRaises(ValueError):
            build_outbox_conflict_manifest("", h_min, h_max)
        with self.assertRaises(ValueError):
            build_outbox_conflict_manifest(event_id, "", h_max)
        with self.assertRaises(ValueError):
            build_outbox_conflict_manifest(event_id, h_min, "   ")

    def test_get_all_conflicts_empty_table(self):
        """Verifies get_all_conflicts() on a fresh database returns an empty list."""
        outbox = Outbox(self.db_path, self.logger)
        conflicts = outbox.get_all_conflicts()
        self.assertEqual(conflicts, [])

    def test_get_all_conflicts_populated_table(self):
        """Verifies get_all_conflicts() returns all conflict records in order, with limit support."""
        outbox = Outbox(self.db_path, self.logger)

        # Base events for two different detection event IDs
        ev1_a = {"detection_event_id": "evt-all-001", "val": "A1"}
        ev1_b = {"detection_event_id": "evt-all-001", "val": "B1"}
        ev2_a = {"detection_event_id": "evt-all-002", "val": "A2"}
        ev2_b = {"detection_event_id": "evt-all-002", "val": "B2"}

        outbox.add_event(ev1_a)
        outbox.add_event(ev2_a)

        with self.assertRaises(OutboxPayloadConflictError) as ctx1:
            outbox.add_event(ev1_b)
        cid1 = ctx1.exception.conflict_id

        with self.assertRaises(OutboxPayloadConflictError) as ctx2:
            outbox.add_event(ev2_b)
        cid2 = ctx2.exception.conflict_id

        all_conflicts = outbox.get_all_conflicts()
        self.assertEqual(len(all_conflicts), 2)
        conflict_ids = [c["conflict_id"] for c in all_conflicts]
        self.assertIn(cid1, conflict_ids)
        self.assertIn(cid2, conflict_ids)

        # Test limit
        limited = outbox.get_all_conflicts(limit=1)
        self.assertEqual(len(limited), 1)
        self.assertEqual(limited[0]["conflict_id"], all_conflicts[0]["conflict_id"])


if __name__ == "__main__":
    unittest.main()

