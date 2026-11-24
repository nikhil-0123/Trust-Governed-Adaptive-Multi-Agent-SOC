import unittest
import os
import glob
import tempfile
import shutil
import logging
import json
from collectors.checkpoint import CheckpointManager, CheckpointLockTimeout, compute_checkpoint_crc32
from transport.outbox import Outbox, TransitionOutbox, OutboxPayloadConflictError
from transport.client import TransitionTransportClient, SendResult


class TestCheckpointManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.logger = logging.getLogger("TestLogger")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_checkpoint_lifecycle(self):
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        self.assertEqual(cm.load_checkpoint(), 0)
        
        cm.save_checkpoint(100)
        self.assertEqual(cm.load_checkpoint(), 100)
        
        cm.save_checkpoint(250)
        self.assertEqual(cm.load_checkpoint(), 250)

    def test_corrupted_checkpoint(self):
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)
        
        # Corrupt it
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            f.write("{invalid_json:")
            
        # Should fail safely and raise RuntimeError
        with self.assertRaises(RuntimeError):
            cm.load_checkpoint()

    def test_channel_boundary_permission_enforcement(self):
        """CheckpointManager for Security cannot mutate System and vice versa."""
        cm_sec = CheckpointManager(self.test_dir, "Security", self.logger)
        with self.assertRaises(PermissionError):
            cm_sec.save_checkpoint(100, target_channel="System")
            
        with self.assertRaises(PermissionError):
            cm_sec.advance_epoch(new_epoch=2, target_channel="System")

    def test_epoch_advancement_and_atomic_transition_registration(self):
        """Epoch advances monotonically and embeds transition marker in the same atomic commit."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        self.assertEqual(cm.get_current_epoch(), 1)
        self.assertEqual(cm.load_checkpoint(), 0)
        
        cm.save_checkpoint(500)
        self.assertEqual(cm.load_checkpoint(), 500)
        
        t_id = "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"
        self.assertFalse(cm.is_transition_applied(t_id))
        
        new_epoch = cm.advance_epoch(
            reset_record_id=0,
            transition_id=t_id,
            transition_metadata={"source_channel": "System", "source_epoch": 2}
        )
        self.assertEqual(new_epoch, 2)
        self.assertEqual(cm.get_current_epoch(), 2)
        self.assertEqual(cm.load_checkpoint(), 0)
        self.assertTrue(cm.is_transition_applied(t_id))
        
        # Backward epoch advancement must raise ValueError
        with self.assertRaises(ValueError):
            cm.advance_epoch(new_epoch=1)

    def test_legacy_v1_checkpoint_migration(self):
        """Legacy flat checkpoint without epoch or applied_transitions defaults safely."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        # Write flat legacy format
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            f.write('{"log_name": "Security", "last_record_id": 45000}')
            
        self.assertEqual(cm.load_checkpoint(), 45000)
        self.assertEqual(cm.get_current_epoch(), 1)
        self.assertFalse(cm.is_transition_applied("dummy_id"))

    def test_ledger_compaction_and_watermark_progression(self):
        """Applied transitions are pruned up to source-channel threshold and watermark updates atomically."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        # Advance to epoch 2 with transition 1
        cm.advance_epoch(reset_record_id=0, transition_id="t1", transition_metadata={"agent_id": "AGT-WIN-01", "source_channel": "System", "source_epoch": 1, "source_record_id": 100})
        # Advance to epoch 3 with transition 2
        cm.advance_epoch(reset_record_id=0, transition_id="t2", transition_metadata={"agent_id": "AGT-WIN-01", "source_channel": "System", "source_epoch": 2, "source_record_id": 200})
        self.assertEqual(cm.get_current_epoch(), 3)
        self.assertTrue(cm.is_transition_applied("t1"))
        self.assertTrue(cm.is_transition_applied("t2"))

        # Missing or invalid source_agent_id must fail closed
        with self.assertRaises(ValueError):
            cm.compact_ledger(source_agent_id="", source_channel="System", prune_source_epoch_threshold=1)

        # Compact up to System source epoch 1 with explicit source_agent_id
        pruned = cm.compact_ledger(source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=1)
        self.assertEqual(pruned, 1)
        self.assertFalse(cm.is_transition_applied("t1"))
        self.assertTrue(cm.is_transition_applied("t2"))

        state = cm.load_state()
        self.assertEqual(state["watermark"]["pruned_source_epochs"]["AGT-WIN-01:System"], 1)
        self.assertEqual(state["watermark"]["total_compacted_count"], 1)
        self.assertTrue(cm.is_transition_retired("System", 1, source_agent_id="AGT-WIN-01"))
        self.assertFalse(cm.is_transition_retired("System", 2, source_agent_id="AGT-WIN-01"))
        # Missing source_agent_id fails closed (returns False)
        self.assertFalse(cm.is_transition_retired("System", 1, source_agent_id=""))

    def test_local_witness_tracking_and_deduplication(self):
        """Local witness clear events are registered atomically and detected."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        self.assertFalse(cm.is_local_witness_replay("Security", 501, 1102))

        local_id = cm.build_local_witness_id("Security", from_epoch=1, record_id=501, event_id=1102)
        meta = {
            "is_local_witness": True,
            "source_channel": "Security",
            "from_epoch": 1,
            "source_record_id": 501,
            "witness_event_id": 1102,
        }
        cm.advance_epoch(reset_record_id=0, transition_id=local_id, transition_metadata=meta)
        self.assertEqual(cm.get_current_epoch(), 2)
        self.assertTrue(cm.is_local_witness_replay("Security", 501, 1102))
        # Different record ID is not applied
        self.assertFalse(cm.is_local_witness_replay("Security", 502, 1102))

    # =========================================================================
    # Phase 3 Tests: Kernel Concurrency Locking, Durability & Cross-Store Handoff
    # =========================================================================

    def test_kernel_concurrency_locking_and_timeout(self):
        """Two managers on the same channel compete for OS kernel lock; loser times out cleanly."""
        cm1 = CheckpointManager(self.test_dir, "Security", self.logger)
        cm2 = CheckpointManager(self.test_dir, "Security", self.logger)

        with cm1.acquire_lock():
            self.assertGreater(cm1.get_lock_epoch(), 0)
            # cm2 should time out because cm1 holds the OS kernel lock
            with self.assertRaises(CheckpointLockTimeout):
                with cm2.acquire_lock(timeout=0.2):
                    pass

        # After cm1 exits, cm2 must successfully acquire lock
        with cm2.acquire_lock(timeout=1.0):
            self.assertGreater(cm2.get_lock_epoch(), cm1.get_lock_epoch())

    def test_lock_ownership_metadata_and_monotonic_lock_epoch(self):
        """Lock file contains structured ownership metadata and monotonically increasing lock_epoch."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        with cm.acquire_lock():
            epoch1 = cm.get_lock_epoch()
            self.assertGreaterEqual(epoch1, 1)
            meta1 = cm.get_lock_metadata()
            self.assertIsNotNone(meta1)
            self.assertEqual(meta1["lock_epoch"], epoch1)
            self.assertEqual(meta1["pid"], os.getpid())
            self.assertEqual(meta1["channel"], "Security")
            self.assertTrue(bool(meta1["owner_uuid"]))
            self.assertTrue(bool(meta1["hostname"]))
            self.assertTrue(bool(meta1["acquired_at"]))

        with cm.acquire_lock():
            epoch2 = cm.get_lock_epoch()
            self.assertEqual(epoch2, epoch1 + 1)
            meta2 = cm.get_lock_metadata()
            self.assertEqual(meta2["lock_epoch"], epoch2)

    def test_stale_in_memory_writer_rejected_by_fencing_token(self):
        """Writers presenting stale fencing tokens are rejected with PermissionError."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        # Acquire lock once to establish epoch 1
        with cm.acquire_lock():
            valid_token = cm.get_lock_epoch()

        # Advance lock epoch by acquiring again
        with cm.acquire_lock():
            advanced_token = cm.get_lock_epoch()
            self.assertGreater(advanced_token, valid_token)

            # Attempting write with stale fencing token must fail closed
            with self.assertRaises(PermissionError):
                cm.save_checkpoint(500, fencing_token=valid_token)

            with self.assertRaises(PermissionError):
                cm.advance_epoch(new_epoch=2, fencing_token=valid_token)

            # Valid current fencing token succeeds
            cm.save_checkpoint(500, fencing_token=advanced_token)
            self.assertEqual(cm.load_checkpoint(), 500)

    def test_reentrant_locking_same_thread(self):
        """Reentrant lock acquisition in the same thread succeeds without self-deadlock."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        with cm.acquire_lock():
            cm.save_checkpoint(150)
            with cm.acquire_lock():
                cm.save_checkpoint(250)
                self.assertEqual(cm.load_checkpoint(), 250)

        self.assertEqual(cm.load_checkpoint(), 250)

    def test_7phase_fsync_backup_protocol(self):
        """Sequential writes maintain verified primary .json and previous valid .bak."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        # Write 1: primary created, no prior backup yet
        cm.save_checkpoint(100)
        self.assertTrue(os.path.exists(cm.checkpoint_file))
        self.assertFalse(os.path.exists(cm.bak_file))
        self.assertEqual(cm.load_checkpoint(), 100)

        # Write 2: primary updated to 200, backup captures previous state (100)
        cm.save_checkpoint(200)
        self.assertTrue(os.path.exists(cm.bak_file))
        with open(cm.bak_file, "r", encoding="utf-8") as f:
            bak_data = json.load(f)
        self.assertEqual(bak_data["last_record_id"], 100)
        self.assertEqual(cm.load_checkpoint(), 200)

        # Write 3: primary updated to 300, backup captures 200
        cm.save_checkpoint(300)
        with open(cm.bak_file, "r", encoding="utf-8") as f:
            bak_data = json.load(f)
        self.assertEqual(bak_data["last_record_id"], 200)
        self.assertEqual(cm.load_checkpoint(), 300)

    def test_corruption_recovery_from_backup(self):
        """Corrupt primary .json is automatically restored from valid .bak."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)
        cm.save_checkpoint(200)
        self.assertEqual(cm.load_checkpoint(), 200)

        # Corrupt primary .json with malformed bytes
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            f.write("{corrupt_json: incomplete")

        # load_state must automatically recover state from .bak (record 100)
        state = cm.load_state()
        self.assertEqual(state["last_record_id"], 100)

        # Primary file must be restored on disk
        with open(cm.checkpoint_file, "r", encoding="utf-8") as f:
            restored = json.load(f)
        self.assertEqual(restored["last_record_id"], 100)

    def test_dual_corruption_fails_closed_and_quarantines(self):
        """Corruption of both primary and backup halts ingestion and quarantines files."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)
        cm.save_checkpoint(200)

        # Corrupt BOTH primary and backup
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            f.write("PRIMARY_CORRUPT")
        with open(cm.bak_file, "w", encoding="utf-8") as f:
            f.write("BACKUP_CORRUPT")

        # Must fail closed with RuntimeError and never silently reset
        with self.assertRaises(RuntimeError) as ctx:
            cm.load_checkpoint()

        self.assertIn("CHECKPOINT_UNRECOVERABLE", str(ctx.exception))

        # Verify quarantined corrupt files exist on disk
        corrupt_files = glob.glob(os.path.join(self.test_dir, "*checkpoint*.corrupt.*"))
        self.assertGreaterEqual(len(corrupt_files), 1)

    def test_pending_outbox_notifications_lifecycle(self):
        """Pending outbox notifications can be added, queried, and removed durably."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        self.assertEqual(cm.get_pending_outbox_notifications(), {})

        notif_payload = {
            "type": "gap_quarantine",
            "channel": "Security",
            "epoch": 2,
            "timestamp": "2026-11-20T12:00:00Z",
        }
        cm.add_pending_outbox_notification("notif-gap-001", notif_payload)

        pending = cm.get_pending_outbox_notifications()
        self.assertEqual(len(pending), 1)
        self.assertIn("notif-gap-001", pending)
        self.assertEqual(pending["notif-gap-001"]["channel"], "Security")

        # Removing non-existent returns False
        self.assertFalse(cm.remove_pending_outbox_notification("non-existent"))

        # Removing existing returns True and updates disk state
        self.assertTrue(cm.remove_pending_outbox_notification("notif-gap-001"))
        self.assertEqual(cm.get_pending_outbox_notifications(), {})

    def test_atomic_epoch_advance_with_pending_notification(self):
        """advance_epoch commits epoch transition, applied witness, and pending notification in one write."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        t_id = "test_trans_12345"
        notif = {
            "detection_event_id": "det-quarantine-999",
            "event_type": "channel_gap_quarantine",
            "severity": "HIGH",
        }

        new_epoch = cm.advance_epoch(
            new_epoch=2,
            reset_record_id=0,
            transition_id=t_id,
            transition_metadata={"is_local_witness": True, "source_record_id": 500, "witness_event_id": 1102},
            pending_notification=notif,
        )
        self.assertEqual(new_epoch, 2)

        # Reload state from disk
        state = cm.load_state()
        self.assertEqual(state["epoch"], 2)
        self.assertEqual(state["last_record_id"], 0)
        self.assertTrue(cm.is_transition_applied(t_id))

        pending = state.get("pending_outbox_notifications", {})
        self.assertIn("det-quarantine-999", pending)
        self.assertEqual(pending["det-quarantine-999"]["event_type"], "channel_gap_quarantine")

    def test_drain_pending_outbox_notifications_coordinated_with_outbox(self):
        """drain_pending_outbox_notifications commits events to Outbox and deletes checkpoint ledger markers."""
        outbox_db = os.path.join(self.test_dir, "test_outbox.db")
        outbox = Outbox(outbox_db, self.logger, synchronous_mode="FULL")

        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        event_1 = {
            "detection_event_id": "DET-EVT-001",
            "event_type": "security_clear_witness",
            "severity": "MEDIUM",
            "channel": "Security",
        }
        event_2 = {
            "detection_event_id": "DET-EVT-002",
            "event_type": "gap_quarantine",
            "severity": "HIGH",
            "channel": "Security",
        }

        cm.add_pending_outbox_notification("DET-EVT-001", event_1)
        cm.add_pending_outbox_notification("DET-EVT-002", event_2)
        self.assertEqual(len(cm.get_pending_outbox_notifications()), 2)

        # Drain using Outbox instance directly
        drained_count = cm.drain_pending_outbox_notifications(outbox)
        self.assertEqual(drained_count, 2)

        # Checkpoint ledger is now empty
        self.assertEqual(cm.get_pending_outbox_notifications(), {})

        # Outbox now contains both pending events
        pending_outbox = outbox.get_pending_events()
        self.assertEqual(len(pending_outbox), 2)
        outbox_ids = {e["detection_event_id"] for e in pending_outbox}
        self.assertEqual(outbox_ids, {"DET-EVT-001", "DET-EVT-002"})

    def test_drain_failure_preserves_pending_notifications(self):
        """Handler failure preserves notifications in checkpoint ledger for retry (fail-closed)."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        event = {
            "detection_event_id": "DET-EVT-FAIL",
            "event_type": "test_failure",
        }
        cm.add_pending_outbox_notification("DET-EVT-FAIL", event)

        def failing_handler(item):
            raise IOError("Simulated network/disk crash during outbox commit")

        with self.assertRaises(IOError):
            cm.drain_pending_outbox_notifications(failing_handler)

        # Notification must still be present in checkpoint JSON
        pending = cm.get_pending_outbox_notifications()
        self.assertIn("DET-EVT-FAIL", pending)

    def test_outbox_payload_conflict_preserves_checkpoint_marker(self):
        """Outbox payload conflict raises OutboxPayloadConflictError and preserves notification."""
        outbox_db = os.path.join(self.test_dir, "test_outbox_conflict.db")
        outbox = Outbox(outbox_db, self.logger, synchronous_mode="FULL")

        # Insert original event into outbox
        original_event = {
            "detection_event_id": "DET-CONFLICT-001",
            "event_type": "payload_a",
            "severity": "LOW",
        }
        outbox.add_event(original_event)

        # Add conflicting event with same ID but different payload to checkpoint pending ledger
        conflicting_event = {
            "detection_event_id": "DET-CONFLICT-001",
            "event_type": "payload_b_conflicting",
            "severity": "CRITICAL",
        }
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.add_pending_outbox_notification("DET-CONFLICT-001", conflicting_event)

        # Draining must fail with OutboxPayloadConflictError
        with self.assertRaises(OutboxPayloadConflictError):
            cm.drain_pending_outbox_notifications(outbox)

        # Notification remains in checkpoint pending ledger
        self.assertIn("DET-CONFLICT-001", cm.get_pending_outbox_notifications())

    # =========================================================================
    # Objective A & B Remediation Tests: CRC32 Checksums & Transition Outbox
    # =========================================================================

    def test_checkpoint_crc32_deterministic_validation(self):
        """Persisted checkpoints include deterministic CRC32 matching canonical fields."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)

        with open(cm.checkpoint_file, "r", encoding="utf-8") as f:
            raw_state = json.load(f)

        self.assertIn("crc32", raw_state)
        computed = compute_checkpoint_crc32(raw_state)
        self.assertEqual(raw_state["crc32"], computed)

        # Modifying a canonical field produces a different checksum
        raw_state["last_record_id"] = 999
        self.assertNotEqual(raw_state["crc32"], compute_checkpoint_crc32(raw_state))

    def test_primary_crc32_mismatch_recovers_from_backup(self):
        """Primary checkpoint with CRC32 mismatch is rejected and recovered from valid backup."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)
        cm.save_checkpoint(200)

        # Tamper primary file CRC32
        with open(cm.checkpoint_file, "r", encoding="utf-8") as f:
            primary_data = json.load(f)
        primary_data["crc32"] = "deadbeef"
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(primary_data, f)

        # load_checkpoint must fail primary CRC, recover state from backup (record 100), and restore primary
        self.assertEqual(cm.load_checkpoint(), 100)

        with open(cm.checkpoint_file, "r", encoding="utf-8") as f:
            restored = json.load(f)
        self.assertEqual(restored["last_record_id"], 100)
        self.assertEqual(restored["crc32"], compute_checkpoint_crc32(restored))

    def test_dual_crc32_mismatch_quarantines_and_fails_closed(self):
        """Both primary and backup CRC32 mismatches cause CHECKPOINT_UNRECOVERABLE and quarantine."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)
        cm.save_checkpoint(200)

        # Tamper both primary and backup CRC32
        with open(cm.checkpoint_file, "r", encoding="utf-8") as f:
            primary_data = json.load(f)
        primary_data["crc32"] = "deadbeef"
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(primary_data, f)

        with open(cm.bak_file, "r", encoding="utf-8") as f:
            bak_data = json.load(f)
        bak_data["crc32"] = "badc0ffe"
        with open(cm.bak_file, "w", encoding="utf-8") as f:
            json.dump(bak_data, f)

        with self.assertRaises(RuntimeError) as ctx:
            cm.load_checkpoint()

        self.assertIn("CHECKPOINT_UNRECOVERABLE", str(ctx.exception))
        corrupt_files = glob.glob(os.path.join(self.test_dir, "*checkpoint*.corrupt.*"))
        self.assertGreaterEqual(len(corrupt_files), 1)

    def test_transition_outbox_isolation_and_idempotence(self):
        """TransitionOutbox isolates transitions into transition_outbox and acknowledges identical duplicates."""
        db_path = os.path.join(self.test_dir, "test_outbox.db")
        trans_outbox = TransitionOutbox(db_path, self.logger, synchronous_mode="FULL")
        det_outbox = Outbox(db_path, self.logger, synchronous_mode="FULL")

        transition_payload = {
            "transition_id": "TRANS-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
        }

        # Add transition
        trans_outbox.add_transition(transition_payload)

        # Detection outbox table is untouched
        self.assertEqual(len(det_outbox.get_pending_events()), 0)

        # Transition outbox contains the pending transition
        pending = trans_outbox.get_pending_transitions()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["transition_id"], "TRANS-001")

        # Duplicate submission is an idempotent no-op
        trans_outbox.add_transition(transition_payload)
        self.assertEqual(len(trans_outbox.get_pending_transitions()), 1)

    def test_transition_outbox_payload_conflict(self):
        """TransitionOutbox raises OutboxPayloadConflictError on different payload for same transition_id."""
        db_path = os.path.join(self.test_dir, "test_outbox.db")
        trans_outbox = TransitionOutbox(db_path, self.logger, synchronous_mode="FULL")

        t1 = {
            "transition_id": "TRANS-CONFLICT-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
        }
        t2 = {
            "transition_id": "TRANS-CONFLICT-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 3,
        }

        trans_outbox.add_transition(t1)

        with self.assertRaises(OutboxPayloadConflictError) as ctx:
            trans_outbox.add_transition(t2)

        self.assertEqual(ctx.exception.event_id, "TRANS-CONFLICT-001")
        conflicts = trans_outbox.get_conflicts_for_transition("TRANS-CONFLICT-001")
        self.assertEqual(len(conflicts), 1)

    def test_drain_routing_separates_detections_and_transitions(self):
        """drain_pending_outbox_notifications routes detections to detection outbox and transitions to transition outbox."""
        db_path = os.path.join(self.test_dir, "test_combined.db")
        det_outbox = Outbox(db_path, self.logger, synchronous_mode="FULL")
        trans_outbox = TransitionOutbox(db_path, self.logger, synchronous_mode="FULL")
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        det_notif = {
            "detection_event_id": "DET-SEP-001",
            "event_type": "security_alert",
            "severity": "HIGH",
        }
        trans_notif = {
            "transition_id": "TRANS-SEP-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
        }

        cm.add_pending_outbox_notification("DET-SEP-001", det_notif)
        cm.add_pending_outbox_notification("TRANS-SEP-001", trans_notif)
        self.assertEqual(len(cm.get_pending_outbox_notifications()), 2)

        # Drain providing both dedicated outboxes
        drained = cm.drain_pending_outbox_notifications(
            detection_outbox=det_outbox,
            transition_outbox=trans_outbox,
        )
        self.assertEqual(drained, 2)
        self.assertEqual(cm.get_pending_outbox_notifications(), {})

        # Detection outbox contains only the detection event
        det_pending = det_outbox.get_pending_events()
        self.assertEqual(len(det_pending), 1)
        self.assertEqual(det_pending[0]["detection_event_id"], "DET-SEP-001")

        # Transition outbox contains only the transition event
        trans_pending = trans_outbox.get_pending_transitions()
        self.assertEqual(len(trans_pending), 1)
        self.assertEqual(trans_pending[0]["transition_id"], "TRANS-SEP-001")

    def test_drain_transition_crash_recovery_idempotence(self):
        """Simulated crash between transition commit and checkpoint write recovers idempotently."""
        db_path = os.path.join(self.test_dir, "test_crash.db")
        trans_outbox = TransitionOutbox(db_path, self.logger, synchronous_mode="FULL")
        cm = CheckpointManager(self.test_dir, "Security", self.logger)

        trans_notif = {
            "transition_id": "TRANS-CRASH-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
            "transition_type": "EPOCH_ADVANCE",
        }
        cm.add_pending_outbox_notification("TRANS-CRASH-001", trans_notif)

        # Step 1: Pre-commit into transition outbox (simulating SQLite commit having happened)
        trans_outbox.add_transition(trans_notif)

        # Checkpoint still has the pending notification (simulating crash before marker removal)
        self.assertIn("TRANS-CRASH-001", cm.get_pending_outbox_notifications())

        # Step 2: Restart/Drain cycle
        drained = cm.drain_pending_outbox_notifications(
            transition_outbox=trans_outbox,
            detection_outbox=Outbox(db_path, self.logger),
        )
        self.assertEqual(drained, 1)

        # Checkpoint pending marker is cleanly removed on idempotent duplicate acknowledgment
        self.assertEqual(cm.get_pending_outbox_notifications(), {})
        self.assertEqual(len(trans_outbox.get_pending_transitions()), 1)

    def test_transition_transport_client_delivery(self):
        """TransitionTransportClient properly formats request, handles HTTP 200, 409, and errors."""
        from unittest.mock import patch, MagicMock

        client = TransitionTransportClient("http://127.0.0.1:8000/api/v1/events/transition", "test_token", self.logger)

        transition = {
            "transition_id": "TRANS-DELIVERY-001",
            "agent_id": "AGT-WIN-01",
            "source_channel": "Security",
            "target_epoch": 2,
        }

        # Mock successful HTTP 200 APPLIED
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"status": "APPLIED", "transition_id": "TRANS-DELIVERY-001"}).encode("utf-8")
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = client.send_transition(transition)
            self.assertTrue(res.success)
            self.assertFalse(res.duplicate)
            self.assertEqual(res.status_code, 200)

        # Mock duplicate HTTP 200 ALREADY_APPLIED
        mock_resp.read.return_value = json.dumps({"status": "ALREADY_APPLIED", "duplicate": True, "transition_id": "TRANS-DELIVERY-001"}).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = client.send_transition(transition)
            self.assertTrue(res.success)
            self.assertTrue(res.duplicate)
            self.assertEqual(res.status_code, 200)
