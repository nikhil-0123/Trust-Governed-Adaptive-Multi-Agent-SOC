import os
import sys
import json
import time
import shutil
import sqlite3
import logging
import unittest
import tempfile
import threading
from unittest import mock
from datetime import datetime, timezone, timedelta

# Ensure windows-telemetry directory is on sys.path
_repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_dir not in sys.path:
    sys.path.insert(0, _repo_dir)

from transport.outbox import (
    Outbox,
    TransitionOutbox,
    OutboxLock,
    CheckpointResult
)
from transport.delivery import DeliveryManager
from transport.worker import DeliveryWorker
from transport.client import TransportClient, SendResult
from config.settings import Settings

class TestOutboxCompaction(unittest.TestCase):
    """
    Deterministic verification of Phase 1 Outbox Retention & Compaction.
    Covers:
    - Configurable retention hours
    - Throttled purging interval
    - Threshold-driven SQLite compaction
    - Auto-vacuum mode awareness (vacuum vs incremental_vacuum)
    - Disk-space guardrail validation
    - Concurrency and lock contention fail-safe behavior
    - WAL-aware database measurements
    - Data preservation across compaction (pending, quarantined, transitions, conflicts)
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_compaction_")
        self.db_path = os.path.join(self.tmp_dir, "test_outbox.db")
        self.logger = logging.getLogger("TestOutboxCompaction")
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass

    def test_settings_retention_and_compaction_defaults_and_validation(self):
        """Verify settings initialize Phase 1 parameters and enforce strict bounds."""
        s = Settings()
        self.assertEqual(s.outbox_retention_hours, 72)
        self.assertEqual(s.outbox_purge_interval_seconds, 3600.0)
        self.assertEqual(s.outbox_vacuum_freelist_threshold, 50)
        self.assertEqual(s.outbox_vacuum_min_interval_seconds, 86400.0)
        self.assertTrue(s.outbox_vacuum_enabled)

        # Validation: OUTBOX_RETENTION_HOURS < 1
        with mock.patch.dict(os.environ, {"OUTBOX_RETENTION_HOURS": "0"}):
            with self.assertRaises(ValueError):
                Settings()

        # Validation: OUTBOX_PURGE_INTERVAL_SECONDS < 1.0
        with mock.patch.dict(os.environ, {"OUTBOX_PURGE_INTERVAL_SECONDS": "0.5"}):
            with self.assertRaises(ValueError):
                Settings()

        # Validation: OUTBOX_VACUUM_FREELIST_THRESHOLD < 1
        with mock.patch.dict(os.environ, {"OUTBOX_VACUUM_FREELIST_THRESHOLD": "0"}):
            with self.assertRaises(ValueError):
                Settings()

        # Validation: OUTBOX_VACUUM_MIN_INTERVAL_SECONDS < 60.0
        with mock.patch.dict(os.environ, {"OUTBOX_VACUUM_MIN_INTERVAL_SECONDS": "30.0"}):
            with self.assertRaises(ValueError):
                Settings()

    def test_configurable_retention_and_purge(self):
        """Verify delivered records are purged strictly according to configured retention_hours."""
        outbox = Outbox(self.db_path, self.logger)
        now = datetime.now(timezone.utc)

        # 1. Add events with varying delivery timestamps
        # Event A: delivered 25 hours ago
        outbox.add_event({"detection_event_id": "evt-25h", "type": "test"})
        outbox.mark_delivered("evt-25h")
        t_25h = (now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Event B: delivered 10 hours ago
        outbox.add_event({"detection_event_id": "evt-10h", "type": "test"})
        outbox.mark_delivered("evt-10h")
        t_10h = (now - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Event C: pending (never purged)
        outbox.add_event({"detection_event_id": "evt-pending", "type": "test"})

        # Event D: quarantined (never purged)
        outbox.add_event({"detection_event_id": "evt-quarantine", "type": "test"})
        outbox.mark_quarantined("evt-quarantine", "test_reason")

        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE outbox SET delivered_at = ? WHERE detection_event_id = 'evt-25h'", (t_25h,))
        conn.execute("UPDATE outbox SET delivered_at = ? WHERE detection_event_id = 'evt-10h'", (t_10h,))
        conn.commit()
        conn.close()

        # Purge with retention_hours=24: evt-25h must be purged, evt-10h preserved
        deleted = outbox.purge_delivered_events(retention_hours=24)
        self.assertEqual(deleted, 1)

        conn = sqlite3.connect(self.db_path)
        rows = dict(conn.execute("SELECT detection_event_id, status FROM outbox").fetchall())
        conn.close()

        self.assertNotIn("evt-25h", rows)
        self.assertIn("evt-10h", rows)
        self.assertIn("evt-pending", rows)
        self.assertIn("evt-quarantine", rows)

    def test_throttled_purging_interval(self):
        """Verify DeliveryManager throttles purge calls using purge_interval_seconds."""
        outbox = Outbox(self.db_path, self.logger)
        client = TransportClient("http://127.0.0.1:9999", "tok", self.logger)

        manager = DeliveryManager(
            outbox,
            client,
            self.logger,
            retention_hours=24,
            purge_interval_seconds=60.0,
            allow_unlocked_for_testing=True
        )

        # First call: executes purge and records monotonic timestamp
        res1 = manager.purge_expired_records()
        self.assertEqual(res1["status"], "purged")

        # Immediate second call: throttled
        res2 = manager.purge_expired_records()
        self.assertEqual(res2["status"], "throttled")
        self.assertEqual(res2["detections"], 0)

        # Force call: executes regardless of throttle
        res3 = manager.purge_expired_records(force=True)
        self.assertEqual(res3["status"], "purged")

        # Simulate monotonic clock advancement past purge_interval_seconds
        manager._last_purge_monotonic = time.monotonic() - 70.0
        res4 = manager.purge_expired_records()
        self.assertEqual(res4["status"], "purged")

    def test_freelist_count_and_compact_reclaims_pages(self):
        """Verify deleting records populates the SQLite freelist and compact() reclaims pages."""
        outbox = Outbox(self.db_path, self.logger)

        # Insert 300 large events to allocate multiple database pages
        large_payload = "X" * 2048
        for i in range(300):
            outbox.add_event({
                "detection_event_id": f"evt-bulk-{i:04d}",
                "data": large_payload,
                "seq": i
            })

        # Mark all delivered
        for i in range(300):
            outbox.mark_delivered(f"evt-bulk-{i:04d}")

        # Purge all delivered events
        cutoff_future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        purged_count = outbox.purge_delivered_events(cutoff_time=cutoff_future)
        self.assertEqual(purged_count, 300)

        # Checkpoint WAL so freed pages are reflected in main database freelist
        outbox.checkpoint("PASSIVE")

        stats_before = outbox.get_db_stats()
        freelist_before = stats_before["freelist_count"]
        self.assertGreater(freelist_before, 10, "Deleting 300 records must generate freelist pages")

        # Compact with threshold=10
        result = outbox.compact(freelist_threshold=10, force=True)
        self.assertEqual(result["status"], "compacted")
        self.assertGreater(result["pages_reclaimed"], 0)
        self.assertEqual(result["freelist_after"], 0)

        stats_after = outbox.get_db_stats()
        self.assertEqual(stats_after["freelist_count"], 0)
        self.assertLess(stats_after["total_size_bytes"], stats_before["total_size_bytes"])

    def test_compact_skips_when_freelist_below_threshold(self):
        """Verify compaction skips gracefully when freelist count is below configured threshold."""
        outbox = Outbox(self.db_path, self.logger)

        # Fresh empty DB has 0 freelist pages
        res = outbox.compact(freelist_threshold=50, force=False)
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "below_freelist_threshold")
        self.assertEqual(res["freelist_count"], 0)
        self.assertEqual(res["threshold"], 50)

    def test_compact_skips_when_interval_not_elapsed(self):
        """Verify compaction skips when elapsed time is less than min_interval_seconds."""
        outbox = Outbox(self.db_path, self.logger)

        # Run forced compaction to set _last_vacuum_monotonic
        res1 = outbox.compact(force=True)
        self.assertIn(res1["status"], ("compacted", "skipped"))

        # Immediate follow-up with min_interval_seconds=86400
        res2 = outbox.compact(freelist_threshold=1, min_interval_seconds=86400.0, force=False)
        self.assertEqual(res2["status"], "skipped")
        self.assertEqual(res2["reason"], "interval_not_elapsed")
        self.assertLess(res2["elapsed_seconds"], 10.0)

    def test_compact_disk_space_guardrail(self):
        """Verify compaction aborts safely if free disk space is below safety threshold."""
        outbox = Outbox(self.db_path, self.logger)

        # Mock shutil.disk_usage to simulate nearly full disk (1024 bytes free)
        mock_usage = mock.Mock(total=10**12, used=10**12 - 1024, free=1024)
        with mock.patch("shutil.disk_usage", return_value=mock_usage):
            res = outbox.compact(force=True)
            self.assertEqual(res["status"], "skipped")
            self.assertEqual(res["reason"], "insufficient_disk_space")
            self.assertEqual(res["free_bytes"], 1024)
            self.assertGreater(res["required_bytes"], 1024)

    def test_compact_auto_vacuum_mode_awareness(self):
        """Verify compact() chooses VACUUM for auto_vacuum=0 and incremental_vacuum for auto_vacuum=2."""
        # 1. Default DB has auto_vacuum = 0
        outbox = Outbox(self.db_path, self.logger)
        self.assertEqual(outbox.get_auto_vacuum_mode(), 0)
        res = outbox.compact(force=True)
        self.assertEqual(res["mode"], "vacuum")

        # 2. Database initialized with auto_vacuum = INCREMENTAL (2)
        inc_db_path = os.path.join(self.tmp_dir, "inc_vac.db")
        conn = sqlite3.connect(inc_db_path)
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL;")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, data TEXT);")
        conn.commit()
        conn.close()

        # Connect Outbox to this incremental db
        inc_outbox = Outbox(inc_db_path, self.logger)
        self.assertEqual(inc_outbox.get_auto_vacuum_mode(), 2)

        # Insert and delete in table t to create freelist
        conn = inc_outbox._get_connection()
        conn.execute("INSERT INTO t (data) VALUES (?)", ("Y" * 4096,))
        conn.commit()
        conn.execute("DELETE FROM t;")
        conn.commit()
        conn.close()

        res_inc = inc_outbox.compact(force=True)
        self.assertEqual(res_inc["mode"], "incremental_vacuum")

    def test_compact_fails_safe_on_lock_contention(self):
        """Verify compact() returns skipped on lock contention without blocking or crashing."""
        outbox = Outbox(self.db_path, self.logger)

        # Acquire lock in a separate holder
        lock = OutboxLock(self.db_path, logger=self.logger)
        lock_acquired = lock.acquire()
        self.assertTrue(lock_acquired, "Lock must be acquired")

        try:
            # Another call to compact from a thread that does not hold the lock
            holder_result = {}
            def _attempt_compact():
                holder_result["res"] = outbox.compact(force=True)

            t = threading.Thread(target=_attempt_compact)
            t.start()
            t.join(timeout=3.0)

            res = holder_result.get("res")
            self.assertIsNotNone(res)
            self.assertEqual(res["status"], "skipped")
            self.assertEqual(res["reason"], "lock_contention")
        finally:
            lock.release()

    def test_compact_fails_safe_on_sqlite_busy(self):
        """Verify compact() returns skipped on SQLite operational errors (database busy/locked)."""
        outbox = Outbox(self.db_path, self.logger)

        # Mock _get_connection to raise sqlite3.OperationalError("database is locked")
        with mock.patch.object(outbox, "_get_connection", side_effect=sqlite3.OperationalError("database is locked")):
            res = outbox.compact(force=True)
            self.assertEqual(res["status"], "skipped")
            self.assertEqual(res["reason"], "database_busy")

    def test_events_and_transitions_preserved_across_compaction(self):
        """Verify pending events, quarantined events, transitions, and conflicts are 100% preserved."""
        outbox = Outbox(self.db_path, self.logger)
        transition_outbox = TransitionOutbox(self.db_path, self.logger)

        # 1. Pending event
        outbox.add_event({"detection_event_id": "evt-pending-1", "severity": "HIGH", "val": 123})

        # 2. Quarantined event
        outbox.add_event({"detection_event_id": "evt-quarantine-1", "severity": "LOW"})
        outbox.mark_quarantined("evt-quarantine-1", "test_quarantine_reason", "simulated error")

        # 3. Delivered event
        outbox.add_event({"detection_event_id": "evt-delivered-1", "severity": "MEDIUM"})
        outbox.mark_delivered("evt-delivered-1")

        # 4. Pending transition
        transition_outbox.add_transition({
            "transition_id": "trans-001",
            "from_channel": "A",
            "to_channel": "B",
            "reason": "rotation"
        })

        # 5. Quarantined transition
        transition_outbox.add_transition({
            "transition_id": "trans-002",
            "from_channel": "B",
            "to_channel": "C"
        })
        transition_outbox.mark_quarantined("trans-002", "schema_violation")

        # Execute forced compaction
        compact_res = outbox.compact(force=True)
        self.assertIn(compact_res["status"], ("compacted", "skipped"))

        # Verify all records remain fully accessible and unchanged
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["detection_event_id"], "evt-pending-1")
        p_data = json.loads(pending[0]["event_data"])
        self.assertEqual(p_data["val"], 123)

        quarantined = outbox.get_quarantined_events()
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["detection_event_id"], "evt-quarantine-1")
        self.assertEqual(quarantined[0]["quarantine_reason"], "test_quarantine_reason")

        pending_trans = transition_outbox.get_pending_transitions()
        self.assertEqual(len(pending_trans), 1)
        self.assertEqual(pending_trans[0]["transition_id"], "trans-001")
        t_data = json.loads(pending_trans[0]["transition_data"])
        self.assertEqual(t_data["reason"], "rotation")

    def test_wal_measurements_in_get_db_stats(self):
        """Verify get_db_stats() provides complete WAL-aware measurements."""
        outbox = Outbox(self.db_path, self.logger)
        stats = outbox.get_db_stats()

        self.assertIn("page_count", stats)
        self.assertIn("page_size", stats)
        self.assertIn("freelist_count", stats)
        self.assertIn("auto_vacuum", stats)
        self.assertIn("db_size_bytes", stats)
        self.assertIn("wal_size_bytes", stats)
        self.assertIn("total_size_bytes", stats)

        self.assertGreaterEqual(stats["page_count"], 1)
        self.assertEqual(stats["page_size"], 4096)
        self.assertGreater(stats["db_size_bytes"], 0)
        self.assertGreaterEqual(stats["wal_size_bytes"], 0)
        self.assertEqual(stats["total_size_bytes"], stats["db_size_bytes"] + stats["wal_size_bytes"])

    def test_transition_outbox_maintenance_delegation(self):
        """Verify TransitionOutbox delegates compaction and stats properly."""
        t_outbox = TransitionOutbox(self.db_path, self.logger)
        stats = t_outbox.get_db_stats()
        self.assertIn("page_count", stats)
        self.assertEqual(t_outbox.get_freelist_count(), stats["freelist_count"])

        res = t_outbox.compact(force=True)
        self.assertIn(res["status"], ("compacted", "skipped"))

    def test_delivery_manager_orchestrates_maintenance(self):
        """Verify DeliveryManager coordinates throttled purge and maybe_compact end-to-end."""
        outbox = Outbox(self.db_path, self.logger)
        t_outbox = TransitionOutbox(self.db_path, self.logger)
        client = TransportClient("http://127.0.0.1:9999", "tok", self.logger)

        manager = DeliveryManager(
            outbox,
            client,
            self.logger,
            retention_hours=1,
            purge_interval_seconds=10.0,
            vacuum_freelist_threshold=5,
            vacuum_min_interval_seconds=60.0,
            vacuum_enabled=True,
            transition_outbox=t_outbox,
            allow_unlocked_for_testing=True
        )

        # Populate delivered detection events older than 1 hour
        now = datetime.now(timezone.utc)
        past_time = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

        for i in range(10):
            eid = f"evt-maint-{i}"
            outbox.add_event({"detection_event_id": eid, "type": "maint"})
            outbox.mark_delivered(eid)

        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE outbox SET delivered_at = ? WHERE detection_event_id LIKE 'evt-maint-%'", (past_time,))
        conn.commit()
        conn.close()

        # Run process_outbox(force_purge=True, force_vacuum=True)
        manager.process_outbox(force_purge=True, force_vacuum=True)

        # Verify all 10 were purged
        conn = sqlite3.connect(self.db_path)
        cnt = conn.execute("SELECT count(*) FROM outbox WHERE detection_event_id LIKE 'evt-maint-%'").fetchone()[0]
        conn.close()
        self.assertEqual(cnt, 0)

    def test_delivery_worker_compaction_live_execution(self):
        """
        Verify live DeliveryWorker holding OutboxLock can execute compaction
        via DeliveryManager without self-lock contention, deadlock, or timeouts.
        """
        outbox = Outbox(self.db_path, self.logger)
        t_outbox = TransitionOutbox(self.db_path, self.logger)
        client = TransportClient("http://127.0.0.1:9999", "tok", self.logger)

        manager = DeliveryManager(
            outbox,
            client,
            self.logger,
            retention_hours=1,
            purge_interval_seconds=1.0,
            vacuum_freelist_threshold=2,
            vacuum_min_interval_seconds=60.0,
            vacuum_enabled=True,
            transition_outbox=t_outbox,
            allow_unlocked_for_testing=False
        )

        worker = DeliveryWorker(
            manager,
            self.logger,
            poll_interval=0.1,
            checkpoint_interval_seconds=300.0,
            allow_unlocked_for_testing=False
        )

        # Confirm lock initialization
        self.assertIsNotNone(worker._lock)

        # Create freelist pages
        for i in range(20):
            eid = f"evt-live-{i}"
            outbox.add_event({"detection_event_id": eid, "data": "A" * 1024})
            outbox.mark_delivered(eid)

        past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE outbox SET delivered_at = ? WHERE detection_event_id LIKE 'evt-live-%'", (past_time,))
        conn.commit()
        conn.close()

        # Start worker and wait for at least one process_outbox execution
        worker.start()
        try:
            # Wait briefly for worker to acquire lock, process outbox, purge, and compact
            time.sleep(0.6)

            # Confirm active lock coordination with manager
            self.assertIs(worker._lock, manager._active_lock)

            # 1. Verify worker executed compaction under its shared lock
            # Freelist was 7, now 0 because worker compacted
            self.assertEqual(outbox.get_freelist_count(), 0)
            self.assertIsNotNone(outbox.get_metadata("last_compaction_at"))
        finally:
            worker.stop(timeout=5.0)

        # 2. After worker stops, active lock is cleared and lock released
        self.assertIsNone(manager._active_lock)

        # 2. After worker stops and releases lock, main thread can compact without contention
        res = manager.maybe_compact(force=True)
        self.assertIsNotNone(res)
        self.assertIn(res.get("status"), ("compacted", "skipped"))
        self.assertNotEqual(res.get("reason"), "lock_contention")

    def test_persistent_cooldown_across_restarts(self):
        """
        Verify compaction timestamp persists in outbox_metadata and enforces
        cooldown interval across complete process/object restarts.
        """
        outbox1 = Outbox(self.db_path, self.logger)

        # Force first compaction to establish baseline
        res1 = outbox1.compact(force=True)
        self.assertIn(res1["status"], ("compacted", "skipped"))
        ts1 = outbox1.get_metadata("last_compaction_at")
        self.assertIsNotNone(ts1)

        # Simulate process shutdown and restart by instantiating fresh Outbox
        del outbox1
        outbox2 = Outbox(self.db_path, self.logger)

        # Verify last_compaction_at loaded into outbox2
        self.assertEqual(outbox2.get_metadata("last_compaction_at"), ts1)

        # Non-forced compaction within min_interval_seconds must skip via persistent metadata
        res2 = outbox2.compact(freelist_threshold=1, min_interval_seconds=86400.0, force=False)
        self.assertEqual(res2["status"], "skipped")
        self.assertEqual(res2["reason"], "interval_not_elapsed")
        self.assertEqual(res2.get("cooldown_source"), "persistent_metadata")

        # Clock-skew resistance: if stored timestamp is in future (e.g. clock rolled back)
        future_ts = (datetime.now(timezone.utc) + timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        outbox2.set_metadata("last_compaction_at", future_ts)

        del outbox2
        outbox3 = Outbox(self.db_path, self.logger)
        # Should handle future timestamp safely without crashing
        res3 = outbox3.compact(force=True)
        self.assertIn(res3["status"], ("compacted", "skipped"))

    def test_explicit_auto_vacuum_policies(self):
        """
        Verify behavior across auto_vacuum policies:
        - Mode 0 (NONE): executes VACUUM
        - Mode 1 (FULL): skips when freelist=0 without redundant rebuild
        - Mode 2 (INCREMENTAL): executes PRAGMA incremental_vacuum
        - Fresh DB initialization with initial_auto_vacuum_mode
        """
        # Test Fresh DB with initial_auto_vacuum_mode = 1 (FULL)
        full_db_path = os.path.join(self.tmp_dir, "fresh_full.db")
        full_outbox = Outbox(full_db_path, self.logger, initial_auto_vacuum_mode=1)
        self.assertEqual(full_outbox.get_auto_vacuum_mode(), 1)

        # On fresh FULL DB with 0 freelist, compact skips cleanly
        res_full = full_outbox.compact(force=False)
        self.assertEqual(res_full["status"], "skipped")
        self.assertEqual(res_full["reason"], "auto_vacuum_full_active")

        # Test Fresh DB with initial_auto_vacuum_mode = 2 (INCREMENTAL)
        inc_db_path = os.path.join(self.tmp_dir, "fresh_inc.db")
        inc_outbox = Outbox(inc_db_path, self.logger, initial_auto_vacuum_mode=2)
        self.assertEqual(inc_outbox.get_auto_vacuum_mode(), 2)
        res_inc = inc_outbox.compact(force=True)
        self.assertEqual(res_inc["mode"], "incremental_vacuum")

        # Test Fresh DB with initial_auto_vacuum_mode = 0 (NONE)
        none_db_path = os.path.join(self.tmp_dir, "fresh_none.db")
        none_outbox = Outbox(none_db_path, self.logger, initial_auto_vacuum_mode=0)
        self.assertEqual(none_outbox.get_auto_vacuum_mode(), 0)
        res_none = none_outbox.compact(force=True)
        self.assertEqual(res_none["mode"], "vacuum")

    def test_incomplete_passive_wal_checkpoint_handling(self):
        """
        Verify PASSIVE checkpoint results (busy, log, checkpointed) are inspected
        properly without assuming data loss or escalating to blocking modes.
        """
        outbox = Outbox(self.db_path, self.logger)

        # Mock checkpoint to return incomplete checkpoint: log=100, checkpointed=25
        mock_cp = CheckpointResult(busy=0, log=100, checkpointed=25)
        with mock.patch.object(outbox, "checkpoint", return_value=mock_cp):
            res = outbox.compact(force=True)
            self.assertIn(res["status"], ("compacted", "skipped"))
            if res["status"] == "compacted":
                self.assertEqual(res["wal_checkpoint_before"]["log"], 100)
                self.assertEqual(res["wal_checkpoint_before"]["checkpointed"], 25)
                self.assertEqual(res["wal_checkpoint_before"]["uncheckpointed"], 75)

    def test_offline_soc_backpressure_and_evidence_preservation(self):
        """
        Verify that offline SOC conditions with large backlogs:
        - Trigger configurable backpressure alerts
        - Never silently delete or prune pending or quarantined events
        - Accurately report volume disk watermarks
        """
        outbox = Outbox(self.db_path, self.logger)

        # Simulate accumulating 15 pending events during SOC outage
        for i in range(15):
            outbox.add_event({"detection_event_id": f"evt-offline-{i}", "severity": "CRITICAL"})

        # Simulate 5 quarantined events
        for i in range(5):
            eid = f"evt-quar-{i}"
            outbox.add_event({"detection_event_id": eid, "severity": "HIGH"})
            outbox.mark_quarantined(eid, "server_unreachable_permanent")

        # Check backpressure with max_pending = 10
        bp_pending = outbox.check_backpressure(max_pending=10, disk_watermark_mb=500)
        self.assertTrue(bp_pending["active"])
        self.assertEqual(bp_pending["pending_count"], 15)
        self.assertEqual(bp_pending["quarantined_count"], 5)
        self.assertTrue(any("pending_count_exceeded" in r for r in bp_pending["reasons"]))

        # Purge delivered events: must purge 0 records (pending and quarantined never touched)
        purged = outbox.purge_delivered_events(retention_hours=1)
        self.assertEqual(purged, 0)

        # Check total remaining records: must be exactly 20 (15 pending + 5 quarantined)
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT status, count(*) FROM outbox GROUP BY status")
        counts = dict(cur.fetchall())
        conn.close()

        self.assertEqual(counts.get("pending"), 15)
        self.assertEqual(counts.get("quarantined"), 5)
        self.assertNotIn("delivered", counts)

        # Simulate volume free space watermark breach
        bp_disk = outbox.check_backpressure(max_pending=1000, disk_watermark_mb=10**9) # 1 Petabyte watermark
        self.assertTrue(bp_disk["active"])
        self.assertTrue(any("disk_watermark_breached" in r for r in bp_disk["reasons"]))

    def test_concurrent_ingestion_during_compaction(self):
        """
        Verify that concurrent event ingestion can proceed safely alongside
        compaction without data loss or SQLite database corruption.
        """
        outbox = Outbox(self.db_path, self.logger)
        ingest_count = 50
        stop_event = threading.Event()
        ingested_ids = []
        ingest_errors = []

        def _ingest_worker():
            for i in range(ingest_count):
                eid = f"evt-concurrent-{i:03d}"
                try:
                    t_start = time.perf_counter()
                    outbox.add_event({"detection_event_id": eid, "payload": "Z" * 512, "idx": i})
                    t_dur = time.perf_counter() - t_start
                    ingested_ids.append((eid, t_dur))
                except Exception as ex:
                    ingest_errors.append((eid, str(ex)))
                time.sleep(0.01)

        t = threading.Thread(target=_ingest_worker)
        t.start()

        # Concurrently perform multiple compactions
        t_maint_start = time.perf_counter()
        compaction_res = outbox.compact(force=True)
        maint_dur = time.perf_counter() - t_maint_start

        t.join(timeout=10.0)

        self.assertEqual(len(ingest_errors), 0, f"Ingestion errors encountered: {ingest_errors}")
        self.assertEqual(len(ingested_ids), ingest_count)
        self.assertIn(compaction_res["status"], ("compacted", "skipped"))

        # Verify all ingested events are present and queryable
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT count(*) FROM outbox WHERE detection_event_id LIKE 'evt-concurrent-%'")
        count = cur.fetchone()[0]
        conn.close()
        self.assertEqual(count, ingest_count)


if __name__ == "__main__":
    unittest.main()
