import unittest
import tempfile
import shutil
import os
import sqlite3
import logging
import json
from datetime import datetime, timezone, timedelta
import email.utils
import subprocess
import sys
import time
from unittest.mock import patch

from transport.outbox import (
    Outbox,
    CheckpointResult,
    SUPPORTED_V1_COLUMN_SPECS,
    EXPECTED_V1_COLUMNS,
    REQUIRED_V2_COLUMN_SPECS,
    REQUIRED_V2_COLUMNS,
    CANONICAL_V2_TABLE_DDL,
    EXPECTED_V2_INDEX_SPECS,
    normalize_predicate,
    extract_check_constraints,
    normalize_check_expr,
    is_valid_status_check_expr,
    validate_v2_check_constraints,
    sanitize_error_message,
    compute_transient_backoff,
    compute_auth_backoff,
    compute_rate_limit_backoff,
    parse_retry_after,
    is_sqlite_busy_or_locked,
    canonicalize_db_path,
    WindowsProcessLock,
    OutboxLock
)
from transport.client import TransportClient, SendResult
from transport.delivery import DeliveryManager, evaluate_delivery_outcome
from transport.worker import DeliveryWorker

class TestOutboxWP2(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_outbox_wp2.db")
        self.logger = logging.getLogger("TestOutboxWP2")
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fresh_database_initialization(self):
        """Verify fresh database initializes canonical V2 schema, indexes, and migrations table."""
        outbox = Outbox(self.db_path, self.logger)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # Check schema_migrations
        cur = conn.execute("SELECT version, description FROM schema_migrations")
        rows = cur.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["version"], 2)

        # Check all 11 required columns
        cols = {r[1] for r in conn.execute("PRAGMA table_info(outbox)").fetchall()}
        self.assertEqual(cols, REQUIRED_V2_COLUMNS)

        # Check primary key
        pk_col = [r[1] for r in conn.execute("PRAGMA table_info(outbox)").fetchall() if r[5] == 1]
        self.assertEqual(pk_col, ["detection_event_id"])

        # Check all 4 indexes exist
        idx_names = {r[1] for r in conn.execute("PRAGMA index_list(outbox)").fetchall()}
        for expected_idx in EXPECTED_V2_INDEX_SPECS.keys():
            self.assertIn(expected_idx, idx_names)

        conn.close()

    def test_fresh_database_idempotency(self):
        """Verify re-opening an already initialized V2 database succeeds and performs no duplicate writes."""
        outbox1 = Outbox(self.db_path, self.logger)
        outbox2 = Outbox(self.db_path, self.logger)

        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 2")
        self.assertEqual(cur.fetchone()[0], 1)
        conn.close()

    def test_supported_v1_migration(self):
        """Verify legacy V1 database is positively identified and migrated atomically to V2."""
        # 1. Seed supported V1 database
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        ancient_time_30d = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        ancient_time_10d = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")

        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, created_at, attempts, last_attempt)
            VALUES ('evt-delivered-legacy', '{"type": "brute_force"}', 'delivered', ?, 1, ?)
        """, (ancient_time_30d, ancient_time_10d))
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, created_at, attempts)
            VALUES ('evt-pending-legacy', '{"type": "lateral_movement"}', 'pending', ?, 0)
        """, (ancient_time_30d,))
        conn.commit()
        conn.close()

        # 2. Run Outbox initialization (triggers migration)
        outbox = Outbox(self.db_path, self.logger)

        # 3. Verify migration result
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # Check version recorded
        cur = conn.execute("SELECT MAX(version) FROM schema_migrations")
        self.assertEqual(cur.fetchone()[0], 2)

        # Check columns
        cols = {r[1] for r in conn.execute("PRAGMA table_info(outbox)").fetchall()}
        self.assertEqual(cols, REQUIRED_V2_COLUMNS)

        # Check legacy delivered record received migration-time UTC (NOT 10d or 30d ago)
        row_del = conn.execute("SELECT * FROM outbox WHERE detection_event_id = 'evt-delivered-legacy'").fetchone()
        self.assertEqual(row_del["status"], "delivered")
        self.assertIsNotNone(row_del["delivered_at"])
        self.assertTrue(row_del["delivered_at"].endswith("Z"))
        self.assertNotIn("2026-10", row_del["delivered_at"])
        self.assertIsNone(row_del["next_attempt_at"])

        # Check legacy pending record received valid next_attempt_at
        row_pend = conn.execute("SELECT * FROM outbox WHERE detection_event_id = 'evt-pending-legacy'").fetchone()
        self.assertEqual(row_pend["status"], "pending")
        self.assertIsNotNone(row_pend["next_attempt_at"])
        self.assertTrue(row_pend["next_attempt_at"].endswith("Z"))

        conn.close()

    def test_legacy_malformed_timestamp_normalization(self):
        """Verify malformed, empty, and NULL timestamps are normalized with deterministic fallback."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.executemany("""
            INSERT INTO outbox (detection_event_id, event_data, status, created_at)
            VALUES (?, '{}', 'pending', ?)
        """, [
            ("evt-std-time", "2026-11-05 08:30:00"),
            ("evt-iso-no-z", "2026-11-05T08:30:00"),
            ("evt-corrupt", "unparseable_string"),
            ("evt-empty", ""),
            ("evt-null", None),
        ])
        conn.commit()
        conn.close()

        outbox = Outbox(self.db_path, self.logger)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM outbox").fetchall()
        for r in rows:
            self.assertIsNotNone(r["created_at"])
            self.assertTrue(r["created_at"].endswith("Z"), f"created_at not ISO UTC: {r['created_at']}")
            self.assertEqual(len(r["created_at"]), 20)
            self.assertIsNotNone(r["next_attempt_at"])
            self.assertTrue(r["next_attempt_at"].endswith("Z"), f"next_attempt_at not ISO UTC: {r['next_attempt_at']}")
            self.assertEqual(len(r["next_attempt_at"]), 20)
        conn.close()

    def test_v1_schema_validation_rejects_missing_columns(self):
        """Verify an existing table missing required V1 columns is rejected and NOT modified."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE outbox (detection_event_id TEXT PRIMARY KEY, event_data TEXT)")
        conn.execute("INSERT INTO outbox VALUES ('evt-keep', '{\"keep\": true}')")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Unrecognized existing outbox schema", str(ctx.exception))

        # Ensure database was NOT modified
        conn = sqlite3.connect(self.db_path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(outbox)").fetchall()}
        self.assertEqual(cols, {"detection_event_id", "event_data"})
        row = conn.execute("SELECT * FROM outbox").fetchone()
        self.assertEqual(row[0], "evt-keep")
        conn.close()

    def test_v1_schema_validation_rejects_foreign_columns(self):
        """Verify an existing table containing unexpected foreign columns is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT,
                foreign_project_column TEXT
            )
        """)
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Unrecognized existing outbox schema", str(ctx.exception))

    def test_v1_schema_validation_rejects_wrong_column_order(self):
        """Verify an existing table with swapped column order is rejected."""
        conn = sqlite3.connect(self.db_path)
        # Swapping status and event_data order
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                event_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("column 1 named 'status', expected 'event_data'", str(ctx.exception))

    def test_v1_schema_validation_rejects_wrong_column_type(self):
        """Verify an existing table with wrong column type is rejected."""
        conn = sqlite3.connect(self.db_path)
        # attempts is TEXT instead of INTEGER
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts TEXT DEFAULT '0',
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("column 'attempts' type is 'TEXT', expected 'INTEGER'", str(ctx.exception))

    def test_v1_schema_validation_rejects_wrong_notnull_constraint(self):
        """Verify an existing table missing NOT NULL constraint on status is rejected."""
        conn = sqlite3.connect(self.db_path)
        # status TEXT without NOT NULL
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("column 'status' notnull is 0, expected 1", str(ctx.exception))

    def test_v1_schema_validation_rejects_wrong_primary_key(self):
        """Verify an existing table without primary key is rejected."""
        conn = sqlite3.connect(self.db_path)
        # detection_event_id without PRIMARY KEY
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("column 'detection_event_id' pk is 0, expected 1", str(ctx.exception))

    def test_v1_schema_validation_rejects_wrong_default(self):
        """Verify an existing table with unexpected default value is rejected."""
        conn = sqlite3.connect(self.db_path)
        # attempts has default 5 instead of 0
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 5,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("column 'attempts' default is '5', expected '0'", str(ctx.exception))

    def test_index_predicate_validation_exact_predicate(self):
        """Verify normalize_predicate accepts valid whitespace and quoting variants of the exact predicate."""
        variants = [
            "CREATE INDEX idx ON outbox (col) WHERE status = 'pending';",
            "CREATE INDEX idx ON outbox (col) WHERE status = 'pending'",
            "CREATE INDEX idx ON outbox (col) WHERE (status = 'pending')",
            "CREATE INDEX idx ON outbox (col) WHERE status='pending'",
            'CREATE INDEX idx ON outbox (col) WHERE status = "pending"',
        ]
        for ddl in variants:
            norm = normalize_predicate(ddl)
            self.assertEqual(norm, "status='pending'", f"Failed on: {ddl}")

    def test_index_predicate_validation_rejects_or_condition(self):
        """Verify index predicate with OR condition is rejected by integrity validation."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        conn.execute(CANONICAL_V2_TABLE_DDL)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending' OR status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("does not exactly match expected predicate 'status='pending''", str(ctx.exception))

    def test_index_predicate_validation_rejects_and_condition(self):
        """Verify index predicate with AND condition is rejected by integrity validation."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        conn.execute(CANONICAL_V2_TABLE_DDL)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending' AND next_attempt_at IS NOT NULL;")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("does not exactly match expected predicate 'status='pending''", str(ctx.exception))

    def test_index_predicate_validation_rejects_tautology_addition(self):
        """Verify index predicate with tautological additions (AND 1=1 or OR 1=1) is rejected."""
        for tautology in ["AND 1=1", "OR 1=1", "OR 'a'='a'"]:
            norm = normalize_predicate(f"CREATE INDEX idx ON outbox (col) WHERE status = 'pending' {tautology}")
            self.assertNotEqual(norm, "status='pending'")

    def test_index_predicate_validation_rejects_missing_partial_predicate(self):
        """Verify an index missing its partial predicate is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        conn.execute(CANONICAL_V2_TABLE_DDL)
        # Missing WHERE clause
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at);")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("expected partial=True, found False", str(ctx.exception))

    def test_index_predicate_validation_rejects_wrong_column_order(self):
        """Verify an index with incorrect column order causes schema validation to fail."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        conn.execute(CANONICAL_V2_TABLE_DDL)
        # Inverted: (created_at, next_attempt_at) instead of (next_attempt_at, created_at)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (created_at, next_attempt_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("expected columns ['next_attempt_at', 'created_at']", str(ctx.exception))

    def test_schema_migrations_missing_columns_rejected(self):
        """Verify a corrupt schema_migrations table missing required columns is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Schema corruption: 'schema_migrations' table missing required columns", str(ctx.exception))

    def test_schema_migrations_invalid_primary_key_rejected(self):
        """Verify a corrupt schema_migrations table where version is not PK is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER, applied_at TEXT, description TEXT)")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Schema corruption: 'version' in 'schema_migrations' must be primary key", str(ctx.exception))

    def test_unsupported_future_version_rejected(self):
        """Verify database marked with version > 2 is rejected with clear RuntimeError."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (3, '2026-11-05', 'Future V3')")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Unsupported outbox schema version: 3", str(ctx.exception))

    def test_v2_missing_columns_rejected(self):
        """Verify a database marked as V2 but missing required columns fails safely."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'Incomplete V2')")
        # Missing quarantine_reason
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_attempt TEXT,
                last_error TEXT,
                delivered_at TEXT,
                next_attempt_at TEXT,
                quarantined_at TEXT
            )
        """)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("missing required columns", str(ctx.exception))
        self.assertIn("quarantine_reason", str(ctx.exception))

    def test_v2_missing_primary_key_rejected(self):
        """Verify a V2 table where detection_event_id is not PK fails validation."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'No PK V2')")
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_attempt TEXT,
                last_error TEXT,
                delivered_at TEXT,
                next_attempt_at TEXT,
                quarantined_at TEXT,
                quarantine_reason TEXT
            )
        """)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("'detection_event_id' must be primary key in Version 2", str(ctx.exception))

    def test_migration_rollback_on_failure(self):
        """Verify migration rolls back atomically when an error occurs during schema rebuild/data copying."""
        # 1. Seed V1 database
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, attempts)
            VALUES ('evt-rb-1', '{"test": "rollback"}', 'pending', 0)
        """)
        conn.commit()
        conn.close()

        # 2. Trigger migration with injected failure right during index creation (after table swapped and data copied)
        with patch.object(Outbox, '_create_indexes', side_effect=sqlite3.OperationalError("Simulated disk error")):
            with self.assertRaises(sqlite3.OperationalError):
                Outbox(self.db_path, self.logger)

        # 3. Verify rollback: V1 schema intact, no partial columns added, row unchanged, no version 2 record
        conn = sqlite3.connect(self.db_path)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(outbox)").fetchall()]
        self.assertEqual(cols, EXPECTED_V1_COLUMNS)

        row = conn.execute("SELECT detection_event_id, event_data, status, attempts FROM outbox").fetchone()
        self.assertEqual(row, ('evt-rb-1', '{"test": "rollback"}', 'pending', 0))

        # schema_migrations table should either not exist or have no version 2 record
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
        if cur.fetchone() is not None:
            cur2 = conn.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 2")
            self.assertEqual(cur2.fetchone()[0], 0)
        conn.close()

        # 4. Subsequent migration succeeds without failure injection
        outbox_clean = Outbox(self.db_path, self.logger)
        conn = sqlite3.connect(self.db_path)
        cols_after = {r[1] for r in conn.execute("PRAGMA table_info(outbox)").fetchall()}
        self.assertEqual(cols_after, REQUIRED_V2_COLUMNS)
        cur_v = conn.execute("SELECT MAX(version) FROM schema_migrations")
        self.assertEqual(cur_v.fetchone()[0], 2)
        conn.close()

    def test_fresh_and_migrated_schema_structural_equivalence(self):
        """Verify fresh V2 and migrated V2 databases produce structurally identical PRAGMA table_info and index DDL."""
        # 1. Fresh V2 DB
        fresh_db_path = os.path.join(self.test_dir, "fresh_v2.db")
        Outbox(fresh_db_path, self.logger)

        # 2. Migrated V2 DB
        mig_db_path = os.path.join(self.test_dir, "migrated_v2.db")
        conn_v1 = sqlite3.connect(mig_db_path)
        conn_v1.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        conn_v1.execute("INSERT INTO outbox VALUES ('evt-seed', '{}', 'pending', CURRENT_TIMESTAMP, 0, NULL, NULL)")
        conn_v1.commit()
        conn_v1.close()
        Outbox(mig_db_path, self.logger)

        # 3. Compare PRAGMA table_info
        c_fresh = sqlite3.connect(fresh_db_path)
        c_mig = sqlite3.connect(mig_db_path)

        fresh_info = c_fresh.execute("PRAGMA table_info(outbox)").fetchall()
        mig_info = c_mig.execute("PRAGMA table_info(outbox)").fetchall()

        self.assertEqual(len(fresh_info), 11)
        self.assertEqual(len(mig_info), 11)
        self.assertEqual(fresh_info, mig_info, f"table_info mismatch:\nFresh: {fresh_info}\nMigrated: {mig_info}")

        # 4. Compare indexes
        fresh_indexes = sorted(c_fresh.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='outbox'").fetchall())
        mig_indexes = sorted(c_mig.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='outbox'").fetchall())
        self.assertEqual(fresh_indexes, mig_indexes, f"Index DDL mismatch:\nFresh: {fresh_indexes}\nMigrated: {mig_indexes}")

        c_fresh.close()
        c_mig.close()

    def test_check_constraint_rejects_pending_with_null_next_attempt_at(self):
        """Verify CHECK constraint strictly forbids pending events from having NULL next_attempt_at, while allowing it for delivered."""
        outbox = Outbox(self.db_path, self.logger)
        conn = sqlite3.connect(self.db_path)

        # Attempting to insert status='pending' with next_attempt_at=NULL must fail
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("""
                INSERT INTO outbox (detection_event_id, event_data, status, next_attempt_at)
                VALUES ('evt-bad-pending', '{}', 'pending', NULL)
            """)

        # Inserting status='delivered' with next_attempt_at=NULL must succeed
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, next_attempt_at, delivered_at)
            VALUES ('evt-good-delivered', '{}', 'delivered', NULL, '2026-11-05T00:00:00Z')
        """)
        conn.commit()

        row = conn.execute("SELECT status, next_attempt_at FROM outbox WHERE detection_event_id='evt-good-delivered'").fetchone()
        self.assertEqual(row[0], 'delivered')
        self.assertIsNone(row[1])
        conn.close()

    def test_migrated_v1_preserves_all_records_ids_payloads_timestamps_statuses(self):
        """Verify table rebuild migration completely preserves all existing records, IDs, payloads, and statuses."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        test_records = [
            ("evt-101", '{"attack": "brute_force", "ip": "10.0.0.1"}', "pending", "2026-11-01 10:00:00", 0, None, None),
            ("evt-102", '{"attack": "powershell_cradle", "user": "admin"}', "delivered", "2026-10-25 12:30:00", 3, "2026-10-25 12:35:00", "500 Internal Error"),
            ("evt-103", '{"attack": "recon", "source": "cmd.exe"}', "pending", "2026-11-04 15:45:00", 2, "2026-11-04 16:00:00", "Connection timeout"),
        ]
        conn.executemany("INSERT INTO outbox VALUES (?, ?, ?, ?, ?, ?, ?)", test_records)
        conn.commit()
        conn.close()

        # Execute migration via Outbox
        outbox = Outbox(self.db_path, self.logger)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # Verify evt-101 (pending, attempts=0)
        r1 = conn.execute("SELECT * FROM outbox WHERE detection_event_id='evt-101'").fetchone()
        self.assertEqual(r1["event_data"], '{"attack": "brute_force", "ip": "10.0.0.1"}')
        self.assertEqual(r1["status"], "pending")
        self.assertEqual(r1["created_at"], "2026-11-01T10:00:00Z")
        self.assertEqual(r1["attempts"], 0)
        self.assertEqual(r1["next_attempt_at"], "2026-11-01T10:00:00Z")
        self.assertIsNone(r1["delivered_at"])

        # Verify evt-102 (delivered, attempts=3, had last_attempt and last_error)
        r2 = conn.execute("SELECT * FROM outbox WHERE detection_event_id='evt-102'").fetchone()
        self.assertEqual(r2["event_data"], '{"attack": "powershell_cradle", "user": "admin"}')
        self.assertEqual(r2["status"], "delivered")
        self.assertEqual(r2["created_at"], "2026-10-25T12:30:00Z")
        self.assertEqual(r2["attempts"], 3)
        self.assertEqual(r2["last_attempt"], "2026-10-25T12:35:00Z")
        self.assertEqual(r2["last_error"], "500 Internal Error")
        self.assertIsNotNone(r2["delivered_at"])
        self.assertTrue(r2["delivered_at"].endswith("Z"))
        self.assertNotIn("2026-10", r2["delivered_at"])  # Fresh migration-time UTC
        self.assertIsNone(r2["next_attempt_at"])

        # Verify evt-103 (pending, attempts=2, had last_attempt and last_error)
        r3 = conn.execute("SELECT * FROM outbox WHERE detection_event_id='evt-103'").fetchone()
        self.assertEqual(r3["event_data"], '{"attack": "recon", "source": "cmd.exe"}')
        self.assertEqual(r3["status"], "pending")
        self.assertEqual(r3["created_at"], "2026-11-04T15:45:00Z")
        self.assertEqual(r3["attempts"], 2)
        self.assertEqual(r3["last_attempt"], "2026-11-04T16:00:00Z")
        self.assertEqual(r3["last_error"], "Connection timeout")
        self.assertEqual(r3["next_attempt_at"], "2026-11-04T15:45:00Z")
        self.assertIsNone(r3["delivered_at"])

        conn.close()

    def test_phase0_outbox_crud_contract(self):
        """Verify Phase 0 add_event, get_pending_events, mark_delivered, mark_failed on V2 schema."""
        outbox = Outbox(self.db_path, self.logger)

        # 1. add_event
        event = {"detection_event_id": "evt-p0-1", "event_type": "brute_force"}
        outbox.add_event(event)

        # Duplicate add should be ignored without error
        outbox.add_event(event)

        # 2. get_pending_events
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["detection_event_id"], "evt-p0-1")

        # 3. mark_failed
        outbox.mark_failed("evt-p0-1", "Connection refused")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM outbox WHERE detection_event_id = 'evt-p0-1'").fetchone()
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["last_error"], "Connection refused")
        self.assertIsNotNone(row["last_attempt"])
        conn.close()

        # 4. mark_delivered
        outbox.mark_delivered("evt-p0-1")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM outbox WHERE detection_event_id = 'evt-p0-1'").fetchone()
        self.assertEqual(row["status"], "delivered")
        self.assertIsNotNone(row["delivered_at"])
        conn.close()

        # get_pending_events should now be empty
        self.assertEqual(len(outbox.get_pending_events()), 0)

    def test_v2_missing_status_check_constraint_rejected(self):
        """Verify a V2 database missing the status values CHECK constraint is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        # Missing CHECK(status IN ('pending', 'delivered', 'quarantined'))
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT,
                last_error TEXT,
                delivered_at TEXT,
                next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                quarantined_at TEXT,
                quarantine_reason TEXT,
                CHECK (status != 'pending' OR next_attempt_at IS NOT NULL)
            )
        """)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Missing required CHECK constraint on 'status' values", str(ctx.exception))

    def test_v2_missing_pending_schedule_check_constraint_rejected(self):
        """Verify a V2 database missing the pending next_attempt_at CHECK constraint is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        # Missing CHECK (status != 'pending' OR next_attempt_at IS NOT NULL)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'quarantined')),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT,
                last_error TEXT,
                delivered_at TEXT,
                next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                quarantined_at TEXT,
                quarantine_reason TEXT
            )
        """)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Missing required CHECK constraint '(status != 'pending' OR next_attempt_at IS NOT NULL)'", str(ctx.exception))

    def test_v2_equivalent_canonical_ddl_accepted(self):
        """Verify equivalent but valid canonical DDL with alternative spacing/casing is accepted."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2')")
        # Equivalent with <> instead of != and different whitespace
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL CHECK ( STATUS IN ('delivered', 'quarantined', 'pending') ),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT,
                last_error TEXT,
                delivered_at TEXT,
                next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                quarantined_at TEXT,
                quarantine_reason TEXT,
                CHECK ( status <> 'pending'  OR  next_attempt_at IS NOT NULL )
            )
        """)
        conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
        conn.commit()
        conn.close()

        # Should initialize and validate successfully without raising RuntimeError
        outbox = Outbox(self.db_path, self.logger)
        self.assertIsNotNone(outbox)

    def test_v2_status_check_rejects_appended_conditions_and_bypasses(self):
        """Verify status CHECK validation strictly rejects appended-condition bypasses and invalid variants."""
        bypass_status_checks = [
            "status IN ('pending', 'delivered', 'quarantined') OR 1=1",
            "(status IN ('pending', 'delivered', 'quarantined') OR 1=1)",
            "(status IN ('pending', 'delivered', 'quarantined')) OR 1=1",
            "((status IN ('pending', 'delivered', 'quarantined')) OR 1=1)",
            "status IN ('pending', 'delivered', 'quarantined') OR status='unknown'",
            "(status IN ('pending', 'delivered', 'quarantined') OR status='unknown')",
            "(status IN ('pending', 'delivered', 'quarantined')) OR (status='unknown')",
            "status IN ('pending', 'delivered', 'quarantined') OR (1=1)",
            "status IN ('pending', 'delivered', 'quarantined') AND 1=1",
            "status IN ('pending', 'delivered', 'quarantined', 'unknown')",
            "status IN ('pending', 'delivered', 'quarantined' OR 1=1)",
            "status IN ('pending', 'delivered')",
            "status NOT IN ('pending', 'delivered', 'quarantined')",
            "status IN ('pending', 'pending', 'pending')",
        ]

        # 1. Direct function validation
        for bypass in bypass_status_checks:
            self.assertFalse(
                is_valid_status_check_expr(bypass),
                f"Expected is_valid_status_check_expr to reject bypass: {bypass}"
            )

        # 2. Database validation through Outbox initialization for key bypass vectors
        key_bypass_vectors = [
            "status IN ('pending', 'delivered', 'quarantined') OR 1=1",
            "(status IN ('pending', 'delivered', 'quarantined') OR 1=1)",
            "status IN ('pending', 'delivered', 'quarantined') OR status='unknown'",
            "status IN ('pending', 'delivered', 'quarantined') OR (1=1)",
            "status IN ('pending', 'delivered', 'quarantined', 'unknown')",
        ]

        for idx, bypass_clause in enumerate(key_bypass_vectors):
            sub_db = os.path.join(self.test_dir, f"bypass_{idx}.db")
            conn = sqlite3.connect(sub_db)
            conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
            conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2 Bypass Attempt')")
            conn.execute(f"""
                CREATE TABLE outbox (
                    detection_event_id TEXT PRIMARY KEY,
                    event_data TEXT NOT NULL,
                    status TEXT NOT NULL CHECK ({bypass_clause}),
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_attempt TEXT,
                    last_error TEXT,
                    delivered_at TEXT,
                    next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    quarantined_at TEXT,
                    quarantine_reason TEXT,
                    CHECK (status != 'pending' OR next_attempt_at IS NOT NULL)
                )
            """)
            conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
            conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
            conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
            conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
            conn.commit()
            conn.close()

            with self.assertRaises(RuntimeError, msg=f"Outbox failed to reject bypass: {bypass_clause}") as ctx:
                Outbox(sub_db, self.logger)
            self.assertIn("Missing required CHECK constraint on 'status' values", str(ctx.exception))

    def test_v2_status_check_accepts_valid_permutations_and_formatting(self):
        """Verify status CHECK validation accepts valid ordering, casing, quotes, outer parens, and spacing variants."""
        valid_status_checks = [
            "status IN ('pending', 'delivered', 'quarantined')",
            "status IN ('delivered', 'quarantined', 'pending')",
            "status IN ('quarantined', 'pending', 'delivered')",
            "status IN ('quarantined', 'delivered', 'pending')",
            "status IN ('delivered', 'pending', 'quarantined')",
            "STATUS IN ('PENDING', 'DELIVERED', 'QUARANTINED')",
            "Status IN ('Pending', 'Delivered', 'Quarantined')",
            'status IN ("pending", "delivered", "quarantined")',
            '"status" IN (\'pending\', \'delivered\', \'quarantined\')',
            '[status] IN (\'pending\', \'delivered\', \'quarantined\')',
            '`status` IN (\'pending\', \'delivered\', \'quarantined\')',
            "(status IN ('pending', 'delivered', 'quarantined'))",
            "((status IN ('pending', 'delivered', 'quarantined')))",
            "  status   IN   (  'pending'  ,  'delivered'  ,  'quarantined'  )  ",
            "status IN ('pending', 'delivered', 'quarantined');",
        ]

        # 1. Direct function validation
        for valid_expr in valid_status_checks:
            self.assertTrue(
                is_valid_status_check_expr(valid_expr),
                f"Expected is_valid_status_check_expr to accept valid expression: {valid_expr}"
            )

        # 2. Database validation through Outbox initialization with valid permutations
        key_valid_variants = [
            "STATUS IN ('delivered', 'quarantined', 'pending')",
            'status IN ("quarantined", "pending", "delivered")',
            "((status IN ('pending', 'delivered', 'quarantined')))",
            "  status   IN   (  'pending'  ,  'delivered'  ,  'quarantined'  )  ",
        ]

        for idx, valid_clause in enumerate(key_valid_variants):
            sub_db = os.path.join(self.test_dir, f"valid_variant_{idx}.db")
            conn = sqlite3.connect(sub_db)
            conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
            conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2 Valid Variant')")
            conn.execute(f"""
                CREATE TABLE outbox (
                    detection_event_id TEXT PRIMARY KEY,
                    event_data TEXT NOT NULL,
                    status TEXT NOT NULL CHECK ({valid_clause}),
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_attempt TEXT,
                    last_error TEXT,
                    delivered_at TEXT,
                    next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    quarantined_at TEXT,
                    quarantine_reason TEXT,
                    CHECK (status != 'pending' OR next_attempt_at IS NOT NULL)
                )
            """)
            conn.execute("CREATE INDEX idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
            conn.execute("CREATE INDEX idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
            conn.execute("CREATE INDEX idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
            conn.execute("CREATE INDEX idx_outbox_created_at ON outbox (created_at);")
            conn.commit()
            conn.close()

            outbox = Outbox(sub_db, self.logger)
            self.assertIsNotNone(outbox)

    def test_migration_normalizes_attempt_counts(self):
        """Verify migration safely normalizes NULL, negative, float, and non-integer attempt counts to integer >= 0."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE outbox (
                detection_event_id TEXT PRIMARY KEY,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                last_error TEXT
            )
        """)
        records = [
            ("evt-null-att", "{}", "pending", "2026-11-05 08:00:00", None),
            ("evt-zero-att", "{}", "pending", "2026-11-05 08:00:00", 0),
            ("evt-pos-att", "{}", "pending", "2026-11-05 08:00:00", 4),
            ("evt-neg-att", "{}", "pending", "2026-11-05 08:00:00", -3),
            ("evt-neg-str", "{}", "pending", "2026-11-05 08:00:00", "-7"),
            ("evt-pos-str", "{}", "pending", "2026-11-05 08:00:00", "5"),
            ("evt-float-att", "{}", "pending", "2026-11-05 08:00:00", 2.9),
            ("evt-neg-float", "{}", "pending", "2026-11-05 08:00:00", -1.8),
            ("evt-corrupt-att", "{}", "pending", "2026-11-05 08:00:00", "invalid_number"),
            ("evt-empty-att", "{}", "pending", "2026-11-05 08:00:00", ""),
        ]
        conn.executemany("INSERT INTO outbox (detection_event_id, event_data, status, created_at, attempts) VALUES (?, ?, ?, ?, ?)", records)
        conn.commit()
        conn.close()

        # Run migration
        outbox = Outbox(self.db_path, self.logger)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = {r["detection_event_id"]: r["attempts"] for r in conn.execute("SELECT detection_event_id, attempts FROM outbox").fetchall()}
        conn.close()

        # All values must be integer >= 0
        expected_attempts = {
            "evt-null-att": 0,
            "evt-zero-att": 0,
            "evt-pos-att": 4,
            "evt-neg-att": 0,
            "evt-neg-str": 0,
            "evt-pos-str": 5,
            "evt-float-att": 2,
            "evt-neg-float": 0,
            "evt-corrupt-att": 0,
            "evt-empty-att": 0,
        }
        for eid, exp_val in expected_attempts.items():
            act_val = rows[eid]
            self.assertEqual(act_val, exp_val, f"Mismatch for {eid}: expected {exp_val}, got {act_val}")
            self.assertIsInstance(act_val, int)
            self.assertGreaterEqual(act_val, 0)

    def test_mark_delivered_is_idempotent(self):
        """Verify calling mark_delivered multiple times preserves the original delivered_at timestamp."""
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-idempotent-1", "type": "auth_event"})

        # First delivery marking
        outbox.mark_delivered("evt-idempotent-1")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        r1 = conn.execute("SELECT delivered_at, last_attempt FROM outbox WHERE detection_event_id='evt-idempotent-1'").fetchone()
        t1 = r1["delivered_at"]
        self.assertIsNotNone(t1)
        self.assertTrue(t1.endswith("Z"))
        conn.close()

        # Second delivery marking (simulate second invocation)
        outbox.mark_delivered("evt-idempotent-1")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        r2 = conn.execute("SELECT delivered_at, last_attempt FROM outbox WHERE detection_event_id='evt-idempotent-1'").fetchone()
        t2 = r2["delivered_at"]
        conn.close()

        # Original delivered_at must be preserved exactly
        self.assertEqual(t1, t2)

    def test_inconsistent_migration_history_v1_without_outbox_rejected(self):
        """Verify schema_migrations indicating version 1 without an outbox table fails closed and does not create outbox."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (1, '2026-11-05', 'V1 migration')")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Schema corruption detected: schema_migrations indicates version 1 but 'outbox' table is missing", str(ctx.exception))

        # Verify no outbox table was silently created
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='outbox'")
        self.assertIsNone(cur.fetchone())
        conn.close()

    def test_inconsistent_migration_history_v2_without_outbox_rejected(self):
        """Verify schema_migrations indicating version 2 without an outbox table fails closed and does not create outbox."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT)")
        conn.execute("INSERT INTO schema_migrations VALUES (2, '2026-11-05', 'V2 migration')")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            Outbox(self.db_path, self.logger)
        self.assertIn("Schema corruption detected: schema_migrations indicates version 2 but 'outbox' table is missing", str(ctx.exception))

        # Verify no outbox table was silently created
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='outbox'")
        self.assertIsNone(cur.fetchone())
        conn.close()

    def test_sanitize_error_message_comprehensive(self):
        """Verify credential sanitization engine redacts refresh_token, user-info, headers, JWTs, and enforces safety."""
        test_cases = [
            ("raw_refresh", "https://soc.local/api/token?refresh_token=secret_refresh_123&scope=read", "secret_refresh_123"),
            ("single_enc_refresh", "https://soc.local/api%3Frefresh_token%3Denc%20secret%20456%26scope%3Dread", "enc%20secret%20456"),
            ("double_enc_refresh", "https://soc.local/api%253Frefresh_token%253Ddouble%2520secret%2520789%2526scope%253Dread", "double%2520secret%2520789"),
            ("user_info_raw", "https://collector_agent:user_pass_super_secret@central-soc.local/ingest", "user_pass_super_secret"),
            ("user_info_enc", "http://soc_user:pass%20123@proxy.corp.local:8080/path", "pass%20123"),
            ("proxy_auth_basic", "Proxy-Authorization: Basic proxy_secret_pass_xyz", "proxy_secret_pass_xyz"),
            ("proxy_auth_bearer", "Proxy-Authorization = Bearer proxy_secret_pass_xyz", "proxy_secret_pass_xyz"),
            ("cookie_header", "Cookie: session_id=sess_secret_cookie_val_abc; auth_token=jwt_secret_token_def", "sess_secret_cookie_val_abc"),
            ("set_cookie_header", "Set-Cookie: session_id=auth_cookie_secret_ghi; Path=/; Secure; HttpOnly", "auth_cookie_secret_ghi"),
            ("auth_bearer", "Authorization: Bearer bearer_secret_token_111", "bearer_secret_token_111"),
            ("auth_raw", "Authorization: raw_secret_token_222", "raw_secret_token_222"),
            ("x_api_key", "x-api-key: x_api_key_secret_333", "x_api_key_secret_333"),
            ("quoted_with_spaces", 'password="my secret password with spaces 444"', "my secret password with spaces 444"),
            ("jwt_in_body", "Error with JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_signature in payload", "do_not_leak_signature"),
            ("html_page", "<html><body>502 Bad Gateway</body></html>", "<html>"),
        ]

        for label, input_str, secret_to_check in test_cases:
            sanitized = sanitize_error_message(input_str)
            self.assertNotIn(
                secret_to_check,
                sanitized,
                f"Sanitizer leaked secret for '{label}': input='{input_str}', sanitized='{sanitized}'"
            )

        # Max length ceiling: string > 500 characters
        long_str = "A" * 600
        sanitized_long = sanitize_error_message(long_str)
        self.assertLessEqual(len(sanitized_long), 500)

        # None input
        self.assertEqual(sanitize_error_message(None), "")

        # Fallback on unhandled exception
        class BuggyError:
            def __str__(self):
                raise ValueError("Explosion during str conversion")
        self.assertIn("[SANITIZATION_FALLBACK]", sanitize_error_message(BuggyError()))

    def test_backoff_calculations_clamped_post_jitter(self):
        """Verify backoff calculations are strictly clamped to their bounds AFTER jitter across high attempt counts."""
        test_attempts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 50, 100, 500, 1000, 5000, 10000]

        for att in test_attempts:
            for _ in range(200):
                trans_delay = compute_transient_backoff(att)
                self.assertGreaterEqual(trans_delay, 1.0)
                self.assertLessEqual(trans_delay, 300.0)

                auth_delay = compute_auth_backoff(att)
                self.assertGreaterEqual(auth_delay, 1.0)
                self.assertLessEqual(auth_delay, 300.0)

        test_retry_afters = [0.0, -10.0, 0.5, 30.0, 60.0, 3599.0, 3600.0, 10000.0]
        for ra in test_retry_afters:
            for _ in range(200):
                rl_delay = compute_rate_limit_backoff(ra)
                self.assertGreaterEqual(rl_delay, 1.0)
                self.assertLessEqual(rl_delay, 3600.0)

    def test_parse_retry_after_headers(self):
        """Verify Retry-After header parsing for delta-seconds, HTTP-date, edge cases, and fallbacks."""
        self.assertEqual(parse_retry_after("60"), 60.0)
        self.assertEqual(parse_retry_after("-5"), 1.0)
        self.assertEqual(parse_retry_after("5000"), 3600.0)
        self.assertEqual(parse_retry_after("0"), 1.0)
        self.assertEqual(parse_retry_after(None), 30.0)
        self.assertEqual(parse_retry_after("invalid_text"), 30.0)

        # HTTP-date
        future_dt = datetime.now(timezone.utc) + timedelta(seconds=120)
        http_date_str = email.utils.format_datetime(future_dt)
        parsed_secs = parse_retry_after(http_date_str)
        self.assertGreaterEqual(parsed_secs, 110.0)
        self.assertLessEqual(parsed_secs, 130.0)

    def test_delivered_retention_purge_governance(self):
        """Verify delivered records are purged strictly past 72h from delivered_at while pending and quarantined are never purged."""
        outbox = Outbox(self.db_path, self.logger)
        conn = sqlite3.connect(self.db_path)

        now_utc = datetime.now(timezone.utc)
        t_71h = (now_utc - timedelta(hours=71, minutes=59)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_72h = (now_utc - timedelta(hours=72, seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_73h = (now_utc - timedelta(hours=73)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_ancient = (now_utc - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Seed events
        # Event A: delivered 71h59m ago (MUST BE RETAINED)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, delivered_at)
            VALUES ('evt-del-retained', '{}', 'delivered', ?)
        """, (t_71h,))

        # Event B: delivered 72h00m01s ago (MUST BE PURGED)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, delivered_at)
            VALUES ('evt-del-boundary', '{}', 'delivered', ?)
        """, (t_72h,))

        # Event C: delivered 73h ago (MUST BE PURGED)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, delivered_at)
            VALUES ('evt-del-old', '{}', 'delivered', ?)
        """, (t_73h,))

        # Event D: pending 30 days old (MUST NEVER BE PURGED)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, created_at, next_attempt_at)
            VALUES ('evt-pending-ancient', '{}', 'pending', ?, ?)
        """, (t_ancient, t_ancient))

        # Event E: quarantined 30 days old (MUST NEVER BE PURGED)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, created_at, quarantined_at, quarantine_reason)
            VALUES ('evt-quarantine-ancient', '{}', 'quarantined', ?, ?, 'max_retries_exceeded')
        """, (t_ancient, t_ancient))
        conn.commit()
        conn.close()

        # 2. Run purge
        deleted_count = outbox.purge_delivered_events(retention_hours=72)
        self.assertEqual(deleted_count, 2)

        # 3. Verify database contents
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        remaining = {r["detection_event_id"]: r["status"] for r in conn.execute("SELECT detection_event_id, status FROM outbox").fetchall()}
        conn.close()

        self.assertIn("evt-del-retained", remaining)
        self.assertNotIn("evt-del-boundary", remaining)
        self.assertNotIn("evt-del-old", remaining)
        self.assertIn("evt-pending-ancient", remaining)
        self.assertIn("evt-quarantine-ancient", remaining)

    def test_quarantine_lifecycle_and_retrieval(self):
        """Verify mark_quarantined and get_quarantined_events record reason, sanitize last_error, and clear next_attempt_at."""
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-quar-1", "type": "auth_event"})

        raw_err = "HTTP 400 Bad Request: invalid payload token=LEAKED_SECRET_999"
        outbox.mark_quarantined("evt-quar-1", "payload_validation_failed", raw_err)

        # Inspect DB row
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM outbox WHERE detection_event_id = 'evt-quar-1'").fetchone()
        conn.close()

        self.assertEqual(row["status"], "quarantined")
        self.assertEqual(row["quarantine_reason"], "payload_validation_failed")
        self.assertIsNotNone(row["quarantined_at"])
        self.assertTrue(row["quarantined_at"].endswith("Z"))
        self.assertIsNone(row["next_attempt_at"])
        self.assertNotIn("LEAKED_SECRET_999", row["last_error"])
        self.assertIn("token=[REDACTED]", row["last_error"])

        # Check get_quarantined_events
        quarantined = outbox.get_quarantined_events()
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["detection_event_id"], "evt-quar-1")
        self.assertEqual(quarantined[0]["quarantine_reason"], "payload_validation_failed")

        # Must not appear in get_pending_events
        self.assertEqual(len(outbox.get_pending_events()), 0)

    def test_eligible_pending_events_query_filtering(self):
        """Verify get_pending_events(eligible_only=True) selects only events where next_attempt_at <= now in order."""
        outbox = Outbox(self.db_path, self.logger)
        conn = sqlite3.connect(self.db_path)

        now_utc = datetime.now(timezone.utc)
        t_past = (now_utc - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_now = (now_utc - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_future = (now_utc + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")

        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, next_attempt_at)
            VALUES ('evt-past', '{}', 'pending', ?)
        """, (t_past,))
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, next_attempt_at)
            VALUES ('evt-now', '{}', 'pending', ?)
        """, (t_now,))
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, next_attempt_at)
            VALUES ('evt-future', '{}', 'pending', ?)
        """, (t_future,))
        conn.commit()
        conn.close()

        # Eligible only
        eligible = outbox.get_pending_events(eligible_only=True)
        self.assertEqual(len(eligible), 2)
        self.assertEqual(eligible[0]["detection_event_id"], "evt-past")
        self.assertEqual(eligible[1]["detection_event_id"], "evt-now")

        # All pending
        all_pending = outbox.get_pending_events(eligible_only=False)
        self.assertEqual(len(all_pending), 3)

    def test_evaluate_delivery_outcome_decision_matrix(self):
        """Verify evaluate_delivery_outcome correctly maps Central SOC responses to state transitions."""
        eid = "evt-eval-1"

        # 1. HTTP 201 valid contract
        r201_good = evaluate_delivery_outcome(eid, 201, '{"accepted": true, "detection_event_id": "evt-eval-1"}', 0)
        self.assertEqual(r201_good["action"], "DELIVER")
        self.assertFalse(r201_good["is_duplicate"])

        # 2. HTTP 201 mismatched event id
        r201_mismatch = evaluate_delivery_outcome(eid, 201, '{"accepted": true, "detection_event_id": "other-id"}', 0)
        self.assertEqual(r201_mismatch["action"], "RETRY_TRANSIENT")

        # 3. HTTP 201 accepted=False
        r201_not_accepted = evaluate_delivery_outcome(eid, 201, '{"accepted": false, "detection_event_id": "evt-eval-1"}', 0)
        self.assertEqual(r201_not_accepted["action"], "RETRY_TRANSIENT")

        # 4. HTTP 409 duplicate contract
        r409_good = evaluate_delivery_outcome(eid, 409, '{"accepted": true, "duplicate": true, "detection_event_id": "evt-eval-1"}', 0)
        self.assertEqual(r409_good["action"], "DELIVER")
        self.assertTrue(r409_good["is_duplicate"])

        # 5. HTTP 409 duplicate=False
        r409_bad = evaluate_delivery_outcome(eid, 409, '{"accepted": true, "duplicate": false, "detection_event_id": "evt-eval-1"}', 0)
        self.assertEqual(r409_bad["action"], "RETRY_TRANSIENT")

        # 6. HTTP 400 Bad Request
        r400 = evaluate_delivery_outcome(eid, 400, '{"error": "Missing agent_id"}', 0)
        self.assertEqual(r400["action"], "QUARANTINE")
        self.assertEqual(r400["quarantine_reason"], "payload_validation_failed")

        # 7. HTTP 422 Unprocessable Entity
        r422 = evaluate_delivery_outcome(eid, 422, '{"error": "Invalid severity"}', 0)
        self.assertEqual(r422["action"], "QUARANTINE")
        self.assertEqual(r422["quarantine_reason"], "payload_validation_failed")

        # 8. HTTP 401 Unauthorized - NEVER quarantined, even at attempt 100
        r401 = evaluate_delivery_outcome(eid, 401, "Unauthorized", 100)
        self.assertEqual(r401["action"], "RETRY_AUTH")
        self.assertLessEqual(r401["retry_delay"], 300.0)

        # 9. HTTP 403 Forbidden - NEVER quarantined
        r403 = evaluate_delivery_outcome(eid, 403, "Forbidden", 100)
        self.assertEqual(r403["action"], "RETRY_AUTH")
        self.assertLessEqual(r403["retry_delay"], 300.0)

        # 10. HTTP 429 Too Many Requests
        r429 = evaluate_delivery_outcome(eid, 429, "Rate limit", 0, headers={"Retry-After": "45"})
        self.assertEqual(r429["action"], "RETRY_429")
        self.assertGreaterEqual(r429["retry_delay"], 45.0)
        self.assertLessEqual(r429["retry_delay"], 48.0)

        # 11. HTTP 500 transient retry (attempts < 10)
        r500_trans = evaluate_delivery_outcome(eid, 500, "Internal Server Error", 4)
        self.assertEqual(r500_trans["action"], "RETRY_TRANSIENT")

        # 12. HTTP 500 retry exhaustion (current_attempts=9, new_attempts=10 >= max_retries)
        r500_exhaust = evaluate_delivery_outcome(eid, 500, "Internal Server Error", 9, max_retries=10)
        self.assertEqual(r500_exhaust["action"], "QUARANTINE")
        self.assertEqual(r500_exhaust["quarantine_reason"], "max_retries_exceeded")

        # 13. HTTP 200 without contract -> RETRY_TRANSIENT
        r200 = evaluate_delivery_outcome(eid, 200, '{"status": "ok"}', 0)
        self.assertEqual(r200["action"], "RETRY_TRANSIENT")

    def test_delivery_manager_e2e_process_outbox(self):
        """Verify DeliveryManager orchestrates retry backoff, quarantine transitions, and delivered purge end-to-end."""
        outbox = Outbox(self.db_path, self.logger)

        class MockWP2Client(TransportClient):
            def __init__(self, logger):
                super().__init__("http://fake", "tok", logger)
                self.responses = []

            def send_event(self, event):
                if self.responses:
                    return self.responses.pop(0)
                return SendResult(True, False, "", status_code=201, response_body=json.dumps({"accepted": True, "detection_event_id": event.get("detection_event_id")}))

        client = MockWP2Client(self.logger)
        manager = DeliveryManager(outbox, client, self.logger, max_retries=3)

        # Scenario A: Corrupt local JSON -> quarantined immediately
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO outbox (detection_event_id, event_data, status) VALUES ('evt-corrupt', 'not valid json{', 'pending')")
        conn.commit()
        conn.close()

        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        r_corrupt = conn.execute("SELECT status, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-corrupt'").fetchone()
        self.assertEqual(r_corrupt[0], "quarantined")
        self.assertEqual(r_corrupt[1], "corrupted_payload")
        conn.close()

        # Scenario B: HTTP 400 Bad Request -> quarantined immediately with 1 attempt
        outbox.add_event({"detection_event_id": "evt-bad-req", "type": "login"})
        client.responses = [SendResult(False, False, "HTTP 400: Bad Request", status_code=400, response_body='{"error": "Missing field"}')]
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        r_400 = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-bad-req'").fetchone()
        self.assertEqual(r_400[0], "quarantined")
        self.assertEqual(r_400[1], 1)
        self.assertEqual(r_400[2], "payload_validation_failed")
        conn.close()

        # Scenario C: HTTP 401 Unauthorized -> remains pending indefinitely
        outbox.add_event({"detection_event_id": "evt-auth-fail", "type": "login"})
        client.responses = [SendResult(False, False, "HTTP 401: Unauthorized", status_code=401, response_body="Unauthorized")]
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        r_401 = conn.execute("SELECT status, attempts, next_attempt_at FROM outbox WHERE detection_event_id = 'evt-auth-fail'").fetchone()
        self.assertEqual(r_401[0], "pending")
        self.assertEqual(r_401[1], 1)
        self.assertIsNotNone(r_401[2])
        conn.close()

        # Scenario D: HTTP 500 retried up to max_retries=3, then quarantined
        outbox.add_event({"detection_event_id": "evt-500-retry", "type": "login"})
        # Attempt 1 (0 -> 1)
        client.responses = [SendResult(False, False, "HTTP 500: Server Error", status_code=500, response_body="Error")]
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT status, attempts FROM outbox WHERE detection_event_id = 'evt-500-retry'").fetchone(), ("pending", 1))
        # Reset next_attempt_at to past so it is eligible for Attempt 2
        conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = 'evt-500-retry'")
        conn.commit()
        conn.close()

        # Attempt 2 (1 -> 2)
        client.responses = [SendResult(False, False, "HTTP 500: Server Error", status_code=500, response_body="Error")]
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT status, attempts FROM outbox WHERE detection_event_id = 'evt-500-retry'").fetchone(), ("pending", 2))
        conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = 'evt-500-retry'")
        conn.commit()
        conn.close()

        # Attempt 3 (2 -> 3 == max_retries: transitions to quarantined with 3 attempts)
        client.responses = [SendResult(False, False, "HTTP 500: Server Error", status_code=500, response_body="Error")]
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        r_exhaust = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-500-retry'").fetchone()
        self.assertEqual(r_exhaust[0], "quarantined")
        self.assertEqual(r_exhaust[1], 3)
        self.assertEqual(r_exhaust[2], "max_retries_exceeded")
        conn.close()

        # Scenario E: HTTP 201 Created -> delivered
        outbox.add_event({"detection_event_id": "evt-success-201", "type": "login"})
        client.responses = [SendResult(True, False, "", status_code=201, response_body='{"accepted": true, "detection_event_id": "evt-success-201"}')]
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        r_succ = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = 'evt-success-201'").fetchone()
        self.assertEqual(r_succ[0], "delivered")
        self.assertIsNotNone(r_succ[1])
        conn.close()

    def test_regression_01_http_201_missing_outgoing_event_id(self):
        """1. HTTP 201 with missing outgoing event ID must be rejected and never delivered."""
        # A. In evaluate_delivery_outcome:
        r_none = evaluate_delivery_outcome(None, 201, '{"accepted": true, "detection_event_id": "evt-1"}', 0)
        self.assertEqual(r_none["action"], "RETRY_TRANSIENT")

        r_empty = evaluate_delivery_outcome("", 201, '{"accepted": true, "detection_event_id": ""}', 0)
        self.assertEqual(r_empty["action"], "RETRY_TRANSIENT")

        # B. In client.send_event:
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b'{"accepted": true, "detection_event_id": "some-id"}'
        mock_resp.headers = {}
        client = TransportClient("http://fake", "tok", self.logger)

        with unittest.mock.patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value = mock_resp
            # Event without detection_event_id
            res = client.send_event({"data": "no_id"})
            self.assertFalse(res[0])
            self.assertIn("Contract violation on HTTP 201", res[2])

    def test_regression_02_http_201_mismatched_response_event_id(self):
        """2. HTTP 201 with mismatched response event ID must be rejected."""
        # A. evaluate_delivery_outcome
        res = evaluate_delivery_outcome("evt-expected", 201, '{"accepted": true, "detection_event_id": "evt-different"}', 0)
        self.assertEqual(res["action"], "RETRY_TRANSIENT")
        self.assertIn("Contract violation on HTTP 201", res["error"])

        # B. client.send_event
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b'{"accepted": true, "detection_event_id": "evt-different"}'
        mock_resp.headers = {}
        client = TransportClient("http://fake", "tok", self.logger)

        with unittest.mock.patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value = mock_resp
            res = client.send_event({"detection_event_id": "evt-expected"})
            self.assertFalse(res[0])
            self.assertIn("Contract violation on HTTP 201", res[2])

    def test_regression_03_http_201_valid_json_non_dict_types(self):
        """3. HTTP 201 with valid JSON array/string/null/number must be rejected safely."""
        non_dict_bodies = [
            json.dumps([{"accepted": True, "detection_event_id": "evt-1"}]),
            json.dumps("accepted"),
            json.dumps(12345),
            json.dumps(None),
            json.dumps(True)
        ]
        client = TransportClient("http://fake", "tok", self.logger)

        for body in non_dict_bodies:
            # A. evaluate_delivery_outcome
            res = evaluate_delivery_outcome("evt-1", 201, body, 0)
            self.assertEqual(res["action"], "RETRY_TRANSIENT")

            # B. client.send_event
            mock_resp = unittest.mock.MagicMock()
            mock_resp.status = 201
            mock_resp.read.return_value = body.encode("utf-8")
            mock_resp.headers = {}
            with unittest.mock.patch("urllib.request.urlopen") as mock_open:
                mock_open.return_value.__enter__.return_value = mock_resp
                c_res = client.send_event({"detection_event_id": "evt-1"})
                self.assertFalse(c_res[0])
                self.assertIn("Contract violation on HTTP 201", c_res[2])

    def test_regression_04_http_409_missing_or_mismatched_event_id(self):
        """4. HTTP 409 with missing or mismatched event ID must be rejected."""
        # A. Missing in response
        r1 = evaluate_delivery_outcome("evt-409", 409, '{"accepted": true, "duplicate": true}', 0)
        self.assertEqual(r1["action"], "RETRY_TRANSIENT")

        # B. Mismatched in response
        r2 = evaluate_delivery_outcome("evt-409", 409, '{"accepted": true, "duplicate": true, "detection_event_id": "other"}', 0)
        self.assertEqual(r2["action"], "RETRY_TRANSIENT")

        # C. Missing outgoing event_id
        r3 = evaluate_delivery_outcome(None, 409, '{"accepted": true, "duplicate": true, "detection_event_id": "other"}', 0)
        self.assertEqual(r3["action"], "RETRY_TRANSIENT")

        # D. In client.send_event with HTTPError 409
        import urllib.error
        client = TransportClient("http://fake", "tok", self.logger)
        with unittest.mock.patch("urllib.request.urlopen") as mock_open:
            mock_open.side_effect = urllib.error.HTTPError(
                url="http://fake", code=409, msg="Conflict", hdrs={}, fp=unittest.mock.MagicMock(read=lambda: b'{"accepted": true, "duplicate": true, "detection_event_id": "mismatched"}')
            )
            c_res = client.send_event({"detection_event_id": "evt-409"})
            self.assertFalse(c_res[0])

    def test_regression_05_http_409_duplicate_false(self):
        """5. HTTP 409 with duplicate=False must not be accepted as duplicate ACK."""
        res = evaluate_delivery_outcome("evt-409", 409, '{"accepted": true, "duplicate": false, "detection_event_id": "evt-409"}', 0)
        self.assertEqual(res["action"], "RETRY_TRANSIENT")

        # In client
        import urllib.error
        client = TransportClient("http://fake", "tok", self.logger)
        with unittest.mock.patch("urllib.request.urlopen") as mock_open:
            mock_open.side_effect = urllib.error.HTTPError(
                url="http://fake", code=409, msg="Conflict", hdrs={}, fp=unittest.mock.MagicMock(read=lambda: b'{"accepted": true, "duplicate": false, "detection_event_id": "evt-409"}')
            )
            c_res = client.send_event({"detection_event_id": "evt-409"})
            self.assertFalse(c_res[0])

    def test_regression_06_http_200_valid_json_never_delivered(self):
        """6. HTTP 200 with valid JSON must not result in delivery."""
        res = evaluate_delivery_outcome("evt-200", 200, '{"accepted": true, "detection_event_id": "evt-200"}', 0)
        self.assertNotEqual(res["action"], "DELIVER")
        self.assertEqual(res["action"], "RETRY_TRANSIENT")

        # Verify in DeliveryManager that event remains pending
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-200-test", "type": "auth"})

        class Mock200Client(TransportClient):
            def send_event(self, event):
                return SendResult(True, False, "", status_code=200, response_body='{"accepted": true, "detection_event_id": "evt-200-test"}')

        manager = DeliveryManager(outbox, Mock200Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        status = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'evt-200-test'").fetchone()[0]
        self.assertEqual(status, "pending")
        conn.close()

    def test_regression_07_http_200_malformed_json_never_delivered(self):
        """7. HTTP 200 with malformed JSON must not result in delivery."""
        res = evaluate_delivery_outcome("evt-200-bad", 200, "<html><body>OK</body></html>", 0)
        self.assertNotEqual(res["action"], "DELIVER")
        self.assertEqual(res["action"], "RETRY_TRANSIENT")

        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-200-bad", "type": "auth"})

        class Mock200BadClient(TransportClient):
            def send_event(self, event):
                return SendResult(True, False, "", status_code=200, response_body="<html><body>OK</body></html>")

        manager = DeliveryManager(outbox, Mock200BadClient("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        status = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'evt-200-bad'").fetchone()[0]
        self.assertEqual(status, "pending")
        conn.close()

    def test_regression_08_http_202_never_delivered(self):
        """8. HTTP 202 must not result in delivery."""
        res = evaluate_delivery_outcome("evt-202", 202, '{"accepted": true, "detection_event_id": "evt-202"}', 0)
        self.assertNotEqual(res["action"], "DELIVER")
        self.assertEqual(res["action"], "RETRY_TRANSIENT")

        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-202-test", "type": "auth"})

        class Mock202Client(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 202: Accepted", status_code=202, response_body='{"accepted": true}')

        manager = DeliveryManager(outbox, Mock202Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        status = conn.execute("SELECT status FROM outbox WHERE detection_event_id = 'evt-202-test'").fetchone()[0]
        self.assertEqual(status, "pending")
        conn.close()

    def test_regression_09_error_body_credentials_absent_from_logs(self):
        """9. Error-body credentials must not appear in application logs."""
        import logging

        class ListLogHandler(logging.Handler):
            def __init__(self):
                super().__init__()
                self.records = []

            def emit(self, record):
                self.records.append(self.format(record))

        test_logger = logging.getLogger("SensitiveLogTest")
        test_logger.setLevel(logging.DEBUG)
        handler = ListLogHandler()
        test_logger.addHandler(handler)

        secret_bearer = "SECRET_BEARER_ABC999"
        secret_proxy = "SECRET_PROXY_PASS_123"
        secret_cookie = "SECRET_COOKIE_SESSION_456"
        secret_url_pass = "SECRET_URL_PASSWORD_789"
        secret_refresh = "SECRET_REFRESH_TOKEN_012"
        secret_api_key = "SECRET_API_KEY_345"
        secret_raw_pass = "SECRET_RAW_PASS_678"
        raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        raw_error_body = (
            f"Failed upstream: Authorization: Bearer {secret_bearer}, "
            f"Proxy-Authorization: Basic {secret_proxy}, "
            f"Cookie: session={secret_cookie}, "
            f"Redirect: https://admin:{secret_url_pass}@internal.soc/ "
            f"Query: https://soc.internal/?refresh_token={secret_refresh}&other=1 "
            f"Header: x-api-key: {secret_api_key} "
            f"Body: password={secret_raw_pass} "
            f"JWT: {raw_jwt}"
        )

        import urllib.error
        client = TransportClient("http://fake", "tok", test_logger)
        with unittest.mock.patch("urllib.request.urlopen") as mock_open:
            mock_open.side_effect = urllib.error.HTTPError(
                url="http://fake", code=500, msg="Server Error", hdrs={},
                fp=unittest.mock.MagicMock(read=lambda: raw_error_body.encode("utf-8"))
            )
            client.send_event({"detection_event_id": "evt-sens-1"})

        log_output = "\n".join(handler.records)
        self.assertNotIn(secret_bearer, log_output)
        self.assertNotIn(secret_proxy, log_output)
        self.assertNotIn(secret_cookie, log_output)
        self.assertNotIn(secret_url_pass, log_output)
        self.assertNotIn(secret_refresh, log_output)
        self.assertNotIn(secret_api_key, log_output)
        self.assertNotIn(secret_raw_pass, log_output)
        self.assertNotIn(raw_jwt, log_output)

    def test_regression_10_sanitized_error_persistence(self):
        """10. Sanitized errors must be safely persisted in SQLite with no secrets leaked and length <= 500."""
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-persist-test", "type": "test"})

        secret = "VERY_CONFIDENTIAL_KEY_777"
        raw_err = f"Upstream error from server: Authorization: Bearer {secret} " + ("padding_" * 100)

        outbox.mark_failed("evt-persist-test", raw_err)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT last_error FROM outbox WHERE detection_event_id = 'evt-persist-test'").fetchone()
        conn.close()

        stored_err = row[0]
        self.assertNotIn(secret, stored_err)
        self.assertIn("Authorization: [REDACTED]", stored_err)
        self.assertLessEqual(len(stored_err), 500)

    def test_regression_11_auth_beyond_normal_retry_limit_remains_pending(self):
        """11. HTTP 401/403 beyond normal retry limit (e.g. 100 attempts) remains pending indefinitely."""
        eid = "evt-auth-100"

        # Check outcome evaluation at attempt 10, 50, 100
        for att in [10, 50, 100]:
            r401 = evaluate_delivery_outcome(eid, 401, "Unauthorized", att, max_retries=10)
            self.assertEqual(r401["action"], "RETRY_AUTH")
            self.assertIsNone(r401["quarantine_reason"])
            self.assertLessEqual(r401["retry_delay"], 300.0)

            r403 = evaluate_delivery_outcome(eid, 403, "Forbidden", att, max_retries=10)
            self.assertEqual(r403["action"], "RETRY_AUTH")
            self.assertIsNone(r403["quarantine_reason"])
            self.assertLessEqual(r403["retry_delay"], 300.0)

        # Check via DeliveryManager over multiple iterations beyond max_retries
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": eid, "type": "auth"})

        class MockAuthFailClient(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 401: Unauthorized", status_code=401, response_body="Unauthorized")

        manager = DeliveryManager(outbox, MockAuthFailClient("http://fake", "tok", self.logger), self.logger, max_retries=3)

        # Run 5 iterations (beyond max_retries=3)
        for i in range(5):
            conn = sqlite3.connect(self.db_path)
            conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = ?", (eid,))
            conn.commit()
            conn.close()
            manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertEqual(row[1], 5)
        self.assertIsNone(row[2])

    def test_regression_12_rate_limit_retry_after_boundary_and_http_date(self):
        """12. HTTP 429 Retry-After boundary values, clamping [1.0, 3600.0], and HTTP-date handling."""
        # A. Boundary delta-seconds
        self.assertEqual(parse_retry_after("0"), 1.0)
        self.assertEqual(parse_retry_after("-10"), 1.0)
        self.assertEqual(parse_retry_after("100000"), 3600.0)
        self.assertEqual(parse_retry_after("60"), 60.0)
        self.assertEqual(parse_retry_after(None), 30.0)
        self.assertEqual(parse_retry_after("invalid_header"), 30.0)

        # B. HTTP-date format (RFC 2822)
        future_dt = datetime.now(timezone.utc) + timedelta(seconds=120)
        future_str = email.utils.format_datetime(future_dt)
        parsed_future = parse_retry_after(future_str)
        self.assertGreaterEqual(parsed_future, 115.0)
        self.assertLessEqual(parsed_future, 125.0)

        past_dt = datetime.now(timezone.utc) - timedelta(seconds=120)
        past_str = email.utils.format_datetime(past_dt)
        parsed_past = parse_retry_after(past_str)
        self.assertEqual(parsed_past, 1.0)

        # C. compute_rate_limit_backoff bounds
        for _ in range(20):
            d1 = compute_rate_limit_backoff(0.0)
            self.assertGreaterEqual(d1, 1.0)
            self.assertLessEqual(d1, 3600.0)

            d2 = compute_rate_limit_backoff(5000.0)
            self.assertEqual(d2, 3600.0)

    def test_regression_13_exactly_once_attempt_increment_per_failed_delivery(self):
        """13. Retry attempts are incremented exactly once per failed delivery attempt."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-incr-test"
        outbox.add_event({"detection_event_id": eid, "type": "test"})

        conn = sqlite3.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()[0], 0)
        conn.close()

        class MockFailClient(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 500: Server Error", status_code=500, response_body="Error")

        manager = DeliveryManager(outbox, MockFailClient("http://fake", "tok", self.logger), self.logger)

        # Attempt 1: 0 -> 1
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()[0], 1)

        # Make eligible for Attempt 2
        conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = ?", (eid,))
        conn.commit()
        conn.close()

        # Attempt 2: 1 -> 2
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()[0], 2)
        conn.close()

    def test_regression_14_corrupted_payload_quarantine_without_head_of_line_starvation(self):
        """14. Corrupted local payload is quarantined without head-of-line starvation of subsequent events."""
        outbox = Outbox(self.db_path, self.logger)

        # Insert corrupted head event directly into database
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, created_at, next_attempt_at)
            VALUES ('evt-corrupt-head', 'MALFORMED JSON {{{', 'pending', '2026-11-06T00:00:00Z', '2026-11-06T00:00:00Z')
        """)
        conn.commit()
        conn.close()

        # Insert valid tail event
        outbox.add_event({"detection_event_id": "evt-valid-tail", "type": "detection"})

        class MockNormalClient(TransportClient):
            def send_event(self, event):
                eid = event.get("detection_event_id")
                return SendResult(True, False, "", status_code=201, response_body=json.dumps({"accepted": True, "detection_event_id": eid}))

        manager = DeliveryManager(outbox, MockNormalClient("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        head_row = conn.execute("SELECT status, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-corrupt-head'").fetchone()
        tail_row = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = 'evt-valid-tail'").fetchone()
        conn.close()

        # Corrupted head was quarantined immediately
        self.assertEqual(head_row[0], "quarantined")
        self.assertEqual(head_row[1], "corrupted_payload")

        # Valid tail was NOT starved; it was delivered in the same process_outbox run
        self.assertEqual(tail_row[0], "delivered")
        self.assertIsNotNone(tail_row[1])

    # =========================================================================
    # WP-2-C Revision 3 Dedicated Regression Tests
    # =========================================================================

    def test_rev3_plain_tuple_true_false_cannot_deliver_in_production(self):
        """Rev3-1: Plain (True, False, "") without verifiable HTTP metadata cannot deliver an event."""
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-tuple-tf", "type": "auth"})

        class PlainTupleClient(TransportClient):
            def send_event(self, event):
                return (True, False, "")

        manager = DeliveryManager(outbox, PlainTupleClient("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = 'evt-tuple-tf'").fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)

    def test_rev3_plain_tuple_true_true_cannot_deliver_in_production(self):
        """Rev3-2: Plain (True, True, "") without verifiable HTTP metadata cannot deliver an event."""
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-tuple-tt", "type": "auth"})

        class PlainTupleDuplicateClient(TransportClient):
            def send_event(self, event):
                return (True, True, "")

        manager = DeliveryManager(outbox, PlainTupleDuplicateClient("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = 'evt-tuple-tt'").fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)

    def test_rev3_missing_or_fabricated_response_body_cannot_authorize_delivery(self):
        """Rev3-3: Missing, fabricated, or empty response body cannot authorize delivery."""
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event({"detection_event_id": "evt-no-body", "type": "auth"})

        class MissingBodyClient(TransportClient):
            def send_event(self, event):
                return SendResult(True, False, "", status_code=201, response_body="")

        manager = DeliveryManager(outbox, MissingBodyClient("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = 'evt-no-body'").fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertIsNone(row[1])

    def test_rev3_real_http_201_with_matching_ack_delivers(self):
        """Rev3-4: Real HTTP 201 with exact matching acknowledgement still delivers."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-real-201"
        outbox.add_event({"detection_event_id": eid, "type": "detection"})

        class Real201Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, False, "", status_code=201,
                    response_body=json.dumps({"accepted": True, "detection_event_id": eid})
                )

        manager = DeliveryManager(outbox, Real201Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "delivered")
        self.assertIsNotNone(row[1])

    def test_rev3_real_http_409_with_duplicate_ack_delivers(self):
        """Rev3-5: Real HTTP 409 with exact duplicate acknowledgement still delivers."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-real-409"
        outbox.add_event({"detection_event_id": eid, "type": "detection"})

        class Real409Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, True, "", status_code=409,
                    response_body=json.dumps({"accepted": True, "duplicate": True, "detection_event_id": eid})
                )

        manager = DeliveryManager(outbox, Real409Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "delivered")
        self.assertIsNotNone(row[1])

    def test_rev3_immediate_http_400_quarantine_increments_attempts_once(self):
        """Rev3-6: Immediate HTTP 400 quarantine increments attempts exactly once."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-quar-400"
        outbox.add_event({"detection_event_id": eid, "type": "bad"})

        class Http400Client(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 400: Bad Request", status_code=400, response_body='{"error": "bad"}')

        manager = DeliveryManager(outbox, Http400Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "quarantined")
        self.assertEqual(row[1], 1)
        self.assertEqual(row[2], "payload_validation_failed")

    def test_rev3_immediate_http_422_quarantine_increments_attempts_once(self):
        """Rev3-7: Immediate HTTP 422 quarantine increments attempts exactly once."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-quar-422"
        outbox.add_event({"detection_event_id": eid, "type": "unprocessable"})

        class Http422Client(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 422: Unprocessable Entity", status_code=422, response_body='{"error": "unprocessable"}')

        manager = DeliveryManager(outbox, Http422Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "quarantined")
        self.assertEqual(row[1], 1)
        self.assertEqual(row[2], "payload_validation_failed")

    def test_rev3_retry_exhaustion_quarantine_increments_attempts_on_terminal_attempt(self):
        """Rev3-8: Retry exhaustion increments attempts exactly once on the terminal attempt."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-exhaust-test"
        outbox.add_event({"detection_event_id": eid, "type": "transient"})

        class Http503Client(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 503: Service Unavailable", status_code=503, response_body="Busy")

        manager = DeliveryManager(outbox, Http503Client("http://fake", "tok", self.logger), self.logger, max_retries=2)

        # Attempt 1: 0 -> 1 (pending)
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        row1 = conn.execute("SELECT status, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        self.assertEqual(row1[0], "pending")
        self.assertEqual(row1[1], 1)

        # Make eligible for Attempt 2
        conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = ?", (eid,))
        conn.commit()
        conn.close()

        # Attempt 2: 1 -> 2 (quarantined: terminal attempt reaching max_retries=2)
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        row2 = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row2[0], "quarantined")
        self.assertEqual(row2[1], 2)
        self.assertEqual(row2[2], "max_retries_exceeded")

    def test_rev3_auth_401_403_increments_once_per_attempt_never_quarantines(self):
        """Rev3-9: HTTP 401/403 increments attempts once per attempt but never enters quarantine."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-auth-incr"
        outbox.add_event({"detection_event_id": eid, "type": "auth"})

        class AuthFailClient(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 401: Unauthorized", status_code=401, response_body="Unauthorized")

        manager = DeliveryManager(outbox, AuthFailClient("http://fake", "tok", self.logger), self.logger, max_retries=2)

        # 4 iterations (exceeding max_retries=2)
        for expected_attempts in range(1, 5):
            conn = sqlite3.connect(self.db_path)
            conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = ?", (eid,))
            conn.commit()
            conn.close()

            manager.process_outbox()

            conn = sqlite3.connect(self.db_path)
            row = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
            conn.close()

            self.assertEqual(row[0], "pending")
            self.assertEqual(row[1], expected_attempts)
            self.assertIsNone(row[2])

    def test_rev3_rate_limit_429_increments_once_per_attempt(self):
        """Rev3-10: HTTP 429 increments attempts once per attempt."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-429-incr"
        outbox.add_event({"detection_event_id": eid, "type": "ratelimit"})

        class RateLimitClient(TransportClient):
            def send_event(self, event):
                return SendResult(False, False, "HTTP 429", status_code=429, response_body="Too Many Requests", headers={"Retry-After": "5"})

        manager = DeliveryManager(outbox, RateLimitClient("http://fake", "tok", self.logger), self.logger, max_retries=5)

        # Attempt 1: 0 -> 1
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        row1 = conn.execute("SELECT status, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        self.assertEqual(row1[0], "pending")
        self.assertEqual(row1[1], 1)

        # Make eligible for Attempt 2
        conn.execute("UPDATE outbox SET next_attempt_at = '2020-01-01T00:00:00Z' WHERE detection_event_id = ?", (eid,))
        conn.commit()
        conn.close()

        # Attempt 2: 1 -> 2
        manager.process_outbox()
        conn = sqlite3.connect(self.db_path)
        row2 = conn.execute("SELECT status, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row2[0], "pending")
        self.assertEqual(row2[1], 2)

    def test_rev3_corrupted_local_payload_quarantine_does_not_increment_attempts(self):
        """Rev3-11: Local corrupted payload quarantine does not increment attempts."""
        outbox = Outbox(self.db_path, self.logger)

        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO outbox (detection_event_id, event_data, status, attempts, created_at, next_attempt_at)
            VALUES ('evt-corrupt-no-incr', 'INVALID JSON {{', 'pending', 0, '2026-11-06T00:00:00Z', '2026-11-06T00:00:00Z')
        """)
        conn.commit()
        conn.close()

        dummy_client = TransportClient("http://fake", "tok", self.logger)
        manager = DeliveryManager(outbox, dummy_client, self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = 'evt-corrupt-no-incr'").fetchone()
        conn.close()

        self.assertEqual(row[0], "quarantined")
        self.assertEqual(row[1], 0)
        self.assertEqual(row[2], "corrupted_payload")

    def test_rev3_reprocessing_quarantined_event_does_not_increment_attempts_again(self):
        """Rev3-12: Reprocessing a quarantined event does not increment attempts again."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-reprocess-test"
        outbox.add_event({"detection_event_id": eid, "type": "test"})

        # Initial quarantine with increment_attempts=True (0 -> 1)
        outbox.mark_quarantined(eid, "initial_reason", "initial error", increment_attempts=True)

        conn = sqlite3.connect(self.db_path)
        row1 = conn.execute("SELECT status, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        self.assertEqual(row1[0], "quarantined")
        self.assertEqual(row1[1], 1)
        conn.close()

        # Subsequent quarantine call on already quarantined event
        outbox.mark_quarantined(eid, "second_reason", "second error", increment_attempts=True)

        conn = sqlite3.connect(self.db_path)
        row2 = conn.execute("SELECT status, attempts, quarantine_reason FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        # Attempts must remain 1
        self.assertEqual(row2[0], "quarantined")
        self.assertEqual(row2[1], 1)
        self.assertEqual(row2[2], "second_reason")

    # =========================================================================
    # WP-2-C REVISION 4 REGRESSION TESTS: FABRICATED RESPONSE BODY COVERAGE
    # =========================================================================

    def test_rev4_http_201_fabricated_response_body_cannot_deliver(self):
        """Rev4-1: HTTP 201 with a fabricated response body cannot mark event delivered."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-rev4-fab"
        outbox.add_event({"detection_event_id": eid, "type": "detection"})

        class Fabricated201Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, False, "", status_code=201,
                    response_body='{"status": "ok", "message": "created", "id": 12345}'
                )

        manager = DeliveryManager(outbox, Fabricated201Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)

    def test_rev4_http_201_accepted_true_missing_event_id_cannot_deliver(self):
        """Rev4-2: HTTP 201 with accepted: true but missing event ID cannot mark event delivered."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-rev4-noid"
        outbox.add_event({"detection_event_id": eid, "type": "detection"})

        class MissingId201Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, False, "", status_code=201,
                    response_body='{"accepted": true}'
                )

        manager = DeliveryManager(outbox, MissingId201Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)

    def test_rev4_http_201_mismatched_event_id_cannot_deliver(self):
        """Rev4-3: HTTP 201 with mismatched event ID cannot mark event delivered."""
        outbox = Outbox(self.db_path, self.logger)
        eid = "evt-rev4-mismatch"
        outbox.add_event({"detection_event_id": eid, "type": "detection"})

        class Mismatched201Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, False, "", status_code=201,
                    response_body=json.dumps({"accepted": True, "detection_event_id": "totally-different-id"})
                )

        manager = DeliveryManager(outbox, Mismatched201Client("http://fake", "tok", self.logger), self.logger)
        manager.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)

    def test_rev4_http_409_missing_or_incorrect_duplicate_fields_cannot_deliver(self):
        """Rev4-4: HTTP 409 with missing or incorrect duplicate acknowledgement fields cannot deliver."""
        bad_409_payloads = [
            # A: missing duplicate key
            json.dumps({"accepted": True, "detection_event_id": "evt-rev4-dup"}),
            # B: duplicate is False
            json.dumps({"accepted": True, "duplicate": False, "detection_event_id": "evt-rev4-dup"}),
            # C: missing accepted key
            json.dumps({"duplicate": True, "detection_event_id": "evt-rev4-dup"}),
            # D: accepted is False
            json.dumps({"accepted": False, "duplicate": True, "detection_event_id": "evt-rev4-dup"}),
            # E: missing detection_event_id
            json.dumps({"accepted": True, "duplicate": True}),
            # F: mismatched detection_event_id
            json.dumps({"accepted": True, "duplicate": True, "detection_event_id": "wrong-id"}),
            # G: completely fabricated body
            json.dumps({"error": "conflict", "code": 409, "detail": "already exists"}),
        ]

        for i, payload in enumerate(bad_409_payloads):
            db_path = os.path.join(self.test_dir, f"test_bad_409_{i}.db")
            outbox = Outbox(db_path, self.logger)
            eid = "evt-rev4-dup"
            outbox.add_event({"detection_event_id": eid, "type": "detection"})

            class Bad409Client(TransportClient):
                def __init__(self, p, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self._payload = p
                def send_event(self, event):
                    return SendResult(
                        True, True, "", status_code=409,
                        response_body=self._payload
                    )

            manager = DeliveryManager(outbox, Bad409Client(payload, "http://fake", "tok", self.logger), self.logger)
            manager.process_outbox()

            conn = sqlite3.connect(db_path)
            row = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = ?", (eid,)).fetchone()
            conn.close()

            self.assertEqual(row[0], "pending", f"Failed on payload index {i}: {payload}")
            self.assertIsNone(row[1], f"delivered_at must be None for payload {i}: {payload}")
            self.assertEqual(row[2], 1, f"attempts must be 1 for payload {i}: {payload}")

    def test_rev4_positive_matching_http_201_and_http_409_deliver(self):
        """Rev4-5: Positive tests for valid matching HTTP 201 and HTTP 409 acknowledgements."""
        # 1. Valid HTTP 201 matching ACK
        eid_201 = "evt-rev4-pos-201"
        outbox_201 = Outbox(self.db_path, self.logger)
        outbox_201.add_event({"detection_event_id": eid_201, "type": "detection"})

        class Valid201Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, False, "", status_code=201,
                    response_body=json.dumps({"accepted": True, "detection_event_id": eid_201})
                )

        manager_201 = DeliveryManager(outbox_201, Valid201Client("http://fake", "tok", self.logger), self.logger)
        manager_201.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row_201 = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = ?", (eid_201,)).fetchone()
        conn.close()

        self.assertEqual(row_201[0], "delivered")
        self.assertIsNotNone(row_201[1])

        # 2. Valid HTTP 409 duplicate matching ACK
        eid_409 = "evt-rev4-pos-409"
        outbox_409 = Outbox(self.db_path, self.logger)
        outbox_409.add_event({"detection_event_id": eid_409, "type": "detection"})

        class Valid409Client(TransportClient):
            def send_event(self, event):
                return SendResult(
                    True, True, "", status_code=409,
                    response_body=json.dumps({"accepted": True, "duplicate": True, "detection_event_id": eid_409})
                )

        manager_409 = DeliveryManager(outbox_409, Valid409Client("http://fake", "tok", self.logger), self.logger)
        manager_409.process_outbox()

        conn = sqlite3.connect(self.db_path)
        row_409 = conn.execute("SELECT status, delivered_at, attempts FROM outbox WHERE detection_event_id = ?", (eid_409,)).fetchone()
        conn.close()

        self.assertEqual(row_409[0], "delivered")
        self.assertIsNotNone(row_409[1])

    # =========================================================================
    # WP-2-D TESTS: WAL, CONCURRENCY, AND BUSY-TIMEOUT CONFIGURATION (16 TESTS)
    # =========================================================================

    def test_wp2d_01_effective_sqlite_pragmas(self):
        """WP-2-D (1/16): Verify connections establish WAL mode, synchronous=NORMAL, busy_timeout=5000, and wal_autocheckpoint=1000."""
        outbox = Outbox(self.db_path, self.logger, busy_timeout_ms=5000, wal_autocheckpoint=1000)
        conn = outbox._get_connection()
        try:
            # 1. Check journal_mode == 'wal'
            cur = conn.execute("PRAGMA journal_mode;")
            journal_mode = cur.fetchone()[0]
            self.assertEqual(journal_mode.lower(), "wal")

            # 2. Check synchronous == 1 (NORMAL)
            cur = conn.execute("PRAGMA synchronous;")
            synchronous = cur.fetchone()[0]
            self.assertEqual(synchronous, 1)

            # 3. Check busy_timeout == 5000
            cur = conn.execute("PRAGMA busy_timeout;")
            busy_timeout = cur.fetchone()[0]
            self.assertEqual(busy_timeout, 5000)

            # 4. Check wal_autocheckpoint == 1000
            cur = conn.execute("PRAGMA wal_autocheckpoint;")
            wal_autocheckpoint = cur.fetchone()[0]
            self.assertEqual(wal_autocheckpoint, 1000)

            # 5. Check temp_store == 2 (MEMORY)
            cur = conn.execute("PRAGMA temp_store;")
            temp_store = cur.fetchone()[0]
            self.assertEqual(temp_store, 2)

            # 6. Check foreign_keys == 1 (ON)
            cur = conn.execute("PRAGMA foreign_keys;")
            foreign_keys = cur.fetchone()[0]
            self.assertEqual(foreign_keys, 1)
        finally:
            conn.close()

    def test_wp2d_02_synchronous_mode_configuration_and_validation(self):
        """WP-2-D (2/16): Verify NORMAL and configurable FULL synchronous modes, and validation rejects invalid modes."""
        # 1. Configurable FULL synchronous mode
        outbox_full = Outbox(self.db_path, self.logger, synchronous_mode="FULL")
        conn_full = outbox_full._get_connection()
        try:
            cur = conn_full.execute("PRAGMA synchronous;")
            self.assertEqual(cur.fetchone()[0], 2)  # FULL == 2
        finally:
            conn_full.close()

        # 2. Configurable NORMAL synchronous mode
        outbox_normal = Outbox(self.db_path, self.logger, synchronous_mode="NORMAL")
        conn_normal = outbox_normal._get_connection()
        try:
            cur = conn_normal.execute("PRAGMA synchronous;")
            self.assertEqual(cur.fetchone()[0], 1)  # NORMAL == 1
        finally:
            conn_normal.close()

        # 3. Validation rejection of invalid synchronous modes
        for invalid_mode in ["OFF", "EXTRA", "0", "FAST", ""]:
            with self.assertRaises(ValueError):
                Outbox(self.db_path, self.logger, synchronous_mode=invalid_mode)

    def test_wp2d_03_wal_autocheckpoint_configuration_and_validation(self):
        """WP-2-D (3/16): Verify wal_autocheckpoint configuration and strict integer validation for both PRAGMAs."""
        # 1. Configurable wal_autocheckpoint
        outbox_500 = Outbox(self.db_path, self.logger, wal_autocheckpoint=500)
        conn = outbox_500._get_connection()
        try:
            cur = conn.execute("PRAGMA wal_autocheckpoint;")
            self.assertEqual(cur.fetchone()[0], 500)
        finally:
            conn.close()

        # 2. Validation rejection for wal_autocheckpoint (< 10 or non-int)
        for invalid_val in [9, 0, -1, "1000", None, 5.5]:
            with self.assertRaises(ValueError):
                Outbox(self.db_path, self.logger, wal_autocheckpoint=invalid_val)

        # 3. Validation rejection for busy_timeout_ms (< 1000 or non-int)
        for invalid_val in [999, 0, -500, "5000", None, 1000.5]:
            with self.assertRaises(ValueError):
                Outbox(self.db_path, self.logger, busy_timeout_ms=invalid_val)

    def test_wp2d_04_passive_checkpoint_returns_tuple_metadata(self):
        """WP-2-D (4/16): Verify PASSIVE checkpoint behavior returning (busy, log, checkpointed) tuple metadata."""
        outbox = Outbox(self.db_path, self.logger)
        res = outbox.checkpoint("PASSIVE")

        # Must be instance of tuple and CheckpointResult
        self.assertIsInstance(res, tuple)
        self.assertIsInstance(res, CheckpointResult)

        # Unpack tuple
        busy, log, checkpointed = res
        self.assertIn(busy, (0, 1))
        self.assertGreaterEqual(log, 0)
        self.assertGreaterEqual(checkpointed, 0)

        # Attribute access
        self.assertEqual(res.busy, busy)
        self.assertEqual(res.log, log)
        self.assertEqual(res.checkpointed, checkpointed)

        # Reject invalid checkpoint modes
        for invalid_mode in ["INVALID", "BLOCKING", "FORCE", ""]:
            with self.assertRaises(ValueError):
                outbox.checkpoint(invalid_mode)

    def test_wp2d_05_checkpoint_while_queue_active(self):
        """WP-2-D (5/16): Verify checkpoint executes non-blockingly while outbox queue is active without data loss."""
        outbox = Outbox(self.db_path, self.logger)

        # Insert events into outbox
        for i in range(5):
            outbox.add_event({
                "detection_event_id": f"evt-wp2d-chk-{i}",
                "event_data": {"type": "test", "num": i}
            })

        # Run PASSIVE checkpoint while queue has pending events
        res1 = outbox.checkpoint("PASSIVE")
        self.assertIsInstance(res1, CheckpointResult)

        # Verify all 5 pending events are present and undamaged
        pending = outbox.get_pending_events(limit=10)
        self.assertEqual(len(pending), 5)
        self.assertEqual({p["detection_event_id"] for p in pending}, {f"evt-wp2d-chk-{i}" for i in range(5)})

        # Deliver two events and checkpoint again
        outbox.mark_delivered("evt-wp2d-chk-0")
        outbox.mark_delivered("evt-wp2d-chk-1")
        res2 = outbox.checkpoint("PASSIVE")
        self.assertIsInstance(res2, CheckpointResult)

        # Verify pending count updated to 3 and delivered status is intact
        pending_after = outbox.get_pending_events(limit=10)
        self.assertEqual(len(pending_after), 3)

    def test_wp2d_06_connection_cleanup_on_pragma_failure(self):
        """WP-2-D (6/16): Verify _get_connection closes connection and does not leak handle on PRAGMA failure."""
        outbox = Outbox(self.db_path, self.logger)
        mock_conn = unittest.mock.MagicMock()
        mock_conn.execute.side_effect = sqlite3.OperationalError("Simulated PRAGMA failure")

        with patch("sqlite3.connect", return_value=mock_conn):
            with self.assertRaises(sqlite3.OperationalError):
                outbox._get_connection()
        mock_conn.close.assert_called_once()

    def test_wp2d_07_is_sqlite_busy_or_locked_masking(self):
        """WP-2-D (7/16): Verify primary and extended SQLite result code masking (code & 0xFF in (5, 6))."""
        class MockSqliteErr(sqlite3.OperationalError):
            def __init__(self, msg, code):
                super().__init__(msg)
                self.sqlite_errorcode = code

        # Primary codes: SQLITE_BUSY (5), SQLITE_LOCKED (6)
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("busy", 5)))
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("locked", 6)))

        # Extended codes:
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("busy snapshot", 517)))       # SQLITE_BUSY_SNAPSHOT
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("busy recovery", 261)))       # SQLITE_BUSY_RECOVERY
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("busy timeout", 773)))        # SQLITE_BUSY_TIMEOUT
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("locked sharedcache", 262)))  # SQLITE_LOCKED_SHAREDCACHE
        self.assertTrue(is_sqlite_busy_or_locked(MockSqliteErr("locked vtab", 518)))         # SQLITE_LOCKED_VTAB

        # Non-contention codes
        self.assertFalse(is_sqlite_busy_or_locked(MockSqliteErr("generic error", 1)))        # SQLITE_ERROR
        self.assertFalse(is_sqlite_busy_or_locked(MockSqliteErr("constraint", 19)))         # SQLITE_CONSTRAINT
        self.assertFalse(is_sqlite_busy_or_locked(MockSqliteErr("corrupt", 11)))            # SQLITE_CORRUPT

        # String fallback inspection (without sqlite_errorcode)
        self.assertTrue(is_sqlite_busy_or_locked(sqlite3.OperationalError("database is locked")))
        self.assertTrue(is_sqlite_busy_or_locked(sqlite3.OperationalError("database is busy")))
        self.assertFalse(is_sqlite_busy_or_locked(sqlite3.OperationalError("no such table: outbox")))

    def test_wp2d_08_bounded_whole_transaction_retry_on_busy(self):
        """WP-2-D (8/16): Verify bounded whole-transaction retry on busy contention with success after retry and failure on exhaustion."""
        outbox = Outbox(self.db_path, self.logger)

        # 1. Operation succeeds after 2 busy failures
        call_count = [0]
        def operation_succeeds_on_attempt_3(conn):
            call_count[0] += 1
            if call_count[0] < 3:
                err = sqlite3.OperationalError("database is locked")
                err.sqlite_errorcode = 5
                raise err
            conn.execute("INSERT OR IGNORE INTO outbox (detection_event_id, event_data, status) VALUES ('retry-succ', '{}', 'pending')")
            return "SUCCESS"

        result = outbox._execute_transaction_with_retry(operation_succeeds_on_attempt_3, max_retries=4)
        self.assertEqual(result, "SUCCESS")
        self.assertEqual(call_count[0], 3)

        # 2. Operation exhausts retries and raises OperationalError
        fail_count = [0]
        def operation_always_busy(conn):
            fail_count[0] += 1
            err = sqlite3.OperationalError("database is busy")
            err.sqlite_errorcode = 5
            raise err

        with self.assertRaises(sqlite3.OperationalError):
            outbox._execute_transaction_with_retry(operation_always_busy, max_retries=3)
        # Attempt 0, plus 3 retries == 4 total invocations
        self.assertEqual(fail_count[0], 4)

    def test_wp2d_09_transaction_rollback_before_retry(self):
        """WP-2-D (9/16): Verify ROLLBACK is executed before retrying transaction on lock contention."""
        outbox = Outbox(self.db_path, self.logger)

        invocations = []
        def failing_op(conn):
            invocations.append("op")
            err = sqlite3.OperationalError("database is locked")
            err.sqlite_errorcode = 5
            raise err

        with patch.object(outbox, "_get_connection") as mock_get_conn:
            mock_conn = unittest.mock.MagicMock()
            mock_get_conn.return_value = mock_conn

            with self.assertRaises(sqlite3.OperationalError):
                outbox._execute_transaction_with_retry(failing_op, max_retries=1)

            # Each attempt must have issued BEGIN IMMEDIATE and ROLLBACK
            rollback_calls = [c for c in mock_conn.execute.call_args_list if c[0][0] == "ROLLBACK"]
            self.assertEqual(len(rollback_calls), 2)  # initial attempt + 1 retry

    def test_wp2d_10_same_process_mutual_exclusion(self):
        """WP-2-D (10/16): Verify Tier 1 same-process mutual exclusion via process-local registry."""
        l1 = OutboxLock(self.db_path, logger=self.logger)
        l2 = OutboxLock(self.db_path, logger=self.logger)

        self.assertTrue(l1.acquire())
        # Second acquire in same process on same path must be rejected immediately
        self.assertFalse(l2.acquire())

        l1.release()

        # After release, l2 must be able to acquire
        self.assertTrue(l2.acquire())
        l2.release()

    def test_wp2d_11_cross_process_mutual_exclusion(self):
        """WP-2-D (11/16): Verify Tier 2 cross-process file lock via external subprocess."""
        lock_path = canonicalize_db_path(self.db_path) + ".lock"

        child_code = (
            "import os, sys, time\n"
            "try:\n"
            "    import msvcrt\n"
            "except ImportError:\n"
            "    sys.exit(2)\n"
            f"lp = r'{lock_path}'\n"
            "os.makedirs(os.path.dirname(lp), exist_ok=True)\n"
            "fd = os.open(lp, os.O_CREAT | os.O_RDWR)\n"
            "msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)\n"
            "print('HELD', flush=True)\n"
            "time.sleep(2.0)\n"
            "try:\n"
            "    os.lseek(fd, 0, os.SEEK_SET)\n"
            "    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)\n"
            "except Exception: pass\n"
            "os.close(fd)\n"
            "print('RELEASED', flush=True)\n"
        )

        proc = subprocess.Popen([sys.executable, "-c", child_code], stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline().strip()
            if line == "HELD":
                main_lock = OutboxLock(self.db_path, logger=self.logger)
                self.assertFalse(main_lock.acquire())
            proc.wait(timeout=5.0)

            main_lock = OutboxLock(self.db_path, logger=self.logger)
            self.assertTrue(main_lock.acquire())
            main_lock.release()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_wp2d_12_canonical_path_equivalence(self):
        """WP-2-D (12/16): Verify path variations (case/slashes) resolve to identical mutual exclusion."""
        p_upper = self.db_path.upper()
        p_lower = self.db_path.lower()

        l_upper = OutboxLock(p_upper, logger=self.logger)
        l_lower = OutboxLock(p_lower, logger=self.logger)

        self.assertEqual(l_upper.canonical_db_path, l_lower.canonical_db_path)
        self.assertEqual(l_upper.canonical_lock_path, l_lower.canonical_lock_path)

        self.assertTrue(l_upper.acquire())
        self.assertFalse(l_lower.acquire())

        l_upper.release()
        self.assertTrue(l_lower.acquire())
        l_lower.release()

    def test_wp2d_13_lock_release_after_exceptions(self):
        """WP-2-D (13/16): Verify OutboxLock releases lock properly when an exception occurs inside context manager."""
        lock = OutboxLock(self.db_path, logger=self.logger)

        try:
            with lock:
                self.assertTrue(lock._local_acquired)
                self.assertTrue(lock._os_acquired)
                raise RuntimeError("Simulated failure inside locked block")
        except RuntimeError:
            pass

        # Verify lock was completely released
        self.assertFalse(lock._local_acquired)
        self.assertFalse(lock._os_acquired)

        # Another lock must be able to acquire immediately
        lock2 = OutboxLock(self.db_path, logger=self.logger)
        self.assertTrue(lock2.acquire())
        lock2.release()

    def test_wp2d_14_delivery_worker_mutual_exclusion_lifecycle(self):
        """WP-2-D (14/16): Verify DeliveryWorker uses OutboxLock, exits cleanly without loop when lock acquisition fails, and allows subsequent workers after termination."""
        outbox = Outbox(self.db_path, self.logger)
        client = TransportClient("http://fake", "tok", self.logger)
        manager = DeliveryManager(outbox, client, self.logger)

        worker1 = DeliveryWorker(manager, self.logger, poll_interval=0.05)
        worker1.start()

        # Allow worker1 to acquire lock
        time.sleep(0.1)
        self.assertTrue(worker1.is_alive())

        # Start worker2 targeting the same outbox
        worker2 = DeliveryWorker(manager, self.logger, poll_interval=0.05)
        worker2.start()

        # worker2 should fail to acquire lock and exit quickly without entering delivery loop
        worker2.join(timeout=1.0)
        self.assertFalse(worker2.is_alive())
        # worker1 must still be running
        self.assertTrue(worker1.is_alive())

        # Stop worker1
        worker1.stop()
        self.assertFalse(worker1.is_alive())

        # Now worker3 should be able to acquire lock and run
        worker3 = DeliveryWorker(manager, self.logger, poll_interval=0.05)
        worker3.start()
        time.sleep(0.1)
        self.assertTrue(worker3.is_alive())
        worker3.stop()
        self.assertFalse(worker3.is_alive())

    def test_wp2d_15_worker_invalid_database_path_fails_closed(self):
        """WP-2-D (15/16): Verify DeliveryWorker validates outbox db_path and fails closed if invalid, empty, or whitespace."""
        client = TransportClient("http://fake", "tok", self.logger)

        # 1. Invalid empty string
        mock_outbox_empty = unittest.mock.MagicMock()
        mock_outbox_empty.db_path = ""
        mgr_empty = DeliveryManager(mock_outbox_empty, client, self.logger)
        with self.assertRaises(ValueError):
            DeliveryWorker(mgr_empty, self.logger)

        # 2. Invalid whitespace string
        mock_outbox_space = unittest.mock.MagicMock()
        mock_outbox_space.db_path = "   "
        mgr_space = DeliveryManager(mock_outbox_space, client, self.logger)
        with self.assertRaises(ValueError):
            DeliveryWorker(mgr_space, self.logger)

        # 3. Invalid None path
        mock_outbox_none = unittest.mock.MagicMock()
        mock_outbox_none.db_path = None
        mgr_none = DeliveryManager(mock_outbox_none, client, self.logger)
        with self.assertRaises(ValueError):
            DeliveryWorker(mgr_none, self.logger)

        # 4. Invalid non-string path
        mock_outbox_num = unittest.mock.MagicMock()
        mock_outbox_num.db_path = 12345
        mgr_num = DeliveryManager(mock_outbox_num, client, self.logger)
        with self.assertRaises(ValueError):
            DeliveryWorker(mgr_num, self.logger)

    def test_wp2d_16_platform_locking_unavailable_fails_closed(self):
        """WP-2-D (16/16): Verify no bypass when cross-process locking is unsupported (msvcrt is None or missing locking) - fails closed."""
        lock_path = self.db_path + ".unsupported.lock"
        proc_lock = WindowsProcessLock(lock_path, logger=self.logger)

        # Simulate msvcrt being None
        with patch("transport.outbox.msvcrt", None):
            self.assertFalse(proc_lock.acquire())

        # Simulate msvcrt missing locking attribute
        mock_msvcrt = unittest.mock.MagicMock(spec=[])
        with patch("transport.outbox.msvcrt", mock_msvcrt):
            self.assertFalse(proc_lock.acquire())

        # Verify OutboxLock also fails closed when platform locking is unavailable
        outbox_lock = OutboxLock(self.db_path, logger=self.logger)
        with patch("transport.outbox.msvcrt", None):
            self.assertFalse(outbox_lock.acquire())

    def test_wp2_worker_missing_delivery_manager_or_outbox_fails_closed(self):
        """Verify DeliveryWorker fails closed if delivery_manager is None or missing 'outbox'."""
        with self.assertRaises(ValueError):
            DeliveryWorker(None, self.logger)

        # Mock delivery_manager missing outbox attribute
        mock_mgr_no_outbox = unittest.mock.NonCallableMagicMock(spec=[])
        with self.assertRaises(ValueError):
            DeliveryWorker(mock_mgr_no_outbox, self.logger)

        # Mock delivery_manager with outbox=None
        mock_mgr_outbox_none = unittest.mock.MagicMock()
        mock_mgr_outbox_none.outbox = None
        with self.assertRaises(ValueError):
            DeliveryWorker(mock_mgr_outbox_none, self.logger)

    def test_wp2_worker_memory_db_path_rejected_in_production(self):
        """Verify DeliveryWorker strictly rejects ':memory:' database path in production mode."""
        client = TransportClient("http://fake", "tok", self.logger)
        mock_outbox_mem = unittest.mock.MagicMock()
        mock_outbox_mem.db_path = ":memory:"
        mgr_mem = DeliveryManager(mock_outbox_mem, client, self.logger)
        with self.assertRaises(ValueError) as ctx:
            DeliveryWorker(mgr_mem, self.logger)
        self.assertIn("':memory:' database cannot be used for production locking", str(ctx.exception))

    def test_wp2_worker_unlocked_when_lock_acquisition_fails_never_processes_events(self):
        """Verify that when OutboxLock acquisition fails, DeliveryWorker immediately terminates and NEVER calls process_outbox()."""
        outbox = Outbox(self.db_path, self.logger)
        client = TransportClient("http://fake", "tok", self.logger)
        manager1 = DeliveryManager(outbox, client, self.logger)

        # Worker 1 acquires lock
        worker1 = DeliveryWorker(manager1, self.logger, poll_interval=0.05)
        worker1.start()
        time.sleep(0.1)
        self.assertTrue(worker1.is_alive())

        # Worker 2 with mock delivery manager pointing to same db_path
        mock_manager2 = unittest.mock.MagicMock()
        mock_manager2.outbox = outbox
        worker2 = DeliveryWorker(mock_manager2, self.logger, poll_interval=0.05)
        worker2.start()

        worker2.join(timeout=1.0)
        self.assertFalse(worker2.is_alive())
        # process_outbox must NEVER have been called on worker2
        mock_manager2.process_outbox.assert_not_called()

        worker1.stop()
        self.assertFalse(worker1.is_alive())

    def test_wp2_worker_explicit_test_mode_behavior(self):
        """Verify explicit opt-in allow_unlocked_for_testing=True allows unlocked execution without production outbox/locking."""
        mock_manager = unittest.mock.MagicMock()
        worker = DeliveryWorker(mock_manager, self.logger, poll_interval=0.05, allow_unlocked_for_testing=True)
        self.assertIsNone(worker._lock)

        worker.start()
        time.sleep(0.15)
        self.assertTrue(mock_manager.process_outbox.called)
        worker.stop()
        self.assertFalse(worker.is_alive())

    def test_wp2_worker_cleanup_after_exceptions(self):
        """Verify worker loop handles unexpected exceptions in process_outbox(), continues running, and releases lock on stop."""
        outbox = Outbox(self.db_path, self.logger)
        mock_client = TransportClient("http://fake", "tok", self.logger)
        manager = DeliveryManager(outbox, mock_client, self.logger)

        call_count = 0
        def exploding_process_outbox():
            nonlocal call_count
            call_count += 1
            raise RuntimeError("Simulated network/DB crash in delivery loop")

        manager.process_outbox = exploding_process_outbox

        worker = DeliveryWorker(manager, self.logger, poll_interval=0.05)
        worker.start()
        time.sleep(0.15)

        # Worker thread must NOT crashpermanently despite exceptions
        self.assertTrue(worker.is_alive())
        self.assertGreaterEqual(call_count, 1)

        # Stopping worker must cleanly exit and release lock
        worker.stop()
        self.assertFalse(worker.is_alive())
        self.assertFalse(worker._lock._local_acquired)
        self.assertFalse(worker._lock._os_acquired)

    def test_wp2_worker_checkpoint_scheduling_under_long_running_delivery(self):
        """Verify periodic WAL checkpoint runs immediately when a long-running process_outbox() finishes past checkpoint_interval."""
        outbox = Outbox(self.db_path, self.logger)
        mock_client = TransportClient("http://fake", "tok", self.logger)
        manager = DeliveryManager(outbox, mock_client, self.logger)

        checkpoint_called = 0
        orig_checkpoint = outbox.checkpoint
        def counting_checkpoint():
            nonlocal checkpoint_called
            checkpoint_called += 1
            return orig_checkpoint()

        outbox.checkpoint = counting_checkpoint

        def slow_process_outbox():
            # Simulate delivery batch taking 0.15s
            time.sleep(0.15)

        manager.process_outbox = slow_process_outbox

        # checkpoint_interval_seconds = 0.08s, so each slow batch exceeds checkpoint interval
        worker = DeliveryWorker(
            manager,
            self.logger,
            poll_interval=0.01,
            checkpoint_interval_seconds=0.08
        )
        worker.start()
        time.sleep(0.25)
        worker.stop()

        self.assertFalse(worker.is_alive())
        # Checkpoint must have been called during the run or in finally
        self.assertGreaterEqual(checkpoint_called, 1)

if __name__ == "__main__":
    unittest.main()
