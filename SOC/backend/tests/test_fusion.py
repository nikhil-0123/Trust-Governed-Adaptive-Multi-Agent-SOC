import unittest
import os
import tempfile
import sqlite3
import json
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

os.environ["FUSION_POLL_INTERVAL_SECONDS"] = "0"
os.environ["FUSION_TIME_WINDOW_SECONDS"] = "3600"

# Database setup will be handled per-test in setUp

from app.database import init_db, get_db_connection
from app.fusion import EvidenceFusionEngine
from app.worker import FusionWorker

class TestFusionEngine(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.environ["SOC_DB_PATH"] = self.db_path
        import app.database
        app.database.DB_PATH = self.db_path
        app.database.init_db()
        os.close(self.db_fd)
        
    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except:
            pass
            
    def _insert_event(self, event_id: str, timestamp: str, hostname: str, severity: str, source_ip: str = None, username: str = None):
        with get_db_connection() as conn:
            data = {
                "detection_event_id": event_id,
                "timestamp": timestamp,
                "agent_id": "agent-1",
                "hostname": hostname,
                "os": "Windows",
                "source_event_id": "src-1",
                "detection_type": "test_rule",
                "confidence": 1.0,
                "severity": severity,
                "detector_name": "test_detector",
                "evidence": {}
            }
            if source_ip:
                data["evidence"]["source_ip"] = source_ip
            if username:
                data["evidence"]["username"] = username
                
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", (event_id, json.dumps(data)))
            conn.execute("INSERT INTO fusion_event_state (detection_event_id, status, updated_at) VALUES (?, 'PENDING', CURRENT_TIMESTAMP)", (event_id,))
            conn.commit()

    def test_single_event_creates_incident(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            conn.commit()
            
            # Verify incident
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["max_severity"], "LOW")
            self.assertEqual(incidents[0]["status"], "OPEN")
            
            # Verify evidence
            cursor = conn.execute("SELECT * FROM incident_evidence")
            evidence = cursor.fetchall()
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]["detection_event_id"], "e1")
            
            # Verify entities
            cursor = conn.execute("SELECT entity_type, entity_value FROM incident_entities")
            entities = {(row["entity_type"], row["entity_value"]) for row in cursor.fetchall()}
            self.assertIn(("hostname", "host1"), entities)
            self.assertIn(("source_ip", "10.0.0.1"), entities)

    def test_correlate_within_window_attaches(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host1", "HIGH", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            conn.commit()
            
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["max_severity"], "HIGH")
            
            cursor = conn.execute("SELECT detection_event_id FROM incident_evidence")
            events = {row["detection_event_id"] for row in cursor.fetchall()}
            self.assertEqual(events, {"e1", "e2"})

    def test_correlate_outside_window_creates_new(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        # 2 hours later, outside 3600s window
        self._insert_event("e2", "2026-10-03T12:00:00Z", "host1", "HIGH", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            conn.commit()
            
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 2)

    def test_different_hostname_creates_new(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host2", "LOW", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            conn.commit()
            
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 2)

    def test_missing_source_ip_fallback(self):
        # e2 has no IP, should correlate via hostname
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host1", "LOW", None)
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            conn.commit()
            
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 1)

    def test_different_source_ip_does_not_correlate(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host1", "LOW", "10.0.0.2")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            conn.commit()
            
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 2)

    def test_severity_escalation(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:10:00Z", "host1", "MEDIUM", "10.0.0.1")
        self._insert_event("e3", "2026-10-03T10:20:00Z", "host1", "HIGH", "10.0.0.1")
        self._insert_event("e4", "2026-10-03T10:30:00Z", "host1", "CRITICAL", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            cursor = conn.execute("SELECT max_severity FROM incidents")
            self.assertEqual(cursor.fetchone()["max_severity"], "MEDIUM")
            
            engine.process_event("e3")
            cursor = conn.execute("SELECT max_severity FROM incidents")
            self.assertEqual(cursor.fetchone()["max_severity"], "HIGH")
            
            engine.process_event("e4")
            cursor = conn.execute("SELECT max_severity FROM incidents")
            self.assertEqual(cursor.fetchone()["max_severity"], "CRITICAL")
            
    def test_invalid_severity(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "UNKNOWN_SEV", "10.0.0.1")
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            cursor = conn.execute("SELECT max_severity FROM incidents")
            self.assertEqual(cursor.fetchone()["max_severity"], "UNKNOWN_SEV")

    def test_invalid_timestamp(self):
        self._insert_event("e1", "invalid-time", "host1", "LOW", "10.0.0.1")
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            with self.assertRaises(ValueError):
                engine.process_event("e1")

    def test_late_event_correlates_historically(self):
        # Process e2 first (10:30), then late event e1 (10:00).
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host1", "HIGH", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e2")
            engine.process_event("e1")
            conn.commit()
            
            cursor = conn.execute("SELECT first_seen, last_seen FROM incidents")
            row = cursor.fetchone()
            self.assertTrue(row["first_seen"].startswith("2026-10-03T10:00:00"))
            self.assertTrue(row["last_seen"].startswith("2026-10-03T10:30:00"))
            
    def test_idempotency_duplicate_evidence_prevented(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e1") # IDEMPOTENT ATTEMPT
            conn.commit()
            
            cursor = conn.execute("SELECT COUNT(*) as c FROM incidents")
            self.assertEqual(cursor.fetchone()["c"], 1)
            
            cursor = conn.execute("SELECT COUNT(*) as c FROM incident_evidence")
            self.assertEqual(cursor.fetchone()["c"], 1)

    def test_worker_processing(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW")
        
        worker = FusionWorker()
        worker.process_batch()
        
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'e1'")
            self.assertEqual(cursor.fetchone()["status"], "PROCESSED")
            
            cursor = conn.execute("SELECT COUNT(*) as c FROM incidents")
            self.assertEqual(cursor.fetchone()["c"], 1)

    def test_worker_failure_handling(self):
        self._insert_event("e1", "invalid-time", "host1", "LOW")
        
        worker = FusionWorker()
        worker.process_batch()
        
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT status, attempts, last_error FROM fusion_event_state WHERE detection_event_id = 'e1'")
            row = cursor.fetchone()
            self.assertEqual(row["status"], "FAILED")
            self.assertEqual(row["attempts"], 1)
            self.assertTrue("Invalid timestamp" in row["last_error"])

    def test_case_d_different_hostname_same_ip(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW", "10.0.0.1")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host2", "LOW", "10.0.0.1")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            cursor = conn.execute("SELECT * FROM incidents")
            self.assertEqual(len(cursor.fetchall()), 2)
            
    def test_stale_processing_recovery(self):
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW")
        with get_db_connection() as conn:
            # Manually set to stale PROCESSING
            conn.execute("UPDATE fusion_event_state SET status = 'PROCESSING', updated_at = datetime('now', '-2 hour') WHERE detection_event_id = 'e1'")
            conn.commit()
            
        worker = FusionWorker()
        worker.process_batch()
        
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT status FROM fusion_event_state WHERE detection_event_id = 'e1'")
            self.assertEqual(cursor.fetchone()["status"], "PROCESSED")
            
    def test_temporal_internal_bound(self):
        # first_seen = 10:00, last_seen = 10:30. Event = 10:50.
        self._insert_event("e1", "2026-10-03T10:00:00Z", "host1", "LOW")
        self._insert_event("e2", "2026-10-03T10:30:00Z", "host1", "LOW")
        self._insert_event("e3", "2026-10-03T10:50:00Z", "host1", "LOW")
        
        with get_db_connection() as conn:
            engine = EvidenceFusionEngine(conn)
            engine.process_event("e1")
            engine.process_event("e2")
            engine.process_event("e3")
            
            cursor = conn.execute("SELECT * FROM incidents")
            incidents = cursor.fetchall()
            self.assertEqual(len(incidents), 1)

if __name__ == '__main__':
    unittest.main()
