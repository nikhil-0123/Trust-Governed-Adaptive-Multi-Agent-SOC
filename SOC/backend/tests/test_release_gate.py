import unittest
import os
import tempfile
import sqlite3
import json
import time

# Create isolated DB
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.environ["SOC_DB_PATH"] = temp_db_path

from app.database import init_db, get_db_connection
from app.fusion import EvidenceFusionEngine
from app.worker import FusionWorker
from app.main import app, startup_event, shutdown_event
from fastapi.testclient import TestClient

class TestReleaseGate(unittest.TestCase):
    def setUp(self):
        if os.path.exists(temp_db_path):
            os.close(temp_db_fd)
            os.unlink(temp_db_path)
            
    def tearDown(self):
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
            
    def test_database_idempotency_and_migration(self):
        # 1. Simulate Step 6 existing DB
        conn = sqlite3.connect(temp_db_path)
        conn.execute('''
            CREATE TABLE events (
                detection_event_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute("INSERT INTO events (detection_event_id, data) VALUES ('old-event', '{}')")
        conn.commit()
        conn.close()
        
        # 2. Run Step 7 init_db
        init_db()
        
        # 3. Verify old events exist
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) as c FROM events WHERE detection_event_id = 'old-event'")
            self.assertEqual(cursor.fetchone()["c"], 1)
            
            # Verify new tables created
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cursor.fetchall()}
            self.assertIn("fusion_event_state", tables)
            self.assertIn("incidents", tables)
            self.assertIn("incident_evidence", tables)
            
        # 4. Run init_db AGAIN to prove idempotency
        init_db()
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) as c FROM events WHERE detection_event_id = 'old-event'")
            self.assertEqual(cursor.fetchone()["c"], 1)
            
    def test_pragma_foreign_keys(self):
        init_db()
        # Verify app.main's get_db()
        from app.main import get_db
        conn_gen = get_db()
        conn = next(conn_gen)
        cursor = conn.execute("PRAGMA foreign_keys")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_worker_graceful_shutdown(self):
        init_db()
        startup_event()
        from app.main import fusion_worker
        self.assertIsNotNone(fusion_worker)
        self.assertTrue(fusion_worker.is_alive())
        
        shutdown_event()
        # Ensure it stopped
        self.assertFalse(fusion_worker.is_alive())

    def test_ingestion_fusion_independence(self):
        init_db()
        os.environ["SOC_API_TOKEN"] = "test-token"
        client = TestClient(app)
        
        valid_event = {
            "detection_event_id": "iso-123",
            "timestamp": "2026-10-03T20:00:00Z",
            "agent_id": "agent-1",
            "hostname": "PC-1",
            "os": "Windows",
            "source_event_id": "src-1",
            "detection_type": "rule",
            "confidence": 1.0,
            "severity": "high",
            "detector_name": "det",
            "evidence": {}
        }
        
        # Ingestion happens synchronously
        response = client.post("/api/v1/detection-events", json=valid_event, headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 201)
        
        # Verify it went to events table
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT * FROM events WHERE detection_event_id = 'iso-123'")
            self.assertIsNotNone(cursor.fetchone())
            
            # Verify it is NOT yet fused (Incident count = 0)
            cursor = conn.execute("SELECT COUNT(*) as c FROM incidents")
            self.assertEqual(cursor.fetchone()["c"], 0)
            
        # This proves the POST returned 201 without waiting for FusionWorker to correlate it

    def test_raw_xml_isolation(self):
        init_db()
        # Insert an event with a fake raw_xml payload
        with get_db_connection() as conn:
            data = {
                "detection_event_id": "xml-1",
                "timestamp": "2026-10-03T20:00:00Z",
                "agent_id": "agent-1",
                "hostname": "PC-1",
                "os": "Windows",
                "source_event_id": "src-1",
                "detection_type": "rule",
                "confidence": 1.0,
                "severity": "high",
                "detector_name": "det",
                "evidence": {"raw_xml": "<Event><System></System></Event>"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("xml-1", json.dumps(data)))
            conn.commit()
            
            engine = EvidenceFusionEngine(conn)
            engine.process_event("xml-1")
            
            # Verify no XML exists in incidents or incident_entities
            cursor = conn.execute("SELECT * FROM incidents")
            incident = dict(cursor.fetchone())
            for key, val in incident.items():
                self.assertNotIn("<Event>", str(val))
                
            cursor = conn.execute("SELECT * FROM incident_entities")
            for row in cursor.fetchall():
                self.assertNotIn("<Event>", str(row["entity_value"]))

if __name__ == '__main__':
    unittest.main()
