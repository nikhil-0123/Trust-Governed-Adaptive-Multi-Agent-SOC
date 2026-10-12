import unittest
import os
import shutil
import tempfile
import json
import logging
from unittest.mock import patch, MagicMock
import urllib.error
import sqlite3

from transport.outbox import Outbox
from transport.client import TransportClient
from transport.delivery import DeliveryManager
from transport.worker import DeliveryWorker

class TestTransport(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "outbox.db")
        self.logger = logging.getLogger("TestTransport")
        self.outbox = Outbox(self.db_path, self.logger)
        self.client = TransportClient("http://127.0.0.1:8000/api/v1/detection-events", "test-token", self.logger)
        self.delivery_manager = DeliveryManager(self.outbox, self.client, self.logger)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_outbox_add_and_retrieve(self):
        event = {"detection_event_id": "evt-001", "data": "test"}
        self.outbox.add_event(event)

        pending = self.outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["detection_event_id"], "evt-001")

        # Duplicate addition is safely ignored
        self.outbox.add_event(event)
        self.assertEqual(len(self.outbox.get_pending_events()), 1)

    def test_outbox_mark_delivered(self):
        event = {"detection_event_id": "evt-002", "data": "test"}
        self.outbox.add_event(event)
        self.outbox.mark_delivered("evt-002")
        self.assertEqual(len(self.outbox.get_pending_events()), 0)

    def test_outbox_mark_failed_increments_attempts(self):
        event = {"detection_event_id": "evt-003", "data": "test"}
        self.outbox.add_event(event)
        self.outbox.mark_failed("evt-003", "Connection refused")

        # Still in outbox for retry
        pending = self.outbox.get_pending_events()
        self.assertEqual(len(pending), 1)

    @patch("urllib.request.urlopen")
    def test_client_http_201_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"accepted": True, "duplicate": False}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        success, dup, err = self.client.send_event({"detection_event_id": "evt-100"})
        self.assertTrue(success)
        self.assertFalse(dup)
        self.assertEqual(err, "")

    @patch("urllib.request.urlopen")
    def test_client_http_duplicate_ack(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"accepted": True, "duplicate": True}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        success, dup, err = self.client.send_event({"detection_event_id": "evt-101"})
        self.assertTrue(success)
        self.assertTrue(dup)

    @patch("urllib.request.urlopen")
    def test_client_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=401, msg="Unauthorized", hdrs={}, fp=MagicMock(read=lambda: b"Unauthorized token")
        )
        success, dup, err = self.client.send_event({"detection_event_id": "evt-102"})
        self.assertFalse(success)
        self.assertIn("401", err)

    @patch("urllib.request.urlopen")
    def test_delivery_manager_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"accepted": True, "duplicate": False}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        self.outbox.add_event({"detection_event_id": "evt-200"})
        self.delivery_manager.process_outbox()

        # Outbox should now be clear of pending events
        self.assertEqual(len(self.outbox.get_pending_events()), 0)

    def test_delivery_worker_thread_lifecycle(self):
        worker = DeliveryWorker(self.delivery_manager, self.logger, poll_interval=0.1)
        worker.start()
        self.assertTrue(worker.is_alive())
        worker.stop()
        worker.join(timeout=1.0)
        self.assertFalse(worker.is_alive())

    def test_outbox_bounded_capacity(self):
        bounded_outbox = Outbox(os.path.join(self.test_dir, "bounded.db"), self.logger, max_queue_size=3)
        for i in range(3):
            bounded_outbox.add_event({"detection_event_id": f"evt-{i}", "val": i})
        self.assertEqual(len(bounded_outbox.get_pending_events()), 3)

        # 4th event exceeds capacity and is dropped to prevent unbounded growth
        bounded_outbox.add_event({"detection_event_id": "evt-overflow", "val": 99})
        pending = bounded_outbox.get_pending_events()
        self.assertEqual(len(pending), 3)
        self.assertNotIn("evt-overflow", [p["detection_event_id"] for p in pending])

    def test_outbox_retry_exhaustion_filters_pending(self):
        retry_outbox = Outbox(os.path.join(self.test_dir, "retry.db"), self.logger, max_retries=2)
        retry_outbox.add_event({"detection_event_id": "evt-flaky"})

        # Attempt 1 failed
        retry_outbox.mark_failed("evt-flaky", "Network down 1")
        self.assertEqual(len(retry_outbox.get_pending_events()), 1)

        # Attempt 2 failed -> reaches max_retries, transitions to exhausted
        retry_outbox.mark_failed("evt-flaky", "Network down 2")
        self.assertEqual(len(retry_outbox.get_pending_events()), 0)

    def test_outbox_purge_delivered_records(self):
        purge_outbox = Outbox(os.path.join(self.test_dir, "purge.db"), self.logger)
        for i in range(5):
            purge_outbox.add_event({"detection_event_id": f"evt-del-{i}"})
            purge_outbox.mark_delivered(f"evt-del-{i}")

        with purge_outbox._init_db() or sqlite3.connect(purge_outbox.db_path) as conn:
            # Purge keeping only latest 2
            purge_outbox.purge_delivered(conn, max_keep=2)
            cur = conn.execute("SELECT count(*) FROM outbox WHERE status = 'delivered'")
            self.assertEqual(cur.fetchone()[0], 2)

    def test_transport_security_rejects_insecure_remote_http_in_production(self):
        with self.assertRaises(ValueError):
            TransportClient("http://remote-soc.corp.internal:8000/api", "token", self.logger, environment="production")

    def test_transport_security_allows_loopback_http(self):
        client = TransportClient("http://127.0.0.1:8000/api", "token", self.logger, environment="production")
        self.assertEqual(client.endpoint_url, "http://127.0.0.1:8000/api")

if __name__ == "__main__":
    unittest.main()
