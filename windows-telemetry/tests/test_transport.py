import unittest
import os
import tempfile
import logging
from typing import Dict, Any, Tuple
from transport.outbox import Outbox
from transport.client import TransportClient
from transport.delivery import DeliveryManager
from transport.worker import DeliveryWorker

class MockClient(TransportClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mock_responses = [] # list of (success, duplicate, error)
        self.sent_events = []

    def send_event(self, event: Dict[str, Any]) -> Tuple[bool, bool, str]:
        self.sent_events.append(event)
        if self.mock_responses:
            return self.mock_responses.pop(0)
        return True, False, ""

class TestTransport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_outbox.db")
        self.logger = logging.getLogger("TestTransport")
        self.logger.setLevel(logging.CRITICAL)
        
        self.event1 = {
            "detection_event_id": "test-id-1",
            "timestamp": "2026-10-03T20:00:00Z",
            "agent_id": "agent-1",
            "hostname": "PC-1",
            "os": "Windows",
            "source_event_id": "123",
            "detection_type": "windows_bruteforce_rule",
            "confidence": 1.0,
            "severity": "high",
            "detector_name": "test",
            "evidence": {}
        }
        self.event2 = self.event1.copy()
        self.event2["detection_event_id"] = "test-id-2"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_outbox_add_and_retrieve(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event1)
        
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["detection_event_id"], "test-id-1")

    def test_outbox_persistence(self):
        outbox1 = Outbox(self.db_path, self.logger)
        outbox1.add_event(self.event1)
        
        # Simulating restart
        outbox2 = Outbox(self.db_path, self.logger)
        pending = outbox2.get_pending_events()
        self.assertEqual(len(pending), 1)

    def test_delivery_success(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event1)
        
        client = MockClient("http://fake", "token", self.logger)
        client.mock_responses = [(True, False, "")]
        
        manager = DeliveryManager(outbox, client, self.logger)
        manager.process_outbox()
        
        # Should be delivered
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 0)

    def test_delivery_duplicate(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event1)
        
        client = MockClient("http://fake", "token", self.logger)
        client.mock_responses = [(True, True, "")]
        
        manager = DeliveryManager(outbox, client, self.logger)
        manager.process_outbox()
        
        # Duplicate ACK is still a successful delivery
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 0)

    def test_delivery_failure_retains_pending(self):
        outbox = Outbox(self.db_path, self.logger)
        outbox.add_event(self.event1)
        
        client = MockClient("http://fake", "token", self.logger)
        client.mock_responses = [(False, False, "HTTP 500")]
        
        manager = DeliveryManager(outbox, client, self.logger)
        manager.process_outbox()
        
        # Still pending
        pending = outbox.get_pending_events()
        self.assertEqual(len(pending), 1)

    def test_client_http_500_mock(self):
        import urllib.request
        from unittest.mock import patch, MagicMock
        client = TransportClient("http://fake", "token", self.logger)
        
        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.read.return_value = b'Internal Error'
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = mock_response
            success, dup, err = client.send_event(self.event1)
            self.assertFalse(success)
            self.assertTrue("Unexpected status: 500" in err)

    def test_client_http_200_mock(self):
        import urllib.request
        from unittest.mock import patch, MagicMock
        client = TransportClient("http://fake", "token", self.logger)
        
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"accepted": true, "duplicate": false}'
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = mock_response
            success, dup, err = client.send_event(self.event1)
            self.assertTrue(success)
            self.assertFalse(dup)

    def test_delivery_worker_decoupling(self):
        from unittest.mock import MagicMock
        mock_manager = MagicMock()
        
        worker = DeliveryWorker(mock_manager, self.logger, poll_interval=0.1)
        worker.start()
        
        import time
        time.sleep(0.3)
        
        self.assertTrue(mock_manager.process_outbox.called)
        
        worker.stop()
        self.assertFalse(worker.is_alive())
        
        # Verify exceptions in loop don't crash the thread permanently
        mock_manager.process_outbox.side_effect = Exception("Timeout")
        worker2 = DeliveryWorker(mock_manager, self.logger, poll_interval=0.1)
        worker2.start()
        time.sleep(0.3)
        worker2.stop()
        self.assertFalse(worker2.is_alive())
