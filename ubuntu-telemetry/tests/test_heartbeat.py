import unittest
from unittest.mock import patch, MagicMock
import logging
import json
from transport.heartbeat import HeartbeatWorker

class TestHeartbeatWorker(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestHeartbeat")
        self.worker = HeartbeatWorker(
            agent_id="test-ubuntu-agent",
            os_type="linux",
            soc_api_url="http://127.0.0.1:8000/api/v1/detection-events",
            api_token="test-token",
            logger=self.logger,
            capabilities=["AuthLog_SSH"],
            heartbeat_interval=1.0
        )

    def tearDown(self):
        if self.worker.is_alive():
            self.worker.stop()

    @patch("urllib.request.urlopen")
    def test_send_heartbeat_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"acknowledged": True, "commands": []}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        self.worker._send_heartbeat()
        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "http://127.0.0.1:8000/api/v1/endpoints/heartbeat")

    @patch("urllib.request.urlopen")
    def test_handle_command_get_health(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        cmd = {"command_id": "cmd-456", "command_type": "GET_HEALTH"}
        self.worker._handle_command(cmd)

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertIn("/commands/cmd-456/result", req.full_url)
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["status"], "EXECUTED")
        self.assertEqual(payload["result"]["status"], "HEALTHY")

if __name__ == "__main__":
    unittest.main()
