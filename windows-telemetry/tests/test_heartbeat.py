import unittest
from unittest.mock import patch, MagicMock
import logging
import json
from config.settings import config
from transport.heartbeat import HeartbeatWorker

class TestHeartbeatWorker(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestHeartbeat")
        self.worker = HeartbeatWorker(
            agent_id="test-win-agent",
            os_type="windows",
            soc_api_url="http://127.0.0.1:8000/api/v1/detection-events",
            api_token="test-token",
            logger=self.logger,
            capabilities=["EventLog_4625"],
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
        self.assertEqual(req.headers["Authorization"], "Bearer test-token")
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["agent_version"], config.version)

    @patch("urllib.request.urlopen")
    def test_handle_command_ping(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        cmd = {"command_id": "cmd-123", "command_type": "PING"}
        self.worker._handle_command(cmd)

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertIn("/commands/cmd-123/result", req.full_url)
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["status"], "EXECUTED")
        self.assertTrue(payload["result"]["pong"])

    @patch("urllib.request.urlopen")
    def test_handle_command_get_status_uses_configured_version(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        cmd = {"command_id": "cmd-status-1", "command_type": "GET_STATUS"}
        self.worker._handle_command(cmd)

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["status"], "EXECUTED")
        self.assertEqual(payload["result"]["agent_version"], config.version)

    def test_custom_agent_version_override(self):
        custom_worker = HeartbeatWorker(
            agent_id="custom-agent",
            os_type="windows",
            soc_api_url="http://127.0.0.1:8000",
            api_token="token",
            logger=self.logger,
            agent_version="2.5.0"
        )
        self.assertEqual(custom_worker.agent_version, "2.5.0")

    def test_default_capabilities_omit_sysmon(self):
        """Default capabilities must only advertise base Security capabilities, omitting Sysmon."""
        worker = HeartbeatWorker(
            agent_id="test-agent",
            os_type="windows",
            soc_api_url="http://127.0.0.1:8000",
            api_token="token",
            logger=self.logger,
            capabilities=None
        )
        self.assertIn("EventLog_4625", worker.capabilities)
        self.assertIn("EventLog_4688", worker.capabilities)
        self.assertIn("BLOCK_SOURCE", worker.capabilities)
        self.assertNotIn("Sysmon_Event1", worker.capabilities)
        self.assertNotIn("Sysmon_Event3", worker.capabilities)
        self.assertNotIn("Sysmon_Event22", worker.capabilities)

    def test_update_capabilities_updates_payload_and_deduplicates(self):
        """update_capabilities must update worker capabilities and eliminate duplicate tags."""
        self.worker.update_capabilities([
            "EventLog_4625", "EventLog_4625",
            "Sysmon_Event1", "Sysmon_Event1", "Sysmon_Event3"
        ])
        self.assertEqual(
            self.worker.capabilities,
            ["EventLog_4625", "Sysmon_Event1", "Sysmon_Event3"]
        )

    @patch("urllib.request.urlopen")
    def test_heartbeat_payload_structure_and_compatibility(self, mock_urlopen):
        """Heartbeat payload must maintain backward-compatible structure with all required fields."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"acknowledged": True, "commands": []}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        self.worker.update_capabilities(["EventLog_4625", "EventLog_4688", "Sysmon_Event1"])
        self.worker._send_heartbeat()

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))

        # Verify all contract keys
        required_keys = {"agent_id", "hostname", "os", "ip_address", "agent_version", "capabilities"}
        self.assertTrue(required_keys.issubset(set(payload.keys())))
        self.assertEqual(payload["capabilities"], ["EventLog_4625", "EventLog_4688", "Sysmon_Event1"])

    @patch("urllib.request.urlopen")
    def test_heartbeat_can_operate_when_sysmon_initialization_fails(self, mock_urlopen):
        """HeartbeatWorker continues dispatching heartbeats with Security capabilities when Sysmon fails."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"acknowledged": True, "commands": []}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        # Worker created with base Security capabilities (Sysmon absent/failed)
        worker = HeartbeatWorker(
            agent_id="agt-sec-only",
            os_type="windows",
            soc_api_url="http://127.0.0.1:8000",
            api_token="token",
            logger=self.logger,
            capabilities=["EventLog_4625", "EventLog_4688", "BLOCK_SOURCE"]
        )
        worker._send_heartbeat()
        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["capabilities"], ["EventLog_4625", "EventLog_4688", "BLOCK_SOURCE"])
        self.assertNotIn("Sysmon_Event1", payload["capabilities"])

if __name__ == "__main__":
    unittest.main()
