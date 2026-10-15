import unittest
from unittest.mock import patch, MagicMock
import os
import json
import logging
from response.executor import WindowsResponseExecutor, PROTECTED_WINDOWS_PROCESSES
from transport.heartbeat import HeartbeatWorker

class TestWindowsResponseExecutor(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestWindowsResponse")
        self.executor = WindowsResponseExecutor(soc_base_url="http://192.168.1.50:8000", logger=self.logger)

    def test_block_source_validation(self):
        # Missing IP
        with self.assertRaises(ValueError):
            self.executor.block_source({})

        # Invalid IP string (injection attempt)
        with self.assertRaises(ValueError):
            self.executor.block_source({"ip": "10.0.0.1; rm -rf /"})

        # Loopback protection
        with self.assertRaises(ValueError):
            self.executor.block_source({"ip": "127.0.0.1"})

    def test_block_source_simulation(self):
        res = self.executor.block_source({"ip": "198.51.100.4", "simulate": True})
        self.assertEqual(res["action"], "BLOCK_SOURCE")
        self.assertEqual(res["target_ip"], "198.51.100.4")
        self.assertTrue(res["simulated"])
        self.assertIn("netsh advfirewall firewall add rule", res["command"])
        self.assertIn("remoteip=198.51.100.4", res["command"])

    @patch("subprocess.run")
    def test_block_source_execution(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Ok.\r\n"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = self.executor.block_source({"ip": "203.0.113.50"})
        self.assertTrue(res["applied"])
        self.assertEqual(res["target_ip"], "203.0.113.50")
        self.assertEqual(res["rule_name"], "TGAM-SOC-Block-203.0.113.50")

    def test_unblock_source_simulation(self):
        res = self.executor.unblock_source({"ip": "198.51.100.4", "simulate": True})
        self.assertEqual(res["action"], "UNBLOCK_SOURCE")
        self.assertTrue(res["simulated"])
        self.assertIn("netsh advfirewall firewall delete rule", res["command"])

    def test_kill_process_safety_checks(self):
        # Protected system PID
        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_id": 4})

        # Protected current process PID
        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_id": os.getpid()})

        # Protected image names
        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_name": "lsass.exe"})

        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_name": "csrss.exe"})

        # Missing parameters
        with self.assertRaises(ValueError):
            self.executor.kill_process({})

    def test_kill_process_simulation(self):
        res = self.executor.kill_process({"process_id": 9999, "simulate": True})
        self.assertEqual(res["action"], "KILL_PROCESS")
        self.assertEqual(res["target_pid"], 9999)
        self.assertTrue(res["simulated"])
        self.assertEqual(res["command"], "taskkill /F /PID 9999")

        res2 = self.executor.kill_process({"process_name": "mimikatz.exe", "simulate": True})
        self.assertEqual(res2["target_process_name"], "mimikatz.exe")
        self.assertEqual(res2["command"], "taskkill /F /IM mimikatz.exe")

    @patch("subprocess.run")
    def test_kill_process_execution(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "SUCCESS: The process with PID 8888 has been terminated."
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = self.executor.kill_process({"process_id": 8888})
        self.assertTrue(res["terminated"])
        self.assertEqual(res["target_pid"], 8888)

    def test_isolate_host_simulation(self):
        res = self.executor.isolate_host({"simulate": True})
        self.assertEqual(res["action"], "ISOLATE_HOST")
        self.assertEqual(res["preserved_soc_ip"], "192.168.1.50")
        self.assertTrue(res["simulated"])
        # Check SOC exclusion rule is created
        cmds_str = " ".join(res["commands"])
        self.assertIn("AllowSOC", cmds_str)
        self.assertIn("BlockOut", cmds_str)

    def test_restore_host_simulation(self):
        res = self.executor.restore_host({"simulate": True})
        self.assertEqual(res["action"], "RESTORE_HOST")
        self.assertTrue(res["simulated"])

    def test_disable_account_safety_and_simulation(self):
        # Protected account
        with self.assertRaises(PermissionError):
            self.executor.disable_account({"username": "Administrator"})

        # Missing username
        with self.assertRaises(ValueError):
            self.executor.disable_account({})

        # Valid simulation
        res = self.executor.disable_account({"username": "compromised_user", "simulate": True})
        self.assertEqual(res["action"], "DISABLE_ACCOUNT")
        self.assertEqual(res["target_user"], "compromised_user")
        self.assertEqual(res["command"], "net user compromised_user /active:no")

    @patch("urllib.request.urlopen")
    def test_heartbeat_worker_dispatches_mitigation(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        worker = HeartbeatWorker(
            agent_id="win-agent-test",
            os_type="windows",
            soc_api_url="http://127.0.0.1:8000/api/v1",
            api_token="test-token",
            logger=self.logger
        )

        cmd = {
            "command_id": "cmd-block-1",
            "command_type": "BLOCK_SOURCE",
            "parameters": {"ip": "198.51.100.99", "simulate": True}
        }
        worker._handle_command(cmd)

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertIn("/commands/cmd-block-1/result", req.full_url)
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["status"], "EXECUTED")
        self.assertTrue(payload["result"]["simulated"])
        self.assertEqual(payload["result"]["target_ip"], "198.51.100.99")

if __name__ == "__main__":
    unittest.main()
