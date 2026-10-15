import unittest
from unittest.mock import patch, MagicMock
import os
import json
import logging
from response.executor import LinuxResponseExecutor, PROTECTED_LINUX_PROCESSES
from transport.heartbeat import HeartbeatWorker

class TestLinuxResponseExecutor(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestLinuxResponse")
        self.executor = LinuxResponseExecutor(soc_base_url="http://192.168.1.100:8000", logger=self.logger)

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
        res = self.executor.block_source({"ip": "198.51.100.12", "simulate": True})
        self.assertEqual(res["action"], "BLOCK_SOURCE")
        self.assertEqual(res["target_ip"], "198.51.100.12")
        self.assertTrue(res["simulated"])
        self.assertIn("iptables -A INPUT -s 198.51.100.12", res["command"])
        self.assertIn("-j DROP", res["command"])

    @patch("subprocess.run")
    def test_block_source_execution(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = ""
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = self.executor.block_source({"ip": "203.0.113.88"})
        self.assertTrue(res["applied"])
        self.assertEqual(res["target_ip"], "203.0.113.88")

    def test_unblock_source_simulation(self):
        res = self.executor.unblock_source({"ip": "198.51.100.12", "simulate": True})
        self.assertEqual(res["action"], "UNBLOCK_SOURCE")
        self.assertTrue(res["simulated"])
        self.assertIn("iptables -D INPUT -s 198.51.100.12", res["command"])

    def test_kill_process_safety_checks(self):
        # Protected system PID
        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_id": 1})

        # Protected current process PID
        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_id": os.getpid()})

        # Protected image names
        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_name": "systemd"})

        with self.assertRaises(PermissionError):
            self.executor.kill_process({"process_name": "sshd"})

        # Missing parameters
        with self.assertRaises(ValueError):
            self.executor.kill_process({})

    def test_kill_process_simulation(self):
        res = self.executor.kill_process({"process_id": 5555, "simulate": True})
        self.assertEqual(res["action"], "KILL_PROCESS")
        self.assertEqual(res["target_pid"], 5555)
        self.assertTrue(res["simulated"])
        self.assertEqual(res["command"], "kill -9 5555")

        res2 = self.executor.kill_process({"process_name": "reverse_shell", "simulate": True})
        self.assertEqual(res2["target_process_name"], "reverse_shell")
        self.assertEqual(res2["command"], "pkill -9 -f reverse_shell")

    @patch("os.kill")
    def test_kill_process_execution_pid(self, mock_kill):
        res = self.executor.kill_process({"process_id": 7777})
        self.assertTrue(res["terminated"])
        self.assertEqual(res["target_pid"], 7777)
        self.assertTrue(mock_kill.called)

    def test_isolate_host_simulation(self):
        res = self.executor.isolate_host({"simulate": True})
        self.assertEqual(res["action"], "ISOLATE_HOST")
        self.assertEqual(res["preserved_soc_ip"], "192.168.1.100")
        self.assertTrue(res["simulated"])
        cmds_str = " ".join(res["commands"])
        self.assertIn("-o lo -j ACCEPT", cmds_str)
        self.assertIn("-d 192.168.1.100 -j ACCEPT", cmds_str)
        self.assertIn("OUTPUT -j DROP", cmds_str)

    def test_restore_host_simulation(self):
        res = self.executor.restore_host({"simulate": True})
        self.assertEqual(res["action"], "RESTORE_HOST")
        self.assertTrue(res["simulated"])

    def test_disable_account_safety_and_simulation(self):
        # Protected account
        with self.assertRaises(PermissionError):
            self.executor.disable_account({"username": "root"})

        # Missing username
        with self.assertRaises(ValueError):
            self.executor.disable_account({})

        # Valid simulation
        res = self.executor.disable_account({"username": "attacker_user", "simulate": True})
        self.assertEqual(res["action"], "DISABLE_ACCOUNT")
        self.assertEqual(res["target_user"], "attacker_user")
        self.assertEqual(res["command"], "usermod -L attacker_user")

    @patch("urllib.request.urlopen")
    def test_heartbeat_worker_dispatches_mitigation(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        worker = HeartbeatWorker(
            agent_id="ubuntu-agent-test",
            os_type="linux",
            soc_api_url="http://127.0.0.1:8000/api/v1",
            api_token="test-token",
            logger=self.logger
        )

        cmd = {
            "command_id": "cmd-block-ubuntu",
            "command_type": "BLOCK_SOURCE",
            "parameters": {"ip": "198.51.100.88", "simulate": True}
        }
        worker._handle_command(cmd)

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertIn("/commands/cmd-block-ubuntu/result", req.full_url)
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["status"], "EXECUTED")
        self.assertTrue(payload["result"]["simulated"])
        self.assertEqual(payload["result"]["target_ip"], "198.51.100.88")

if __name__ == "__main__":
    unittest.main()
