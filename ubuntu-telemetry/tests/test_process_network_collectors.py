import unittest
import os
import shutil
import tempfile
from collectors.process_collector import ProcessCollector
from collectors.network_collector import NetworkCollector

class TestProcessAndNetworkCollectors(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_process_sanitizer(self):
        raw_cmd = "myapp --user admin --password secret123 --host localhost"
        sanitized = ProcessCollector.sanitize_cmdline(raw_cmd)
        self.assertNotIn("secret123", sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_process_collector_from_mock_proc(self):
        proc_dir = os.path.join(self.test_dir, "proc")
        pid_dir = os.path.join(proc_dir, "1234")
        os.makedirs(pid_dir, exist_ok=True)

        with open(os.path.join(pid_dir, "cmdline"), "wb") as f:
            f.write(b"/usr/bin/sshd\x00-D\x00")

        with open(os.path.join(pid_dir, "status"), "w", encoding="utf-8") as f:
            f.write("Name:\tsshd\nState:\tS (sleeping)\n")

        collector = ProcessCollector()
        procs = collector.collect_processes(proc_dir=proc_dir)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]["pid"], 1234)
        self.assertEqual(procs[0]["name"], "sshd")
        self.assertIn("/usr/bin/sshd -D", procs[0]["cmdline"])

    def test_process_sanitizer_extended_formats(self):
        # Test space and '=' separators across flags
        cases = [
            ("app --password=secretPass1", "secretPass1"),
            ("app --token=ghp_secretTokenVal", "ghp_secretTokenVal"),
            ("app --api-key=myApiKey123", "myApiKey123"),
            ("app -p=quickPass", "quickPass"),
            ("app -p superSecret", "superSecret"),
            ("app --auth=bearerXYZ", "bearerXYZ")
        ]
        for raw, secret in cases:
            sanitized = ProcessCollector.sanitize_cmdline(raw)
            self.assertNotIn(secret, sanitized, f"Secret leaked in: {raw}")
            self.assertIn("[REDACTED]", sanitized)

    def test_network_collector_from_mock_proc_net_tcp(self):
        mock_tcp = os.path.join(self.test_dir, "tcp")
        content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n"
            "   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 54321 1\n"
        )
        with open(mock_tcp, "w", encoding="utf-8") as f:
            f.write(content)

        collector = NetworkCollector()
        sockets = collector.collect_sockets(tcp_paths=[mock_tcp])
        self.assertEqual(len(sockets), 2)
        # Port 0x16 = 22, State 0A = LISTEN
        self.assertEqual(sockets[0]["local_port"], 22)
        self.assertEqual(sockets[0]["state"], "LISTEN")
        # Port 0x1F90 = 8080, State 01 = ESTABLISHED
        self.assertEqual(sockets[1]["state"], "ESTABLISHED")

    def test_network_collector_ipv6_parsing(self):
        # Test IPv6 hex parsing in NetworkCollector
        # IPv6 ::1 (loopback) in Linux /proc/net/tcp6 is 00000000000000000000000001000000
        hex_loopback_v6 = "00000000000000000000000001000000:0016"
        ip, port = NetworkCollector._hex_to_ip_port(hex_loopback_v6)
        self.assertEqual(ip, "::1")
        self.assertEqual(port, 22)

        # IPv6 :: (any)
        hex_any_v6 = "00000000000000000000000000000000:1F90"
        ip_any, port_any = NetworkCollector._hex_to_ip_port(hex_any_v6)
        self.assertEqual(ip_any, "::")
        self.assertEqual(port_any, 8080)

if __name__ == "__main__":
    unittest.main()
