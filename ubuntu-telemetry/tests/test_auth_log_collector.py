import unittest
from unittest.mock import patch, MagicMock
import os
import shutil
import tempfile
import logging
from collectors.auth_log_collector import AuthLogCollector, parse_syslog_timestamp

class TestAuthLogCollector(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, "auth.log")
        self.logger = logging.getLogger("TestAuthCollector")
        # Direct checkpoint state to test_dir
        os.environ["DATA_DIR"] = self.test_dir
        os.environ["UBUNTU_CHECKPOINT_DIR"] = os.path.join(self.test_dir, "state")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_timestamp_parser(self):
        # ISO timestamp
        iso_res = parse_syslog_timestamp("2026-10-11T20:30:00+00:00")
        self.assertIn("2026-10-11T20:30:00", iso_res)

        # Legacy syslog format
        legacy_res = parse_syslog_timestamp("Oct 11 20:30:00")
        self.assertIn("T20:30:00", legacy_res)

    def test_missing_file_returns_empty_gracefully(self):
        collector = AuthLogCollector(log_path=os.path.join(self.test_dir, "nonexistent.log"), logger=self.logger)
        collector.initialize()
        events = collector.collect_once()
        self.assertEqual(events, [])

    def test_parse_ssh_failed_password(self):
        line = "Oct 11 21:00:00 ubuntu-node sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        collector = AuthLogCollector(log_path=self.log_path, logger=self.logger)
        collector.initialize()
        events = collector.collect_once()

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["hostname"], "ubuntu-node")
        self.assertEqual(ev["process"], "sshd")
        self.assertEqual(ev["pid"], 12345)
        self.assertEqual(ev["auth_status"], "failed")
        self.assertEqual(ev["username"], "admin")
        self.assertEqual(ev["source_ip"], "192.168.1.100")
        self.assertEqual(ev["port"], 54321)
        self.assertEqual(ev["event_subtype"], "ssh_login_failure")

    def test_parse_ssh_accepted_publickey(self):
        line = "2026-10-11T21:05:00.000+00:00 ubuntu-node sshd[2222]: Accepted publickey for alice from 10.0.0.5 port 42100 ssh2\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        collector = AuthLogCollector(log_path=self.log_path, logger=self.logger)
        collector.initialize()
        events = collector.collect_once()

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["auth_status"], "accepted")
        self.assertEqual(ev["auth_method"], "publickey")
        self.assertEqual(ev["username"], "alice")
        self.assertEqual(ev["source_ip"], "10.0.0.5")
        self.assertEqual(ev["event_subtype"], "ssh_login_success")

    def test_parse_ssh_invalid_user(self):
        line = "Oct 11 21:10:00 ubuntu-node sshd[3333]: Invalid user guest from 172.16.0.40 port 50000\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        collector = AuthLogCollector(log_path=self.log_path, logger=self.logger)
        collector.initialize()
        events = collector.collect_once()

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["auth_status"], "failed")
        self.assertEqual(ev["username"], "guest")
        self.assertEqual(ev["source_ip"], "172.16.0.40")
        self.assertEqual(ev["event_subtype"], "ssh_invalid_user")

    def test_parse_sudo_events(self):
        lines = (
            "Oct 11 21:15:00 ubuntu-node sudo: pam_unix(sudo:auth): authentication failure; logname= user=bob\n"
            "Oct 11 21:16:00 ubuntu-node sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls\n"
        )
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(lines)

        collector = AuthLogCollector(log_path=self.log_path, logger=self.logger)
        collector.initialize()
        events = collector.collect_once()

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["auth_status"], "failed")
        self.assertEqual(events[0]["username"], "bob")
        self.assertEqual(events[0]["event_subtype"], "sudo_auth_failure")

        self.assertEqual(events[1]["auth_status"], "accepted")
        self.assertEqual(events[1]["username"], "bob")
        self.assertEqual(events[1]["event_subtype"], "sudo_command_execution")

    def test_incremental_read_and_checkpoint(self):
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("Oct 11 21:00:00 ubuntu-node sshd[1]: line 1\n")

        collector = AuthLogCollector(log_path=self.log_path, logger=self.logger)
        collector.initialize()
        batch1 = collector.collect_once()
        self.assertEqual(len(batch1), 1)

        collector.update_checkpoint(batch1[0]["record_id"], batch1[0]["byte_offset"])

        # No new events
        self.assertEqual(collector.collect_once(), [])

        # Append second line
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write("Oct 11 21:00:01 ubuntu-node sshd[2]: line 2\n")

        batch2 = collector.collect_once()
        self.assertEqual(len(batch2), 1)
        self.assertIn("line 2", batch2[0]["raw_message"])

    def test_malformed_unstructured_line(self):
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("Random corrupted text without syslog structure\n")

        collector = AuthLogCollector(log_path=self.log_path, logger=self.logger)
        collector.initialize()
        events = collector.collect_once()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_subtype"], "unstructured_log")

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_journald_fallback_success(self, mock_run, mock_which):
        mock_which.return_value = "/bin/journalctl"
        mock_output = (
            "2026-10-11T21:00:00+00:00 ubuntu-node sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2\n"
            "2026-10-11T21:05:00+00:00 ubuntu-node sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/id\n"
        )
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output
        mock_run.return_value = mock_proc

        nonexistent_log = os.path.join(self.test_dir, "nonexistent.log")
        collector = AuthLogCollector(log_path=nonexistent_log, logger=self.logger, enable_journald_fallback=True)
        collector.initialize()

        events = collector.collect_once()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["auth_status"], "failed")
        self.assertEqual(events[0]["username"], "admin")
        self.assertEqual(events[0]["event_subtype"], "ssh_login_failure")
        self.assertEqual(events[1]["username"], "alice")
        self.assertEqual(events[1]["event_subtype"], "sudo_command_execution")

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertEqual(args[0], "/bin/journalctl")
        self.assertIn("-u", args)

    @patch("shutil.which")
    def test_journald_fallback_not_installed(self, mock_which):
        mock_which.return_value = None
        nonexistent_log = os.path.join(self.test_dir, "nonexistent.log")
        collector = AuthLogCollector(log_path=nonexistent_log, logger=self.logger, enable_journald_fallback=True)
        collector.initialize()

        events = collector.collect_once()
        self.assertEqual(events, [])

if __name__ == "__main__":
    unittest.main()
