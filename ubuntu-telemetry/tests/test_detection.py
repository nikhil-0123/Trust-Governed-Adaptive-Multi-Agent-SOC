import unittest
from datetime import datetime, timezone, timedelta
from detection.rules import LinuxSSHBruteForceRule, LinuxSuspiciousSudoRule
from detection.detector import DetectionEngine

def make_norm_event(idx: int, user: str, ip: str, subtype: str = "ssh_login_failure", time_offset: int = 0) -> dict:
    base = datetime(2026, 10, 11, 21, 0, 0, tzinfo=timezone.utc)
    ts = (base + timedelta(seconds=time_offset)).isoformat()
    return {
        "event_id": f"evt-{idx}",
        "timestamp": ts,
        "agent_id": "test-agent-ubuntu",
        "hostname": "test-ubuntu",
        "os": "Linux",
        "username": user,
        "source_ip": ip,
        "severity": "medium",
        "evidence": {
            "process": "sshd" if "ssh" in subtype else "sudo",
            "auth_status": "failed",
            "event_subtype": subtype,
            "port": 2222
        }
    }

class TestUbuntuDetection(unittest.TestCase):
    def setUp(self):
        self.ssh_rule = LinuxSSHBruteForceRule(failure_threshold=5, window_seconds=60)
        self.sudo_rule = LinuxSuspiciousSudoRule(failure_threshold=3, window_seconds=60)

    def test_four_ssh_events_no_detection(self):
        for i in range(4):
            ev = make_norm_event(i, "admin", "192.168.1.10", time_offset=i*5)
            res = self.ssh_rule.evaluate(ev)
            self.assertIsNone(res)

    def test_fifth_ssh_event_triggers_detection(self):
        for i in range(4):
            ev = make_norm_event(i, "admin", "192.168.1.10", time_offset=i*5)
            self.ssh_rule.evaluate(ev)

        ev5 = make_norm_event(4, "admin", "192.168.1.10", time_offset=20)
        res = self.ssh_rule.evaluate(ev5)

        self.assertIsNotNone(res)
        self.assertTrue(res.detected)
        self.assertEqual(res.detection_type, "brute_force")
        self.assertEqual(res.severity, "high")
        self.assertEqual(res.confidence, 1.0)
        self.assertEqual(res.evidence["failure_count"], 5)
        self.assertEqual(res.evidence["username"], "admin")
        self.assertEqual(res.evidence["source_ip"], "192.168.1.10")

    def test_duplicate_suppression_within_window(self):
        for i in range(5):
            ev = make_norm_event(i, "admin", "192.168.1.10", time_offset=i*2)
            res = self.ssh_rule.evaluate(ev)
        self.assertIsNotNone(res)

        # 6th failure in same window should be suppressed
        ev6 = make_norm_event(5, "admin", "192.168.1.10", time_offset=12)
        res6 = self.ssh_rule.evaluate(ev6)
        self.assertIsNone(res6)

    def test_window_expiration(self):
        for i in range(4):
            ev = make_norm_event(i, "admin", "192.168.1.10", time_offset=i*2)
            self.ssh_rule.evaluate(ev)

        # 5th event after 70 seconds -> earlier 4 events expired
        ev5 = make_norm_event(4, "admin", "192.168.1.10", time_offset=70)
        res = self.ssh_rule.evaluate(ev5)
        self.assertIsNone(res)

    def test_isolation_between_different_ips(self):
        for i in range(4):
            ev1 = make_norm_event(i, "admin", "192.168.1.10", time_offset=i*2)
            self.ssh_rule.evaluate(ev1)

        # 5th event from different IP
        ev_diff = make_norm_event(4, "admin", "10.0.0.50", time_offset=10)
        res = self.ssh_rule.evaluate(ev_diff)
        self.assertIsNone(res)

    def test_suspicious_sudo_rule(self):
        for i in range(2):
            ev = make_norm_event(i, "alice", "127.0.0.1", subtype="sudo_auth_failure", time_offset=i*5)
            res = self.sudo_rule.evaluate(ev)
            self.assertIsNone(res)

        ev3 = make_norm_event(2, "alice", "127.0.0.1", subtype="sudo_auth_failure", time_offset=12)
        res3 = self.sudo_rule.evaluate(ev3)
        self.assertIsNotNone(res3)
        self.assertEqual(res3.detection_type, "suspicious_sudo_activity")
        self.assertEqual(res3.severity, "medium")

    def test_engine_input_immutability(self):
        engine = DetectionEngine()
        ev = make_norm_event(1, "admin", "192.168.1.10")
        original_ev = dict(ev)
        original_evidence = dict(ev["evidence"])

        engine.process_event(ev)
        self.assertEqual(ev, original_ev)
        self.assertEqual(ev["evidence"], original_evidence)

if __name__ == "__main__":
    unittest.main()
