import unittest
import copy
import logging
from datetime import datetime, timedelta, timezone
from detection.models import DetectionResult
from detection.detector import DetectionEngine
from detection.xgboost_detector import XGBoostDetector, ModelNotAvailableError
from detection.rules import BruteForceRule

class TestDetectionLayer(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestDetection")
        self.logger.setLevel(logging.CRITICAL)
        self.engine = DetectionEngine(self.logger)
        self.rule = BruteForceRule()
        
    def _make_event(self, timestamp: str, event_id: str, win_event_id: int, user: str = "admin", ip: str = "10.0.0.1"):
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "agent_id": "agent-1",
            "hostname": "TEST-PC",
            "os": "Windows",
            "event_type": "windows_security_event",
            "source_ip": ip,
            "username": user,
            "severity": "low",
            "detection_type": None,
            "confidence": None,
            "evidence": {
                "record_id": 999,
                "windows_event_id": win_event_id
            }
        }

    def test_single_event_no_detection(self):
        e = self._make_event("2026-10-03T15:00:00Z", "e1", 4625)
        self.assertIsNone(self.rule.evaluate(e))

    def test_four_events_no_detection(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            e = self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625)
            self.assertIsNone(self.rule.evaluate(e))

    def test_fifth_event_detection(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625))
            
        e5 = self._make_event((base_time + timedelta(seconds=4)).isoformat(), "e4", 4625)
        result = self.rule.evaluate(e5)
        
        self.assertIsNotNone(result)
        self.assertTrue(result.detected)
        self.assertEqual(result.detection_type, "windows_bruteforce_rule")
        self.assertEqual(result.confidence, 1.0)
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.detector_name, "windows_bruteforce_rule")
        self.assertEqual(result.source_event_id, "e4")
        self.assertEqual(result.evidence["failure_count"], 5)
        self.assertEqual(result.evidence["threshold"], 5)
        self.assertEqual(result.evidence["window_seconds"], 60)
        self.assertEqual(result.evidence["related_event_ids"], ["e0", "e1", "e2", "e3", "e4"])
        
    def test_duplicate_suppression_behavior(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        # 5 failures trigger alert
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625))
        res1 = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=4)).isoformat(), "e4", 4625))
        self.assertIsNotNone(res1)
        
        # 6th failure inside window should NOT trigger another alert
        res2 = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=5)).isoformat(), "e5", 4625))
        self.assertIsNone(res2)
        
        # Another failure at t=61 (which expires the first alert's cutoff)
        # At t=61, failures at [1, 2, 3, 4, 5, 61] are kept (6 failures).
        # The previous alert was at t=4. cutoff is 61-60 = 1.
        # last_alert_time (4) is NOT < cutoff (1). So it is STILL suppressed!
        res3 = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=61)).isoformat(), "e6", 4625))
        self.assertIsNone(res3)
        
        # At t=65, failures at [5, 61, 65] (3 failures) -> no alert anyway.
        res4 = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=65)).isoformat(), "e7", 4625))
        self.assertIsNone(res4)
        
        # At t=120, old alert was t=4.
        # Existing events in state: t=61, t=65.
        # Adding t=120 -> 3 events
        self.assertIsNone(self.rule.evaluate(self._make_event((base_time + timedelta(seconds=120)).isoformat(), "e8", 4625)))
        # Adding t=121 -> 4 events
        self.assertIsNone(self.rule.evaluate(self._make_event((base_time + timedelta(seconds=121)).isoformat(), "e9", 4625)))
        
        # Adding t=122 -> Cutoff is 62. t=61 is expired!
        # Remaining: 65, 120, 121, 122 -> 4 events.
        self.assertIsNone(self.rule.evaluate(self._make_event((base_time + timedelta(seconds=122)).isoformat(), "e10", 4625)))
        
        # Adding t=123 -> Cutoff is 63.
        # Remaining: 65, 120, 121, 122, 123 -> 5 events!
        # last_alert is 4. 4 < 63 is True. ALERT!
        res5 = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=123)).isoformat(), "e11", 4625))
        self.assertIsNotNone(res5)
        
        # Adding t=124 -> Cutoff is 64. 65, 120, 121, 122, 123, 124 -> 6 events.
        # last_alert is 123. 123 < 64 is False. Suppressed!
        res6 = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=124)).isoformat(), "e12", 4625))
        self.assertIsNone(res6)

    def test_non_4625_ignored(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(10):
            self.assertIsNone(self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4624)))

    def test_different_users_isolated(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625, user="userA"))
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e_b{i}", 4625, user="userB"))
        # Neither has 5 yet
        self.assertIsNone(self.rule.evaluate(self._make_event((base_time + timedelta(seconds=5)).isoformat(), "e_c", 4625, user="userC")))

    def test_different_ips_isolated(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625, ip="1.1.1.1"))
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e_b{i}", 4625, ip="2.2.2.2"))
        
        res = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=4)).isoformat(), "e4", 4625, ip="1.1.1.1"))
        self.assertIsNotNone(res)
        
    def test_missing_ip(self):
        e = self._make_event("2026-10-03T15:00:00Z", "e1", 4625, ip=None)
        self.rule.evaluate(e)
        self.assertIn(("admin", None), self.rule.state)
        
    def test_missing_username_ignored(self):
        e = self._make_event("2026-10-03T15:00:00Z", "e1", 4625, user=None)
        self.assertIsNone(self.rule.evaluate(e))
        self.assertEqual(len(self.rule.state), 0)

    def test_window_expiration(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i*10)).isoformat(), f"e{i}", 4625))
            
        # 5th event at t=70. The one at t=0 will be expired (70 - 60 = 10, so t=0 < 10).
        # We will only have [10, 20, 30, 70] -> 4 events. No alert.
        e5 = self._make_event((base_time + timedelta(seconds=70)).isoformat(), "e5", 4625)
        self.assertIsNone(self.rule.evaluate(e5))
        
    def test_exact_boundary(self):
        # Window is 60 seconds. An event exactly 60 seconds old is included (>= cutoff)
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625))
        
        # 5th event exactly at 60s
        e5 = self._make_event((base_time + timedelta(seconds=60)).isoformat(), "e5", 4625)
        res = self.rule.evaluate(e5)
        self.assertIsNotNone(res)

    def test_input_immutability(self):
        e = self._make_event("2026-10-03T15:00:00Z", "e1", 4625)
        e_copy = copy.deepcopy(e)
        self.rule.evaluate(e)
        self.assertEqual(e, e_copy)
        
    def test_invalid_timestamp(self):
        e = self._make_event("bad_time", "e1", 4625)
        with self.assertRaises(ValueError):
            self.rule.evaluate(e)
            
    def test_state_reset(self):
        e = self._make_event("2026-10-03T15:00:00Z", "e1", 4625)
        self.rule.evaluate(e)
        self.assertEqual(len(self.rule.state), 1)
        self.rule.reset_state()
        self.assertEqual(len(self.rule.state), 0)

    def test_engine_graceful_with_xgboost_unavailable(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            self.engine.process_event(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e{i}", 4625))
            
        # 5th should trigger brute force despite XGBoost throwing ModelNotAvailableError
        results = self.engine.process_event(self._make_event((base_time + timedelta(seconds=4)).isoformat(), "e4", 4625))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].detection_type, "windows_bruteforce_rule")
