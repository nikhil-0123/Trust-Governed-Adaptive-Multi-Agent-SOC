import unittest
import copy
import logging
from datetime import datetime, timedelta, timezone
from detection.models import DetectionResult
from detection.detector import DetectionEngine
from detection.xgboost_detector import XGBoostDetector, ModelNotAvailableError
from detection.rules import BruteForceRule
from core.logger import StructuredFormatter

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

    def test_ttl_expiration_prunes_stale_keys(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        # Event for userA at t=0
        self.rule.evaluate(self._make_event(base_time.isoformat(), "e_a", 4625, user="userA"))
        self.assertIn(("userA", "10.0.0.1"), self.rule.state)

        # Event for userB at t=100 (t=0 is older than 100 - 60 = 40)
        self.rule.evaluate(self._make_event((base_time + timedelta(seconds=100)).isoformat(), "e_b", 4625, user="userB"))
        # userA should have been evicted as stale
        self.assertNotIn(("userA", "10.0.0.1"), self.rule.state)
        self.assertIn(("userB", "10.0.0.1"), self.rule.state)

    def test_active_keys_preserved_during_cleanup(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        # userA at t=50
        self.rule.evaluate(self._make_event((base_time + timedelta(seconds=50)).isoformat(), "e_a", 4625, user="userA"))
        # userB at t=70
        self.rule.evaluate(self._make_event((base_time + timedelta(seconds=70)).isoformat(), "e_b", 4625, user="userB"))
        # Both keys should be active since 50 >= 70 - 60 (10)
        self.assertIn(("userA", "10.0.0.1"), self.rule.state)
        self.assertIn(("userB", "10.0.0.1"), self.rule.state)

    def test_repeated_events_deduplicated(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        # Send the exact same event_id 5 times
        for i in range(5):
            res = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), "identical_event_id", 4625))
            self.assertIsNone(res, "Duplicate event IDs must not trigger repeated alerts")
        # Ensure failure count remained 1
        group_state = self.rule.state[("admin", "10.0.0.1")]
        self.assertEqual(len(group_state["events"]), 1)

    def test_out_of_order_timestamps_detection(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        # Arrive out-of-order: t=10, 20, 50, 60, then late-arriving t=30
        timestamps = [10, 20, 50, 60, 30]
        event_ids = ["e10", "e20", "e50", "e60", "e30"]

        results = []
        for sec, eid in zip(timestamps, event_ids):
            r = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=sec)).isoformat(), eid, 4625))
            if r:
                results.append(r)

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertTrue(res.detected)
        self.assertEqual(res.evidence["failure_count"], 5)
        # Chronologically sorted related events
        self.assertEqual(res.evidence["related_event_ids"], ["e10", "e20", "e30", "e50", "e60"])

    def test_out_of_order_ancient_event_pruned(self):
        base_time = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        # 4 events near t=100
        for i in range(4):
            self.rule.evaluate(self._make_event((base_time + timedelta(seconds=90 + i)).isoformat(), f"e_{i}", 4625))

        # A very late-arriving ancient event at t=10 arrives (cutoff is 93 - 60 = 33, so 10 < 33)
        res = self.rule.evaluate(self._make_event((base_time + timedelta(seconds=10)).isoformat(), "ancient_event", 4625))
        self.assertIsNone(res, "Ancient out-of-order event must be pruned and not trigger detection")
        group_state = self.rule.state[("admin", "10.0.0.1")]
        self.assertEqual(len(group_state["events"]), 4)

    def test_failure_threshold_validation(self):
        with self.assertRaises(ValueError):
            BruteForceRule(failure_threshold=2)
        with self.assertRaises(ValueError):
            BruteForceRule(failure_threshold=0)
        # Threshold >= 3 should succeed
        r = BruteForceRule(failure_threshold=3)
        self.assertEqual(r.failure_threshold, 3)

    def test_state_capacity_limit_and_watermark_batch_eviction(self):
        # Configure rule with small capacity: max=20, low_watermark=int(20*0.85)=17
        rule = BruteForceRule(max_state_keys=20, cleanup_interval_seconds=10.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # Ingest 21 unique keys within same time window
        for i in range(21):
            t = base_time + timedelta(seconds=i % 10)
            e = self._make_event(t.isoformat(), f"id_{i}", 4625, user=f"user_{i}", ip=f"10.0.0.{i}")
            rule.evaluate(e)

        # High watermark was hit (20), batch evicted down to <= low_watermark (17) + current group
        self.assertLessEqual(len(rule.state), 18)
        self.assertGreater(rule.metrics["total_evictions"], 0)

    def test_tier1_noise_evicted_before_tier2(self):
        # max=10, low=8. Insert 5 Tier 2 keys (2 attempts each) and 5 Tier 1 keys (1 attempt each)
        rule = BruteForceRule(max_state_keys=10, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # 5 Tier 2 keys (2 attempts each)
        for i in range(5):
            u = f"tier2_user_{i}"
            rule.evaluate(self._make_event(base_time.isoformat(), f"t2_a_{i}", 4625, user=u, ip="10.0.0.2"))
            rule.evaluate(self._make_event((base_time + timedelta(seconds=1)).isoformat(), f"t2_b_{i}", 4625, user=u, ip="10.0.0.2"))

        # 5 Tier 1 keys (1 attempt each)
        for i in range(5):
            u = f"tier1_user_{i}"
            rule.evaluate(self._make_event(base_time.isoformat(), f"t1_{i}", 4625, user=u, ip="10.0.0.1"))

        self.assertEqual(len(rule.state), 10)

        # Ingest an 11th key, triggering batch eviction
        rule.evaluate(self._make_event(base_time.isoformat(), "new_key", 4625, user="new_user", ip="10.0.0.3"))

        # All 5 Tier 2 keys must still be preserved!
        for i in range(5):
            self.assertIn((f"tier2_user_{i}", "10.0.0.2"), rule.state)

    def test_near_threshold_candidates_protected_from_noise_eviction(self):
        # max=10. Insert 3 Tier 4 protected keys (4 attempts each) and 7 Tier 1 keys (1 attempt each)
        rule = BruteForceRule(max_state_keys=10, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        for i in range(3):
            u = f"target_user_{i}"
            for att in range(4):
                rule.evaluate(self._make_event((base_time + timedelta(seconds=att)).isoformat(), f"tgt_{i}_{att}", 4625, user=u, ip="192.168.1.50"))

        for i in range(7):
            rule.evaluate(self._make_event(base_time.isoformat(), f"noise_{i}", 4625, user=f"noise_user_{i}", ip="10.0.0.1"))

        self.assertEqual(len(rule.state), 10)

        # Inject 5 new noise keys, triggering eviction
        for i in range(5):
            rule.evaluate(self._make_event(base_time.isoformat(), f"extra_noise_{i}", 4625, user=f"extra_{i}", ip="10.0.0.1"))

        # All 3 Tier 4 protected keys must be completely intact with all 4 events preserved!
        for i in range(3):
            key = (f"target_user_{i}", "192.168.1.50")
            self.assertIn(key, rule.state)
            self.assertEqual(len(rule.state[key]["events"]), 4)

            # 5th attempt triggers detection successfully
            res = rule.evaluate(self._make_event((base_time + timedelta(seconds=10)).isoformat(), f"tgt_final_{i}", 4625, user=f"target_user_{i}", ip="192.168.1.50"))
            self.assertIsNotNone(res)
            self.assertTrue(res.detected)

    def test_alerted_group_duplicate_suppression_and_retention(self):
        rule = BruteForceRule(max_state_keys=10, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # Trigger detection on user_alert
        for i in range(5):
            res = rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"ev_{i}", 4625, user="user_alert", ip="10.0.0.9"))
        self.assertIsNotNone(res)

        # Add 9 noise keys to fill capacity to 10
        for i in range(9):
            rule.evaluate(self._make_event(base_time.isoformat(), f"n_{i}", 4625, user=f"noise_{i}", ip="10.0.0.1"))

        # Add another key to trigger watermark eviction
        rule.evaluate(self._make_event(base_time.isoformat(), "trigger_key", 4625, user="trig", ip="10.0.0.1"))

        # Alerted group is in Tier 3 (protected ongoing cluster), so it must NOT be evicted before noise!
        self.assertIn(("user_alert", "10.0.0.9"), rule.state)

        # Next event within window must be suppressed (no duplicate alert)
        res6 = rule.evaluate(self._make_event((base_time + timedelta(seconds=10)).isoformat(), "ev_6", 4625, user="user_alert", ip="10.0.0.9"))
        self.assertIsNone(res6, "Subsequent attempt within window must be suppressed and not duplicate alert")

    def test_expired_alert_with_active_events_reclassified(self):
        rule = BruteForceRule(max_state_keys=10, window_seconds=60, cleanup_interval_seconds=1.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # Alert triggered at t=0
        for i in range(5):
            rule.evaluate(self._make_event((base_time + timedelta(seconds=i)).isoformat(), f"e_{i}", 4625, user="reclass_user", ip="10.0.0.1"))

        group = rule.state[("reclass_user", "10.0.0.1")]
        self.assertIsNotNone(group["last_alert_time"])

        # Advance time to t=70 (window_seconds=60, so last_alert_time is now expired)
        t_70 = base_time + timedelta(seconds=70)
        # Ingest 1 new event at t=70
        rule.evaluate(self._make_event(t_70.isoformat(), "e_70", 4625, user="reclass_user", ip="10.0.0.1"))

        # Alert suppression has expired, active events is 1 -> reclassified as Tier 1 Noise!
        group = rule.state[("reclass_user", "10.0.0.1")]
        self.assertEqual(len(group["events"]), 1)

    def test_deterministic_saturated_fallback(self):
        # max=5. Fill all 5 keys with Tier 4 (4 attempts each)
        rule = BruteForceRule(max_state_keys=5, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        for i in range(5):
            u = f"sat_user_{i}"
            for att in range(4):
                # Time staggered: user_0 is oldest, user_4 is newest
                t = base_time + timedelta(seconds=i * 5 + att)
                rule.evaluate(self._make_event(t.isoformat(), f"s_{i}_{att}", 4625, user=u, ip="10.0.0.1"))

        self.assertEqual(len(rule.state), 5)
        self.assertEqual(rule.metrics["forced_active_state_evictions"], 0)

        # Ingest 6th key. Since all 5 keys are Tier 4, saturated fallback must trigger!
        rule.evaluate(self._make_event((base_time + timedelta(seconds=50)).isoformat(), "inflow_6", 4625, user="inflow_user", ip="10.0.0.1"))

        # Metrics must increment forced active eviction counter
        self.assertGreaterEqual(rule.metrics["forced_active_state_evictions"], 1)
        # Oldest Tier 4 candidate (sat_user_0) was deterministically evicted
        self.assertNotIn(("sat_user_0", "10.0.0.1"), rule.state)
        # Newer candidates preserved
        self.assertIn(("sat_user_4", "10.0.0.1"), rule.state)

    def test_throttled_ttl_cleanup_monotonic(self):
        rule = BruteForceRule(cleanup_interval_seconds=60.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # Ingest event 1 at t=0
        rule.evaluate(self._make_event(base_time.isoformat(), "e1", 4625, user="u1", ip="10.0.0.1"))
        cleanups_before = rule.metrics["ttl_cleanups"]

        # Call evaluate with timestamp at t=10 (delta 10s < cleanup_interval 60s, monotonic < 60s)
        t_next = base_time + timedelta(seconds=10)
        rule.evaluate(self._make_event(t_next.isoformat(), "e2", 4625, user="u2", ip="10.0.0.1"))

        # Periodic cleanup was throttled
        self.assertEqual(rule.metrics["ttl_cleanups"], cleanups_before)

        # Advance to t=100 (delta 100s > 60s) -> triggers cleanup
        t_fut = base_time + timedelta(seconds=100)
        rule.evaluate(self._make_event(t_fut.isoformat(), "e3", 4625, user="u3", ip="10.0.0.1"))
        self.assertGreater(rule.metrics["ttl_cleanups"], cleanups_before)
        # u1 (at t=0) is older than t=100 - 60s = 40s -> pruned!
        self.assertNotIn(("u1", "10.0.0.1"), rule.state)

    def test_configuration_boundary_validation(self):
        # max_state_keys validation
        with self.assertRaises(ValueError):
            BruteForceRule(max_state_keys=1)
        with self.assertRaises(ValueError):
            BruteForceRule(max_state_keys=0)
        with self.assertRaises(ValueError):
            BruteForceRule(max_state_keys=-5)
        with self.assertRaises(TypeError):
            BruteForceRule(max_state_keys=True)
        with self.assertRaises(TypeError):
            BruteForceRule(max_state_keys=False)
        with self.assertRaises(TypeError):
            BruteForceRule(max_state_keys=10.5)
        with self.assertRaises(TypeError):
            BruteForceRule(max_state_keys="100")

        # cleanup_interval_seconds validation
        with self.assertRaises(ValueError):
            BruteForceRule(cleanup_interval_seconds=0)
        with self.assertRaises(ValueError):
            BruteForceRule(cleanup_interval_seconds=-1.0)
        with self.assertRaises(ValueError):
            BruteForceRule(cleanup_interval_seconds=float('nan'))
        with self.assertRaises(ValueError):
            BruteForceRule(cleanup_interval_seconds=float('inf'))
        with self.assertRaises(ValueError):
            BruteForceRule(cleanup_interval_seconds=float('-inf'))
        with self.assertRaises(TypeError):
            BruteForceRule(cleanup_interval_seconds=True)
        with self.assertRaises(TypeError):
            BruteForceRule(cleanup_interval_seconds="5.0")

        # window_seconds validation
        with self.assertRaises(ValueError):
            BruteForceRule(window_seconds=0)
        with self.assertRaises(ValueError):
            BruteForceRule(window_seconds=-10)
        with self.assertRaises(ValueError):
            BruteForceRule(window_seconds=True)

        # Valid initialization at exact boundary
        r = BruteForceRule(max_state_keys=2, cleanup_interval_seconds=0.1, window_seconds=1, failure_threshold=3)
        self.assertEqual(r.max_state_keys, 2)
        self.assertEqual(r.cleanup_interval, 0.1)

    def test_low_watermark_bounds(self):
        for n in [2, 3, 4, 5, 10, 50, 100, 1000, 10000]:
            r = BruteForceRule(max_state_keys=n)
            self.assertGreater(r.low_watermark, 0, f"low_watermark must be > 0 for max={n}")
            self.assertLess(r.low_watermark, n, f"low_watermark must be < max for max={n}")

    def test_forced_eviction_precedence_tier3_before_tier4(self):
        # max=5, low_watermark=4. When full (5) and 6th arrives, num_to_evict = 6 - 4 = 2.
        rule = BruteForceRule(max_state_keys=5, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # 2 Tier 3 keys (alerted groups, 5 attempts each)
        for i in range(2):
            u = f"tier3_user_{i}"
            for att in range(5):
                t = base_time + timedelta(seconds=i * 10 + att)
                rule.evaluate(self._make_event(t.isoformat(), f"t3_{i}_{att}", 4625, user=u, ip="10.0.0.3"))

        # 3 Tier 4 keys (near-threshold groups, 4 attempts each)
        for i in range(3):
            u = f"tier4_user_{i}"
            for att in range(4):
                t = base_time + timedelta(seconds=20 + i * 5 + att)
                rule.evaluate(self._make_event(t.isoformat(), f"t4_{i}_{att}", 4625, user=u, ip="10.0.0.4"))

        self.assertEqual(len(rule.state), 5)
        self.assertEqual(rule.metrics["forced_tier3_evictions"], 0)
        self.assertEqual(rule.metrics["forced_tier4_evictions"], 0)

        # Inflow 6th key triggers eviction of 2 keys
        t_trigger = base_time + timedelta(seconds=50)
        rule.evaluate(self._make_event(t_trigger.isoformat(), "inflow_trigger", 4625, user="inflow_user", ip="10.0.0.9"))

        # Precedence check: Tier 3 (alerted) MUST be evicted before Tier 4 (near-threshold)!
        self.assertEqual(rule.metrics["forced_tier3_evictions"], 2)
        self.assertEqual(rule.metrics["forced_tier4_evictions"], 0)
        self.assertEqual(rule.metrics["forced_active_state_evictions"], 2)

        # All 3 Tier 4 keys must be completely intact!
        for i in range(3):
            self.assertIn((f"tier4_user_{i}", "10.0.0.4"), rule.state)

    def test_forced_eviction_tier4_when_tier3_exhausted(self):
        # max=4, low_watermark=3. When full (4) and 5th arrives, num_to_evict = 5 - 3 = 2.
        rule = BruteForceRule(max_state_keys=4, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # 1 Tier 3 key (alerted group, 5 attempts)
        for att in range(5):
            rule.evaluate(self._make_event((base_time + timedelta(seconds=att)).isoformat(), f"t3_{att}", 4625, user="t3_only", ip="10.0.0.3"))

        # 3 Tier 4 keys (near-threshold groups, 4 attempts each)
        for i in range(3):
            u = f"t4_u_{i}"
            for att in range(4):
                t = base_time + timedelta(seconds=10 + i * 5 + att)
                rule.evaluate(self._make_event(t.isoformat(), f"t4_{i}_{att}", 4625, user=u, ip="10.0.0.4"))

        self.assertEqual(len(rule.state), 4)

        # 5th key triggers eviction of 2 keys
        rule.evaluate(self._make_event((base_time + timedelta(seconds=50)).isoformat(), "trigger", 4625, user="new_user", ip="10.0.0.9"))

        # 1 Tier 3 key evicted, and 1 Tier 4 key forced evicted!
        self.assertEqual(rule.metrics["forced_tier3_evictions"], 1)
        self.assertEqual(rule.metrics["forced_tier4_evictions"], 1)
        self.assertEqual(rule.metrics["forced_active_state_evictions"], 2)

    def test_structured_logging_during_forced_eviction(self):
        log_records = []
        class LogCapturer(logging.Handler):
            def emit(self, record):
                log_records.append(record)

        logger = logging.getLogger("TestForcedEvictionLog")
        logger.setLevel(logging.WARNING)
        capturer = LogCapturer()
        formatter = StructuredFormatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        capturer.setFormatter(formatter)
        logger.addHandler(capturer)

        try:
            rule = BruteForceRule(max_state_keys=4, cleanup_interval_seconds=100.0, logger=logger)
            base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

            # 4 Tier 4 keys
            for i in range(4):
                for att in range(4):
                    rule.evaluate(self._make_event((base_time + timedelta(seconds=i*5+att)).isoformat(), f"e_{i}_{att}", 4625, user=f"secret_user_{i}", ip=f"192.168.1.{i+10}"))

            # 5th key triggers forced eviction of Tier 4
            rule.evaluate(self._make_event((base_time + timedelta(seconds=50)).isoformat(), "trig", 4625, user="trig_u", ip="10.0.0.1"))

            # Verify structured warning
            self.assertTrue(len(log_records) > 0, "A forced eviction log message should have been emitted")
            record = log_records[0]

            # Verify explicit extra fields on record
            self.assertEqual(getattr(record, "event_type", None), "state_forced_eviction")
            self.assertEqual(getattr(record, "eviction_tier", None), "Tier 4 (Near-Threshold)")
            self.assertEqual(getattr(record, "forced_eviction_count", None), 2)
            self.assertEqual(getattr(record, "max_capacity", None), 4)
            self.assertEqual(getattr(record, "low_watermark", None), 3)
            self.assertIsInstance(getattr(record, "current_size", None), int)

            # Verify structured formatter serialization
            formatted_text = formatter.format(record)
            self.assertIn("event_type=state_forced_eviction", formatted_text)
            self.assertIn("eviction_tier=Tier 4 (Near-Threshold)", formatted_text)
            self.assertIn("forced_eviction_count=2", formatted_text)
            self.assertIn("max_capacity=4", formatted_text)
            self.assertIn("low_watermark=3", formatted_text)

            # Verify no usernames or IPs are leaked in log record message or formatted text
            for i in range(4):
                self.assertNotIn(f"secret_user_{i}", record.getMessage())
                self.assertNotIn(f"192.168.1.{i+10}", record.getMessage())
                self.assertNotIn(f"secret_user_{i}", formatted_text)
                self.assertNotIn(f"192.168.1.{i+10}", formatted_text)
        finally:
            logger.removeHandler(capturer)

    def test_structured_logging_combined_tier3_and_tier4(self):
        log_records = []
        class LogCapturer(logging.Handler):
            def emit(self, record):
                log_records.append(record)

        logger = logging.getLogger("TestCombinedEvictionLog")
        logger.setLevel(logging.WARNING)
        capturer = LogCapturer()
        formatter = StructuredFormatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        capturer.setFormatter(formatter)
        logger.addHandler(capturer)

        try:
            # max=4, low_watermark=3. When 5th arrives, need to evict 2 keys.
            rule = BruteForceRule(max_state_keys=4, cleanup_interval_seconds=100.0, logger=logger)
            base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

            # 1 Tier 3 key (alerted group)
            for att in range(5):
                rule.evaluate(self._make_event((base_time + timedelta(seconds=att)).isoformat(), f"t3_{att}", 4625, user="t3_u", ip="10.0.0.1"))

            # 3 Tier 4 keys (near-threshold groups)
            for i in range(3):
                for att in range(4):
                    rule.evaluate(self._make_event((base_time + timedelta(seconds=10 + i*5 + att)).isoformat(), f"t4_{i}_{att}", 4625, user=f"t4_u_{i}", ip="10.0.0.2"))

            # 5th key triggers eviction of 2 keys: 1 from Tier 3 and 1 from Tier 4
            rule.evaluate(self._make_event((base_time + timedelta(seconds=50)).isoformat(), "trig", 4625, user="new_u", ip="10.0.0.3"))

            # Exactly ONE warning must be emitted containing both counts!
            self.assertEqual(len(log_records), 1, "Exactly one warning must be emitted when both tiers are evicted")
            record = log_records[0]
            self.assertEqual(getattr(record, "event_type", None), "state_forced_eviction")
            self.assertEqual(getattr(record, "eviction_tier", None), "Tier 3 (Alerted) + Tier 4 (Near-Threshold)")
            self.assertEqual(getattr(record, "forced_eviction_count", None), 2)
            self.assertIn("evicted 1 Tier 3 and 1 Tier 4", record.getMessage())

            formatted_text = formatter.format(record)
            self.assertIn("eviction_tier=Tier 3 (Alerted) + Tier 4 (Near-Threshold)", formatted_text)
            self.assertIn("forced_eviction_count=2", formatted_text)
        finally:
            logger.removeHandler(capturer)

    def test_event_time_watermark_consistency_forward_and_out_of_order(self):
        rule = BruteForceRule(cleanup_interval_seconds=5.0, window_seconds=60)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # 1. Forward timestamp at t=100
        t100 = base_time + timedelta(seconds=100)
        rule.evaluate(self._make_event(t100.isoformat(), "e100", 4625, user="u100"))
        self.assertEqual(rule._max_observed_event_time, t100)
        self.assertEqual(rule._last_cleanup_event_time, t100)
        cleanups_initial = rule.metrics["ttl_cleanups"]

        # 2. Out-of-order timestamp at t=50 (older)
        t50 = base_time + timedelta(seconds=50)
        rule.evaluate(self._make_event(t50.isoformat(), "e50", 4625, user="u50"))
        # Watermark and cleanup tracker MUST NOT regress!
        self.assertEqual(rule._max_observed_event_time, t100)
        self.assertEqual(rule._last_cleanup_event_time, t100)

        # 3. Monotonic cleanup triggered during an out-of-order event
        # Force monotonic interval to be due by artificially advancing monotonic baseline
        rule._last_cleanup_monotonic = 0.0
        t55 = base_time + timedelta(seconds=55)
        rule.evaluate(self._make_event(t55.isoformat(), "e55", 4625, user="u55"))
        self.assertGreater(rule.metrics["ttl_cleanups"], cleanups_initial)
        # Even though cleanup ran during t=55, tracker and watermark MUST STILL remain at t100!
        self.assertEqual(rule._max_observed_event_time, t100)
        self.assertEqual(rule._last_cleanup_event_time, t100)

        # 4. Subsequent forward timestamp at t=103 (delta 3s < cleanup_interval 5s)
        cleanups_before_fwd = rule.metrics["ttl_cleanups"]
        t103 = base_time + timedelta(seconds=103)
        rule.evaluate(self._make_event(t103.isoformat(), "e103", 4625, user="u103"))
        self.assertEqual(rule._max_observed_event_time, t103)
        # Event time delta from tracker (100) is 3s < 5s -> throttled
        self.assertEqual(rule.metrics["ttl_cleanups"], cleanups_before_fwd)
        self.assertEqual(rule._last_cleanup_event_time, t100)

        # 5. Subsequent forward timestamp at t=107 (delta 7s >= cleanup_interval 5s)
        t107 = base_time + timedelta(seconds=107)
        rule.evaluate(self._make_event(t107.isoformat(), "e107", 4625, user="u107"))
        self.assertGreater(rule.metrics["ttl_cleanups"], cleanups_before_fwd)
        self.assertEqual(rule._max_observed_event_time, t107)
        self.assertEqual(rule._last_cleanup_event_time, t107)

    def test_historical_batch_replay_cleanup(self):
        # 100 events spanning 1000 seconds of event time (10s intervals), delivered in milliseconds
        rule = BruteForceRule(cleanup_interval_seconds=5.0, window_seconds=60)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        for i in range(100):
            t = base_time + timedelta(seconds=i * 10)
            rule.evaluate(self._make_event(t.isoformat(), f"replay_{i}", 4625, user=f"replay_user_{i}"))

        # In 1000 seconds at 10s intervals (every step >= 5s interval), cleanup should trigger continuously
        self.assertGreater(rule.metrics["ttl_cleanups"], 50)
        # Stale keys older than 60s window should be pruned. At t=990, only users with t >= 930 remain (~7 keys)
        self.assertLessEqual(len(rule.state), 10)

    def test_disaggregated_performance_metrics(self):
        rule = BruteForceRule(max_state_keys=10, cleanup_interval_seconds=100.0)
        base_time = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # 1. Non-4625 event -> fast path
        rule.evaluate(self._make_event(base_time.isoformat(), "fp1", 4624))
        self.assertEqual(rule.metrics["evaluations"], 1)
        self.assertEqual(rule.metrics["fast_path_evaluations"], 1)

        # 2. Missing username -> fast path
        rule.evaluate(self._make_event(base_time.isoformat(), "fp2", 4625, user=None))
        self.assertEqual(rule.metrics["evaluations"], 2)
        self.assertEqual(rule.metrics["fast_path_evaluations"], 2)

        # 3. Regular event
        rule.evaluate(self._make_event(base_time.isoformat(), "reg1", 4625, user="reg_user"))
        self.assertEqual(rule.metrics["evaluations"], 3)
        self.assertEqual(rule.metrics["fast_path_evaluations"], 2)

        # 4. Duplicate event_id -> fast path
        rule.evaluate(self._make_event(base_time.isoformat(), "reg1", 4625, user="reg_user"))
        self.assertEqual(rule.metrics["evaluations"], 4)
        self.assertEqual(rule.metrics["fast_path_evaluations"], 3)

if __name__ == "__main__":
    unittest.main()
