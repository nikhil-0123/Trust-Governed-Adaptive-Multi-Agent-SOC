"""
Unit and integration tests for Phase 3.1: Windows Telemetry Authentication Feature Extractor.
Validates all acceptance criteria:
- Non-arbitrary record ordering anomaly handling
- Checkpoint backlog recovery vs unrecoverable gaps
- Event-time deduplication recovery semantics
- Timezone determinism (f6 and f7)
- Quality exposure for Shannon entropy (f5)
- Ambiguous identity role feature suppression (f1-f4)
- Memory limits, LRU eviction, and fail-closed safety
"""

import pytest
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo
from detection.features import (
    AuthenticationFeatureExtractor,
    BusinessHoursConfig,
    CanonicalAuthEvent,
    DeterministicSimClock,
    FieldStatus,
    FutureEventError,
    IdentityRole,
    IPValidationStatus,
    LogonTypeStatus,
    SweepStatus,
    canonical_auth_from_contract_v1,
)


def make_test_canonical_event(
    event_id: str = "evt-001",
    record_id: int = 100,
    timestamp_epoch: float = 1000.0,
    event_type: str = "AUTHENTICATION_FAILURE",
    source_ip: str = "192.168.1.50",
    source_ip_status: IPValidationStatus = IPValidationStatus.VALID,
    observed_username: str = "alice",
    identity_role: IdentityRole = IdentityRole.AMBIGUOUS,
    logon_type: int = 3,
    logon_type_status: LogonTypeStatus = LogonTypeStatus.VALID,
    destination_host: str = "WORKSTATION-01",
    collector_id: str = "agent-win-01",
    source_log_name: str = "Security",
    dedup_hash: Optional[str] = None
) -> CanonicalAuthEvent:
    return CanonicalAuthEvent(
        event_id=event_id,
        collector_id=collector_id,
        raw_record_id=record_id,
        source_log_name=source_log_name,
        timestamp_epoch=timestamp_epoch,
        event_type=event_type,
        logon_type=logon_type,
        logon_type_status=logon_type_status,
        observed_username=observed_username,
        identity_role=identity_role,
        source_ip=source_ip,
        source_ip_status=source_ip_status,
        destination_host=destination_host,
        ingestion_timestamp=timestamp_epoch,
        dedup_hash=dedup_hash or event_id
    )


class TestAuthenticationFeatureExtractor:

    def test_delayed_sweep_backlog_recovery_preserves_coverage(self):
        """
        AC-3.1.9.1: A delayed collection sweep that recovers an intact, contiguous
        backlog via SUCCESS_COMPLETE maintains continuous coverage.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Baseline: initial event starts warm-up at t=100
        e1 = make_test_canonical_event(event_id="e1", record_id=100, timestamp_epoch=100.0)
        extractor.process_event(e1)

        # Ingest events up to t=1000 (establishing 900s of continuous coverage)
        e2 = make_test_canonical_event(event_id="e2", record_id=150, timestamp_epoch=1000.0)
        f2, can_pred2 = extractor.process_event(e2)
        assert f2.f5_logon_type_entropy_15m.is_available is True

        # Simulate a 10-minute delay in polling (sweep starts 600s later)
        # Upstream notifies that the delayed sweep completed successfully and completely
        extractor.notify_sweep_status(
            sweep_start_utc=1600.0,
            sweep_end_utc=1605.0,
            records_ingested=50,
            status=SweepStatus.SUCCESS_COMPLETE
        )

        # Ingest contiguous backlog event at t=1600
        e3 = make_test_canonical_event(event_id="e3", record_id=200, timestamp_epoch=1600.0)
        f3, can_pred3 = extractor.process_event(e3)

        # Continuous coverage was NOT broken by collection delay
        assert f3.f5_logon_type_entropy_15m.is_available is True
        assert can_pred3 is True

    def test_unrecoverable_evtx_overwrite_invalidates_window(self):
        """
        AC-3.1.9.2: Confirmed unrecoverable loss (EVTX circular overwrite) invalidates
        overlapping feature windows and restarts warm-up.
        """
        clock = DeterministicSimClock(current_time=2500.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Establish coverage from t=100 to t=1000
        extractor.process_event(make_test_canonical_event(event_id="e1", record_id=100, timestamp_epoch=100.0))
        extractor.process_event(make_test_canonical_event(event_id="e2", record_id=101, timestamp_epoch=1000.0))

        # Confirmed wrap-around gap between t=1100 and t=1400
        extractor.notify_unrecoverable_gap(
            gap_start_utc=1100.0,
            gap_end_utc=1400.0,
            reason="UNRECOVERABLE_EVTX_OVERWRITE"
        )

        # Event at t=1500 overlaps the gap (1500 - 900 = 600 <= 1100 < 1400 <= 1500)
        e3 = make_test_canonical_event(event_id="e3", record_id=5000, timestamp_epoch=1500.0)
        f3, _ = extractor.process_event(e3)

        assert f3.f5_logon_type_entropy_15m.is_available is False
        assert f3.f5_logon_type_entropy_15m.reason in ("TELEMETRY_GAP_DETECTED", "INSUFFICIENT_HISTORICAL_COVERAGE")

    def test_partial_sweep_failure_invalidates_coverage(self):
        """
        AC-3.1.9.3: A sweep reporting PARTIAL_FAILURE breaks coverage.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        extractor.process_event(make_test_canonical_event(event_id="e1", record_id=100, timestamp_epoch=100.0))
        extractor.process_event(make_test_canonical_event(event_id="e2", record_id=101, timestamp_epoch=1000.0))

        # Sweep partial failure
        extractor.notify_sweep_status(
            sweep_start_utc=1050.0,
            sweep_end_utc=1055.0,
            records_ingested=10,
            status=SweepStatus.PARTIAL_FAILURE,
            error_detail="Connection reset"
        )

        # Event immediately after partial failure returns unavailable
        e3 = make_test_canonical_event(event_id="e3", record_id=102, timestamp_epoch=1060.0)
        f3, _ = extractor.process_event(e3)

        assert f3.f5_logon_type_entropy_15m.is_available is False
        assert f3.f5_logon_type_entropy_15m.reason in ("TELEMETRY_GAP_DETECTED", "INSUFFICIENT_HISTORICAL_COVERAGE")

    def test_authoritative_event_1102_rotates_epoch(self):
        """
        AC-3.1.9.4: Windows Event ID 1102 rotates the internal epoch, purges the dedup cache,
        and restarts warm-up.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)
        initial_epoch = extractor.internal_epoch

        extractor.process_event(make_test_canonical_event(event_id="e1", record_id=500, timestamp_epoch=100.0))
        extractor.process_event(make_test_canonical_event(event_id="e2", record_id=501, timestamp_epoch=1000.0))

        # Authoritative clear
        extractor.notify_log_cleared(event_1102_timestamp_utc=1050.0)

        assert extractor.internal_epoch == initial_epoch + 1
        assert len(extractor._dedup_cache) == 0

        # Post-clear event restarts warm-up
        e3 = make_test_canonical_event(event_id="e3", record_id=1, timestamp_epoch=1060.0)
        f3, _ = extractor.process_event(e3)
        assert f3.f5_logon_type_entropy_15m.is_available is False
        assert f3.f5_logon_type_entropy_15m.reason == "INSUFFICIENT_HISTORICAL_COVERAGE"

    def test_unverified_record_regression_with_forward_timestamp_fails_closed(self):
        """
        AC-3.1.9.5: An unverified record-ID regression with a forward/recent timestamp (e.g. record 5 after 5000)
        without Event 1102 cannot establish log-generation continuity. It fails closed, is NOT inserted into
        trusted rolling history, restarts warm-up, and does not contaminate subsequent calculations.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Baseline: record 5000 at t=1000
        e1 = make_test_canonical_event(event_id="e5000", record_id=5000, timestamp_epoch=1000.0)
        extractor.process_event(e1)
        q1 = extractor._entity_events.get("WORKSTATION-01|192.168.1.50", [])
        assert len(q1) == 1
        assert q1[0].record_id == 5000

        # Unverified reset: record 5 at t=1010 (forward timestamp, unseen hash, no Event 1102)
        e2 = make_test_canonical_event(event_id="e5", record_id=5, timestamp_epoch=1010.0)
        f2, can_pred2 = extractor.process_event(e2)

        # Must fail closed immediately
        assert can_pred2 is False
        assert f2.f5_logon_type_entropy_15m.is_available is False
        assert f2.f5_logon_type_entropy_15m.reason == "UNRESOLVED_RECORD_ORDERING_ANOMALY"

        # PROOF: Record 5 was NOT inserted into trusted rolling history, and pre-regression history was purged
        q2 = extractor._entity_events.get("WORKSTATION-01|192.168.1.50", [])
        assert len(q2) == 0

        # PROOF: Warm-up was restarted and watermark cleared
        assert "WORKSTATION-01" not in extractor._coverage_start
        assert "WORKSTATION-01" not in extractor._entity_watermarks

        # PROOF: Subsequent calculations are uncontaminated by the rejected event and start fresh
        e3 = make_test_canonical_event(event_id="e6", record_id=5001, timestamp_epoch=1020.0)
        f3, _ = extractor.process_event(e3)
        q3 = extractor._entity_events.get("WORKSTATION-01|192.168.1.50", [])
        assert [r.record_id for r in q3] == [5001]

    def test_unverified_record_regression_with_older_timestamp_fails_closed(self):
        """
        AC-3.1.9.6: An unverified record-ID regression with an older timestamp (e.g. record 4900 after 5000)
        without Event 1102 also cannot establish generation continuity. It fails closed and is NOT inserted.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Baseline: record 5000 at t=1000
        extractor.process_event(make_test_canonical_event(event_id="e5000", record_id=5000, timestamp_epoch=1000.0))

        # Regressed record 4900 at t=950 (older timestamp, no Event 1102)
        e_ooo = make_test_canonical_event(event_id="e4900", record_id=4900, timestamp_epoch=950.0)
        f_ooo, can_pred = extractor.process_event(e_ooo)

        assert can_pred is False
        assert f_ooo.f5_logon_type_entropy_15m.is_available is False
        assert f_ooo.f5_logon_type_entropy_15m.reason == "UNRESOLVED_RECORD_ORDERING_ANOMALY"

        # PROOF: Record 4900 was NOT inserted into rolling history
        q = extractor._entity_events.get("WORKSTATION-01|192.168.1.50", [])
        assert 4900 not in [r.record_id for r in q]
        assert "WORKSTATION-01" not in extractor._coverage_start

    def test_late_event_timestamp_jitter_with_monotonic_records_ingested_safely(self):
        """
        Validates that timestamp jitter (t2 < t1) within monotonic record IDs (record 5001 >= 5000)
        is ingested safely into history without failing closed as a record ordering anomaly.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        extractor.process_event(make_test_canonical_event(event_id="e1", record_id=5000, timestamp_epoch=1000.0))

        # Monotonic record ID 5001 with slightly older timestamp t=995 (within retention)
        e_jitter = make_test_canonical_event(event_id="e2", record_id=5001, timestamp_epoch=995.0)
        _, can_pred = extractor.process_event(e_jitter)

        # Monotonic record ID is accepted into history; prediction is false because it's late
        assert can_pred is False
        q = extractor._entity_events.get("WORKSTATION-01|192.168.1.50", [])
        assert [r.record_id for r in q] == [5000, 5001]

    def test_event_time_dedup_recovery(self):
        """
        AC-3.1.9.7: When an in-window dedup hash is evicted, measurements remain unavailable
        until the event-time watermark advances strictly beyond t_evicted + 900s.
        """
        clock = DeterministicSimClock(current_time=3000.0)
        # Cache size 5 allows testing controlled eviction and safe recovery
        extractor = AuthenticationFeatureExtractor(clock=clock, max_dedup_cache_size=5)

        # Baseline warm-up
        extractor.process_event(make_test_canonical_event(event_id="e1", record_id=100, timestamp_epoch=100.0))
        extractor.process_event(make_test_canonical_event(event_id="e2", record_id=101, timestamp_epoch=1000.0))
        extractor.process_event(make_test_canonical_event(event_id="e3", record_id=102, timestamp_epoch=1001.0))
        extractor.process_event(make_test_canonical_event(event_id="e4", record_id=103, timestamp_epoch=1002.0))
        extractor.process_event(make_test_canonical_event(event_id="e5", record_id=104, timestamp_epoch=1003.0))

        # Adding e6 (t=1004) evicts e1 (t=100) -> safe eviction (100 < 1004 - 900 = 104)
        extractor.process_event(make_test_canonical_event(event_id="e6", record_id=105, timestamp_epoch=1004.0))

        # Adding e7 (t=1005) evicts e2 (t=1000) -> in-window eviction (1000 >= 1005 - 900 = 105)
        # Compromises dedup completeness until watermark > 1000 + 900 = 1900.0
        extractor.process_event(make_test_canonical_event(event_id="e7", record_id=106, timestamp_epoch=1005.0))

        # At t=1500 (watermark = 1500 <= 1900), measurements are UNAVAILABLE
        e_mid = make_test_canonical_event(event_id="e_mid", record_id=107, timestamp_epoch=1500.0)
        f_mid, _ = extractor.process_event(e_mid)
        assert f_mid.f5_logon_type_entropy_15m.is_available is False
        assert f_mid.f5_logon_type_entropy_15m.reason == "DEDUPLICATION_COMPLETENESS_LOST"

        # Advance watermark strictly beyond 1900s (e.g. t=1910)
        # Evicting e3 (t=1001) is safe at t=1910 because 1001 < 1910 - 900 = 1010
        e_rec = make_test_canonical_event(event_id="e_rec", record_id=108, timestamp_epoch=1910.0)
        f_rec, _ = extractor.process_event(e_rec)
        assert f_rec.f5_logon_type_entropy_15m.is_available is True

    def test_wall_clock_passage_does_not_recover_dedup(self):
        """
        AC-3.1.9.8: Wall-clock time passage does NOT recover deduplication completeness
        if the event-time watermark has not advanced.
        """
        clock = DeterministicSimClock(current_time=2000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock, max_dedup_cache_size=2)

        extractor.process_event(make_test_canonical_event(event_id="e1", record_id=100, timestamp_epoch=100.0))
        extractor.process_event(make_test_canonical_event(event_id="e2", record_id=101, timestamp_epoch=1000.0))
        extractor.process_event(make_test_canonical_event(event_id="e3", record_id=102, timestamp_epoch=1010.0))
        extractor.process_event(make_test_canonical_event(event_id="e4", record_id=103, timestamp_epoch=1020.0))

        # Advance wall clock by 10 hours, but stream watermark stays at 1200
        clock.set_time(36000.0)
        e_stalled = make_test_canonical_event(event_id="e_stalled", record_id=104, timestamp_epoch=1200.0)
        f_stalled, _ = extractor.process_event(e_stalled)

        # Measurements remain unavailable because event-time watermark <= 1900
        assert f_stalled.f5_logon_type_entropy_15m.is_available is False
        assert f_stalled.f5_logon_type_entropy_15m.reason == "DEDUPLICATION_COMPLETENESS_LOST"

    def test_f6_and_f7_shared_iana_timezone(self):
        """
        AC-3.1.9.9: f6 and f7 share the configured IANA timezone and correctly handle
        UTC vs local offsets and weekend/business hour boundaries.
        """
        # Business hours: Mon-Fri, 08:00 - 18:00 Asia/Kolkata (UTC+5:30)
        config = BusinessHoursConfig(
            iana_timezone="Asia/Kolkata",
            workdays=(0, 1, 2, 3, 4),
            work_start_hour=8,
            work_end_hour=18
        )
        clock = DeterministicSimClock(current_time=2000000000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock, business_hours_config=config)

        # 1. First event: Wednesday 2026-11-04T04:30:00Z -> Wednesday 10:00 AM IST (weekday = 2)
        dt_work = datetime(2026, 11, 4, 4, 30, 0, tzinfo=timezone.utc)
        e_work = make_test_canonical_event(event_id="e_work", record_id=100, timestamp_epoch=dt_work.timestamp())
        f_work, _ = extractor.process_event(e_work)

        assert f_work.f6_hour_of_day.is_available is True
        assert f_work.f6_hour_of_day.value == 10.0
        assert f_work.f7_is_off_hours.is_available is True
        assert f_work.f7_is_off_hours.value == 0.0  # Normal business hours

        # 2. Chronologically subsequent event: Saturday 2026-11-07T04:30:00Z -> Saturday 10:00 AM IST (weekday = 5)
        dt_sat = datetime(2026, 11, 7, 4, 30, 0, tzinfo=timezone.utc)
        e_sat = make_test_canonical_event(event_id="e_sat", record_id=101, timestamp_epoch=dt_sat.timestamp())
        f_sat, _ = extractor.process_event(e_sat)

        assert f_sat.f6_hour_of_day.is_available is True
        assert f_sat.f6_hour_of_day.value == 10.0
        assert f_sat.f7_is_off_hours.is_available is True
        assert f_sat.f7_is_off_hours.value == 1.0  # Off-hours (Saturday)

    def test_f7_unconfigured_fails_closed(self):
        """
        AC-3.1.9.10: Unconfigured business hours fail closed to UNAVAILABLE.
        """
        extractor = AuthenticationFeatureExtractor(business_hours_config=None)
        event = make_test_canonical_event(event_id="e1", timestamp_epoch=1000.0)
        features, _ = extractor.process_event(event)

        assert features.f6_hour_of_day.is_available is False
        assert features.f6_hour_of_day.reason == "UNCONFIGURED_TIMEZONE"
        assert features.f7_is_off_hours.is_available is False
        assert features.f7_is_off_hours.reason == "UNCONFIGURED_BUSINESS_HOURS"

    def test_f7_invalid_config_raises_error(self):
        """
        AC-3.1.9.11: Invalid business hours configurations raise ValueError on initialization.
        """
        with pytest.raises(ValueError, match="Invalid IANA timezone"):
            BusinessHoursConfig(iana_timezone="Invalid/Timezone_Name")

        with pytest.raises(ValueError, match="Invalid hours"):
            BusinessHoursConfig(iana_timezone="Asia/Kolkata", work_start_hour=18, work_end_hour=8)

        with pytest.raises(ValueError, match="Invalid workday index"):
            BusinessHoursConfig(iana_timezone="Asia/Kolkata", workdays=(0, 7))

    def test_logontype_quality_summary_exposure(self):
        """
        AC-3.1.9.12: LogonTypeQualitySummary exposes counts and flags degraded telemetry.
        """
        clock = DeterministicSimClock(current_time=3000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Baseline warm-up
        extractor.process_event(make_test_canonical_event(event_id="e0", record_id=1, timestamp_epoch=100.0))

        # Ingest 4 events of Type 3, 2 unknown (Type 99), and 1 missing
        extractor.process_event(make_test_canonical_event(
            event_id="e1", record_id=2, timestamp_epoch=1000.0, logon_type=3, logon_type_status=LogonTypeStatus.VALID
        ))
        extractor.process_event(make_test_canonical_event(
            event_id="e2", record_id=3, timestamp_epoch=1010.0, logon_type=3, logon_type_status=LogonTypeStatus.VALID
        ))
        extractor.process_event(make_test_canonical_event(
            event_id="e3", record_id=4, timestamp_epoch=1020.0, logon_type=99, logon_type_status=LogonTypeStatus.UNKNOWN_VALUE
        ))
        extractor.process_event(make_test_canonical_event(
            event_id="e4", record_id=5, timestamp_epoch=1030.0, logon_type=None, logon_type_status=LogonTypeStatus.MISSING
        ))

        # Evaluate at t=1040
        eval_event = make_test_canonical_event(event_id="eval", record_id=6, timestamp_epoch=1040.0)
        features, _ = extractor.process_event(eval_event)

        assert features.f5_logon_type_entropy_15m.is_available is True
        assert features.f5_logon_type_entropy_15m.value == 0.0  # Only Type 3 was valid

        q = features.logon_type_quality
        assert q is not None
        assert q.valid_count == 2
        assert q.unknown_count == 1
        assert q.missing_count == 1
        assert q.total_observed == 4
        assert q.quality_warning == "DEGRADED_LOGON_TYPE_QUALITY"

    def test_f1_to_f4_unavailable_ambiguous_role(self):
        """
        AC-3.1.9.13: f1-f4 are strictly unavailable when identity role is AMBIGUOUS.
        """
        extractor = AuthenticationFeatureExtractor()
        event = make_test_canonical_event(identity_role=IdentityRole.AMBIGUOUS)
        features, _ = extractor.process_event(event)

        assert features.f1_failed_logins_1m.is_available is False
        assert features.f1_failed_logins_1m.reason == "AMBIGUOUS_IDENTITY_ROLE"
        assert features.f2_failed_logins_5m.is_available is False
        assert features.f3_failed_logins_15m.is_available is False
        assert features.f4_unique_users_per_ip_15m.is_available is False
        assert features.f4_unique_users_per_ip_15m.reason == "AMBIGUOUS_IDENTITY_ROLE"

    def test_contract_v1_adapter_and_validations(self):
        """
        AC-3.1.9.14: Adapter converts valid 4624/4625, rejects non-auth 4688,
        and fails closed on missing identity or timezone-naive timestamps.
        """
        # Valid Contract v1 dictionary
        valid_contract = {
            "event_id": "sha-256-hash",
            "agent_id": "agent-01",
            "hostname": "WORKBENCH",
            "timestamp": "2026-11-07T08:30:00Z",
            "source_ip": "192.168.1.100",
            "username": "administrator",
            "evidence": {
                "windows_event_id": 4625,
                "record_id": 501,
                "log_name": "Security",
                "logon_type": 3
            }
        }
        res = canonical_auth_from_contract_v1(valid_contract)
        assert res is not None
        assert res.raw_record_id == 501
        assert res.source_ip == "192.168.1.100"
        assert res.source_ip_status == IPValidationStatus.VALID
        assert res.identity_role == IdentityRole.AMBIGUOUS

        # Rejects non-auth event 4688
        non_auth = dict(valid_contract)
        non_auth["evidence"] = {"windows_event_id": 4688, "record_id": 502}
        assert canonical_auth_from_contract_v1(non_auth) is None

        # Rejects missing agent_id
        missing_agent = dict(valid_contract)
        missing_agent["agent_id"] = None
        assert canonical_auth_from_contract_v1(missing_agent) is None

        # Rejects timezone-naive timestamp
        naive_ts = dict(valid_contract)
        naive_ts["timestamp"] = "2026-11-07T08:30:00"  # missing Z or offset
        assert canonical_auth_from_contract_v1(naive_ts) is None

    def test_source_ip_taxonomy_and_loopback_exclusion(self):
        """
        AC-3.1.9.15: Source IP taxonomy classifies valid, missing, malformed,
        and excludes loopback as NOT_APPLICABLE.
        """
        base_event = {
            "event_id": "hash",
            "agent_id": "agent",
            "hostname": "host",
            "timestamp": "2026-11-07T08:30:00Z",
            "evidence": {"windows_event_id": 4624, "record_id": 1, "log_name": "Security"}
        }

        # Loopback IPv4
        evt_loop4 = dict(base_event, source_ip="127.0.0.1")
        c_loop4 = canonical_auth_from_contract_v1(evt_loop4)
        assert c_loop4.source_ip is None
        assert c_loop4.source_ip_status == IPValidationStatus.NOT_APPLICABLE

        # Loopback IPv6
        evt_loop6 = dict(base_event, source_ip="::1")
        c_loop6 = canonical_auth_from_contract_v1(evt_loop6)
        assert c_loop6.source_ip is None
        assert c_loop6.source_ip_status == IPValidationStatus.NOT_APPLICABLE

        # Missing
        evt_miss = dict(base_event, source_ip="-")
        c_miss = canonical_auth_from_contract_v1(evt_miss)
        assert c_miss.source_ip is None
        assert c_miss.source_ip_status == IPValidationStatus.MISSING

        # Malformed
        evt_mal = dict(base_event, source_ip="999.999.999.999")
        c_mal = canonical_auth_from_contract_v1(evt_mal)
        assert c_mal.source_ip is None
        assert c_mal.source_ip_status == IPValidationStatus.MALFORMED

    def test_memory_limits_and_history_truncation(self):
        """
        AC-3.1.9.16: Enforces max_events_per_entity hard bound and flags HISTORY_TRUNCATED_MEMORY_LIMIT.
        """
        clock = DeterministicSimClock(current_time=3000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock, max_events_per_entity=3)

        # Baseline warm-up
        extractor.process_event(make_test_canonical_event(event_id="e0", record_id=1, timestamp_epoch=100.0))

        # Ingest 3 events for same IP
        for i in range(1, 4):
            extractor.process_event(make_test_canonical_event(
                event_id=f"e{i}", record_id=1+i, timestamp_epoch=1000.0 + i
            ))

        # Queue has 3 events (at capacity)
        assert len(extractor._entity_events["WORKSTATION-01|192.168.1.50"]) == 3

        # Ingest 4th event -> forces truncation of oldest
        extractor.process_event(make_test_canonical_event(
            event_id="e4", record_id=5, timestamp_epoch=1005.0
        ))

        # Evaluating f5 should return UNAVAILABLE with HISTORY_TRUNCATED_MEMORY_LIMIT
        eval_evt = make_test_canonical_event(event_id="eval", record_id=6, timestamp_epoch=1006.0)
        features, _ = extractor.process_event(eval_evt)

        assert features.f5_logon_type_entropy_15m.is_available is False
        assert features.f5_logon_type_entropy_15m.reason == "HISTORY_TRUNCATED_MEMORY_LIMIT"

    def test_future_clock_skew_tolerance(self):
        """
        AC-3.1.9.17: Event with timestamp exceeding clock by > tolerance raises FutureEventError.
        """
        clock = DeterministicSimClock(current_time=1000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock, future_clock_skew_tolerance_seconds=5.0)

        # 4.9s in future -> allowed
        e_ok = make_test_canonical_event(event_id="ok", timestamp_epoch=1004.9)
        extractor.process_event(e_ok)

        # 5.1s in future -> rejected
        e_future = make_test_canonical_event(event_id="future", timestamp_epoch=1005.1)
        with pytest.raises(FutureEventError, match="exceeds clock time"):
            extractor.process_event(e_future)

    def test_forward_timestamp_pre_regression_history_purged_and_cannot_contribute_after_900s(self):
        """
        Regression Test 1: Verifies that pre-regression events with forward timestamps (clock skew/jitter)
        are purged upon an unverified record-ID regression and cannot leak into feature windows after warm-up.
        """
        clock = DeterministicSimClock(current_time=100000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Pre-regression event with forward timestamp (t=2000.0, record=5000, logon_type=2)
        e1 = make_test_canonical_event(
            event_id="e1", record_id=5000, timestamp_epoch=2000.0, logon_type=2
        )
        extractor.process_event(e1)
        assert len(extractor._entity_events["WORKSTATION-01|192.168.1.50"]) == 1

        # Unverified regression: record 4500 < 5000 at t=1100.0
        e_anomaly = make_test_canonical_event(
            event_id="e_anom", record_id=4500, timestamp_epoch=1100.0, logon_type=2
        )
        f_anom, can_pred_anom = extractor.process_event(e_anomaly)
        assert can_pred_anom is False
        assert f_anom.f5_logon_type_entropy_15m.reason == "UNRESOLVED_RECORD_ORDERING_ANOMALY"

        # PROOF: Pre-regression history was purged immediately
        assert len(extractor._entity_events.get("WORKSTATION-01|192.168.1.50", [])) == 0
        assert "WORKSTATION-01" not in extractor._coverage_start
        assert "WORKSTATION-01" not in extractor._entity_watermarks

        # Post-anomaly stream starts: record 5001 at t=1105.0 with logon_type=10
        e_post1 = make_test_canonical_event(
            event_id="e_post1", record_id=5001, timestamp_epoch=1105.0, logon_type=10
        )
        f_post1, can_pred_post1 = extractor.process_event(e_post1)
        assert can_pred_post1 is True
        assert extractor._coverage_start["WORKSTATION-01"] == 1105.0
        assert extractor._entity_watermarks["WORKSTATION-01"] == 1105.0

        # Intermediate post-anomaly event: record 5002 at t=1500.0 with logon_type=10
        e_mid = make_test_canonical_event(
            event_id="e_mid", record_id=5002, timestamp_epoch=1500.0, logon_type=10
        )
        extractor.process_event(e_mid)

        # After 900s warm-up (901s after coverage start): record 5003 at t=2006.0 with logon_type=10
        # Window is [1106.0, 2006.0).
        # If e1 (t=2000.0, logon_type=2) had leaked, entropy would be > 0.0 (mixed types 2 and 10).
        e_eval = make_test_canonical_event(
            event_id="e_eval", record_id=5003, timestamp_epoch=2006.0, logon_type=10
        )
        f_eval, can_pred_eval = extractor.process_event(e_eval)

        assert can_pred_eval is True
        assert f_eval.f5_logon_type_entropy_15m.is_available is True
        # Pure single-type entropy = 0.0 (only e_mid with type 10 is in window)
        assert f_eval.f5_logon_type_entropy_15m.value == 0.0
        assert f_eval.logon_type_quality is not None
        assert f_eval.logon_type_quality.valid_count == 1
        assert f_eval.logon_type_quality.total_observed == 1

        # Explicit verification: Pre-regression record 5000 is NOT in queue
        q_final = extractor._entity_events["WORKSTATION-01|192.168.1.50"]
        assert 5000 not in [r.record_id for r in q_final]

    def test_post_anomaly_reused_dedup_hash_not_suppressed(self):
        """
        Regression Test 2: Verifies that if an event in the post-anomaly stream reuses a dedup_hash
        seen prior to the regression on that host, it is NOT discarded as a DUPLICATE_EVENT.
        """
        clock = DeterministicSimClock(current_time=100000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Pre-regression event with hash "shared-hash-01"
        e1 = make_test_canonical_event(
            event_id="e1", record_id=5000, timestamp_epoch=1000.0, dedup_hash="shared-hash-01"
        )
        extractor.process_event(e1)
        assert ("WORKSTATION-01", "shared-hash-01") in extractor._dedup_cache

        # Unverified regression
        e_anom = make_test_canonical_event(
            event_id="e_anom", record_id=4500, timestamp_epoch=1005.0, dedup_hash="anom-hash"
        )
        extractor.process_event(e_anom)

        # Post-anomaly event reuses "shared-hash-01"
        e_post = make_test_canonical_event(
            event_id="e_post", record_id=5001, timestamp_epoch=1010.0, dedup_hash="shared-hash-01"
        )
        f_post, _ = extractor.process_event(e_post)

        # PROOF: Was NOT dropped as a duplicate; enters dedup recovery / warm-up
        assert f_post.f5_logon_type_entropy_15m.reason != "DUPLICATE_EVENT"
        assert f_post.f5_logon_type_entropy_15m.reason in ("DEDUPLICATION_COMPLETENESS_LOST", "INSUFFICIENT_HISTORICAL_COVERAGE")
        assert ("WORKSTATION-01", "shared-hash-01") in extractor._dedup_cache

    def test_regression_on_one_host_does_not_clear_another_host_state(self):
        """
        Regression Test 3: Verifies scoped isolation. An unverified regression on HOST-A
        does NOT clear or invalidate history, watermarks, coverage, or dedup cache of HOST-B.
        """
        clock = DeterministicSimClock(current_time=100000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # HOST-A baseline
        eA1 = make_test_canonical_event(
            event_id="eA1", record_id=5000, timestamp_epoch=1000.0,
            destination_host="HOST-A", source_ip="192.168.1.10", dedup_hash="hash-A1"
        )
        extractor.process_event(eA1)

        # HOST-B baseline
        eB1 = make_test_canonical_event(
            event_id="eB1", record_id=2000, timestamp_epoch=1000.0,
            destination_host="HOST-B", source_ip="10.0.0.5", dedup_hash="hash-B1"
        )
        extractor.process_event(eB1)

        assert extractor._coverage_start["HOST-A"] == 1000.0
        assert extractor._coverage_start["HOST-B"] == 1000.0
        assert len(extractor._entity_events["HOST-A|192.168.1.10"]) == 1
        assert len(extractor._entity_events["HOST-B|10.0.0.5"]) == 1

        # Anomaly on HOST-A (record 4000 < 5000)
        eA_anom = make_test_canonical_event(
            event_id="eA_anom", record_id=4000, timestamp_epoch=1005.0,
            destination_host="HOST-A", source_ip="192.168.1.10", dedup_hash="hash-A-anom"
        )
        fA, _ = extractor.process_event(eA_anom)
        assert fA.f5_logon_type_entropy_15m.reason == "UNRESOLVED_RECORD_ORDERING_ANOMALY"

        # PROOF: HOST-A state is purged
        assert "HOST-A" not in extractor._coverage_start
        assert "HOST-A" not in extractor._entity_watermarks
        assert len(extractor._entity_events.get("HOST-A|192.168.1.10", [])) == 0
        assert ("HOST-A", "hash-A1") not in extractor._dedup_cache

        # PROOF: HOST-B state is COMPLETELY INTACT
        assert extractor._coverage_start["HOST-B"] == 1000.0
        assert extractor._entity_watermarks["HOST-B"] == 1000.0
        assert len(extractor._entity_events["HOST-B|10.0.0.5"]) == 1
        assert ("HOST-B", "hash-B1") in extractor._dedup_cache

        # Duplicate check on HOST-B still works properly
        eB_dup = make_test_canonical_event(
            event_id="eB_dup", record_id=2001, timestamp_epoch=1010.0,
            destination_host="HOST-B", source_ip="10.0.0.5", dedup_hash="hash-B1"
        )
        fB_dup, can_pred_dup = extractor.process_event(eB_dup)
        assert can_pred_dup is False
        assert fB_dup.f5_logon_type_entropy_15m.reason == "DUPLICATE_EVENT"

    def test_backward_timestamp_anomaly_resets_watermark_cleanly(self):
        """
        Regression Test 4: Verifies backward timestamp anomaly handling. Watermark is purged on anomaly
        so post-anomaly events with lower timestamps than pre-regression events are NOT misclassified as late.
        """
        clock = DeterministicSimClock(current_time=100000.0)
        extractor = AuthenticationFeatureExtractor(clock=clock)

        # Pre-regression event at t=2000.0, record=5000
        e1 = make_test_canonical_event(event_id="e1", record_id=5000, timestamp_epoch=2000.0)
        extractor.process_event(e1)
        assert extractor._entity_watermarks["WORKSTATION-01"] == 2000.0

        # Anomaly event at t=1100.0, record=4500
        e_anom = make_test_canonical_event(event_id="e_anom", record_id=4500, timestamp_epoch=1100.0)
        extractor.process_event(e_anom)
        assert "WORKSTATION-01" not in extractor._entity_watermarks

        # Post-anomaly event at t=1105.0, record=5001
        e_post = make_test_canonical_event(event_id="e_post", record_id=5001, timestamp_epoch=1105.0)
        _, can_pred = extractor.process_event(e_post)

        # PROOF: can_predict is True (not misclassified as late event against old 2000.0 watermark)
        assert can_pred is True
        assert extractor._entity_watermarks["WORKSTATION-01"] == 1105.0
        assert extractor._coverage_start["WORKSTATION-01"] == 1105.0
