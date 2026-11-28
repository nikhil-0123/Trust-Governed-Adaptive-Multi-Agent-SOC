"""
Deterministic validation tests for the Phase 3A Windows authentication anomaly
offline dataset and feature generation pipeline.

These fixture tests verify preprocessing mathematics, schema invariants,
identifier sanitization, manifest provenance, and leakage-free splitting.
They do NOT constitute evidence of model detection accuracy.
"""

from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys
import tempfile

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.auth_anomaly import (
    DATASET_SCHEMA_VERSION,
    FEATURE_COLUMNS,
    MODEL_INPUT_COLUMNS,
    AuthDatasetRow,
    DatasetBuildConfig,
    LabelAssignment,
    OfflineAuthFeatureExtractor,
    TelemetryOrigin,
    adapt_raw_security_event_to_contract_v1,
    assert_no_partition_leakage,
    build_auth_feature_dataset,
    chronological_split_with_embargo,
    scenario_grouped_split,
    validate_feature_row,
)
from detection.features import (  # noqa: E402
    BusinessHoursConfig,
    CanonicalAuthEvent,
    DeterministicSimClock,
    IdentityRole,
    IPValidationStatus,
    LogonTypeStatus,
    canonical_auth_from_contract_v1,
)


def _make_auth_event(
    event_id: str,
    record_id: int,
    ts_epoch: float,
    win_event_id: int = 4625,
    source_ip: str = "198.51.100.25",
    target_user: str = "alice",
    target_domain: str = "CORP",
    logon_type: int = 3,
    hostname: str = "WIN-WS-01",
    is_simulated: bool = True,
) -> dict:
    ts_iso = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "event_id": event_id,
        "timestamp": ts_iso,
        "agent_id": "agt-win-01",
        "hostname": hostname,
        "os": "Windows",
        "event_type": "windows_security_event",
        "source_ip": source_ip,
        "username": target_user,
        "severity": "low",
        "detection_type": None,
        "confidence": None,
        "evidence": {
            "windows_event_id": win_event_id,
            "record_id": record_id,
            "log_name": "Security",
            "logon_type": logon_type,
            "target_user": target_user,
            "target_domain": target_domain,
            "is_simulated": is_simulated,
        },
    }


class TestOfflineAuthFeatureExtractor:

    def test_f1_to_f7_exact_window_boundaries_and_self_exclusion(self):
        """Verify strict [t - W, t) preceding window boundaries and math for f1-f7."""
        bh = BusinessHoursConfig(iana_timezone="UTC", workdays=(0, 1, 2, 3, 4), work_start_hour=8, work_end_hour=18)
        base_t = 1_700_000_000.0  # 2023-11-14T22:13:20Z (Tuesday off-hours UTC)
        clock = DeterministicSimClock(current_time=base_t + 5000.0)
        extractor = OfflineAuthFeatureExtractor(clock=clock, business_hours_config=bh)

        # Warm-up baseline at t = base_t (900s earlier than evaluation point t_eval = base_t + 900)
        # Note: At t_eval = base_t + 900, base_t itself is at lower edge [t_eval - 900, t_eval) -> INCLUDED in 15m!
        events = [
            _make_auth_event("e0", 100, base_t, win_event_id=4624, target_user="bob", logon_type=2),
            # Within 15m [base_t, base_t+900), outside 5m (t = base_t + 500)
            _make_auth_event("e1", 101, base_t + 500.0, win_event_id=4625, target_user="alice", logon_type=3),
            # Exact left boundary of 5m window: t_eval - 300 = base_t + 600 -> INCLUDED in 5m and 15m
            _make_auth_event("e2", 102, base_t + 600.0, win_event_id=4625, target_user="charlie", logon_type=3),
            # Exact left boundary of 1m window: t_eval - 60 = base_t + 840 -> INCLUDED in 1m, 5m, 15m
            _make_auth_event("e3", 103, base_t + 840.0, win_event_id=4625, target_user="alice", logon_type=10),
            # Inside 1m window (base_t + 880)
            _make_auth_event("e4", 104, base_t + 880.0, win_event_id=4625, target_user="dave", logon_type=10),
        ]

        for ev in events:
            canon = canonical_auth_from_contract_v1(ev)
            assert canon is not None
            extractor.process_event(canon)

        # Evaluate at t_eval = base_t + 900.0 with a new 4625 for user "eve" and logon_type=8.
        # Strict self-exclusion: e_eval ("eve", failure) MUST NOT count toward f1-f5 at t_eval!
        e_eval = _make_auth_event("e_eval", 105, base_t + 900.0, win_event_id=4625, target_user="eve", logon_type=8)
        feats, can_predict = extractor.process_event(canonical_auth_from_contract_v1(e_eval))

        assert can_predict is True
        # Failures in [840, 900): e3, e4 -> 2
        assert feats.f1_failed_logins_1m.is_available is True
        assert feats.f1_failed_logins_1m.value == 2.0
        # Failures in [600, 900): e2, e3, e4 -> 3
        assert feats.f2_failed_logins_5m.is_available is True
        assert feats.f2_failed_logins_5m.value == 3.0
        # Failures in [0, 900): e1, e2, e3, e4 (e0 was 4624 success) -> 4
        assert feats.f3_failed_logins_15m.is_available is True
        assert feats.f3_failed_logins_15m.value == 4.0
        # Unique verified users across preceding auth attempts in [0, 900): bob, alice, charlie, dave -> 4 (not eve!)
        assert feats.f4_unique_users_per_ip_15m.is_available is True
        assert feats.f4_unique_users_per_ip_15m.value == 4.0

        # Logon-type entropy in [0, 900): types {2: 1, 3: 2, 10: 2} (excludes logon_type=8 of e_eval)
        expected_entropy = -(0.2 * math.log2(0.2) + 0.4 * math.log2(0.4) + 0.4 * math.log2(0.4))
        assert feats.f5_logon_type_entropy_15m.is_available is True
        assert feats.f5_logon_type_entropy_15m.value == round(expected_entropy, 6)

        # f6, f7 at 2023-11-14T22:28:20Z -> hour 22.0, off-hours 1.0
        assert feats.f6_hour_of_day.value == 22.0
        assert feats.f7_is_off_hours.value == 1.0

    def test_progressive_warmup_and_unverified_identity_suppression(self):
        """f1 opens after 60s, f2 after 300s, f3-f5 after 900s; unverified domain suppresses f1-f4."""
        bh = BusinessHoursConfig(iana_timezone="UTC")
        t0 = 1_700_000_000.0
        clock = DeterministicSimClock(current_time=t0 + 2000.0)
        extractor = OfflineAuthFeatureExtractor(clock=clock, business_hours_config=bh)

        extractor.process_event(canonical_auth_from_contract_v1(_make_auth_event("w0", 1, t0)))

        # At t0 + 60s: f1 available, f2 and f3 unavailable
        f_60, _ = extractor.process_event(canonical_auth_from_contract_v1(_make_auth_event("w1", 2, t0 + 60.0)))
        assert f_60.f1_failed_logins_1m.is_available is True
        assert f_60.f1_failed_logins_1m.value == 1.0
        assert f_60.f2_failed_logins_5m.is_available is False
        assert f_60.f2_failed_logins_5m.reason == "INSUFFICIENT_HISTORICAL_COVERAGE"
        assert f_60.f3_failed_logins_15m.is_available is False

        # At t0 + 300s: f1, f2 available, f3 unavailable
        f_300, _ = extractor.process_event(canonical_auth_from_contract_v1(_make_auth_event("w2", 3, t0 + 300.0)))
        assert f_300.f1_failed_logins_1m.is_available is True
        assert f_300.f2_failed_logins_5m.is_available is True
        assert f_300.f2_failed_logins_5m.value == 2.0
        assert f_300.f3_failed_logins_15m.is_available is False

        # At t0 + 900s with UNVERIFIED domain: f1-f4 fail closed while f5-f7 stay available
        unverified = _make_auth_event("w3", 4, t0 + 900.0, target_domain=None)
        f_900, _ = extractor.process_event(canonical_auth_from_contract_v1(unverified))
        assert f_900.f1_failed_logins_1m.is_available is False
        assert f_900.f1_failed_logins_1m.reason == "TARGET_DOMAIN_UNVERIFIED"
        assert f_900.f4_unique_users_per_ip_15m.is_available is False
        assert f_900.f5_logon_type_entropy_15m.is_available is True

    def test_adapt_raw_security_event_preserves_contract_fields(self):
        raw = {
            "record_id": 42,
            "event_id": 4625,
            "timestamp": "2026-11-27T10:00:00Z",
            "computer": "HOST-A",
            "source_ip": "10.10.1.5",
            "target_user": "jdoe",
            "target_domain": "CORP",
            "logon_type": 3,
        }
        adapted = adapt_raw_security_event_to_contract_v1(raw)
        canon = canonical_auth_from_contract_v1(adapted)
        assert canon is not None
        assert canon.event_type == "AUTHENTICATION_FAILURE"
        assert canon.target_account_id == "DOMAIN:CORP\\jdoe"
        assert canon.identity_role == IdentityRole.TARGET_USER
        assert canon.source_ip == "10.10.1.5"
        assert canon.source_ip_status == IPValidationStatus.VALID

    def test_duplicate_late_restart_log_clear_and_loopback_handling(self):
        """Verify duplicate suppression, late-event can_predict=False, Event 1102 clear restart, and loopback exclusion."""
        bh = BusinessHoursConfig(iana_timezone="UTC")
        t0 = 1_700_000_000.0
        clock = DeterministicSimClock(current_time=t0 + 5000.0)
        extractor = OfflineAuthFeatureExtractor(clock=clock, business_hours_config=bh)

        extractor.process_event(canonical_auth_from_contract_v1(_make_auth_event("r1", 10, t0)))
        extractor.process_event(canonical_auth_from_contract_v1(_make_auth_event("r2", 11, t0 + 900.0)))

        # Duplicate event_id -> unavailable, can_predict=False
        f_dup, pred_dup = extractor.process_event(canonical_auth_from_contract_v1(_make_auth_event("r2", 12, t0 + 905.0)))
        assert pred_dup is False
        assert f_dup.f1_failed_logins_1m.reason == "DUPLICATE_EVENT"

        # Loopback source_ip -> NOT_APPLICABLE for f1-f5, f6-f7 remain available
        f_loop, pred_loop = extractor.process_event(
            canonical_auth_from_contract_v1(_make_auth_event("r_loop", 13, t0 + 910.0, source_ip="127.0.0.1"))
        )
        assert pred_loop is True
        assert f_loop.f1_failed_logins_1m.is_available is False
        assert f_loop.f1_failed_logins_1m.reason == "MISSING_OR_INVALID_SOURCE_IP"
        assert f_loop.f6_hour_of_day.is_available is True

        # Late out-of-order event with monotonic record_id (ts < watermark 910) -> can_predict=False
        _, pred_late = extractor.process_event(
            canonical_auth_from_contract_v1(_make_auth_event("r_late", 14, t0 + 890.0))
        )
        assert pred_late is False

        # Authoritative Event 1102 log clear restarts warm-up
        extractor.notify_log_cleared(event_1102_timestamp_utc=t0 + 950.0)
        f_post_clear, pred_post = extractor.process_event(
            canonical_auth_from_contract_v1(_make_auth_event("r_post", 1, t0 + 960.0))
        )
        assert pred_post is True
        assert f_post_clear.f1_failed_logins_1m.is_available is False
        assert f_post_clear.f1_failed_logins_1m.reason == "INSUFFICIENT_HISTORICAL_COVERAGE"


class TestOfflineDatasetBuilderAndSplitting:

    def test_reproducible_dataset_manifest_sanitization_and_schema(self):
        """
        Verify deterministic JSONL export, cryptographic SHA-256 manifest,
        HMAC pseudonymization (no raw username/IP/hostname leakage), and
        segregation of baseline rule output from ML input columns.
        """
        t0 = 1_700_000_000.0
        fixture_events = [
            # Warm-up + normal baseline events (benign scenario)
            _make_auth_event("n0", 10, t0, 4624, "198.51.100.10", "normal_alice", "CORP", 2),
            _make_auth_event("n1", 11, t0 + 950.0, 4624, "198.51.100.10", "normal_alice", "CORP", 2),
            _make_auth_event("n_dup", 11, t0 + 950.0, 4624, "198.51.100.10", "normal_alice", "CORP", 2),  # duplicate event_id if same
            # Benign single mistyped password
            _make_auth_event("n2", 12, t0 + 1000.0, 4625, "198.51.100.10", "normal_alice", "CORP", 3),
            # Controlled attack scenario >= 1900s later (clean embargo gap >= 900s)
            _make_auth_event("a1", 20, t0 + 2000.0, 4625, "203.0.113.55", "secret_admin", "CORP", 3),
            _make_auth_event("a2", 21, t0 + 2005.0, 4625, "203.0.113.55", "secret_admin", "CORP", 3),
            _make_auth_event("a3", 22, t0 + 2010.0, 4625, "203.0.113.55", "secret_admin", "CORP", 3),
            _make_auth_event("a4", 23, t0 + 2015.0, 4625, "203.0.113.55", "secret_admin", "CORP", 3),
            _make_auth_event("a5", 24, t0 + 2020.0, 4625, "203.0.113.55", "secret_admin", "CORP", 3),
        ]
        # Force identical event_id on n_dup to test deduplication
        fixture_events[2]["event_id"] = "n1"

        labels = [
            LabelAssignment(
                scenario_id="sc_normal_01",
                label=0,
                label_source="controlled_fixture_benign",
                telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
                start_epoch=t0,
                end_epoch=t0 + 1500.0,
            ),
            LabelAssignment(
                scenario_id="sc_attack_01",
                label=1,
                label_source="controlled_fixture_bruteforce",
                telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
                start_epoch=t0 + 2000.0,
                end_epoch=t0 + 2100.0,
            ),
        ]

        cfg = DatasetBuildConfig(
            dataset_name="test_auth_fixture",
            dataset_version="1.0.0",
            business_hours=BusinessHoursConfig(iana_timezone="Asia/Kolkata"),
            pseudonymization_salt="phase3a-unit-test-salt",
            output_format="jsonl",
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_file = tmp_path / "raw_fixture.jsonl"
            with open(raw_file, "w", encoding="utf-8") as f:
                for ev in fixture_events:
                    f.write(json.dumps(ev) + "\n")

            out1 = tmp_path / "run1"
            out2 = tmp_path / "run2"

            rows1, manifest1 = build_auth_feature_dataset(
                [raw_file], labels, out1, cfg, created_at_utc_override="2026-11-27T00:00:00Z"
            )
            rows2, manifest2 = build_auth_feature_dataset(
                [raw_file], labels, out2, cfg, created_at_utc_override="2026-11-27T00:00:00Z"
            )

            assert manifest1.schema_version == DATASET_SCHEMA_VERSION
            assert manifest1.output_sha256 == manifest2.output_sha256
            assert manifest1.input_checksums == manifest2.input_checksums
            assert manifest1.duplicate_records_skipped == 1
            assert manifest1.total_rows_exported == 8
            assert manifest1.label_distribution == {"0": 3, "1": 5}

            # Verify rule metadata flagged on 5th brute-force attempt (a5) while absent from MODEL_INPUT_COLUMNS
            assert rows1[-1].baseline_rule_bruteforce_detected is True
            assert rows1[-1].f1_failed_logins_1m == 4.0  # precedes a5!
            assert "baseline_rule_bruteforce_detected" not in MODEL_INPUT_COLUMNS
            assert "label" not in MODEL_INPUT_COLUMNS

            model_vec = rows1[-1].to_model_feature_dict()
            assert tuple(model_vec.keys()) == MODEL_INPUT_COLUMNS

            # Verify sensitive raw identifiers are absent from exported dataset text
            exported_text = (out1 / manifest1.output_file).read_text(encoding="utf-8")
            for sensitive in ("normal_alice", "secret_admin", "WIN-WS-01", "198.51.100.10", "203.0.113.55"):
                assert sensitive not in exported_text

    def test_provenance_fail_closed_and_parquet_export(self):
        """Simulated fixtures cannot claim genuine_windows origin; missing labels fail closed; Parquet works."""
        t0 = 1_700_000_000.0
        ev = _make_auth_event("sim1", 1, t0, is_simulated=True)

        bad_label = LabelAssignment(
            scenario_id="sc_bad",
            label=0,
            label_source="bad_claim",
            telemetry_origin=TelemetryOrigin.GENUINE_WINDOWS.value,
            start_epoch=t0,
            end_epoch=t0 + 10.0,
        )
        cfg_parquet = DatasetBuildConfig(
            dataset_name="test_parquet",
            dataset_version="1.0.0",
            business_hours=BusinessHoursConfig(iana_timezone="UTC"),
            pseudonymization_salt="phase3a-unit-test-salt",
            output_format="parquet",
        )

        with tempfile.TemporaryDirectory() as tmp:
            raw_file = Path(tmp) / "sim.jsonl"
            raw_file.write_text(json.dumps(ev) + "\n", encoding="utf-8")

            with pytest.raises(ValueError, match="cannot be labeled as 'genuine_windows'"):
                build_auth_feature_dataset([raw_file], [bad_label], Path(tmp) / "out_bad", cfg_parquet)

            good_label = LabelAssignment(
                scenario_id="sc_sim",
                label=0,
                label_source="fixture_ok",
                telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
                start_epoch=t0,
                end_epoch=t0 + 10.0,
            )
            rows, manifest = build_auth_feature_dataset([raw_file], [good_label], Path(tmp) / "out_ok", cfg_parquet)
            assert manifest.output_format == "parquet"
            assert (Path(tmp) / "out_ok" / manifest.output_file).exists()
            assert len(rows) == 1

    def test_validate_feature_row_rejects_invariants_and_nan(self):
        base = AuthDatasetRow(
            event_id="e1",
            raw_record_id=1,
            timestamp_utc="2026-11-27T00:00:00Z",
            timestamp_epoch=1_700_000_000.0,
            host_pseudonym="host_123",
            source_ip_pseudonym="ip_123",
            account_pseudonym="acct_123",
            can_predict=True,
            telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
            scenario_id="sc1",
            label=0,
            label_source="fixture",
            baseline_rule_bruteforce_detected=False,
            windows_event_id=4625,
            is_auth_failure=1,
            logon_type=3.0,
            f1_failed_logins_1m=2.0,
            f2_failed_logins_5m=3.0,
            f3_failed_logins_15m=4.0,
            f4_unique_users_per_ip_15m=1.0,
            f5_logon_type_entropy_15m=0.0,
            f6_hour_of_day=12.0,
            f7_is_off_hours=0.0,
            f1_available=1,
            f2_available=1,
            f3_available=1,
            f4_available=1,
            f5_available=1,
            f6_available=1,
            f7_available=1,
        )
        validate_feature_row(base)

        # Invariant f1 > f2 fails
        bad_window = AuthDatasetRow(**{**base.__dict__, "f1_failed_logins_1m": 5.0})
        with pytest.raises(ValueError, match="Window invariant violated"):
            validate_feature_row(bad_window)

        # Non-finite NaN with available=1 fails
        bad_nan = AuthDatasetRow(**{**base.__dict__, "f5_logon_type_entropy_15m": float("nan")})
        with pytest.raises(ValueError, match="must be finite"):
            validate_feature_row(bad_nan)

    def test_leakage_free_chronological_and_scenario_splitting(self):
        """Chronological embargo drops boundary rows and enforces >= 900s temporal separation."""
        rows = []
        base_t = 1_700_000_000.0
        for i in range(10):
            t = base_t + i * 600.0  # spaced every 600s over 5400s
            rows.append(
                AuthDatasetRow(
                    event_id=f"ev-{i}",
                    raw_record_id=i + 1,
                    timestamp_utc="2026-11-27T00:00:00Z",
                    timestamp_epoch=t,
                    host_pseudonym="host_1",
                    source_ip_pseudonym="ip_1",
                    account_pseudonym="acct_1",
                    can_predict=True,
                    telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
                    scenario_id=f"sc-{i // 3}",
                    label=0,
                    label_source="fixture",
                    baseline_rule_bruteforce_detected=False,
                    windows_event_id=4624,
                    is_auth_failure=0,
                    logon_type=3.0,
                    f1_failed_logins_1m=0.0,
                    f2_failed_logins_5m=0.0,
                    f3_failed_logins_15m=0.0,
                    f4_unique_users_per_ip_15m=1.0,
                    f5_logon_type_entropy_15m=0.0,
                    f6_hour_of_day=10.0,
                    f7_is_off_hours=0.0,
                    f1_available=1,
                    f2_available=1,
                    f3_available=1,
                    f4_available=1,
                    f5_available=1,
                    f6_available=1,
                    f7_available=1,
                )
            )

        splits = chronological_split_with_embargo(rows, train_ratio=0.5, val_ratio=0.25, embargo_seconds=900.0)
        assert len(splits["embargo_dropped"]) >= 2
        assert_no_partition_leakage(
            splits,
            require_disjoint_scenarios=False,
            min_chronological_embargo_seconds=900.0,
        )

        # Scenario-grouped assignment catches shared scenarios
        sc_splits = scenario_grouped_split(
            rows,
            {"sc-0": "train", "sc-1": "train", "sc-2": "val", "sc-3": "test"},
        )
        assert_no_partition_leakage(sc_splits, require_disjoint_scenarios=True)

        # Inject duplicate row across splits and verify detector catches leakage
        sc_splits["test"].append(sc_splits["train"][0])
        with pytest.raises(AssertionError, match="Data leakage"):
            assert_no_partition_leakage(sc_splits)
