"""
Phase 3B tests for safe read-only Security collector, independent scenario
manifest ground truth, F1-F7 edge-case semantics, privacy guarantees, and
combined chronological/scenario partition leakage checks.

These fixture tests verify preprocessing/collection mechanics and do NOT claim
model generalization or fabricated telemetry results.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.auth_anomaly import (
    MODEL_INPUT_COLUMNS,
    CollectorIsolationError,
    CoverageStatus,
    DatasetBuildConfig,
    DiscontinuityError,
    LabelAssignment,
    OfflineAuthFeatureExtractor,
    OfflineSecurityAuthCollector,
    ScenarioFamily,
    TelemetryOrigin,
    analyze_dataset_statistics,
    assert_no_partition_leakage,
    build_auth_feature_dataset,
    combined_chronological_scenario_split,
    create_pseudonymized_scenario,
    load_scenario_manifest,
    save_scenario_manifest,
    scenario_manifest_to_label_assignments,
)
from detection.features import (  # noqa: E402
    BusinessHoursConfig,
    DeterministicSimClock,
    canonical_auth_from_contract_v1,
)


def _security_xml(
    event_id: int,
    record_id: int,
    ts_iso: str,
    target_user: str = "test_user",
    target_domain: str = "LAB",
    logon_type: int = 3,
    ip_addr: str = "198.51.100.10",
) -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        f"<EventID>{event_id}</EventID>"
        f"<TimeCreated SystemTime='{ts_iso}'/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        "<Channel>Security</Channel>"
        "<Computer>LAB-ENDPOINT-01</Computer>"
        "</System>"
        "<EventData>"
        f"<Data Name='TargetUserName'>{target_user}</Data>"
        f"<Data Name='TargetDomainName'>{target_domain}</Data>"
        f"<Data Name='LogonType'>{logon_type}</Data>"
        f"<Data Name='IpAddress'>{ip_addr}</Data>"
        "<Data Name='SecretTokenShouldNotBeKept'>TOP_SECRET_VALUE</Data>"
        "</EventData>"
        "</Event>"
    )


class TestSafeOfflineSecurityCollector:

    def test_isolation_guard_rejects_production_paths_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            # Refuse directory containing outbox.db / agent_identity.json / soc_central.db
            prod_dir = base / "prod_overlap"
            prod_dir.mkdir()
            (prod_dir / "outbox.db").write_text("", encoding="utf-8")

            with pytest.raises(CollectorIsolationError, match="outbox.db"):
                OfflineSecurityAuthCollector(state_dir=prod_dir, output_dir=base / "out")

            # Refuse windows-telemetry source directory
            with pytest.raises(CollectorIsolationError):
                OfflineSecurityAuthCollector(
                    state_dir=_REPO_ROOT / "windows-telemetry" / "tmp_state",
                    output_dir=base / "out",
                )

            # Refuse invalid batch size
            with pytest.raises(ValueError, match="batch_size"):
                OfflineSecurityAuthCollector(state_dir=base / "st", output_dir=base / "out", batch_size=0)

    def test_incremental_collection_dedup_overwrite_gap_and_log_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state_dir = base / "ml_state"
            out_dir = base / "ml_out"

            stage = {"step": 1}

            def fake_runner(args, capture_output=True, timeout=30.0):
                cmd = " ".join(args)
                if args[:2] == ["wevtutil", "gl"]:
                    out = "name: Security\nenabled: true\nretention: false\nmaxSize: 20971520\n"
                    return subprocess.CompletedProcess(args, 0, out.encode("utf-8"), b"")
                if args[0] == "auditpol":
                    out = "Logon/Logoff\n  Logon                                   Success and Failure\n"
                    return subprocess.CompletedProcess(args, 0, out.encode("utf-8"), b"")
                if "/c:1" in args and "/rd:true" not in args:
                    rec = 100 if stage["step"] == 1 else (105 if stage["step"] == 2 else 1)
                    xml = _security_xml(4624, rec, "2026-11-27T08:00:00Z")
                    return subprocess.CompletedProcess(args, 0, xml.encode("utf-8"), b"")
                if "/c:1" in args and "/rd:true" in args:
                    rec = 101 if stage["step"] == 1 else (110 if stage["step"] == 2 else 2)
                    xml = _security_xml(4625, rec, "2026-11-27T08:10:00Z")
                    return subprocess.CompletedProcess(args, 0, xml.encode("utf-8"), b"")
                if "EventID=1102" in cmd:
                    if stage["step"] == 3:
                        xml = _security_xml(1102, 1, "2026-11-27T08:20:00Z")
                    else:
                        xml = ""
                    return subprocess.CompletedProcess(args, 0, xml.encode("utf-8"), b"")
                if "EventRecordID >" in cmd:
                    if stage["step"] == 1:
                        xml = (
                            _security_xml(4624, 100, "2026-11-27T08:00:00Z")
                            + _security_xml(4625, 101, "2026-11-27T08:01:00Z")
                        )
                    elif stage["step"] == 2:
                        # Includes already-seen 101 (to verify dedup) and 110 after gap 101->105
                        xml = (
                            _security_xml(4625, 101, "2026-11-27T08:01:00Z")
                            + _security_xml(4624, 110, "2026-11-27T08:10:00Z")
                        )
                    else:
                        xml = _security_xml(4624, 2, "2026-11-27T08:21:00Z")
                    return subprocess.CompletedProcess(args, 0, xml.encode("utf-8"), b"")
                raise AssertionError(f"Unexpected command: {args}")

            collector = OfflineSecurityAuthCollector(state_dir, out_dir, batch_size=50, runner=fake_runner)
            s1 = collector.collect_incremental("run1", output_filename="capture.jsonl")
            assert s1.events_written == 2
            assert s1.end_checkpoint_record_id == 101
            assert s1.channel_epoch == 1
            assert s1.gap_detected is False
            # Confirm unwhitelisted field was NOT stored
            text1 = Path(s1.output_jsonl_path).read_text(encoding="utf-8")
            assert "TOP_SECRET_VALUE" not in text1
            assert "<Event" not in text1

            # Step 2: circular overwrite gap (earliest 105 > checkpoint 101 + 1) + duplicate record 101
            stage["step"] = 2
            s2 = collector.collect_incremental("run2", output_filename="capture.jsonl")
            assert s2.gap_detected is True
            assert s2.gap_details[0]["gap_type"] == "UNRECOVERABLE_OVERWRITE_GAP"
            assert s2.duplicates_skipped == 1
            assert s2.events_written == 1
            assert s2.end_checkpoint_record_id == 110

            # Step 3: Event 1102 log clear advances epoch 1 -> 2
            stage["step"] = 3
            s3 = collector.collect_incremental("run3", output_filename="capture.jsonl")
            assert s3.channel_epoch == 2
            assert s3.gap_detected is True
            assert s3.gap_details[0]["gap_type"] == "LOG_CLEARED_1102"
            assert s3.events_written == 1

            # Step 4: Regression without 1102 fails closed
            def corrupt_runner(args, capture_output=True, timeout=30.0):
                if "EventID=1102" in " ".join(args):
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                if "/c:1" in args and "/rd:true" in args:
                    return subprocess.CompletedProcess(args, 0, _security_xml(4624, 1, "2026-11-27T09:00:00Z").encode("utf-8"), b"")
                return fake_runner(args, capture_output=capture_output, timeout=timeout)

            bad_collector = OfflineSecurityAuthCollector(state_dir, out_dir, runner=corrupt_runner)
            with pytest.raises(DiscontinuityError, match="without Event 1102"):
                bad_collector.collect_incremental("run4")


class TestIndependentGroundTruthScenarios:

    def test_scenario_manifest_rejects_circular_justification_and_overlaps(self):
        salt = "phase3b-salt-987654"
        with pytest.raises(ValueError, match="Circular labeling prohibited"):
            create_pseudonymized_scenario(
                scenario_id="sc_circ",
                scenario_family=ScenarioFamily.CONTROLLED_BRUTE_FORCE,
                authorized_endpoint_id="lab-win-01",
                raw_source_ip="203.0.113.45",
                pseudonymization_salt=salt,
                start_timestamp_utc="2026-11-27T10:00:00Z",
                end_timestamp_utc="2026-11-27T10:05:00Z",
                ground_truth_label=1,
                label_justification="Labeled because windows_bruteforce_rule triggered high alert",
                telemetry_origin=TelemetryOrigin.AUTHORIZED_CONTROLLED_TEST,
                collection_coverage_status=CoverageStatus.CONTINUOUS_COMPLETE,
                expected_event_category="4625_burst",
            )

        benign = create_pseudonymized_scenario(
            scenario_id="sc_benign_1",
            scenario_family=ScenarioFamily.BENIGN_NORMAL_LOGON,
            authorized_endpoint_id="lab-win-01",
            raw_source_ip="198.51.100.10",
            pseudonymization_salt=salt,
            start_timestamp_utc="2026-11-27T10:00:00Z",
            end_timestamp_utc="2026-11-27T10:20:00Z",
            ground_truth_label=0,
            label_justification="Verified normal shift logon sequence from workstation test operator log",
            telemetry_origin=TelemetryOrigin.GENUINE_WINDOWS,
            collection_coverage_status=CoverageStatus.CONTINUOUS_COMPLETE,
            expected_event_category="4624_workstation_logon",
        )
        conflicting_attack = create_pseudonymized_scenario(
            scenario_id="sc_attack_overlap",
            scenario_family=ScenarioFamily.CONTROLLED_PASSWORD_SPRAY,
            authorized_endpoint_id="lab-win-01",
            raw_source_ip="198.51.100.10",
            pseudonymization_salt=salt,
            start_timestamp_utc="2026-11-27T10:10:00Z",
            end_timestamp_utc="2026-11-27T10:15:00Z",
            ground_truth_label=1,
            label_justification="Controlled spray script run documented in lab notebook",
            telemetry_origin=TelemetryOrigin.AUTHORIZED_CONTROLLED_TEST,
            collection_coverage_status=CoverageStatus.CONTINUOUS_COMPLETE,
            expected_event_category="4625_spray",
        )
        ambiguous = create_pseudonymized_scenario(
            scenario_id="sc_ambig",
            scenario_family=ScenarioFamily.AMBIGUOUS_UNLABELED,
            authorized_endpoint_id="lab-win-02",
            raw_source_ip=None,
            pseudonymization_salt=salt,
            start_timestamp_utc="2026-11-27T11:00:00Z",
            end_timestamp_utc="2026-11-27T11:10:00Z",
            ground_truth_label=None,
            label_justification="Unverified overlapping maintenance window excluded from supervised training",
            telemetry_origin=TelemetryOrigin.GENUINE_WINDOWS,
            collection_coverage_status=CoverageStatus.PARTIAL_OVERWRITE,
            expected_event_category="unknown",
        )

        with tempfile.TemporaryDirectory() as tmp:
            mpath = Path(tmp) / "manifest.json"
            with pytest.raises(ValueError, match="Conflicting overlapping scenarios"):
                save_scenario_manifest([benign, conflicting_attack], mpath)

            save_scenario_manifest([benign, ambiguous], mpath)
            raw_txt = mpath.read_text(encoding="utf-8")
            assert "198.51.100.10" not in raw_txt
            loaded = load_scenario_manifest(mpath)
            assignments = scenario_manifest_to_label_assignments(loaded)
            # Ambiguous scenario is safely excluded
            assert len(assignments) == 1
            assert assignments[0].scenario_id == "sc_benign_1"
            assert assignments[0].source_ip_pseudonym == benign.source_ip_pseudonym


class TestPhase3BF7EdgeCasesPrivacyAndSplitting:

    def _raw_record(self, rec_id: int, eid: int, ts_epoch: float, user: str = "u1", ip: str = "198.51.100.20", host: str = "H1", seq: int = None):
        ts_iso = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        d = {
            "event_id": eid,
            "record_id": rec_id,
            "timestamp": ts_iso,
            "computer": host,
            "source_ip": ip,
            "target_user": user,
            "target_domain": "LAB",
            "logon_type": 3,
            "channel_epoch": 1,
            "telemetry_origin": TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
            "is_simulated": True,
        }
        if seq is not None:
            d["collection_seq"] = seq
        return d

    def test_identical_timestamps_multi_file_duplicates_and_causal_jitter_order(self):
        t0 = 1_700_000_000.0
        # Establish 900s clean coverage (r9 at t0 starts coverage; r10 at t0+50 stays inside 900s at t0+910),
        # then emit two events with IDENTICAL timestamp t0 + 910,
        # plus one backward clock-jitter event (seq=5, rec=13, t=t0+905) after (seq=4, rec=12, t=t0+910).
        file1_recs = [
            self._raw_record(9, 4624, t0, user="expired_warmup", seq=1),
            self._raw_record(10, 4624, t0 + 50.0, user="warmup_user", seq=2),
            self._raw_record(11, 4625, t0 + 910.0, user="u_a", seq=3),
            self._raw_record(12, 4625, t0 + 910.0, user="u_b", seq=4),
            self._raw_record(13, 4625, t0 + 905.0, user="u_late", seq=5),
        ]
        # File 2 repeats record 11 (cross-file duplicate) and adds record 14 after recovery
        file2_recs = [
            self._raw_record(11, 4625, t0 + 910.0, user="u_a", seq=3),
            self._raw_record(14, 4625, t0 + 920.0, user="u_c", seq=6),
        ]

        labels = [
            LabelAssignment(
                scenario_id="sc_edge",
                label=0,
                label_source="edge_case_fixture",
                telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
                start_epoch=t0,
                end_epoch=t0 + 1000.0,
            )
        ]
        cfg = DatasetBuildConfig(
            dataset_name="edge_cases",
            dataset_version="1.0.0",
            business_hours=BusinessHoursConfig(iana_timezone="Asia/Kolkata"),
            pseudonymization_salt="phase3b-salt-987654",
            replay_order="auto",
        )

        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "f1.jsonl"
            p2 = Path(tmp) / "f2.jsonl"
            p1.write_text("\n".join(json.dumps(x) for x in file1_recs) + "\n", encoding="utf-8")
            p2.write_text("\n".join(json.dumps(x) for x in file2_recs) + "\n", encoding="utf-8")

            rows, manifest = build_auth_feature_dataset([p1, p2], labels, Path(tmp) / "out", cfg)
            # rec 9, rec 10, rec 11 (first copy), rec 12 (identical ts), rec 14 survive;
            # duplicate rec 11 skipped, backward-jitter late rec 13 excluded (can_predict=False)
            assert manifest.duplicate_records_skipped == 1
            assert manifest.excluded_late_or_invalid_rows == 2
            assert len(rows) == 5

            # Verify identical-timestamp r11 & r12 do NOT count each other:
            # r9 (expired at t0 < t0+10) excluded; r10 at t0+50 included -> both see failure count = 0 and f4 = 1.0
            by_rec = {r.raw_record_id: r for r in rows}
            assert by_rec[11].f1_failed_logins_1m == 0.0
            assert by_rec[11].f1_available == 1  # genuine 0.0 distinguishable from None!
            assert by_rec[12].f1_failed_logins_1m == 0.0
            assert by_rec[12].f4_unique_users_per_ip_15m == 1.0

            # r14 at t0+920 sees r10 (warmup_user), r11 (u_a), r12 (u_b), AND r13 (u_late) -> f4=4.0, f1=3.0 failures
            assert by_rec[14].f1_failed_logins_1m == 3.0
            assert by_rec[14].f4_unique_users_per_ip_15m == 4.0  # counts 4624 + 4625 attempted verified accounts

            # Confirm MODEL_INPUT_COLUMNS includes context event_id & logon_type but excludes identifiers/labels
            assert "windows_event_id" in MODEL_INPUT_COLUMNS
            assert "logon_type" in MODEL_INPUT_COLUMNS
            assert "host_pseudonym" not in MODEL_INPUT_COLUMNS

            # Check statistics helper
            stats = analyze_dataset_statistics(rows)
            assert stats["scenario_counts"]["sc_edge"] == 5
            assert stats["class_distributions"]["0"]["count"] == 5

            # Strict privacy inspection on exported JSONL & manifest (no raw hostnames, usernames, or IPs in event_id/rows)
            exported_text = (Path(tmp) / "out" / manifest.output_file).read_text(encoding="utf-8")
            manifest_text = (Path(tmp) / "out" / f"{cfg.dataset_name}_v{cfg.dataset_version}.manifest.json").read_text(encoding="utf-8")
            for forbidden in ("198.51.100.20", "warmup_user", "expired_warmup", "u_a", "u_b", "u_c", "|H1|"):
                assert forbidden not in exported_text
                assert forbidden not in manifest_text
            assert len(by_rec[11].event_id) == 64  # SHA-256 hex digest, never plaintext host|rec

    def test_gap_prevents_coverage_inference_even_across_900s(self):
        """Even if t2 - t1 >= 900s, an unrecoverable overwrite gap invalidates F1-F5."""
        t0 = 1_700_000_000.0
        recs = [
            self._raw_record(100, 4624, t0, seq=1),
            self._raw_record(500, 4625, t0 + 1000.0, seq=2),
        ]
        labels = [
            LabelAssignment(
                scenario_id="sc_gap",
                label=0,
                label_source="gap_fixture",
                telemetry_origin=TelemetryOrigin.SIMULATED_TEST_FIXTURE.value,
                start_epoch=t0,
                end_epoch=t0 + 1100.0,
            )
        ]
        cfg = DatasetBuildConfig(
            dataset_name="gap_test",
            dataset_version="1.0.0",
            business_hours=BusinessHoursConfig(iana_timezone="UTC"),
            pseudonymization_salt="phase3b-salt-987654",
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "raw.jsonl"
            p.write_text("\n".join(json.dumps(x) for x in recs) + "\n", encoding="utf-8")
            rows, manifest = build_auth_feature_dataset(
                [p],
                labels,
                Path(tmp) / "out",
                cfg,
                unrecoverable_gaps=[(t0 + 200.0, t0 + 600.0, "UNRECOVERABLE_OVERWRITE_GAP")],
            )
            r_last = rows[-1]
            # Coverage was broken by gap at [200, 600], so 1m and 15m rolling features fail closed!
            assert r_last.f1_available == 0
            assert r_last.f1_failed_logins_1m is None
            assert r_last.f5_available == 0
            assert r_last.unavailable_reasons["f1_failed_logins_1m"] == "INSUFFICIENT_HISTORICAL_COVERAGE"
            # While point-in-time F6/F7 timezone features remain available
            assert r_last.f6_available == 1

    def test_combined_chronological_scenario_split_sufficiency_and_embargo(self):
        t0 = 1_700_000_000.0
        recs = [
            self._raw_record(1, 4624, t0, seq=1),
            self._raw_record(2, 4624, t0 + 2000.0, seq=2),
            self._raw_record(3, 4625, t0 + 4000.0, seq=3),
            self._raw_record(4, 4625, t0 + 6000.0, seq=4),
        ]
        labels = [
            LabelAssignment("sc_1", 0, "l1", TelemetryOrigin.SIMULATED_TEST_FIXTURE.value, t0, t0 + 100.0),
            LabelAssignment("sc_2", 0, "l2", TelemetryOrigin.SIMULATED_TEST_FIXTURE.value, t0 + 1900.0, t0 + 2100.0),
            LabelAssignment("sc_3", 1, "l3", TelemetryOrigin.SIMULATED_TEST_FIXTURE.value, t0 + 3900.0, t0 + 4100.0),
            LabelAssignment("sc_4", 1, "l4", TelemetryOrigin.SIMULATED_TEST_FIXTURE.value, t0 + 5900.0, t0 + 6100.0),
        ]
        cfg = DatasetBuildConfig(
            dataset_name="split_test",
            dataset_version="1.0.0",
            business_hours=BusinessHoursConfig(iana_timezone="UTC"),
            pseudonymization_salt="phase3b-salt-987654",
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "raw.jsonl"
            p.write_text("\n".join(json.dumps(x) for x in recs) + "\n", encoding="utf-8")
            rows, _ = build_auth_feature_dataset([p], labels, Path(tmp) / "out", cfg)

            res_3way = combined_chronological_scenario_split(rows, train_ratio=0.5, val_ratio=0.25, embargo_seconds=900.0)
            assert res_3way["sufficient_for_3way_split"] is True
            assert_no_partition_leakage(res_3way, require_disjoint_scenarios=True, min_chronological_embargo_seconds=900.0)

            # Pilot too small (< 3 scenarios) refuses to force a broken 3-way split
            res_small = combined_chronological_scenario_split(rows[:2], embargo_seconds=900.0)
            assert res_small["sufficient_for_3way_split"] is False

    def test_expired_late_event_host_isolation_and_ist_midnight_boundary(self):
        """Verify expired late events (>900s behind watermark), per-host isolation, and IST midnight cutoff."""
        bh = BusinessHoursConfig(iana_timezone="Asia/Kolkata", workdays=(0, 1, 2, 3, 4), work_start_hour=8, work_end_hour=18)
        # Friday 2026-11-27T04:00:00Z = Friday 09:30 IST (business hours -> f7=0.0)
        t_fri_biz = datetime(2026, 11, 27, 4, 0, 0, tzinfo=timezone.utc).timestamp()
        # Friday 2026-11-27T18:30:00Z = Saturday 00:00 IST (weekend midnight -> f6=0.0, f7=1.0)
        t_sat_mid = datetime(2026, 11, 27, 18, 30, 0, tzinfo=timezone.utc).timestamp()

        clock = DeterministicSimClock(current_time=t_sat_mid + 5000.0)
        ext = OfflineAuthFeatureExtractor(clock=clock, business_hours_config=bh)

        ev_fri = canonical_auth_from_contract_v1({
            "event_id": "fri-1", "timestamp": "2026-11-27T04:00:00Z", "agent_id": "agt", "hostname": "HOST-A",
            "os": "Windows", "source_ip": "198.51.100.5", "username": "u1",
            "evidence": {"windows_event_id": 4624, "record_id": 100, "log_name": "Security", "target_user": "u1", "target_domain": "LAB", "logon_type": 3},
        })
        f_fri, pred_fri = ext.process_event(ev_fri)
        assert pred_fri is True
        assert f_fri.f6_hour_of_day.value == 9.0
        assert f_fri.f7_is_off_hours.value == 0.0

        # Host-B establishes baseline cleanly before Host-A anomaly
        ev_b = canonical_auth_from_contract_v1({
            "event_id": "hb-1", "timestamp": "2026-11-27T18:30:00Z", "agent_id": "agt", "hostname": "HOST-B",
            "os": "Windows", "source_ip": "198.51.100.6", "username": "u2",
            "evidence": {"windows_event_id": 4624, "record_id": 10, "log_name": "Security", "target_user": "u2", "target_domain": "LAB", "logon_type": 3},
        })
        f_b, _ = ext.process_event(ev_b)
        assert f_b.f6_hour_of_day.value == 0.0
        assert f_b.f7_is_off_hours.value == 1.0

        # Host-A experiences unverified record-ID regression -> Host-B coverage unaffected
        ev_a_reg = canonical_auth_from_contract_v1({
            "event_id": "ha-reg", "timestamp": "2026-11-27T18:35:00Z", "agent_id": "agt", "hostname": "HOST-A",
            "os": "Windows", "source_ip": "198.51.100.5", "username": "u1",
            "evidence": {"windows_event_id": 4625, "record_id": 50, "log_name": "Security", "target_user": "u1", "target_domain": "LAB", "logon_type": 3},
        })
        _, pred_reg = ext.process_event(ev_a_reg)
        assert pred_reg is False
        assert "HOST-B" in ext._coverage_start
        assert "HOST-A" not in ext._coverage_start

        # Expired late event on Host-B (> 900s behind Host-B watermark t_sat_mid)
        ev_b_exp = canonical_auth_from_contract_v1({
            "event_id": "hb-exp", "timestamp": "2026-11-27T17:00:00Z", "agent_id": "agt", "hostname": "HOST-B",
            "os": "Windows", "source_ip": "198.51.100.6", "username": "u2",
            "evidence": {"windows_event_id": 4625, "record_id": 11, "log_name": "Security", "target_user": "u2", "target_domain": "LAB", "logon_type": 3},
        })
        f_exp, pred_exp = ext.process_event(ev_b_exp)
        assert pred_exp is False
        assert f_exp.f1_failed_logins_1m.reason == "EXPIRED_LATE_EVENT"
