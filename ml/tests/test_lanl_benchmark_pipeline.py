"""
Deterministic Regression Tests for Research-Only LANL Benchmark (`lanl_auth_features_v1`)
and Passive OTRF Schema Adapter (`otrf_mordor_audit_v1`).

Uses explicitly synthetic unit fixtures ONLY — never reported as authentic dataset metrics.
"""

from __future__ import annotations

import gzip
import json
import math
from pathlib import Path
import zipfile

import pytest

from ml.auth_anomaly.schema import DATASET_SCHEMA_VERSION
from ml.lanl_benchmark.features import LanlCausalFeatureExtractor
from ml.lanl_benchmark.labels import MatchStatus, RedteamAnnotationIndex
from ml.lanl_benchmark.parser import iter_lanl_auth_gz, iter_lanl_auth_lines, load_redteam_annotations_lines
from ml.lanl_benchmark.pipeline import (
    LanlBlockSpec,
    LanlBuildConfig,
    audit_lanl_partition_hygiene,
    build_lanl_benchmark_dataset,
    build_lanl_block_parquet_dataset,
    lanl_chronological_split_with_embargo,
)
from ml.lanl_benchmark.schema import (
    LANL_MODEL_INPUT_COLUMNS,
    LANL_SCHEMA_VERSION,
    LanlRawAuthEvent,
    get_lanl_pyarrow_schema,
    normalize_lanl_auth_type_family,
    validate_lanl_feature_row,
)
from ml.public_datasets.otrf_adapter import (
    OTRF_SCHEMA_VERSION,
    parse_otrf_auth_event,
    summarize_otrf_auth_capture,
)


def _write_gz(path: Path, lines: list[str]) -> Path:
    with gzip.open(path, "wt", encoding="utf-8", newline="\n") as f:
        for ln in lines:
            f.write(ln + "\n")
    return path


def test_lanl_schema_strictly_isolated_from_native_windows_schema():
    assert LANL_SCHEMA_VERSION == "lanl_auth_features_v1"
    assert DATASET_SCHEMA_VERSION == "auth_anomaly_features_v1"
    assert LANL_SCHEMA_VERSION != DATASET_SCHEMA_VERSION

    forbidden_cols = {
        "label",
        "label_source",
        "match_status",
        "source_computer",
        "destination_computer",
        "source_user",
        "destination_user",
        "record_seq",
        "windows_event_id",
        "source_ip_pseudonym",
    }
    assert not (forbidden_cols & set(LANL_MODEL_INPUT_COLUMNS))


def test_streaming_gz_parser_preserves_question_marks_without_fabrication(tmp_path: Path):
    auth_lines = [
        "10,U1@DOM1,U1@DOM1,C100,C200,Kerberos,Network,LogOn,Success",
        "12,?,U2@DOM1,?,C200,?, ?,TGS,Fail",
        "bad,line,only,4,cols",
        "0,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOn,Success",  # invalid time_rel < 1
        "15,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOn,UnknownOutcome",
    ]
    gz_path = _write_gz(tmp_path / "auth_sample.txt.gz", auth_lines)

    stats = {}
    parsed = list(iter_lanl_auth_gz(gz_path, stats=stats))
    assert len(parsed) == 2
    assert stats["lines_read"] == 5
    assert stats["valid_events"] == 2
    assert stats["malformed_lines"] == 3

    first, second = parsed
    assert first.time_rel == 10
    assert first.source_computer == "C100"
    assert first.outcome == "Success"

    assert second.time_rel == 12
    assert second.source_user is None
    assert second.source_computer is None
    assert second.auth_type is None
    assert second.logon_type is None
    assert second.outcome == "Fail"
    assert not hasattr(second, "event_id")
    assert not hasattr(second, "source_ip")


def test_redteam_exact_join_duplicates_and_ambiguity_audit():
    rt_lines = [
        "1000,U9@DOM1,C_ATK,C_VICTIM",
        "1000,U9@DOM1,C_ATK,C_VICTIM",  # duplicate annotation
        "2000,U8@DOM1,C_ATK,C_SRV",
        "9999,U7@DOM1,C_GONE,C_NONE",  # unmatched annotation
    ]
    annotations, malformed = load_redteam_annotations_lines(rt_lines + ["bad_row"])
    assert malformed == 1
    assert len(annotations) == 4

    idx = RedteamAnnotationIndex(annotations)
    assert idx.total_annotations == 4
    assert idx.unique_annotation_keys == 3
    assert idx.duplicate_annotation_count == 1

    ev_dup_ann = LanlRawAuthEvent(1, 1000, "U9@DOM1", "U9@DOM1", "C_ATK", "C_VICTIM", "Kerberos", "Network", "LogOn", "Success", "h1")
    r1 = idx.match_event(ev_dup_ann, precomputed_key_hits=1)
    assert r1.label == 1
    assert r1.status == MatchStatus.AMBIGUOUS_MULTI_MATCH.value
    assert r1.annotation_duplicate_count == 1
    assert r1.is_ambiguous is True

    ev_unique = LanlRawAuthEvent(2, 2000, "U8@DOM1", "U8@DOM1", "C_ATK", "C_SRV", "NTLM", "Network", "LogOn", "Success", "h2")
    r2 = idx.match_event(ev_unique, precomputed_key_hits=1)
    assert r2.label == 1
    assert r2.status == MatchStatus.EXACT_UNIQUE_MATCH.value
    assert r2.annotation_duplicate_count == 0
    assert r2.is_ambiguous is False

    ev_multi_hit = LanlRawAuthEvent(3, 2000, "U8@DOM1", "U8@DOM1", "C_ATK", "C_SRV", "NTLM", "Network", "LogOn", "Fail", "h3")
    r3 = idx.match_event(ev_multi_hit, precomputed_key_hits=2)
    assert r3.label == 1
    assert r3.status == MatchStatus.AMBIGUOUS_MULTI_MATCH.value
    assert r3.match_multiplicity == 2
    assert r3.is_ambiguous is True

    ev_bg = LanlRawAuthEvent(4, 2005, "U1@DOM1", "U1@DOM1", "C1", "C2", "Kerberos", "Network", "LogOn", "Success", "h4")
    r4 = idx.match_event(ev_bg)
    assert r4.label == 0
    assert r4.status == MatchStatus.UNMATCHED_NON_REDTEAM.value
    assert r4.label_source == "unmatched_background_not_in_redteam"
    assert len(idx.unmatched_annotation_keys) == 1


def test_causal_feature_extraction_and_future_perturbation_invariance():
    base_events = [
        LanlRawAuthEvent(1, 100, "U1@D", "U1@D", "C_SRC", "C_DST1", "NTLM", "Network", "LogOn", "Fail", "ha"),
        LanlRawAuthEvent(2, 120, "U2@D", "U2@D", "C_SRC", "C_DST1", "NTLM", "Interactive", "LogOn", "Fail", "hb"),
        LanlRawAuthEvent(3, 180, "U1@D", "U1@D", "C_SRC", "C_DST1", "Kerberos", "Network", "LogOn", "Success", "hc"),
        LanlRawAuthEvent(4, 240, "U1@D", "U1@D", "C_SRC", "C_DST2", "Kerberos", "Network", "LogOn", "Success", "hc2"),
        LanlRawAuthEvent(5, 1020, "U3@D", "U3@D", "C_SRC", "C_DST1", "Kerberos", "Service", "LogOn", "Success", "hd"),
        LanlRawAuthEvent(6, 1020, "U4@D", "U4@D", "C_SRC", "C_DST1", "Kerberos", "Service", "LogOn", "Fail", "he"),
    ]

    ext_a = LanlCausalFeatureExtractor(retention_seconds=900)
    feats_a = [ext_a.process_event(ev) for ev in base_events]

    # Warmup gates: t=100 (elapsed=0) has 0 availability for rolling windows
    assert feats_a[0].lanl_fail_1m_available == 0
    assert feats_a[0].lanl_fail_count_1m is None
    assert feats_a[0].unavailable_reasons["lanl_fail_count_1m"] == "INSUFFICIENT_HISTORICAL_COVERAGE"

    # t=180 (elapsed=80) on same pair (C_SRC, C_DST1):
    # 1m window [120, 180) has Fail at t=120 only (t=100 is out of 60s window); 5m still unavailable
    assert feats_a[2].lanl_fail_1m_available == 1
    assert feats_a[2].lanl_fail_count_1m == 1.0
    assert feats_a[2].lanl_fail_5m_available == 0

    # t=240 (elapsed=140) on distinct destination C_DST2 has 0 pair fails even though C_DST1 failed earlier
    assert feats_a[3].lanl_fail_1m_available == 1
    assert feats_a[3].lanl_fail_count_1m == 0.0

    # t=1020 (elapsed=920 >= 900): full 15m window [120, 1020) active on (C_SRC, C_DST1)
    # t=100 is < 1020-900=120 -> pruned; t=120 (Fail, U2@D, Interactive) + t=180 (Success, U1@D, Network) included
    # Same-timestamp event #6 at t=1020 MUST NOT leak into event #5 at t=1020
    f5 = feats_a[4]
    assert f5.lanl_fail_15m_available == 1
    assert f5.lanl_fail_count_15m == 1.0
    assert f5.lanl_auth_count_15m == 2.0
    assert f5.lanl_unique_dest_users_15m == 2.0
    # Source host C_SRC saw C_DST1 and C_DST2 in [120, 1020) -> 2 unique dst hosts
    assert f5.lanl_unique_dst_hosts_per_src_15m == 2.0
    assert math.isclose(f5.lanl_logon_type_entropy_15m or 0.0, 1.0, rel_tol=1e-6)
    assert f5.lanl_rel_hour_mod24 == float((1020 // 3600) % 24)

    # Mutate future event #6 after event #5 and prove event #5 is unchanged
    perturbed_events = base_events[:5] + [
        LanlRawAuthEvent(6, 1020, "U99@D", "U99@D", "C_SRC", "C_DST1", "NTLM", "Batch", "LogOn", "Fail", "hz")
    ]
    ext_b = LanlCausalFeatureExtractor(retention_seconds=900)
    feats_b = [ext_b.process_event(ev) for ev in perturbed_events]
    assert feats_b[4] == feats_a[4]


def test_end_to_end_streaming_build_embargo_split_and_hygiene_audit(tmp_path: Path):
    # Construct compressed fixture spanning t=100..5000 without disk decompression
    raw_auth = [
        "100,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail",
        "200,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Success",
        "1100,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Fail",
        "1100,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Fail",  # exact duplicate line!
        "1200,U_RED@D,U_RED@D,C_ATK1,C_SRV1,NTLM,Network,LogOn,Success",
        "2300,U2@D,U2@D,C3,C4,Kerberos,Interactive,LogOn,Success",
        "2600,U_RED2@D,U_RED2@D,C_ATK1,C_SRV2,NTLM,Network,LogOn,Success",
        "4000,U_RED3@D,U_RED3@D,C_ATK2,C_SRV3,NTLM,Network,LogOn,Success",
        "4200,U3@D,U3@D,C5,C6,Kerberos,Network,LogOn,Success",
    ]
    # Note: line 3 & 4 are identical; if matching redteam, dedup preserves uniqueness
    redteam = [
        "1100,U1@D,C1,C2",
        "1200,U_RED@D,C_ATK1,C_SRV1",
        "2600,U_RED2@D,C_ATK1,C_SRV2",
        "4000,U_RED3@D,C_ATK2,C_SRV3",
    ]
    auth_gz = _write_gz(tmp_path / "auth.txt.gz", raw_auth)
    rt_gz = _write_gz(tmp_path / "redteam.txt.gz", redteam)
    out_dir = tmp_path / "out"

    rows, manifest = build_lanl_benchmark_dataset(
        auth_gz,
        rt_gz,
        out_dir,
        config=LanlBuildConfig(dataset_version="test1", exclude_duplicates=True),
        created_at_utc_override="2026-11-27T12:00:00Z",
    )

    assert len(rows) == 8  # 9 read minus 1 exact duplicate
    assert manifest.exact_line_duplicates_skipped == 1
    assert manifest.redteam_matched_events == 4
    # Exact duplicate line skipped cleanly -> unique match, NOT spurious ambiguity
    row_1100 = [r for r in rows if r.time_rel == 1100][0]
    assert row_1100.match_status == MatchStatus.EXACT_UNIQUE_MATCH.value
    assert row_1100.is_ambiguous_match is False

    for r in rows:
        validate_lanl_feature_row(r)

    splits = lanl_chronological_split_with_embargo(rows, train_ratio=0.5, val_ratio=0.25, embargo_seconds=900)
    hygiene = audit_lanl_partition_hygiene(splits, min_embargo_seconds=900)
    # C_ATK1 appeared at t=1200 (train) and t=2600 (if val); verify gap & host audit runs cleanly
    assert isinstance(hygiene["train_test_shared_positive_src_hosts"], list)

    # Deliberately break embargo to confirm audit fails closed
    bad_splits = {
        "train": [rows[0]],
        "val": [rows[1]],  # t=200 - t=100 = 100s < 900s
        "test": [],
    }
    with pytest.raises(AssertionError, match="Embargo violation"):
        audit_lanl_partition_hygiene(bad_splits, min_embargo_seconds=900)


def test_otrf_passive_zip_adapter_schema_edge_cases_and_no_synthetic_labels(tmp_path: Path):
    fixture_records = [
        # Lowercase 'security' channel + Mordor RecordNumber + IPv4
        {
            "@timestamp": "2020-10-22T08:29:53.908Z",
            "Channel": "security",
            "EventID": 4624,
            "RecordNumber": 537141,
            "Hostname": "MORDORDC.theshire.local",
            "IpAddress": "172.18.39.5",
            "LogonType": "3",
            "TargetUserName": "pgustavo",
            "TargetDomainName": "THESHIRE.LOCAL",
            "TargetUserSid": "S-1-5-21-1104",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "AuthenticationPackageName": "Kerberos",
            "tags": ["mordorDataset"],
        },
        # 4625 failed logon with '-' IpAddress
        {
            "@timestamp": "2020-10-22T08:29:55.210Z",
            "Channel": "Security",
            "EventID": 4625,
            "RecordNumber": 134058,
            "Hostname": "WORKSTATION5.theshire.local",
            "IpAddress": "-",
            "LogonType": "2",
            "TargetUserName": "lrodriguez",
            "TargetDomainName": "theshire.local",
            "TargetUserSid": "S-1-0-0",
            "SubjectUserName": "pgustavo",
            "SubjectDomainName": "THESHIRE",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
            "tags": ["mordorDataset"],
        },
        # Loopback ::1 logon
        {
            "@timestamp": "2020-10-22T08:29:56.000Z",
            "Channel": "Security",
            "EventID": 4624,
            "EventRecordID": 9001,
            "Hostname": "MORDORDC.theshire.local",
            "IpAddress": "::1",
            "LogonType": "3",
            "TargetUserName": "MORDORDC$",
            "TargetDomainName": "THESHIRE.LOCAL",
        },
        # Non-Security Sysmon event (must be skipped cleanly by auth parser)
        {
            "@timestamp": "2020-10-22T08:29:57.000Z",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 12,
            "RecordNumber": 50,
            "Hostname": "MORDORDC.theshire.local",
        },
    ]

    zip_path = tmp_path / "otrf_fixture.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "capture.json",
            "\n".join(json.dumps(r) for r in fixture_records) + "\n",
        )

    summary = summarize_otrf_auth_capture(zip_path, source_capture="fixture_cap")
    assert summary.total_events == 4
    assert summary.security_channel_events == 3
    assert summary.lowercase_security_channel_events == 1
    assert summary.event_4624_count == 2
    assert summary.event_4625_count == 1
    assert summary.auth_with_non_loopback_ip == 1
    assert summary.auth_with_loopback_ip == 1
    assert summary.auth_with_missing_ip == 1
    assert summary.duplicate_raw_records == 0
    assert summary.duplicate_channel_host_record_id == 0
    assert summary.per_event_ground_truth_available is False

    parsed_first = parse_otrf_auth_event(fixture_records[0], "fixture_cap")
    assert parsed_first is not None
    assert parsed_first.schema_version == OTRF_SCHEMA_VERSION
    assert parsed_first.channel == "Security"
    assert parsed_first.logon_type == 3
    assert parsed_first.record_id == 537141
    assert parsed_first.source_ip == "172.18.39.5"
    assert parsed_first.label is None
    assert parsed_first.label_source == "unlabeled_mixed_adversarial_capture"

    parsed_fail = parse_otrf_auth_event(fixture_records[1], "fixture_cap")
    assert parsed_fail is not None
    assert parsed_fail.event_id == 4625
    assert parsed_fail.source_ip is None
    assert parsed_fail.source_ip_present is False
    assert parsed_fail.status_code == "0xc000006d"
    assert parsed_fail.label is None

    assert parse_otrf_auth_event(fixture_records[3], "fixture_cap") is None


def test_disjoint_block_reset_prevents_post_gap_false_availability():
    ext = LanlCausalFeatureExtractor(retention_seconds=900)
    # Day 8 block warmed up to exact 900s lower inclusive boundary [1000, 1900)
    for t in (1000, 1900):
        f = ext.process_event(
            LanlRawAuthEvent(t, t, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Fail", f"h{t}")
        )
    assert f.lanl_fail_15m_available == 1
    assert f.lanl_fail_count_15m == 1.0

    # Jumping to a later disjoint block MUST reset warmup origin so Day 13 start doesn't emit fake 0.0s
    ext.reset_for_block()
    f_post_gap = ext.process_event(
        LanlRawAuthEvent(3, 500_000, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Success", "hg")
    )
    assert f_post_gap.lanl_fail_1m_available == 0
    assert f_post_gap.lanl_fail_15m_available == 0
    assert f_post_gap.lanl_fail_count_15m is None
    assert f_post_gap.unavailable_reasons["lanl_fail_count_15m"] == "INSUFFICIENT_HISTORICAL_COVERAGE"


def test_genuine_truncated_auth_types_and_mixed_same_second_outcomes(tmp_path: Path):
    # Genuine LANL prefix truncations + LogOff + ScreenLock + exact same-second Fail & Success redteam match
    assert normalize_lanl_auth_type_family("MICROSOFT_AUTHENTICATION_PACKAG") == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
    assert normalize_lanl_auth_type_family("MICROSOFT_AUTHENTICATION_PA") == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
    assert normalize_lanl_auth_type_family("NETWARE_AUTHENTICATION_PACK") == "NETWARE_AUTHENTICATION_PACKAGE_V1_0"
    assert normalize_lanl_auth_type_family("?") == "MISSING"
    assert normalize_lanl_auth_type_family("Kerberos") == "Kerberos"

    lines = [
        "100,U1@D,U1@D,C1,C2,MICROSOFT_AUTHENTICATION_PACKAG,Network,LogOn,Fail",
        "200,U1@D,U1@D,C1,C2,?,Network,LogOff,Success",
        "1200,C1$@D,SYSTEM@C1,C1,C1,Negotiate,Service,ScreenLock,Success",
        "2000,U9263@DOM1,U9263@DOM1,C17693,C828,NTLM,Network,LogOn,Fail",
        "2000,U9263@DOM1,U9263@DOM1,C17693,C828,NTLM,Network,LogOn,Success",
    ]
    rt_lines = [
        "2000,U9263@DOM1,C17693,C828",
        "2000,U9263@DOM1,C17693,C828",  # duplicate annotation just like redteam.txt.gz
    ]
    auth_gz = _write_gz(tmp_path / "auth_trunc.csv.gz", lines)
    rt_gz = _write_gz(tmp_path / "rt_trunc.csv.gz", rt_lines)

    rows, manifest = build_lanl_benchmark_dataset(
        auth_gz,
        rt_gz,
        tmp_path / "out",
        config=LanlBuildConfig(dataset_version="tgen"),
        created_at_utc_override="2026-11-28T00:00:00Z",
    )
    assert rows[0].auth_type_cat == "MICROSOFT_AUTHENTICATION_PACKAG"  # raw preserved
    assert rows[1].auth_orientation_cat == "LogOff"
    assert rows[2].auth_orientation_cat == "ScreenLock"
    assert manifest.redteam_duplicate_annotations == 1

    # Both same-second Fail & Success matched via destination_user with AMBIGUOUS_MULTI_MATCH
    pos_rows = [r for r in rows if r.label == 1]
    assert len(pos_rows) == 2
    assert {r.is_auth_failure for r in pos_rows} == {0, 1}
    assert all(r.match_status == MatchStatus.AMBIGUOUS_MULTI_MATCH.value for r in pos_rows)


def test_chunked_parquet_warmup_null_schema_stability_and_guards(tmp_path: Path):
    import pyarrow.parquet as pq

    # Build a block where chunk_size=2 forces chunk 1 to have ALL-None rolling 5m/15m features
    # (verifying explicit Arrow schema prevents `double vs null` crash on warmed chunk 2)
    b1_lines = [
        "100,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail",     # warmup
        "1050,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Success",  # warmup >= 900s after start
        "1200,U2@D,U2@D,C1,C2,NTLM,Network,LogOn,Fail",     # eval chunk 1
        "1250,U2@D,U2@D,C1,C2,NTLM,Network,LogOn,Success",  # eval chunk 1
        "1300,U3@D,U3@D,C17693,C2,NTLM,Network,LogOn,Success",  # eval chunk 2 positive
    ]
    b2_lines = [
        "10000,U4@D,U4@D,C3,C4,Kerberos,Network,LogOn,Success",  # warmup
        "11000,U5@D,U5@D,C3,C4,Kerberos,Network,LogOn,Success",  # eval block 2 (post-gap warmup check)
    ]
    rt_lines = ["1300,U3@D,C17693,C2"]

    b1_gz = _write_gz(tmp_path / "b1.csv.gz", b1_lines)
    b2_gz = _write_gz(tmp_path / "b2.csv.gz", b2_lines)
    rt_gz = _write_gz(tmp_path / "rt.csv.gz", rt_lines)

    specs = [
        LanlBlockSpec("b1", "train", b1_gz, extract_start_t=100, eval_start_t=1100, eval_end_t=1400),
        LanlBlockSpec("b2", "test", b2_gz, extract_start_t=10000, eval_start_t=10900, eval_end_t=11200),
    ]
    manifest = build_lanl_block_parquet_dataset(
        specs,
        rt_gz,
        tmp_path / "pq_out",
        dataset_version="pq1",
        chunk_size=2,
        max_output_bytes=10 * 1024 * 1024,
        compute_line_hash=False,
        created_at_utc_override="2026-11-28T00:00:00Z",
    )
    assert manifest["total_eval_rows_exported"] == 4  # 3 in b1 + 1 in b2
    assert manifest["total_positives_exported"] == 1
    p1 = tmp_path / "pq_out" / "b1_vpq1.parquet"
    tbl = pq.read_table(p1)
    assert tbl.schema.equals(get_lanl_pyarrow_schema())
    assert tbl.num_rows == 3
    assert tbl["label"].to_pylist() == [0, 0, 1]

    # Partition embargo violation (< 900s gap) fails closed
    bad_specs = [
        LanlBlockSpec("b1", "train", b1_gz, extract_start_t=100, eval_start_t=1100, eval_end_t=1400),
        LanlBlockSpec("b2", "test", b2_gz, extract_start_t=800, eval_start_t=1700, eval_end_t=2000),  # gap=300s < 900s
    ]
    with pytest.raises(ValueError, match="Temporal separation violation"):
        build_lanl_block_parquet_dataset(bad_specs, rt_gz, tmp_path / "pq_bad")

    # Tiny storage cap fails closed
    with pytest.raises(RuntimeError, match="max_output_bytes"):
        build_lanl_block_parquet_dataset(
            specs, rt_gz, tmp_path / "pq_cap", dataset_version="cap", max_output_bytes=10
        )


def test_o1_sliding_window_exact_parity_with_reference_spec():
    """
    Proves the O(1) incremental sliding window extractor matches brute-force [t - W, t)
    reference aggregation bit-for-bit across same-second bursts, missing values, and evictions.
    """
    import random

    rng = random.Random(42)
    stream = []
    t_cur = 1000
    hosts = ["C_HUB", "C_A", "C_B", "C_C"]
    users = ["U1@D", "U2@D", "U3@D", None]
    lts = ["Network", "Interactive", "Service", None]

    for seq in range(1, 350):
        t_cur += rng.choice([0, 0, 0, 1, 5, 35, 180])
        sc = "C_HUB" if seq % 3 == 0 else rng.choice(hosts)
        dc = rng.choice(hosts)
        stream.append(
            LanlRawAuthEvent(
                record_seq=seq,
                time_rel=t_cur,
                source_user="U_SRC@D",
                destination_user=rng.choice(users),
                source_computer=sc,
                destination_computer=dc,
                auth_type="NTLM",
                logon_type=rng.choice(lts),
                auth_orientation="LogOn",
                outcome="Fail" if rng.random() < 0.3 else "Success",
                raw_line_hash=f"sig_{seq}",
            )
        )

    ext = LanlCausalFeatureExtractor(retention_seconds=900)
    t0 = stream[0].time_rel
    seen = []
    for ev in stream:
        got = ext.process_event(ev, deduplicate=True)
        t = ev.time_rel
        elapsed = t - t0
        prior_pair = [
            r for r in seen
            if r.time_rel < t and r.source_computer == ev.source_computer and r.destination_computer == ev.destination_computer
        ]
        prior_src = [r for r in seen if r.time_rel < t and r.source_computer == ev.source_computer]

        if elapsed >= 60:
            exp_f1 = float(sum(1 for r in prior_pair if r.time_rel >= t - 60 and r.outcome == "Fail"))
            assert got.lanl_fail_1m_available == 1 and got.lanl_fail_count_1m == exp_f1
        else:
            assert got.lanl_fail_1m_available == 0 and got.lanl_fail_count_1m is None

        if elapsed >= 300:
            exp_f5 = float(sum(1 for r in prior_pair if r.time_rel >= t - 300 and r.outcome == "Fail"))
            assert got.lanl_fail_5m_available == 1 and got.lanl_fail_count_5m == exp_f5
        else:
            assert got.lanl_fail_5m_available == 0 and got.lanl_fail_count_5m is None

        if elapsed >= 900:
            w15 = [r for r in prior_pair if r.time_rel >= t - 900]
            exp_f15 = float(sum(1 for r in w15 if r.outcome == "Fail"))
            exp_a15 = float(len(w15))
            exp_u15 = float(len({r.destination_user for r in w15 if r.destination_user}))
            exp_h15 = float(len({r.destination_computer for r in prior_src if r.time_rel >= t - 900}))
            assert got.lanl_fail_count_15m == exp_f15
            assert got.lanl_auth_count_15m == exp_a15
            assert got.lanl_unique_dest_users_15m == exp_u15
            assert got.lanl_unique_dst_hosts_per_src_15m == exp_h15

            lt_cnt = {}
            for r in w15:
                if r.logon_type:
                    lt_cnt[r.logon_type] = lt_cnt.get(r.logon_type, 0) + 1
            if not lt_cnt:
                assert got.lanl_logon_type_entropy_15m_available == 0 and got.lanl_logon_type_entropy_15m is None
            else:
                tot = sum(lt_cnt.values())
                exp_ent = 0.0 if len(lt_cnt) == 1 else round(-sum((c / tot) * math.log2(c / tot) for c in lt_cnt.values()), 6)
                assert got.lanl_logon_type_entropy_15m_available == 1 and got.lanl_logon_type_entropy_15m == exp_ent

        seen.append(ev)


def test_reproduced_out_of_order_sequence_1_1002_901_fails_closed_preserving_state():
    """
    Verifies exact Codex reproduction sequence (1, 1002, 901):
    - Late event at 901 rejects explicitly BEFORE mutating watermark, dedup cache, or window state.
    - Never emits false available=1 zero or disables pruning on disordered streams.
    - Subsequent ordered continuation (>= 1002) and equal timestamps remain intact.
    """
    ext = LanlCausalFeatureExtractor(retention_seconds=900)
    ev1 = LanlRawAuthEvent(1, 1, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Fail", "h1")
    ev2 = LanlRawAuthEvent(2, 1002, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Success", "h2")
    ev_late = LanlRawAuthEvent(3, 901, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Fail", "h_late")
    ev_late_dup = LanlRawAuthEvent(4, 901, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Fail", "h1")

    ext.process_event(ev1)
    f2 = ext.process_event(ev2)
    assert f2.lanl_fail_15m_available == 1
    assert f2.lanl_fail_count_15m == 0.0  # t=1 is evicted when t=1002

    snap_wm = ext._watermark_time
    snap_start = ext._stream_start_time
    snap_dedup = set(ext._dedup_set)
    snap_qlen = len(ext._pair_events[("C1", "C2")].q900)
    snap_pending = list(ext._pair_events[("C1", "C2")].pending_entries)

    # Late event (both normal and duplicate signature) MUST raise ValueError without mutating state
    with pytest.raises(ValueError, match="Out-of-order timestamp regression rejected"):
        ext.process_event(ev_late)
    with pytest.raises(ValueError, match="Out-of-order timestamp regression rejected"):
        ext.process_event(ev_late_dup)

    assert ext._watermark_time == snap_wm == 1002
    assert ext._stream_start_time == snap_start == 1
    assert ext._dedup_set == snap_dedup
    assert len(ext._pair_events[("C1", "C2")].q900) == snap_qlen
    assert ext._pair_events[("C1", "C2")].pending_entries == snap_pending

    # Equal timestamp (t=1002) and later timestamp (t=1003) still work cleanly and prune prior pending
    ev_eq = LanlRawAuthEvent(5, 1002, "U2@D", "U2@D", "C1", "C2", "NTLM", "Network", "LogOn", "Fail", "h_eq")
    f_eq = ext.process_event(ev_eq)
    assert f_eq.lanl_auth_count_15m == 0.0  # ev2 at t=1002 excluded from tie
    ev_next = LanlRawAuthEvent(6, 1003, "U3@D", "U3@D", "C1", "C2", "NTLM", "Network", "LogOn", "Success", "h_next")
    f_next = ext.process_event(ev_next)
    assert f_next.lanl_auth_count_15m == 2.0
    assert f_next.lanl_fail_count_15m == 1.0


def test_disordered_long_stream_rejects_regression_instead_of_retaining_unpruned_state():
    ext = LanlCausalFeatureExtractor(retention_seconds=900)
    for t in range(1, 1002):
        ext.process_event(
            LanlRawAuthEvent(t, t, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Success", f"hs_{t}")
        )
    # 1..101 expired before t=1001; pending=1001 -> active q900 <= 900 entries
    assert len(ext._pair_events[("C1", "C2")].q900) <= 900

    with pytest.raises(ValueError, match="Out-of-order timestamp regression rejected"):
        ext.process_event(
            LanlRawAuthEvent(1002, 500, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", "Fail", "bad_late")
        )
    assert len(ext._pair_events[("C1", "C2")].q900) <= 900


def test_parser_and_pipeline_propagate_out_of_order_error_without_partial_artifacts(tmp_path: Path):
    # Direct parser error propagation when enforce_monotonic=True
    lines = [
        "1,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail",
        "1002,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Success",
        "901,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail",
    ]
    it = iter_lanl_auth_lines(lines, enforce_monotonic=True)
    assert next(it).time_rel == 1
    assert next(it).time_rel == 1002
    with pytest.raises(ValueError, match="Non-monotonic timestamp regression"):
        next(it)

    # build_lanl_benchmark_dataset error propagation -> no partial jsonl/manifest written
    auth_gz = _write_gz(tmp_path / "ooo_auth.csv.gz", lines)
    rt_gz = _write_gz(tmp_path / "ooo_rt.csv.gz", ["1002,U1@D,C1,C2"])
    out_jsonl_dir = tmp_path / "out_jsonl"
    with pytest.raises(ValueError, match="timestamp regression"):
        build_lanl_benchmark_dataset(auth_gz, rt_gz, out_jsonl_dir)
    assert not list(out_jsonl_dir.glob("*.jsonl"))
    assert not list(out_jsonl_dir.glob("*.manifest.json"))

    # build_lanl_block_parquet_dataset error propagation -> unlinks partial parquet and skips manifest
    block_lines = [
        "100,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail",
        "1100,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Success",
        "1050,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail",  # regresses inside eval block
    ]
    blk_gz = _write_gz(tmp_path / "blk_ooo.csv.gz", block_lines)
    spec = LanlBlockSpec("blk_bad", "train", blk_gz, extract_start_t=100, eval_start_t=1000, eval_end_t=1300)
    out_pq_dir = tmp_path / "out_pq"
    with pytest.raises(ValueError, match="Out-of-order timestamp regression rejected"):
        build_lanl_block_parquet_dataset([spec], rt_gz, out_pq_dir)
    assert not list(out_pq_dir.glob("*.parquet"))
    assert not list(out_pq_dir.glob("*.manifest.json"))


def test_fixed_900s_retention_enforced_and_exact_60_300_900_boundaries():
    # Reject unsupported retention configurations across extractor, build config, and block spec
    for bad_ret in (1800, 300, 0, -1, True):
        with pytest.raises(ValueError, match="fixed retention_seconds=900"):
            LanlCausalFeatureExtractor(retention_seconds=bad_ret)
        with pytest.raises(ValueError, match="fixed retention_seconds=900"):
            LanlBuildConfig(retention_seconds=bad_ret)
        with pytest.raises(ValueError, match="fixed retention_seconds=900"):
            LanlBlockSpec("b", "train", Path("dummy.gz"), 100, 1000, 1200, retention_seconds=bad_ret)

    # Exact supported retention_seconds=900 boundaries and expiry checks:
    # Base stream start = 100 -> at t=1000 (elapsed=900):
    # - 1m window = [940, 1000) -> includes 940, excludes 939 & 1000
    # - 5m window = [700, 1000) -> includes 700, excludes 699 & 1000
    # - 15m window = [100, 1000) -> includes 100, excludes 99 & 1000
    ext = LanlCausalFeatureExtractor(retention_seconds=900)
    events = [
        (100, "Fail", "Network", "U1@D"),     # inside 15m of 1000 (100 >= 100), expires at 1001
        (699, "Fail", "Network", "U2@D"),     # outside 5m of 1000, inside 15m of 1000
        (700, "Fail", "Interactive", "U3@D"), # inside 5m & 15m of 1000
        (939, "Fail", "Service", "U4@D"),     # outside 1m of 1000, inside 5m & 15m of 1000
        (940, "Fail", None, None),            # inside 1m, 5m, 15m of 1000 (missing lt/user)
        (1000, "Fail", "Network", "U5@D"),    # tie at 1000 -> MUST NOT self-count at t=1000
        (1001, "Success", "Network", "U6@D"), # t=100 MUST now be expired (100 < 1001-900=101)
    ]
    res = {}
    for seq, (t, oc, lt, usr) in enumerate(events, start=1):
        res[t] = ext.process_event(
            LanlRawAuthEvent(seq, t, "USRC@D", usr, "C_S", "C_D", "NTLM", lt, "LogOn", oc, f"b_{seq}")
        )

    f1000 = res[1000]
    assert f1000.lanl_fail_1m_available == 1 and f1000.lanl_fail_count_1m == 1.0  # t=940 only
    assert f1000.lanl_fail_5m_available == 1 and f1000.lanl_fail_count_5m == 3.0  # 700, 939, 940
    assert f1000.lanl_fail_15m_available == 1 and f1000.lanl_fail_count_15m == 5.0  # 100, 699, 700, 939, 940
    assert f1000.lanl_auth_count_15m == 5.0
    assert f1000.lanl_unique_dest_users_15m == 4.0  # U1..U4 (940 had None)

    f1001 = res[1001]
    assert f1001.lanl_auth_count_15m == 5.0  # 699, 700, 939, 940, 1000 (t=100 expired!)
    assert f1001.lanl_fail_count_15m == 5.0

    # Genuine zero after full 900s history with quiet unseen pair
    f_quiet = ext.process_event(
        LanlRawAuthEvent(8, 2000, "UX@D", "UX@D", "C_Q1", "C_Q2", "Kerberos", "Network", "LogOn", "Success", "bq")
    )
    assert f_quiet.lanl_fail_15m_available == 1 and f_quiet.lanl_fail_count_15m == 0.0
    assert f_quiet.lanl_logon_type_entropy_15m_available == 0
    assert f_quiet.unavailable_reasons["lanl_logon_type_entropy_15m"] == "NO_VALID_LOGON_TYPES"

    # Verify reset_for_block zeroes coverage cleanly even after full warmup
    ext.reset_for_block()
    f_reset = ext.process_event(
        LanlRawAuthEvent(9, 5000, "UX@D", "UX@D", "C_Q1", "C_Q2", "Kerberos", "Network", "LogOn", "Fail", "br")
    )
    assert f_reset.lanl_fail_1m_available == 0 and f_reset.lanl_fail_15m_available == 0
    assert f_reset.lanl_fail_count_15m is None
    assert f_reset.unavailable_reasons["lanl_fail_count_15m"] == "INSUFFICIENT_HISTORICAL_COVERAGE"
