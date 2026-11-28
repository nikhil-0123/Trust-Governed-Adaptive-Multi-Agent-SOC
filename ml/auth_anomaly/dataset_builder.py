"""
Reproducible Offline Dataset Builder for TGAM-SOC Authentication Anomaly Detection.

Reads raw Security/Contract-v1 JSONL telemetry plus an explicit ground-truth
LabelAssignment manifest, computes deterministic point-in-time f1-f7 vectors,
records frozen deterministic BruteForceRule baseline predictions strictly as
comparison metadata, sanitizes sensitive identifiers, validates schema invariants,
and writes an immutable dataset artifact + cryptographic DatasetManifest.
"""

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WIN_TELEMETRY_ROOT = str(_REPO_ROOT / "windows-telemetry")
if _WIN_TELEMETRY_ROOT not in sys.path:
    sys.path.insert(0, _WIN_TELEMETRY_ROOT)

from detection.rules import BruteForceRule  # noqa: E402

from .extractor import (  # noqa: E402
    BusinessHoursConfig,
    DeterministicSimClock,
    OfflineAuthFeatureExtractor,
    adapt_raw_security_event_to_contract_v1,
    canonical_auth_from_contract_v1,
)
from .schema import (  # noqa: E402
    AVAILABILITY_COLUMNS,
    DATASET_SCHEMA_VERSION,
    FEATURE_COLUMNS,
    MODEL_INPUT_COLUMNS,
    AuthDatasetRow,
    DatasetManifest,
    LabelAssignment,
    pseudonymize_identifier,
    validate_feature_row,
)


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class DatasetBuildConfig:
    dataset_name: str
    dataset_version: str
    business_hours: BusinessHoursConfig
    pseudonymization_salt: str
    exclude_unpredictable_rows: bool = True
    output_format: str = "jsonl"  # "jsonl" or "parquet"
    future_clock_skew_tolerance_seconds: float = 5.0
    retention_horizon_seconds: float = 900.0
    replay_order: str = "auto"  # "auto" | "arrival" | "chronological"


def _match_label(
    event_id: str,
    host: str,
    source_ip: Optional[str],
    source_ip_pseudonym: Optional[str],
    ts_epoch: float,
    labels: Sequence[LabelAssignment],
) -> LabelAssignment:
    matches: List[LabelAssignment] = []
    for lbl in labels:
        if lbl.event_ids is not None:
            if event_id in lbl.event_ids:
                matches.append(lbl)
            continue
        if not (lbl.start_epoch <= ts_epoch <= lbl.end_epoch):
            continue
        if lbl.host is not None and lbl.host.lower() != host.lower():
            continue
        if lbl.source_ip is not None:
            if not source_ip or lbl.source_ip != source_ip:
                continue
        if lbl.source_ip_pseudonym is not None:
            if not source_ip_pseudonym or lbl.source_ip_pseudonym != source_ip_pseudonym:
                continue
        matches.append(lbl)

    if not matches:
        raise ValueError(
            f"Unlabeled event '{event_id}' (host={host}, ip_pseudo={source_ip_pseudonym}, t={ts_epoch}): "
            "offline dataset requires explicit LabelAssignment provenance."
        )
    if len(matches) > 1:
        distinct_pairs = {(m.scenario_id, m.label, m.telemetry_origin) for m in matches}
        if len(distinct_pairs) > 1:
            raise ValueError(
                f"Conflicting LabelAssignments matched event '{event_id}': {sorted(distinct_pairs)}"
            )
    return matches[0]


def _parse_iso_utc(ts_epoch: float) -> str:
    return datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def analyze_dataset_statistics(rows: Sequence[AuthDatasetRow]) -> Dict[str, Any]:
    """
    Computes empirical dataset diagnostics separately for benign vs suspicious classes,
    scenario counts, telemetry origins, and potential missingness/context confounding.
    """
    by_class: Dict[int, List[AuthDatasetRow]] = {0: [], 1: []}
    for r in rows:
        by_class.setdefault(r.label, []).append(r)

    class_stats: Dict[str, Any] = {}
    for cls in (0, 1):
        sub = by_class.get(cls, [])
        n = len(sub)
        feat_summary: Dict[str, Any] = {}
        for fcol, acol in zip(FEATURE_COLUMNS, AVAILABILITY_COLUMNS):
            avail_vals = [float(getattr(r, fcol)) for r in sub if getattr(r, acol) == 1]
            feat_summary[fcol] = {
                "available_count": len(avail_vals),
                "missing_count": n - len(avail_vals),
                "availability_rate": round(len(avail_vals) / n, 6) if n else 0.0,
                "min": min(avail_vals) if avail_vals else None,
                "max": max(avail_vals) if avail_vals else None,
                "mean": round(sum(avail_vals) / len(avail_vals), 6) if avail_vals else None,
            }
        class_stats[str(cls)] = {
            "count": n,
            "event_id_4625_count": sum(1 for r in sub if r.is_auth_failure == 1),
            "event_id_4624_count": sum(1 for r in sub if r.is_auth_failure == 0),
            "logon_types": dict(Counter(r.logon_type for r in sub)),
            "features": feat_summary,
        }

    return {
        "total_rows": len(rows),
        "scenario_counts": dict(Counter(r.scenario_id for r in rows)),
        "telemetry_origin_counts": dict(Counter(r.telemetry_origin for r in rows)),
        "host_counts": dict(Counter(r.host_pseudonym for r in rows)),
        "class_distributions": class_stats,
    }


def build_auth_feature_dataset(
    raw_event_paths: Sequence[Path],
    label_assignments: Sequence[LabelAssignment],
    output_dir: Path,
    config: DatasetBuildConfig,
    log_clear_epochs_utc: Optional[Sequence[float]] = None,
    unrecoverable_gaps: Optional[Sequence[Tuple[float, float, str]]] = None,
    created_at_utc_override: Optional[str] = None,
) -> Tuple[List[AuthDatasetRow], DatasetManifest]:
    """
    Executes deterministic offline dataset preparation:
    1. Computes input file SHA-256 digests.
    2. Loads and adapts raw Security / Contract v1 JSONL records.
    3. Replays records in live-collector causal order (preventing future sort leakage).
    4. Runs OfflineAuthFeatureExtractor (f1-f7) + shadow BruteForceRule baseline.
    5. Attaches explicit ground-truth LabelAssignment with telemetry origin verification.
    6. Validates every row and writes dataset + DatasetManifest deterministically.
    """
    if not raw_event_paths:
        raise ValueError("raw_event_paths cannot be empty")
    if not label_assignments:
        raise ValueError("label_assignments cannot be empty")
    if not config.pseudonymization_salt or len(config.pseudonymization_salt) < 8:
        raise ValueError("pseudonymization_salt must be at least 8 characters for identifier hashing")

    output_dir.mkdir(parents=True, exist_ok=True)

    input_checksums: Dict[str, str] = {}
    adapted_events: List[Tuple[int, Dict[str, Any], Optional[str], bool, Optional[int], int]] = []
    total_raw_records = 0

    for file_idx, p in enumerate(sorted(raw_event_paths, key=lambda x: str(x))):
        input_checksums[p.name] = compute_file_sha256(p)
        with open(p, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                total_raw_records += 1
                raw_obj = json.loads(stripped)
                raw_origin = raw_obj.get("telemetry_origin")
                raw_is_sim = bool(
                    raw_obj.get("is_simulated")
                    or (isinstance(raw_obj.get("evidence"), dict) and raw_obj["evidence"].get("is_simulated"))
                )
                coll_seq = raw_obj.get("collection_seq")
                chan_epoch = int(
                    raw_obj.get("channel_epoch")
                    or (raw_obj.get("evidence", {}).get("channel_epoch") if isinstance(raw_obj.get("evidence"), dict) else None)
                    or 1
                )
                contract_ev = adapt_raw_security_event_to_contract_v1(raw_obj)
                adapted_events.append((total_raw_records, contract_ev, raw_origin, raw_is_sim, coll_seq, chan_epoch))

    parsed_items = []
    for arrival_idx, contract_ev, raw_origin, raw_is_sim, coll_seq, chan_epoch in adapted_events:
        canon = canonical_auth_from_contract_v1(contract_ev)
        if canon is None:
            continue
        parsed_items.append((arrival_idx, canon, contract_ev, raw_origin, raw_is_sim, coll_seq, chan_epoch))

    # Replay ordering preserving live collector causality
    all_have_seq = all(item[5] is not None for item in parsed_items)
    mode = config.replay_order
    if mode == "arrival":
        pass  # Keep exact input file/line order
    elif mode == "auto" and all_have_seq:
        parsed_items.sort(
            key=lambda it: (
                it[1].destination_host,
                it[6],  # channel_epoch
                int(it[5]),  # collection_seq
                it[1].raw_record_id,
                it[1].event_id,
            )
        )
    elif mode in ("auto", "chronological"):
        parsed_items.sort(
            key=lambda it: (
                it[1].timestamp_epoch,
                it[1].destination_host,
                it[6],
                it[1].raw_record_id,
                it[1].event_id,
            )
        )
    else:
        raise ValueError(f"Invalid replay_order '{mode}'; expected 'auto', 'arrival', or 'chronological'")

    max_ts = max((item[1].timestamp_epoch for item in parsed_items), default=0.0)
    clock = DeterministicSimClock(current_time=max_ts)
    extractor = OfflineAuthFeatureExtractor(
        clock=clock,
        business_hours_config=config.business_hours,
        future_clock_skew_tolerance_seconds=config.future_clock_skew_tolerance_seconds,
        retention_horizon_seconds=config.retention_horizon_seconds,
    )
    baseline_rule = BruteForceRule()

    clear_idx = 0
    sorted_clears = sorted(log_clear_epochs_utc or [])
    gap_idx = 0
    sorted_gaps = sorted(unrecoverable_gaps or [], key=lambda g: (g[1], g[0]))

    rows: List[AuthDatasetRow] = []
    excluded_count = 0
    duplicate_count = 0
    label_dist = {"0": 0, "1": 0}
    origin_dist: Dict[str, int] = {}

    for _, canon, contract_ev, raw_origin, raw_is_sim, _, _ in parsed_items:
        while clear_idx < len(sorted_clears) and canon.timestamp_epoch >= sorted_clears[clear_idx]:
            extractor.notify_log_cleared(sorted_clears[clear_idx])
            clear_idx += 1

        while gap_idx < len(sorted_gaps) and canon.timestamp_epoch >= sorted_gaps[gap_idx][1]:
            g_start, g_end, g_reason = sorted_gaps[gap_idx]
            extractor.notify_unrecoverable_gap(g_start, g_end, g_reason)
            gap_idx += 1

        feats, can_predict = extractor.process_event(canon)

        # Evaluate frozen deterministic rule solely as benchmark comparison metadata
        rule_det = baseline_rule.evaluate(contract_ev)
        rule_detected = bool(rule_det and rule_det.detected)

        if feats.f6_hour_of_day.reason == "DUPLICATE_EVENT":
            duplicate_count += 1
            if config.exclude_unpredictable_rows:
                excluded_count += 1
                continue

        if config.exclude_unpredictable_rows and not can_predict:
            excluded_count += 1
            continue

        ip_pseudo = pseudonymize_identifier(canon.source_ip, config.pseudonymization_salt, "ip")
        lbl = _match_label(
            event_id=canon.event_id,
            host=canon.destination_host,
            source_ip=canon.source_ip,
            source_ip_pseudonym=ip_pseudo,
            ts_epoch=canon.timestamp_epoch,
            labels=label_assignments,
        )

        if raw_is_sim and lbl.telemetry_origin == "genuine_windows":
            raise ValueError(
                f"Provenance violation on event '{canon.event_id}': simulated telemetry cannot be labeled as 'genuine_windows'."
            )
        if raw_origin and raw_origin != lbl.telemetry_origin:
            raise ValueError(
                f"Provenance mismatch on event '{canon.event_id}': record origin '{raw_origin}' != label origin '{lbl.telemetry_origin}'."
            )

        unavail_reasons: Dict[str, str] = {}
        f_pairs = [
            ("f1_failed_logins_1m", feats.f1_failed_logins_1m),
            ("f2_failed_logins_5m", feats.f2_failed_logins_5m),
            ("f3_failed_logins_15m", feats.f3_failed_logins_15m),
            ("f4_unique_users_per_ip_15m", feats.f4_unique_users_per_ip_15m),
            ("f5_logon_type_entropy_15m", feats.f5_logon_type_entropy_15m),
            ("f6_hour_of_day", feats.f6_hour_of_day),
            ("f7_is_off_hours", feats.f7_is_off_hours),
        ]
        for fname, fm in f_pairs:
            if not fm.is_available and fm.reason:
                unavail_reasons[fname] = fm.reason

        win_eid = int(contract_ev["evidence"]["windows_event_id"])
        row = AuthDatasetRow(
            event_id=canon.event_id,
            raw_record_id=canon.raw_record_id,
            timestamp_utc=_parse_iso_utc(canon.timestamp_epoch),
            timestamp_epoch=canon.timestamp_epoch,
            host_pseudonym=pseudonymize_identifier(canon.destination_host, config.pseudonymization_salt, "host") or "host_unknown",
            source_ip_pseudonym=ip_pseudo,
            account_pseudonym=pseudonymize_identifier(canon.target_account_id, config.pseudonymization_salt, "acct"),
            can_predict=can_predict,
            telemetry_origin=lbl.telemetry_origin,
            scenario_id=lbl.scenario_id,
            label=lbl.label,
            label_source=lbl.label_source,
            baseline_rule_bruteforce_detected=rule_detected,
            windows_event_id=win_eid,
            is_auth_failure=1 if win_eid == 4625 else 0,
            logon_type=float(canon.logon_type) if canon.logon_type is not None else None,
            f1_failed_logins_1m=feats.f1_failed_logins_1m.value,
            f2_failed_logins_5m=feats.f2_failed_logins_5m.value,
            f3_failed_logins_15m=feats.f3_failed_logins_15m.value,
            f4_unique_users_per_ip_15m=feats.f4_unique_users_per_ip_15m.value,
            f5_logon_type_entropy_15m=feats.f5_logon_type_entropy_15m.value,
            f6_hour_of_day=feats.f6_hour_of_day.value,
            f7_is_off_hours=feats.f7_is_off_hours.value,
            f1_available=1 if feats.f1_failed_logins_1m.is_available else 0,
            f2_available=1 if feats.f2_failed_logins_5m.is_available else 0,
            f3_available=1 if feats.f3_failed_logins_15m.is_available else 0,
            f4_available=1 if feats.f4_unique_users_per_ip_15m.is_available else 0,
            f5_available=1 if feats.f5_logon_type_entropy_15m.is_available else 0,
            f6_available=1 if feats.f6_hour_of_day.is_available else 0,
            f7_available=1 if feats.f7_is_off_hours.is_available else 0,
            unavailable_reasons=unavail_reasons,
        )
        validate_feature_row(row)
        rows.append(row)
        label_dist[str(row.label)] += 1
        origin_dist[row.telemetry_origin] = origin_dist.get(row.telemetry_origin, 0) + 1

    if config.output_format == "jsonl":
        out_path = output_dir / f"{config.dataset_name}_v{config.dataset_version}.jsonl"
        with open(out_path, "w", encoding="utf-8", newline="\n") as out_f:
            for r in rows:
                out_f.write(json.dumps(r.to_ordered_dict(), sort_keys=False) + "\n")
    elif config.output_format == "parquet":
        import pandas as pd

        out_path = output_dir / f"{config.dataset_name}_v{config.dataset_version}.parquet"
        records = [r.to_ordered_dict() for r in rows]
        for rec in records:
            rec["unavailable_reasons"] = json.dumps(rec["unavailable_reasons"], sort_keys=True)
        df = pd.DataFrame.from_records(records)
        df.to_parquet(out_path, index=False)
    else:
        raise ValueError(f"Unsupported output_format: {config.output_format}")

    output_sha256 = compute_file_sha256(out_path)

    n_rows = len(rows)
    avail_rates: Dict[str, float] = {}
    for col in AVAILABILITY_COLUMNS:
        avail_rates[col] = round(sum(getattr(r, col) for r in rows) / n_rows, 6) if n_rows else 0.0

    created_at = created_at_utc_override or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    manifest = DatasetManifest(
        schema_version=DATASET_SCHEMA_VERSION,
        dataset_version=config.dataset_version,
        dataset_name=config.dataset_name,
        created_at_utc=created_at,
        input_checksums=input_checksums,
        output_file=out_path.name,
        output_sha256=output_sha256,
        output_format=config.output_format,
        total_raw_records=total_raw_records,
        total_auth_records=len(parsed_items),
        total_rows_exported=n_rows,
        excluded_late_or_invalid_rows=excluded_count,
        duplicate_records_skipped=duplicate_count,
        label_distribution=label_dist,
        telemetry_origin_distribution=origin_dist,
        feature_availability_rates=avail_rates,
        feature_columns=FEATURE_COLUMNS,
        model_input_columns=MODEL_INPUT_COLUMNS,
        business_hours_config=asdict(config.business_hours),
        identifier_sanitization="hmac_sha256_pseudonymized",
        leakage_guarantees=(
            "strict_preceding_window_[t-W,t)",
            "live_collector_causal_replay",
            "rules_and_labels_excluded_from_model_input_columns",
            "hmac_pseudonymized_entities",
        ),
    )

    manifest_path = output_dir / f"{config.dataset_name}_v{config.dataset_version}.manifest.json"
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as mf:
        json.dump(asdict(manifest), mf, indent=2, sort_keys=True)

    return rows, manifest
