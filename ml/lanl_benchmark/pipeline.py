"""
End-to-End Streaming LANL Cyber1 Dataset Builder & Chronological/Host Partition Audits.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .features import SUPPORTED_RETENTION_SECONDS, LanlCausalFeatureExtractor
from .labels import MatchStatus, RedteamAnnotationIndex
from .parser import iter_lanl_auth_gz, load_redteam_annotations_gz
from .schema import (
    LANL_AVAILABILITY_COLUMNS,
    LANL_MODEL_INPUT_COLUMNS,
    LANL_SCHEMA_VERSION,
    LanlAuthDatasetRow,
    LanlDatasetManifest,
    get_lanl_pyarrow_schema,
    validate_lanl_feature_row,
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            c = f.read(1048576)
            if not c:
                break
            h.update(c)
    return h.hexdigest()


@dataclass(frozen=True)
class LanlBuildConfig:
    dataset_version: str = "1.0.0"
    exclude_duplicates: bool = True
    exclude_ambiguous_redteam_matches: bool = False
    max_records: Optional[int] = None
    retention_seconds: int = SUPPORTED_RETENTION_SECONDS

    def __post_init__(self) -> None:
        if (
            isinstance(self.retention_seconds, bool)
            or int(self.retention_seconds) != SUPPORTED_RETENTION_SECONDS
        ):
            raise ValueError(
                f"lanl_auth_features_v1 requires fixed retention_seconds={SUPPORTED_RETENTION_SECONDS}, "
                f"got {self.retention_seconds!r}"
            )


def build_lanl_benchmark_dataset(
    auth_path: Path,
    redteam_path: Path,
    output_dir: Path,
    config: LanlBuildConfig = LanlBuildConfig(),
    created_at_utc_override: Optional[str] = None,
) -> Tuple[List[LanlAuthDatasetRow], LanlDatasetManifest]:
    """
    Streams compressed/plain `auth` + `redteam` files cleanly without decompressing
    multi-GB archives onto disk. Writes deterministic JSONL + manifest.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    auth_sha = _sha256_file(auth_path)
    redteam_sha = _sha256_file(redteam_path)

    annotations, malformed_rt = load_redteam_annotations_gz(redteam_path)
    rt_index = RedteamAnnotationIndex(annotations)

    # First pass for multiplicity of redteam keys across auth stream
    # (lightweight: only increments counts for deduplicated lines actually present in small redteam set!)
    pre_key_counts: Dict[Tuple[int, str, str, str], int] = {}
    seen_rt_line_hashes: Dict[Tuple[int, str, str, str], set] = {}
    for ev in iter_lanl_auth_gz(auth_path, max_records=config.max_records, enforce_monotonic=True):
        if ev.source_computer and ev.destination_computer:
            for u in {ev.destination_user, ev.source_user}:
                if u:
                    k = (ev.time_rel, u, ev.source_computer, ev.destination_computer)
                    if k in rt_index._key_counts:
                        if config.exclude_duplicates:
                            line_hashes = seen_rt_line_hashes.setdefault(k, set())
                            if ev.raw_line_hash in line_hashes:
                                continue
                            line_hashes.add(ev.raw_line_hash)
                        pre_key_counts[k] = pre_key_counts.get(k, 0) + 1

    # Second pass: causal extraction + join + validation
    parse_stats: Dict[str, int] = {}
    extractor = LanlCausalFeatureExtractor(retention_seconds=config.retention_seconds)

    rows: List[LanlAuthDatasetRow] = []
    exact_dups = 0
    matched_count = 0
    ambig_count = 0
    label_dist = {"0": 0, "1": 0}

    for ev in iter_lanl_auth_gz(auth_path, stats=parse_stats, max_records=config.max_records):
        feats = extractor.process_event(ev, deduplicate=True)
        if feats.is_exact_duplicate:
            exact_dups += 1
            if config.exclude_duplicates:
                continue

        # Look up precomputed multiplicity for primary key if matched
        cand_hits = 0
        if ev.source_computer and ev.destination_computer:
            for u in (ev.destination_user, ev.source_user):
                if u and (ev.time_rel, u, ev.source_computer, ev.destination_computer) in rt_index._key_counts:
                    cand_hits = max(cand_hits, pre_key_counts.get((ev.time_rel, u, ev.source_computer, ev.destination_computer), 1))

        join_res = rt_index.match_event(ev, precomputed_key_hits=cand_hits if cand_hits > 0 else None)
        if join_res.label == 1:
            matched_count += 1
        if join_res.is_ambiguous:
            ambig_count += 1
            if config.exclude_ambiguous_redteam_matches:
                continue

        is_cross = 1 if (ev.source_computer and ev.destination_computer and ev.source_computer != ev.destination_computer) else 0
        row = LanlAuthDatasetRow(
            record_seq=ev.record_seq,
            time_rel=ev.time_rel,
            source_computer=ev.source_computer,
            destination_computer=ev.destination_computer,
            source_user=ev.source_user,
            destination_user=ev.destination_user,
            match_status=join_res.status,
            match_multiplicity=join_res.match_multiplicity,
            is_ambiguous_match=join_res.is_ambiguous,
            label=join_res.label,
            label_source=join_res.label_source,
            is_auth_failure=1 if ev.outcome == "Fail" else 0,
            is_cross_host=is_cross,
            auth_type_cat=ev.auth_type or "MISSING",
            logon_type_cat=ev.logon_type or "MISSING",
            auth_orientation_cat=ev.auth_orientation or "MISSING",
            lanl_fail_count_1m=feats.lanl_fail_count_1m,
            lanl_fail_count_5m=feats.lanl_fail_count_5m,
            lanl_fail_count_15m=feats.lanl_fail_count_15m,
            lanl_auth_count_15m=feats.lanl_auth_count_15m,
            lanl_unique_dest_users_15m=feats.lanl_unique_dest_users_15m,
            lanl_unique_dst_hosts_per_src_15m=feats.lanl_unique_dst_hosts_per_src_15m,
            lanl_logon_type_entropy_15m=feats.lanl_logon_type_entropy_15m,
            lanl_rel_hour_mod24=feats.lanl_rel_hour_mod24,
            lanl_fail_1m_available=feats.lanl_fail_1m_available,
            lanl_fail_5m_available=feats.lanl_fail_5m_available,
            lanl_fail_15m_available=feats.lanl_fail_15m_available,
            lanl_auth_15m_available=feats.lanl_auth_15m_available,
            lanl_unique_dest_users_15m_available=feats.lanl_unique_dest_users_15m_available,
            lanl_unique_dst_hosts_per_src_15m_available=feats.lanl_unique_dst_hosts_per_src_15m_available,
            lanl_logon_type_entropy_15m_available=feats.lanl_logon_type_entropy_15m_available,
            lanl_rel_hour_available=feats.lanl_rel_hour_available,
            unavailable_reasons=feats.unavailable_reasons,
        )
        validate_lanl_feature_row(row)
        rows.append(row)
        label_dist[str(row.label)] += 1

    out_path = output_dir / f"lanl_auth_features_v{config.dataset_version}.jsonl"
    with open(out_path, "w", encoding="utf-8", newline="\n") as out_f:
        for r in rows:
            out_f.write(json.dumps(r.to_ordered_dict(), sort_keys=False) + "\n")

    n_rows = len(rows)
    avail_rates = {
        col: round(sum(getattr(r, col) for r in rows) / n_rows, 6) if n_rows else 0.0
        for col in LANL_AVAILABILITY_COLUMNS
    }
    manifest = LanlDatasetManifest(
        schema_version=LANL_SCHEMA_VERSION,
        dataset_version=config.dataset_version,
        created_at_utc=created_at_utc_override or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        auth_input_sha256=auth_sha,
        redteam_input_sha256=redteam_sha,
        output_file=out_path.name,
        output_sha256=_sha256_file(out_path),
        total_auth_lines_read=parse_stats.get("lines_read", 0),
        malformed_auth_lines_skipped=parse_stats.get("malformed_lines", 0) + malformed_rt,
        exact_line_duplicates_skipped=exact_dups,
        redteam_annotations_total=rt_index.total_annotations,
        redteam_duplicate_annotations=rt_index.duplicate_annotation_count,
        redteam_matched_events=matched_count,
        redteam_ambiguous_matches=ambig_count,
        redteam_unmatched_annotations=len(rt_index.unmatched_annotation_keys),
        total_rows_exported=n_rows,
        label_distribution=label_dist,
        failure_sampling_caveat="Failed authentication records are only retained for accounts that had at least one successful auth in LANL Cyber1.",
        unmatched_label_caveat="Unmatched events indicate absence from redteam.txt compromise list, not independently verified clean enterprise activity.",
        feature_availability_rates=avail_rates,
        model_input_columns=LANL_MODEL_INPUT_COLUMNS,
    )
    manifest_path = output_dir / f"lanl_auth_features_v{config.dataset_version}.manifest.json"
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as mf:
        json.dump(asdict(manifest), mf, indent=2, sort_keys=True)

    return rows, manifest


def lanl_chronological_split_with_embargo(
    rows: Sequence[LanlAuthDatasetRow],
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
    embargo_seconds: int = 900,
) -> Dict[str, List[LanlAuthDatasetRow]]:
    ordered = sorted(rows, key=lambda r: (r.time_rel, r.record_seq))
    if not ordered:
        return {"train": [], "val": [], "test": [], "embargo_dropped": []}

    n = len(ordered)
    train_end_t = ordered[max(0, min(n - 1, int(n * train_ratio) - 1))].time_rel
    val_start_t = train_end_t + embargo_seconds

    train_rows: List[LanlAuthDatasetRow] = []
    val_candidates: List[LanlAuthDatasetRow] = []
    embargo_dropped: List[LanlAuthDatasetRow] = []
    for r in ordered:
        if r.time_rel <= train_end_t:
            train_rows.append(r)
        elif r.time_rel < val_start_t:
            embargo_dropped.append(r)
        else:
            val_candidates.append(r)

    if not val_candidates:
        return {"train": train_rows, "val": [], "test": [], "embargo_dropped": embargo_dropped}

    rel_val = val_ratio / (1.0 - train_ratio)
    val_end_t = val_candidates[max(0, min(len(val_candidates) - 1, int(len(val_candidates) * rel_val) - 1))].time_rel
    test_start_t = val_end_t + embargo_seconds

    val_rows: List[LanlAuthDatasetRow] = []
    test_rows: List[LanlAuthDatasetRow] = []
    for r in val_candidates:
        if r.time_rel <= val_end_t:
            val_rows.append(r)
        elif r.time_rel < test_start_t:
            embargo_dropped.append(r)
        else:
            test_rows.append(r)

    return {
        "train": train_rows,
        "val": val_rows,
        "test": test_rows,
        "embargo_dropped": embargo_dropped,
    }


def audit_lanl_partition_hygiene(
    splits: Dict[str, Sequence[LanlAuthDatasetRow]],
    min_embargo_seconds: int = 900,
) -> Dict[str, Any]:
    """
    Audits LANL splits for:
    - Zero shared record_seq across partitions
    - Strict >= min_embargo_seconds chronological gap
    - Overlap of positive red-team source/destination computers across splits
      (compromised attacker workstation shortcut risk).
    """
    seen_seqs: Dict[int, str] = {}
    pos_src_hosts: Dict[str, set] = {"train": set(), "val": set(), "test": set()}
    pos_dst_hosts: Dict[str, set] = {"train": set(), "val": set(), "test": set()}

    for part in ("train", "val", "test"):
        for r in splits.get(part, ()):
            if r.record_seq in seen_seqs:
                raise AssertionError(f"Duplicate record_seq {r.record_seq} in {seen_seqs[r.record_seq]} and {part}")
            seen_seqs[r.record_seq] = part
            if r.label == 1:
                if r.source_computer:
                    pos_src_hosts[part].add(r.source_computer)
                if r.destination_computer:
                    pos_dst_hosts[part].add(r.destination_computer)

    for earlier, later in (("train", "val"), ("val", "test")):
        er, lr = splits.get(earlier, ()), splits.get(later, ())
        if er and lr:
            gap = min(r.time_rel for r in lr) - max(r.time_rel for r in er)
            if gap < min_embargo_seconds:
                raise AssertionError(f"Embargo violation between {earlier} and {later}: {gap}s < {min_embargo_seconds}s")

    return {
        "train_test_shared_positive_src_hosts": sorted(pos_src_hosts["train"] & pos_src_hosts["test"]),
        "train_val_shared_positive_src_hosts": sorted(pos_src_hosts["train"] & pos_src_hosts["val"]),
        "train_test_shared_positive_dst_hosts": sorted(pos_dst_hosts["train"] & pos_dst_hosts["test"]),
    }


@dataclass(frozen=True)
class LanlBlockSpec:
    """Contiguous evaluation block definition with dedicated preceding causal warmup window."""

    name: str
    split_role: str  # "train", "val", "test", or "pilot"
    auth_gz_path: Path
    extract_start_t: int
    eval_start_t: int
    eval_end_t: int
    retention_seconds: int = SUPPORTED_RETENTION_SECONDS

    def __post_init__(self) -> None:
        if (
            isinstance(self.retention_seconds, bool)
            or int(self.retention_seconds) != SUPPORTED_RETENTION_SECONDS
        ):
            raise ValueError(
                f"Block '{self.name}' requires fixed retention_seconds={SUPPORTED_RETENTION_SECONDS}, "
                f"got {self.retention_seconds!r}"
            )
        if self.eval_start_t - self.extract_start_t < self.retention_seconds:
            raise ValueError(
                f"Block '{self.name}' warmup ({self.eval_start_t - self.extract_start_t}s) "
                f"< retention_seconds ({self.retention_seconds}s)"
            )
        if self.eval_end_t <= self.eval_start_t:
            raise ValueError(f"Block '{self.name}' eval_end_t must exceed eval_start_t")


def build_lanl_block_parquet_dataset(
    block_specs: Sequence[LanlBlockSpec],
    redteam_path: Path,
    output_dir: Path,
    dataset_version: str = "1.0.0",
    chunk_size: int = 50_000,
    max_output_bytes: int = 4 * 1024**3,
    exclude_duplicates: bool = True,
    exclude_ambiguous_redteam_matches: bool = False,
    compute_line_hash: bool = False,
    min_embargo_seconds: int = 900,
    source_raw_metadata: Optional[Dict[str, Any]] = None,
    created_at_utc_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Streams contiguous compressed LANL blocks through `iter_lanl_auth_gz`, `LanlCausalFeatureExtractor`,
    and `RedteamAnnotationIndex`, isolating causal warmup lead-in from exported rows and writing
    schema-pinned Zstd chunked Parquet partitions plus a complete provenance manifest.
    """
    import time
    import pyarrow as pa
    import pyarrow.parquet as pq

    ordered_blocks = sorted(block_specs, key=lambda b: b.eval_start_t)
    if not ordered_blocks:
        raise ValueError("block_specs must not be empty")

    for i in range(1, len(ordered_blocks)):
        prev_b, curr_b = ordered_blocks[i - 1], ordered_blocks[i]
        gap = curr_b.eval_start_t - prev_b.eval_end_t
        if gap < min_embargo_seconds:
            raise ValueError(
                f"Temporal separation violation between '{prev_b.name}' and '{curr_b.name}': "
                f"{gap}s < {min_embargo_seconds}s"
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    annotations, malformed_rt = load_redteam_annotations_gz(redteam_path)
    rt_index = RedteamAnnotationIndex(annotations)
    pq_schema = get_lanl_pyarrow_schema()

    t_run0 = time.perf_counter()
    seq_cursor = 0
    total_bytes_written = 0
    partition_summaries: List[Dict[str, Any]] = []
    pos_src_hosts_by_role: Dict[str, set] = {}
    pos_dst_hosts_by_role: Dict[str, set] = {}

    for spec in ordered_blocks:
        # First pass over block for exact multiplicity of matched redteam keys
        pre_key_counts: Dict[Tuple[int, str, str, str], int] = {}
        seen_rt_hashes: Dict[Tuple[int, str, str, str], set] = {}
        for ev in iter_lanl_auth_gz(spec.auth_gz_path, compute_line_hash=compute_line_hash):
            if ev.time_rel < spec.eval_start_t or ev.time_rel >= spec.eval_end_t:
                continue
            if ev.source_computer and ev.destination_computer:
                for u in {ev.destination_user, ev.source_user}:
                    if u:
                        k = (ev.time_rel, u, ev.source_computer, ev.destination_computer)
                        if k in rt_index._key_counts:
                            if exclude_duplicates:
                                hs = seen_rt_hashes.setdefault(k, set())
                                if ev.raw_line_hash in hs:
                                    continue
                                hs.add(ev.raw_line_hash)
                            pre_key_counts[k] = pre_key_counts.get(k, 0) + 1

        extractor = LanlCausalFeatureExtractor(retention_seconds=spec.retention_seconds)
        extractor.reset_for_block()

        pq_path = output_dir / f"{spec.name}_v{dataset_version}.parquet"
        writer = pq.ParquetWriter(pq_path, pq_schema, compression="zstd")
        chunk_rows: List[Dict[str, Any]] = []
        parse_stats: Dict[str, int] = {}
        warmup_rows = 0
        eval_rows = 0
        dup_skipped = 0
        ambig_skipped = 0
        ambig_retained = 0
        label_counts = {"0": 0, "1": 0}
        avail_sums = {col: 0 for col in LANL_AVAILABILITY_COLUMNS}
        missing_cat = {"auth_type_cat": 0, "logon_type_cat": 0}
        pos_outcomes = {"Success": 0, "Fail": 0}
        pos_src_hosts = set()
        pos_dst_hosts = set()
        min_eval_t = None
        max_eval_t = None

        try:
            for ev in iter_lanl_auth_gz(
                spec.auth_gz_path, stats=parse_stats, compute_line_hash=compute_line_hash
            ):
                if ev.time_rel < spec.extract_start_t:
                    continue
                if ev.time_rel >= spec.eval_end_t:
                    break

                feats = extractor.process_event(ev, deduplicate=exclude_duplicates)
                if feats.is_exact_duplicate:
                    dup_skipped += 1
                    continue

                if ev.time_rel < spec.eval_start_t:
                    warmup_rows += 1
                    continue

                cand_hits = 0
                if ev.source_computer and ev.destination_computer:
                    for u in (ev.destination_user, ev.source_user):
                        if u:
                            k = (ev.time_rel, u, ev.source_computer, ev.destination_computer)
                            if k in rt_index._key_counts:
                                cand_hits = max(cand_hits, pre_key_counts.get(k, 1))

                join_res = rt_index.match_event(
                    ev, precomputed_key_hits=cand_hits if cand_hits > 0 else None
                )
                if join_res.is_ambiguous:
                    if exclude_ambiguous_redteam_matches:
                        ambig_skipped += 1
                        continue
                    ambig_retained += 1

                seq_cursor += 1
                eval_rows += 1
                if min_eval_t is None or ev.time_rel < min_eval_t:
                    min_eval_t = ev.time_rel
                if max_eval_t is None or ev.time_rel > max_eval_t:
                    max_eval_t = ev.time_rel

                is_cross = (
                    1
                    if (
                        ev.source_computer
                        and ev.destination_computer
                        and ev.source_computer != ev.destination_computer
                    )
                    else 0
                )
                at_cat = ev.auth_type or "MISSING"
                lt_cat = ev.logon_type or "MISSING"
                if at_cat == "MISSING":
                    missing_cat["auth_type_cat"] += 1
                if lt_cat == "MISSING":
                    missing_cat["logon_type_cat"] += 1

                row = LanlAuthDatasetRow(
                    record_seq=seq_cursor,
                    time_rel=ev.time_rel,
                    source_computer=ev.source_computer,
                    destination_computer=ev.destination_computer,
                    source_user=ev.source_user,
                    destination_user=ev.destination_user,
                    match_status=join_res.status,
                    match_multiplicity=join_res.match_multiplicity,
                    is_ambiguous_match=join_res.is_ambiguous,
                    label=join_res.label,
                    label_source=join_res.label_source,
                    is_auth_failure=1 if ev.outcome == "Fail" else 0,
                    is_cross_host=is_cross,
                    auth_type_cat=at_cat,
                    logon_type_cat=lt_cat,
                    auth_orientation_cat=ev.auth_orientation or "MISSING",
                    lanl_fail_count_1m=feats.lanl_fail_count_1m,
                    lanl_fail_count_5m=feats.lanl_fail_count_5m,
                    lanl_fail_count_15m=feats.lanl_fail_count_15m,
                    lanl_auth_count_15m=feats.lanl_auth_count_15m,
                    lanl_unique_dest_users_15m=feats.lanl_unique_dest_users_15m,
                    lanl_unique_dst_hosts_per_src_15m=feats.lanl_unique_dst_hosts_per_src_15m,
                    lanl_logon_type_entropy_15m=feats.lanl_logon_type_entropy_15m,
                    lanl_rel_hour_mod24=feats.lanl_rel_hour_mod24,
                    lanl_fail_1m_available=feats.lanl_fail_1m_available,
                    lanl_fail_5m_available=feats.lanl_fail_5m_available,
                    lanl_fail_15m_available=feats.lanl_fail_15m_available,
                    lanl_auth_15m_available=feats.lanl_auth_15m_available,
                    lanl_unique_dest_users_15m_available=feats.lanl_unique_dest_users_15m_available,
                    lanl_unique_dst_hosts_per_src_15m_available=feats.lanl_unique_dst_hosts_per_src_15m_available,
                    lanl_logon_type_entropy_15m_available=feats.lanl_logon_type_entropy_15m_available,
                    lanl_rel_hour_available=feats.lanl_rel_hour_available,
                    unavailable_reasons=feats.unavailable_reasons,
                )
                validate_lanl_feature_row(row)

                label_counts[str(row.label)] += 1
                if row.label == 1:
                    pos_outcomes[ev.outcome] = pos_outcomes.get(ev.outcome, 0) + 1
                    if ev.source_computer:
                        pos_src_hosts.add(ev.source_computer)
                    if ev.destination_computer:
                        pos_dst_hosts.add(ev.destination_computer)
                for col in LANL_AVAILABILITY_COLUMNS:
                    avail_sums[col] += getattr(row, col)

                rd = row.to_ordered_dict()
                rd["unavailable_reasons"] = (
                    json.dumps(rd["unavailable_reasons"], sort_keys=True)
                    if rd["unavailable_reasons"]
                    else ""
                )
                chunk_rows.append(rd)
                if len(chunk_rows) >= chunk_size:
                    tbl = pa.Table.from_pylist(chunk_rows, schema=pq_schema)
                    writer.write_table(tbl)
                    chunk_rows.clear()
                    if pq_path.exists() and (total_bytes_written + pq_path.stat().st_size) > max_output_bytes:
                        raise RuntimeError(
                            f"Output size exceeded max_output_bytes={max_output_bytes}"
                        )

            if chunk_rows:
                tbl = pa.Table.from_pylist(chunk_rows, schema=pq_schema)
                writer.write_table(tbl)
                chunk_rows.clear()
        except Exception:
            writer.close()
            if pq_path.exists():
                pq_path.unlink()
            raise
        finally:
            writer.close()

        pq_bytes = pq_path.stat().st_size
        total_bytes_written += pq_bytes
        if total_bytes_written > max_output_bytes:
            raise RuntimeError(
                f"Total Parquet output ({total_bytes_written} B) exceeded max_output_bytes={max_output_bytes}"
            )

        pos_src_hosts_by_role.setdefault(spec.split_role, set()).update(pos_src_hosts)
        pos_dst_hosts_by_role.setdefault(spec.split_role, set()).update(pos_dst_hosts)

        partition_summaries.append(
            {
                "name": spec.name,
                "split_role": spec.split_role,
                "extract_start_t": spec.extract_start_t,
                "eval_start_t": spec.eval_start_t,
                "eval_end_t": spec.eval_end_t,
                "warmup_rows_processed": warmup_rows,
                "eval_rows_exported": eval_rows,
                "min_eval_time_rel": min_eval_t,
                "max_eval_time_rel": max_eval_t,
                "malformed_lines_skipped": parse_stats.get("malformed_lines", 0),
                "duplicate_lines_skipped": dup_skipped,
                "ambiguous_matches_retained": ambig_retained,
                "ambiguous_matches_skipped": ambig_skipped,
                "label_distribution": label_counts,
                "positive_rate": round(label_counts["1"] / eval_rows, 8) if eval_rows else 0.0,
                "positive_outcome_distribution": pos_outcomes,
                "positive_source_hosts": sorted(pos_src_hosts),
                "missing_categorical_counts": missing_cat,
                "feature_availability_rates": {
                    c: round(avail_sums[c] / eval_rows, 6) if eval_rows else 0.0
                    for c in LANL_AVAILABILITY_COLUMNS
                },
                "output_parquet_file": pq_path.name,
                "output_parquet_bytes": pq_bytes,
                "output_parquet_sha256": _sha256_file(pq_path),
            }
        )

    elapsed_total = round(time.perf_counter() - t_run0, 2)
    roles = sorted(pos_src_hosts_by_role.keys())
    src_host_overlaps: Dict[str, List[str]] = {}
    for i in range(len(roles)):
        for j in range(i + 1, len(roles)):
            r1, r2 = roles[i], roles[j]
            src_host_overlaps[f"{r1}_vs_{r2}"] = sorted(
                pos_src_hosts_by_role[r1] & pos_src_hosts_by_role[r2]
            )

    manifest = {
        "schema_version": LANL_SCHEMA_VERSION,
        "dataset_version": dataset_version,
        "parser_version": "ml.lanl_benchmark.parser_v1",
        "created_at_utc": created_at_utc_override
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "raw_source_metadata": source_raw_metadata or {},
        "redteam_input_sha256": _sha256_file(redteam_path),
        "redteam_malformed_lines": malformed_rt,
        "model_input_columns": list(LANL_MODEL_INPUT_COLUMNS),
        "label_assignment_policy": {
            "positive_definition": "Exact match against LANL redteam.txt.gz (time_rel, user@domain, source_computer, destination_computer).",
            "unmatched_semantics": "UNMATCHED_NON_REDTEAM means unannotated background traffic, not independently proven clean activity.",
            "ambiguous_record_handling": "excluded" if exclude_ambiguous_redteam_matches else "retained_with_flag",
            "duplicate_line_handling": "deduplicated" if exclude_duplicates else "retained",
        },
        "partitions": partition_summaries,
        "total_eval_rows_exported": sum(p["eval_rows_exported"] for p in partition_summaries),
        "total_positives_exported": sum(p["label_distribution"]["1"] for p in partition_summaries),
        "total_output_parquet_bytes": total_bytes_written,
        "compromised_source_host_overlap_audit": src_host_overlaps,
        "measured_elapsed_seconds": elapsed_total,
        "known_limitations": [
            "Failed authentication events exist only for users with >=1 successful auth in LANL Cyber1.",
            "lanl_rel_hour_mod24 is relative integer offset mod 24, not local timezone time of day; treat as optional ablation feature.",
            "Positive red-team events cluster across only 4 source hosts (dominated by C17693), causing conflict between chronological splitting and source-host disjointness.",
        ],
    }

    manifest_path = output_dir / f"lanl_research_subset_v{dataset_version}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest
