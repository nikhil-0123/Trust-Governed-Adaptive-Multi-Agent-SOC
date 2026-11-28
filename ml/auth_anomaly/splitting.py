"""
Leakage-Prevention Partitioning Utilities for Time-Series Endpoint Telemetry.

Prohibits random row-level splits over overlapping sliding feature windows.
Enforces chronological splitting with explicit embargo gaps (>= retention horizon),
scenario-grouped assignment, and combined chronological + scenario partition checks.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple
from .schema import AuthDatasetRow


def chronological_split_with_embargo(
    rows: Sequence[AuthDatasetRow],
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
    embargo_seconds: float = 900.0,
) -> Dict[str, List[AuthDatasetRow]]:
    """
    Splits chronologically ordered rows into train / val / test with hard temporal
    embargo zones (>= 900s) between splits so no sliding window [t - 900, t)
    shares observations across split boundaries.

    Rows falling inside embargo gaps are dropped from both adjacent partitions.
    """
    if not (0.0 < train_ratio < 1.0) or not (0.0 < val_ratio < 1.0) or (train_ratio + val_ratio >= 1.0):
        raise ValueError("train_ratio and val_ratio must be > 0 and sum to < 1.0")
    if embargo_seconds < 0.0:
        raise ValueError("embargo_seconds must be non-negative")

    ordered = sorted(rows, key=lambda r: (r.timestamp_epoch, r.raw_record_id, r.event_id))
    if not ordered:
        return {"train": [], "val": [], "test": [], "embargo_dropped": []}

    n = len(ordered)
    train_cut_idx = max(0, min(n - 1, int(n * train_ratio) - 1))

    train_end_t = ordered[train_cut_idx].timestamp_epoch
    val_start_t = train_end_t + embargo_seconds

    train_rows: List[AuthDatasetRow] = []
    val_candidates: List[AuthDatasetRow] = []
    embargo_dropped: List[AuthDatasetRow] = []

    for r in ordered:
        if r.timestamp_epoch <= train_end_t:
            train_rows.append(r)
        elif r.timestamp_epoch < val_start_t:
            embargo_dropped.append(r)
        else:
            val_candidates.append(r)

    if not val_candidates:
        return {"train": train_rows, "val": [], "test": [], "embargo_dropped": embargo_dropped}

    rel_val_share = val_ratio / (1.0 - train_ratio)
    val_rel_idx = max(0, min(len(val_candidates) - 1, int(len(val_candidates) * rel_val_share) - 1))
    val_end_t = val_candidates[val_rel_idx].timestamp_epoch
    test_start_t = val_end_t + embargo_seconds

    val_rows: List[AuthDatasetRow] = []
    test_rows: List[AuthDatasetRow] = []
    for r in val_candidates:
        if r.timestamp_epoch <= val_end_t:
            val_rows.append(r)
        elif r.timestamp_epoch < test_start_t:
            embargo_dropped.append(r)
        else:
            test_rows.append(r)

    return {
        "train": train_rows,
        "val": val_rows,
        "test": test_rows,
        "embargo_dropped": embargo_dropped,
    }


def scenario_grouped_split(
    rows: Sequence[AuthDatasetRow],
    scenario_to_partition: Dict[str, str],
) -> Dict[str, List[AuthDatasetRow]]:
    """
    Assigns entire scenario_ids exclusively to one partition ('train', 'val', 'test')
    and validates that no scenario spans multiple splits.
    """
    valid_parts = {"train", "val", "test"}
    splits: Dict[str, List[AuthDatasetRow]] = {"train": [], "val": [], "test": []}

    for r in sorted(rows, key=lambda x: (x.timestamp_epoch, x.raw_record_id, x.event_id)):
        part = scenario_to_partition.get(r.scenario_id)
        if part not in valid_parts:
            raise ValueError(
                f"Scenario '{r.scenario_id}' has invalid/missing partition assignment '{part}'. "
                f"Expected one of {sorted(valid_parts)}."
            )
        splits[part].append(r)

    return splits


def combined_chronological_scenario_split(
    rows: Sequence[AuthDatasetRow],
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
    embargo_seconds: float = 900.0,
) -> Dict[str, Any]:
    """
    Combined scenario-grouped + chronological split with hard temporal embargo >= 900s.
    Whole scenario_ids are assigned monotonically in chronological scenario blocks;
    scenarios overlapping an embargo boundary are placed into 'embargo_dropped' so no
    scenario is split and no sliding window overlaps across train/val/test.
    """
    if not (0.0 < train_ratio < 1.0) or not (0.0 < val_ratio < 1.0) or (train_ratio + val_ratio >= 1.0):
        raise ValueError("train_ratio and val_ratio must be > 0 and sum to < 1.0")
    if embargo_seconds < 0.0:
        raise ValueError("embargo_seconds must be non-negative")

    by_scenario: Dict[str, List[AuthDatasetRow]] = {}
    for r in rows:
        by_scenario.setdefault(r.scenario_id, []).append(r)

    scenario_blocks = []
    for sc_id, sc_rows in by_scenario.items():
        min_t = min(x.timestamp_epoch for x in sc_rows)
        max_t = max(x.timestamp_epoch for x in sc_rows)
        scenario_blocks.append((min_t, max_t, sc_id, sorted(sc_rows, key=lambda x: (x.timestamp_epoch, x.raw_record_id, x.event_id))))
    scenario_blocks.sort(key=lambda b: (b[0], b[1], b[2]))

    total_rows = len(rows)
    if total_rows == 0 or len(scenario_blocks) < 3:
        return {
            "train": list(rows) if len(scenario_blocks) > 0 else [],
            "val": [],
            "test": [],
            "embargo_dropped": [],
            "sufficient_for_3way_split": False,
            "reason": f"Need at least 3 disjoint chronological scenarios for 3-way split, found {len(scenario_blocks)}.",
        }

    train_target = total_rows * train_ratio
    val_target = total_rows * val_ratio

    train_rows: List[AuthDatasetRow] = []
    val_rows: List[AuthDatasetRow] = []
    test_rows: List[AuthDatasetRow] = []
    embargo_dropped: List[AuthDatasetRow] = []

    phase = "train"
    train_max_t: Optional[float] = None
    val_max_t: Optional[float] = None

    for idx, (min_t, max_t, sc_id, sc_rows) in enumerate(scenario_blocks):
        remaining_scenarios = len(scenario_blocks) - idx
        if phase == "train":
            if len(train_rows) < train_target and remaining_scenarios >= 3:
                train_rows.extend(sc_rows)
                train_max_t = max_t if train_max_t is None else max(train_max_t, max_t)
                continue
            elif not train_rows:
                train_rows.extend(sc_rows)
                train_max_t = max_t
                continue
            else:
                phase = "val"

        if phase == "val":
            if train_max_t is not None and min_t < train_max_t + embargo_seconds:
                embargo_dropped.extend(sc_rows)
                continue
            if len(val_rows) < val_target and remaining_scenarios >= 2:
                val_rows.extend(sc_rows)
                val_max_t = max_t if val_max_t is None else max(val_max_t, max_t)
                continue
            elif not val_rows:
                val_rows.extend(sc_rows)
                val_max_t = max_t
                continue
            else:
                phase = "test"

        if phase == "test":
            boundary_t = val_max_t if val_max_t is not None else train_max_t
            if boundary_t is not None and min_t < boundary_t + embargo_seconds:
                embargo_dropped.extend(sc_rows)
                continue
            test_rows.extend(sc_rows)

    sufficient = bool(train_rows and val_rows and test_rows)
    return {
        "train": train_rows,
        "val": val_rows,
        "test": test_rows,
        "embargo_dropped": embargo_dropped,
        "sufficient_for_3way_split": sufficient,
        "reason": None if sufficient else "Insufficient non-overlapping scenarios after enforcing embargo separation.",
    }


def assert_no_partition_leakage(
    splits: Dict[str, Sequence[AuthDatasetRow]],
    require_disjoint_scenarios: bool = True,
    min_chronological_embargo_seconds: float = 0.0,
) -> None:
    """
    Programmatically verifies partition hygiene:
    - Zero duplicate event_id across train/val/test.
    - Optional zero shared scenario_id across train/val/test.
    - Optional chronological embargo gap between train -> val -> test.
    """
    seen_event_ids: Dict[str, str] = {}
    seen_scenarios: Dict[str, str] = {}

    for part_name in ("train", "val", "test"):
        for r in splits.get(part_name, ()):
            if r.event_id in seen_event_ids:
                raise AssertionError(
                    f"Data leakage: event_id '{r.event_id}' appears in both '{seen_event_ids[r.event_id]}' and '{part_name}'"
                )
            seen_event_ids[r.event_id] = part_name

            if require_disjoint_scenarios:
                if r.scenario_id in seen_scenarios and seen_scenarios[r.scenario_id] != part_name:
                    raise AssertionError(
                        f"Scenario leakage: scenario_id '{r.scenario_id}' split across '{seen_scenarios[r.scenario_id]}' and '{part_name}'"
                    )
                seen_scenarios[r.scenario_id] = part_name

    if min_chronological_embargo_seconds > 0.0:
        pairs: List[Tuple[str, str]] = [("train", "val"), ("val", "test")]
        for earlier, later in pairs:
            early_rows = splits.get(earlier, ())
            late_rows = splits.get(later, ())
            if early_rows and late_rows:
                max_early = max(r.timestamp_epoch for r in early_rows)
                min_late = min(r.timestamp_epoch for r in late_rows)
                gap = min_late - max_early
                if gap < min_chronological_embargo_seconds:
                    raise AssertionError(
                        f"Temporal window overlap: gap between '{earlier}' max ({max_early}) and "
                        f"'{later}' min ({min_late}) is {gap:.2f}s < required {min_chronological_embargo_seconds:.2f}s"
                    )
