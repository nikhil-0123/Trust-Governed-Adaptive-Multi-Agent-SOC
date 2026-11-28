"""
Research-only feature schema `lanl_auth_features_v1` for LANL Cyber1 authentication logs.
"""

from dataclasses import dataclass, field, asdict
import math
from typing import Any, Dict, Optional, Tuple

LANL_SCHEMA_VERSION = "lanl_auth_features_v1"

LANL_FEATURE_COLUMNS: Tuple[str, ...] = (
    "lanl_fail_count_1m",
    "lanl_fail_count_5m",
    "lanl_fail_count_15m",
    "lanl_auth_count_15m",
    "lanl_unique_dest_users_15m",
    "lanl_unique_dst_hosts_per_src_15m",
    "lanl_logon_type_entropy_15m",
    "lanl_rel_hour_mod24",
)

LANL_AVAILABILITY_COLUMNS: Tuple[str, ...] = (
    "lanl_fail_1m_available",
    "lanl_fail_5m_available",
    "lanl_fail_15m_available",
    "lanl_auth_15m_available",
    "lanl_unique_dest_users_15m_available",
    "lanl_unique_dst_hosts_per_src_15m_available",
    "lanl_logon_type_entropy_15m_available",
    "lanl_rel_hour_available",
)

# Current-record LANL fields safely observable at prediction time
LANL_CONTEXT_COLUMNS: Tuple[str, ...] = (
    "is_auth_failure",
    "is_cross_host",
    "auth_type_cat",
    "logon_type_cat",
    "auth_orientation_cat",
)

LANL_MODEL_INPUT_COLUMNS: Tuple[str, ...] = (
    LANL_FEATURE_COLUMNS + LANL_AVAILABILITY_COLUMNS + LANL_CONTEXT_COLUMNS
)

LANL_PROVENANCE_COLUMNS: Tuple[str, ...] = (
    "record_seq",
    "time_rel",
    "source_computer",
    "destination_computer",
    "source_user",
    "destination_user",
    "match_status",
    "match_multiplicity",
    "is_ambiguous_match",
    "label",
    "label_source",
)


@dataclass(frozen=True)
class LanlRawAuthEvent:
    """Validated parsed record from LANL Cyber1 auth.txt.gz (no fabricated fields)."""
    record_seq: int
    time_rel: int
    source_user: Optional[str]
    destination_user: Optional[str]
    source_computer: Optional[str]
    destination_computer: Optional[str]
    auth_type: Optional[str]
    logon_type: Optional[str]
    auth_orientation: Optional[str]
    outcome: str  # "Success" or "Fail"
    raw_line_hash: str


@dataclass(frozen=True)
class LanlRedteamAnnotation:
    """Validated ground-truth entry from LANL Cyber1 redteam.txt.gz."""
    annotation_seq: int
    time_rel: int
    user_domain: str
    source_computer: str
    destination_computer: str


@dataclass(frozen=True)
class LanlAuthDatasetRow:
    """Processed, leakage-checked feature row conforming to `lanl_auth_features_v1`."""
    record_seq: int
    time_rel: int
    source_computer: Optional[str]
    destination_computer: Optional[str]
    source_user: Optional[str]
    destination_user: Optional[str]
    match_status: str
    match_multiplicity: int
    is_ambiguous_match: bool
    label: int
    label_source: str

    # Prediction-time context
    is_auth_failure: int
    is_cross_host: int
    auth_type_cat: str
    logon_type_cat: str
    auth_orientation_cat: str

    # Causal rolling features
    lanl_fail_count_1m: Optional[float]
    lanl_fail_count_5m: Optional[float]
    lanl_fail_count_15m: Optional[float]
    lanl_auth_count_15m: Optional[float]
    lanl_unique_dest_users_15m: Optional[float]
    lanl_unique_dst_hosts_per_src_15m: Optional[float]
    lanl_logon_type_entropy_15m: Optional[float]
    lanl_rel_hour_mod24: float

    # Availability flags
    lanl_fail_1m_available: int
    lanl_fail_5m_available: int
    lanl_fail_15m_available: int
    lanl_auth_15m_available: int
    lanl_unique_dest_users_15m_available: int
    lanl_unique_dst_hosts_per_src_15m_available: int
    lanl_logon_type_entropy_15m_available: int
    lanl_rel_hour_available: int

    unavailable_reasons: Dict[str, str] = field(default_factory=dict)

    def to_ordered_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        ordered: Dict[str, Any] = {}
        for c in LANL_PROVENANCE_COLUMNS + LANL_CONTEXT_COLUMNS + LANL_FEATURE_COLUMNS + LANL_AVAILABILITY_COLUMNS:
            ordered[c] = d[c]
        ordered["unavailable_reasons"] = d["unavailable_reasons"]
        return ordered

    def to_model_feature_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {c: d[c] for c in LANL_MODEL_INPUT_COLUMNS}


@dataclass(frozen=True)
class LanlDatasetManifest:
    schema_version: str
    dataset_version: str
    created_at_utc: str
    auth_input_sha256: str
    redteam_input_sha256: str
    output_file: str
    output_sha256: str
    total_auth_lines_read: int
    malformed_auth_lines_skipped: int
    exact_line_duplicates_skipped: int
    redteam_annotations_total: int
    redteam_duplicate_annotations: int
    redteam_matched_events: int
    redteam_ambiguous_matches: int
    redteam_unmatched_annotations: int
    total_rows_exported: int
    label_distribution: Dict[str, int]
    failure_sampling_caveat: str
    unmatched_label_caveat: str
    feature_availability_rates: Dict[str, float]
    model_input_columns: Tuple[str, ...]


def _check_num(val: Optional[float], avail: int, name: str, lo: float, hi: Optional[float] = None) -> None:
    if avail not in (0, 1):
        raise ValueError(f"Availability flag for {name} must be 0 or 1, got {avail!r}")
    if avail == 1 and val is None:
        raise ValueError(f"{name} marked available=1 but value is None")
    if avail == 0 and val is not None:
        raise ValueError(f"{name} marked available=0 but value is {val!r}")
    if val is None:
        return
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise TypeError(f"{name} must be float/int, got {type(val).__name__}")
    f = float(val)
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"{name} must be finite, got {val!r}")
    if f < lo or (hi is not None and f > hi):
        raise ValueError(f"{name} out of bounds [{lo}, {hi}]: {f}")


def validate_lanl_feature_row(row: LanlAuthDatasetRow) -> None:
    if row.time_rel < 1:
        raise ValueError(f"LANL time_rel must be >= 1, got {row.time_rel}")
    if row.label not in (0, 1) or isinstance(row.label, bool):
        raise ValueError(f"label must be 0 or 1, got {row.label!r}")
    if row.is_auth_failure not in (0, 1) or row.is_cross_host not in (0, 1):
        raise ValueError("Binary context indicators must be 0 or 1")

    checks = [
        ("lanl_fail_count_1m", row.lanl_fail_count_1m, row.lanl_fail_1m_available, 0.0, None),
        ("lanl_fail_count_5m", row.lanl_fail_count_5m, row.lanl_fail_5m_available, 0.0, None),
        ("lanl_fail_count_15m", row.lanl_fail_count_15m, row.lanl_fail_15m_available, 0.0, None),
        ("lanl_auth_count_15m", row.lanl_auth_count_15m, row.lanl_auth_15m_available, 0.0, None),
        ("lanl_unique_dest_users_15m", row.lanl_unique_dest_users_15m, row.lanl_unique_dest_users_15m_available, 0.0, None),
        ("lanl_unique_dst_hosts_per_src_15m", row.lanl_unique_dst_hosts_per_src_15m, row.lanl_unique_dst_hosts_per_src_15m_available, 0.0, None),
        ("lanl_logon_type_entropy_15m", row.lanl_logon_type_entropy_15m, row.lanl_logon_type_entropy_15m_available, 0.0, None),
        ("lanl_rel_hour_mod24", row.lanl_rel_hour_mod24, row.lanl_rel_hour_available, 0.0, 23.0),
    ]
    for name, val, avail, lo, hi in checks:
        _check_num(val, avail, name, lo, hi)

    if row.lanl_fail_1m_available and row.lanl_fail_5m_available:
        if row.lanl_fail_count_1m > row.lanl_fail_count_5m:
            raise ValueError("Window invariant violated: 1m fail count > 5m fail count")
    if row.lanl_fail_5m_available and row.lanl_fail_15m_available:
        if row.lanl_fail_count_5m > row.lanl_fail_count_15m:
            raise ValueError("Window invariant violated: 5m fail count > 15m fail count")
    if row.lanl_fail_15m_available and row.lanl_auth_15m_available:
        if row.lanl_fail_count_15m > row.lanl_auth_count_15m:
            raise ValueError("Window invariant violated: 15m fail count > 15m total auth count")


def normalize_lanl_auth_type_family(auth_type: Optional[str]) -> str:
    """
    Canonicalizes genuine LANL truncated auth_type prefixes (e.g.
    `MICROSOFT_AUTHENTICATION_PACKAG` -> `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`)
    for optional normalized analysis without altering raw `auth_type_cat`.
    """
    if auth_type is None:
        return "MISSING"
    s = auth_type.strip()
    if not s or s == "?":
        return "MISSING"
    if s.startswith("MICROSOFT_AUTHENTICAT"):
        return "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
    if s.startswith("NETWARE_AUTHENTICATION"):
        return "NETWARE_AUTHENTICATION_PACKAGE_V1_0"
    return s


def get_lanl_pyarrow_schema():
    """
    Returns an explicit fixed PyArrow schema for `lanl_auth_features_v1` chunked Parquet
    writes so warmup chunks containing all-null rolling features preserve `float64` typing.
    """
    import pyarrow as pa

    return pa.schema(
        [
            ("record_seq", pa.int64()),
            ("time_rel", pa.int64()),
            ("source_computer", pa.string()),
            ("destination_computer", pa.string()),
            ("source_user", pa.string()),
            ("destination_user", pa.string()),
            ("match_status", pa.string()),
            ("match_multiplicity", pa.int64()),
            ("is_ambiguous_match", pa.bool_()),
            ("label", pa.int64()),
            ("label_source", pa.string()),
            ("is_auth_failure", pa.int64()),
            ("is_cross_host", pa.int64()),
            ("auth_type_cat", pa.string()),
            ("logon_type_cat", pa.string()),
            ("auth_orientation_cat", pa.string()),
            ("lanl_fail_count_1m", pa.float64()),
            ("lanl_fail_count_5m", pa.float64()),
            ("lanl_fail_count_15m", pa.float64()),
            ("lanl_auth_count_15m", pa.float64()),
            ("lanl_unique_dest_users_15m", pa.float64()),
            ("lanl_unique_dst_hosts_per_src_15m", pa.float64()),
            ("lanl_logon_type_entropy_15m", pa.float64()),
            ("lanl_rel_hour_mod24", pa.float64()),
            ("lanl_fail_1m_available", pa.int64()),
            ("lanl_fail_5m_available", pa.int64()),
            ("lanl_fail_15m_available", pa.int64()),
            ("lanl_auth_15m_available", pa.int64()),
            ("lanl_unique_dest_users_15m_available", pa.int64()),
            ("lanl_unique_dst_hosts_per_src_15m_available", pa.int64()),
            ("lanl_logon_type_entropy_15m_available", pa.int64()),
            ("lanl_rel_hour_available", pa.int64()),
            ("unavailable_reasons", pa.string()),
        ]
    )
