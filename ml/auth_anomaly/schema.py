"""
Explicit schema, validation, and sanitization contract for the Phase 3A
Windows authentication anomaly dataset pipeline.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import hmac
import math
from typing import Any, Dict, List, Optional, Tuple

DATASET_SCHEMA_VERSION = "auth_anomaly_features_v1"

# Ordered deterministic feature columns matching windows-telemetry/detection/features.py
FEATURE_COLUMNS: Tuple[str, ...] = (
    "f1_failed_logins_1m",
    "f2_failed_logins_5m",
    "f3_failed_logins_15m",
    "f4_unique_users_per_ip_15m",
    "f5_logon_type_entropy_15m",
    "f6_hour_of_day",
    "f7_is_off_hours",
)

AVAILABILITY_COLUMNS: Tuple[str, ...] = (
    "f1_available",
    "f2_available",
    "f3_available",
    "f4_available",
    "f5_available",
    "f6_available",
    "f7_available",
)

# Prediction-time context columns safe against target/future leakage
CONTEXT_FEATURE_COLUMNS: Tuple[str, ...] = (
    "windows_event_id",
    "is_auth_failure",
    "logon_type",
)

# Full ordered feature matrix columns (excludes labels, baseline rule flags, and identifiers)
MODEL_INPUT_COLUMNS: Tuple[str, ...] = (
    FEATURE_COLUMNS + AVAILABILITY_COLUMNS + CONTEXT_FEATURE_COLUMNS
)

PROVENANCE_COLUMNS: Tuple[str, ...] = (
    "event_id",
    "raw_record_id",
    "timestamp_utc",
    "timestamp_epoch",
    "host_pseudonym",
    "source_ip_pseudonym",
    "account_pseudonym",
    "can_predict",
    "telemetry_origin",
    "scenario_id",
    "label",
    "label_source",
    "baseline_rule_bruteforce_detected",
)

# Bounded validation ranges
MAX_SUPPORTED_ENTROPY_BITS = math.log2(11) + 1e-6


class TelemetryOrigin(str, Enum):
    GENUINE_WINDOWS = "genuine_windows"
    AUTHORIZED_CONTROLLED_TEST = "authorized_controlled_test"
    SIMULATED_TEST_FIXTURE = "simulated_test_fixture"


@dataclass(frozen=True)
class LabelAssignment:
    """Explicit ground-truth label record with provenance; never inferred from rules alone."""
    scenario_id: str
    label: int  # 0 = benign, 1 = suspicious/attack
    label_source: str  # e.g., "scenario_manifest_run_2026_11_27", "baseline_normal_log"
    telemetry_origin: str
    start_epoch: float
    end_epoch: float
    host: Optional[str] = None
    source_ip: Optional[str] = None
    source_ip_pseudonym: Optional[str] = None
    event_ids: Optional[Tuple[str, ...]] = None

    def __post_init__(self):
        if not self.scenario_id or not str(self.scenario_id).strip():
            raise ValueError("scenario_id must be a non-empty string")
        if self.label not in (0, 1) or isinstance(self.label, bool):
            raise ValueError(f"label must be integer 0 or 1, got {self.label!r}")
        if not self.label_source or not str(self.label_source).strip():
            raise ValueError("label_source must be non-empty")
        valid_origins = {o.value for o in TelemetryOrigin}
        if self.telemetry_origin not in valid_origins:
            raise ValueError(
                f"Invalid telemetry_origin '{self.telemetry_origin}'. Must be one of {sorted(valid_origins)}"
            )
        if not math.isfinite(self.start_epoch) or not math.isfinite(self.end_epoch):
            raise ValueError("start_epoch and end_epoch must be finite floats")
        if self.end_epoch < self.start_epoch:
            raise ValueError("end_epoch cannot be less than start_epoch")


@dataclass(frozen=True)
class AuthDatasetRow:
    """Single validated, identifier-sanitized row in the offline authentication dataset."""
    # Provenance & target
    event_id: str
    raw_record_id: int
    timestamp_utc: str
    timestamp_epoch: float
    host_pseudonym: str
    source_ip_pseudonym: Optional[str]
    account_pseudonym: Optional[str]
    can_predict: bool
    telemetry_origin: str
    scenario_id: str
    label: int
    label_source: str
    baseline_rule_bruteforce_detected: bool

    # Prediction-time context
    windows_event_id: int
    is_auth_failure: int
    logon_type: Optional[float]

    # Point-in-time feature vector (f1-f7) + availability flags
    f1_failed_logins_1m: Optional[float]
    f2_failed_logins_5m: Optional[float]
    f3_failed_logins_15m: Optional[float]
    f4_unique_users_per_ip_15m: Optional[float]
    f5_logon_type_entropy_15m: Optional[float]
    f6_hour_of_day: Optional[float]
    f7_is_off_hours: Optional[float]

    f1_available: int
    f2_available: int
    f3_available: int
    f4_available: int
    f5_available: int
    f6_available: int
    f7_available: int

    # Explicit unavailability reasons (excluded from ML matrix, retained for audit)
    unavailable_reasons: Dict[str, str] = field(default_factory=dict)

    def to_ordered_dict(self) -> Dict[str, Any]:
        """Returns dictionary with deterministic canonical column ordering."""
        ordered: Dict[str, Any] = {}
        d = asdict(self)
        for col in PROVENANCE_COLUMNS + CONTEXT_FEATURE_COLUMNS + FEATURE_COLUMNS + AVAILABILITY_COLUMNS:
            ordered[col] = d[col]
        ordered["unavailable_reasons"] = d["unavailable_reasons"]
        return ordered

    def to_model_feature_dict(self) -> Dict[str, Optional[float]]:
        """Returns strictly model-safe features (never contains labels, IDs, or rule outputs)."""
        d = asdict(self)
        return {col: float(d[col]) if d[col] is not None else None for col in MODEL_INPUT_COLUMNS}


@dataclass(frozen=True)
class DatasetManifest:
    """Deterministic provenance and validation manifest for a generated dataset."""
    schema_version: str
    dataset_version: str
    dataset_name: str
    created_at_utc: str
    input_checksums: Dict[str, str]
    output_file: str
    output_sha256: str
    output_format: str
    total_raw_records: int
    total_auth_records: int
    total_rows_exported: int
    excluded_late_or_invalid_rows: int
    duplicate_records_skipped: int
    label_distribution: Dict[str, int]
    telemetry_origin_distribution: Dict[str, int]
    feature_availability_rates: Dict[str, float]
    feature_columns: Tuple[str, ...]
    model_input_columns: Tuple[str, ...]
    business_hours_config: Dict[str, Any]
    identifier_sanitization: str
    leakage_guarantees: Tuple[str, ...]


def pseudonymize_identifier(value: Optional[str], salt: str, prefix: str = "id") -> Optional[str]:
    """
    Deterministically pseudonymizes sensitive identifiers (usernames, IPs, hostnames)
    using HMAC-SHA256 so grouping properties survive without storing raw PII/secrets.
    """
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned or cleaned == "-":
        return None
    digest = hmac.new(
        salt.encode("utf-8"),
        cleaned.lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _check_optional_numeric(val: Optional[float], name: str, min_val: float, max_val: Optional[float] = None) -> None:
    if val is None:
        return
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise TypeError(f"{name} must be int/float or None, got {type(val).__name__}")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval):
        raise ValueError(f"{name} must be finite when present, got {val!r}")
    if fval < min_val:
        raise ValueError(f"{name} must be >= {min_val}, got {fval}")
    if max_val is not None and fval > max_val:
        raise ValueError(f"{name} must be <= {max_val}, got {fval}")


def validate_feature_row(row: AuthDatasetRow) -> None:
    """Enforces schema types, finiteness, mathematical invariants, and missingness consistency."""
    if row.label not in (0, 1) or isinstance(row.label, bool):
        raise ValueError(f"Invalid label: {row.label!r}")
    if row.windows_event_id not in (4624, 4625):
        raise ValueError(f"Invalid windows_event_id: {row.windows_event_id}")
    if row.is_auth_failure not in (0, 1):
        raise ValueError(f"Invalid is_auth_failure: {row.is_auth_failure}")
    _check_optional_numeric(row.logon_type, "logon_type", 0.0, 255.0)

    # Validate availability flags match feature None/non-None state
    pairs = [
        ("f1_failed_logins_1m", row.f1_failed_logins_1m, row.f1_available, 0.0, None),
        ("f2_failed_logins_5m", row.f2_failed_logins_5m, row.f2_available, 0.0, None),
        ("f3_failed_logins_15m", row.f3_failed_logins_15m, row.f3_available, 0.0, None),
        ("f4_unique_users_per_ip_15m", row.f4_unique_users_per_ip_15m, row.f4_available, 0.0, None),
        ("f5_logon_type_entropy_15m", row.f5_logon_type_entropy_15m, row.f5_available, 0.0, MAX_SUPPORTED_ENTROPY_BITS),
        ("f6_hour_of_day", row.f6_hour_of_day, row.f6_available, 0.0, 23.0),
        ("f7_is_off_hours", row.f7_is_off_hours, row.f7_available, 0.0, 1.0),
    ]
    for name, val, avail, lo, hi in pairs:
        if avail not in (0, 1):
            raise ValueError(f"Availability flag for {name} must be 0 or 1, got {avail!r}")
        if avail == 1 and val is None:
            raise ValueError(f"{name} marked available=1 but value is None")
        if avail == 0 and val is not None:
            raise ValueError(f"{name} marked available=0 but value is {val!r}")
        _check_optional_numeric(val, name, lo, hi)

    # Monotonic window count invariants: 1m <= 5m <= 15m when jointly available
    if row.f1_available and row.f2_available and row.f1_failed_logins_1m > row.f2_failed_logins_5m:
        raise ValueError(
            f"Window invariant violated: f1 ({row.f1_failed_logins_1m}) > f2 ({row.f2_failed_logins_5m})"
        )
    if row.f2_available and row.f3_available and row.f2_failed_logins_5m > row.f3_failed_logins_15m:
        raise ValueError(
            f"Window invariant violated: f2 ({row.f2_failed_logins_5m}) > f3 ({row.f3_failed_logins_15m})"
        )
    if row.f7_available and row.f7_is_off_hours not in (0.0, 1.0):
        raise ValueError(f"f7_is_off_hours must be 0.0 or 1.0, got {row.f7_is_off_hours}")
