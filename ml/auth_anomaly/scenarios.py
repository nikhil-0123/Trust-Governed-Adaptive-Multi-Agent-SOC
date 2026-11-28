"""
Independent Ground-Truth Scenario Manifest & Labeling Procedure (Phase 3B).

Ensures labels derive strictly from documented laboratory / operational
scenario provenance, NEVER from detector outputs, rule triggers, or model guesses.
Raw source IPs are scrubbed before saving manifests to disk.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence

from .schema import LabelAssignment, TelemetryOrigin, pseudonymize_identifier


FORBIDDEN_CIRCULAR_JUSTIFICATION_RE = re.compile(
    r"\b(?:bruteforce_rule|windows_bruteforce_rule|xgboost|detector_output|rule_triggered|model_predicted|confidence\s*[><=])\b",
    re.IGNORECASE,
)


class ScenarioFamily(str, Enum):
    BENIGN_NORMAL_LOGON = "BENIGN_NORMAL_LOGON"
    BENIGN_MISTYPED_FAILURE = "BENIGN_MISTYPED_FAILURE"
    BENIGN_OPERATIONAL_RETRY = "BENIGN_OPERATIONAL_RETRY"
    CONTROLLED_BRUTE_FORCE = "CONTROLLED_BRUTE_FORCE"
    CONTROLLED_PASSWORD_SPRAY = "CONTROLLED_PASSWORD_SPRAY"
    CONTROLLED_OFF_HOURS_ANOMALY = "CONTROLLED_OFF_HOURS_ANOMALY"
    AMBIGUOUS_UNLABELED = "AMBIGUOUS_UNLABELED"


class CoverageStatus(str, Enum):
    CONTINUOUS_COMPLETE = "CONTINUOUS_COMPLETE"
    GAP_DETECTED = "GAP_DETECTED"
    AUDIT_DISABLED = "AUDIT_DISABLED"
    PARTIAL_OVERWRITE = "PARTIAL_OVERWRITE"


def _parse_utc_epoch(ts: str) -> float:
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp must be timezone-aware: {ts}")
    return dt.timestamp()


@dataclass(frozen=True)
class ScenarioRecord:
    scenario_id: str
    scenario_family: str
    authorized_endpoint_id: str
    source_ip_pseudonym: Optional[str]
    start_timestamp_utc: str
    end_timestamp_utc: str
    ground_truth_label: Optional[int]  # 0=benign, 1=attack, None=ambiguous/excluded
    label_justification: str
    telemetry_origin: str
    collection_coverage_status: str
    expected_event_category: str
    actual_observed_event_count: int = 0

    def __post_init__(self):
        if not self.scenario_id or not str(self.scenario_id).strip():
            raise ValueError("scenario_id must be non-empty")
        valid_fams = {f.value for f in ScenarioFamily}
        if self.scenario_family not in valid_fams:
            raise ValueError(f"Invalid scenario_family '{self.scenario_family}'")
        if not self.authorized_endpoint_id or not str(self.authorized_endpoint_id).strip():
            raise ValueError("authorized_endpoint_id must be non-empty")

        start_ep = _parse_utc_epoch(self.start_timestamp_utc)
        end_ep = _parse_utc_epoch(self.end_timestamp_utc)
        if end_ep < start_ep:
            raise ValueError("end_timestamp_utc cannot precede start_timestamp_utc")

        if self.ground_truth_label is not None:
            if isinstance(self.ground_truth_label, bool) or self.ground_truth_label not in (0, 1):
                raise ValueError(f"ground_truth_label must be 0, 1, or None, got {self.ground_truth_label!r}")

        if not self.label_justification or len(self.label_justification.strip()) < 10:
            raise ValueError("label_justification must document substantive independent provenance")
        if FORBIDDEN_CIRCULAR_JUSTIFICATION_RE.search(self.label_justification):
            raise ValueError(
                "Circular labeling prohibited: label_justification cannot reference rule/model predictions."
            )

        valid_origins = {o.value for o in TelemetryOrigin}
        if self.telemetry_origin not in valid_origins:
            raise ValueError(f"Invalid telemetry_origin '{self.telemetry_origin}'")
        valid_cov = {c.value for c in CoverageStatus}
        if self.collection_coverage_status not in valid_cov:
            raise ValueError(f"Invalid collection_coverage_status '{self.collection_coverage_status}'")
        if self.actual_observed_event_count < 0:
            raise ValueError("actual_observed_event_count cannot be negative")

        # Fail closed on malicious attack claim without attack justification or ambiguous family
        if self.scenario_family == ScenarioFamily.AMBIGUOUS_UNLABELED.value and self.ground_truth_label is not None:
            raise ValueError("AMBIGUOUS_UNLABELED scenarios must have ground_truth_label=None")

    @property
    def start_epoch(self) -> float:
        return _parse_utc_epoch(self.start_timestamp_utc)

    @property
    def end_epoch(self) -> float:
        return _parse_utc_epoch(self.end_timestamp_utc)


def create_pseudonymized_scenario(
    scenario_id: str,
    scenario_family: ScenarioFamily,
    authorized_endpoint_id: str,
    raw_source_ip: Optional[str],
    pseudonymization_salt: str,
    start_timestamp_utc: str,
    end_timestamp_utc: str,
    ground_truth_label: Optional[int],
    label_justification: str,
    telemetry_origin: TelemetryOrigin,
    collection_coverage_status: CoverageStatus,
    expected_event_category: str,
    actual_observed_event_count: int = 0,
) -> ScenarioRecord:
    """Constructs a ScenarioRecord while immediately pseudonymizing any source IP."""
    if not pseudonymization_salt or len(pseudonymization_salt) < 8:
        raise ValueError("pseudonymization_salt must be >= 8 characters")
    ip_pseudo = pseudonymize_identifier(raw_source_ip, pseudonymization_salt, prefix="ip")
    return ScenarioRecord(
        scenario_id=scenario_id,
        scenario_family=scenario_family.value,
        authorized_endpoint_id=authorized_endpoint_id,
        source_ip_pseudonym=ip_pseudo,
        start_timestamp_utc=start_timestamp_utc,
        end_timestamp_utc=end_timestamp_utc,
        ground_truth_label=ground_truth_label,
        label_justification=label_justification,
        telemetry_origin=telemetry_origin.value,
        collection_coverage_status=collection_coverage_status.value,
        expected_event_category=expected_event_category,
        actual_observed_event_count=actual_observed_event_count,
    )


def validate_scenario_manifest(records: Sequence[ScenarioRecord]) -> None:
    """
    Validates manifest integrity:
    - Unique scenario_id per record.
    - No overlapping time windows on the same endpoint with conflicting labels.
    """
    seen_ids = set()
    by_endpoint: Dict[str, List[ScenarioRecord]] = {}
    for rec in records:
        if rec.scenario_id in seen_ids:
            raise ValueError(f"Duplicate scenario_id in manifest: '{rec.scenario_id}'")
        seen_ids.add(rec.scenario_id)
        by_endpoint.setdefault(rec.authorized_endpoint_id.lower(), []).append(rec)

    for ep, recs in by_endpoint.items():
        ordered = sorted(recs, key=lambda r: (r.start_epoch, r.end_epoch))
        for i in range(len(ordered)):
            for j in range(i + 1, len(ordered)):
                a, b = ordered[i], ordered[j]
                if b.start_epoch > a.end_epoch:
                    break
                # Overlapping time window on same endpoint:
                # If both share same source_ip_pseudonym (or either applies broadly with None) and labels conflict -> fail closed
                same_ip_scope = (
                    a.source_ip_pseudonym is None
                    or b.source_ip_pseudonym is None
                    or a.source_ip_pseudonym == b.source_ip_pseudonym
                )
                if same_ip_scope and a.ground_truth_label != b.ground_truth_label:
                    raise ValueError(
                        f"Conflicting overlapping scenarios on endpoint '{ep}': "
                        f"'{a.scenario_id}' (label={a.ground_truth_label}) vs "
                        f"'{b.scenario_id}' (label={b.ground_truth_label})"
                    )


def save_scenario_manifest(records: Sequence[ScenarioRecord], path: Path) -> None:
    validate_scenario_manifest(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(r) for r in records]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


def load_scenario_manifest(path: Path) -> List[ScenarioRecord]:
    with open(path, "r", encoding="utf-8") as f:
        items = json.load(f)
    recs = [ScenarioRecord(**item) for item in items]
    validate_scenario_manifest(recs)
    return recs


def scenario_manifest_to_label_assignments(
    records: Sequence[ScenarioRecord],
    exclude_incomplete_coverage: bool = True,
) -> List[LabelAssignment]:
    """
    Converts verified ScenarioRecords into supervised LabelAssignments.
    Automatically excludes AMBIGUOUS (label=None) scenarios and optionally
    excludes scenarios with degraded collection coverage.
    """
    validate_scenario_manifest(records)
    assignments: List[LabelAssignment] = []
    for rec in records:
        if rec.ground_truth_label is None:
            continue
        if exclude_incomplete_coverage and rec.collection_coverage_status != CoverageStatus.CONTINUOUS_COMPLETE.value:
            continue
        assignments.append(
            LabelAssignment(
                scenario_id=rec.scenario_id,
                label=rec.ground_truth_label,
                label_source=f"{rec.scenario_family}:{rec.label_justification}",
                telemetry_origin=rec.telemetry_origin,
                start_epoch=rec.start_epoch,
                end_epoch=rec.end_epoch,
                source_ip_pseudonym=rec.source_ip_pseudonym,
            )
        )
    return assignments
