"""
Offline Windows Authentication Feature Extraction Engine.

Subclasses the frozen `AuthenticationFeatureExtractor` from
`windows-telemetry/detection/features.py` without modifying Phase 2 files,
implementing the complete f1-f7 point-in-time feature vector contract with strict
preceding windowing [t - W, t), identity verification, continuity, and gap guards.
"""

from collections import deque
import hashlib
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WIN_TELEMETRY_ROOT = str(_REPO_ROOT / "windows-telemetry")
if _WIN_TELEMETRY_ROOT not in sys.path:
    sys.path.insert(0, _WIN_TELEMETRY_ROOT)

from detection.features import (  # noqa: E402
    AuthenticationFeatureExtractor,
    BusinessHoursConfig,
    CanonicalAuthEvent,
    Clock,
    DeterministicSimClock,
    ExtractedFeatures,
    FeatureMeasurement,
    IdentityRole,
    IPValidationStatus,
    LogonTypeQualitySummary,
    SUPPORTED_WINDOWS_LOGON_TYPES,
    canonical_auth_from_contract_v1,
)


def adapt_raw_security_event_to_contract_v1(
    raw_event: Dict[str, Any],
    default_agent_id: str = "offline-collector",
    default_hostname: str = "UNKNOWN-HOST",
) -> Dict[str, Any]:
    """
    Adapts either an already-normalized Contract v1 dictionary or a raw Security
    collector dictionary into a canonical Contract v1 event dictionary.
    Does not invent missing domain/user/IP values.
    """
    if (
        isinstance(raw_event.get("evidence"), dict)
        and "windows_event_id" in raw_event["evidence"]
        and "event_id" in raw_event
    ):
        return raw_event

    win_eid = raw_event.get("windows_event_id") or raw_event.get("event_id")
    record_id = raw_event.get("record_id")
    hostname = raw_event.get("hostname") or raw_event.get("computer") or default_hostname
    agent_id = raw_event.get("agent_id") or default_agent_id
    log_name = raw_event.get("channel") or raw_event.get("log_name") or "Security"
    target_user = raw_event.get("target_user")
    target_domain = raw_event.get("target_domain")
    username = target_user or raw_event.get("username")

    chan_epoch = raw_event.get("channel_epoch") or 1
    raw_identity = f"{agent_id}|{hostname}|{log_name}|{chan_epoch}|{record_id}"
    synthetic_event_id = (
        raw_event.get("source_event_id")
        or raw_event.get("canonical_event_id")
        or hashlib.sha256(raw_identity.encode("utf-8")).hexdigest()
    )

    evidence: Dict[str, Any] = {
        "windows_event_id": win_eid,
        "record_id": record_id,
        "log_name": log_name,
        "logon_type": raw_event.get("logon_type"),
        "target_user": target_user,
        "target_domain": target_domain,
        "caller_user": raw_event.get("subject_user") or raw_event.get("caller_user"),
        "workstation_name": raw_event.get("workstation_name"),
        "status": raw_event.get("status"),
        "sub_status": raw_event.get("sub_status"),
    }
    if "domain_status" in raw_event:
        evidence["domain_status"] = raw_event["domain_status"]
    if "domain_namespace" in raw_event:
        evidence["domain_namespace"] = raw_event["domain_namespace"]
    if "target_account_id" in raw_event:
        evidence["target_account_id"] = raw_event["target_account_id"]

    return {
        "event_id": str(synthetic_event_id),
        "timestamp": raw_event.get("timestamp"),
        "agent_id": str(agent_id),
        "hostname": str(hostname),
        "os": raw_event.get("os", "Windows"),
        "event_type": "windows_security_event",
        "source_ip": raw_event.get("source_ip"),
        "username": username,
        "severity": raw_event.get("severity", "low"),
        "detection_type": None,
        "confidence": None,
        "evidence": evidence,
    }


class OfflineAuthFeatureExtractor(AuthenticationFeatureExtractor):
    """
    Complete offline point-in-time feature extractor implementing all seven
    authentication features (f1-f7) over preceding windows [t - W, t), while
    preserving every safety guard from frozen AuthenticationFeatureExtractor.
    """

    def _window_precheck(
        self,
        event: CanonicalAuthEvent,
        window_seconds: float,
        is_dedup_compromised: bool,
        require_verified_identity: bool = True,
    ) -> Optional[str]:
        host = event.destination_host
        t = event.timestamp_epoch

        if require_verified_identity:
            if event.domain_status == "UNVERIFIED" and event.target_user:
                return "TARGET_DOMAIN_UNVERIFIED"
            if event.identity_role == IdentityRole.AMBIGUOUS:
                return "AMBIGUOUS_IDENTITY_ROLE"
            if event.identity_role != IdentityRole.TARGET_USER or not event.target_account_id:
                return "TARGET_USER_REQUIRED"

        if event.source_ip_status != IPValidationStatus.VALID or not event.source_ip:
            return "MISSING_OR_INVALID_SOURCE_IP"

        if is_dedup_compromised:
            return "DEDUPLICATION_COMPLETENESS_LOST"

        cov_start = self._coverage_start.get(host)
        if cov_start is None or (t - cov_start) < window_seconds:
            return "INSUFFICIENT_HISTORICAL_COVERAGE"

        for g_start, g_end in self._unrecoverable_gaps.get(host, []):
            if not (t <= g_start or (t - window_seconds) >= g_end):
                return "TELEMETRY_GAP_DETECTED"

        entity_key = f"{host}|{event.source_ip}"
        if self._entity_truncated.get(entity_key, False):
            return "HISTORY_TRUNCATED_MEMORY_LIMIT"

        return None

    def _calculate_failed_logins_window(
        self,
        event: CanonicalAuthEvent,
        window_seconds: float,
        is_dedup_compromised: bool,
    ) -> FeatureMeasurement:
        reason = self._window_precheck(
            event,
            window_seconds=window_seconds,
            is_dedup_compromised=is_dedup_compromised,
            require_verified_identity=True,
        )
        if reason is not None:
            return FeatureMeasurement(value=None, is_available=False, reason=reason)

        entity_key = f"{event.destination_host}|{event.source_ip}"
        q = self._entity_events.get(entity_key, deque())
        t = event.timestamp_epoch
        lower = t - window_seconds

        # Preceding context [t - W, t): strictly excludes current event
        failed_count = sum(
            1
            for r in q
            if lower <= r.timestamp_epoch < t and r.event_type == "AUTHENTICATION_FAILURE"
        )
        return FeatureMeasurement(value=float(failed_count), is_available=True, reason=None)

    def _calculate_unique_users_15m(
        self,
        event: CanonicalAuthEvent,
        is_dedup_compromised: bool,
    ) -> FeatureMeasurement:
        reason = self._window_precheck(
            event,
            window_seconds=900.0,
            is_dedup_compromised=is_dedup_compromised,
            require_verified_identity=True,
        )
        if reason is not None:
            return FeatureMeasurement(value=None, is_available=False, reason=reason)

        entity_key = f"{event.destination_host}|{event.source_ip}"
        q = self._entity_events.get(entity_key, deque())
        t = event.timestamp_epoch
        lower = t - 900.0

        # Distinct verified target accounts targeted from this source_ip in [t - 900, t)
        unique_accounts = {
            r.target_account_id.lower()
            for r in q
            if lower <= r.timestamp_epoch < t
            and r.target_account_id
            and r.domain_namespace != "UNVERIFIED"
        }
        return FeatureMeasurement(value=float(len(unique_accounts)), is_available=True, reason=None)

    def _calculate_features(
        self,
        event: CanonicalAuthEvent,
        is_dedup_compromised: bool,
    ) -> ExtractedFeatures:
        f1 = self._calculate_failed_logins_window(event, 60.0, is_dedup_compromised)
        f2 = self._calculate_failed_logins_window(event, 300.0, is_dedup_compromised)
        f3 = self._calculate_failed_logins_window(event, 900.0, is_dedup_compromised)
        f4 = self._calculate_unique_users_15m(event, is_dedup_compromised)
        f5, quality = self._calculate_f5(event, is_dedup_compromised)
        f6 = self._calculate_f6(event)
        f7 = self._calculate_f7(event)

        return ExtractedFeatures(
            f1_failed_logins_1m=f1,
            f2_failed_logins_5m=f2,
            f3_failed_logins_15m=f3,
            f4_unique_users_per_ip_15m=f4,
            f5_logon_type_entropy_15m=f5,
            f6_hour_of_day=f6,
            f7_is_off_hours=f7,
            logon_type_quality=quality,
        )
