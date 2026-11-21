"""
Phase 3.1: Windows Telemetry Authentication Feature Extraction Engine.

Implements CanonicalAuthEvent normalization, strict stateful windowing,
bounded memory retention, event-time watermark progression, and feature
extraction (f1-f7) conforming to Normalized Event Contract v1.
"""

from abc import ABC, abstractmethod
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import ipaddress
import math
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo


class IdentityRole(Enum):
    TARGET_USER = "TARGET_USER"          # Verified target of authentication
    CALLER_PROCESS = "CALLER_PROCESS"    # Verified calling process (e.g. SYSTEM)
    AMBIGUOUS = "AMBIGUOUS"              # Collapsed by collector; role uncertain
    UNKNOWN = "UNKNOWN"                  # Identity completely absent


class IPValidationStatus(Enum):
    VALID = "VALID"                      # Valid remote IPv4/IPv6 address
    MISSING = "MISSING"                  # Field applicable but empty/null
    MALFORMED = "MALFORMED"              # String failed IP syntax validation
    NOT_APPLICABLE = "NOT_APPLICABLE"    # Local console or loopback (127.0.0.1, ::1)


class FieldStatus(Enum):
    VALID = "VALID"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SweepStatus(Enum):
    SUCCESS_COMPLETE = "SUCCESS_COMPLETE"  # Query completed fully without errors
    PARTIAL_FAILURE = "PARTIAL_FAILURE"    # Batch truncated due to error mid-sweep
    QUERY_ERROR = "QUERY_ERROR"            # wevtutil returned nonzero exit code
    QUERY_TIMEOUT = "QUERY_TIMEOUT"        # Query exceeded timeout threshold
    ACCESS_DENIED = "ACCESS_DENIED"        # Collector lacked elevated privileges


class LogonTypeStatus(Enum):
    VALID = "VALID"
    UNKNOWN_VALUE = "UNKNOWN_VALUE"
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"


SUPPORTED_WINDOWS_LOGON_TYPES = frozenset({2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13})


class FutureEventError(ValueError):
    """Raised when an event's timestamp is in the future beyond acceptable skew."""
    pass


@dataclass(frozen=True)
class FeatureMeasurement:
    value: Optional[float]
    is_available: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class LogonTypeQualitySummary:
    valid_count: int
    unknown_count: int
    missing_count: int
    malformed_count: int
    total_observed: int
    quality_warning: Optional[str] = None


@dataclass(frozen=True)
class ExtractedFeatures:
    f1_failed_logins_1m: FeatureMeasurement
    f2_failed_logins_5m: FeatureMeasurement
    f3_failed_logins_15m: FeatureMeasurement
    f4_unique_users_per_ip_15m: FeatureMeasurement
    f5_logon_type_entropy_15m: FeatureMeasurement
    f6_hour_of_day: FeatureMeasurement
    f7_is_off_hours: FeatureMeasurement
    logon_type_quality: Optional[LogonTypeQualitySummary] = None


@dataclass(frozen=True)
class BusinessHoursConfig:
    iana_timezone: str
    workdays: Tuple[int, ...] = (0, 1, 2, 3, 4)
    work_start_hour: int = 8
    work_end_hour: int = 18
    holidays_supported: bool = False

    def __post_init__(self):
        try:
            ZoneInfo(self.iana_timezone)
        except Exception as e:
            raise ValueError(f"Invalid IANA timezone: {self.iana_timezone}") from e
        if not (0 <= self.work_start_hour < self.work_end_hour <= 24):
            raise ValueError(
                f"Invalid hours: start={self.work_start_hour}, end={self.work_end_hour}. "
                "Must satisfy: 0 <= start < end <= 24."
            )
        for day in self.workdays:
            if day not in range(7):
                raise ValueError(f"Invalid workday index: {day}. Must be in [0, 6].")


@dataclass(frozen=True)
class CanonicalAuthEvent:
    event_id: str
    collector_id: str
    raw_record_id: int
    source_log_name: str
    timestamp_epoch: float
    event_type: str
    logon_type: Optional[int]
    logon_type_status: LogonTypeStatus
    observed_username: Optional[str]
    identity_role: IdentityRole
    source_ip: Optional[str]
    source_ip_status: IPValidationStatus
    destination_host: str
    ingestion_timestamp: float
    dedup_hash: str
    target_user: Optional[str] = None
    caller_user: Optional[str] = None
    status_code: Optional[str] = None
    sub_status_code: Optional[str] = None
    target_domain: Optional[str] = None
    source_workstation: Optional[str] = None
    domain_status: str = "UNVERIFIED"
    domain_namespace: str = "UNVERIFIED"
    target_account_id: Optional[str] = None


@dataclass(frozen=True)
class HistoricalAuthRecord:
    event_id: str
    record_id: int
    timestamp_epoch: float
    event_type: str
    source_ip: Optional[str]
    observed_username: Optional[str]
    logon_type: Optional[int]
    logon_type_status: LogonTypeStatus
    target_account_id: Optional[str] = None
    target_user: Optional[str] = None
    domain_namespace: Optional[str] = None


class Clock(ABC):
    @abstractmethod
    def now_epoch(self) -> float:
        ...


class SystemClock(Clock):
    def now_epoch(self) -> float:
        return time.time()


class DeterministicSimClock(Clock):
    def __init__(self, current_time: float = 0.0):
        self._current_time = float(current_time)

    def set_time(self, t: float) -> None:
        self._current_time = float(t)

    def advance(self, delta: float) -> None:
        self._current_time += float(delta)

    def now_epoch(self) -> float:
        return self._current_time


class ICollectionHealthListener(ABC):
    @abstractmethod
    def notify_sweep_status(
        self,
        sweep_start_utc: float,
        sweep_end_utc: float,
        records_ingested: int,
        status: SweepStatus,
        error_detail: Optional[str] = None
    ) -> None:
        """Receives upstream assertion of collection sweep execution health."""
        ...

    @abstractmethod
    def notify_unrecoverable_gap(
        self,
        gap_start_utc: float,
        gap_end_utc: float,
        reason: str
    ) -> None:
        """Receives upstream notification of confirmed unrecoverable event loss."""
        ...

    @abstractmethod
    def notify_log_cleared(self, event_1102_timestamp_utc: float) -> None:
        """Receives authoritative notification of Windows Event 1102."""
        ...


def canonical_auth_from_contract_v1(event: Dict[str, Any]) -> Optional[CanonicalAuthEvent]:
    """
    Adapts a Normalized Event Contract v1 dictionary to a CanonicalAuthEvent.
    Fails closed (returns None) on missing required identity components or non-auth events.
    """
    evidence = event.get("evidence")
    if not isinstance(evidence, dict):
        return None

    win_event_id = evidence.get("windows_event_id")
    if win_event_id not in (4624, 4625):
        return None

    agent_id = event.get("agent_id")
    hostname = event.get("hostname")
    event_id = event.get("event_id")
    raw_record_id = evidence.get("record_id")
    log_name = evidence.get("log_name", "Security")

    if not agent_id or not hostname or not event_id or not log_name:
        return None

    if not isinstance(raw_record_id, int) or raw_record_id <= 0:
        return None

    ts_str = event.get("timestamp")
    if not isinstance(ts_str, str):
        return None

    # Enforce timezone-aware timestamp
    try:
        if ts_str.endswith("Z"):
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            return None
        timestamp_epoch = dt.timestamp()
    except (ValueError, TypeError):
        return None

    # Source IP parsing & Loopback exclusion
    raw_ip = event.get("source_ip")
    if raw_ip in (None, "", "-"):
        source_ip = None
        ip_status = IPValidationStatus.MISSING
    else:
        try:
            ip_obj = ipaddress.ip_address(str(raw_ip).strip())
            if ip_obj.is_loopback:
                source_ip = None
                ip_status = IPValidationStatus.NOT_APPLICABLE
            elif ip_obj.is_unspecified or ip_obj.is_multicast:
                source_ip = None
                ip_status = IPValidationStatus.MALFORMED
            else:
                source_ip = str(ip_obj)
                ip_status = IPValidationStatus.VALID
        except ValueError:
            source_ip = None
            ip_status = IPValidationStatus.MALFORMED

    # Observed username role
    raw_user = event.get("username")
    if raw_user in (None, "", "-"):
        observed_username = None
        identity_role = IdentityRole.UNKNOWN
    else:
        observed_username = str(raw_user).strip()
        identity_role = IdentityRole.AMBIGUOUS

    # WP-1C: Invariant resolution for canonical identity fields
    target_user = evidence.get("target_user")
    if target_user is None and raw_user not in (None, "", "-"):
        target_user = str(raw_user).strip()
    target_domain = evidence.get("target_domain")
    domain_status = evidence.get("domain_status")
    domain_namespace = evidence.get("domain_namespace")
    target_account_id = evidence.get("target_account_id")

    if domain_status is None:
        if target_user is None:
            domain_status = "UNVERIFIED"
            domain_namespace = "UNVERIFIED"
            target_account_id = None
        elif target_domain == ".":
            domain_status = "LOCAL_SAM"
            domain_namespace = "LOCAL_SAM"
            target_account_id = f"LOCAL_SAM\\{target_user.lower()}"
        elif target_domain is not None:
            domain_status = "OBSERVED_DOMAIN"
            domain_namespace = f"DOMAIN:{target_domain.upper()}"
            target_account_id = f"{domain_namespace}\\{target_user.lower()}"
        else:
            domain_status = "UNVERIFIED"
            domain_namespace = "UNVERIFIED"
            target_account_id = None

    if target_account_id:
        identity_role = IdentityRole.TARGET_USER

    # Logon type parsing
    raw_lt = evidence.get("logon_type")
    if raw_lt is None or raw_lt == "" or raw_lt == "-":
        logon_type = None
        lt_status = LogonTypeStatus.MISSING
    else:
        try:
            lt_int = int(raw_lt)
            logon_type = lt_int
            if lt_int in SUPPORTED_WINDOWS_LOGON_TYPES:
                lt_status = LogonTypeStatus.VALID
            else:
                lt_status = LogonTypeStatus.UNKNOWN_VALUE
        except (ValueError, TypeError):
            logon_type = None
            lt_status = LogonTypeStatus.MALFORMED

    return CanonicalAuthEvent(
        event_id=str(event_id),
        collector_id=str(agent_id),
        raw_record_id=raw_record_id,
        source_log_name=str(log_name),
        timestamp_epoch=timestamp_epoch,
        event_type="AUTHENTICATION_SUCCESS" if win_event_id == 4624 else "AUTHENTICATION_FAILURE",
        logon_type=logon_type,
        logon_type_status=lt_status,
        observed_username=observed_username,
        identity_role=identity_role,
        source_ip=source_ip,
        source_ip_status=ip_status,
        destination_host=str(hostname),
        ingestion_timestamp=datetime.now(timezone.utc).timestamp(),
        dedup_hash=str(event_id),
        target_user=target_user,
        caller_user=evidence.get("caller_user"),
        status_code=evidence.get("status"),
        sub_status_code=evidence.get("sub_status"),
        target_domain=target_domain,
        source_workstation=evidence.get("workstation_name"),
        domain_status=domain_status,
        domain_namespace=domain_namespace,
        target_account_id=target_account_id
    )


class AuthenticationFeatureExtractor(ICollectionHealthListener):
    """
    Stateful point-in-time authentication feature extractor.
    Enforces per-entity watermarks, hard memory bounds, non-arbitrary ordering
    anomaly handling, and continuous historical coverage verification.
    """

    def __init__(
        self,
        clock: Optional[Clock] = None,
        business_hours_config: Optional[BusinessHoursConfig] = None,
        future_clock_skew_tolerance_seconds: float = 5.0,
        max_tracked_entities: int = 5000,
        max_events_per_entity: int = 10000,
        max_dedup_cache_size: int = 50000,
        retention_horizon_seconds: float = 900.0,
    ):
        self.clock = clock or SystemClock()
        self.business_hours_config = business_hours_config
        self.future_clock_skew_tolerance = float(future_clock_skew_tolerance_seconds)
        self.max_tracked_entities = int(max_tracked_entities)
        self.max_events_per_entity = int(max_events_per_entity)
        self.max_dedup_cache_size = int(max_dedup_cache_size)
        self.retention_horizon = float(retention_horizon_seconds)

        # Monotonic watermarks per host
        self._entity_watermarks: Dict[str, float] = {}

        # Highest record ID observed per (agent_id, hostname, log_name)
        self._entity_highest_record: Dict[Tuple[str, str, str], int] = {}

        # Deduplication cache: (host, dedup_hash) -> event_timestamp
        self._dedup_cache: OrderedDict[Tuple[str, str], float] = OrderedDict()

        # Deduplication recovery watermark per host
        self._dedup_compromised_until: Dict[str, float] = {}

        # Historical events keyed by entity: Dict[entity_key, deque[HistoricalAuthRecord]]
        # Entity keys are: ("host_ip", host, ip)
        self._entity_events: Dict[str, Deque[HistoricalAuthRecord]] = {}
        self._entity_last_active: Dict[str, float] = {}
        self._entity_truncated: Dict[str, bool] = {}

        # Continuous coverage start timestamp per host
        self._coverage_start: Dict[str, float] = {}

        # Telemetry gaps per host: list of (gap_start, gap_end)
        self._unrecoverable_gaps: Dict[str, List[Tuple[float, float]]] = {}

        # Internal epoch for log clearing
        self.internal_epoch: int = 1

    # -------------------------------------------------------------------------
    # ICollectionHealthListener implementation
    # -------------------------------------------------------------------------

    def notify_sweep_status(
        self,
        sweep_start_utc: float,
        sweep_end_utc: float,
        records_ingested: int,
        status: SweepStatus,
        error_detail: Optional[str] = None
    ) -> None:
        if status != SweepStatus.SUCCESS_COMPLETE:
            # Query failed, access denied, or partial read: coverage broken
            for host in list(self._coverage_start.keys()):
                self._record_gap_for_host(host, sweep_start_utc, sweep_end_utc)
                self._coverage_start.pop(host, None)
        # Note: Delayed sweeps with SUCCESS_COMPLETE recover contiguous backlog and do not invalidate.

    def notify_unrecoverable_gap(
        self,
        gap_start_utc: float,
        gap_end_utc: float,
        reason: str
    ) -> None:
        for host in list(self._coverage_start.keys()):
            self._record_gap_for_host(host, gap_start_utc, gap_end_utc)
            self._coverage_start.pop(host, None)

    def notify_log_cleared(self, event_1102_timestamp_utc: float) -> None:
        self.internal_epoch += 1
        self._dedup_cache.clear()
        self._entity_events.clear()
        self._entity_last_active.clear()
        self._entity_truncated.clear()
        self._coverage_start.clear()
        self._entity_watermarks.clear()
        self._entity_highest_record.clear()
        self._dedup_compromised_until.clear()

    def _record_gap_for_host(self, host: str, gap_start: float, gap_end: float) -> None:
        if host not in self._unrecoverable_gaps:
            self._unrecoverable_gaps[host] = []
        self._unrecoverable_gaps[host].append((gap_start, gap_end))

    # -------------------------------------------------------------------------
    # Processing and Feature Extraction
    # -------------------------------------------------------------------------

    def process_event(
        self,
        event: CanonicalAuthEvent
    ) -> Tuple[ExtractedFeatures, bool]:
        """
        Extracts features for the event over preceding context [t - W, t).
        Returns (features, can_generate_prediction).
        """
        host = event.destination_host
        t_event = event.timestamp_epoch
        now = self.clock.now_epoch()

        # 1. Future clock skew rejection
        if t_event > now + self.future_clock_skew_tolerance:
            raise FutureEventError(
                f"Event timestamp {t_event} exceeds clock time {now} by > {self.future_clock_skew_tolerance}s."
            )

        # 2. Authoritative log-clear check and record-ID regression validation
        channel_key = (event.collector_id, event.destination_host, event.source_log_name)
        r_current = event.raw_record_id
        r_highest = self._entity_highest_record.get(channel_key, 0)

        if r_current < r_highest:
            # An unverified record-ID regression without an authoritative log-clear signal (Event 1102)
            # cannot establish channel-generation provenance. Fail closed and isolate state for this host:
            # 1. Purge all rolling history and tracking state for this host
            host_keys = [k for k in self._entity_events if k.split("|", 1)[0] == host]
            for k in host_keys:
                self._entity_events.pop(k, None)
                self._entity_last_active.pop(k, None)
                self._entity_truncated.pop(k, None)

            # 2. Reset host coverage start and watermark so fresh warm-up restarts cleanly on next event
            self._coverage_start.pop(host, None)
            self._entity_watermarks.pop(host, None)

            # 3. Purge deduplication cache entries belonging to this host and track recovery horizon
            dedup_keys = [k for k in self._dedup_cache if k[0] == host]
            for k in dedup_keys:
                del self._dedup_cache[k]
            self._dedup_compromised_until[host] = max(
                self._dedup_compromised_until.get(host, 0.0),
                t_event + self.retention_horizon
            )

            return self._build_anomaly_features("UNRESOLVED_RECORD_ORDERING_ANOMALY"), False

        self._entity_highest_record[channel_key] = r_current

        # 3. Watermark and Lateness Evaluation
        can_predict = True
        if host not in self._entity_watermarks:
            self._entity_watermarks[host] = t_event
            if host not in self._coverage_start:
                self._coverage_start[host] = t_event
            current_wm = t_event
        else:
            if t_event >= self._entity_watermarks[host]:
                self._entity_watermarks[host] = t_event
                current_wm = t_event
            else:
                current_wm = self._entity_watermarks[host]
                can_predict = False
                if t_event < current_wm - self.retention_horizon:
                    # Expired late event: drop entirely
                    return self._build_expired_features(), False

        # 4. Deduplication completeness check for this host
        dedup_recovery_wm = self._dedup_compromised_until.get(host)
        if dedup_recovery_wm is not None:
            if current_wm > dedup_recovery_wm:
                self._dedup_compromised_until.pop(host, None)
                is_dedup_compromised = False
            else:
                is_dedup_compromised = True
        else:
            is_dedup_compromised = False

        # 5. Deduplication check (scoped to host)
        dedup_key = (host, event.dedup_hash)
        if dedup_key in self._dedup_cache:
            # Idempotent duplicate: return unavailable features, no state change
            return self._build_duplicate_features(), False

        # Insert into dedup cache with hard bounds
        self._insert_dedup_cache(host, event.dedup_hash, t_event, current_wm)

        # 6. Extract Features over PRECEDING context [t - W, t) (exclusive of current event)
        features = self._calculate_features(event, is_dedup_compromised)

        # 7. Commit event to state history AFTER feature calculation
        self._commit_to_history(event)

        return features, can_predict

    def _insert_dedup_cache(self, host: str, dedup_hash: str, t_event: float, current_wm: float) -> None:
        dedup_key = (host, dedup_hash)
        if len(self._dedup_cache) >= self.max_dedup_cache_size:
            evicted_key, evicted_ts = self._dedup_cache.popitem(last=False)
            evicted_host = evicted_key[0]
            wm = self._entity_watermarks.get(evicted_host, current_wm)
            # If evicted hash falls within the active 15m retention horizon, dedup completeness is lost for that host
            if evicted_ts >= wm - self.retention_horizon:
                recovery_point = evicted_ts + self.retention_horizon
                self._dedup_compromised_until[evicted_host] = max(
                    self._dedup_compromised_until.get(evicted_host, 0.0),
                    recovery_point
                )
        self._dedup_cache[dedup_key] = t_event

    def _commit_to_history(self, event: CanonicalAuthEvent) -> None:
        if event.source_ip_status != IPValidationStatus.VALID or not event.source_ip:
            return

        entity_key = f"{event.destination_host}|{event.source_ip}"
        self._enforce_tracked_entities_limit(entity_key, event.timestamp_epoch)

        if entity_key not in self._entity_events:
            self._entity_events[entity_key] = deque()
            self._entity_truncated[entity_key] = False

        q = self._entity_events[entity_key]
        wm = self._entity_watermarks.get(event.destination_host, event.timestamp_epoch)

        # Prune events older than retention horizon
        while q and q[0].timestamp_epoch < wm - self.retention_horizon:
            q.popleft()

        # Hard bound on events per entity
        if len(q) >= self.max_events_per_entity:
            q.popleft()
            self._entity_truncated[entity_key] = True

        rec = HistoricalAuthRecord(
            event_id=event.event_id,
            record_id=event.raw_record_id,
            timestamp_epoch=event.timestamp_epoch,
            event_type=event.event_type,
            source_ip=event.source_ip,
            observed_username=event.observed_username,
            logon_type=event.logon_type,
            logon_type_status=event.logon_type_status,
            target_account_id=event.target_account_id,
            target_user=event.target_user,
            domain_namespace=event.domain_namespace
        )
        q.append(rec)
        self._entity_last_active[entity_key] = event.timestamp_epoch

    def _enforce_tracked_entities_limit(self, current_key: str, current_time: float) -> None:
        if current_key in self._entity_events:
            return
        if len(self._entity_events) >= self.max_tracked_entities:
            # Evict least recently active entity (LRU)
            oldest_key = min(self._entity_last_active.keys(), key=lambda k: self._entity_last_active[k])
            self._entity_events.pop(oldest_key, None)
            self._entity_last_active.pop(oldest_key, None)
            self._entity_truncated.pop(oldest_key, None)

    def _calculate_features(self, event: CanonicalAuthEvent, is_dedup_compromised: bool) -> ExtractedFeatures:
        host = event.destination_host
        t = event.timestamp_epoch

        # Features f1-f4: strictly unavailable while identity is ambiguous or domain unverified
        if event.domain_status == "UNVERIFIED" and event.target_user:
            f1_reason = "TARGET_DOMAIN_UNVERIFIED"
        else:
            f1_reason = "AMBIGUOUS_IDENTITY_ROLE" if event.identity_role == IdentityRole.AMBIGUOUS else "TARGET_USER_REQUIRED"
        f1 = FeatureMeasurement(value=None, is_available=False, reason=f1_reason)
        f2 = FeatureMeasurement(value=None, is_available=False, reason=f1_reason)
        f3 = FeatureMeasurement(value=None, is_available=False, reason=f1_reason)
        f4 = FeatureMeasurement(value=None, is_available=False, reason=f1_reason)

        # Feature f5: logon type entropy per source IP
        f5, quality = self._calculate_f5(event, is_dedup_compromised)

        # Feature f6: hour of day
        f6 = self._calculate_f6(event)

        # Feature f7: is off hours
        f7 = self._calculate_f7(event)

        return ExtractedFeatures(
            f1_failed_logins_1m=f1,
            f2_failed_logins_5m=f2,
            f3_failed_logins_15m=f3,
            f4_unique_users_per_ip_15m=f4,
            f5_logon_type_entropy_15m=f5,
            f6_hour_of_day=f6,
            f7_is_off_hours=f7,
            logon_type_quality=quality
        )

    def _calculate_f5(
        self,
        event: CanonicalAuthEvent,
        is_dedup_compromised: bool
    ) -> Tuple[FeatureMeasurement, Optional[LogonTypeQualitySummary]]:
        host = event.destination_host
        t = event.timestamp_epoch

        if event.source_ip_status != IPValidationStatus.VALID or not event.source_ip:
            return FeatureMeasurement(value=None, is_available=False, reason="MISSING_OR_INVALID_SOURCE_IP"), None

        # Check deduplication completeness
        if is_dedup_compromised:
            return FeatureMeasurement(value=None, is_available=False, reason="DEDUPLICATION_COMPLETENESS_LOST"), None

        # Check continuous historical coverage for 900s window
        cov_start = self._coverage_start.get(host)
        if cov_start is None or (t - cov_start < 900.0):
            # Incomplete coverage warm-up
            return FeatureMeasurement(value=None, is_available=False, reason="INSUFFICIENT_HISTORICAL_COVERAGE"), None

        # Check recorded unrecoverable gaps overlapping [t - 900, t)
        for g_start, g_end in self._unrecoverable_gaps.get(host, []):
            if not (t <= g_start or (t - 900.0) >= g_end):
                return FeatureMeasurement(value=None, is_available=False, reason="TELEMETRY_GAP_DETECTED"), None

        entity_key = f"{host}|{event.source_ip}"
        if self._entity_truncated.get(entity_key, False):
            return FeatureMeasurement(value=None, is_available=False, reason="HISTORY_TRUNCATED_MEMORY_LIMIT"), None

        q = self._entity_events.get(entity_key, deque())

        # Preceding context [t - 900, t)
        history = [r for r in q if (t - 900.0) <= r.timestamp_epoch < t]

        valid_counts: Dict[int, int] = {}
        unknown_count = 0
        missing_count = 0
        malformed_count = 0

        for r in history:
            if r.logon_type_status == LogonTypeStatus.VALID and r.logon_type is not None:
                valid_counts[r.logon_type] = valid_counts.get(r.logon_type, 0) + 1
            elif r.logon_type_status == LogonTypeStatus.UNKNOWN_VALUE:
                unknown_count += 1
            elif r.logon_type_status == LogonTypeStatus.MISSING:
                missing_count += 1
            elif r.logon_type_status == LogonTypeStatus.MALFORMED:
                malformed_count += 1

        total_valid = sum(valid_counts.values())
        total_observed = len(history)

        warning = None
        if total_valid > 0 and (unknown_count + missing_count + malformed_count) > 0:
            warning = "DEGRADED_LOGON_TYPE_QUALITY"

        quality = LogonTypeQualitySummary(
            valid_count=total_valid,
            unknown_count=unknown_count,
            missing_count=missing_count,
            malformed_count=malformed_count,
            total_observed=total_observed,
            quality_warning=warning
        )

        if total_valid == 0:
            return FeatureMeasurement(value=None, is_available=False, reason="NO_SUPPORTED_LOGON_TYPES"), quality

        if len(valid_counts) == 1:
            return FeatureMeasurement(value=0.0, is_available=True, reason=None), quality

        entropy = 0.0
        for count in valid_counts.values():
            p = count / total_valid
            if p > 0:
                entropy -= p * math.log2(p)

        return FeatureMeasurement(value=round(entropy, 6), is_available=True, reason=None), quality

    def _calculate_f6(self, event: CanonicalAuthEvent) -> FeatureMeasurement:
        if self.business_hours_config is None:
            return FeatureMeasurement(value=None, is_available=False, reason="UNCONFIGURED_TIMEZONE")
        try:
            tz = ZoneInfo(self.business_hours_config.iana_timezone)
            dt_local = datetime.fromtimestamp(event.timestamp_epoch, tz=timezone.utc).astimezone(tz)
            return FeatureMeasurement(value=float(dt_local.hour), is_available=True, reason=None)
        except Exception as e:
            return FeatureMeasurement(value=None, is_available=False, reason=f"TIMEZONE_CALCULATION_ERROR: {e}")

    def _calculate_f7(self, event: CanonicalAuthEvent) -> FeatureMeasurement:
        if self.business_hours_config is None:
            return FeatureMeasurement(value=None, is_available=False, reason="UNCONFIGURED_BUSINESS_HOURS")
        try:
            tz = ZoneInfo(self.business_hours_config.iana_timezone)
            dt_local = datetime.fromtimestamp(event.timestamp_epoch, tz=timezone.utc).astimezone(tz)
            weekday = dt_local.weekday()
            hour = dt_local.hour
            is_workday = weekday in self.business_hours_config.workdays
            is_work_hour = self.business_hours_config.work_start_hour <= hour < self.business_hours_config.work_end_hour
            if is_workday and is_work_hour:
                return FeatureMeasurement(value=0.0, is_available=True, reason=None)
            else:
                return FeatureMeasurement(value=1.0, is_available=True, reason=None)
        except Exception as e:
            return FeatureMeasurement(value=None, is_available=False, reason=f"BUSINESS_HOURS_CALCULATION_ERROR: {e}")

    def _build_duplicate_features(self) -> ExtractedFeatures:
        unavail = FeatureMeasurement(value=None, is_available=False, reason="DUPLICATE_EVENT")
        return ExtractedFeatures(unavail, unavail, unavail, unavail, unavail, unavail, unavail)

    def _build_expired_features(self) -> ExtractedFeatures:
        unavail = FeatureMeasurement(value=None, is_available=False, reason="EXPIRED_LATE_EVENT")
        return ExtractedFeatures(unavail, unavail, unavail, unavail, unavail, unavail, unavail)

    def _build_anomaly_features(self, reason: str) -> ExtractedFeatures:
        unavail = FeatureMeasurement(value=None, is_available=False, reason=reason)
        return ExtractedFeatures(unavail, unavail, unavail, unavail, unavail, unavail, unavail)
