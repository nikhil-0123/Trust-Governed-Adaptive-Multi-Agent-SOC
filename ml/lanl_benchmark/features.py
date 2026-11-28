"""
Causal Streaming Feature Extraction for LANL Cyber1 (`lanl_auth_features_v1`).

Supported Input Ordering & Window Contract:
- Requires non-decreasing chronological `time_rel` inputs (`ev.time_rel >= watermark`).
- Equal timestamps (`ev.time_rel == watermark`) are accepted and preserve strict
  same-second exclusion (`r.time_rel < t`) over half-open `[t - W, t)` windows.
- Out-of-order timestamp regressions (`ev.time_rel < watermark`) fail closed with
  `ValueError` BEFORE mutating extractor state.
- Enforces the fixed `900`-second (`SUPPORTED_RETENTION_SECONDS = 900`) retention window
  matching the nominal 1-minute (`60s`), 5-minute (`300s`), and 15-minute (`900s`)
  feature definitions without silent truncation or expiration drift.
"""

from collections import deque
from dataclasses import dataclass
import math
from typing import Deque, Dict, Iterator, List, Optional, Tuple

from .schema import LanlRawAuthEvent

SUPPORTED_RETENTION_SECONDS = 900


@dataclass(frozen=True)
class _HistoryEntry:
    time_rel: int
    dest_user: Optional[str]
    dst_computer: str
    logon_type: Optional[str]
    is_fail: bool


class _PairWindowState:
    """O(1)-amortized incremental [t - W, t) window tracker for one (src, dst) pair."""

    __slots__ = (
        "pending_t",
        "pending_entries",
        "q900",
        "q300_fails",
        "q60_fails",
        "fail_count_900",
        "total_count_900",
        "dest_user_counts",
        "logon_type_counts",
        "logon_type_total",
    )

    def __init__(self) -> None:
        self.pending_t: Optional[int] = None
        self.pending_entries: List[_HistoryEntry] = []
        self.q900: Deque[_HistoryEntry] = deque()
        self.q300_fails: Deque[int] = deque()
        self.q60_fails: Deque[int] = deque()
        self.fail_count_900: int = 0
        self.total_count_900: int = 0
        self.dest_user_counts: Dict[str, int] = {}
        self.logon_type_counts: Dict[str, int] = {}
        self.logon_type_total: int = 0

    def _add_to_q900(self, entry: _HistoryEntry) -> None:
        self.q900.append(entry)
        self.total_count_900 += 1
        if entry.is_fail:
            self.fail_count_900 += 1
            self.q300_fails.append(entry.time_rel)
            self.q60_fails.append(entry.time_rel)
        if entry.dest_user:
            self.dest_user_counts[entry.dest_user] = self.dest_user_counts.get(entry.dest_user, 0) + 1
        if entry.logon_type:
            self.logon_type_counts[entry.logon_type] = self.logon_type_counts.get(entry.logon_type, 0) + 1
            self.logon_type_total += 1

    def _flush_pending_before(self, t: int, retention_seconds: int) -> None:
        if self.pending_t is not None and t > self.pending_t:
            cutoff_max = t - retention_seconds
            for entry in self.pending_entries:
                if entry.time_rel >= cutoff_max:
                    self._add_to_q900(entry)
            self.pending_entries.clear()
            self.pending_t = None

    def prune(self, current_t: int, retention_seconds: int) -> None:
        self._flush_pending_before(current_t, retention_seconds)
        cutoff_900 = current_t - retention_seconds
        while self.q900 and self.q900[0].time_rel < cutoff_900:
            old = self.q900.popleft()
            self.total_count_900 -= 1
            if old.is_fail:
                self.fail_count_900 -= 1
            if old.dest_user:
                c = self.dest_user_counts[old.dest_user] - 1
                if c <= 0:
                    del self.dest_user_counts[old.dest_user]
                else:
                    self.dest_user_counts[old.dest_user] = c
            if old.logon_type:
                c = self.logon_type_counts[old.logon_type] - 1
                if c <= 0:
                    del self.logon_type_counts[old.logon_type]
                else:
                    self.logon_type_counts[old.logon_type] = c
                self.logon_type_total -= 1

        cutoff_300 = current_t - 300
        while self.q300_fails and self.q300_fails[0] < cutoff_300:
            self.q300_fails.popleft()

        cutoff_60 = current_t - 60
        while self.q60_fails and self.q60_fails[0] < cutoff_60:
            self.q60_fails.popleft()

    def stage_event(self, entry: _HistoryEntry, retention_seconds: int) -> None:
        if self.pending_t is None or entry.time_rel == self.pending_t:
            self.pending_t = entry.time_rel
            self.pending_entries.append(entry)
        else:
            self._flush_pending_before(entry.time_rel, retention_seconds)
            self.pending_t = entry.time_rel
            self.pending_entries.append(entry)


class _SrcWindowState:
    """O(1)-amortized incremental [t - W, t) destination-computer diversity tracker for one src host."""

    __slots__ = (
        "pending_t",
        "pending_entries",
        "q900",
        "dst_counts",
    )

    def __init__(self) -> None:
        self.pending_t: Optional[int] = None
        self.pending_entries: List[_HistoryEntry] = []
        self.q900: Deque[_HistoryEntry] = deque()
        self.dst_counts: Dict[str, int] = {}

    def __iter__(self) -> Iterator[_HistoryEntry]:
        yield from self.q900
        yield from self.pending_entries

    def _add_to_q900(self, entry: _HistoryEntry) -> None:
        self.q900.append(entry)
        self.dst_counts[entry.dst_computer] = self.dst_counts.get(entry.dst_computer, 0) + 1

    def _flush_pending_before(self, t: int, retention_seconds: int) -> None:
        if self.pending_t is not None and t > self.pending_t:
            cutoff_max = t - retention_seconds
            for entry in self.pending_entries:
                if entry.time_rel >= cutoff_max:
                    self._add_to_q900(entry)
            self.pending_entries.clear()
            self.pending_t = None

    def prune(self, current_t: int, retention_seconds: int) -> None:
        self._flush_pending_before(current_t, retention_seconds)
        cutoff = current_t - retention_seconds
        while self.q900 and self.q900[0].time_rel < cutoff:
            old = self.q900.popleft()
            c = self.dst_counts[old.dst_computer] - 1
            if c <= 0:
                del self.dst_counts[old.dst_computer]
            else:
                self.dst_counts[old.dst_computer] = c

    def stage_event(self, entry: _HistoryEntry, retention_seconds: int) -> None:
        if self.pending_t is None or entry.time_rel == self.pending_t:
            self.pending_t = entry.time_rel
            self.pending_entries.append(entry)
        else:
            self._flush_pending_before(entry.time_rel, retention_seconds)
            self.pending_t = entry.time_rel
            self.pending_entries.append(entry)


@dataclass(frozen=True)
class LanlExtractedFeatures:
    lanl_fail_count_1m: Optional[float]
    lanl_fail_count_5m: Optional[float]
    lanl_fail_count_15m: Optional[float]
    lanl_auth_count_15m: Optional[float]
    lanl_unique_dest_users_15m: Optional[float]
    lanl_unique_dst_hosts_per_src_15m: Optional[float]
    lanl_logon_type_entropy_15m: Optional[float]
    lanl_rel_hour_mod24: float
    lanl_fail_1m_available: int
    lanl_fail_5m_available: int
    lanl_fail_15m_available: int
    lanl_auth_15m_available: int
    lanl_unique_dest_users_15m_available: int
    lanl_unique_dst_hosts_per_src_15m_available: int
    lanl_logon_type_entropy_15m_available: int
    lanl_rel_hour_available: int
    unavailable_reasons: Dict[str, str]
    is_out_of_order: bool = False
    is_exact_duplicate: bool = False


class LanlCausalFeatureExtractor:
    """
    Bounded streaming causal extractor over monotonic chronological LANL Cyber1 records.
    Enforces fixed 900-second retention aligned with its 60s/300s/900s aggregation windows:
      - Pair stream: `(source_computer, destination_computer)`
      - Source host lateral stream: `source_computer`
    Rejects timestamp regressions (`time_rel < watermark`) with `ValueError` prior to mutating state.
    """

    def __init__(self, retention_seconds: int = SUPPORTED_RETENTION_SECONDS, max_dedup_cache: int = 100000):
        if isinstance(retention_seconds, bool) or int(retention_seconds) != SUPPORTED_RETENTION_SECONDS:
            raise ValueError(
                f"lanl_auth_features_v1 requires fixed retention_seconds={SUPPORTED_RETENTION_SECONDS}, "
                f"got {retention_seconds!r}"
            )
        self.retention_seconds = SUPPORTED_RETENTION_SECONDS
        self.max_dedup_cache = int(max_dedup_cache)
        self._stream_start_time: Optional[int] = None
        self._watermark_time: Optional[int] = None
        self._pair_events: Dict[Tuple[str, str], _PairWindowState] = {}
        self._src_events: Dict[str, _SrcWindowState] = {}
        self._dedup_seen: Deque[str] = deque()
        self._dedup_set = set()

    def reset_for_block(self) -> None:
        """
        Resets rolling state, warmup coverage origin, and watermark across non-contiguous
        time blocks so post-gap windows cannot emit false 0.0 counts with `available=1`.
        """
        self._stream_start_time = None
        self._watermark_time = None
        self._pair_events.clear()
        self._src_events.clear()
        self._dedup_seen.clear()
        self._dedup_set.clear()

    def _check_duplicate(self, dedup_key: str) -> bool:
        if dedup_key in self._dedup_set:
            return True
        if len(self._dedup_seen) >= self.max_dedup_cache:
            evicted = self._dedup_seen.popleft()
            self._dedup_set.discard(evicted)
        self._dedup_seen.append(dedup_key)
        self._dedup_set.add(dedup_key)
        return False

    @staticmethod
    def _entropy_from_counts(counts: Dict[str, int], total: int) -> Tuple[Optional[float], int, Optional[str]]:
        if total == 0:
            return None, 0, "NO_VALID_LOGON_TYPES"
        if len(counts) == 1:
            return 0.0, 1, None
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * math.log2(p)
        return round(ent, 6), 1, None

    def process_event(self, ev: LanlRawAuthEvent, deduplicate: bool = True) -> LanlExtractedFeatures:
        t = ev.time_rel
        # Fail closed on out-of-order regression BEFORE mutating dedup or rolling state
        if self._watermark_time is not None and t < self._watermark_time:
            raise ValueError(
                f"Out-of-order timestamp regression rejected: time_rel={t} < watermark={self._watermark_time}. "
                "LanlCausalFeatureExtractor requires non-decreasing chronological input."
            )

        # Strict line dedup check: (time_rel, raw_line_hash)
        if deduplicate and self._check_duplicate(f"{t}:{ev.raw_line_hash}"):
            if self._stream_start_time is None:
                self._stream_start_time = t
            if self._watermark_time is None:
                self._watermark_time = t
            return LanlExtractedFeatures(
                lanl_fail_count_1m=None,
                lanl_fail_count_5m=None,
                lanl_fail_count_15m=None,
                lanl_auth_count_15m=None,
                lanl_unique_dest_users_15m=None,
                lanl_unique_dst_hosts_per_src_15m=None,
                lanl_logon_type_entropy_15m=None,
                lanl_rel_hour_mod24=float((t // 3600) % 24),
                lanl_fail_1m_available=0,
                lanl_fail_5m_available=0,
                lanl_fail_15m_available=0,
                lanl_auth_15m_available=0,
                lanl_unique_dest_users_15m_available=0,
                lanl_unique_dst_hosts_per_src_15m_available=0,
                lanl_logon_type_entropy_15m_available=0,
                lanl_rel_hour_available=1,
                unavailable_reasons={"all_rolling": "EXACT_DUPLICATE_LINE"},
                is_exact_duplicate=True,
            )

        if self._stream_start_time is None:
            self._stream_start_time = t
        self._watermark_time = t

        reasons: Dict[str, str] = {}
        rel_hour = float((t // 3600) % 24)
        elapsed = t - self._stream_start_time

        has_pair = bool(ev.source_computer and ev.destination_computer)
        has_src = bool(ev.source_computer)

        if not has_pair:
            f1 = f2 = f3 = f_auth15 = f_users15 = f_ent15 = None
            a1 = a2 = a3 = a_auth15 = a_users15 = a_ent15 = 0
            for k in (
                "lanl_fail_count_1m",
                "lanl_fail_count_5m",
                "lanl_fail_count_15m",
                "lanl_auth_count_15m",
                "lanl_unique_dest_users_15m",
                "lanl_logon_type_entropy_15m",
            ):
                reasons[k] = "MISSING_COMPUTER_IDENTITY"
        else:
            pair_key = (ev.source_computer, ev.destination_computer)
            pstate = self._pair_events.get(pair_key)
            if pstate is not None:
                pstate.prune(t, self.retention_seconds)

            if elapsed < 60:
                f1, a1, r1 = None, 0, "INSUFFICIENT_HISTORICAL_COVERAGE"
            else:
                f1, a1, r1 = float(len(pstate.q60_fails)) if pstate else 0.0, 1, None

            if elapsed < 300:
                f2, a2, r2 = None, 0, "INSUFFICIENT_HISTORICAL_COVERAGE"
            else:
                f2, a2, r2 = float(len(pstate.q300_fails)) if pstate else 0.0, 1, None

            if elapsed < 900:
                f3 = f_auth15 = f_users15 = f_ent15 = None
                a3 = a_auth15 = a_users15 = a_ent15 = 0
                r3 = r_auth15 = r_u15 = r_e15 = "INSUFFICIENT_HISTORICAL_COVERAGE"
            else:
                if pstate is None:
                    f3, a3, r3 = 0.0, 1, None
                    f_auth15, a_auth15, r_auth15 = 0.0, 1, None
                    f_users15, a_users15, r_u15 = 0.0, 1, None
                    f_ent15, a_ent15, r_e15 = None, 0, "NO_VALID_LOGON_TYPES"
                else:
                    f3, a3, r3 = float(pstate.fail_count_900), 1, None
                    f_auth15, a_auth15, r_auth15 = float(pstate.total_count_900), 1, None
                    f_users15, a_users15, r_u15 = float(len(pstate.dest_user_counts)), 1, None
                    f_ent15, a_ent15, r_e15 = self._entropy_from_counts(
                        pstate.logon_type_counts, pstate.logon_type_total
                    )

            for k, r in (
                ("lanl_fail_count_1m", r1),
                ("lanl_fail_count_5m", r2),
                ("lanl_fail_count_15m", r3),
                ("lanl_auth_count_15m", r_auth15),
                ("lanl_unique_dest_users_15m", r_u15),
                ("lanl_logon_type_entropy_15m", r_e15),
            ):
                if r:
                    reasons[k] = r

        if not has_src:
            f_hosts15, a_hosts15 = None, 0
            reasons["lanl_unique_dst_hosts_per_src_15m"] = "MISSING_SOURCE_COMPUTER"
        else:
            sstate = self._src_events.get(ev.source_computer)
            if elapsed < 900:
                f_hosts15, a_hosts15 = None, 0
                reasons["lanl_unique_dst_hosts_per_src_15m"] = "INSUFFICIENT_HISTORICAL_COVERAGE"
            elif sstate is None:
                f_hosts15, a_hosts15 = 0.0, 1
            else:
                sstate.prune(t, self.retention_seconds)
                f_hosts15, a_hosts15 = float(len(sstate.dst_counts)), 1

        # Commit event AFTER feature computation strictly preserving point-in-time causality
        if has_src and ev.destination_computer:
            entry = _HistoryEntry(
                time_rel=t,
                dest_user=ev.destination_user,
                dst_computer=ev.destination_computer,
                logon_type=ev.logon_type,
                is_fail=(ev.outcome == "Fail"),
            )
            sstate = self._src_events.get(ev.source_computer)
            if sstate is None:
                sstate = _SrcWindowState()
                self._src_events[ev.source_computer] = sstate
            sstate.stage_event(entry, self.retention_seconds)

            if has_pair:
                pair_key = (ev.source_computer, ev.destination_computer)
                pstate = self._pair_events.get(pair_key)
                if pstate is None:
                    pstate = _PairWindowState()
                    self._pair_events[pair_key] = pstate
                pstate.stage_event(entry, self.retention_seconds)

        return LanlExtractedFeatures(
            lanl_fail_count_1m=f1,
            lanl_fail_count_5m=f2,
            lanl_fail_count_15m=f3,
            lanl_auth_count_15m=f_auth15,
            lanl_unique_dest_users_15m=f_users15,
            lanl_unique_dst_hosts_per_src_15m=f_hosts15,
            lanl_logon_type_entropy_15m=f_ent15,
            lanl_rel_hour_mod24=rel_hour,
            lanl_fail_1m_available=a1,
            lanl_fail_5m_available=a2,
            lanl_fail_15m_available=a3,
            lanl_auth_15m_available=a_auth15,
            lanl_unique_dest_users_15m_available=a_users15,
            lanl_unique_dst_hosts_per_src_15m_available=a_hosts15,
            lanl_logon_type_entropy_15m_available=a_ent15,
            lanl_rel_hour_available=1,
            unavailable_reasons=reasons,
            is_out_of_order=False,
            is_exact_duplicate=False,
        )
