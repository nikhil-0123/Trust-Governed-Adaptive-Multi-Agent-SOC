"""
Passive Offline OTRF Security-Datasets Windows Authentication Adapter (`otrf_mordor_audit_v1`).

Reads OTRF Mordor/Winlogbeat JSON records directly from `.zip` or `.jsonl` streams
without extracting scripts/binaries to disk and without fabricating missing fields
or per-event malicious ground-truth labels.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple
import zipfile

OTRF_SCHEMA_VERSION = "otrf_mordor_audit_v1"

_MISSING_IP_MARKERS = {"", "-", "::", "0.0.0.0"}
_LOOPBACK_IPS = {"127.0.0.1", "::1"}


@dataclass(frozen=True)
class OtrfAuthRecord:
    """Normalized OTRF Windows Security Event 4624/4625 record without synthetic labels."""

    schema_version: str
    source_capture: str
    channel: str
    event_id: int
    record_id: Optional[int]
    hostname: Optional[str]
    timestamp_utc: Optional[str]
    source_ip: Optional[str]
    source_ip_present: bool
    is_loopback_ip: bool
    logon_type: Optional[int]
    target_username: Optional[str]
    target_domain: Optional[str]
    target_user_sid: Optional[str]
    subject_username: Optional[str]
    subject_domain: Optional[str]
    auth_package: Optional[str]
    status_code: Optional[str]
    sub_status_code: Optional[str]
    raw_tags: Tuple[str, ...]
    raw_record_hash: str
    label: Optional[int] = None
    label_source: str = "unlabeled_mixed_adversarial_capture"


@dataclass(frozen=True)
class OtrfCaptureSummary:
    """Passive schema, identity, field-availability, and duplicate audit summary."""

    source_capture: str
    total_events: int
    security_channel_events: int
    lowercase_security_channel_events: int
    event_4624_count: int
    event_4625_count: int
    auth_with_non_loopback_ip: int
    auth_with_loopback_ip: int
    auth_with_missing_ip: int
    logon_types_4624: Dict[str, int]
    logon_types_4625: Dict[str, int]
    duplicate_raw_records: int
    duplicate_channel_host_record_id: int
    timestamp_min: Optional[str]
    timestamp_max: Optional[str]
    per_event_ground_truth_available: bool


def _clean_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    if not s or s == "-":
        return None
    return s


def _get_field(rec: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    event_data = rec.get("EventData") or rec.get("winlog", {}).get("event_data")
    if isinstance(event_data, dict):
        for k in keys:
            if k in event_data and event_data[k] not in (None, ""):
                return event_data[k]
    return None


def iter_otrf_json_lines(raw_text: str) -> Iterator[Dict[str, Any]]:
    """Iterates JSON object records from either a JSON array or JSON-lines payload."""
    stripped = raw_text.lstrip()
    if not stripped:
        return
    if stripped.startswith("["):
        arr = json.loads(stripped)
        for obj in arr:
            if isinstance(obj, dict):
                yield obj
        return
    for line in io.StringIO(stripped):
        s = line.strip()
        if not s:
            continue
        obj = json.loads(s)
        if isinstance(obj, dict):
            yield obj


def iter_otrf_zip_records(zip_path: Path) -> Iterator[Dict[str, Any]]:
    """Passively streams JSON records inside an OTRF `.zip` without disk extraction."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if not info.filename.lower().endswith((".json", ".jsonl")):
                continue
            raw_bytes = zf.read(info.filename)
            yield from iter_otrf_json_lines(raw_bytes.decode("utf-8", errors="replace"))


def parse_otrf_auth_event(rec: Dict[str, Any], source_capture: str) -> Optional[OtrfAuthRecord]:
    """
    Parses an OTRF Security 4624/4625 JSON object cleanly.
    Normalizes case-insensitive `Channel` (`Security`/`security`), string `LogonType`,
    and Mordor `RecordNumber` vs `EventRecordID` without fabricating missing values or labels.
    """
    raw_channel = _clean_str(_get_field(rec, "Channel", "channel"))
    if not raw_channel or raw_channel.lower() != "security":
        return None

    eid_val = _get_field(rec, "EventID", "event_id")
    try:
        eid = int(eid_val)
    except (TypeError, ValueError):
        return None
    if eid not in (4624, 4625):
        return None

    rec_id_val = _get_field(rec, "EventRecordID", "RecordNumber")
    try:
        record_id = int(rec_id_val) if rec_id_val is not None else None
    except (TypeError, ValueError):
        record_id = None

    raw_ip = _get_field(rec, "IpAddress", "SourceNetworkAddress")
    ip_norm = None if raw_ip is None else str(raw_ip).strip()
    if not ip_norm or ip_norm in _MISSING_IP_MARKERS:
        source_ip = None
        ip_present = False
        is_loopback = False
    else:
        source_ip = ip_norm
        ip_present = True
        is_loopback = ip_norm in _LOOPBACK_IPS

    lt_val = _get_field(rec, "LogonType")
    try:
        logon_type = int(str(lt_val).strip()) if _clean_str(lt_val) is not None else None
    except ValueError:
        logon_type = None

    raw_tags_val = rec.get("tags") or rec.get("tag") or ()
    if isinstance(raw_tags_val, list):
        raw_tags = tuple(str(t) for t in raw_tags_val)
    elif raw_tags_val is None:
        raw_tags = ()
    else:
        raw_tags = (str(raw_tags_val),)

    raw_hash = hashlib.sha256(
        json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:24]

    return OtrfAuthRecord(
        schema_version=OTRF_SCHEMA_VERSION,
        source_capture=source_capture,
        channel="Security",
        event_id=eid,
        record_id=record_id,
        hostname=_clean_str(_get_field(rec, "Hostname", "Computer", "host")),
        timestamp_utc=_clean_str(_get_field(rec, "@timestamp", "TimeCreated", "EventTime", "timestamp")),
        source_ip=source_ip,
        source_ip_present=ip_present,
        is_loopback_ip=is_loopback,
        logon_type=logon_type,
        target_username=_clean_str(_get_field(rec, "TargetUserName")),
        target_domain=_clean_str(_get_field(rec, "TargetDomainName")),
        target_user_sid=_clean_str(_get_field(rec, "TargetUserSid")),
        subject_username=_clean_str(_get_field(rec, "SubjectUserName")),
        subject_domain=_clean_str(_get_field(rec, "SubjectDomainName")),
        auth_package=_clean_str(_get_field(rec, "AuthenticationPackageName")),
        status_code=_clean_str(_get_field(rec, "Status")),
        sub_status_code=_clean_str(_get_field(rec, "SubStatus")),
        raw_tags=raw_tags,
        raw_record_hash=raw_hash,
        label=None,
        label_source="unlabeled_mixed_adversarial_capture",
    )


def summarize_otrf_records(records: Iterable[Dict[str, Any]], source_capture: str) -> OtrfCaptureSummary:
    """Computes passive telemetry and duplicate audit statistics over OTRF event dicts."""
    total = 0
    sec_events = 0
    lower_sec = 0
    cnt_4624 = 0
    cnt_4625 = 0
    non_loopback = 0
    loopback = 0
    missing_ip = 0
    lt_4624: Counter = Counter()
    lt_4625: Counter = Counter()
    timestamps = []
    seen_hashes = set()
    dup_raw = 0
    seen_ids = set()
    dup_ids = 0

    for rec in records:
        total += 1
        raw_hash = hashlib.sha256(
            json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if raw_hash in seen_hashes:
            dup_raw += 1
        else:
            seen_hashes.add(raw_hash)

        raw_ch = str(_get_field(rec, "Channel", "channel") or "")
        if raw_ch.lower() == "security":
            sec_events += 1
            if raw_ch == "security":
                lower_sec += 1

        ts = _clean_str(_get_field(rec, "@timestamp", "TimeCreated", "EventTime", "timestamp"))
        if ts:
            timestamps.append(ts)

        host = _clean_str(_get_field(rec, "Hostname", "Computer", "host"))
        rec_id = _get_field(rec, "EventRecordID", "RecordNumber")
        if raw_ch and host and rec_id is not None:
            ident = (raw_ch.lower(), host.lower(), str(rec_id))
            if ident in seen_ids:
                dup_ids += 1
            else:
                seen_ids.add(ident)

        parsed = parse_otrf_auth_event(rec, source_capture=source_capture)
        if parsed is None:
            continue
        if parsed.event_id == 4624:
            cnt_4624 += 1
            lt_4624[str(parsed.logon_type) if parsed.logon_type is not None else "<missing>"] += 1
        else:
            cnt_4625 += 1
            lt_4625[str(parsed.logon_type) if parsed.logon_type is not None else "<missing>"] += 1

        if not parsed.source_ip_present:
            missing_ip += 1
        elif parsed.is_loopback_ip:
            loopback += 1
        else:
            non_loopback += 1

    return OtrfCaptureSummary(
        source_capture=source_capture,
        total_events=total,
        security_channel_events=sec_events,
        lowercase_security_channel_events=lower_sec,
        event_4624_count=cnt_4624,
        event_4625_count=cnt_4625,
        auth_with_non_loopback_ip=non_loopback,
        auth_with_loopback_ip=loopback,
        auth_with_missing_ip=missing_ip,
        logon_types_4624=dict(lt_4624.most_common()),
        logon_types_4625=dict(lt_4625.most_common()),
        duplicate_raw_records=dup_raw,
        duplicate_channel_host_record_id=dup_ids,
        timestamp_min=min(timestamps) if timestamps else None,
        timestamp_max=max(timestamps) if timestamps else None,
        per_event_ground_truth_available=False,
    )


def summarize_otrf_auth_capture(zip_path: Path, source_capture: Optional[str] = None) -> OtrfCaptureSummary:
    """Runs passive audit statistics over an OTRF `.zip` archive without extraction."""
    name = source_capture or zip_path.stem
    return summarize_otrf_records(iter_otrf_zip_records(zip_path), source_capture=name)
