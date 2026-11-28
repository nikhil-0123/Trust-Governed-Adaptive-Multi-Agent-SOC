"""
Safe Offline Windows Security Authentication Collector (Phase 3B).

Collects genuine Windows Event IDs 4624 and 4625 in strict read-only mode
using wevtutil, completely isolated from frozen production windows-telemetry
checkpoints, agent_identity.json, outbox.db, and soc_central.db.
"""

from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

from .schema import TelemetryOrigin


PRODUCTION_FORBIDDEN_FILENAMES = ("outbox.db", "agent_identity.json", "soc_central.db")
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_BATCH_SIZE = 1000

# Strictly whitelisted authentication event fields (never collects credentials/tokens)
SAFE_EVENT_DATA_FIELDS = (
    "TargetUserName",
    "TargetDomainName",
    "SubjectUserName",
    "SubjectDomainName",
    "LogonType",
    "IpAddress",
    "IpPort",
    "WorkstationName",
    "LogonProcessName",
    "AuthenticationPackageName",
    "Status",
    "SubStatus",
)


class CollectorIsolationError(RuntimeError):
    """Raised when collection paths risk overlapping production telemetry state."""
    pass


class DiscontinuityError(RuntimeError):
    """Raised when Security record ID regresses without an authoritative Event 1102 clear witness."""
    pass


def validate_isolated_ml_paths(state_dir: Path, output_dir: Path) -> None:
    """
    Fail-closed guard ensuring offline ML dataset collection state and outputs
    never overlap with production or simulation telemetry directories (avoiding
    the explicit DATA_DIR overlap hazard).
    """
    resolved_state = state_dir.resolve()
    resolved_out = output_dir.resolve()

    home_tgam = (Path.home() / ".tgam_soc").resolve()
    programdata_tgam = Path(r"C:\ProgramData\TGAM-SOC").resolve()
    repo_root = Path(__file__).resolve().parents[2]
    win_tel_dir = (repo_root / "windows-telemetry").resolve()
    soc_dir = (repo_root / "SOC").resolve()

    forbidden_roots = [home_tgam, programdata_tgam, win_tel_dir, soc_dir]
    if os.getenv("DATA_DIR"):
        forbidden_roots.append(Path(os.environ["DATA_DIR"]).resolve())
    if os.getenv("WINDOWS_CHECKPOINT_DIR"):
        forbidden_roots.append(Path(os.environ["WINDOWS_CHECKPOINT_DIR"]).resolve())

    for target in (resolved_state, resolved_out):
        for root in forbidden_roots:
            try:
                target.relative_to(root)
                raise CollectorIsolationError(
                    f"Isolated ML collector path '{target}' cannot be inside runtime/source path '{root}'."
                )
            except ValueError:
                pass
        if target.exists():
            for fname in PRODUCTION_FORBIDDEN_FILENAMES:
                if (target / fname).exists():
                    raise CollectorIsolationError(
                        f"Refusing to share directory '{target}' containing runtime artifact '{fname}'."
                    )


def _decode_command_output(raw: bytes) -> str:
    if not raw:
        return ""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    for enc in ("utf-8", "cp1252", "mbcs"):
        try:
            text = raw.decode(enc)
            if "\x00" not in text:
                return text
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def parse_security_auth_xml(xml_text: str) -> List[Dict[str, Any]]:
    """
    Parses read-only wevtutil Security XML into sanitized auth event dicts
    containing strictly whitelisted metadata/auth fields (no raw XML stored).
    """
    stripped = xml_text.strip()
    if not stripped:
        return []
    # Strip optional UTF/XML declaration if present
    stripped = re.sub(r"^<\?xml[^>]+\?>\s*", "", stripped, flags=re.IGNORECASE)
    if not stripped:
        return []

    root = ET.fromstring(f"<Events>{stripped}</Events>")
    events: List[Dict[str, Any]] = []
    for ev in root:
        sys_elem = ev.find("./{*}System")
        if sys_elem is None:
            continue

        eid_elem = sys_elem.find("./{*}EventID")
        rec_elem = sys_elem.find("./{*}EventRecordID")
        ts_elem = sys_elem.find("./{*}TimeCreated")
        comp_elem = sys_elem.find("./{*}Computer")
        prov_elem = sys_elem.find("./{*}Provider")
        chan_elem = sys_elem.find("./{*}Channel")

        if eid_elem is None or rec_elem is None or ts_elem is None:
            continue

        event_id = int(eid_elem.text.strip())
        record_id = int(rec_elem.text.strip())
        ts_str = ts_elem.attrib.get("SystemTime", "").strip()
        computer = comp_elem.text.strip() if (comp_elem is not None and comp_elem.text) else None
        provider = prov_elem.attrib.get("Name") if prov_elem is not None else "Microsoft-Windows-Security-Auditing"
        channel = chan_elem.text.strip() if (chan_elem is not None and chan_elem.text) else "Security"

        raw_data: Dict[str, str] = {}
        ed_elem = ev.find("./{*}EventData")
        if ed_elem is not None:
            for d in ed_elem:
                name = d.attrib.get("Name")
                if name in SAFE_EVENT_DATA_FIELDS:
                    val = d.text.strip() if d.text else ""
                    if val and val != "-":
                        raw_data[name] = val

        logon_type: Optional[int] = None
        if "LogonType" in raw_data:
            try:
                logon_type = int(raw_data["LogonType"])
            except ValueError:
                logon_type = None

        target_user = raw_data.get("TargetUserName")
        target_domain = raw_data.get("TargetDomainName")
        subject_user = raw_data.get("SubjectUserName")
        subject_domain = raw_data.get("SubjectDomainName")

        events.append({
            "channel": channel,
            "provider": provider,
            "event_id": event_id,
            "record_id": record_id,
            "timestamp": ts_str,
            "computer": computer,
            "target_user": target_user,
            "target_domain": target_domain,
            "subject_user": subject_user,
            "subject_domain": subject_domain,
            "logon_type": logon_type,
            "source_ip": raw_data.get("IpAddress"),
            "ip_port": raw_data.get("IpPort"),
            "workstation_name": raw_data.get("WorkstationName"),
            "logon_process": raw_data.get("LogonProcessName"),
            "auth_package": raw_data.get("AuthenticationPackageName"),
            "status": raw_data.get("Status"),
            "sub_status": raw_data.get("SubStatus"),
            "telemetry_origin": TelemetryOrigin.GENUINE_WINDOWS.value,
        })
    return events


def parse_wevtutil_gl_security(gl_text: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    for line in gl_text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if key in ("enabled", "retention", "autobackup"):
            meta[key] = val.lower() == "true"
        elif key == "maxsize":
            try:
                meta["max_size_bytes"] = int(val)
            except ValueError:
                pass
        elif key == "name":
            meta["channel_name"] = val
    return meta


def parse_auditpol_logon(audit_text: str) -> Dict[str, str]:
    policy: Dict[str, str] = {}
    for line in audit_text.splitlines():
        stripped = line.strip()
        for subcat in ("Logon", "Logoff", "Account Lockout", "Special Logon", "Other Logon/Logoff Events"):
            if stripped.startswith(subcat):
                rest = stripped[len(subcat):].strip()
                if rest:
                    policy[subcat] = rest
    return policy


@dataclass
class OfflineCollectionSummary:
    session_id: str
    collection_start_utc: str
    collection_end_utc: str
    channel: str
    channel_epoch: int
    start_checkpoint_record_id: int
    end_checkpoint_record_id: int
    earliest_host_record_id: Optional[int]
    latest_host_record_id: Optional[int]
    earliest_host_timestamp_utc: Optional[str]
    latest_host_timestamp_utc: Optional[str]
    events_queried: int
    events_written: int
    duplicates_skipped: int
    gap_detected: bool
    gap_details: List[Dict[str, Any]]
    audit_policy: Dict[str, str]
    channel_config: Dict[str, Any]
    output_jsonl_path: str
    output_jsonl_sha256: str


class OfflineSecurityAuthCollector:
    """
    Incremental read-only collector for genuine Windows Security Events 4624/4625.
    Does not mutate Windows logs and never touches production telemetry state.
    """

    def __init__(
        self,
        state_dir: Path,
        output_dir: Path,
        batch_size: int = 250,
        runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    ):
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not (1 <= batch_size <= MAX_BATCH_SIZE):
            raise ValueError(f"batch_size must be an integer between 1 and {MAX_BATCH_SIZE}, got {batch_size!r}")

        self.state_dir = Path(state_dir)
        self.output_dir = Path(output_dir)
        validate_isolated_ml_paths(self.state_dir, self.output_dir)

        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.batch_size = batch_size
        self.runner = runner or subprocess.run
        self.state_file = self.state_dir / "offline_ml_security_state.json"

    def _run_cmd(self, args: Sequence[str]) -> str:
        res = self.runner(list(args), capture_output=True, timeout=DEFAULT_TIMEOUT_SECONDS)
        if res.returncode != 0:
            err = _decode_command_output(res.stderr or b"")
            raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(args)} -> {err.strip()}")
        return _decode_command_output(res.stdout or b"")

    def _load_state(self) -> Dict[str, Any]:
        if not self.state_file.exists():
            return {
                "last_record_id": 0,
                "channel_epoch": 1,
                "collection_seq": 0,
                "coverage_start_utc": None,
                "gaps": [],
                "recent_seen_keys": [],
            }
        with open(self.state_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_state_atomic(self, state: Dict[str, Any]) -> None:
        tmp = self.state_file.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_file)

    def inspect_environment_readiness(self) -> Dict[str, Any]:
        """Executes read-only checks of Security audit policy, log config, bounds, and Event 1102."""
        gl_raw = self._run_cmd(["wevtutil", "gl", "Security"])
        audit_raw = self._run_cmd(["auditpol", "/get", "/category:Logon/Logoff"])
        earliest_raw = self._run_cmd(["wevtutil", "qe", "Security", "/c:1", "/f:xml"])
        latest_raw = self._run_cmd(["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:xml"])

        earliest_evs = parse_security_auth_xml(earliest_raw)
        latest_evs = parse_security_auth_xml(latest_raw)

        return {
            "channel_config": parse_wevtutil_gl_security(gl_raw),
            "audit_policy": parse_auditpol_logon(audit_raw),
            "earliest_record": earliest_evs[0] if earliest_evs else None,
            "latest_record": latest_evs[0] if latest_evs else None,
        }

    def collect_incremental(
        self,
        session_id: str,
        max_batches: int = 20,
        output_filename: Optional[str] = None,
    ) -> OfflineCollectionSummary:
        """
        Incrementally exports unread Windows Security Event 4624/4625 records into
        gitignored JSONL, tracking continuity, overwrite gaps, epoch clears, and duplicates.
        """
        if not session_id or not str(session_id).strip():
            raise ValueError("session_id must be non-empty")

        collection_start_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        state = self._load_state()
        start_checkpoint = int(state.get("last_record_id", 0))
        epoch = int(state.get("channel_epoch", 1))
        seq = int(state.get("collection_seq", 0))
        seen_queue = deque(state.get("recent_seen_keys", []), maxlen=20000)
        seen_set = set(seen_queue)

        env = self.inspect_environment_readiness()
        earliest = env.get("earliest_record")
        latest = env.get("latest_record")
        earliest_rec_id = earliest["record_id"] if earliest else None
        latest_rec_id = latest["record_id"] if latest else None

        gap_details: List[Dict[str, Any]] = []
        gap_detected = False

        # Detect circular overwrite gap or record regression
        if start_checkpoint > 0 and latest_rec_id is not None:
            if latest_rec_id < start_checkpoint:
                # Probe Security 1102 read-only to distinguish legitimate log clear vs corruption
                clear_xml = self._run_cmd([
                    "wevtutil", "qe", "Security", "/q:*[System[(EventID=1102)]]", "/c:5", "/rd:true", "/f:xml"
                ])
                clear_evs = parse_security_auth_xml(clear_xml)
                if not clear_evs:
                    raise DiscontinuityError(
                        f"Security EventRecordID regressed ({start_checkpoint} -> {latest_rec_id}) without Event 1102 clear witness."
                    )
                epoch += 1
                start_checkpoint = 0
                gap_detected = True
                gap_details.append({
                    "gap_type": "LOG_CLEARED_1102",
                    "new_epoch": epoch,
                    "clear_timestamp_utc": clear_evs[0]["timestamp"],
                })
            elif earliest_rec_id is not None and earliest_rec_id > start_checkpoint + 1:
                gap_detected = True
                gap_details.append({
                    "gap_type": "UNRECOVERABLE_OVERWRITE_GAP",
                    "missing_after_record_id": start_checkpoint,
                    "earliest_available_record_id": earliest_rec_id,
                    "gap_end_utc": earliest["timestamp"] if earliest else collection_start_utc,
                })

        fname = output_filename or f"security_auth_{session_id}.jsonl"
        out_path = self.output_dir / fname

        cursor = start_checkpoint
        events_queried = 0
        events_written = 0
        duplicates_skipped = 0

        existing_records: List[Dict[str, Any]] = []
        if out_path.exists():
            with open(out_path, "r", encoding="utf-8") as ef:
                for line in ef:
                    if line.strip():
                        existing_records.append(json.loads(line))
                        try:
                            rec_obj = existing_records[-1]
                            k = f"{rec_obj.get('channel_epoch', epoch)}:{rec_obj.get('record_id')}"
                            if k not in seen_set:
                                seen_queue.append(k)
                                seen_set.add(k)
                        except Exception:
                            pass

        new_records: List[Dict[str, Any]] = []
        for _ in range(max_batches):
            if latest_rec_id is not None and cursor >= latest_rec_id:
                break

            xpath = f"*[System[(EventID=4624 or EventID=4625) and EventRecordID > {cursor}]]"
            raw_xml = self._run_cmd([
                "wevtutil", "qe", "Security", f"/q:{xpath}", f"/c:{self.batch_size}", "/f:xml"
            ])
            batch = parse_security_auth_xml(raw_xml)
            if not batch:
                # Advance cursor safely to latest_rec_id only if query returned empty at tail?
                # Do NOT skip unknown intermediate records; break cleanly at end of auth events
                break

            events_queried += len(batch)
            max_batch_rec = cursor
            for ev in batch:
                rec_id = int(ev["record_id"])
                if rec_id > max_batch_rec:
                    max_batch_rec = rec_id

                dedup_key = f"{epoch}:{rec_id}"
                if dedup_key in seen_set:
                    duplicates_skipped += 1
                    continue

                seq += 1
                seen_queue.append(dedup_key)
                seen_set.add(dedup_key)
                ev["channel_epoch"] = epoch
                ev["collection_seq"] = seq
                ev["collected_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                new_records.append(ev)
                events_written += 1

            if max_batch_rec <= cursor:
                break
            cursor = max_batch_rec
            if len(batch) < self.batch_size:
                break

        with open(out_path, "w", encoding="utf-8", newline="\n") as out_f:
            for item in existing_records + new_records:
                out_f.write(json.dumps(item, sort_keys=True) + "\n")

        out_hash = hashlib.sha256(out_path.read_bytes()).hexdigest()
        collection_end_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Update persistent collector checkpoint state atomically
        new_state = {
            "last_record_id": cursor,
            "channel_epoch": epoch,
            "collection_seq": seq,
            "coverage_start_utc": state.get("coverage_start_utc") or (earliest["timestamp"] if earliest else collection_start_utc),
            "last_collection_utc": collection_end_utc,
            "gaps": state.get("gaps", []) + gap_details,
            "recent_seen_keys": list(seen_queue),
        }
        self._save_state_atomic(new_state)

        summary = OfflineCollectionSummary(
            session_id=session_id,
            collection_start_utc=collection_start_utc,
            collection_end_utc=collection_end_utc,
            channel="Security",
            channel_epoch=epoch,
            start_checkpoint_record_id=start_checkpoint,
            end_checkpoint_record_id=cursor,
            earliest_host_record_id=earliest_rec_id,
            latest_host_record_id=latest_rec_id,
            earliest_host_timestamp_utc=earliest["timestamp"] if earliest else None,
            latest_host_timestamp_utc=latest["timestamp"] if latest else None,
            events_queried=events_queried,
            events_written=events_written,
            duplicates_skipped=duplicates_skipped,
            gap_detected=gap_detected,
            gap_details=gap_details,
            audit_policy=env["audit_policy"],
            channel_config=env["channel_config"],
            output_jsonl_path=str(out_path),
            output_jsonl_sha256=out_hash,
        )

        manifest_path = self.output_dir / f"collection_session_{session_id}.json"
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as mf:
            json.dump(asdict(summary), mf, indent=2, sort_keys=True)

        return summary
