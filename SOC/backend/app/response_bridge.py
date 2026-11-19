import json
import uuid
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Canonical action types recognized by TGAM-SOC Response Engine
SUPPORTED_RESPONSE_ACTIONS = {
    "ISOLATE_HOST",
    "BLOCK_SOURCE",
    "BLOCK_SOURCE_IP",
    "KILL_PROCESS",
    "DISABLE_ACCOUNT",
    "QUARANTINE_FILE"
}

AUTHORIZED_RECOVERY_REASONS = {
    "CORRUPTED_LOCAL_CHECKPOINT",
    "HOST_UNEXPECTED_REBOOT",
    "ADMINISTRATIVE_RESET",
    "CRASH_RECOVERY",
    "OFFLINE_CHECKPOINT_RECOVERY",
    "LOCAL_CHECKPOINT_CORRUPTION",
}

AUTHORIZED_RECOVERY_TRANSITION_TYPES = {
    "ADMINISTRATIVE_GAP_RESOLUTION",
    "RECOVERY",
    "RECOVERY_RELEASE",
    "GAP_RESOLUTION",
}

# Approved authorization statuses in TGAM-SOC transition and recovery governance
APPROVED_AUTHORIZATION_STATUSES = {
    "RESOLVED",
    "APPLIED",
    "APPROVED",
    "ALLOCATED",
}

# Trusted actors authorized to grant recovery or administrative transitions
TRUSTED_AUTHORIZATION_ACTORS = {
    "ADMIN",
    "SOC_ADMIN",
    "SOC-LEAD-ANALYST",
    "SOC_LEAD_ANALYST",
    "SOC_LEAD",
    "AUTONOMOUS_GOVERNANCE",
    "ANALYST",
    "SOC_ANALYST",
}

@dataclass(frozen=True)
class AccountTargetRecord:
    target_account_id: str
    target_user: str
    target_domain: Optional[str]
    domain_status: str
    domain_namespace: str
    target_agent_id: str
    target_hostname: str
    originating_detection_event_id: str
    source_event_id: Optional[str] = None

def validate_account_target_record(record: AccountTargetRecord) -> bool:
    """
    Validates cross-field identity consistency for an AccountTargetRecord.
    Raises ValueError on contradictory identity fields.
    """
    if record.domain_status == "LOCAL_SAM":
        if record.domain_namespace != "LOCAL_SAM":
            raise ValueError(f"Contradictory identity: domain_status is LOCAL_SAM but domain_namespace is '{record.domain_namespace}'")
        if record.target_account_id and not record.target_account_id.lower().startswith("local_sam\\"):
            raise ValueError(f"Contradictory identity: domain_status is LOCAL_SAM but target_account_id is '{record.target_account_id}'")
        if record.target_account_id and record.target_user:
            expected_id = f"LOCAL_SAM\\{record.target_user.lower()}"
            if record.target_account_id.lower() != expected_id.lower():
                raise ValueError(f"Contradictory identity: target_account_id '{record.target_account_id}' does not match expected '{expected_id}'")
    elif record.domain_status == "OBSERVED_DOMAIN":
        if not record.domain_namespace or not record.domain_namespace.startswith("DOMAIN:"):
            raise ValueError(f"Contradictory identity: domain_status is OBSERVED_DOMAIN but domain_namespace is '{record.domain_namespace}'")
        expected_id = f"{record.domain_namespace}\\{record.target_user.lower()}"
        if record.target_account_id and record.target_account_id.lower() != expected_id.lower():
            raise ValueError(f"Contradictory identity: target_account_id '{record.target_account_id}' does not match expected '{expected_id}'")
    elif record.domain_status == "UNVERIFIED":
        if record.domain_namespace not in (None, "UNVERIFIED"):
            raise ValueError(f"Contradictory identity: domain_status is UNVERIFIED but domain_namespace is '{record.domain_namespace}'")
    else:
        raise ValueError(f"Invalid domain_status: '{record.domain_status}'")
    return True

def select_account_target_record(
    incident_id: str,
    account_targets: List[AccountTargetRecord],
    custom_params: Optional[Dict[str, Any]] = None
) -> AccountTargetRecord:
    """
    Resolves exactly one AccountTargetRecord for the incident based on governance parameters.
    Fails closed on zero or multiple matching records (strictly enforces cardinality == 1).
    """
    if not account_targets:
        raise ValueError(f"No account targets available for incident {incident_id}")

    candidates = list(account_targets)
    params = custom_params or {}

    # Disambiguation filters
    if params.get("originating_detection_event_id"):
        candidates = [c for c in candidates if c.originating_detection_event_id == params["originating_detection_event_id"]]
    if params.get("target_agent_id"):
        candidates = [c for c in candidates if c.target_agent_id == params["target_agent_id"]]
    if params.get("target_account_id"):
        candidates = [c for c in candidates if c.target_account_id.lower() == params["target_account_id"].lower()]
    if params.get("username"):
        candidates = [c for c in candidates if c.target_user.lower() == params["username"].lower()]

    if len(candidates) == 0:
        raise ValueError(f"Zero AccountTargetRecord matches for incident {incident_id} with filters {params}")
    if len(candidates) > 1:
        raise ValueError(
            f"Ambiguous account target for incident {incident_id}: {len(candidates)} records matched. "
            f"Exact target disambiguation requires 'originating_detection_event_id' or more specific target parameters. "
            f"Candidate detection events: {[c.originating_detection_event_id for c in candidates]}"
        )

    selected = candidates[0]
    validate_account_target_record(selected)
    return selected

def get_incident_endpoint_targets(conn, incident_id: str) -> Dict[str, Any]:
    """
    Extracts all endpoint targets (agent IDs, IPs, hostnames, usernames, process evidence, account targets)
    associated with an incident case.
    """
    # 1. Fetch from incident_entities
    cursor = conn.execute("""
        SELECT entity_type, entity_value 
        FROM incident_entities 
        WHERE incident_id = ?
    """, (incident_id,))
    
    entities: Dict[str, List[str]] = {}
    for row in cursor.fetchall():
        etype = row["entity_type"]
        evalue = row["entity_value"]
        if etype not in entities:
            entities[etype] = []
        if evalue not in entities[etype]:
            entities[etype].append(evalue)

    # 2. Fetch raw evidence from events table via incident_evidence
    ev_cursor = conn.execute("""
        SELECT e.data
        FROM events e
        JOIN incident_evidence ie ON e.detection_event_id = ie.detection_event_id
        WHERE ie.incident_id = ?
    """, (incident_id,))
    
    events_data = []
    agent_ids = list(entities.get("agent_id", []))
    hostnames = list(entities.get("hostname", []))
    source_ips = list(entities.get("source_ip", []))
    usernames = list(entities.get("username", []))
    process_ids = []
    process_names = []
    account_targets: List[AccountTargetRecord] = []

    for r in ev_cursor.fetchall():
        try:
            ev = json.loads(r["data"])
            events_data.append(ev)
            if ev.get("agent_id") and ev["agent_id"] not in agent_ids:
                agent_ids.append(ev["agent_id"])
            if ev.get("hostname") and ev["hostname"] not in hostnames:
                hostnames.append(ev["hostname"])
            if ev.get("source_ip") and ev["source_ip"] not in source_ips:
                source_ips.append(ev["source_ip"])
            if ev.get("username") and ev["username"] not in usernames:
                usernames.append(ev["username"])

            ev_evidence = ev.get("evidence") or {}
            if ev_evidence.get("source_ip") and ev_evidence["source_ip"] not in source_ips:
                source_ips.append(ev_evidence["source_ip"])
            if ev_evidence.get("process_id") and ev_evidence["process_id"] not in process_ids:
                process_ids.append(str(ev_evidence["process_id"]))
            if ev_evidence.get("process_name") and ev_evidence["process_name"] not in process_names:
                process_names.append(ev_evidence["process_name"])

            # Account Target Record Extraction
            target_account_id = ev_evidence.get("target_account_id")
            target_user = ev_evidence.get("target_user")
            domain_status = ev_evidence.get("domain_status")
            domain_namespace = ev_evidence.get("domain_namespace")
            target_domain = ev_evidence.get("target_domain")

            if not target_user and ev.get("username"):
                target_user = ev.get("username")

            if target_account_id or target_user:
                u_str = target_user or (target_account_id.split("\\", 1)[-1] if target_account_id else "")
                if domain_status == "LOCAL_SAM":
                    resolved_ns = "LOCAL_SAM"
                    expected_id = f"LOCAL_SAM\\{u_str.lower()}"
                elif domain_status == "OBSERVED_DOMAIN":
                    dom = target_domain.upper() if target_domain else (domain_namespace.split(":", 1)[1] if domain_namespace and ":" in domain_namespace else "UNKNOWN")
                    resolved_ns = domain_namespace or f"DOMAIN:{dom}"
                    expected_id = f"{resolved_ns}\\{u_str.lower()}"
                else:
                    resolved_ns = domain_namespace or "UNVERIFIED"
                    expected_id = target_account_id or u_str

                rec = AccountTargetRecord(
                    target_account_id=target_account_id or expected_id,
                    target_user=u_str,
                    target_domain=target_domain,
                    domain_status=domain_status or "UNVERIFIED",
                    domain_namespace=domain_namespace or resolved_ns,
                    target_agent_id=ev.get("agent_id") or "",
                    target_hostname=ev.get("hostname") or "",
                    originating_detection_event_id=ev.get("detection_event_id") or "",
                    source_event_id=ev.get("source_event_id") or ev_evidence.get("source_event_id")
                )
                account_targets.append(rec)
        except Exception:
            continue

    # 3. If no agent_id found yet, attempt to match registered endpoints by hostname or IP
    if not agent_ids:
        for host in hostnames:
            ep_row = conn.execute("SELECT agent_id FROM endpoints WHERE hostname = ? LIMIT 1", (host,)).fetchone()
            if ep_row and ep_row["agent_id"] not in agent_ids:
                agent_ids.append(ep_row["agent_id"])

    return {
        "incident_id": incident_id,
        "agent_ids": agent_ids,
        "hostnames": hostnames,
        "source_ips": source_ips,
        "usernames": usernames,
        "process_ids": process_ids,
        "process_names": process_names,
        "account_targets": account_targets,
        "events_count": len(events_data)
    }


def build_endpoint_command_params(
    action_type: str,
    targets: Dict[str, Any],
    reason: str,
    incident_id: str,
    custom_params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Constructs structured command parameters for the endpoint agent."""
    norm_action = action_type.upper()
    params = custom_params.copy() if custom_params else {}
    params["incident_id"] = incident_id
    params["reason"] = reason
    params["dispatched_at"] = datetime.now(timezone.utc).isoformat()

    if norm_action in ("BLOCK_SOURCE", "BLOCK_SOURCE_IP"):
        # Select target IP from targets
        target_ip = params.get("ip") or (targets["source_ips"][0] if targets["source_ips"] else None)
        params["ip"] = target_ip or "127.0.0.1"
        params["direction"] = params.get("direction", "inbound")
        params["action"] = "block"

    elif norm_action == "KILL_PROCESS":
        target_pid = params.get("process_id") or (targets["process_ids"][0] if targets["process_ids"] else None)
        target_pname = params.get("process_name") or (targets["process_names"][0] if targets["process_names"] else None)
        params["process_id"] = target_pid
        params["process_name"] = target_pname

    elif norm_action == "ISOLATE_HOST":
        params["mode"] = params.get("mode", "network_isolation")
        params["preserve_soc_communication"] = True

    elif norm_action == "DISABLE_ACCOUNT":
        account_targets = targets.get("account_targets", [])
        selected = select_account_target_record(incident_id, account_targets, custom_params)

        if selected.domain_status == "UNVERIFIED":
            raise ValueError(f"Cannot target account with UNVERIFIED domain status for incident {incident_id}")

        if selected.domain_namespace.startswith("DOMAIN:") or selected.domain_status == "OBSERVED_DOMAIN":
            params["status"] = "ESCALATION_REQUIRED"
            params["escalation_reason"] = (
                f"Account '{selected.target_account_id}' belongs to domain '{selected.domain_namespace}'. "
                f"Endpoint agents cannot disable enterprise domain accounts without DC/IAM coordination."
            )
            params["target_account_id"] = selected.target_account_id
            params["target_user"] = selected.target_user
            params["domain_namespace"] = selected.domain_namespace
            params["target_agent_id"] = selected.target_agent_id
            params["target_hostname"] = selected.target_hostname
            params["originating_detection_event_id"] = selected.originating_detection_event_id
            return params

        if selected.domain_status == "LOCAL_SAM" and selected.domain_namespace == "LOCAL_SAM":
            params["username"] = selected.target_user
            params["domain"] = "LOCAL_SAM"
            params["target_account_id"] = selected.target_account_id
            params["target_agent_id"] = selected.target_agent_id
            params["target_hostname"] = selected.target_hostname
            params["originating_detection_event_id"] = selected.originating_detection_event_id
            return params

        raise ValueError(f"Unhandled domain status/namespace: {selected.domain_status}/{selected.domain_namespace}")

    return params


class IneligibleEvidenceError(ValueError):
    """Raised when an incident contains quarantined, retired, future-epoch, or LEGACY_UNVERIFIED evidence."""
    pass


def check_incident_evidence_eligibility(conn, incident_id: str) -> Tuple[bool, Optional[str]]:
    """
    Independent defense-in-depth eligibility verification for incident evidence.
    Fails closed:
    - Accepts ONLY explicitly recognized eligibility states: ACTIVE_VERIFIED and RELEASED.
    - Strictly rejects incidents with zero evidence records.
    - Strictly rejects NULL, unknown, malformed, or LEGACY_UNVERIFIED statuses.
    - Requires valid agent_id, channel, and a positive integer channel_epoch (>= 1).
    - Requires an authoritative agent_channel_epochs record for (agent_id, channel).
    - For ACTIVE_VERIFIED: channel status must be 'ACTIVE' and event epoch must exactly match current_epoch.
    - For RELEASED: channel must not be quarantined and event epoch must not exceed current_epoch.
    """
    if not incident_id or not isinstance(incident_id, str):
        return False, "invalid incident_id"

    try:
        cursor = conn.execute("""
            SELECT e.detection_event_id, e.quarantine_status, e.channel_epoch, e.agent_id, e.channel, e.data,
                   e.transition_id, e.recovery_request_id
            FROM incident_evidence ie
            JOIN events e ON ie.detection_event_id = e.detection_event_id
            WHERE ie.incident_id = ?
        """, (incident_id,))
    except sqlite3.OperationalError:
        cursor = conn.execute("""
            SELECT e.detection_event_id, e.quarantine_status, e.channel_epoch, e.agent_id, e.channel, e.data
            FROM incident_evidence ie
            JOIN events e ON ie.detection_event_id = e.detection_event_id
            WHERE ie.incident_id = ?
        """, (incident_id,))
    rows = cursor.fetchall()

    # Requirement 6: Reject incidents with zero evidence records
    if not rows:
        return False, f"incident {incident_id} has zero associated evidence records"

    for r in rows:
        event_id = r["detection_event_id"]
        q_status = r["quarantine_status"]
        epoch = r["channel_epoch"]
        agent_id = r["agent_id"]
        channel = r["channel"]

        # Parse JSON data
        ev_data: Dict[str, Any] = {}
        if r["data"]:
            try:
                ev_data = json.loads(r["data"]) if isinstance(r["data"], str) else (r["data"] or {})
            except Exception:
                ev_data = {}
        if not isinstance(ev_data, dict):
            ev_data = {}

        if agent_id is None:
            agent_id = ev_data.get("agent_id")
        if channel is None:
            evidence = ev_data.get("evidence") or {}
            manifest = evidence.get("source_manifest") if isinstance(evidence, dict) else {}
            channel = (
                ev_data.get("channel")
                or (evidence.get("log_name") if isinstance(evidence, dict) else None)
                or (manifest.get("channel") if isinstance(manifest, dict) else None)
            )
        if epoch is None:
            evidence = ev_data.get("evidence") or {}
            manifest = evidence.get("source_manifest") if isinstance(evidence, dict) else {}
            epoch = (
                ev_data.get("channel_epoch")
                or ev_data.get("epoch")
                or (evidence.get("channel_epoch") if isinstance(evidence, dict) else None)
                or (manifest.get("epoch") if isinstance(manifest, dict) else None)
            )

        # Requirement 1 & 2: Fail closed. Accept only ACTIVE_VERIFIED and RELEASED.
        # Reject NULL, unknown, malformed, or LEGACY_UNVERIFIED statuses.
        if q_status is None:
            return False, f"evidence {event_id} has NULL quarantine_status"

        if not isinstance(q_status, str) or q_status not in ("ACTIVE_VERIFIED", "RELEASED"):
            return False, f"evidence {event_id} has ineligible or unknown status '{q_status}'"

        # Requirement 3: Require valid agent_id, channel, and a valid positive integer channel_epoch
        if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
            return False, f"evidence {event_id} missing valid agent_id"

        if not channel or not isinstance(channel, str) or not channel.strip():
            return False, f"evidence {event_id} missing valid channel"

        clean_agent_id = agent_id.strip()
        clean_channel = channel.strip()

        # Validate channel_epoch: genuine positive integer >= 1 (reject bool, float, string, None, <= 0)
        if epoch is None:
            return False, f"evidence {event_id} missing channel_epoch"
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            return False, f"evidence {event_id} has invalid channel_epoch '{epoch}'"

        # Extract event-side provenance hints
        ev_evidence = ev_data.get("evidence") if isinstance(ev_data, dict) else {}
        if not isinstance(ev_evidence, dict):
            ev_evidence = {}
        ev_manifest = ev_evidence.get("source_manifest") if isinstance(ev_evidence, dict) else {}
        if not isinstance(ev_manifest, dict):
            ev_manifest = {}

        row_tid = None
        row_rec_req_id = None
        if hasattr(r, "keys"):
            if "transition_id" in r.keys() and r["transition_id"]:
                row_tid = r["transition_id"]
            if "recovery_request_id" in r.keys() and r["recovery_request_id"]:
                row_rec_req_id = r["recovery_request_id"]

        ev_recovery_request_id = (
            ev_data.get("recovery_request_id")
            or ev_evidence.get("recovery_request_id")
            or ev_manifest.get("recovery_request_id")
            or row_rec_req_id
        )
        ev_transition_id = (
            ev_data.get("transition_id")
            or ev_evidence.get("transition_id")
            or ev_manifest.get("transition_id")
            or row_tid
        )
        ev_source_epoch = (
            ev_data.get("source_epoch")
            or ev_evidence.get("source_epoch")
            or ev_manifest.get("source_epoch")
        )
        if isinstance(ev_source_epoch, bool):
            return False, f"evidence {event_id} has invalid boolean source_epoch"

        # Query authoritative channel record
        ch_cur = conn.execute(
            "SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
            (clean_agent_id, clean_channel)
        )
        ch_row = ch_cur.fetchone()

        # Requirement: Require an existing authoritative agent_channel_epochs record
        if not ch_row:
            return False, f"evidence {event_id} has no authoritative channel epoch record for {clean_agent_id}/{clean_channel}"

        ch_epoch = ch_row["current_epoch"]
        ch_status = ch_row["status"]

        # Validate authoritative current_epoch: genuine positive integer >= 1
        if ch_epoch is None or isinstance(ch_epoch, bool) or not isinstance(ch_epoch, int) or ch_epoch < 1:
            return False, f"evidence {event_id} channel '{clean_channel}' has invalid current_epoch '{ch_epoch}'"

        # Explicitly accepted channel states; reject unknown or malformed states
        ACCEPTED_CHANNEL_STATES = {"ACTIVE"}
        if ch_status not in ACCEPTED_CHANNEL_STATES:
            if ch_status == "EPOCH_GAP_QUARANTINED":
                return False, f"evidence {event_id} belongs to quarantined channel '{clean_channel}' (status: '{ch_status}')"
            return False, f"evidence {event_id} channel '{clean_channel}' has invalid or unaccepted status '{ch_status}'"

        # ACTIVE_VERIFIED check: exact equality between event epoch and active current epoch
        if q_status == "ACTIVE_VERIFIED":
            if epoch != ch_epoch:
                if epoch > ch_epoch:
                    return False, f"evidence {event_id} has future epoch {epoch} (active: {ch_epoch})"
                else:
                    return False, f"evidence {event_id} has retired epoch {epoch} (active: {ch_epoch})"

        # RELEASED check:
        # Both active-epoch (epoch == ch_epoch) and retired-epoch (epoch < ch_epoch) evidence
        # MUST pass through the common strict provenance validation path:
        # 1. Reject future-epoch evidence exceeding active channel epoch (epoch > ch_epoch)
        # 2. Reject if no approved recovery or transition record exists for (agent_id, channel)
        # 3. Source-scoped retirement watermarks and minimum recovery epochs are applied consistently
        #    to both allocation-based and transition-based authorizations.
        # 4. Allocation authorization requires exact recovery_request_id binding, exact epoch match,
        #    and authorized recovery_reason.
        # 5. Transition authorization requires authorized transition type, exact agent/channel identity,
        #    source_epoch <= epoch <= target_epoch, and valid authorization state.
        elif q_status == "RELEASED":
            if epoch > ch_epoch:
                return False, f"RELEASED evidence {event_id} has future epoch {epoch} exceeding active channel epoch {ch_epoch}"

            # Query exact transition record if transition_id is present (no broad query!)
            if ev_transition_id:
                clean_tid = str(ev_transition_id).strip()
                t_cur = conn.execute("""
                    SELECT transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, payload, recovery_request_id
                    FROM channel_transitions
                    WHERE transition_id = ?
                """, (clean_tid,))
                transitions = t_cur.fetchall()
                if not transitions:
                    return False, f"evidence {event_id} references non-existent or mismatched transition '{clean_tid}'"
                t_match = transitions[0]
                if t_match["agent_id"] != clean_agent_id:
                    return False, f"evidence {event_id} transition {clean_tid} agent mismatch ('{t_match['agent_id']}' != '{clean_agent_id}')"
                if clean_channel not in (t_match["source_channel"], t_match["target_channel"]):
                    return False, f"evidence {event_id} transition {clean_tid} channel mismatch"
            else:
                transitions = []

            # Query source-scoped recovery allocations for this agent and channel
            a_cur = conn.execute("""
                SELECT recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at
                FROM epoch_allocation_ledger
                WHERE agent_id = ? AND channel = ?
            """, (clean_agent_id, clean_channel))
            allocations = a_cur.fetchall()

            # Check if any transitions exist in the DB for this agent and channel
            any_transitions_in_db = conn.execute("""
                SELECT 1 FROM channel_transitions
                WHERE agent_id = ? AND (source_channel = ? OR target_channel = ?)
                LIMIT 1
            """, (clean_agent_id, clean_channel, clean_channel)).fetchone() is not None

            # Release provenance check: Reject if no recovery or transition records exist for (agent_id, channel)
            if not any_transitions_in_db and not allocations:
                return False, f"RELEASED evidence {event_id} has no approved recovery or transition record for {clean_agent_id}/{clean_channel} (lacks valid approved recovery provenance)"

            # Parse and validate transition payloads
            parsed_transitions = []
            for t in transitions:
                tid = t["transition_id"]
                p_raw = t["payload"]
                p = {}
                if p_raw is not None:
                    if not isinstance(p_raw, (str, dict)):
                        return False, f"evidence {event_id} transition {tid} has malformed payload type '{type(p_raw).__name__}'"
                    if isinstance(p_raw, str):
                        try:
                            p = json.loads(p_raw)
                        except Exception as json_err:
                            return False, f"evidence {event_id} transition {tid} has malformed JSON payload: {json_err}"
                    else:
                        p = p_raw
                    if not isinstance(p, dict):
                        return False, f"evidence {event_id} transition {tid} payload must be a JSON object"

                # Check cross-source constraints in payload if specified
                if isinstance(p, dict):
                    p_agent = p.get("source_agent_id") or p.get("agent_id")
                    if p_agent and str(p_agent).strip() != clean_agent_id:
                        return False, f"evidence {event_id} transition {tid} cross-source agent mismatch: '{p_agent}' != '{clean_agent_id}'"
                    p_chan = p.get("source_channel") or p.get("channel")
                    if p_chan and str(p_chan).strip() != clean_channel:
                        return False, f"evidence {event_id} transition {tid} cross-source channel mismatch: '{p_chan}' != '{clean_channel}'"

                parsed_transitions.append((t, p))

            # --- WATERMARK CONSISTENCY (Applied consistently across allocations and transitions) ---
            for t, p in parsed_transitions:
                tid = t["transition_id"]
                if not isinstance(p, dict):
                    continue

                if "watermark" in p or "source_watermark" in p or "retired_watermark" in p or "pruned_epoch" in p:
                    raw_wm = (
                        p.get("watermark")
                        if "watermark" in p
                        else (
                            p.get("source_watermark")
                            if "source_watermark" in p
                            else (p.get("retired_watermark") if "retired_watermark" in p else p.get("pruned_epoch"))
                        )
                    )

                    # Explicitly reject boolean watermark
                    if isinstance(raw_wm, bool):
                        return False, f"evidence {event_id} transition {tid} has invalid boolean watermark '{raw_wm}'"

                    if isinstance(raw_wm, int):
                        if raw_wm < 0:
                            return False, f"evidence {event_id} transition {tid} has invalid negative watermark '{raw_wm}'"
                        wm_threshold = raw_wm
                    elif isinstance(raw_wm, dict):
                        wm_map = raw_wm.get("pruned_source_epochs", raw_wm)
                        if not isinstance(wm_map, dict):
                            return False, f"evidence {event_id} transition {tid} has malformed watermark structure '{raw_wm}'"
                        scoped_val = (
                            wm_map.get(f"{clean_agent_id}:{clean_channel}")
                            or wm_map.get(clean_channel)
                            or wm_map.get("default")
                        )
                        if scoped_val is None:
                            return False, f"evidence {event_id} transition {tid} watermark structure missing required source scope '{clean_agent_id}:{clean_channel}'"
                        if isinstance(scoped_val, bool) or not isinstance(scoped_val, int) or scoped_val < 0:
                            return False, f"evidence {event_id} transition {tid} has invalid scoped watermark value '{scoped_val}' (must be non-negative integer, not bool)"
                        wm_threshold = scoped_val
                    else:
                        return False, f"evidence {event_id} transition {tid} has invalid watermark type '{type(raw_wm).__name__}'"

                    # Apply watermark rule: rejects both allocation-authorized and transition-authorized evidence
                    if epoch <= wm_threshold:
                        return False, f"RELEASED evidence {event_id} at epoch {epoch} is retired by watermark threshold {wm_threshold}"

                # Check min_epoch if present
                if "min_epoch" in p:
                    min_ep = p["min_epoch"]
                    if isinstance(min_ep, bool) or not isinstance(min_ep, int) or min_ep < 1:
                        return False, f"evidence {event_id} transition {tid} has invalid boolean or non-integer min_epoch '{min_ep}'"
                    if epoch < min_ep:
                        return False, f"RELEASED evidence {event_id} at epoch {epoch} is below recovery scope minimum epoch {min_ep}"

            # Check channel-level watermark consistency for allocation-authorized evidence when no transition is bound
            if not parsed_transitions:
                wm_cur = conn.execute("""
                    SELECT transition_id, payload FROM channel_transitions
                    WHERE agent_id = ? AND (source_channel = ? OR target_channel = ?)
                """, (clean_agent_id, clean_channel, clean_channel))
                for wm_row in wm_cur.fetchall():
                    wm_p_raw = wm_row["payload"]
                    try:
                        wm_p = json.loads(wm_p_raw) if isinstance(wm_p_raw, str) else (wm_p_raw or {})
                    except Exception:
                        wm_p = {}
                    if isinstance(wm_p, dict) and "watermark" in wm_p:
                        raw_wm = wm_p["watermark"]
                        if isinstance(raw_wm, int) and raw_wm >= 0 and epoch <= raw_wm:
                            return False, f"RELEASED evidence {event_id} at epoch {epoch} is retired by watermark threshold {raw_wm}"

            # --- PROVENANCE EVALUATION (Common Path for Active and Retired Evidence) ---
            valid_allocations = []
            allocation_rejection_reason = None

            for a in allocations:
                # Exact source scope: allocated_epoch must match the event epoch
                if a["allocated_epoch"] != epoch:
                    continue

                # Requirement 1.B: Require non-empty recovery_request_id on event
                if not ev_recovery_request_id or not isinstance(ev_recovery_request_id, str) or not str(ev_recovery_request_id).strip():
                    allocation_rejection_reason = f"evidence {event_id} allocation authorization requires non-empty recovery_request_id"
                    continue

                # Exact equality with allocation recovery_request_id
                if str(a["recovery_request_id"]).strip() != str(ev_recovery_request_id).strip():
                    allocation_rejection_reason = f"evidence {event_id} recovery_request_id '{ev_recovery_request_id}' does not match allocation '{a['recovery_request_id']}'"
                    continue

                # Validate recovery_reason: must be non-empty, recognized, and cannot be unauthorized or invalid
                rec_reason = a["recovery_reason"]
                if not rec_reason or not isinstance(rec_reason, str) or not rec_reason.strip():
                    return False, f"evidence {event_id} recovery allocation {a['recovery_request_id']} has empty recovery_reason"

                clean_reason = rec_reason.strip().upper()
                if "UNAUTHORIZED" in clean_reason or "INVALID" in clean_reason or clean_reason not in AUTHORIZED_RECOVERY_REASONS:
                    return False, f"evidence {event_id} recovery allocation {a['recovery_request_id']} has unauthorized or invalid recovery_reason '{rec_reason}'"

                valid_allocations.append(a)

            valid_transitions = []
            transition_rejection_reason = None

            for t, p in parsed_transitions:
                tid = t["transition_id"]
                ttype = t["transition_type"]

                # Requirement 1.C: Authorized transition type (EPOCH_ADVANCE disqualified)
                if ttype not in AUTHORIZED_RECOVERY_TRANSITION_TYPES:
                    continue

                # Target epoch must cover event epoch
                if t["target_epoch"] < epoch:
                    continue

                # Check reason in transition payload first
                if isinstance(p, dict):
                    trans_reason = str(p.get("reason", "")).upper()
                    if "UNAUTHORIZED" in trans_reason or "INVALID" in trans_reason:
                        return False, f"evidence {event_id} transition {tid} has unauthorized recovery reason '{p.get('reason')}'"

                # Validate source epoch against event
                t_source_epoch = p.get("source_epoch") if isinstance(p, dict) else None
                if t_source_epoch is None:
                    transition_rejection_reason = f"evidence {event_id} transition {tid} missing required source_epoch"
                    continue
                if isinstance(t_source_epoch, bool) or not isinstance(t_source_epoch, int) or t_source_epoch < 1:
                    return False, f"evidence {event_id} transition {tid} has invalid source_epoch '{t_source_epoch}'"

                # Wrong source epoch with matching target epoch:
                # Event epoch must be >= transition source_epoch
                if epoch < t_source_epoch:
                    return False, f"evidence {event_id} at epoch {epoch} is outside transition {tid} source scope (source_epoch: {t_source_epoch}, target_epoch: {t['target_epoch']})"

                if ev_source_epoch is not None and not isinstance(ev_source_epoch, bool) and isinstance(ev_source_epoch, int):
                    if ev_source_epoch != t_source_epoch:
                        return False, f"evidence {event_id} source_epoch {ev_source_epoch} does not match transition {tid} source_epoch {t_source_epoch}"

                # If event specifies transition_id, it must match
                if ev_transition_id and str(tid).strip() != str(ev_transition_id).strip():
                    continue

                # Requirement 4 (WP-1E.4S): Exact recovery_request_id binding
                trans_rec_id = t["recovery_request_id"] or (p.get("recovery_request_id") if isinstance(p, dict) else None)
                if ev_recovery_request_id and trans_rec_id:
                    if str(ev_recovery_request_id).strip() != str(trans_rec_id).strip():
                        return False, f"evidence {event_id} recovery_request_id '{ev_recovery_request_id}' does not match transition recovery_request_id '{trans_rec_id}'"

                # Requirement: Positive authorization validation (Defect A)
                # Keep actor identity and authorization status semantically separate.
                # Positive validation against the actual approved authorization contract.
                # Reject missing, unknown, malformed, untrusted, or unauthorized states.
                if isinstance(p, dict):
                    trans_reason = p.get("reason")
                    if trans_reason is not None:
                        if not isinstance(trans_reason, str) or not trans_reason.strip():
                            return False, f"evidence {event_id} transition {tid} has empty or malformed recovery reason"
                        clean_t_reason = trans_reason.strip().upper()
                        if "UNAUTHORIZED" in clean_t_reason or "INVALID" in clean_t_reason:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery reason '{trans_reason}'"

                    status_candidates = {}
                    for field_name in ("authorization_status", "status", "state"):
                        if field_name in p:
                            status_candidates[field_name] = p[field_name]

                    actor_candidates = {}
                    for field_name in ("authorized_by", "approved_by"):
                        if field_name in p:
                            actor_candidates[field_name] = p[field_name]

                    if not status_candidates and not actor_candidates:
                        return False, f"evidence {event_id} transition {tid} missing authorization state or trusted actor"

                    # Validate status fields against positive allowlist
                    validated_status = None
                    for fname, sval in status_candidates.items():
                        if sval is None or isinstance(sval, bool) or not isinstance(sval, str) or not sval.strip():
                            return False, f"evidence {event_id} transition {tid} has empty or malformed {fname}"
                        clean_s = sval.strip().upper()
                        # Reject actor identity supplied as authorization status
                        if clean_s in TRUSTED_AUTHORIZATION_ACTORS:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery authorization state: actor identity '{sval}' supplied as {fname}"
                        # Positive validation against approved statuses
                        if clean_s not in APPROVED_AUTHORIZATION_STATUSES:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery authorization state: unapproved status '{sval}' in {fname}"
                        if validated_status is not None and clean_s != validated_status:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery authorization state: conflicting authorization status fields ('{validated_status}' vs '{clean_s}')"
                        validated_status = clean_s

                    # Validate actor fields against positive allowlist
                    validated_actor = None
                    for fname, aval in actor_candidates.items():
                        if aval is None or isinstance(aval, bool) or not isinstance(aval, str) or not aval.strip():
                            return False, f"evidence {event_id} transition {tid} has empty or malformed {fname}"
                        clean_a = aval.strip().upper()
                        # Reject authorization status supplied as actor identity
                        if clean_a in APPROVED_AUTHORIZATION_STATUSES:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery authorization state: authorization status '{aval}' supplied as {fname}"
                        # Positive validation against trusted actors
                        if clean_a not in TRUSTED_AUTHORIZATION_ACTORS:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery authorization state: untrusted actor '{aval}' in {fname}"
                        if validated_actor is not None and clean_a != validated_actor:
                            return False, f"evidence {event_id} transition {tid} has unauthorized recovery authorization state: conflicting authorization actor fields ('{validated_actor}' vs '{clean_a}')"
                        validated_actor = clean_a

                valid_transitions.append((t, p))

            # Defect B enforcement:
            # For retired-epoch evidence (epoch < ch_epoch):
            # Allocation records alone must NOT authorize RELEASED evidence.
            # Require an authoritative transition record that establishes recovery scope and retirement boundary.
            if epoch < ch_epoch:
                if not valid_transitions:
                    if valid_allocations:
                        return False, f"RELEASED evidence {event_id} from retired epoch {epoch} cannot be authorized by allocation alone; requires authoritative recovery transition"
                    if not ev_transition_id or not isinstance(ev_transition_id, str) or not str(ev_transition_id).strip():
                        return False, f"RELEASED evidence {event_id} from retired epoch {epoch} missing mandatory transition_id for recovery authorization (lacks valid approved recovery provenance)"
                    if transition_rejection_reason and not allocations:
                        return False, transition_rejection_reason
                    if allocation_rejection_reason and not transitions:
                        return False, allocation_rejection_reason
                    return False, f"RELEASED evidence {event_id} from retired epoch {epoch} lacks valid approved recovery provenance (active epoch: {ch_epoch})"

            # For active-epoch evidence (epoch == ch_epoch):
            # Must have either a valid allocation OR a valid transition
            else:
                if not valid_allocations and not valid_transitions:
                    if allocation_rejection_reason and not transitions:
                        return False, allocation_rejection_reason
                    if transition_rejection_reason and not allocations:
                        return False, transition_rejection_reason
                    return False, f"RELEASED evidence {event_id} at active epoch {epoch} lacks valid approved recovery provenance"

    return True, None


def dispatch_governed_response(
    conn,
    incident_id: str,
    recommendations: List[Dict[str, Any]],
    approved_by: str = "AUTONOMOUS_GOVERNANCE",
    target_action: Optional[str] = None,
    custom_params: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Translates approved/autonomous mitigation recommendations into actionable endpoint_commands
    and records them atomically in the central database.
    """
    # Defense-in-depth: reject incidents containing quarantined, retired, future-epoch, or LEGACY_UNVERIFIED evidence
    is_eligible, ineligible_reason = check_incident_evidence_eligibility(conn, incident_id)
    if not is_eligible:
        raise IneligibleEvidenceError(
            f"Cannot dispatch response for incident {incident_id}: contains ineligible evidence ({ineligible_reason})"
        )

    targets = get_incident_endpoint_targets(conn, incident_id)
    target_agent_ids = targets["agent_ids"]

    # Determine which actions to dispatch
    actions_to_process = []
    if target_action:
        actions_to_process.append({
            "type": target_action.upper(),
            "reason": f"Manually approved action '{target_action}' by {approved_by}"
        })
    elif recommendations:
        for rec in recommendations:
            r_type = rec.get("type", "").upper()
            if r_type and r_type in SUPPORTED_RESPONSE_ACTIONS:
                actions_to_process.append({
                    "type": r_type,
                    "reason": rec.get("reason", f"Governed recommendation {r_type} approved by {approved_by}")
                })

    dispatched = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for action_item in actions_to_process:
        cmd_type = action_item["type"]
        reason = action_item["reason"]

        if cmd_type == "DISABLE_ACCOUNT":
            # Cardinality and target validation strictly enforced: NEVER broadcast
            params = build_endpoint_command_params(cmd_type, targets, reason, incident_id, custom_params)
            params["approved_by"] = approved_by

            if params.get("status") == "ESCALATION_REQUIRED":
                logger.info(
                    f"DISABLE_ACCOUNT for incident {incident_id} requires enterprise escalation: "
                    f"{params.get('escalation_reason')}. Zero commands dispatched to endpoints."
                )
                continue

            target_agent = params.get("target_agent_id")
            if not target_agent:
                raise ValueError(f"Missing target_agent_id for DISABLE_ACCOUNT in incident {incident_id}")

            ep_check = conn.execute("SELECT 1 FROM endpoints WHERE agent_id = ?", (target_agent,)).fetchone()
            if not ep_check:
                target_host = params.get("target_hostname") or (targets["hostnames"][0] if targets["hostnames"] else "unknown-host")
                conn.execute("""
                    INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat)
                    VALUES (?, ?, 'windows', 'ONLINE', ?)
                """, (target_agent, target_host, now_iso))

            cmd_id = str(uuid.uuid4())
            params_json = json.dumps(params)
            conn.execute("""
                INSERT INTO endpoint_commands (
                    command_id, agent_id, command_type, parameters, status, result, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'PENDING', NULL, ?, ?)
            """, (cmd_id, target_agent, cmd_type, params_json, now_iso, now_iso))

            dispatched.append({
                "command_id": cmd_id,
                "agent_id": target_agent,
                "command_type": cmd_type,
                "parameters": params,
                "status": "PENDING",
                "created_at": now_iso
            })

        else:
            if not target_agent_ids:
                logger.warning(f"No target agent IDs identified for incident {incident_id}. Command {cmd_type} will not be dispatched.")
                continue

            for agent_id in target_agent_ids:
                ep_check = conn.execute("SELECT 1 FROM endpoints WHERE agent_id = ?", (agent_id,)).fetchone()
                if not ep_check:
                    primary_host = targets["hostnames"][0] if targets["hostnames"] else "unknown-host"
                    conn.execute("""
                        INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat)
                        VALUES (?, ?, 'unknown', 'ONLINE', ?)
                    """, (agent_id, primary_host, now_iso))

                params = build_endpoint_command_params(cmd_type, targets, reason, incident_id, custom_params)
                params["approved_by"] = approved_by

                cmd_id = str(uuid.uuid4())
                params_json = json.dumps(params)

                conn.execute("""
                    INSERT INTO endpoint_commands (
                        command_id, agent_id, command_type, parameters, status, result, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'PENDING', NULL, ?, ?)
                """, (cmd_id, agent_id, cmd_type, params_json, now_iso, now_iso))

                dispatched.append({
                    "command_id": cmd_id,
                    "agent_id": agent_id,
                    "command_type": cmd_type,
                    "parameters": params,
                    "status": "PENDING",
                    "created_at": now_iso
                })

    conn.commit()
    logger.info(f"Dispatched {len(dispatched)} response command(s) for incident {incident_id} (Approved by: {approved_by})")
    return dispatched
