import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

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

def get_incident_endpoint_targets(conn, incident_id: str) -> Dict[str, Any]:
    """
    Extracts all endpoint targets (agent IDs, IPs, hostnames, usernames, process evidence)
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
        target_user = params.get("username") or (targets["usernames"][0] if targets["usernames"] else None)
        params["username"] = target_user

    return params


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
    targets = get_incident_endpoint_targets(conn, incident_id)
    target_agent_ids = targets["agent_ids"]

    if not target_agent_ids:
        logger.warning(f"No target agent IDs identified for incident {incident_id}. Commands will not be dispatched.")
        return []

    dispatched = []
    now_iso = datetime.now(timezone.utc).isoformat()

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

    # Dispatch to all target agents involved
    for agent_id in target_agent_ids:
        # Check if agent exists in endpoints table; if not, upsert dummy stub so foreign key passes
        ep_check = conn.execute("SELECT 1 FROM endpoints WHERE agent_id = ?", (agent_id,)).fetchone()
        if not ep_check:
            primary_host = targets["hostnames"][0] if targets["hostnames"] else "unknown-host"
            conn.execute("""
                INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat)
                VALUES (?, ?, 'unknown', 'ONLINE', ?)
            """, (agent_id, primary_host, now_iso))

        for action_item in actions_to_process:
            cmd_type = action_item["type"]
            reason = action_item["reason"]
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
