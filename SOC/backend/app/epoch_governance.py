"""
TGAM-SOC Central SOC Idempotency and Epoch Governance Engine
============================================================

Implements:
1. Transaction-safe, payload-aware event ingestion idempotency.
2. Canonical TGAM-RCC-v1 conflict manifest generation and durable conflict logging.
3. Strict duplicate JSON key rejection before model validation.
4. Channel-scoped sequential epoch transition governance ($E_{incoming} == E_{active} + 1$).
5. Epoch gap freeze and quarantine (`EPOCH_GAP_QUARANTINED` / `GAP_QUARANTINED`).
6. Authoritative gap resolution (Path A replayed sequential transitions and Path B admin override).
7. Scoped epoch allocation ledger with recovery_request_id idempotency and scope verification.
"""

import json
import sqlite3
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from app.canonical import (
    canonicalize_tgam_rcc_v1,
    compute_payload_hash,
    parse_raw_json,
    generate_outbox_conflict_id,
    build_outbox_conflict_manifest,
    validate_epoch,
    DuplicateKeyError,
    TGAMCanonicalizationError,
)

logger = logging.getLogger(__name__)


def ingest_event_transactional(
    conn: sqlite3.Connection,
    raw_bytes: bytes
) -> Tuple[int, Dict[str, Any]]:
    """
    Ingests a raw JSON detection event with strict payload idempotency and epoch governance.
    Returns (status_code, response_data).
    """
    # Step 1: Parse raw bytes with duplicate key detection
    try:
        parsed_dict = parse_raw_json(raw_bytes)
    except DuplicateKeyError as e:
        return 400, {"detail": f"Duplicate key rejected: {e}"}
    except (TGAMCanonicalizationError, json.JSONDecodeError, UnicodeDecodeError) as e:
        return 400, {"detail": f"Malformed JSON: {e}"}

    if not isinstance(parsed_dict, dict):
        return 400, {"detail": "JSON body must be an object"}

    # Step 2: Validate essential schema fields
    event_id = parsed_dict.get("detection_event_id")
    if not event_id or not isinstance(event_id, str):
        return 422, {"detail": "Missing or invalid required field 'detection_event_id'"}
    
    agent_id = parsed_dict.get("agent_id")
    if not agent_id or not isinstance(agent_id, str):
        return 422, {"detail": "Missing or invalid required field 'agent_id'"}

    confidence = parsed_dict.get("confidence")
    if confidence is None or not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        return 422, {"detail": "Missing or invalid required field 'confidence'"}
    if confidence < 0.0 or confidence > 1.0:
        return 422, {"detail": "confidence must be between 0.0 and 1.0"}

    # Step 3: Compute canonical payload hash
    incoming_hash = compute_payload_hash(parsed_dict)

    # Step 4: Extract routing & epoch metadata
    evidence = parsed_dict.get("evidence") or {}
    source_manifest = evidence.get("source_manifest") if isinstance(evidence, dict) else {}
    if not isinstance(source_manifest, dict):
        source_manifest = {}

    channel = (
        parsed_dict.get("channel")
        or (evidence.get("log_name") if isinstance(evidence, dict) else None)
        or source_manifest.get("channel")
        or "Security"
    )

    raw_epoch = (
        parsed_dict.get("channel_epoch")
        or parsed_dict.get("epoch")
        or (evidence.get("channel_epoch") if isinstance(evidence, dict) else None)
        or source_manifest.get("epoch")
    )

    event_epoch: Optional[int] = None
    if raw_epoch is not None:
        try:
            event_epoch = validate_epoch(raw_epoch)
        except (TypeError, ValueError) as e:
            return 422, {"detail": f"Invalid channel_epoch: {e}"}

    # Step 5: Begin atomic transaction
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        pass  # Transaction already started

    try:
        # Check existing event
        cur = conn.execute(
            "SELECT data, payload_hash, quarantine_status FROM events WHERE detection_event_id = ?",
            (event_id,)
        )
        row = cur.fetchone()

        if row is not None:
            existing_data_str = row["data"]
            existing_hash = row["payload_hash"]

            if not existing_hash:
                try:
                    existing_parsed = parse_raw_json(existing_data_str.encode("utf-8"))
                    existing_hash = compute_payload_hash(existing_parsed)
                except Exception:
                    existing_hash = incoming_hash  # fallback

            if incoming_hash == existing_hash:
                # IDENTICAL DUPLICATE
                conn.commit()
                return 201, {
                    "accepted": True,
                    "detection_event_id": event_id,
                    "duplicate": True
                }
            else:
                # CONFLICTING PAYLOAD
                h_min = min(existing_hash, incoming_hash)
                h_max = max(existing_hash, incoming_hash)
                conflict_id = generate_outbox_conflict_id(event_id, h_min, h_max)

                incoming_data_str = json.dumps(parsed_dict, sort_keys=True)
                if existing_hash == h_min:
                    payload_a, payload_a_hash = existing_data_str, existing_hash
                    payload_b, payload_b_hash = incoming_data_str, incoming_hash
                else:
                    payload_a, payload_a_hash = incoming_data_str, incoming_hash
                    payload_b, payload_b_hash = existing_data_str, existing_hash

                now_iso = datetime.now(timezone.utc).isoformat()
                conn.execute("""
                    INSERT OR IGNORE INTO event_conflicts 
                    (conflict_id, event_id, payload_a, payload_a_hash, payload_b, payload_b_hash, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (conflict_id, event_id, payload_a, payload_a_hash, payload_b, payload_b_hash, now_iso))

                # Commit transaction so conflict record is guaranteed durable before returning HTTP 409
                conn.commit()

                return 409, {
                    "detail": "Event payload conflict detected",
                    "conflict_id": conflict_id,
                    "event_id": event_id,
                    "accepted": False,
                    "duplicate": False
                }

        # NEW EVENT: check epoch governance state
        ch_cur = conn.execute(
            "SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
            (agent_id, channel)
        )
        ch_row = ch_cur.fetchone()

        if ch_row is not None:
            active_epoch = ch_row["current_epoch"]
            ch_status = ch_row["status"]
        else:
            active_epoch = 1
            ch_status = "ACTIVE"
            conn.execute("""
                INSERT OR IGNORE INTO agent_channel_epochs 
                (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, ?, 1, 'ACTIVE', CURRENT_TIMESTAMP)
            """, (agent_id, channel))

        # Check if event has verified V2 epoch/channel identity
        # Requirement 1: Explicitly classify events without verified V2 epoch/channel identity as LEGACY_UNVERIFIED
        # Requirement 6: Do not invent epoch values for legacy events
        if event_epoch is None or not channel:
            quarantine_status = "LEGACY_UNVERIFIED"
            stored_epoch = None
        elif ch_status == "EPOCH_GAP_QUARANTINED":
            quarantine_status = "GAP_QUARANTINED"
            stored_epoch = event_epoch
        elif event_epoch > active_epoch:
            quarantine_status = "GAP_QUARANTINED"
            stored_epoch = event_epoch
        elif event_epoch < active_epoch:
            quarantine_status = "RETIRED_EPOCH_DELAYED"
            stored_epoch = event_epoch
        else:
            quarantine_status = "ACTIVE_VERIFIED"
            stored_epoch = event_epoch

        # Insert new event
        conn.execute("""
            INSERT INTO events 
            (detection_event_id, data, payload_hash, quarantine_status, agent_id, channel, channel_epoch)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            json.dumps(parsed_dict),
            incoming_hash,
            quarantine_status,
            agent_id,
            channel,
            stored_epoch
        ))

        conn.commit()
        return 201, {
            "accepted": True,
            "detection_event_id": event_id,
            "duplicate": False,
            "quarantine_status": quarantine_status
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error in ingest_event_transactional: {e}")
        raise


def process_channel_transition(
    conn: sqlite3.Connection,
    transition_dict: Dict[str, Any],
    authenticated_actor: Optional[str] = None
) -> Tuple[int, Dict[str, Any]]:
    """
    Processes an incoming channel epoch transition envelope with sequential enforcement.
    Protects channel_transitions from replacement: duplicate idempotent submissions are acknowledged,
    while conflicting payloads for the same transition_id produce durable conflict records.
    Returns (status_code, response_data).
    """
    transition_id = transition_dict.get("transition_id")
    agent_id = transition_dict.get("agent_id")
    source_channel = transition_dict.get("source_channel")
    target_channel = transition_dict.get("target_channel") or source_channel
    raw_target_epoch = transition_dict.get("target_epoch")
    transition_type = transition_dict.get("transition_type", "EPOCH_ADVANCE")

    if not transition_id or not isinstance(transition_id, str):
        return 422, {"detail": "Missing or invalid 'transition_id'"}
    if not agent_id or not isinstance(agent_id, str):
        return 422, {"detail": "Missing or invalid 'agent_id'"}
    if not source_channel or not isinstance(source_channel, str):
        return 422, {"detail": "Missing or invalid 'source_channel'"}
    if raw_target_epoch is None:
        return 422, {"detail": "Missing 'target_epoch'"}

    try:
        target_epoch = validate_epoch(raw_target_epoch)
    except (TypeError, ValueError) as e:
        return 422, {"detail": f"Invalid target_epoch: {e}"}

    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        pass

    try:
        # Check if transition_id already exists (Requirement 3: Never silently overwrite)
        cur_t = conn.execute("""
            SELECT transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, payload, payload_hash
            FROM channel_transitions WHERE transition_id = ?
        """, (transition_id,))
        existing_t = cur_t.fetchone()

        # Sanitize and server-derive authorization fields
        stored_payload = dict(transition_dict)
        if authenticated_actor:
            stored_payload["authorized_by"] = authenticated_actor
            stored_payload["status"] = "APPROVED"
        else:
            # Strip caller-supplied administrative claims if not authenticated as admin
            for field in ("authorized_by", "approved_by", "authorization_status", "status", "state"):
                stored_payload.pop(field, None)

        incoming_hash = compute_payload_hash(stored_payload)
        rec_req_id = stored_payload.get("recovery_request_id")

        if existing_t is not None:
            existing_hash = existing_t["payload_hash"]
            if not existing_hash and existing_t["payload"]:
                try:
                    existing_hash = compute_payload_hash(json.loads(existing_t["payload"]))
                except Exception:
                    existing_hash = ""

            # Check if identical duplicate
            if incoming_hash == existing_hash and (
                existing_t["agent_id"] == agent_id and
                existing_t["source_channel"] == source_channel and
                existing_t["target_epoch"] == target_epoch and
                existing_t["transition_type"] == transition_type
            ):
                conn.commit()
                return 200, {
                    "status": "ALREADY_APPLIED",
                    "agent_id": agent_id,
                    "channel": source_channel,
                    "active_epoch": target_epoch,
                    "transition_id": transition_id,
                    "duplicate": True
                }
            else:
                # Durable conflict detected (same transition_id, different payload/parameters)
                h_min = min(existing_hash or "0", incoming_hash)
                h_max = max(existing_hash or "0", incoming_hash)
                conflict_id = generate_outbox_conflict_id(transition_id, h_min, h_max)
                now_iso = datetime.now(timezone.utc).isoformat()
                existing_payload_str = existing_t["payload"] or "{}"
                incoming_payload_str = json.dumps(stored_payload, sort_keys=True)

                if (existing_hash or "0") == h_min:
                    payload_a, payload_a_hash = existing_payload_str, existing_hash or "0"
                    payload_b, payload_b_hash = incoming_payload_str, incoming_hash
                else:
                    payload_a, payload_a_hash = incoming_payload_str, incoming_hash
                    payload_b, payload_b_hash = existing_payload_str, existing_hash or "0"

                conn.execute("""
                    INSERT OR IGNORE INTO transition_conflicts 
                    (conflict_id, transition_id, payload_a, payload_a_hash, payload_b, payload_b_hash, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (conflict_id, transition_id, payload_a, payload_a_hash, payload_b, payload_b_hash, now_iso))
                conn.execute("""
                    INSERT OR IGNORE INTO event_conflicts 
                    (conflict_id, event_id, payload_a, payload_a_hash, payload_b, payload_b_hash, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (conflict_id, transition_id, payload_a, payload_a_hash, payload_b, payload_b_hash, now_iso))
                conn.commit()
                return 409, {
                    "detail": "Transition payload conflict detected",
                    "conflict_id": conflict_id,
                    "transition_id": transition_id,
                    "accepted": False,
                    "duplicate": False
                }

        # Check active channel epoch
        cur = conn.execute(
            "SELECT current_epoch, status FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
            (agent_id, source_channel)
        )
        row = cur.fetchone()

        if row is not None:
            active_epoch = row["current_epoch"]
            ch_status = row["status"]
        else:
            active_epoch = 1
            ch_status = "ACTIVE"
            conn.execute("""
                INSERT OR IGNORE INTO agent_channel_epochs 
                (agent_id, channel, current_epoch, status, updated_at)
                VALUES (?, ?, 1, 'ACTIVE', CURRENT_TIMESTAMP)
            """, (agent_id, source_channel))

        # Check target_epoch relative to active_epoch
        if target_epoch == active_epoch + 1:
            # SEQUENTIAL ADVANCE
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE agent_channel_epochs 
                SET current_epoch = ?, status = 'ACTIVE', last_transition_id = ?, updated_at = ?
                WHERE agent_id = ? AND channel = ?
            """, (target_epoch, transition_id, now_iso, agent_id, source_channel))

            conn.execute("""
                INSERT INTO channel_transitions 
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload, payload_hash, recovery_request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transition_id, agent_id, source_channel, target_channel,
                target_epoch, transition_type, now_iso, json.dumps(stored_payload), incoming_hash, rec_req_id
            ))

            # Path A resolution: If channel was quarantined or had gap-quarantined events,
            # release events now at or below new active epoch
            conn.execute("""
                UPDATE events 
                SET quarantine_status = 'RELEASED', transition_id = ?
                WHERE agent_id = ? AND channel = ? AND channel_epoch <= ? AND quarantine_status IN ('GAP_QUARANTINED', 'EPOCH_GAP_QUARANTINED')
            """, (transition_id, agent_id, source_channel, target_epoch))

            conn.commit()
            return 200, {
                "status": "APPLIED",
                "agent_id": agent_id,
                "channel": source_channel,
                "active_epoch": target_epoch,
                "transition_id": transition_id
            }

        elif target_epoch == active_epoch:
            # ALREADY APPLIED / DUPLICATE
            conn.commit()
            return 200, {
                "status": "ALREADY_APPLIED",
                "agent_id": agent_id,
                "channel": source_channel,
                "active_epoch": active_epoch,
                "transition_id": transition_id
            }

        elif target_epoch < active_epoch:
            # OBSOLETE / RETIRED TRANSITION
            conn.commit()
            return 200, {
                "status": "OBSOLETE",
                "agent_id": agent_id,
                "channel": source_channel,
                "active_epoch": active_epoch,
                "transition_id": transition_id
            }

        else:
            # GAP DETECTED (target_epoch > active_epoch + 1)
            # Freeze channel at active_epoch, mark channel as EPOCH_GAP_QUARANTINED
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE agent_channel_epochs 
                SET status = 'EPOCH_GAP_QUARANTINED', updated_at = ?
                WHERE agent_id = ? AND channel = ?
            """, (now_iso, agent_id, source_channel))

            conn.execute("""
                INSERT INTO channel_transitions 
                (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload, payload_hash, recovery_request_id)
                VALUES (?, ?, ?, ?, ?, 'GAP_DETECTED', ?, ?, ?, ?)
            """, (
                transition_id, agent_id, source_channel, target_channel,
                target_epoch, now_iso, json.dumps(stored_payload), incoming_hash, rec_req_id
            ))

            conn.commit()
            return 409, {
                "status": "EPOCH_GAP_QUARANTINED",
                "agent_id": agent_id,
                "channel": source_channel,
                "active_epoch": active_epoch,
                "target_epoch": target_epoch,
                "detail": f"Epoch gap detected: expected {active_epoch + 1}, received {target_epoch}"
            }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error in process_channel_transition: {e}")
        raise


def resolve_epoch_gap(
    conn: sqlite3.Connection,
    agent_id: str,
    channel: str,
    target_epoch: int,
    resolution_reason: str,
    authorized_by: str = "SOC_ADMIN",
    recovery_request_id: Optional[str] = None
) -> Tuple[int, Dict[str, Any]]:
    """
    Authoritative Administrative Gap Resolution (Path B).
    Forces channel active epoch to target_epoch, sets status to ACTIVE, and releases quarantined events.
    Sets exact transition_id and recovery_request_id on released event rows.
    """
    try:
        valid_target = validate_epoch(target_epoch)
    except (TypeError, ValueError) as e:
        return 422, {"detail": f"Invalid target_epoch: {e}"}

    if not agent_id or not isinstance(agent_id, str):
        return 422, {"detail": "Missing agent_id"}
    if not channel or not isinstance(channel, str):
        return 422, {"detail": "Missing channel"}

    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        pass

    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        transition_id = f"GAP-RES-{uuid.uuid4().hex[:12]}"

        # Fetch current epoch prior to update to record authoritative source_epoch
        cur_row = conn.execute(
            "SELECT current_epoch FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
            (agent_id, channel)
        ).fetchone()
        source_epoch = cur_row["current_epoch"] if cur_row else 1

        payload_data = {
            "reason": resolution_reason,
            "authorized_by": authorized_by,
            "source_epoch": source_epoch,
            "status": "RESOLVED"
        }
        if recovery_request_id:
            payload_data["recovery_request_id"] = recovery_request_id
        payload_hash = compute_payload_hash(payload_data)

        conn.execute("""
            INSERT INTO agent_channel_epochs (agent_id, channel, current_epoch, status, last_transition_id, updated_at)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?)
            ON CONFLICT(agent_id, channel) DO UPDATE SET
                current_epoch = excluded.current_epoch,
                status = 'ACTIVE',
                last_transition_id = excluded.last_transition_id,
                updated_at = excluded.updated_at
        """, (agent_id, channel, valid_target, transition_id, now_iso))

        # Release quarantined events at or below the target epoch and bind transition_id & recovery_request_id
        cur = conn.execute("""
            UPDATE events 
            SET quarantine_status = 'RELEASED', transition_id = ?, recovery_request_id = ?
            WHERE agent_id = ? AND channel = ? AND (channel_epoch <= ? OR channel_epoch IS NULL) AND quarantine_status IN ('GAP_QUARANTINED', 'EPOCH_GAP_QUARANTINED')
        """, (transition_id, recovery_request_id, agent_id, channel, valid_target))
        released_count = cur.rowcount

        conn.execute("""
            INSERT INTO channel_transitions 
            (transition_id, agent_id, source_channel, target_channel, target_epoch, transition_type, received_at, payload, payload_hash, recovery_request_id)
            VALUES (?, ?, ?, ?, ?, 'ADMINISTRATIVE_GAP_RESOLUTION', ?, ?, ?, ?)
        """, (
            transition_id, agent_id, channel, channel, valid_target, now_iso,
            json.dumps(payload_data), payload_hash, recovery_request_id
        ))

        conn.commit()
        return 200, {
            "status": "RESOLVED",
            "agent_id": agent_id,
            "channel": channel,
            "active_epoch": valid_target,
            "released_events_count": released_count,
            "resolution_id": transition_id
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error in resolve_epoch_gap: {e}")
        raise


def allocate_recovery_epoch(
    conn: sqlite3.Connection,
    recovery_request_id: str,
    agent_id: str,
    channel: str,
    recovery_reason: str
) -> Tuple[int, Dict[str, Any]]:
    """
    Scoped epoch allocation ledger API with strict scope verification and idempotency.
    """
    if not recovery_request_id or not isinstance(recovery_request_id, str):
        return 422, {"detail": "Missing or invalid recovery_request_id"}
    if not agent_id or not isinstance(agent_id, str):
        return 422, {"detail": "Missing or invalid agent_id"}
    if not channel or not isinstance(channel, str):
        return 422, {"detail": "Missing or invalid channel"}
    if not recovery_reason or not isinstance(recovery_reason, str):
        return 422, {"detail": "Missing or invalid recovery_reason"}

    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        pass

    try:
        # Check existing allocation for this request ID
        cur = conn.execute(
            "SELECT agent_id, channel, recovery_reason, allocated_epoch FROM epoch_allocation_ledger WHERE recovery_request_id = ?",
            (recovery_request_id,)
        )
        row = cur.fetchone()

        if row is not None:
            # Check scope match
            if (row["agent_id"] == agent_id and
                row["channel"] == channel and
                row["recovery_reason"] == recovery_reason):
                conn.commit()
                return 200, {
                    "allocated_epoch": row["allocated_epoch"],
                    "recovery_request_id": recovery_request_id,
                    "status": "ALREADY_ALLOCATED"
                }
            else:
                conn.commit()
                return 409, {
                    "detail": "ALLOCATION_REQUEST_ID_SCOPE_MISMATCH",
                    "recovery_request_id": recovery_request_id,
                    "expected_scope": {
                        "agent_id": row["agent_id"],
                        "channel": row["channel"],
                        "recovery_reason": row["recovery_reason"]
                    },
                    "provided_scope": {
                        "agent_id": agent_id,
                        "channel": channel,
                        "recovery_reason": recovery_reason
                    }
                }

        # Determine next epoch
        cur_epoch = conn.execute(
            "SELECT current_epoch FROM agent_channel_epochs WHERE agent_id = ? AND channel = ?",
            (agent_id, channel)
        ).fetchone()
        active = cur_epoch["current_epoch"] if cur_epoch else 1

        cur_alloc = conn.execute(
            "SELECT MAX(allocated_epoch) as max_alloc FROM epoch_allocation_ledger WHERE agent_id = ? AND channel = ?",
            (agent_id, channel)
        ).fetchone()
        max_allocated = cur_alloc["max_alloc"] if cur_alloc and cur_alloc["max_alloc"] is not None else 1

        highest = max(active, max_allocated)
        next_epoch = highest + 1

        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO epoch_allocation_ledger 
            (recovery_request_id, agent_id, channel, recovery_reason, allocated_epoch, allocated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (recovery_request_id, agent_id, channel, recovery_reason, next_epoch, now_iso))

        conn.commit()
        return 200, {
            "allocated_epoch": next_epoch,
            "recovery_request_id": recovery_request_id,
            "status": "ALLOCATED"
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error in allocate_recovery_epoch: {e}")
        raise


def get_conflicts_query(
    conn: sqlite3.Connection,
    event_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Returns recorded payload conflicts, optionally filtered by event_id.
    """
    if event_id:
        cur = conn.execute(
            "SELECT * FROM event_conflicts WHERE event_id = ? ORDER BY detected_at DESC",
            (event_id,)
        )
    else:
        cur = conn.execute("SELECT * FROM event_conflicts ORDER BY detected_at DESC")
    return [dict(r) for r in cur.fetchall()]
