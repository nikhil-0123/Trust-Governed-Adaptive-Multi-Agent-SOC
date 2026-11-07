import logging
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from .outbox import (
    Outbox,
    compute_transient_backoff,
    compute_auth_backoff,
    compute_rate_limit_backoff,
    parse_retry_after,
    sanitize_error_message
)
from .client import TransportClient

def evaluate_delivery_outcome(
    event_id: str,
    status_code: int,
    resp_body: str,
    current_attempts: int,
    headers: Optional[Dict[str, str]] = None,
    error_msg: str = "",
    max_retries: int = 10
) -> Dict[str, Any]:
    """
    Evaluates the delivery outcome and determines the precise outbox state transition.
    Returns:
    {
        'action': 'DELIVER' | 'RETRY_TRANSIENT' | 'RETRY_AUTH' | 'RETRY_429' | 'QUARANTINE',
        'quarantine_reason': Optional[str],
        'is_duplicate': bool,
        'retry_delay': float,
        'error': str
    }
    """
    is_valid_event_id = bool(event_id) and isinstance(event_id, str) and bool(event_id.strip())

    # 1. HTTP 201 Created (Success only with matching ID, accepted=True, and valid dict)
    if status_code == 201:
        valid_ack = False
        try:
            data = json.loads(resp_body) if isinstance(resp_body, str) else resp_body
            if (
                isinstance(data, dict)
                and data.get("accepted") is True
                and is_valid_event_id
                and data.get("detection_event_id") == event_id
            ):
                valid_ack = True
        except Exception:
            pass

        if valid_ack:
            return {
                "action": "DELIVER",
                "is_duplicate": False,
                "quarantine_reason": None,
                "retry_delay": 0.0,
                "error": ""
            }

        new_attempts = current_attempts + 1
        sanitized_resp = sanitize_error_message(resp_body or error_msg)
        err = f"Contract violation on HTTP 201: {sanitized_resp}"
        if new_attempts >= max_retries:
            return {
                "action": "QUARANTINE",
                "quarantine_reason": "max_retries_exceeded",
                "is_duplicate": False,
                "retry_delay": 0.0,
                "error": err
            }
        delay = compute_transient_backoff(new_attempts)
        return {
            "action": "RETRY_TRANSIENT",
            "quarantine_reason": None,
            "is_duplicate": False,
            "retry_delay": delay,
            "error": err
        }

    # 2. HTTP 409 Conflict (Duplicate acknowledged only with accepted=True, duplicate=True, matching ID, and valid dict)
    if status_code == 409:
        valid_dup_ack = False
        try:
            data = json.loads(resp_body) if isinstance(resp_body, str) else resp_body
            if (
                isinstance(data, dict)
                and data.get("accepted") is True
                and data.get("duplicate") is True
                and is_valid_event_id
                and data.get("detection_event_id") == event_id
            ):
                valid_dup_ack = True
        except Exception:
            pass

        if valid_dup_ack:
            return {
                "action": "DELIVER",
                "is_duplicate": True,
                "quarantine_reason": None,
                "retry_delay": 0.0,
                "error": ""
            }

        new_attempts = current_attempts + 1
        sanitized_resp = sanitize_error_message(resp_body or error_msg)
        err = f"Contract violation on HTTP 409: {sanitized_resp}"
        if new_attempts >= max_retries:
            return {
                "action": "QUARANTINE",
                "quarantine_reason": "max_retries_exceeded",
                "is_duplicate": False,
                "retry_delay": 0.0,
                "error": err
            }
        delay = compute_transient_backoff(new_attempts)
        return {
            "action": "RETRY_TRANSIENT",
            "quarantine_reason": None,
            "is_duplicate": False,
            "retry_delay": delay,
            "error": err
        }

    # 3. HTTP 200 and HTTP 202: Strict contract violation (Central SOC contract requires HTTP 201 Created)
    if status_code in (200, 202):
        new_attempts = current_attempts + 1
        err = f"Contract violation: Unexpected HTTP status {status_code}. Central SOC requires HTTP 201."
        if new_attempts >= max_retries:
            return {
                "action": "QUARANTINE",
                "quarantine_reason": "max_retries_exceeded",
                "is_duplicate": False,
                "retry_delay": 0.0,
                "error": err
            }
        delay = compute_transient_backoff(new_attempts)
        return {
            "action": "RETRY_TRANSIENT",
            "quarantine_reason": None,
            "is_duplicate": False,
            "retry_delay": delay,
            "error": err
        }

    # 4. HTTP 400 Bad Request or HTTP 422 Unprocessable Entity (Immediate Quarantine)
    if status_code in (400, 422):
        sanitized_err = sanitize_error_message(error_msg or resp_body or f"HTTP {status_code}")
        return {
            "action": "QUARANTINE",
            "quarantine_reason": "payload_validation_failed",
            "is_duplicate": False,
            "retry_delay": 0.0,
            "error": sanitized_err
        }

    # 5. HTTP 401 Unauthorized or HTTP 403 Forbidden (Never Quarantine, Indefinite Auth Backoff)
    if status_code in (401, 403):
        delay = compute_auth_backoff(current_attempts + 1)
        sanitized_err = sanitize_error_message(error_msg or resp_body or f"HTTP {status_code}")
        return {
            "action": "RETRY_AUTH",
            "quarantine_reason": None,
            "is_duplicate": False,
            "retry_delay": delay,
            "error": sanitized_err
        }

    # 6. HTTP 429 Too Many Requests (Rate Limit Backoff)
    if status_code == 429:
        retry_after_val = (headers or {}).get("Retry-After") or (headers or {}).get("retry-after")
        retry_secs = parse_retry_after(retry_after_val, default_seconds=30.0)
        delay = compute_rate_limit_backoff(retry_secs)
        sanitized_err = sanitize_error_message(error_msg or resp_body or "HTTP 429 Too Many Requests")
        return {
            "action": "RETRY_429",
            "quarantine_reason": None,
            "is_duplicate": False,
            "retry_delay": delay,
            "error": sanitized_err
        }

    # 7. HTTP 5xx, Network/Transient errors, or other status
    new_attempts = current_attempts + 1
    sanitized_err = sanitize_error_message(error_msg or f"HTTP {status_code}")
    if new_attempts >= max_retries:
        return {
            "action": "QUARANTINE",
            "quarantine_reason": "max_retries_exceeded",
            "is_duplicate": False,
            "retry_delay": 0.0,
            "error": sanitized_err
        }
    delay = compute_transient_backoff(new_attempts)
    return {
        "action": "RETRY_TRANSIENT",
        "quarantine_reason": None,
        "is_duplicate": False,
        "retry_delay": delay,
        "error": sanitized_err
    }

class DeliveryManager:
    def __init__(
        self,
        outbox: Outbox,
        client: TransportClient,
        logger: logging.Logger,
        max_retries: int = 10,
        retention_hours: int = 72
    ):
        self.outbox = outbox
        self.client = client
        self.logger = logger
        self.max_retries = max_retries
        self.retention_hours = retention_hours
        
    def process_outbox(self):
        # 1. Purge expired delivered events older than retention_hours (default 72h)
        try:
            self.outbox.purge_delivered_events(retention_hours=self.retention_hours)
        except Exception as e:
            sanitized_e = sanitize_error_message(e)
            self.logger.warning(f"Failed to purge expired delivered events: {sanitized_e}")

        # 2. Retrieve eligible pending events (where next_attempt_at <= now)
        try:
            pending_events = self.outbox.get_pending_events(eligible_only=True)
        except TypeError:
            pending_events = self.outbox.get_pending_events()
        except Exception as e:
            sanitized_e = sanitize_error_message(e)
            self.logger.error(f"Failed to retrieve pending events: {sanitized_e}")
            return

        for row in pending_events:
            event_id = row["detection_event_id"]
            current_attempts = row.get("attempts", 0)

            # 3. Parse local payload
            try:
                event_data = json.loads(row["event_data"])
                if not isinstance(event_data, dict):
                    raise ValueError("Payload is not a valid JSON object")
            except Exception as e:
                sanitized_e = sanitize_error_message(f"JSON parse error: {e}")
                self.logger.error(f"Corrupt event data in outbox for {event_id}: {sanitized_e}")
                self.outbox.mark_quarantined(event_id, "corrupted_payload", sanitized_e, increment_attempts=False)
                continue
                
            # 4. Dispatch event via client
            send_result = self.client.send_event(event_data)
            error_msg = send_result[2] if len(send_result) > 2 else ""

            status_code = getattr(send_result, "status_code", 0)
            resp_body = getattr(send_result, "response_body", "")
            headers = getattr(send_result, "headers", {})

            if status_code == 0 and error_msg:
                m = re.search(r'\b(?:HTTP\s*|status:\s*)(\d{3})\b', error_msg)
                if m:
                    status_code = int(m.group(1))

            # 5. Evaluate outcome
            outcome = evaluate_delivery_outcome(
                event_id=event_id,
                status_code=status_code,
                resp_body=resp_body,
                current_attempts=current_attempts,
                headers=headers,
                error_msg=error_msg,
                max_retries=self.max_retries
            )

            action = outcome["action"]
            if action == "DELIVER":
                if outcome["is_duplicate"]:
                    self.logger.info(f"Event {event_id} delivered to Central SOC (duplicate).")
                else:
                    self.logger.info(f"Event {event_id} delivered to Central SOC.")
                self.outbox.mark_delivered(event_id)
            elif action == "QUARANTINE":
                reason = outcome["quarantine_reason"] or "unknown_quarantine_reason"
                self.logger.warning(f"Quarantining event {event_id} ({reason}): {outcome['error']}")
                self.outbox.mark_quarantined(event_id, reason, outcome["error"], increment_attempts=True)
            else:
                # RETRY_TRANSIENT, RETRY_AUTH, RETRY_429
                delay = outcome["retry_delay"]
                next_attempt_dt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                next_attempt_str = next_attempt_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                self.logger.warning(
                    f"Delivery attempt failed for {event_id} ({action}, retry delay {delay:.1f}s): {outcome['error']}"
                )
                self.outbox.mark_failed(event_id, outcome["error"], next_attempt_at=next_attempt_str)
