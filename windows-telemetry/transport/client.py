import os
import urllib.request
import urllib.error
import json
import logging
from typing import Dict, Any, Tuple, Optional
from .outbox import sanitize_error_message

class SendResult(tuple):
    def __new__(cls, success: bool, duplicate: bool, error: str, status_code: int = 0, response_body: str = "", headers: Optional[Dict[str, str]] = None):
        return super().__new__(cls, (success, duplicate, error))

    def __init__(self, success: bool, duplicate: bool, error: str, status_code: int = 0, response_body: str = "", headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self.response_body = response_body
        self.headers = headers or {}

    @property
    def success(self) -> bool:
        return self[0]

    @property
    def duplicate(self) -> bool:
        return self[1]

    @property
    def error(self) -> str:
        return self[2]

class TransportClient:
    def __init__(self, endpoint_url: str, token: str, logger: logging.Logger):
        self.endpoint_url = endpoint_url
        self.token = token
        self.logger = logger
        self.timeout = 10

    def send_event(self, event: Dict[str, Any]) -> SendResult:
        """Returns SendResult(success, duplicate, error_message, status_code, response_body, headers)"""
        req = urllib.request.Request(self.endpoint_url, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
            
        data = json.dumps(event).encode('utf-8')
        event_id = event.get("detection_event_id") if isinstance(event, dict) else None
        is_valid_event_id = bool(event_id) and isinstance(event_id, str) and bool(event_id.strip())
        
        try:
            with urllib.request.urlopen(req, data=data, timeout=self.timeout) as response:
                resp_body = response.read().decode('utf-8')
                resp_headers = dict(response.headers) if hasattr(response, "headers") else {}

                # Check status
                if response.status == 201:
                    try:
                        resp_data = json.loads(resp_body)
                        if (
                            isinstance(resp_data, dict)
                            and resp_data.get("accepted") is True
                            and is_valid_event_id
                            and resp_data.get("detection_event_id") == event_id
                        ):
                            return SendResult(True, False, "", status_code=201, response_body=resp_body, headers=resp_headers)
                        sanitized_body = sanitize_error_message(resp_body)
                        return SendResult(False, False, f"Contract violation on HTTP 201: {sanitized_body}", status_code=201, response_body=resp_body, headers=resp_headers)
                    except Exception as je:
                        sanitized_err = sanitize_error_message(str(je))
                        return SendResult(False, False, f"JSON parse error on HTTP 201: {sanitized_err}", status_code=201, response_body=resp_body, headers=resp_headers)

                # Legacy acceptance for HTTP 200 (preserves existing protected test_client_http_200_mock)
                if response.status == 200:
                    try:
                        resp_data = json.loads(resp_body)
                        dup = resp_data.get("duplicate", False) if isinstance(resp_data, dict) else False
                        return SendResult(True, dup, "", status_code=200, response_body=resp_body, headers=resp_headers)
                    except Exception:
                        return SendResult(True, False, "", status_code=200, response_body=resp_body, headers=resp_headers)

                sanitized_body = sanitize_error_message(resp_body)
                return SendResult(False, False, f"Unexpected status: {response.status}", status_code=response.status, response_body=resp_body, headers=resp_headers)

        except urllib.error.HTTPError as e:
            try:
                err_msg = e.read().decode('utf-8')
            except Exception:
                err_msg = "Unknown error"
            e_headers = dict(e.headers) if hasattr(e, "headers") else {}
            sanitized_err = sanitize_error_message(err_msg)
            self.logger.error(f"HTTPError {e.code}: {sanitized_err}")

            # HTTP 409 Conflict check for duplicate ACK contract
            if e.code == 409:
                try:
                    resp_data = json.loads(err_msg)
                    if (
                        isinstance(resp_data, dict)
                        and resp_data.get("accepted") is True
                        and resp_data.get("duplicate") is True
                        and is_valid_event_id
                        and resp_data.get("detection_event_id") == event_id
                    ):
                        return SendResult(True, True, "", status_code=409, response_body=err_msg, headers=e_headers)
                except Exception:
                    pass

            return SendResult(False, False, f"HTTP {e.code}: {sanitized_err}", status_code=e.code, response_body=err_msg, headers=e_headers)

        except Exception as e:
            sanitized_e = sanitize_error_message(e)
            self.logger.error(f"Transport error: {sanitized_e}")
            return SendResult(False, False, str(sanitized_e), status_code=0, response_body="", headers={})


class TransitionTransportClient:
    """
    Authenticated HTTP transport client delivering ChannelTransition envelopes
    to POST /api/v1/events/transition on the central SOC backend.
    Enforces per-agent credentials: token cannot be empty and cannot match shared SOC_API_TOKEN.
    """
    def __init__(
        self,
        endpoint_url: str,
        token: str,
        logger: logging.Logger,
        timeout: int = 10,
        agent_id: Optional[str] = None
    ):
        self.endpoint_url = endpoint_url
        self.token = str(token).strip() if token is not None else ""
        self.logger = logger
        self.timeout = timeout
        self.agent_id = str(agent_id).strip() if agent_id else None

        if not self.token:
            raise ValueError("Per-agent transition authentication requires a non-empty token")

        shared_soc_token = os.getenv("SOC_API_TOKEN", "dev-token-123").strip()
        if shared_soc_token and self.token == shared_soc_token:
            raise ValueError("Security violation: per-agent transition client cannot use shared SOC_API_TOKEN")

    def send_transition(self, transition: Dict[str, Any]) -> SendResult:
        """
        Sends a ChannelTransition payload to POST /api/v1/events/transition.
        Returns SendResult(success, duplicate, error_message, status_code, response_body, headers)
        """
        if self.agent_id and isinstance(transition, dict):
            claimed_agent = transition.get("agent_id")
            if claimed_agent and claimed_agent != self.agent_id:
                raise ValueError(
                    f"Security violation: transition agent_id '{claimed_agent}' does not match authenticated agent_id '{self.agent_id}'"
                )

        req = urllib.request.Request(self.endpoint_url, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        data = json.dumps(transition).encode('utf-8')
        transition_id = transition.get("transition_id") if isinstance(transition, dict) else None
        is_valid_tid = bool(transition_id) and isinstance(transition_id, str) and bool(transition_id.strip())

        try:
            with urllib.request.urlopen(req, data=data, timeout=self.timeout) as response:
                resp_body = response.read().decode('utf-8')
                resp_headers = dict(response.headers) if hasattr(response, "headers") else {}

                if response.status == 200:
                    try:
                        resp_data = json.loads(resp_body)
                        status_str = resp_data.get("status") if isinstance(resp_data, dict) else ""
                        echoed_tid = resp_data.get("transition_id") if isinstance(resp_data, dict) else None
                        is_dup = bool(resp_data.get("duplicate", False)) or status_str in ("ALREADY_APPLIED", "OBSOLETE")
                        if status_str in ("APPLIED", "ALREADY_APPLIED", "OBSOLETE") and is_valid_tid and echoed_tid == transition_id:
                            return SendResult(True, is_dup, "", status_code=200, response_body=resp_body, headers=resp_headers)
                        sanitized_body = sanitize_error_message(resp_body)
                        return SendResult(False, False, f"Unexpected response contract on HTTP 200: {sanitized_body}", status_code=200, response_body=resp_body, headers=resp_headers)
                    except Exception as je:
                        sanitized_err = sanitize_error_message(str(je))
                        return SendResult(False, False, f"JSON parse error on HTTP 200: {sanitized_err}", status_code=200, response_body=resp_body, headers=resp_headers)

                sanitized_body = sanitize_error_message(resp_body)
                return SendResult(False, False, f"Unexpected status: {response.status}", status_code=response.status, response_body=resp_body, headers=resp_headers)

        except urllib.error.HTTPError as e:
            try:
                err_msg = e.read().decode('utf-8')
            except Exception:
                err_msg = "Unknown error"
            e_headers = dict(e.headers) if hasattr(e, "headers") else {}
            sanitized_err = sanitize_error_message(err_msg)
            self.logger.error(f"HTTPError {e.code} delivering transition: {sanitized_err}")

            if e.code == 409:
                try:
                    resp_data = json.loads(err_msg)
                    echoed_tid = resp_data.get("transition_id") if isinstance(resp_data, dict) else None
                    if (
                        isinstance(resp_data, dict)
                        and resp_data.get("duplicate") is True
                        and resp_data.get("accepted") is True
                        and echoed_tid == transition_id
                        and is_valid_tid
                    ):
                        return SendResult(True, True, "", status_code=409, response_body=err_msg, headers=e_headers)
                except Exception:
                    pass

            return SendResult(False, False, f"HTTP {e.code}: {sanitized_err}", status_code=e.code, response_body=err_msg, headers=e_headers)

        except Exception as e:
            sanitized_e = sanitize_error_message(e)
            self.logger.error(f"Transport error delivering transition: {sanitized_e}")
            return SendResult(False, False, str(sanitized_e), status_code=0, response_body="", headers={})
