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
