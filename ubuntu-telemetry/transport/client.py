import urllib.request
import urllib.error
import json
import logging
from typing import Dict, Any, Tuple, Optional

import urllib.parse

class TransportClient:
    """
    HTTP/HTTPS client for delivering DetectionEvents to the Central SOC Ingestion API.
    Uses static Bearer Token authentication and bounded request timeouts.
    Restricts plain HTTP transport to local development/test environments.
    """
    def __init__(self, endpoint_url: str, token: str, logger: Optional[logging.Logger] = None, environment: str = "development"):
        self.endpoint_url = endpoint_url
        self.token = token
        self.logger = logger or logging.getLogger("TransportClient")
        self.environment = environment
        self.timeout = 10
        self._validate_transport_security()

    def _validate_transport_security(self):
        parsed = urllib.parse.urlparse(self.endpoint_url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        is_loopback = host in ("127.0.0.1", "localhost", "::1", "testserver")
        if scheme == "http":
            if not is_loopback and self.environment not in ("development", "test"):
                raise ValueError(
                    f"Insecure HTTP transport rejected for non-loopback host '{host}' in {self.environment} environment. "
                    "Central SOC transport requires HTTPS to prevent Bearer token and evidence exposure."
                )
            elif not is_loopback:
                self.logger.warning(f"Insecure HTTP transport permitted for host '{host}' in development mode.")

    def send_event(self, event: Dict[str, Any]) -> Tuple[bool, bool, str]:
        """
        Sends a single DetectionEvent to Central SOC.
        Returns (success: bool, duplicate: bool, error_message: str).
        """
        req = urllib.request.Request(self.endpoint_url, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        data = json.dumps(event).encode("utf-8")

        try:
            with urllib.request.urlopen(req, data=data, timeout=self.timeout) as response:
                resp_body = response.read().decode("utf-8")
                if response.status in (200, 201):
                    try:
                        resp_data = json.loads(resp_body)
                        return True, resp_data.get("duplicate", False), ""
                    except json.JSONDecodeError:
                        return True, False, ""
                return False, False, f"Unexpected status: {response.status}"
        except urllib.error.HTTPError as e:
            try:
                err_msg = e.read().decode("utf-8")
            except Exception:
                err_msg = "Unknown error"
            self.logger.error(f"HTTPError {e.code}: {err_msg}")
            return False, False, f"HTTP {e.code}: {err_msg}"
        except Exception as e:
            self.logger.error(f"Transport error sending event: {e}")
            return False, False, str(e)
