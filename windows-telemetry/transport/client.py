import urllib.request
import urllib.error
import json
import logging
from typing import Dict, Any, Tuple

class TransportClient:
    def __init__(self, endpoint_url: str, token: str, logger: logging.Logger):
        self.endpoint_url = endpoint_url
        self.token = token
        self.logger = logger
        self.timeout = 10

    def send_event(self, event: Dict[str, Any]) -> Tuple[bool, bool, str]:
        """Returns (success, duplicate, error_message)"""
        req = urllib.request.Request(self.endpoint_url, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
            
        data = json.dumps(event).encode('utf-8')
        
        try:
            with urllib.request.urlopen(req, data=data, timeout=self.timeout) as response:
                resp_body = response.read().decode('utf-8')
                if response.status in (200, 201):
                    try:
                        resp_data = json.loads(resp_body)
                        return True, resp_data.get("duplicate", False), ""
                    except json.JSONDecodeError:
                        return True, False, ""
                return False, False, f"Unexpected status: {response.status}"
        except urllib.error.HTTPError as e:
            try:
                err_msg = e.read().decode('utf-8')
            except:
                err_msg = "Unknown error"
            self.logger.error(f"HTTPError {e.code}: {err_msg}")
            return False, False, f"HTTP {e.code}: {err_msg}"
        except Exception as e:
            self.logger.error(f"Transport error: {e}")
            return False, False, str(e)
