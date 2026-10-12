from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from .models import DetectionResult

class LinuxSSHBruteForceRule:
    """
    Detects repeated SSH authentication failures on Ubuntu within a sliding window.
    Generates high-severity 'brute_force' detections for integration with MITRE T1110.
    """
    def __init__(self, failure_threshold: int = 5, window_seconds: int = 60):
        self.name = "linux_ssh_bruteforce_rule"
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.state = {}

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        evidence = normalized_event.get("evidence", {})

        # Check if this is an SSH failure
        is_ssh = evidence.get("process") == "sshd" or "ssh" in str(evidence.get("event_subtype", ""))
        is_failure = evidence.get("auth_status") == "failed" or evidence.get("event_subtype") in ("ssh_login_failure", "ssh_invalid_user")

        if not (is_ssh and is_failure):
            return None

        username = normalized_event.get("username")
        if not username:
            return None

        source_ip = normalized_event.get("source_ip")
        group_key = (username, source_ip)

        timestamp_str = normalized_event.get("timestamp")
        try:
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"
            current_time = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Invalid timestamp in event: {timestamp_str}") from e

        group_state = self.state.setdefault(group_key, {"events": [], "last_alert_time": None})
        events = group_state["events"]

        event_id = normalized_event.get("event_id")
        events.append((current_time, event_id))

        cutoff = current_time - timedelta(seconds=self.window_seconds)
        # Purge events outside the sliding window
        group_state["events"] = [(t, eid) for t, eid in events if t >= cutoff]

        if len(group_state["events"]) >= self.failure_threshold:
            last_alert = group_state["last_alert_time"]

            # Suppress duplicate alerts in the same window
            if last_alert is None or last_alert < cutoff:
                group_state["last_alert_time"] = current_time

                result_evidence = {
                    "source": "auth.log",
                    "process": "sshd",
                    "failure_count": len(group_state["events"]),
                    "threshold": self.failure_threshold,
                    "window_seconds": self.window_seconds,
                    "username": username,
                    "related_event_ids": [eid for t, eid in group_state["events"]]
                }
                if source_ip is not None:
                    result_evidence["source_ip"] = source_ip

                return DetectionResult(
                    detected=True,
                    detection_type="brute_force",  # Aligns with mitre_catalog.json (T1110)
                    confidence=1.0,
                    severity="high",
                    detector_name=self.name,
                    source_event_id=event_id,
                    evidence=result_evidence
                )

        return None

    def reset_state(self):
        self.state.clear()


class LinuxSuspiciousSudoRule:
    """
    Detects repeated sudo authentication failures on Ubuntu.
    """
    def __init__(self, failure_threshold: int = 3, window_seconds: int = 60):
        self.name = "linux_suspicious_sudo_rule"
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.state = {}

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        evidence = normalized_event.get("evidence", {})
        if evidence.get("event_subtype") != "sudo_auth_failure":
            return None

        username = normalized_event.get("username") or "unknown"
        timestamp_str = normalized_event.get("timestamp")
        try:
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"
            current_time = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Invalid timestamp in event: {timestamp_str}") from e

        group_state = self.state.setdefault(username, {"events": [], "last_alert_time": None})
        events = group_state["events"]
        event_id = normalized_event.get("event_id")
        events.append((current_time, event_id))

        cutoff = current_time - timedelta(seconds=self.window_seconds)
        group_state["events"] = [(t, eid) for t, eid in events if t >= cutoff]

        if len(group_state["events"]) >= self.failure_threshold:
            last_alert = group_state["last_alert_time"]
            if last_alert is None or last_alert < cutoff:
                group_state["last_alert_time"] = current_time
                return DetectionResult(
                    detected=True,
                    detection_type="suspicious_sudo_activity",
                    confidence=0.85,
                    severity="medium",
                    detector_name=self.name,
                    source_event_id=event_id,
                    evidence={
                        "source": "auth.log",
                        "process": "sudo",
                        "username": username,
                        "failure_count": len(group_state["events"]),
                        "threshold": self.failure_threshold,
                        "window_seconds": self.window_seconds
                    }
                )

        return None

    def reset_state(self):
        self.state.clear()
