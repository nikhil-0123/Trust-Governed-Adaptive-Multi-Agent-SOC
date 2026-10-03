from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from .models import DetectionResult

class BruteForceRule:
    def __init__(self):
        self.name = "windows_bruteforce_rule"
        self.failure_threshold = 5
        self.window_seconds = 60
        self.state = {}

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        evidence = normalized_event.get("evidence", {})
        
        # Only process Windows Event ID 4625 (Failed Logon)
        if evidence.get("windows_event_id") != 4625:
            return None
            
        username = normalized_event.get("username")
        if not username:
            # Cannot group safely without a username
            return None
            
        source_ip = normalized_event.get("source_ip")
        group_key = (username, source_ip)
        
        timestamp_str = normalized_event.get("timestamp")
        try:
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            current_time = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Invalid timestamp in event: {timestamp_str}") from e

        group_state = self.state.setdefault(group_key, {"events": [], "last_alert_time": None})
        events = group_state["events"]
        
        event_id = normalized_event.get("event_id")
        events.append((current_time, event_id))
        
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        # Keep events within the window (>= cutoff)
        group_state["events"] = [(t, eid) for t, eid in events if t >= cutoff]
        
        if len(group_state["events"]) >= self.failure_threshold:
            last_alert = group_state["last_alert_time"]
            
            # Suppress duplicate alerts in the same sliding window
            if last_alert is None or last_alert < cutoff:
                group_state["last_alert_time"] = current_time
                
                result_evidence = {
                    "windows_event_id": 4625,
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
                    detection_type=self.name,
                    confidence=1.0,
                    severity="high",
                    detector_name=self.name,
                    source_event_id=event_id,
                    evidence=result_evidence
                )
                
        return None

    def reset_state(self):
        self.state.clear()
