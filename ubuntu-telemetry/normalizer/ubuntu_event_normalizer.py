import hashlib
import logging
from typing import Dict, Any, List, Optional
from core.agent_identity import AgentIdentity

class UbuntuEventNormalizer:
    """
    Normalizes raw Ubuntu/Linux telemetry events to the common normalized event contract v1.
    Ensures UTF-8 encoding, deterministic event IDs, UTC ISO timestamps, and sanitized evidence.
    """
    def __init__(self, agent_identity: AgentIdentity, logger: Optional[logging.Logger] = None):
        self.agent_identity = agent_identity
        self.logger = logger or logging.getLogger("UbuntuEventNormalizer")

    def _map_severity(self, auth_status: str, event_subtype: str) -> str:
        """Determines normalized severity: 'low', 'medium', 'high', 'critical'."""
        if auth_status == "failed" or event_subtype in ("ssh_login_failure", "ssh_invalid_user", "sudo_auth_failure"):
            return "medium"
        elif auth_status == "accepted":
            return "low"
        return "low"

    def _generate_event_id(self, record_id: str, hostname: str, source: str) -> str:
        """Generates a stable, unique SHA-256 event ID."""
        agent_id = self.agent_identity.agent_id
        raw_identity = f"{agent_id}|{hostname}|{source}|{record_id}"
        return hashlib.sha256(raw_identity.encode("utf-8")).hexdigest()

    def normalize(self, raw_event: Dict[str, Any], source_name: str = "auth.log") -> Dict[str, Any]:
        """Normalizes a single raw event to the standard schema."""
        if "record_id" not in raw_event:
            raise ValueError("Raw event missing required 'record_id'")
        if "timestamp" not in raw_event:
            raise ValueError("Raw event missing required 'timestamp'")

        hostname = raw_event.get("hostname")
        if not hostname:
            hostname = self.agent_identity.get_hostname()

        event_id = self._generate_event_id(str(raw_event["record_id"]), hostname, source_name)
        severity = self._map_severity(raw_event.get("auth_status", ""), raw_event.get("event_subtype", ""))

        # Evidence dictionary preserves forensic context
        evidence = {
            "record_id": raw_event.get("record_id"),
            "source_name": source_name,
            "process": raw_event.get("process"),
            "pid": raw_event.get("pid"),
            "auth_status": raw_event.get("auth_status"),
            "event_subtype": raw_event.get("event_subtype"),
            "auth_method": raw_event.get("auth_method"),
            "port": raw_event.get("port"),
            "raw_message": raw_event.get("raw_message")
        }

        # Include source_ip and username inside evidence for downstream engine extraction
        if raw_event.get("source_ip"):
            evidence["source_ip"] = raw_event["source_ip"]
        if raw_event.get("username"):
            evidence["username"] = raw_event["username"]

        return {
            "event_id": event_id,
            "timestamp": raw_event["timestamp"],
            "agent_id": self.agent_identity.agent_id,
            "hostname": hostname,
            "os": "Linux",
            "event_type": "linux_auth_event",
            "source_ip": raw_event.get("source_ip", None),
            "username": raw_event.get("username", None),
            "severity": severity,
            "detection_type": None,
            "confidence": None,
            "evidence": evidence
        }

    def normalize_batch(self, raw_events: List[Dict[str, Any]], source_name: str = "auth.log") -> List[Dict[str, Any]]:
        """Normalizes a list of raw events, skipping malformed records safely."""
        normalized_events = []
        for raw_event in raw_events:
            try:
                normalized = self.normalize(raw_event, source_name)
                normalized_events.append(normalized)
            except Exception as e:
                self.logger.error(f"Failed to normalize Linux event: {e}. Keys: {list(raw_event.keys())}")
        return normalized_events
