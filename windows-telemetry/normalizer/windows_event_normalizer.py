import hashlib
import logging
from typing import Dict, Any, List, Optional
from core.agent_identity import AgentIdentity

class WindowsEventNormalizer:
    def __init__(self, agent_identity: AgentIdentity, logger: logging.Logger):
        self.agent_identity = agent_identity
        self.logger = logger
        
    def _map_severity(self, level: Optional[int]) -> str:
        # Windows levels: 1=Critical, 2=Error, 3=Warning, 4=Info, 0=Log Always
        if level == 1:
            return "critical"
        elif level == 2:
            return "high"
        elif level == 3:
            return "medium"
        else:
            return "low"
            
    def _generate_event_id(self, record_id: str, hostname: str, log_name: str) -> str:
        agent_id = self.agent_identity.agent_id
        raw_identity = f"{agent_id}|{hostname}|{log_name}|{record_id}"
        return hashlib.sha256(raw_identity.encode('utf-8')).hexdigest()

    def normalize(self, raw_event: Dict[str, Any], log_name: str = "Security") -> Dict[str, Any]:
        """Normalizes a single raw Windows event to the standard contract."""
        if "record_id" not in raw_event:
            raise ValueError("Raw event missing required 'record_id'")
        if "timestamp" not in raw_event:
            raise ValueError("Raw event missing required 'timestamp'")
            
        hostname = raw_event.get("computer")
        if not hostname:
            hostname = self.agent_identity.get_hostname()
            
        event_id = self._generate_event_id(str(raw_event["record_id"]), hostname, log_name)
        
        severity = self._map_severity(raw_event.get("level"))
        
        # Evidence preserves untrusted raw source info
        evidence = {
            "record_id": raw_event.get("record_id"),
            "provider": raw_event.get("provider"),
            "log_name": log_name,
            "level": raw_event.get("level"),
            "task": raw_event.get("task"),
            "keywords": raw_event.get("keywords")
        }
        
        if "event_id" in raw_event:
            evidence["windows_event_id"] = raw_event["event_id"]

        if "logon_type" in raw_event and raw_event["logon_type"] is not None:
            evidence["logon_type"] = raw_event["logon_type"]

        if "raw_xml" in raw_event:
            evidence["raw_xml"] = raw_event["raw_xml"]
            
        return {
            "event_id": event_id,
            "timestamp": raw_event["timestamp"],
            "agent_id": self.agent_identity.agent_id,
            "hostname": hostname,
            "os": "Windows",
            "event_type": "windows_security_event",
            "source_ip": raw_event.get("source_ip", None),
            "username": raw_event.get("username", None),
            "severity": severity,
            "detection_type": None,
            "confidence": None,
            "evidence": evidence
        }

    def normalize_batch(self, raw_events: List[Dict[str, Any]], log_name: str = "Security") -> List[Dict[str, Any]]:
        """Normalizes a batch of raw events sequentially, preserving order."""
        normalized_events = []
        for raw_event in raw_events:
            try:
                normalized = self.normalize(raw_event, log_name)
                normalized_events.append(normalized)
            except Exception as e:
                self.logger.error(f"Failed to normalize event: {e}. Raw keys: {list(raw_event.keys())}")
        return normalized_events
