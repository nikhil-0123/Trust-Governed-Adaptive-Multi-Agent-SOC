import hashlib
from typing import Dict, Any, Optional
from detection.models import DetectionResult
from .models import DetectionEvent

class DetectionEventBuilder:
    @staticmethod
    def build(normalized_event: Dict[str, Any], result: DetectionResult) -> Optional[DetectionEvent]:
        if not result.detected:
            return None
            
        required_keys = ["agent_id", "hostname", "os", "timestamp"]
        for key in required_keys:
            if key not in normalized_event:
                raise ValueError(f"Normalized event missing required key: {key}")
                
        if not result.detection_type or result.confidence is None or not result.severity or not result.detector_name:
            raise ValueError("DetectionResult missing required fields")
            
        source_event_id = result.source_event_id or normalized_event.get("event_id")
        if not source_event_id:
            raise ValueError("Source event ID is missing")
            
        # Deterministic ID algorithm: SHA256(agent_id + source_event_id + detection_type + detector_name)
        hash_input = f"{normalized_event['agent_id']}|{source_event_id}|{result.detection_type}|{result.detector_name}".encode('utf-8')
        detection_event_id = hashlib.sha256(hash_input).hexdigest()

        # WP-1C: Ensure all canonical identity attributes from normalized event survive into DetectionEvent.evidence
        evidence = result.evidence.copy() if result.evidence else {}
        norm_evidence = normalized_event.get("evidence") or {}
        for id_field in (
            "target_account_id",
            "target_user",
            "target_domain",
            "domain_status",
            "domain_namespace",
            "caller_user",
            "caller_domain",
        ):
            if id_field in norm_evidence and id_field not in evidence:
                evidence[id_field] = norm_evidence[id_field]

        if "username" in normalized_event and "username" not in evidence:
            evidence["username"] = normalized_event["username"]

        # Phase 2: Preserve Sysmon process, network, and DNS attributes
        for fld in (
            "sysmon_event_id",
            "process_guid",
            "parent_process_guid",
            "process_id",
            "parent_process_id",
            "process_name",
            "parent_process_name",
            "sha256",
            "md5",
            "sha1",
            "imphash",
            "integrity_level",
            "current_directory",
            "destination_ip",
            "destination_port",
            "source_port",
            "protocol",
            "initiated",
            "query_name",
            "query_status",
            "query_results",
        ):
            if fld in norm_evidence and fld not in evidence:
                evidence[fld] = norm_evidence[fld]
        
        return DetectionEvent(
            detection_event_id=detection_event_id,
            timestamp=normalized_event["timestamp"],
            agent_id=normalized_event["agent_id"],
            hostname=normalized_event["hostname"],
            os=normalized_event["os"],
            source_event_id=source_event_id,
            detection_type=result.detection_type,
            confidence=result.confidence,
            severity=result.severity,
            detector_name=result.detector_name,
            evidence=evidence
        )
