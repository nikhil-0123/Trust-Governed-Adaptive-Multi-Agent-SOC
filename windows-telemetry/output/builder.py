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
            evidence=result.evidence.copy()
        )
