from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class DetectionEvent:
    detection_event_id: str
    timestamp: str
    agent_id: str
    hostname: str
    os: str
    source_event_id: str
    detection_type: str
    confidence: float
    severity: str
    detector_name: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    detector_version: str = "1.0.0"
    detector_revision: Optional[str] = None
