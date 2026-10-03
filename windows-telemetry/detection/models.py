from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class DetectionResult:
    detected: bool
    detection_type: Optional[str]
    confidence: Optional[float]
    severity: Optional[str]
    detector_name: str
    source_event_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
