from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class DetectionResult:
    detected: bool
    detection_type: Optional[str] = None
    confidence: Optional[float] = None
    severity: Optional[str] = None
    detector_name: Optional[str] = None
    source_event_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
