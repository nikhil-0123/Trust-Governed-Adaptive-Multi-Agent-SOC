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
    detector_version: str = "1.0.0"
    rules_digest: Optional[str] = None
    thresholds: Optional[Dict[str, Any]] = None
    detector_config: Optional[Dict[str, Any]] = None
    model_artifact_digest: Optional[str] = None
    detector_manifest: Optional[Dict[str, Any]] = None
