from pydantic import BaseModel, Field
from typing import Dict, Any, List
from datetime import datetime

class DetectionEvent(BaseModel):
    detection_event_id: str
    timestamp: str
    agent_id: str
    hostname: str
    os: str
    source_event_id: str
    detection_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    detector_name: str
    evidence: Dict[str, Any]

class IncidentEvidence(BaseModel):
    incident_id: str
    detection_event_id: str

class IncidentEntity(BaseModel):
    incident_id: str
    entity_type: str
    entity_value: str

class Incident(BaseModel):
    incident_id: str
    created_at: datetime
    updated_at: datetime
    first_seen: datetime
    last_seen: datetime
    max_severity: str
    status: str
