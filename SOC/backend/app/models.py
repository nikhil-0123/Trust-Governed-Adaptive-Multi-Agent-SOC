from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
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
    latest_assessment_id: Optional[str] = None
    latest_analysis_id: Optional[str] = None
    # Enriched Governance & Response Status for real-time dashboard presentation
    governance_decision: Optional[str] = None
    approval_status: Optional[str] = None
    mitigation_dispatched_count: Optional[int] = 0
    dispatched_command_types: Optional[List[str]] = Field(default_factory=list)

class ThreatContext(BaseModel):
    context_id: str
    incident_id: str
    technique_id: str
    technique_name: str
    tactic: str
    mitre_version: str
    mapping_method: str

class Assessment(BaseModel):
    assessment_id: str
    incident_id: str
    trust_score: Optional[float]
    risk_score: Optional[float]
    status: str
    formula_version: str
    config_version: str
    input_snapshot: str
    trust_explanation: Optional[str]
    risk_explanation: Optional[str]
    created_at: str

class Analysis(BaseModel):
    analysis_id: str
    incident_id: str
    assessment_id: str
    status: str
    model_provenance: str
    analysis_output: str
    created_at: str

class GovernanceDecision(BaseModel):
    decision_id: str
    incident_id: str
    assessment_id: str
    analysis_id: str
    decision: str
    reason: str
    policy_version: str
    config_version: str
    created_at: str

class ProvenanceHistory(BaseModel):
    incident: Incident
    assessment: Optional[Assessment] = None
    analysis: Optional[Analysis] = None
    decision: Optional[GovernanceDecision] = None
    historical_decisions: List[GovernanceDecision] = []

class AnalystOverrideRequest(BaseModel):
    action: str
    reason: str

class EndpointHeartbeat(BaseModel):
    agent_id: str
    hostname: str
    os: str
    ip_address: Optional[str] = None
    agent_version: Optional[str] = "1.0.0"
    capabilities: Optional[List[str]] = Field(default_factory=list)

class EndpointCommandCreate(BaseModel):
    command_type: str  # PING, GET_HEALTH, GET_STATUS
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

class EndpointCommand(BaseModel):
    command_id: str
    agent_id: str
    command_type: str
    parameters: Optional[Dict[str, Any]] = None
    status: str  # PENDING, SENT, EXECUTED, FAILED
    result: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: str

class EndpointCommandResult(BaseModel):
    status: str = "EXECUTED"  # EXECUTED or FAILED
    result: Dict[str, Any] = Field(default_factory=dict)

class EndpointInfo(BaseModel):
    agent_id: str
    hostname: str
    os: str
    ip_address: Optional[str] = None
    status: str  # ONLINE, OFFLINE
    last_heartbeat: str
    agent_version: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)

class GovernanceApprovalRequest(BaseModel):
    action: Optional[str] = None  # Specific action to approve (e.g. ISOLATE_HOST or BLOCK_SOURCE), or None for all
    analyst_name: Optional[str] = "soc_analyst"
    reason: Optional[str] = "Analyst approved recommended mitigation"
    custom_params: Optional[Dict[str, Any]] = None

class GovernanceRejectionRequest(BaseModel):
    analyst_name: Optional[str] = "soc_analyst"
    reason: str = "Analyst rejected recommended mitigation"

class IncidentGovernanceStatus(BaseModel):
    incident_id: str
    decision_id: Optional[str] = None
    decision: Optional[str] = None
    approval_status: str  # PENDING, AUTO_APPROVED, APPROVED, REJECTED, NOT_REQUIRED
    reason: Optional[str] = None
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    dispatched_commands: List[EndpointCommand] = Field(default_factory=list)
    updated_at: Optional[str] = None

