from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any

class Claim(BaseModel):
    claim_id: str
    incident_id: str
    claim_type: str
    statement: str
    reasoning_summary: str
    supporting_evidence: List[str]
    mitre_techniques: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    status: Optional[str] = None
    agent_id: str

class VerificationResult(BaseModel):
    claim_id: str
    verification_status: Literal["VERIFIED", "PARTIALLY_VERIFIED", "UNVERIFIED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE"]
    verification_reason: str
    supporting_evidence: List[str]
    contradictory_evidence: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    verifier_agent_id: str

class Recommendation(BaseModel):
    type: str
    status: Literal["RECOMMENDED"]
    reason: str
    supporting_claims: List[str]

class FinalAnalysis(BaseModel):
    analysis_id: str
    incident_id: str
    assessment_id: str
    assessment_snapshot: Dict[str, Any]
    incident_summary: str
    evidence_summary: str
    verified_claims: List[Claim]
    rejected_claims: List[Claim]
    unsupported_claims: List[Claim]
    verification_results: List[VerificationResult]
    authoritative_mitre_context: List[Dict[str, Any]]
    proposed_mitre_context: List[Dict[str, Any]]
    uncertainty: Dict[str, Any]
    recommendations: List[Recommendation]
    model_provenance: str
    prompt_versions: Dict[str, Any]
    created_at: str
