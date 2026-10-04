import json
import os
import sqlite3
from typing import List, Dict, Any

from pydantic import BaseModel, ValidationError

from app.reasoning_models import Claim
from app.reasoning_provider import LLMProvider, LLMProviderError
from app.evidence_validator import EvidenceValidator

class AnalysisInput(BaseModel):
    """
    Strongly typed input bounding the data available to the AnalysisAgent.
    """
    incident_id: str
    assessment_id: str
    incident_summary: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    entities: List[Dict[str, Any]]
    authoritative_mitre_context: List[Dict[str, Any]]
    assessment_snapshot: Dict[str, Any]

class RejectedClaim(BaseModel):
    """Represents a claim that failed structural or evidence validation."""
    raw_claim: Dict[str, Any]
    reasons: List[str]

class AnalysisResult(BaseModel):
    """Result of the AnalysisAgent candidate generation."""
    accepted_claims: List[Claim]
    rejected_claims: List[RejectedClaim]
    provider: str
    model: str
    request_id: str
    prompt_version: str

class AnalysisAgentParsingError(Exception):
    """Raised when the LLM output cannot be parsed as the required JSON structure."""
    pass

class AnalysisAgentConfigurationError(Exception):
    """Raised for agent misconfigurations."""
    pass

class AnalysisAgent:
    """
    Step 10C: Analysis Agent.
    Generates candidate factual claims based on bounded analysis input.
    Does NOT execute actions, modify databases, or perform synthesis.
    """
    def __init__(self, provider: LLMProvider, validator: EvidenceValidator, config: Dict[str, Any]):
        self.provider = provider
        self.validator = validator
        self.config = config

    def generate_candidate_claims(self, input_data: AnalysisInput, conn: sqlite3.Connection) -> AnalysisResult:
        # Enforce max evidence limit strictly
        max_ev = self.config.get("max_evidence_events", 100)
        if len(input_data.evidence) > max_ev:
            raise ValueError(f"Supplied evidence count ({len(input_data.evidence)}) exceeds configured limit ({max_ev})")
        
        # Determine prompt version
        prompt_versions_map = self.config.get("prompt_versions", {})
        prompt_version = prompt_versions_map.get("analysis", "analysis_v1")
        
        # Safely load prompt (preventing directory traversal)
        safe_version = os.path.basename(prompt_version)
        prompt_path = os.path.join(os.path.dirname(__file__), "reasoning", "prompts", f"{safe_version}.md")
        if not os.path.exists(prompt_path):
            raise AnalysisAgentConfigurationError(f"Configured prompt version '{safe_version}' not found at {prompt_path}.")
            
        with open(prompt_path, "r", encoding="utf-8") as f:
            system_prompt = f.read()

        user_prompt = input_data.model_dump_json()
        model_name = self.config.get("model", "mock-model")
        timeout = self.config.get("timeout_seconds", 30)

        # Provider interaction
        try:
            response = self.provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=model_name,
                timeout_seconds=timeout
            )
        except LLMProviderError as e:
            # Wrap or propagate provider error without fabricating claims
            raise e

        # JSON Parsing
        try:
            parsed = json.loads(response.content)
        except json.JSONDecodeError as e:
            raise AnalysisAgentParsingError(f"Malformed JSON output from provider: {e}")

        if not isinstance(parsed, dict) or "claims" not in parsed:
            raise AnalysisAgentParsingError("Top-level JSON must be an object containing a 'claims' array.")
            
        raw_claims = parsed["claims"]
        if not isinstance(raw_claims, list):
            raise AnalysisAgentParsingError("The 'claims' field must be a JSON array.")

        accepted = []
        rejected = []

        # Claim Validation
        for raw in raw_claims:
            if not isinstance(raw, dict):
                rejected.append(RejectedClaim(raw_claim={"_malformed": str(raw)}, reasons=["Claim is not a JSON object"]))
                continue
                
            try:
                claim = Claim.model_validate(raw)
            except ValidationError as e:
                reasons = [err.get("msg", "Validation error") for err in e.errors()]
                rejected.append(RejectedClaim(raw_claim=raw, reasons=reasons))
                continue

            # Check Incident Scope
            if claim.incident_id != input_data.incident_id:
                raw["status"] = "UNSUPPORTED"
                rejected.append(RejectedClaim(raw_claim=raw, reasons=["CLAIM_INCIDENT_MISMATCH"]))
                continue

            # Deterministic Evidence Validation
            val_res = self.validator.validate_claim(claim, input_data.incident_id, conn)
            
            if not val_res.valid:
                # Force status to unsupported based on validator decision
                claim.status = "UNSUPPORTED"
                raw["status"] = "UNSUPPORTED"
                rejected.append(RejectedClaim(raw_claim=raw, reasons=val_res.validation_errors))
            else:
                accepted.append(claim)

        return AnalysisResult(
            accepted_claims=accepted,
            rejected_claims=rejected,
            provider=response.provider,
            model=response.model,
            request_id=response.request_id,
            prompt_version=prompt_version
        )
