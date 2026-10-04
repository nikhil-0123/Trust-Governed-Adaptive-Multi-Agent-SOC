import json
import os
import sqlite3
from typing import List, Dict, Any

from pydantic import BaseModel, ValidationError

from app.reasoning_models import Claim, VerificationResult
from app.reasoning_provider import LLMProvider, LLMProviderError
from app.evidence_validator import EvidenceValidator

class VerificationInput(BaseModel):
    """
    Strongly typed input bounding the data available to the VerificationAgent.
    """
    incident_id: str
    assessment_id: str
    claim: Claim
    evidence: List[Dict[str, Any]]
    authoritative_mitre_context: List[Dict[str, Any]]
    assessment_snapshot: Dict[str, Any]


class VerificationAgentParsingError(Exception):
    """Raised when the LLM output cannot be parsed as the required JSON structure."""
    pass


class VerificationAgentConfigurationError(Exception):
    """Raised for agent misconfigurations."""
    pass


class VerificationAgent:
    """
    Step 10D: Verification Agent.
    Independently evaluates candidate claims using only supplied persisted SOC evidence.
    Does NOT execute actions, modify databases, or perform synthesis.
    """
    def __init__(self, provider: LLMProvider, validator: EvidenceValidator, config: Dict[str, Any]):
        self.provider = provider
        self.validator = validator
        self.config = config

    def verify_claim(self, input_data: VerificationInput, conn: sqlite3.Connection) -> VerificationResult:
        # Pre-validation check 1: Incident scoping
        if input_data.claim.incident_id != input_data.incident_id:
            return self._build_deterministic_result(
                input_data.claim.claim_id,
                "UNVERIFIED",
                "CLAIM_INCIDENT_MISMATCH",
                []
            )

        # Pre-validation check 2: Deterministic Evidence validation
        val_res = self.validator.validate_claim(input_data.claim, input_data.incident_id, conn)
        if not val_res.valid:
            # If the deterministic validator rejects structural evidence references, 
            # do not even ask the LLM to verify. Safe downgrade.
            return self._build_deterministic_result(
                input_data.claim.claim_id,
                "INSUFFICIENT_EVIDENCE",
                f"Deterministic evidence validation failed: {', '.join(val_res.validation_errors)}",
                val_res.valid_evidence_ids
            )

        # Prompt resolution
        prompt_versions_map = self.config.get("prompt_versions", {})
        prompt_version = prompt_versions_map.get("verification", "verification_v1")
        
        safe_version = os.path.basename(prompt_version)
        prompt_path = os.path.join(os.path.dirname(__file__), "prompts", f"{safe_version}.md")
        if not os.path.exists(prompt_path):
            raise VerificationAgentConfigurationError(f"Configured prompt version '{safe_version}' not found at {prompt_path}.")
            
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
            raise VerificationAgentParsingError(f"Malformed JSON output from provider: {e}")

        if not isinstance(parsed, dict):
            raise VerificationAgentParsingError("Top-level JSON must be an object.")
            
        allowed_statuses = {"VERIFIED", "PARTIALLY_VERIFIED", "UNVERIFIED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE"}
        status = parsed.get("verification_status")
        
        if status not in allowed_statuses:
            raise VerificationAgentParsingError(f"Invalid verification_status: {status}")

        try:
            conf = float(parsed.get("confidence", -1.0))
            if not (0.0 <= conf <= 1.0):
                raise VerificationAgentParsingError("Confidence must be a float between 0.0 and 1.0.")
        except (ValueError, TypeError):
            raise VerificationAgentParsingError("Confidence must be a valid float.")

        supporting = parsed.get("supporting_evidence", [])
        contradictory = parsed.get("contradictory_evidence", [])
        
        if not isinstance(supporting, list) or not isinstance(contradictory, list):
            raise VerificationAgentParsingError("Evidence fields must be lists of strings.")

        # Post-validation checks: Ensure model didn't invent evidence IDs not present in supplied evidence
        supplied_ids = {ev.get("detection_event_id") for ev in input_data.evidence if "detection_event_id" in ev}
        # Include original claim validated IDs too
        supplied_ids.update(input_data.claim.supporting_evidence)

        invented = []
        for ev in supporting + contradictory:
            if not isinstance(ev, str):
                raise VerificationAgentParsingError("Evidence IDs must be strings.")
            if ev not in supplied_ids:
                invented.append(ev)
                
        if invented:
            # Downgrade to INSUFFICIENT_EVIDENCE deterministically due to hallucinated IDs
            return self._build_deterministic_result(
                input_data.claim.claim_id,
                "INSUFFICIENT_EVIDENCE",
                f"Model referenced unsupplied evidence IDs: {', '.join(invented)}",
                list(set(input_data.claim.supporting_evidence) & supplied_ids)
            )

        # Build valid final result using reasoning_models
        return VerificationResult(
            claim_id=input_data.claim.claim_id,
            verification_status=status,
            verification_reason=parsed.get("verification_reason", ""),
            supporting_evidence=supporting,
            contradictory_evidence=contradictory,
            confidence=conf,
            verifier_agent_id="verification-agent"
        )

    def _build_deterministic_result(self, claim_id: str, status: str, reason: str, supporting: List[str]) -> VerificationResult:
        # We must use typing.Literal types supported natively
        return VerificationResult(
            claim_id=claim_id,
            verification_status=status,
            verification_reason=reason,
            supporting_evidence=supporting,
            contradictory_evidence=[],
            confidence=0.0,
            verifier_agent_id="verification-agent"
        )
