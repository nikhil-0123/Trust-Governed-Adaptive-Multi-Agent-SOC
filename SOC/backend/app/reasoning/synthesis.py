import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, ValidationError

from app.reasoning_models import Claim, VerificationResult, Recommendation, FinalAnalysis
from app.reasoning_provider import LLMProvider, LLMProviderError


class SynthesisInput(BaseModel):
    """
    Strongly typed input bounding the data available to the SynthesisAgent.
    """
    analysis_id: str
    incident_id: str
    assessment_id: str
    incident_context: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    candidate_claims: List[Claim]
    rejected_claims: List[Claim]
    verification_results: List[VerificationResult]
    authoritative_mitre_context: List[Dict[str, Any]]
    proposed_mitre_context: List[Dict[str, Any]]
    assessment_snapshot: Dict[str, Any]


class SynthesisAgentParsingError(Exception):
    """Raised when the LLM output cannot be parsed as the required JSON structure."""
    pass


class SynthesisAgentConfigurationError(Exception):
    """Raised for agent misconfigurations."""
    pass


class SynthesisAgent:
    """
    Step 10E: Synthesis Agent.
    Combines verified facts and explicit uncertainties into the FinalAnalysis.
    Does NOT execute recommendations, alter verification states, or perform database operations.
    """
    def __init__(self, provider: LLMProvider, config: Dict[str, Any]):
        self.provider = provider
        self.config = config

    def synthesize(self, input_data: SynthesisInput) -> FinalAnalysis:
        prompt_versions_map = self.config.get("prompt_versions", {})
        prompt_version = prompt_versions_map.get("synthesis", "synthesis_v1")
        
        safe_version = os.path.basename(prompt_version)
        prompt_path = os.path.join(os.path.dirname(__file__), "prompts", f"{safe_version}.md")
        if not os.path.exists(prompt_path):
            raise SynthesisAgentConfigurationError(f"Configured prompt version '{safe_version}' not found at {prompt_path}.")
            
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
            # Wrap or propagate provider error
            raise e

        # JSON Parsing
        try:
            parsed = json.loads(response.content)
        except json.JSONDecodeError as e:
            raise SynthesisAgentParsingError(f"Malformed JSON output from provider: {e}")

        if not isinstance(parsed, dict):
            raise SynthesisAgentParsingError("Top-level JSON must be an object.")

        # Re-enforce input constraints
        # 1. Verification results are immutable
        # 2. Authoritative MITRE is immutable
        # 3. Assessment snapshot is immutable
        # 4. Do not invent evidence or claim IDs
        
        allowed_evidence_ids = {ev.get("detection_event_id") for ev in input_data.evidence if "detection_event_id" in ev}
        allowed_claim_ids = {c.claim_id for c in input_data.candidate_claims} | {c.claim_id for c in input_data.rejected_claims}
        
        # We enforce exactly the authoritative snapshot and MITRE context, regardless of LLM output
        final_snapshot = input_data.assessment_snapshot
        final_auth_mitre = input_data.authoritative_mitre_context
        final_verification = input_data.verification_results
        
        # Validations for Claims
        def parse_claims(raw_list):
            if not isinstance(raw_list, list):
                return []
            claims = []
            for item in raw_list:
                try:
                    c = Claim.model_validate(item)
                    # Check invented evidence
                    for ev in c.supporting_evidence:
                        if ev not in allowed_evidence_ids:
                            raise SynthesisAgentParsingError(f"Model invented evidence ID: {ev}")
                    claims.append(c)
                except ValidationError:
                    pass
            return claims

        verified_claims = parse_claims(parsed.get("verified_claims", []))
        rejected_claims = parse_claims(parsed.get("rejected_claims", []))
        unsupported_claims = parse_claims(parsed.get("unsupported_claims", []))

        # Check invented claim IDs in claims themselves
        all_parsed_claims = verified_claims + rejected_claims + unsupported_claims
        for c in all_parsed_claims:
            if c.claim_id not in allowed_claim_ids:
                raise SynthesisAgentParsingError(f"Model invented claim ID: {c.claim_id}")

        # Check recommendations
        recommendations = []
        raw_recs = parsed.get("recommendations", [])
        if isinstance(raw_recs, list):
            for raw_rec in raw_recs:
                try:
                    r = Recommendation.model_validate(raw_rec)
                    # Force recommendation to RECOMMENDED status
                    if r.status != "RECOMMENDED":
                        raise SynthesisAgentParsingError(f"Model attempted to change recommendation status to {r.status}")
                    
                    for c_id in r.supporting_claims:
                        if c_id not in allowed_claim_ids:
                            raise SynthesisAgentParsingError(f"Model invented claim ID in recommendation: {c_id}")
                    recommendations.append(r)
                except ValidationError:
                    pass

        # Uncertainty handling
        uncertainty = parsed.get("uncertainty", {})
        if not isinstance(uncertainty, dict):
            uncertainty = {"description": "Format error", "factors": []}

        # Build final analysis
        now_str = datetime.now(timezone.utc).isoformat()
        
        return FinalAnalysis(
            analysis_id=input_data.analysis_id,
            incident_id=input_data.incident_id,
            assessment_id=input_data.assessment_id,
            assessment_snapshot=final_snapshot,
            incident_summary=str(parsed.get("incident_summary", "")),
            evidence_summary=str(parsed.get("evidence_summary", "")),
            verified_claims=verified_claims,
            rejected_claims=rejected_claims,
            unsupported_claims=unsupported_claims,
            verification_results=final_verification,
            authoritative_mitre_context=final_auth_mitre,
            proposed_mitre_context=parsed.get("proposed_mitre_context", []),
            uncertainty=uncertainty,
            recommendations=recommendations,
            model_provenance=f"{response.provider}/{response.model}",
            prompt_versions={"synthesis": prompt_version},
            created_at=now_str
        )
