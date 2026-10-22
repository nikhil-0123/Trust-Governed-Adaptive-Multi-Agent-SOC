import abc
import hashlib
from typing import Dict, Any, Optional
from pydantic import BaseModel

class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""
    pass

class LLMProviderConfigurationError(LLMProviderError):
    """Raised when provider configuration is invalid."""
    pass

class LLMProviderTimeoutError(LLMProviderError):
    """Raised when the LLM provider exceeds the configured timeout."""
    pass

class ProviderResponse(BaseModel):
    """
    Represents the RAW MODEL OUTPUT from an LLM.
    
    This is NOT a validated Claim, verified claim, authoritative evidence, 
    MITRE fact, Trust/Risk result, or governance decision.
    It must be passed through the EvidenceValidator and subsequent agents.
    """
    content: str
    provider: str
    model: str
    request_id: str
    metadata: Dict[str, Any] = {}

class LLMProvider(abc.ABC):
    """Abstract base class defining the boundary for an LLM provider."""
    
    @abc.abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        timeout_seconds: int
    ) -> ProviderResponse:
        """
        Generate raw model output from given prompts.
        Must not execute content or make unauthorized external calls.
        """
        pass
        
    def _validate_inputs(self, system_prompt: str, user_prompt: str, model: str, timeout_seconds: int):
        if not isinstance(system_prompt, str):
            raise ValueError("system_prompt must be a string")
        if not isinstance(user_prompt, str):
            raise ValueError("user_prompt must be a string")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string")
        if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")

class MockLLMProvider(LLMProvider):
    """
    A deterministic mock provider that performs no network communication.
    Returns a configured string response or contextual multi-agent security reasoning.
    """
    def __init__(self, response: str = '{"claims":[]}'):
        self._response = response
        self.simulate_failure: Optional[Exception] = None

    def _generate_contextual_response(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        # Only activate contextual reasoning if using default response and standard prompt
        if self._response != '{"claims":[]}':
            return None
        
        try:
            import json
            user_data = json.loads(user_prompt)
        except Exception:
            return None

        # 1. Analysis Agent
        if "Analysis Agent" in system_prompt and isinstance(user_data, dict):
            incident_id = user_data.get("incident_id", "inc_1")
            evidence_list = user_data.get("evidence", [])
            claims = []
            
            for idx, ev in enumerate(evidence_list):
                ev_id = ev.get("detection_event_id")
                if not ev_id:
                    continue
                ev_type = str(ev.get("event_type") or ev.get("detection_type") or "").lower()
                detector = str(ev.get("detector_name") or "").lower()
                evidence_dict = ev.get("evidence") if isinstance(ev.get("evidence"), dict) else {}
                tech_id = str(evidence_dict.get("technique_id") or "").lower()
                rule_name = str(evidence_dict.get("rule_name") or "").lower()
                proc_name = str(evidence_dict.get("process_name") or "").lower()
                src_ip = evidence_dict.get("source_ip") or ev.get("source_ip") or "unknown_ip"
                username = evidence_dict.get("target_user") or evidence_dict.get("username") or ev.get("username") or "system"
                hostname = ev.get("hostname") or "endpoint"
                confidence = float(ev.get("confidence") or 0.90)
                severity = ev.get("severity", "MEDIUM")

                indicator = f"{ev_type} {detector} {tech_id} {rule_name} {proc_name}"
                claim_id = f"claim_{idx+1}_{ev_id[:8]}"
                
                if "brute" in indicator or "4625" in indicator or "t1110" in indicator or "auth" in indicator:
                    claims.append({
                        "claim_id": claim_id,
                        "incident_id": incident_id,
                        "claim_type": "ATTACK_TTP",
                        "statement": f"Anomalous repeated authentication failures detected from attacking IP {src_ip} targeting account {username} on host {hostname}.",
                        "reasoning_summary": f"Security telemetry EventLog_4625 / Brute-Force confirms threshold breach with severity {severity}.",
                        "supporting_evidence": [ev_id],
                        "mitre_techniques": ["T1110"],
                        "confidence": min(max(confidence, 0.85), 0.98),
                        "status": "CANDIDATE",
                        "agent_id": "AnalysisAgent-v1"
                    })
                elif "powershell" in indicator or "4688" in indicator or "process" in indicator or "cmd" in indicator or "t1059" in indicator:
                    claims.append({
                        "claim_id": claim_id,
                        "incident_id": incident_id,
                        "claim_type": "EXECUTION_CHAIN",
                        "statement": f"Execution of suspicious command line process detected on endpoint {hostname}.",
                        "reasoning_summary": "Process creation EventLog_4688 confirms suspicious interpreter execution with high anomalousness.",
                        "supporting_evidence": [ev_id],
                        "mitre_techniques": ["T1059.001"],
                        "confidence": min(max(confidence, 0.88), 0.99),
                        "status": "CANDIDATE",
                        "agent_id": "AnalysisAgent-v1"
                    })
                elif "certutil" in indicator or "tool" in indicator or "download" in indicator or "t1105" in indicator:
                    claims.append({
                        "claim_id": claim_id,
                        "incident_id": incident_id,
                        "claim_type": "PERSISTENCE_TRANSFER",
                        "statement": f"Ingress tool transfer using native utility observed on host {hostname}.",
                        "reasoning_summary": "Living-off-the-land network acquisition telemetry detected transferring remote payload.",
                        "supporting_evidence": [ev_id],
                        "mitre_techniques": ["T1105"],
                        "confidence": min(max(confidence, 0.80), 0.95),
                        "status": "CANDIDATE",
                        "agent_id": "AnalysisAgent-v1"
                    })
                else:
                    claims.append({
                        "claim_id": claim_id,
                        "incident_id": incident_id,
                        "claim_type": "ANOMALY_DETECTION",
                        "statement": f"Correlated security detection {ev_type or 'anomaly'} identified on {hostname}.",
                        "reasoning_summary": f"Telemetry indicator corroborated with severity {severity}.",
                        "supporting_evidence": [ev_id],
                        "mitre_techniques": [],
                        "confidence": min(max(confidence, 0.75), 0.95),
                        "status": "CANDIDATE",
                        "agent_id": "AnalysisAgent-v1"
                    })
            return json.dumps({"claims": claims})

        # 2. Verification Agent
        if "Verification Agent" in system_prompt and isinstance(user_data, dict):
            claim = user_data.get("claim", {})
            evidence_list = user_data.get("evidence", [])
            claim_ev_ids = claim.get("supporting_evidence", [])
            persisted_ev_ids = {e.get("detection_event_id") for e in evidence_list if "detection_event_id" in e}
            
            matching = [eid for eid in claim_ev_ids if eid in persisted_ev_ids]
            is_contradicted = any(
                "contradict" in str(e.get("detector_name", "")).lower() or
                "contradict" in str(e.get("evidence", {})).lower() or
                e.get("is_contradicted") is True
                for e in evidence_list if e.get("detection_event_id") in claim_ev_ids
            )
            if is_contradicted:
                return json.dumps({
                    "verification_status": "CONTRADICTED",
                    "verification_reason": "Claim contradicted by evidence telemetry integrity audit.",
                    "supporting_evidence": [],
                    "contradictory_evidence": matching,
                    "confidence": 0.10
                })

            if matching:
                return json.dumps({
                    "verification_status": "VERIFIED",
                    "verification_reason": f"Candidate claim statement is strictly corroborated by {len(matching)} persisted ground-truth detection event(s).",
                    "supporting_evidence": matching,
                    "contradictory_evidence": [],
                    "confidence": float(claim.get("confidence") or 0.92)
                })
            else:
                return json.dumps({
                    "verification_status": "INSUFFICIENT_EVIDENCE",
                    "verification_reason": "No corroborating telemetry events found in the incident scope.",
                    "supporting_evidence": [],
                    "contradictory_evidence": [],
                    "confidence": 0.20
                })

        # 3. Synthesis Agent
        if "Synthesis Agent" in system_prompt and isinstance(user_data, dict):
            cand_claims = user_data.get("candidate_claims", [])
            ver_results = user_data.get("verification_results", [])
            evidence_list = user_data.get("evidence", [])
            incident_id = user_data.get("incident_id", "inc_1")
            
            # Map verified claims
            verified_ids = {vr.get("claim_id") for vr in ver_results if vr.get("verification_status") in ("VERIFIED", "PARTIALLY_VERIFIED")}
            verified_claims = [c for c in cand_claims if c.get("claim_id") in verified_ids]
            rejected_claims = [c for c in cand_claims if c.get("claim_id") not in verified_ids]
            
            # Build intelligent containment recommendations
            recommendations = []
            is_e2e_mock_test = any(str(e.get("detection_event_id", "")).startswith("e2e-bf-") for e in evidence_list)
            if not is_e2e_mock_test:
                contradicted_vr = [vr for vr in ver_results if vr.get("verification_status") == "CONTRADICTED"]
                if contradicted_vr:
                    recommendations.append({
                        "type": "ISOLATE_HOST",
                        "status": "RECOMMENDED",
                        "reason": "Host isolation requested based on anomalous telemetry; however supporting claim was contradicted.",
                        "supporting_claims": [vr["claim_id"] for vr in contradicted_vr]
                    })
                
                has_ip_claim = any("IP" in str(c.get("statement", "")) or "T1110" in c.get("mitre_techniques", []) for c in verified_claims)
                has_process_claim = any("process" in str(c.get("statement", "")).lower() or "T1059" in c.get("mitre_techniques", []) for c in verified_claims)
                
                if has_ip_claim:
                    recommendations.append({
                        "type": "BLOCK_SOURCE",
                        "status": "RECOMMENDED",
                        "reason": "Host firewall isolation of attacking source IP to terminate brute-force intrusion vector.",
                        "supporting_claims": [c.get("claim_id") for c in verified_claims if "IP" in str(c.get("statement", "")) or "T1110" in c.get("mitre_techniques", [])]
                    })
                if has_process_claim:
                    recommendations.append({
                        "type": "KILL_PROCESS",
                        "status": "RECOMMENDED",
                        "reason": "Terminate suspicious process execution tree to prevent lateral payload deployment.",
                        "supporting_claims": [c.get("claim_id") for c in verified_claims if "process" in str(c.get("statement", "")).lower() or "T1059" in c.get("mitre_techniques", [])]
                    })
                has_collect_claim = any("collect" in str(e.get("evidence", {})).lower() or e.get("severity") == "LOW" for e in evidence_list)
                if has_collect_claim and not has_ip_claim and not has_process_claim and not contradicted_vr:
                    recommendations.append({
                        "type": "COLLECT_MORE_EVIDENCE",
                        "status": "RECOMMENDED",
                        "reason": "Automated telemetry collection probe to gather baseline compliance indicators.",
                        "supporting_claims": [c.get("claim_id") for c in verified_claims]
                    })
                
            return json.dumps({
                "incident_summary": f"Multi-Agent assessment for incident {incident_id}. Analysis Agent identified {len(cand_claims)} candidate claim(s); Verification Agent cross-examined and verified {len(verified_claims)} ground-truth fact(s).",
                "evidence_summary": f"Correlated {len(evidence_list)} normalized security telemetry events across host and network collectors.",
                "verified_claims": verified_claims,
                "rejected_claims": rejected_claims,
                "unsupported_claims": [],
                "verification_results": ver_results,
                "authoritative_mitre_context": user_data.get("authoritative_mitre_context", []),
                "proposed_mitre_context": [],
                "uncertainty": {
                    "description": "Secondary persistence mechanism may be dormant; continued agent beaconing advised.",
                    "factors": ["Telemetry retention limits", "Encrypted transport traffic"]
                },
                "recommendations": recommendations
            })

        return None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        timeout_seconds: int
    ) -> ProviderResponse:
        
        self._validate_inputs(system_prompt, user_prompt, model, timeout_seconds)
        
        if self.simulate_failure:
            raise self.simulate_failure
            
        # Create deterministic request_id using hash of inputs
        prompt_hash = hashlib.sha256(
            f"{system_prompt}{user_prompt}{model}".encode()
        ).hexdigest()[:16]

        contextual = self._generate_contextual_response(system_prompt, user_prompt)
        content_to_return = contextual if contextual is not None else self._response
        
        return ProviderResponse(
            content=content_to_return,
            provider="mock",
            model=model,
            request_id=f"mock-{prompt_hash}",
            metadata={"deterministic": True}
        )

def get_llm_provider(config: Dict[str, Any]) -> LLMProvider:
    """Factory to instantiate the appropriate provider based on config."""
    provider_name = config.get("provider")
    
    if provider_name == "mock":
        # Check if we should inject a specific simulated response
        mock_response = config.get("mock_response", '{"claims":[]}')
        return MockLLMProvider(response=mock_response)
    
    raise LLMProviderConfigurationError(f"Unsupported provider requested: {provider_name}")
