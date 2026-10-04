import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class GovernanceDecision:
    def __init__(self, decision: str, reason: str, policy_version: str, config_version: str):
        self.decision = decision
        self.reason = reason
        self.policy_version = policy_version
        self.config_version = config_version

class GovernancePolicyEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policy_version = config.get("policy_version", "v1.0")
        self.config_version = config.get("config_version", "v1.0")
        self.trust_policy = config.get("trust_policy", {})
        self.risk_policy = config.get("risk_policy", {})
        self.severity_policy = config.get("severity_policy", {})
        self.verification_policy = config.get("verification_policy", {})
        self.allowed_actions = set(config.get("autonomous_action_allowlist", []))
        self.mitre_restrictions = config.get("mitre_restrictions", {})
        self.confidence_threshold = config.get("confidence_threshold", {})
        
        # Severity ordering for comparison
        self.severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        
    def evaluate(self, analysis_dict: Dict[str, Any], assessment_dict: Dict[str, Any], severity: str) -> GovernanceDecision:
        # Precedence 1: Invalid/missing required input
        if not analysis_dict or not assessment_dict or not severity:
            return GovernanceDecision("HOLD", "Missing required input data.", self.policy_version, self.config_version)
            
        assessment_status = assessment_dict.get("status")
        if assessment_status == "INSUFFICIENT_DATA":
            return GovernanceDecision("HOLD", "Step 9 assessment was INSUFFICIENT_DATA.", self.policy_version, self.config_version)
            
        if assessment_status == "FAILED" or analysis_dict.get("status") == "FAILED":
            return GovernanceDecision("HOLD", "Upstream state is FAILED.", self.policy_version, self.config_version)

        recommendations = analysis_dict.get("recommendations", [])
        if not recommendations:
            return GovernanceDecision("HOLD", "No recommendations provided in analysis.", self.policy_version, self.config_version)

        # For simplicity, we evaluate the first recommendation (or aggregate them).
        # We will aggregate by taking the most restrictive decision.
        # Order of restrictiveness: REJECT > HOLD > HUMAN_APPROVAL > AUTO_APPROVE
        overall_decision = "AUTO_APPROVE"
        overall_reason = "All recommendations satisfied auto-approve criteria."
        
        for rec in recommendations:
            dec, reason = self._evaluate_single_recommendation(rec, analysis_dict, assessment_dict, severity)
            
            # Precedence application across multiple recommendations
            if dec == "REJECT":
                return GovernanceDecision("REJECT", reason, self.policy_version, self.config_version)
            elif dec == "HOLD" and overall_decision not in ("REJECT",):
                overall_decision = "HOLD"
                overall_reason = reason
            elif dec == "HUMAN_APPROVAL" and overall_decision not in ("REJECT", "HOLD"):
                overall_decision = "HUMAN_APPROVAL"
                overall_reason = reason
                
        return GovernanceDecision(overall_decision, overall_reason, self.policy_version, self.config_version)

    def _evaluate_single_recommendation(self, rec: Dict[str, Any], analysis_dict: Dict[str, Any], assessment_dict: Dict[str, Any], severity: str) -> tuple[str, str]:
        rec_type = rec.get("type")
        
        # Precedence 6: Unknown action
        if not rec_type or rec_type not in self.allowed_actions:
            return "HOLD", f"Action type '{rec_type}' is unknown or not in allowlist."
            
        # Check supporting claims
        supporting_claim_ids = rec.get("supporting_claims", [])
        if not supporting_claim_ids:
            return "HOLD", "Recommendation has no supporting claims."
            
        # Collect verification results for these claims
        verifications = {v["claim_id"]: v for v in analysis_dict.get("verification_results", [])}
        
        worst_verification_rank = 5 # 5=VERIFIED, 4=PARTIALLY, 3=UNVERIFIED, 2=INSUFFICIENT, 1=CONTRADICTED
        verification_status_map = {
            "VERIFIED": 5,
            "PARTIALLY_VERIFIED": 4,
            "UNVERIFIED": 3,
            "INSUFFICIENT_EVIDENCE": 2,
            "CONTRADICTED": 1
        }
        
        lowest_status_name = "VERIFIED"
        
        for cid in supporting_claim_ids:
            v_res = verifications.get(cid)
            if not v_res:
                # Precedence 2: Missing evidence/verification
                return "HOLD", f"Supporting claim {cid} lacks a verification result."
            
            v_status = v_res.get("verification_status")
            if v_status not in verification_status_map:
                return "HOLD", f"Unknown verification status '{v_status}'."
                
            rank = verification_status_map[v_status]
            if rank < worst_verification_rank:
                worst_verification_rank = rank
                lowest_status_name = v_status
                
        # Precedence 3: CONTRADICTED
        if lowest_status_name == "CONTRADICTED":
            return "REJECT", "Recommendation is supported by CONTRADICTED claims."
            
        # Precedence 5: Global Trust/Risk rejection
        trust = assessment_dict.get("trust_score", 1.0)
        risk = assessment_dict.get("risk_score", 0.0)
        
        if trust < self.trust_policy.get("global_reject_max_trust_threshold", 0.0):
            return "REJECT", f"Trust score {trust} is below global reject threshold."
            
        if risk > self.risk_policy.get("global_reject_min_risk_threshold", 1.0):
            return "REJECT", f"Risk score {risk} is above global reject threshold."
            
        # Precedence 7, 8: UNVERIFIED, INSUFFICIENT_EVIDENCE
        if lowest_status_name in ("UNVERIFIED", "INSUFFICIENT_EVIDENCE"):
            return "HOLD", f"Recommendation supporting claims are {lowest_status_name}."
            
        # Precedence 11: MITRE restriction
        auth_mitre = analysis_dict.get("authoritative_mitre_context", [])
        for mitre_entry in auth_mitre:
            tactic = mitre_entry.get("tactic")
            restricted_actions = self.mitre_restrictions.get(tactic, [])
            if rec_type in restricted_actions:
                return "HUMAN_APPROVAL", f"Action {rec_type} is restricted for MITRE tactic {tactic}."
                
        # Precedence 9, 10, 12, 13: Capability downgrade evaluation
        # We start by assuming AUTO_APPROVE eligibility and downgrade if criteria fail.
        
        # 1. Verification downgrade
        if lowest_status_name == "PARTIALLY_VERIFIED":
            # Maximum capability is HUMAN_APPROVAL
            return "HUMAN_APPROVAL", "Supporting claims are only PARTIALLY_VERIFIED."
            
        # 2. Severity cap downgrade
        sev_policy = self.severity_policy.get(severity, "HUMAN_APPROVAL")
        if sev_policy == "HUMAN_APPROVAL":
            return "HUMAN_APPROVAL", f"Severity {severity} caps capability at HUMAN_APPROVAL."
        elif sev_policy in ("REJECT", "HOLD"):
            return sev_policy, f"Severity {severity} mandates {sev_policy}."
            
        # 3. Trust/Risk/Confidence thresholds
        min_trust = self.trust_policy.get("auto_approve_min_trust", 1.0)
        max_risk = self.risk_policy.get("auto_approve_max_risk", 0.0)
        min_conf = self.confidence_threshold.get("auto_approve_min_confidence", 1.0)
        
        overall_conf = analysis_dict.get("uncertainty", {}).get("overall_confidence", 1.0)
        
        if trust < min_trust:
            return "HUMAN_APPROVAL", f"Trust score {trust} does not meet AUTO_APPROVE minimum {min_trust}."
            
        if risk > max_risk:
            return "HUMAN_APPROVAL", f"Risk score {risk} exceeds AUTO_APPROVE maximum {max_risk}."
            
        if overall_conf < min_conf:
            return "HUMAN_APPROVAL", f"Overall confidence {overall_conf} does not meet AUTO_APPROVE minimum {min_conf}."
            
        # Precedence 12: Strict AUTO_APPROVE AND-gate passed
        return "AUTO_APPROVE", "All strict AUTO_APPROVE thresholds and policies passed."
