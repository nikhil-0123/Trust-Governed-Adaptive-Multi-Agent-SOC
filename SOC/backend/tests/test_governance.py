import unittest
from app.governance import GovernancePolicyEngine

class TestGovernanceEngine(unittest.TestCase):
    def setUp(self):
        self.config = {
            "environment": "DEVELOPMENT / EXPERIMENTAL",
            "policy_version": "v1.0",
            "config_version": "v1.0",
            "trust_policy": {
                "global_reject_max_trust_threshold": 0.2,
                "auto_approve_min_trust": 0.8
            },
            "risk_policy": {
                "global_reject_min_risk_threshold": 0.9,
                "auto_approve_max_risk": 0.4
            },
            "severity_policy": {
                "LOW": "AUTO_APPROVE",
                "MEDIUM": "AUTO_APPROVE",
                "HIGH": "HUMAN_APPROVAL",
                "CRITICAL": "HUMAN_APPROVAL"
            },
            "verification_policy": {
                "VERIFIED": "AUTO_APPROVE",
                "PARTIALLY_VERIFIED": "HUMAN_APPROVAL",
                "UNVERIFIED": "HOLD",
                "INSUFFICIENT_EVIDENCE": "HOLD",
                "CONTRADICTED": "REJECT"
            },
            "autonomous_action_allowlist": ["ISOLATE_HOST"],
            "mitre_restrictions": {
                "Exfiltration": ["ISOLATE_HOST"]
            },
            "confidence_threshold": {
                "auto_approve_min_confidence": 0.8
            }
        }
        self.engine = GovernancePolicyEngine(self.config)
        
        self.base_analysis = {
            "status": "COMPLETED",
            "recommendations": [
                {
                    "type": "ISOLATE_HOST",
                    "reason": "Test",
                    "supporting_claims": ["c1"]
                }
            ],
            "verification_results": [
                {
                    "claim_id": "c1",
                    "verification_status": "VERIFIED"
                }
            ],
            "authoritative_mitre_context": [],
            "uncertainty": {"overall_confidence": 0.9}
        }
        self.base_assessment = {
            "status": "COMPLETED",
            "trust_score": 0.9,
            "risk_score": 0.1
        }
        self.base_severity = "LOW"

    # A, B, F, K: Perfect conditions
    def test_auto_approve_perfect(self):
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "AUTO_APPROVE")
        
    # C: Low Trust / High Risk global boundary
    def test_global_reject_trust(self):
        self.base_assessment["trust_score"] = 0.1
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "REJECT")
        
    def test_global_reject_risk(self):
        self.base_assessment["risk_score"] = 0.95
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "REJECT")
        
    # D: High Trust, High Risk (Downgrade to HUMAN_APPROVAL)
    def test_high_risk_downgrade(self):
        self.base_assessment["risk_score"] = 0.5 # > auto_approve_max_risk
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HUMAN_APPROVAL")
        
    # G, H, I, J: Verification states
    def test_partially_verified_downgrade(self):
        self.base_analysis["verification_results"][0]["verification_status"] = "PARTIALLY_VERIFIED"
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HUMAN_APPROVAL")
        
    def test_unverified_hold(self):
        self.base_analysis["verification_results"][0]["verification_status"] = "UNVERIFIED"
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HOLD")
        
    def test_contradicted_reject(self):
        self.base_analysis["verification_results"][0]["verification_status"] = "CONTRADICTED"
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "REJECT")
        
    # L, M, N: Severity caps
    def test_severity_cap(self):
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, "CRITICAL")
        self.assertEqual(dec.decision, "HUMAN_APPROVAL")
        
    # O, P, Q: Upstream failure / Missing
    def test_upstream_insufficient_data(self):
        self.base_assessment["status"] = "INSUFFICIENT_DATA"
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HOLD")
        
    def test_upstream_failed(self):
        self.base_analysis["status"] = "FAILED"
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HOLD")
        
    # R, S: Unknown/Invalid Recommendation
    def test_unknown_recommendation(self):
        self.base_analysis["recommendations"][0]["type"] = "TERMINATE_PROCESS_MAGICALLY"
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HOLD")
        
    def test_missing_claims_reference(self):
        self.base_analysis["recommendations"][0]["supporting_claims"] = []
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HOLD")
        
    def test_missing_verification_result(self):
        self.base_analysis["verification_results"] = []
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HOLD")
        
    # T: MITRE restrictions
    def test_mitre_restriction(self):
        self.base_analysis["authoritative_mitre_context"] = [{"tactic": "Exfiltration"}]
        dec = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec.decision, "HUMAN_APPROVAL")
        
    # Determinism
    def test_repeated_deterministic(self):
        dec1 = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        dec2 = self.engine.evaluate(self.base_analysis, self.base_assessment, self.base_severity)
        self.assertEqual(dec1.decision, dec2.decision)
