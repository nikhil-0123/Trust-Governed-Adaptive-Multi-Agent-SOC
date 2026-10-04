import unittest
import json
import os
import tempfile
import sqlite3
from datetime import datetime, timezone

from app.database import init_db
from app.reasoning_provider import MockLLMProvider, LLMProviderTimeoutError
from app.reasoning.synthesis import (
    SynthesisAgent, SynthesisInput, SynthesisAgentParsingError, SynthesisAgentConfigurationError
)
from app.reasoning_models import Claim, VerificationResult, Recommendation, FinalAnalysis

class TestSynthesisAgent(unittest.TestCase):
    def setUp(self):
        self.config = {
            "provider": "mock",
            "model": "mock-model",
            "timeout_seconds": 30,
            "prompt_versions": {
                "synthesis": "synthesis_v1"
            }
        }
        self.provider = MockLLMProvider()
        self.agent = SynthesisAgent(self.provider, self.config)

    def _build_input(self):
        claim_1 = Claim(claim_id="c1", incident_id="inc_1", claim_type="T", statement="c1 stmt", reasoning_summary="R", supporting_evidence=["ev_1"], mitre_techniques=[], confidence=0.9, agent_id="A")
        claim_2 = Claim(claim_id="c2", incident_id="inc_1", claim_type="T", statement="c2 stmt", reasoning_summary="R", supporting_evidence=["ev_2"], mitre_techniques=[], confidence=0.9, agent_id="A")
        claim_3 = Claim(claim_id="c3", incident_id="inc_1", claim_type="T", statement="c3 stmt", reasoning_summary="R", supporting_evidence=["ev_3"], mitre_techniques=[], confidence=0.9, agent_id="A")
        
        vr_1 = VerificationResult(claim_id="c1", verification_status="VERIFIED", verification_reason="V", supporting_evidence=["ev_1"], contradictory_evidence=[], confidence=0.9, verifier_agent_id="V")
        vr_2 = VerificationResult(claim_id="c2", verification_status="CONTRADICTED", verification_reason="V", supporting_evidence=[], contradictory_evidence=["ev_2"], confidence=0.9, verifier_agent_id="V")
        vr_3 = VerificationResult(claim_id="c3", verification_status="INSUFFICIENT_EVIDENCE", verification_reason="V", supporting_evidence=[], contradictory_evidence=[], confidence=0.9, verifier_agent_id="V")
        
        return SynthesisInput(
            analysis_id="an_1",
            incident_id="inc_1",
            assessment_id="ass_1",
            incident_context={"status": "open"},
            evidence=[{"detection_event_id": "ev_1"}, {"detection_event_id": "ev_2"}, {"detection_event_id": "ev_3"}],
            candidate_claims=[claim_1, claim_2, claim_3],
            rejected_claims=[],
            verification_results=[vr_1, vr_2, vr_3],
            authoritative_mitre_context=[{"technique_id": "T1110"}],
            proposed_mitre_context=[],
            assessment_snapshot={"trust_score": 0.72, "risk_score": 0.81, "status": "COMPLETED"}
        )

    def _set_mock_response(self, content: str):
        self.provider._response = content

    def test_valid_final_analysis_generation(self):
        inp = self._build_input()
        self._set_mock_response(json.dumps({
            "incident_summary": "Test incident summary",
            "evidence_summary": "Test evidence summary",
            "verified_claims": [inp.candidate_claims[0].model_dump()],
            "rejected_claims": [],
            "unsupported_claims": [inp.candidate_claims[1].model_dump()],
            "verification_results": [vr.model_dump() for vr in inp.verification_results],
            "authoritative_mitre_context": [{"technique_id": "T1110"}],
            "proposed_mitre_context": [{"technique_id": "T9999"}],
            "uncertainty": {"description": "Unknown", "factors": ["F1"]},
            "recommendations": [{"type": "ACTION", "status": "RECOMMENDED", "reason": "R", "supporting_claims": ["c1"]}]
        }))
        res = self.agent.synthesize(inp)
        self.assertIsInstance(res, FinalAnalysis)
        self.assertEqual(res.incident_summary, "Test incident summary")
        self.assertEqual(res.evidence_summary, "Test evidence summary")
        self.assertEqual(len(res.verified_claims), 1)
        self.assertEqual(len(res.recommendations), 1)
        self.assertEqual(res.recommendations[0].status, "RECOMMENDED")

    def test_semantic_test_a_verification_state_preservation(self):
        # Semantic Test A: Verification states are explicitly preserved from the input.
        inp = self._build_input()
        # Even if the model tries to alter the verification results, the agent forces the authoritative results
        self._set_mock_response(json.dumps({
            "verification_results": [{"claim_id": "c2", "verification_status": "VERIFIED"}], # Model attempts override
            "incident_summary": "summary"
        }))
        res = self.agent.synthesize(inp)
        
        # Check that the three distinct states were preserved exactly as they came in
        vr_dict = {vr.claim_id: vr.verification_status for vr in res.verification_results}
        self.assertEqual(vr_dict["c1"], "VERIFIED")
        self.assertEqual(vr_dict["c2"], "CONTRADICTED")
        self.assertEqual(vr_dict["c3"], "INSUFFICIENT_EVIDENCE")

    def test_semantic_test_b_trust_risk_preservation(self):
        # Semantic Test B: Input assessment trust/risk scores must remain unchanged.
        inp = self._build_input()
        self._set_mock_response(json.dumps({
            "assessment_snapshot": {"trust_score": 0.99, "risk_score": 0.01}, # Model attempts override
            "incident_summary": "summary"
        }))
        res = self.agent.synthesize(inp)
        self.assertEqual(res.assessment_snapshot["trust_score"], 0.72)
        self.assertEqual(res.assessment_snapshot["risk_score"], 0.81)

    def test_semantic_test_c_mitre_authority(self):
        # Semantic Test C: Model cannot promote proposed MITRE to authoritative.
        inp = self._build_input()
        self._set_mock_response(json.dumps({
            "authoritative_mitre_context": [{"technique_id": "T1110"}, {"technique_id": "T9999"}],
            "proposed_mitre_context": [],
            "incident_summary": "summary"
        }))
        res = self.agent.synthesize(inp)
        self.assertEqual(len(res.authoritative_mitre_context), 1)
        self.assertEqual(res.authoritative_mitre_context[0]["technique_id"], "T1110")

    def test_semantic_test_d_invented_evidence(self):
        # Semantic Test D: Model returns invented evidence 'event-999'. Must be rejected.
        inp = self._build_input()
        claim_dump = inp.candidate_claims[0].model_dump()
        claim_dump["supporting_evidence"] = ["ev_1", "event-999"] # Invented ID
        
        self._set_mock_response(json.dumps({
            "verified_claims": [claim_dump],
            "incident_summary": "summary"
        }))
        
        with self.assertRaises(SynthesisAgentParsingError) as context:
            self.agent.synthesize(inp)
        self.assertIn("event-999", str(context.exception))

    def test_semantic_test_e_uncertainty_preservation(self):
        # Semantic Test E: Model explicitly outputs uncertainty.
        inp = self._build_input()
        self._set_mock_response(json.dumps({
            "incident_summary": "Unknown attacker identity",
            "uncertainty": {"description": "Attacker identity is unknown", "factors": ["Only auth failures seen"]},
        }))
        res = self.agent.synthesize(inp)
        self.assertEqual(res.uncertainty["description"], "Attacker identity is unknown")
        self.assertEqual(res.incident_summary, "Unknown attacker identity")

    def test_invented_claim_ids_rejected(self):
        inp = self._build_input()
        claim_dump = inp.candidate_claims[0].model_dump()
        claim_dump["claim_id"] = "c999" # Invented Claim ID
        
        self._set_mock_response(json.dumps({
            "verified_claims": [claim_dump]
        }))
        
        with self.assertRaises(SynthesisAgentParsingError) as context:
            self.agent.synthesize(inp)
        self.assertIn("c999", str(context.exception))

    def test_invalid_recommendation_status_rejected(self):
        # Recommendation execution safety
        inp = self._build_input()
        self._set_mock_response(json.dumps({
            "recommendations": [{"type": "ACTION", "status": "EXECUTED", "reason": "R", "supporting_claims": ["c1"]}]
        }))
        
        with self.assertRaises(SynthesisAgentParsingError) as context:
            self.agent.synthesize(inp)
        self.assertIn("EXECUTED", str(context.exception))

    def test_malformed_json_rejected(self):
        inp = self._build_input()
        self._set_mock_response("bad json")
        with self.assertRaises(SynthesisAgentParsingError):
            self.agent.synthesize(inp)

    def test_root_array_rejected(self):
        inp = self._build_input()
        self._set_mock_response("[]")
        with self.assertRaises(SynthesisAgentParsingError):
            self.agent.synthesize(inp)

    def test_provider_failure(self):
        inp = self._build_input()
        self.provider.simulate_failure = LLMProviderTimeoutError("Timeout")
        with self.assertRaises(LLMProviderTimeoutError):
            self.agent.synthesize(inp)

    def test_deterministic_and_data_treatment(self):
        # Malicious strings treated as data
        malicious = "drop table incidents; eval(1)"
        inp = self._build_input()
        self._set_mock_response(json.dumps({
            "incident_summary": malicious,
            "evidence_summary": malicious
        }))
        res = self.agent.synthesize(inp)
        self.assertEqual(res.incident_summary, malicious)
        self.assertEqual(res.evidence_summary, malicious)
