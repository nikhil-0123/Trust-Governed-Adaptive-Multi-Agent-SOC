import unittest
import sqlite3
import os
import tempfile
from datetime import datetime, timezone

from app.database import init_db
from app.reasoning_models import Claim
from app.evidence_validator import EvidenceValidator, ValidationResult

class TestEvidenceValidator(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.environ["SOC_DB_PATH"] = self.db_path
        
        # Override module variable for this test
        import app.database
        app.database.DB_PATH = self.db_path
        init_db()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.row_factory = sqlite3.Row
        
        self.validator = EvidenceValidator()
        self._setup_test_data()

    def tearDown(self):
        self.conn.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def _setup_test_data(self):
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          ("inc_1", now, now, now, now, "HIGH", "ACTIVE"))
        self.conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          ("inc_2", now, now, now, now, "LOW", "ACTIVE"))
        
        self.conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("ev_1", "{}"))
        self.conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("ev_2", "{}"))
        self.conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("ev_3", "{}"))
        
        self.conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc_1", "ev_1"))
        self.conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc_1", "ev_2"))
        self.conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc_2", "ev_3"))
        
        self.conn.commit()

    def _create_claim(self, evidence, incident_id="inc_1", claim_id="c1", claim_type="T", statement="S", confidence=0.9):
        # We manually instantiate ignoring pydantic initial checks using construct for bad data if needed, 
        # or use normal init when possible.
        return Claim(
            claim_id=claim_id, incident_id=incident_id, claim_type=claim_type,
            statement=statement, reasoning_summary="R", supporting_evidence=evidence,
            mitre_techniques=[], confidence=confidence, agent_id="A"
        )
        
    def test_valid_single_evidence(self):
        claim = self._create_claim(["ev_1"])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertTrue(res.valid)
        self.assertEqual(res.status, "VALID")
        self.assertEqual(res.valid_evidence_ids, ["ev_1"])

    def test_valid_multiple_evidence(self):
        claim = self._create_claim(["ev_1", "ev_2"])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertTrue(res.valid)
        self.assertEqual(res.valid_evidence_ids, ["ev_1", "ev_2"])

    def test_nonexistent_evidence(self):
        claim = self._create_claim(["ev_99"])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertFalse(res.valid)
        self.assertEqual(res.status, "UNSUPPORTED")
        self.assertIn("EVIDENCE_NOT_FOUND", res.validation_errors)

    def test_evidence_outside_incident(self):
        claim = self._create_claim(["ev_3"])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertFalse(res.valid)
        self.assertEqual(res.status, "UNSUPPORTED")
        self.assertIn("EVIDENCE_OUTSIDE_INCIDENT", res.validation_errors)

    def test_mixed_validity_reports_all_invalid(self):
        claim = self._create_claim(["ev_1", "ev_99", "ev_3"])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertFalse(res.valid)
        self.assertEqual(res.valid_evidence_ids, ["ev_1"])
        self.assertEqual(set(res.invalid_evidence_ids), {"ev_99", "ev_3"})
        self.assertIn("EVIDENCE_NOT_FOUND", res.validation_errors)
        self.assertIn("EVIDENCE_OUTSIDE_INCIDENT", res.validation_errors)

    def test_duplicate_evidence_normalized(self):
        claim = self._create_claim(["ev_1", "ev_1", "ev_2", "ev_2"])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertTrue(res.valid)
        # Order should be preserved and duplicates removed
        self.assertEqual(res.valid_evidence_ids, ["ev_1", "ev_2"])

    def test_missing_required_evidence(self):
        claim = self._create_claim([])
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertFalse(res.valid)
        self.assertIn("EMPTY_REQUIRED_EVIDENCE", res.validation_errors)

    def test_nonexistent_incident(self):
        claim = self._create_claim(["ev_1"], incident_id="inc_99")
        res = self.validator.validate_claim(claim, "inc_99", self.conn)
        self.assertFalse(res.valid)
        self.assertIn("INCIDENT_NOT_FOUND", res.validation_errors)

    def test_mismatched_incident(self):
        claim = self._create_claim(["ev_1"], incident_id="inc_1")
        # Passing wrong incident_id to validator vs claim
        res = self.validator.validate_claim(claim, "inc_2", self.conn)
        self.assertFalse(res.valid)
        self.assertIn("CLAIM_INCIDENT_MISMATCH", res.validation_errors)

    def test_malformed_evidence_ids(self):
        # Bypass pydantic type checking to test the validator's resilience
        claim = Claim.model_construct(
            claim_id="c1", incident_id="inc_1", claim_type="T", statement="S",
            reasoning_summary="R", supporting_evidence=[None, "", "  ", 123, {}, []],
            mitre_techniques=[], confidence=0.9, agent_id="A"
        )
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertFalse(res.valid)
        self.assertIn("INVALID_EVIDENCE_ID_FORMAT", res.validation_errors)
        self.assertEqual(len(res.invalid_evidence_ids), 6)

    def test_empty_claim_fields(self):
        claim = Claim.model_construct(
            claim_id="", incident_id="inc_1", claim_type="", statement="",
            reasoning_summary="R", supporting_evidence=["ev_1"],
            mitre_techniques=[], confidence=0.9, agent_id="A"
        )
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertFalse(res.valid)
        self.assertIn("EMPTY_CLAIM_ID", res.validation_errors)
        self.assertIn("EMPTY_CLAIM_TYPE", res.validation_errors)
        self.assertIn("EMPTY_STATEMENT", res.validation_errors)

    def test_invalid_confidence_values(self):
        for bad_conf in [-1.0, 1.1, float('nan'), float('inf'), "string"]:
            claim = Claim.model_construct(
                claim_id="c1", incident_id="inc_1", claim_type="T", statement="S",
                reasoning_summary="R", supporting_evidence=["ev_1"],
                mitre_techniques=[], confidence=bad_conf, agent_id="A"
            )
            res = self.validator.validate_claim(claim, "inc_1", self.conn)
            self.assertFalse(res.valid)
            self.assertTrue(
                "INVALID_CONFIDENCE_RANGE" in res.validation_errors or 
                "INVALID_CONFIDENCE_TYPE" in res.validation_errors
            )

    def test_batch_validation(self):
        claims = [
            self._create_claim(["ev_1"], claim_id="c1"),
            self._create_claim(["ev_99"], claim_id="c2")
        ]
        results = self.validator.validate_claims(claims, "inc_1", self.conn)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].valid)
        self.assertFalse(results[1].valid)

    def test_read_only_database_safety(self):
        # Ensure validator does not modify anything.
        # Run validation and verify DB unchanged.
        claim = self._create_claim(["ev_1"])
        self.validator.validate_claim(claim, "inc_1", self.conn)
        events = self.conn.execute("SELECT count(*) as c FROM events").fetchone()["c"]
        self.assertEqual(events, 3)

    def test_mitre_proposed_techniques_untouched(self):
        # 21. authoritative MITRE context remains read-only
        # 22. proposed MITRE technique remains proposed
        # 23. unknown proposed technique does not modify Step 8
        # Since validator doesn't implement mitre checking for rejection directly (unless required by schema),
        # this ensures it just passes them through safely.
        claim = Claim.model_construct(
            claim_id="c1", incident_id="inc_1", claim_type="T", statement="S",
            reasoning_summary="R", supporting_evidence=["ev_1"],
            mitre_techniques=["T9999"], confidence=0.9, agent_id="A"
        )
        res = self.validator.validate_claim(claim, "inc_1", self.conn)
        self.assertTrue(res.valid)
        
        # Verify db wasn't modified
        techs = self.conn.execute("SELECT count(*) as c FROM threat_context").fetchone()["c"]
        self.assertEqual(techs, 0)
