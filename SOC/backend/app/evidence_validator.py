from typing import List, Optional
from pydantic import BaseModel
import sqlite3

from app.reasoning_models import Claim

class ValidationResult(BaseModel):
    """
    Deterministically represents the validation status of a claim against 
    authoritative, persisted SOC evidence.
    """
    valid: bool
    status: str
    reason: str
    claim_id: str
    valid_evidence_ids: List[str]
    invalid_evidence_ids: List[str]
    validation_errors: List[str]

class EvidenceValidator:
    """
    Level 2: Deterministic Evidence Validation.
    Validates structural integrity, format, existence, and incident-scoping of claim references.
    Does NOT infer real-world truth or perform semantic verification.
    Uses READ-ONLY deterministic database operations.
    """

    def validate_claim(self, claim: Claim, incident_id: str, conn: sqlite3.Connection) -> ValidationResult:
        # Pre-check basic formatting required before database interaction
        errors = self._check_claim_structure(claim)
        
        if incident_id != claim.incident_id:
            errors.append("CLAIM_INCIDENT_MISMATCH")
            
        if errors:
            return self._build_result(claim, False, "UNSUPPORTED", "Structural claim validation failed", [], [], errors)

        # Check evidence formats and normalize duplicates deterministically (preserving original order for first occurences)
        seen = set()
        normalized_evidence = []
        invalid_format_evidence = []
        
        for ev in claim.supporting_evidence:
            if not isinstance(ev, str) or not ev.strip():
                invalid_format_evidence.append(str(ev))
            elif ev not in seen:
                seen.add(ev)
                normalized_evidence.append(ev)

        if invalid_format_evidence:
            errors.append("INVALID_EVIDENCE_ID_FORMAT")
            return self._build_result(claim, False, "UNSUPPORTED", "Malformed evidence IDs found", [], invalid_format_evidence, errors)

        if not normalized_evidence:
            errors.append("EMPTY_REQUIRED_EVIDENCE")
            return self._build_result(claim, False, "UNSUPPORTED", "No evidence references provided", [], [], errors)

        # Bulk verify against authoritative persisted evidence (READ-ONLY)
        valid_ids, invalid_ids, db_errors = self._verify_evidence_in_db(normalized_evidence, incident_id, conn)
        errors.extend(db_errors)
        
        if invalid_ids or errors:
            reason = "Unsupported due to invalid evidence references or scope violations."
            return self._build_result(claim, False, "UNSUPPORTED", reason, valid_ids, invalid_ids, errors)

        return self._build_result(claim, True, "VALID", "Structurally supported by persisted evidence.", valid_ids, [], [])

    def validate_claims(self, claims: List[Claim], incident_id: str, conn: sqlite3.Connection) -> List[ValidationResult]:
        """Batch validation method (preserves exact behavior of individual validation)."""
        return [self.validate_claim(claim, incident_id, conn) for claim in claims]

    def _check_claim_structure(self, claim: Claim) -> List[str]:
        errors = []
        if not claim.claim_id or not claim.claim_id.strip():
            errors.append("EMPTY_CLAIM_ID")
        if not claim.claim_type or not claim.claim_type.strip():
            errors.append("EMPTY_CLAIM_TYPE")
        if not claim.statement or not claim.statement.strip():
            errors.append("EMPTY_STATEMENT")
        
        try:
            val = float(claim.confidence)
            if not (0.0 <= val <= 1.0):
                errors.append("INVALID_CONFIDENCE_RANGE")
        except (ValueError, TypeError):
            errors.append("INVALID_CONFIDENCE_TYPE")
            
        return errors

    def _verify_evidence_in_db(self, evidence_ids: List[str], incident_id: str, conn: sqlite3.Connection):
        """
        Queries the database for existence and incident-scoping.
        Returns (valid_ids, invalid_ids, errors).
        """
        valid_ids = []
        invalid_ids = []
        errors = set()
        
        # Verify incident exists
        incident_row = conn.execute("SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not incident_row:
            errors.add("INCIDENT_NOT_FOUND")
            return [], evidence_ids, list(errors)

        # Batch query using IN clause for existence and scope
        placeholders = ",".join("?" for _ in evidence_ids)
        query = f"""
            SELECT e.detection_event_id, 
                   ie.incident_id 
            FROM events e
            LEFT JOIN incident_evidence ie ON e.detection_event_id = ie.detection_event_id 
                                            AND ie.incident_id = ?
            WHERE e.detection_event_id IN ({placeholders})
        """
        # Execute query safely parameterizing incident_id and list of evidence_ids
        params = [incident_id] + evidence_ids
        rows = conn.execute(query, params).fetchall()
        
        # Map DB results
        found_events = {}
        for row in rows:
            found_events[row["detection_event_id"]] = row["incident_id"]

        for ev_id in evidence_ids:
            if ev_id not in found_events:
                invalid_ids.append(ev_id)
                errors.add("EVIDENCE_NOT_FOUND")
            elif found_events[ev_id] != incident_id:
                invalid_ids.append(ev_id)
                errors.add("EVIDENCE_OUTSIDE_INCIDENT")
            else:
                valid_ids.append(ev_id)

        return valid_ids, invalid_ids, sorted(list(errors))

    def _build_result(self, claim: Claim, valid: bool, status: str, reason: str, 
                      valid_ids: List[str], invalid_ids: List[str], errors: List[str]) -> ValidationResult:
        return ValidationResult(
            valid=valid,
            status=status,
            reason=reason,
            claim_id=claim.claim_id if hasattr(claim, 'claim_id') else "unknown",
            valid_evidence_ids=valid_ids,
            invalid_evidence_ids=invalid_ids,
            validation_errors=errors
        )
