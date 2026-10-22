import threading
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone

from app.database import get_db_connection
from app.reasoning_provider import MockLLMProvider, LLMProviderError
from app.evidence_validator import EvidenceValidator
from app.reasoning_agents import AnalysisAgent, AnalysisInput, AnalysisAgentParsingError
from app.reasoning.verification import VerificationAgent, VerificationInput, VerificationAgentParsingError
from app.reasoning.synthesis import SynthesisAgent, SynthesisInput, SynthesisAgentParsingError
from app.reasoning_models import Claim

logger = logging.getLogger(__name__)


class ReasoningConfigError(Exception):
    pass


class ReasoningWorker(threading.Thread):
    def __init__(self, config_path: str = None):
        super().__init__(daemon=True, name="ReasoningWorker")
        self._stop_event = threading.Event()
        
        # Load config
        self.config_path = config_path or "app/reasoning_config.json"
        try:
            import os
            base_dir = os.path.dirname(__file__)
            full_path = os.path.join(base_dir, "reasoning_config.json") if not os.path.isabs(self.config_path) else self.config_path
            with open(full_path, "r") as f:
                self.config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load reasoning config: {e}")
            self.config = {
                "worker": {"poll_interval_seconds": 5, "stale_processing_seconds": 3600, "max_evidence_events": 100},
                "provider": "mock",
                "model": "mock-model",
                "timeout_seconds": 30,
                "prompt_versions": {
                    "analysis": "analysis_v1",
                    "verification": "verification_v1",
                    "synthesis": "synthesis_v1"
                }
            }
            
        self.poll_interval = self.config.get("worker", {}).get("poll_interval_seconds", 5)
        self.stale_timeout = self.config.get("worker", {}).get("stale_processing_seconds", 3600)
        self.max_evidence_events = self.config.get("worker", {}).get("max_evidence_events", 100)
        
        provider_name = self.config.get("provider", "mock")
        if provider_name == "mock":
            self.provider = MockLLMProvider()
        else:
            self.provider = MockLLMProvider() # Default back to mock if unknown
            
        self.evidence_validator = EvidenceValidator()
        self.analysis_agent = AnalysisAgent(self.provider, self.evidence_validator, self.config)
        self.verification_agent = VerificationAgent(self.provider, self.evidence_validator, self.config)
        self.synthesis_agent = SynthesisAgent(self.provider, self.config)

    def start_worker(self):
        self.start()
        
    def stop(self):
        self._stop_event.set()
        
    def run(self):
        logger.info("ReasoningWorker started.")
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception as e:
                logger.error(f"Unexpected error in ReasoningWorker loop: {e}")
            self._stop_event.wait(self.poll_interval)
        logger.info("ReasoningWorker stopped.")
        
    def run_once(self):
        with get_db_connection() as conn:
            # 1. Discover work
            now_iso = datetime.now(timezone.utc).isoformat()
            stale_threshold = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - self.stale_timeout, timezone.utc).isoformat()
            
            cursor = conn.execute("""
                SELECT i.incident_id, i.latest_assessment_id, a.status as assessment_status
                FROM incidents i
                JOIN assessments a ON i.latest_assessment_id = a.assessment_id
                LEFT JOIN analysis_state s ON i.incident_id = s.incident_id AND a.assessment_id = s.assessment_id
                WHERE a.status IN ('COMPLETED', 'INSUFFICIENT_DATA')
                  AND (
                      s.status IS NULL 
                      OR s.status IN ('PENDING', 'FAILED') 
                      OR (s.status = 'PROCESSING' AND s.updated_at < ?)
                  )
            """, (stale_threshold,))
            
            rows = cursor.fetchall()
            for row in rows:
                if self._stop_event.is_set():
                    break
                
                incident_id = row["incident_id"]
                assessment_id = row["latest_assessment_id"]
                assessment_status = row["assessment_status"]
                
                # Fast check for INSUFFICIENT_DATA and no evidence
                if assessment_status == "INSUFFICIENT_DATA":
                    ev_cursor = conn.execute("SELECT 1 FROM incident_evidence WHERE incident_id = ?", (incident_id,))
                    if not ev_cursor.fetchone():
                        # Nothing to reason about
                        continue

                # 2. Atomic claim (Transaction A)
                try:
                    conn.execute("BEGIN TRANSACTION")
                    claim_cursor = conn.execute("""
                        INSERT INTO analysis_state (incident_id, assessment_id, status, attempts, updated_at)
                        VALUES (?, ?, 'PROCESSING', 1, ?)
                        ON CONFLICT(incident_id, assessment_id) DO UPDATE SET
                            status = 'PROCESSING',
                            attempts = attempts + 1,
                            updated_at = ?
                        WHERE status IN ('PENDING', 'FAILED') 
                           OR (status = 'PROCESSING' AND updated_at < ?)
                    """, (incident_id, assessment_id, now_iso, now_iso, stale_threshold))
                    
                    if claim_cursor.rowcount == 0:
                        conn.rollback()
                        continue # Another worker claimed it or it completed
                        
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    logger.error(f"Error during claim for {incident_id}/{assessment_id}: {e}")
                    continue
                    
                # 3. Process
                try:
                    self._process_incident(conn, incident_id, assessment_id)
                except Exception as e:
                    logger.error(f"Failed processing incident {incident_id}, assessment {assessment_id}: {e}")
                    self._mark_failed(conn, incident_id, assessment_id, str(e))
                    
    def _mark_failed(self, conn, incident_id: str, assessment_id: str, error_msg: str):
        try:
            conn.execute("BEGIN TRANSACTION")
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE analysis_state
                SET status = 'FAILED', last_error = ?, updated_at = ?
                WHERE incident_id = ? AND assessment_id = ?
            """, (error_msg, now_iso, incident_id, assessment_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to record failure state for {incident_id}/{assessment_id}: {e}")

    def _process_incident(self, conn, incident_id: str, assessment_id: str):
        # 1. Retrieve Assessment Snapshot
        cursor = conn.execute("""
            SELECT trust_score, risk_score, status, formula_version, config_version, 
                   input_snapshot, trust_explanation, risk_explanation, created_at
            FROM assessments WHERE assessment_id = ?
        """, (assessment_id,))
        a_row = cursor.fetchone()
        if not a_row:
            raise ValueError("DATA_ERROR: Assessment not found.")
            
        assessment_snapshot = {
            "assessment_id": assessment_id,
            "incident_id": incident_id,
            "trust_score": a_row["trust_score"],
            "risk_score": a_row["risk_score"],
            "status": a_row["status"],
            "formula_version": a_row["formula_version"],
            "config_version": a_row["config_version"],
            "input_snapshot": json.loads(a_row["input_snapshot"]),
            "trust_explanation": json.loads(a_row["trust_explanation"]) if a_row["trust_explanation"] else None,
            "risk_explanation": json.loads(a_row["risk_explanation"]) if a_row["risk_explanation"] else None,
            "calculation_parameters": json.loads(a_row["input_snapshot"]).get("calculation_parameters", {}),
            "created_at": a_row["created_at"]
        }
        
        # 2. Retrieve Incident Snapshot
        cursor = conn.execute("SELECT first_seen, last_seen, max_severity, status FROM incidents WHERE incident_id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        
        # 3. Retrieve Entities
        cursor = conn.execute("SELECT entity_type, entity_value FROM incident_entities WHERE incident_id = ?", (incident_id,))
        entities = {}
        for row in cursor.fetchall():
            etype = row["entity_type"]
            evalue = row["entity_value"]
            if etype not in entities:
                entities[etype] = []
            entities[etype].append(evalue)
            
        hostname = entities.get("hostname", ["unavailable"])[0]
        source_ip = entities.get("source_ip", ["unavailable"])[0]
        username = entities.get("username", ["unavailable"])[0]
        agent_id = entities.get("agent_id", ["unavailable"])[0]
            
        incident_context = {
            "incident_id": incident_id,
            "first_seen": inc_row["first_seen"],
            "last_seen": inc_row["last_seen"],
            "max_severity": inc_row["max_severity"],
            "status": inc_row["status"],
            "hostname": hostname,
            "source_ip": source_ip,
            "username": username,
            "agent_id": agent_id
        }

        # 4. Bounded Evidence Retrieval
        cursor = conn.execute(f"""
            SELECT e.detection_event_id, e.data 
            FROM events e
            JOIN incident_evidence ie ON e.detection_event_id = ie.detection_event_id
            WHERE ie.incident_id = ?
            ORDER BY 
                CASE json_extract(e.data, '$.severity')
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END DESC,
                json_extract(e.data, '$.timestamp') DESC,
                e.detection_event_id ASC
            LIMIT ?
        """, (incident_id, self.max_evidence_events))
        
        evidence_list = []
        for row in cursor.fetchall():
            try:
                raw_data = json.loads(row["data"])
                bounded = {
                    "detection_event_id": row["detection_event_id"],
                    "timestamp": raw_data.get("timestamp"),
                    "agent_id": raw_data.get("agent_id"),
                    "hostname": raw_data.get("hostname"),
                    "os": raw_data.get("os"),
                    "event_type": raw_data.get("event_type"),
                    "source_ip": raw_data.get("source_ip"),
                    "username": raw_data.get("username"),
                    "severity": raw_data.get("severity"),
                    "detection_type": raw_data.get("detection_type"),
                    "confidence": raw_data.get("confidence"),
                    "evidence": raw_data.get("evidence", {}) # Just the parsed inner struct
                }
                evidence_list.append(bounded)
            except Exception:
                pass
                
        # 5. MITRE Retrieval
        cursor = conn.execute("""
            SELECT context_id, technique_id, technique_name, tactic, mitre_version
            FROM threat_context WHERE incident_id = ?
        """, (incident_id,))
        auth_mitre = [dict(r) for r in cursor.fetchall()]

        # ==== STAGE 1: Analysis ====
        try:
            analysis_input = AnalysisInput(
                incident_id=incident_id,
                assessment_id=assessment_id,
                incident_summary=incident_context,
                evidence=evidence_list,
                entities=[],
                authoritative_mitre_context=auth_mitre,
                assessment_snapshot=assessment_snapshot
            )
            analysis_result = self.analysis_agent.generate_candidate_claims(analysis_input, conn)
            accepted_claims = analysis_result.accepted_claims
            rejected_claims = analysis_result.rejected_claims
        except LLMProviderError as e:
            raise Exception(f"PROVIDER_ERROR: {e}")
        except AnalysisAgentParsingError as e:
            raise Exception(f"PARSING_ERROR: {e}")
        except Exception as e:
            raise Exception(f"UNEXPECTED_ERROR: {e}")

        # ==== STAGE 2: Verification ====
        verification_results = []
        for claim in accepted_claims:
            try:
                v_input = VerificationInput(
                    incident_id=incident_id,
                    assessment_id=assessment_id,
                    claim=claim,
                    evidence=evidence_list,
                    authoritative_mitre_context=auth_mitre,
                    assessment_snapshot=assessment_snapshot
                )
                res = self.verification_agent.verify_claim(v_input, conn)
                verification_results.append(res)
            except VerificationAgentParsingError:
                # Per-claim parsing failure -> mark unsupported gracefully
                from app.reasoning_models import VerificationResult
                res = VerificationResult(
                    claim_id=claim.claim_id,
                    verification_status="UNVERIFIED",
                    verification_reason="VALIDATION_ERROR: Claim verification output was malformed.",
                    supporting_evidence=[],
                    contradictory_evidence=[],
                    confidence=0.0,
                    verifier_agent_id="VerificationAgent"
                )
                verification_results.append(res)
            except LLMProviderError as e:
                # Global failure
                raise Exception(f"PROVIDER_ERROR: {e}")
            except Exception as e:
                raise Exception(f"UNEXPECTED_ERROR: {e}")

        # ==== STAGE 3: Synthesis ====
        analysis_id = str(uuid.uuid4())
        try:
            s_input = SynthesisInput(
                analysis_id=analysis_id,
                incident_id=incident_id,
                assessment_id=assessment_id,
                incident_context=incident_context,
                evidence=evidence_list,
                candidate_claims=accepted_claims,
                rejected_claims=rejected_claims,
                verification_results=verification_results,
                authoritative_mitre_context=auth_mitre,
                proposed_mitre_context=[], # Handled purely by Synthesis output normally
                assessment_snapshot=assessment_snapshot
            )
            final_analysis = self.synthesis_agent.synthesize(s_input)
        except SynthesisAgentParsingError as e:
            raise Exception(f"PARSING_ERROR: {e}")
        except LLMProviderError as e:
            raise Exception(f"PROVIDER_ERROR: {e}")
        except Exception as e:
            raise Exception(f"UNEXPECTED_ERROR: {e}")
            
        # ==== STAGE 4: Final DB Persistence (Transaction B) ====
        try:
            conn.execute("BEGIN TRANSACTION")
            
            now_iso = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT INTO analyses (
                    analysis_id, incident_id, assessment_id, assessment_snapshot, 
                    status, model_provenance, prompt_versions, analysis_output, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                final_analysis.analysis_id,
                final_analysis.incident_id,
                final_analysis.assessment_id,
                json.dumps(final_analysis.assessment_snapshot),
                "COMPLETED",
                final_analysis.model_provenance,
                json.dumps(final_analysis.prompt_versions),
                final_analysis.model_dump_json(),
                now_iso
            ))
            
            # Concurrency check: Assessment A vs Assessment B Race
            cursor = conn.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id = ?", (incident_id,))
            latest_row = cursor.fetchone()
            if not latest_row:
                raise ValueError("DATA_ERROR: Incident deleted during processing.")
                
            if latest_row["latest_assessment_id"] == assessment_id:
                # Update latest analysis pointer
                conn.execute("UPDATE incidents SET latest_analysis_id = ? WHERE incident_id = ?", (final_analysis.analysis_id, incident_id))
            
            conn.execute("""
                UPDATE analysis_state SET status = 'COMPLETED', updated_at = ? 
                WHERE incident_id = ? AND assessment_id = ?
            """, (now_iso, incident_id, assessment_id))
            
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.rollback()
            # If idx_analyses_completed_unique fails, it means another stale worker finished it first.
            logger.info(f"Duplicate execution blocked by uniqueness constraint for {incident_id}/{assessment_id}")
            # Mark this worker's processing as complete implicitly since it was beaten, or do nothing.
        except Exception as e:
            conn.rollback()
            raise Exception(f"PERSISTENCE_ERROR: {e}")
