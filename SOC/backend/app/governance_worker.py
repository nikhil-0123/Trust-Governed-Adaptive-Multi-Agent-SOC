import threading
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
import os

from app.database import get_db_connection
from app.governance import GovernancePolicyEngine, GovernanceDecision

logger = logging.getLogger(__name__)

class GovernanceWorker(threading.Thread):
    def __init__(self, config_path: str = None):
        super().__init__(daemon=True, name="GovernanceWorker")
        self._stop_event = threading.Event()
        
        self.config_path = config_path or "app/governance_config.json"
        self.is_valid = False
        try:
            base_dir = os.path.dirname(__file__)
            full_path = os.path.join(base_dir, "governance_config.json") if not os.path.isabs(self.config_path) else self.config_path
            with open(full_path, "r") as f:
                self.config = json.load(f)
            self._validate_config()
            self.is_valid = True
        except Exception as e:
            logger.error(f"GovernanceWorker initialization failed due to invalid configuration: {e}")
            self.config = {}
            
        if self.is_valid:
            self.engine = GovernancePolicyEngine(self.config)
            ws = self.config.get("worker_settings", {})
            self.poll_interval = ws.get("poll_interval_seconds", 5)
            self.stale_timeout = ws.get("stale_processing_seconds", 3600)
        else:
            self.engine = None
            self.poll_interval = 5
            self.stale_timeout = 3600

    def _validate_config(self):
        req_keys = [
            "policy_version", "config_version", "environment", "trust_policy", 
            "risk_policy", "confidence_threshold", "severity_policy", "verification_policy", 
            "autonomous_action_allowlist", "mitre_restrictions", "approval_timeout_seconds", 
            "worker_settings"
        ]
        for k in req_keys:
            if k not in self.config:
                raise ValueError(f"Missing required config section: {k}")

        for k, v in self.config["trust_policy"].items():
            if not isinstance(v, (int, float)) or not (0.0 <= v <= 1.0):
                raise ValueError(f"Trust policy value {k} out of range [0.0, 1.0]: {v}")
                
        for k, v in self.config["risk_policy"].items():
            if not isinstance(v, (int, float)) or not (0.0 <= v <= 1.0):
                raise ValueError(f"Risk policy value {k} out of range [0.0, 1.0]: {v}")
                
        for k, v in self.config["confidence_threshold"].items():
            if not isinstance(v, (int, float)) or not (0.0 <= v <= 1.0):
                raise ValueError(f"Confidence threshold value {k} out of range [0.0, 1.0]: {v}")
                
        if not isinstance(self.config["severity_policy"], dict) or not self.config["severity_policy"]:
            raise ValueError("severity_policy must be a non-empty dictionary")
            
        if not isinstance(self.config["autonomous_action_allowlist"], list):
            raise ValueError("autonomous_action_allowlist must be a list")

    def start_worker(self):
        self.start()
        
    def stop(self):
        self._stop_event.set()
        
    def run(self):
        logger.info("GovernanceWorker started.")
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception as e:
                logger.error(f"Unexpected error in GovernanceWorker loop: {e}")
            self._stop_event.wait(self.poll_interval)
        logger.info("GovernanceWorker stopped.")

    def run_once(self):
        if not getattr(self, 'is_valid', False):
            return
            
        with get_db_connection() as conn:
            # 1. Discover work - We need incidents that have a completed analysis but no governance_state yet
            # OR governance_state is PENDING/FAILED or stale PROCESSING.
            now_iso = datetime.now(timezone.utc).isoformat()
            stale_threshold = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - self.stale_timeout, timezone.utc).isoformat()
            
            # Find eligible incidents by looking at the incidents table latest pointers.
            cursor = conn.execute("""
                SELECT i.incident_id, i.latest_assessment_id, i.latest_analysis_id, 
                       gs.status, gs.updated_at
                FROM incidents i
                LEFT JOIN governance_state gs ON i.incident_id = gs.incident_id 
                    AND i.latest_assessment_id = gs.assessment_id 
                    AND i.latest_analysis_id = gs.analysis_id
                WHERE i.latest_analysis_id IS NOT NULL
                  AND (
                      gs.status IS NULL 
                      OR gs.status IN ('PENDING', 'FAILED') 
                      OR (gs.status = 'PROCESSING' AND gs.updated_at < ?)
                  )
            """, (stale_threshold,))
            
            rows = cursor.fetchall()
            for row in rows:
                if self._stop_event.is_set():
                    break
                    
                incident_id = row["incident_id"]
                assessment_id = row["latest_assessment_id"]
                analysis_id = row["latest_analysis_id"]
                
                # 2. Atomic claim
                try:
                    conn.execute("BEGIN TRANSACTION")
                    claim_cursor = conn.execute("""
                        INSERT INTO governance_state (incident_id, assessment_id, analysis_id, status, approval_status, attempts, updated_at)
                        VALUES (?, ?, ?, 'PROCESSING', 'NOT_REQUIRED', 1, ?)
                        ON CONFLICT(incident_id) DO UPDATE SET
                            assessment_id = excluded.assessment_id,
                            analysis_id = excluded.analysis_id,
                            status = 'PROCESSING',
                            attempts = attempts + 1,
                            updated_at = ?
                        WHERE status IN ('PENDING', 'FAILED') 
                           OR (status = 'PROCESSING' AND updated_at < ?)
                           OR analysis_id != excluded.analysis_id -- allow replacing if analysis pointer moved
                    """, (incident_id, assessment_id, analysis_id, now_iso, now_iso, stale_threshold))
                    
                    if claim_cursor.rowcount == 0:
                        conn.rollback()
                        continue
                        
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    logger.error(f"Error during claim for {incident_id}: {e}")
                    continue
                    
                # 3. Process
                try:
                    self._process_incident(conn, incident_id, assessment_id, analysis_id)
                except Exception as e:
                    logger.error(f"Failed processing governance for {incident_id}: {e}")
                    self._mark_failed(conn, incident_id, str(e))
                    
    def _mark_failed(self, conn, incident_id: str, error_msg: str):
        try:
            conn.execute("BEGIN TRANSACTION")
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE governance_state
                SET status = 'FAILED', last_error = ?, updated_at = ?
                WHERE incident_id = ?
            """, (error_msg, now_iso, incident_id))
            conn.commit()
        except Exception:
            conn.rollback()

    def _process_incident(self, conn, incident_id: str, assessment_id: str, analysis_id: str):
        # Retrieve dependencies
        # Assessment
        a_cursor = conn.execute("SELECT status, trust_score, risk_score, formula_version, config_version, input_snapshot FROM assessments WHERE assessment_id = ?", (assessment_id,))
        a_row = a_cursor.fetchone()
        if not a_row:
            raise ValueError("Assessment not found.")
        
        # Analysis
        an_cursor = conn.execute("SELECT status, analysis_output FROM analyses WHERE analysis_id = ?", (analysis_id,))
        an_row = an_cursor.fetchone()
        if not an_row:
            raise ValueError("Analysis not found.")
            
        if an_row["status"] == "FAILED" or a_row["status"] == "FAILED":
            raise ValueError("Upstream state is FAILED.")
            
        # Incident context
        inc_cursor = conn.execute("SELECT max_severity, status, latest_assessment_id, latest_analysis_id FROM incidents WHERE incident_id = ?", (incident_id,))
        inc_row = inc_cursor.fetchone()
        if not inc_row:
            raise ValueError("Incident not found.")
            
        assessment_dict = dict(a_row)
        analysis_dict = json.loads(an_row["analysis_output"])
        severity = inc_row["max_severity"]
        
        # Calculate decision purely in memory
        decision_obj = self.engine.evaluate(analysis_dict, assessment_dict, severity)
        
        decision_id = str(uuid.uuid4())
        
        approval_status = "NOT_REQUIRED"
        if decision_obj.decision == "HUMAN_APPROVAL":
            approval_status = "PENDING"
            
        input_snapshot = {
            "incident_id": incident_id,
            "assessment_id": assessment_id,
            "analysis_id": analysis_id,
            "trust_score": assessment_dict["trust_score"],
            "risk_score": assessment_dict["risk_score"],
            "assessment_status": assessment_dict["status"],
            "analysis_status": an_row["status"],
            "severity": severity,
            "recommendations": analysis_dict.get("recommendations"),
            "verification_results": analysis_dict.get("verification_results"),
            "authoritative_mitre_context": analysis_dict.get("authoritative_mitre_context"),
            "uncertainty": analysis_dict.get("uncertainty"),
            "policy_version": decision_obj.policy_version,
            "config_version": decision_obj.config_version
        }
        
        try:
            conn.execute("BEGIN TRANSACTION")
            
            now_iso = datetime.now(timezone.utc).isoformat()
            
            # Persist historical decision immutably
            conn.execute("""
                INSERT INTO governance_decisions (
                    decision_id, incident_id, assessment_id, analysis_id, 
                    decision, reason, input_snapshot, policy_version, config_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision_id, incident_id, assessment_id, analysis_id,
                decision_obj.decision, decision_obj.reason,
                json.dumps(input_snapshot), decision_obj.policy_version, decision_obj.config_version, now_iso
            ))
            
            # Check A/B race before updating state pointer
            check_cursor = conn.execute("SELECT latest_assessment_id, latest_analysis_id FROM incidents WHERE incident_id = ?", (incident_id,))
            current_pointers = check_cursor.fetchone()
            
            if current_pointers["latest_assessment_id"] == assessment_id and current_pointers["latest_analysis_id"] == analysis_id:
                # Still current, update state
                conn.execute("""
                    UPDATE governance_state 
                    SET status = 'DECIDED', decision_id = ?, approval_status = ?, updated_at = ?
                    WHERE incident_id = ? AND assessment_id = ? AND analysis_id = ?
                """, (decision_id, approval_status, now_iso, incident_id, assessment_id, analysis_id))

                # If AUTO_APPROVE, automatically dispatch mitigation commands to endpoints
                if decision_obj.decision == "AUTO_APPROVE":
                    try:
                        from app.response_bridge import dispatch_governed_response
                        recs = analysis_dict.get("recommendations", [])
                        dispatch_governed_response(conn, incident_id, recs, approved_by="AUTONOMOUS_GOVERNANCE")
                    except Exception as bridge_err:
                        logger.error(f"Failed to auto-dispatch governed response for {incident_id}: {bridge_err}")
            
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            logger.info(f"Duplicate governance processing prevented by uniqueness for {incident_id}/{assessment_id}/{analysis_id}")
            # Mark processing as successfully completed since another worker did it
        except Exception as e:
            conn.rollback()
            raise Exception(f"Persistence error: {e}")
