import threading
import time
import logging
import os
from datetime import datetime, timezone
from app.database import get_db_connection
from app.assessment import AssessmentEngine, AssessmentConfigError

logger = logging.getLogger(__name__)
MAX_RETRIES = 3

class AssessmentWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="AssessmentWorker")
        self._stop_event = threading.Event()
        try:
            self.engine = AssessmentEngine()
            self.poll_interval = self.engine.config["worker"].get("poll_interval_seconds", 5)
            self.stale_timeout = self.engine.config["worker"].get("stale_processing_seconds", 3600)
        except AssessmentConfigError as e:
            logger.error(f"Failed to load Assessment config. Worker will transition events to FAILED. Error: {e}")
            self.engine = None
            self.poll_interval = 5
            self.stale_timeout = 3600

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("AssessmentWorker started.")
        while not self._stop_event.is_set():
            try:
                self.process_batch()
            except Exception as e:
                logger.error(f"Unexpected error in AssessmentWorker loop: {e}")
            
            self._stop_event.wait(self.poll_interval)
        logger.info("AssessmentWorker stopped.")

    def process_batch(self):
        with get_db_connection() as conn:
            # Select batch of PENDING, retryable FAILED, or stale PROCESSING
            cursor = conn.execute(f"""
                SELECT incident_id FROM assessment_state
                WHERE (status IN ('PENDING', 'FAILED') OR (status = 'PROCESSING' AND updated_at < datetime('now', '-{self.stale_timeout} seconds')))
                AND attempts < ?
                ORDER BY updated_at ASC LIMIT 100
            """, (MAX_RETRIES,))
            
            rows = cursor.fetchall()
            if not rows:
                return

            for row in rows:
                incident_id = row["incident_id"]
                self._process_single_incident(conn, incident_id)

    def _process_single_incident(self, conn, incident_id: str):
        try:
            now = datetime.now(timezone.utc).isoformat()
            
            # 1. Update state to processing and commit immediately
            conn.execute("""
                UPDATE assessment_state 
                SET status = 'PROCESSING', updated_at = ?, attempts = attempts + 1 
                WHERE incident_id = ?
            """, (now, incident_id))
            conn.commit()
            
            # 2. Transaction for actual assessment calculation
            conn.execute("BEGIN TRANSACTION")
            
            if self.engine is None:
                raise ValueError("AssessmentEngine is unavailable due to config failure.")
            
            final_status = self.engine.process_incident(conn, incident_id)
            
            conn.execute("""
                UPDATE assessment_state 
                SET status = ?, updated_at = ?, last_error = NULL
                WHERE incident_id = ?
            """, (final_status, now, incident_id))
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            logger.error(f"AssessmentEngine failed on incident {incident_id}: {e}")
            now = datetime.now(timezone.utc).isoformat()
            
            try:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("""
                    UPDATE assessment_state 
                    SET status = 'FAILED', updated_at = ?, last_error = ?
                    WHERE incident_id = ?
                """, (now, str(e), incident_id))
                conn.commit()
            except Exception as inner_e:
                conn.rollback()
                logger.error(f"Failed to record failure state for incident {incident_id}: {inner_e}")
