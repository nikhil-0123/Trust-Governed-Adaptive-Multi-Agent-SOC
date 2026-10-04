import threading
import time
import logging
import os
from datetime import datetime, timezone
from app.database import get_db_connection
from app.mitre import MitreEngine, MitreCatalogError

logger = logging.getLogger(__name__)

MITRE_POLL_INTERVAL_SECONDS = int(os.getenv("MITRE_POLL_INTERVAL_SECONDS", "5"))
MITRE_STALE_PROCESSING_SECONDS = int(os.getenv("MITRE_STALE_PROCESSING_SECONDS", "3600"))
MAX_RETRIES = 3

class MitreWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="MitreWorker")
        self._stop_event = threading.Event()
        try:
            self.engine = MitreEngine()
        except MitreCatalogError as e:
            logger.error(f"Failed to load MITRE catalog. Worker will transition events to FAILED. Error: {e}")
            self.engine = None

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("MitreWorker started.")
        while not self._stop_event.is_set():
            try:
                self.process_batch()
            except Exception as e:
                logger.error(f"Unexpected error in MitreWorker loop: {e}")
            
            self._stop_event.wait(MITRE_POLL_INTERVAL_SECONDS)
        logger.info("MitreWorker stopped.")

    def process_batch(self):
        with get_db_connection() as conn:
            # Select batch of PENDING, retryable FAILED, or stale PROCESSING
            cursor = conn.execute(f"""
                SELECT detection_event_id FROM threat_context_state
                WHERE (status IN ('PENDING', 'FAILED') OR (status = 'PROCESSING' AND updated_at < datetime('now', '-{MITRE_STALE_PROCESSING_SECONDS} seconds')))
                AND attempts < ?
                ORDER BY updated_at ASC LIMIT 100
            """, (MAX_RETRIES,))
            
            rows = cursor.fetchall()
            if not rows:
                return

            for row in rows:
                event_id = row["detection_event_id"]
                self._process_single_event(conn, event_id)

    def _process_single_event(self, conn, event_id: str):
        try:
            now = datetime.now(timezone.utc).isoformat()
            
            # 1. Update state to processing and commit immediately
            conn.execute("""
                UPDATE threat_context_state 
                SET status = 'PROCESSING', updated_at = ?, attempts = attempts + 1 
                WHERE detection_event_id = ?
            """, (now, event_id))
            conn.commit()
            
            # 2. Transaction for actual Mitre mapping
            conn.execute("BEGIN TRANSACTION")
            
            if self.engine is None:
                raise ValueError("MitreEngine is unavailable due to catalog failure.")
            
            final_status = self.engine.process_event(conn, event_id)
            
            conn.execute("""
                UPDATE threat_context_state 
                SET status = ?, updated_at = ?, last_error = NULL
                WHERE detection_event_id = ?
            """, (final_status, now, event_id))
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            logger.error(f"MitreEngine failed on event {event_id}: {e}")
            now = datetime.now(timezone.utc).isoformat()
            
            try:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("""
                    UPDATE threat_context_state 
                    SET status = 'FAILED', updated_at = ?, last_error = ?
                    WHERE detection_event_id = ?
                """, (now, str(e), event_id))
                conn.commit()
            except Exception as inner_e:
                conn.rollback()
                logger.error(f"Failed to record failure state for event {event_id}: {inner_e}")
