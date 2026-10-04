import threading
import time
import logging
import os
from datetime import datetime, timezone
from app.database import get_db_connection
from app.fusion import EvidenceFusionEngine

logger = logging.getLogger(__name__)

FUSION_POLL_INTERVAL_SECONDS = int(os.getenv("FUSION_POLL_INTERVAL_SECONDS", "5"))
MAX_RETRIES = 3

class FusionWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="FusionWorker")
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("FusionWorker started.")
        while not self._stop_event.is_set():
            try:
                self.process_batch()
            except Exception as e:
                logger.error(f"Unexpected error in FusionWorker loop: {e}")
            
            self._stop_event.wait(FUSION_POLL_INTERVAL_SECONDS)
        logger.info("FusionWorker stopped.")

    def process_batch(self):
        with get_db_connection() as conn:
            # Sync fusion_event_state for any new events
            # Insert PENDING for events that aren't in fusion_event_state yet
            conn.execute("""
                INSERT INTO fusion_event_state (detection_event_id, status, updated_at)
                SELECT detection_event_id, 'PENDING', CURRENT_TIMESTAMP 
                FROM events 
                WHERE detection_event_id NOT IN (SELECT detection_event_id FROM fusion_event_state)
            """)
            conn.commit()

            # Select batch of PENDING, retryable FAILED, or stale PROCESSING
            cursor = conn.execute("""
                SELECT detection_event_id FROM fusion_event_state
                WHERE (status IN ('PENDING', 'FAILED') OR (status = 'PROCESSING' AND updated_at < datetime('now', '-1 hour')))
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
                UPDATE fusion_event_state 
                SET status = 'PROCESSING', updated_at = ?, attempts = attempts + 1 
                WHERE detection_event_id = ?
            """, (now, event_id))
            conn.commit()

            # 2. Transaction for actual fusion work
            conn.execute("BEGIN TRANSACTION")
            
            engine = EvidenceFusionEngine(conn)
            engine.process_event(event_id)
            
            now = datetime.now(timezone.utc).isoformat()
            
            # Mark processed
            conn.execute("""
                UPDATE fusion_event_state 
                SET status = 'PROCESSED', updated_at = ?, last_error = NULL
                WHERE detection_event_id = ?
            """, (now, event_id))
            
            # Step 8 handoff
            conn.execute("""
                INSERT OR IGNORE INTO threat_context_state (detection_event_id, status, updated_at)
                VALUES (?, 'PENDING', ?)
            """, (event_id, now))
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Fusion engine failed on event {event_id}: {e}")
            now = datetime.now(timezone.utc).isoformat()
            
            # Save failure state in a new transaction
            try:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("""
                    UPDATE fusion_event_state 
                    SET status = 'FAILED', updated_at = ?, last_error = ?
                    WHERE detection_event_id = ?
                """, (now, str(e), event_id))
                conn.commit()
            except Exception as inner_e:
                conn.rollback()
                logger.error(f"Failed to record failure state for event {event_id}: {inner_e}")
