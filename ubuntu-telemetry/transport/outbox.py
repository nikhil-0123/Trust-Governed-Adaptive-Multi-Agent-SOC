import sqlite3
import json
import logging
import os
from typing import List, Dict, Any, Optional
from contextlib import closing

class Outbox:
    """
    SQLite-backed persistent outbox providing durable at-least-once delivery semantics.
    Enforces deduplication on detection_event_id.
    """
    def __init__(self, db_path: str, logger: Optional[logging.Logger] = None, max_queue_size: int = 10000, max_retries: int = 10):
        self.db_path = db_path
        self.logger = logger or logging.getLogger("Outbox")
        self.max_queue_size = max_queue_size
        self.max_retries = max_retries
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS outbox (
                        detection_event_id TEXT PRIMARY KEY,
                        event_data TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        attempts INTEGER DEFAULT 0,
                        last_attempt TIMESTAMP,
                        last_error TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status, created_at)")

    def add_event(self, event: Dict[str, Any]):
        """Adds a detection event to the outbox if not already present, enforcing bounded queue size."""
        event_id = event.get("detection_event_id")
        if not event_id:
            raise ValueError("Event missing detection_event_id")

        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    # Enforce bounded queue
                    cur = conn.execute("SELECT count(*) as c FROM outbox WHERE status = 'pending'")
                    if cur.fetchone()[0] >= self.max_queue_size:
                        self.logger.warning(f"Outbox queue capacity ({self.max_queue_size}) reached. Dropping new event {event_id} to prevent unbounded growth.")
                        return

                    conn.execute("""
                        INSERT OR IGNORE INTO outbox (detection_event_id, event_data, status)
                        VALUES (?, ?, ?)
                    """, (event_id, json.dumps(event), "pending"))
        except Exception as e:
            self.logger.error(f"Failed to add event {event_id} to outbox: {e}")
            raise

    def get_pending_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves pending events in FIFO order, excluding retry-exhausted events."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT detection_event_id, event_data FROM outbox
                WHERE status = 'pending' AND attempts < ?
                ORDER BY created_at ASC LIMIT ?
            """, (self.max_retries, limit))
            rows = [dict(row) for row in cursor.fetchall()]
            cursor.close()
            return rows

    def mark_delivered(self, event_id: str):
        """Marks event as successfully delivered and purges older delivered records to bound disk usage."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("""
                    UPDATE outbox SET status = 'delivered', last_attempt = CURRENT_TIMESTAMP
                    WHERE detection_event_id = ?
                """, (event_id,))
                self.purge_delivered(conn, max_keep=500)

    def mark_failed(self, event_id: str, error: str):
        """Records delivery attempt failure, transitioning to 'exhausted' if retries exceeded."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                # Check current attempts
                cur = conn.execute("SELECT attempts FROM outbox WHERE detection_event_id = ?", (event_id,))
                row = cur.fetchone()
                current_attempts = row[0] if row else 0
                new_status = "exhausted" if (current_attempts + 1) >= self.max_retries else "pending"

                conn.execute("""
                    UPDATE outbox SET
                        attempts = attempts + 1,
                        status = ?,
                        last_attempt = CURRENT_TIMESTAMP,
                        last_error = ?
                    WHERE detection_event_id = ?
                """, (new_status, error, event_id))

    def purge_delivered(self, conn: sqlite3.Connection, max_keep: int = 500):
        """Deletes excess delivered events beyond max_keep to prevent unbounded disk growth."""
        try:
            conn.execute("""
                DELETE FROM outbox WHERE detection_event_id IN (
                    SELECT detection_event_id FROM outbox
                    WHERE status = 'delivered'
                    ORDER BY last_attempt DESC
                    LIMIT -1 OFFSET ?
                )
            """, (max_keep,))
        except Exception as e:
            self.logger.debug(f"Outbox purge delivered skipped: {e}")
