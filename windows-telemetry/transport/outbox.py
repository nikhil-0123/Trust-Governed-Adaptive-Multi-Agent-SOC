import sqlite3
import json
import logging
from typing import List, Dict, Any
import os
from contextlib import closing

class Outbox:
    def __init__(self, db_path: str, logger: logging.Logger):
        self.db_path = db_path
        self.logger = logger
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS outbox (
                        detection_event_id TEXT PRIMARY KEY,
                        event_data TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        attempts INTEGER DEFAULT 0,
                        last_attempt TIMESTAMP,
                        last_error TEXT
                    )
                ''')

    def add_event(self, event: Dict[str, Any]):
        event_id = event.get("detection_event_id")
        if not event_id:
            raise ValueError("Event missing detection_event_id")
            
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.execute('''
                        INSERT OR IGNORE INTO outbox (detection_event_id, event_data, status)
                        VALUES (?, ?, ?)
                    ''', (event_id, json.dumps(event), "pending"))
        except Exception as e:
            self.logger.error(f"Failed to add event {event_id} to outbox: {e}")
            raise

    def get_pending_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT detection_event_id, event_data FROM outbox 
                WHERE status = 'pending' 
                ORDER BY created_at ASC LIMIT ?
            ''', (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            cursor.close()
            return rows

    def mark_delivered(self, event_id: str):
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute('''
                    UPDATE outbox SET status = 'delivered', last_attempt = CURRENT_TIMESTAMP
                    WHERE detection_event_id = ?
                ''', (event_id,))

    def mark_failed(self, event_id: str, error: str):
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute('''
                    UPDATE outbox SET 
                        attempts = attempts + 1,
                        last_attempt = CURRENT_TIMESTAMP,
                        last_error = ?
                    WHERE detection_event_id = ?
                ''', (error, event_id))
