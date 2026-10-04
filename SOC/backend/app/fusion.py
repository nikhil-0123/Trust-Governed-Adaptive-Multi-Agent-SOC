import json
import logging
from datetime import datetime, timezone
import uuid
import os
from typing import Optional, List, Tuple
from app.models import DetectionEvent

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
FUSION_TIME_WINDOW_SECONDS = int(os.getenv("FUSION_TIME_WINDOW_SECONDS", "3600"))

def parse_utc_timestamp(ts_str: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError("Timestamp must be timezone-aware")
        return dt.astimezone(timezone.utc)
    except Exception as e:
        raise ValueError(f"Invalid timestamp '{ts_str}': {e}")

def max_severity(sev1: str, sev2: str) -> str:
    s1 = sev1.upper()
    s2 = sev2.upper()
    val1 = SEVERITY_ORDER.get(s1, 0)
    val2 = SEVERITY_ORDER.get(s2, 0)
    if val1 == 0 and val2 == 0:
        return "UNKNOWN"
    return s1 if val1 >= val2 else s2

class EvidenceFusionEngine:
    def __init__(self, db_conn):
        self.conn = db_conn

    def process_event(self, detection_event_id: str):
        # 1. Fetch event
        cursor = self.conn.execute("SELECT data FROM events WHERE detection_event_id = ?", (detection_event_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Event {detection_event_id} not found in events table.")
            
        try:
            event_data = json.loads(row["data"])
            event = DetectionEvent(**event_data)
        except Exception as e:
            raise ValueError(f"Failed to parse event data: {e}")

        event_time = parse_utc_timestamp(event.timestamp)
        hostname = event.hostname
        evidence = event.evidence or {}
        source_ip = evidence.get("source_ip")
        
        entities = [("hostname", hostname)]
        if source_ip:
            entities.append(("source_ip", source_ip))
        if event.agent_id:
            entities.append(("agent_id", event.agent_id))
        username = evidence.get("username")
        if username:
            entities.append(("username", username))

        candidate_incident_id = self._find_candidate_incident(hostname, source_ip, event_time)

        if candidate_incident_id:
            self._attach_evidence(candidate_incident_id, event, event_time, entities)
        else:
            self._create_incident(event, event_time, entities)

    def _find_candidate_incident(self, hostname: str, source_ip: Optional[str], event_time: datetime) -> Optional[str]:
        # Case 1 & Case 2: Matching hostname + optional source_ip + within time window
        # Select newest compatible incident by last_seen, use incident_id as tie-breaker
        
        query = """
            SELECT i.incident_id, i.first_seen, i.last_seen 
            FROM incidents i
            JOIN incident_entities e ON i.incident_id = e.incident_id
            WHERE i.status = 'OPEN' 
            AND e.entity_type = 'hostname' AND e.entity_value = ?
        """
        params = [hostname]
        
        if source_ip:
            query += """
                AND EXISTS (
                    SELECT 1 FROM incident_entities e2 
                    WHERE e2.incident_id = i.incident_id 
                    AND e2.entity_type = 'source_ip' AND e2.entity_value = ?
                )
            """
            params.append(source_ip)
            
        cursor = self.conn.execute(query, params)
        candidates = cursor.fetchall()
        
        valid_candidates = []
        for row in candidates:
            first_seen = parse_utc_timestamp(row["first_seen"])
            last_seen = parse_utc_timestamp(row["last_seen"])
            
            lower_bound = first_seen.timestamp() - FUSION_TIME_WINDOW_SECONDS
            upper_bound = last_seen.timestamp() + FUSION_TIME_WINDOW_SECONDS
            
            if lower_bound <= event_time.timestamp() <= upper_bound:
                if event_time < first_seen:
                    diff = first_seen.timestamp() - event_time.timestamp()
                elif event_time > last_seen:
                    diff = event_time.timestamp() - last_seen.timestamp()
                else:
                    diff = 0
                    
                valid_candidates.append({
                    "incident_id": row["incident_id"],
                    "last_seen": last_seen,
                    "diff": diff
                })
                
        if not valid_candidates:
            return None
            
        # Select: 1. smallest absolute time distance, 2. newest last_seen, 3. incident_id
        valid_candidates.sort(key=lambda x: (x["diff"], -x["last_seen"].timestamp(), x["incident_id"]))
        return valid_candidates[0]["incident_id"]

    def _create_incident(self, event: DetectionEvent, event_time: datetime, entities: List[Tuple[str, str]]):
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        event_time_str = event_time.isoformat()
        
        self.conn.execute("""
            INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (incident_id, now, now, event_time_str, event_time_str, event.severity.upper(), "OPEN"))
        
        self.conn.execute("""
            INSERT INTO incident_evidence (incident_id, detection_event_id)
            VALUES (?, ?)
        """, (incident_id, event.detection_event_id))
        
        for e_type, e_val in entities:
            self.conn.execute("""
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_value)
                VALUES (?, ?, ?)
            """, (incident_id, e_type, e_val))
            
        self.conn.execute("""
            INSERT OR REPLACE INTO assessment_state (incident_id, status, attempts, updated_at)
            VALUES (?, 'PENDING', 0, ?)
        """, (incident_id, now))

    def _attach_evidence(self, incident_id: str, event: DetectionEvent, event_time: datetime, entities: List[Tuple[str, str]]):
        # Idempotency check: if already attached, do nothing
        cursor = self.conn.execute("SELECT 1 FROM incident_evidence WHERE incident_id = ? AND detection_event_id = ?", (incident_id, event.detection_event_id))
        if cursor.fetchone():
            return
            
        cursor = self.conn.execute("SELECT first_seen, last_seen, max_severity FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        
        current_first = parse_utc_timestamp(row["first_seen"])
        current_last = parse_utc_timestamp(row["last_seen"])
        current_severity = row["max_severity"]
        
        new_first = min(current_first, event_time)
        new_last = max(current_last, event_time)
        new_severity = max_severity(current_severity, event.severity)
        now = datetime.now(timezone.utc).isoformat()
        
        self.conn.execute("""
            UPDATE incidents 
            SET updated_at = ?, first_seen = ?, last_seen = ?, max_severity = ?
            WHERE incident_id = ?
        """, (now, new_first.isoformat(), new_last.isoformat(), new_severity, incident_id))
        
        self.conn.execute("""
            INSERT OR IGNORE INTO incident_evidence (incident_id, detection_event_id)
            VALUES (?, ?)
        """, (incident_id, event.detection_event_id))
        
        for e_type, e_val in entities:
            self.conn.execute("""
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_value)
                VALUES (?, ?, ?)
            """, (incident_id, e_type, e_val))
            
        self.conn.execute("""
            INSERT OR REPLACE INTO assessment_state (incident_id, status, attempts, updated_at)
            VALUES (?, 'PENDING', 0, ?)
        """, (incident_id, now))
