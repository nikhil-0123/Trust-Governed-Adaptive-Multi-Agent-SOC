import json
import sqlite3
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

        domain_status = evidence.get("domain_status")
        target_account_id = evidence.get("target_account_id")
        target_user = evidence.get("target_user")
        raw_username = evidence.get("username") or getattr(event, "username", None)

        domain_account = None
        endpoint_account = None

        if domain_status in ("OBSERVED_DOMAIN", "EXPLICIT_DOMAIN") and target_account_id:
            domain_account = target_account_id
            entities.append(("domain_account", domain_account))
        elif domain_status == "LOCAL_SAM" and (target_user or target_account_id):
            u = target_user or (target_account_id.split("\\", 1)[-1] if target_account_id else "")
            endpoint_account = f"{event.agent_id}|LOCAL_SAM\\{u}"
            entities.append(("endpoint_account", endpoint_account))
        elif target_account_id and domain_status not in (None, "UNVERIFIED"):
            domain_account = target_account_id
            entities.append(("domain_account", domain_account))
        elif raw_username:
            endpoint_account = f"{event.agent_id}|{raw_username}"
            entities.append(("endpoint_account", endpoint_account))

        # WP-1E Phase 5: Check incident_anchors for historical anchor or re-evaluation
        if event.agent_id and event.source_event_id:
            try:
                anchor_cursor = self.conn.execute(
                    "SELECT incident_id FROM incident_anchors WHERE agent_id = ? AND source_event_id = ?",
                    (event.agent_id, event.source_event_id)
                )
                anchor_row = anchor_cursor.fetchone()
                if anchor_row:
                    anchored_incident_id = anchor_row["incident_id"] if isinstance(anchor_row, sqlite3.Row) else anchor_row[0]
                    self._attach_evidence(anchored_incident_id, event, event_time, entities, is_reevaluation=True)
                    return
            except sqlite3.OperationalError:
                pass

        candidate_incident_id = self._find_candidate_incident(
            hostname=hostname,
            source_ip=source_ip,
            event_time=event_time,
            agent_id=event.agent_id,
            domain_account=domain_account
        )

        if candidate_incident_id:
            incident_id = candidate_incident_id
            self._attach_evidence(incident_id, event, event_time, entities, is_reevaluation=False)
            if event.agent_id and event.source_event_id:
                try:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    self.conn.execute("""
                        INSERT OR IGNORE INTO incident_anchors (agent_id, source_event_id, incident_id, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (event.agent_id, event.source_event_id, incident_id, now_iso))
                except sqlite3.OperationalError:
                    pass
        else:
            # Need to create an incident. Use a SAVEPOINT to guard against concurrent anchor creation races.
            if event.agent_id and event.source_event_id:
                sp_name = f"sp_anchor_{uuid.uuid4().hex[:8]}"
                self.conn.execute(f"SAVEPOINT {sp_name}")
                try:
                    incident_id = self._create_incident(event, event_time, entities)
                    now_iso = datetime.now(timezone.utc).isoformat()
                    self.conn.execute("""
                        INSERT INTO incident_anchors (agent_id, source_event_id, incident_id, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (event.agent_id, event.source_event_id, incident_id, now_iso))
                    self.conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                except sqlite3.IntegrityError:
                    # Concurrency conflict: another worker already anchored (agent_id, source_event_id)!
                    # Rollback the savepoint to completely eliminate the speculative duplicate incident!
                    self.conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")

                    # Fetch the winning anchor and attach this event as HISTORICAL_RE_EVALUATION
                    anchor_cursor = self.conn.execute(
                        "SELECT incident_id FROM incident_anchors WHERE agent_id = ? AND source_event_id = ?",
                        (event.agent_id, event.source_event_id)
                    )
                    anchor_row = anchor_cursor.fetchone()
                    if anchor_row:
                        winning_id = anchor_row["incident_id"] if isinstance(anchor_row, sqlite3.Row) else anchor_row[0]
                        self._attach_evidence(winning_id, event, event_time, entities, is_reevaluation=True)
            else:
                self._create_incident(event, event_time, entities)

    def _filter_and_rank_candidates(self, candidates, event_time: datetime) -> Optional[str]:
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
            
        valid_candidates.sort(key=lambda x: (x["diff"], -x["last_seen"].timestamp(), x["incident_id"]))
        return valid_candidates[0]["incident_id"]

    def _find_candidate_incident(
        self,
        hostname: str,
        source_ip: Optional[str],
        event_time: datetime,
        agent_id: Optional[str] = None,
        domain_account: Optional[str] = None
    ) -> Optional[str]:
        # 1. Domain-account correlation across endpoints
        if domain_account:
            query = """
                SELECT i.incident_id, i.first_seen, i.last_seen
                FROM incidents i
                JOIN incident_entities e ON i.incident_id = e.incident_id
                WHERE i.status = 'OPEN'
                AND e.entity_type = 'domain_account' AND e.entity_value = ?
            """
            cursor = self.conn.execute(query, (domain_account,))
            match = self._filter_and_rank_candidates(cursor.fetchall(), event_time)
            if match:
                return match

        # 2. Hostname + optional source_ip + agent_id within time window
        query = """
            SELECT i.incident_id, i.first_seen, i.last_seen
            FROM incidents i
            JOIN incident_entities e ON i.incident_id = e.incident_id
            WHERE i.status = 'OPEN'
            AND e.entity_type = 'hostname' AND e.entity_value = ?
        """
        params = [hostname]

        if agent_id:
            query += """
                AND EXISTS (
                    SELECT 1 FROM incident_entities ea_match
                    WHERE ea_match.incident_id = i.incident_id
                    AND ea_match.entity_type = 'agent_id'
                    AND ea_match.entity_value = ?
                )
                AND NOT EXISTS (
                    SELECT 1 FROM incident_entities ea_conflict
                    WHERE ea_conflict.incident_id = i.incident_id
                    AND ea_conflict.entity_type = 'agent_id'
                    AND ea_conflict.entity_value != ?
                )
            """
            params.extend([agent_id, agent_id])
        else:
            query += """
                AND NOT EXISTS (
                    SELECT 1 FROM incident_entities ea_any
                    WHERE ea_any.incident_id = i.incident_id
                    AND ea_any.entity_type = 'agent_id'
                )
            """

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
        return self._filter_and_rank_candidates(cursor.fetchall(), event_time)

    def _create_incident(self, event: DetectionEvent, event_time: datetime, entities: List[Tuple[str, str]]):
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        event_time_str = event_time.isoformat()
        
        self.conn.execute("""
            INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (incident_id, now, now, event_time_str, event_time_str, event.severity.upper(), "OPEN"))
        
        try:
            self.conn.execute("""
                INSERT INTO incident_evidence (incident_id, detection_event_id, classification)
                VALUES (?, ?, 'PRIMARY_DETECTION')
            """, (incident_id, event.detection_event_id))
        except sqlite3.OperationalError:
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
        return incident_id

    def _attach_evidence(self, incident_id: str, event: DetectionEvent, event_time: datetime, entities: List[Tuple[str, str]], is_reevaluation: bool = False):
        classification = "HISTORICAL_RE_EVALUATION" if is_reevaluation else "PRIMARY_DETECTION"
        # Idempotency check: if already attached, do nothing (or update classification if re-evaluation)
        cursor = self.conn.execute("SELECT 1 FROM incident_evidence WHERE incident_id = ? AND detection_event_id = ?", (incident_id, event.detection_event_id))
        if cursor.fetchone():
            if is_reevaluation:
                try:
                    self.conn.execute("UPDATE incident_evidence SET classification = ? WHERE incident_id = ? AND detection_event_id = ?", (classification, incident_id, event.detection_event_id))
                except sqlite3.OperationalError:
                    pass
            return
            
        cursor = self.conn.execute("SELECT first_seen, last_seen, max_severity FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return

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
        
        try:
            self.conn.execute("""
                INSERT INTO incident_evidence (incident_id, detection_event_id, classification)
                VALUES (?, ?, ?)
                ON CONFLICT(incident_id, detection_event_id) DO UPDATE SET classification = excluded.classification
            """, (incident_id, event.detection_event_id, classification))
        except sqlite3.OperationalError:
            self.conn.execute("""
                INSERT OR IGNORE INTO incident_evidence (incident_id, detection_event_id)
                VALUES (?, ?)
            """, (incident_id, event.detection_event_id))

        try:
            self.conn.execute("UPDATE events SET classification = ? WHERE detection_event_id = ?", (classification, event.detection_event_id))
        except sqlite3.OperationalError:
            pass
        
        for e_type, e_val in entities:
            self.conn.execute("""
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_value)
                VALUES (?, ?, ?)
            """, (incident_id, e_type, e_val))
            
        self.conn.execute("""
            INSERT OR REPLACE INTO assessment_state (incident_id, status, attempts, updated_at)
            VALUES (?, 'PENDING', 0, ?)
        """, (incident_id, now))
        return incident_id
