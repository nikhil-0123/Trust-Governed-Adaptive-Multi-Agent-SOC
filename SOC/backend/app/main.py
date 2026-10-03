from fastapi import FastAPI, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import sqlite3
import os

app = FastAPI(title="TGAM-SOC Central Ingestion")

API_TOKEN = os.getenv("SOC_API_TOKEN", "dev-token-123")
DB_PATH = os.getenv("SOC_DB_PATH", "soc_central.db")

class DetectionEvent(BaseModel):
    detection_event_id: str
    timestamp: str
    agent_id: str
    hostname: str
    os: str
    source_event_id: str
    detection_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    detector_name: str
    evidence: Dict[str, Any]

def get_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                detection_event_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        yield conn
    finally:
        conn.close()

def verify_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token

@app.post("/api/v1/detection-events", status_code=status.HTTP_201_CREATED)
def ingest_event(event: DetectionEvent, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    try:
        cursor = db.execute("SELECT 1 FROM events WHERE detection_event_id = ?", (event.detection_event_id,))
        if cursor.fetchone():
            return {"accepted": True, "detection_event_id": event.detection_event_id, "duplicate": True}
            
        db.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", (event.detection_event_id, event.model_dump_json()))
        db.commit()
        return {"accepted": True, "detection_event_id": event.detection_event_id, "duplicate": False}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database Error")
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")
