from fastapi import FastAPI, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import sqlite3
import os

app = FastAPI(title="TGAM-SOC Central Ingestion")

API_TOKEN = os.getenv("SOC_API_TOKEN", "dev-token-123")
from app.models import DetectionEvent
from app import database
from app.worker import FusionWorker
from app.mitre_worker import MitreWorker
from app.assessment_worker import AssessmentWorker
from app.reasoning_worker import ReasoningWorker
from app.governance_worker import GovernanceWorker

fusion_worker = None
mitre_worker = None
assessment_worker = None
reasoning_worker = None
governance_worker = None

@app.on_event("startup")
def startup_event():
    database.init_db()
    global fusion_worker, mitre_worker, assessment_worker, reasoning_worker, governance_worker
    fusion_worker = FusionWorker()
    fusion_worker.start()
    mitre_worker = MitreWorker()
    mitre_worker.start()
    assessment_worker = AssessmentWorker()
    assessment_worker.start()
    reasoning_worker = ReasoningWorker()
    reasoning_worker.start()
    governance_worker = GovernanceWorker()
    governance_worker.start()

@app.on_event("shutdown")
def shutdown_event():
    global fusion_worker, mitre_worker, assessment_worker, reasoning_worker, governance_worker
    if fusion_worker:
        fusion_worker.stop()
        fusion_worker.join(timeout=5.0)
    if mitre_worker:
        mitre_worker.stop()
        mitre_worker.join(timeout=5.0)
    if assessment_worker:
        assessment_worker.stop()
        assessment_worker.join(timeout=5.0)
    if reasoning_worker:
        reasoning_worker.stop()
        reasoning_worker.join(timeout=5.0)
    if governance_worker:
        governance_worker.stop()
        governance_worker.join(timeout=5.0)

def get_db():
    conn = sqlite3.connect(database.DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
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
