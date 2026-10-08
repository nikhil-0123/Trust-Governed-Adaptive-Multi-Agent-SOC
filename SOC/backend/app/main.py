from fastapi import FastAPI, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
import sqlite3
import os

app = FastAPI(title="TGAM-SOC Central Ingestion")

API_TOKEN = os.getenv("SOC_API_TOKEN", "dev-token-123")
from app.models import (
    DetectionEvent, Incident, IncidentEntity, ThreatContext,
    Assessment, Analysis, GovernanceDecision, ProvenanceHistory, AnalystOverrideRequest
)
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
    conn.row_factory = sqlite3.Row
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

import json

@app.get("/api/v1/incidents", response_model=List[Incident])
def get_incidents(token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT 100")
    incidents = []
    for row in cursor.fetchall():
        d = dict(row)
        incidents.append(Incident(**d))
    return incidents

@app.get("/api/v1/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return Incident(**dict(row))

@app.get("/api/v1/incidents/{incident_id}/evidence", response_model=List[DetectionEvent])
def get_incident_evidence(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("""
        SELECT e.data FROM events e
        JOIN incident_evidence ie ON e.detection_event_id = ie.detection_event_id
        WHERE ie.incident_id = ?
    """, (incident_id,))
    events = []
    for row in cursor.fetchall():
        try:
            events.append(DetectionEvent.model_validate_json(row["data"]))
        except Exception:
            pass
    return events

@app.get("/api/v1/incidents/{incident_id}/entities", response_model=List[IncidentEntity])
def get_incident_entities(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT * FROM incident_entities WHERE incident_id = ?", (incident_id,))
    return [IncidentEntity(**dict(row)) for row in cursor.fetchall()]

@app.get("/api/v1/incidents/{incident_id}/mitre", response_model=List[ThreatContext])
def get_incident_mitre(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT * FROM threat_context WHERE incident_id = ?", (incident_id,))
    return [ThreatContext(**dict(row)) for row in cursor.fetchall()]

@app.get("/api/v1/incidents/{incident_id}/assessment", response_model=Assessment)
def get_incident_assessment(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT latest_assessment_id FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row or not row["latest_assessment_id"]:
        raise HTTPException(status_code=404, detail="Assessment not found")

    a_cursor = db.execute("SELECT * FROM assessments WHERE assessment_id = ?", (row["latest_assessment_id"],))
    a_row = a_cursor.fetchone()
    if not a_row:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return Assessment(**dict(a_row))

@app.get("/api/v1/incidents/{incident_id}/analysis", response_model=Analysis)
def get_incident_analysis(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT latest_analysis_id FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row or not row["latest_analysis_id"]:
        raise HTTPException(status_code=404, detail="Analysis not found")

    an_cursor = db.execute("SELECT * FROM analyses WHERE analysis_id = ?", (row["latest_analysis_id"],))
    an_row = an_cursor.fetchone()
    if not an_row:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return Analysis(**dict(an_row))

@app.get("/api/v1/incidents/{incident_id}/decision", response_model=GovernanceDecision)
def get_incident_decision(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT decision_id FROM governance_state WHERE incident_id = ? AND status = 'DECIDED'", (incident_id,))
    row = cursor.fetchone()
    if not row or not row["decision_id"]:
        raise HTTPException(status_code=404, detail="Decision not found")

    gd_cursor = db.execute("SELECT * FROM governance_decisions WHERE decision_id = ?", (row["decision_id"],))
    gd_row = gd_cursor.fetchone()
    if not gd_row:
        raise HTTPException(status_code=404, detail="Decision not found")
    return GovernanceDecision(**dict(gd_row))

@app.get("/api/v1/incidents/{incident_id}/history", response_model=ProvenanceHistory)
def get_incident_history(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    inc_cursor = db.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    inc_row = inc_cursor.fetchone()
    if not inc_row:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = Incident(**dict(inc_row))
    assessment = None
    if incident.latest_assessment_id:
        a_row = db.execute("SELECT * FROM assessments WHERE assessment_id = ?", (incident.latest_assessment_id,)).fetchone()
        if a_row: assessment = Assessment(**dict(a_row))

    analysis = None
    if incident.latest_analysis_id:
        an_row = db.execute("SELECT * FROM analyses WHERE analysis_id = ?", (incident.latest_analysis_id,)).fetchone()
        if an_row: analysis = Analysis(**dict(an_row))

    decision = None
    gs_row = db.execute("SELECT decision_id FROM governance_state WHERE incident_id = ? AND status = 'DECIDED'", (incident_id,)).fetchone()
    if gs_row and gs_row["decision_id"]:
        gd_row = db.execute("SELECT * FROM governance_decisions WHERE decision_id = ?", (gs_row["decision_id"],)).fetchone()
        if gd_row: decision = GovernanceDecision(**dict(gd_row))

    historical_decisions = []
    gd_cursor = db.execute("SELECT * FROM governance_decisions WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,))
    for row in gd_cursor.fetchall():
        historical_decisions.append(GovernanceDecision(**dict(row)))

    return ProvenanceHistory(
        incident=incident,
        assessment=assessment,
        analysis=analysis,
        decision=decision,
        historical_decisions=historical_decisions
    )

@app.post("/api/v1/incidents/{incident_id}/governance/override", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def override_decision(incident_id: str, req: AnalystOverrideRequest, token: str = Depends(verify_token)):
    raise HTTPException(
        status_code=501,
        detail="Current architecture enforces unique (incident, assessment, analysis) decisions and does not support append-only analyst overrides."
    )
