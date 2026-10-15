from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
import sqlite3
import os
import uuid
from datetime import datetime, timezone

app = FastAPI(title="TGAM-SOC Central Ingestion")

cors_origins_env = os.getenv(
    "SOC_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173,http://localhost:3000,http://127.0.0.1:3000"
)
cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_TOKEN = os.getenv("SOC_API_TOKEN", "dev-token-123")
from app.models import (
    DetectionEvent, Incident, IncidentEntity, ThreatContext,
    Assessment, Analysis, GovernanceDecision, ProvenanceHistory, AnalystOverrideRequest,
    EndpointHeartbeat, EndpointCommandCreate, EndpointCommand, EndpointCommandResult, EndpointInfo,
    GovernanceApprovalRequest, GovernanceRejectionRequest, IncidentGovernanceStatus
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

@app.get("/api/v1/mitre/matrix")
def get_mitre_matrix(token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("""
        SELECT tc.technique_id, tc.technique_name, tc.tactic, tc.mitre_version,
               COUNT(DISTINCT tc.incident_id) as incident_count,
               COUNT(tce.detection_event_id) as event_count,
               GROUP_CONCAT(DISTINCT tc.incident_id) as incident_ids
        FROM threat_context tc
        LEFT JOIN threat_context_evidence tce ON tc.context_id = tce.context_id
        GROUP BY tc.technique_id, tc.technique_name, tc.tactic, tc.mitre_version
    """)
    matrix = []
    for row in cursor.fetchall():
        d = dict(row)
        d["incident_ids"] = [i.strip() for i in d["incident_ids"].split(",") if i.strip()] if d.get("incident_ids") else []
        matrix.append(d)
    return matrix

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

@app.get("/api/v1/incidents/{incident_id}/governance", response_model=IncidentGovernanceStatus)
def get_incident_governance_status(
    incident_id: str,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    inc = db.execute("SELECT incident_id, latest_analysis_id FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    gs = db.execute("SELECT * FROM governance_state WHERE incident_id = ?", (incident_id,)).fetchone()
    if not gs:
        raise HTTPException(status_code=404, detail="Governance state not found for incident")

    decision = None
    reason = None
    if gs["decision_id"]:
        gd = db.execute("SELECT decision, reason FROM governance_decisions WHERE decision_id = ?", (gs["decision_id"],)).fetchone()
        if gd:
            decision = gd["decision"]
            reason = gd["reason"]

    # Recommendations from latest analysis
    recs = []
    if inc["latest_analysis_id"]:
        an_row = db.execute("SELECT analysis_output FROM analyses WHERE analysis_id = ?", (inc["latest_analysis_id"],)).fetchone()
        if an_row:
            try:
                an_data = json.loads(an_row["analysis_output"])
                recs = an_data.get("recommendations", [])
            except Exception:
                pass

    # Dispatched commands associated with this incident
    cmds = []
    cmd_cursor = db.execute("""
        SELECT * FROM endpoint_commands 
        WHERE parameters LIKE ?
        ORDER BY created_at DESC
    """, (f'%"{incident_id}"%',))
    for row in cmd_cursor.fetchall():
        d = dict(row)
        if d.get("parameters"):
            try:
                d["parameters"] = json.loads(d["parameters"])
            except Exception:
                pass
        if d.get("result"):
            try:
                d["result"] = json.loads(d["result"])
            except Exception:
                pass
        cmds.append(EndpointCommand(**d))

    return IncidentGovernanceStatus(
        incident_id=incident_id,
        decision_id=gs["decision_id"],
        decision=decision,
        approval_status=gs["approval_status"],
        reason=reason,
        recommendations=recs,
        dispatched_commands=cmds,
        updated_at=gs["updated_at"]
    )

@app.post("/api/v1/incidents/{incident_id}/governance/approve")
def approve_governance_mitigation(
    incident_id: str,
    req: GovernanceApprovalRequest = GovernanceApprovalRequest(),
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    inc = db.execute("SELECT incident_id, latest_analysis_id FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    gs = db.execute("SELECT * FROM governance_state WHERE incident_id = ?", (incident_id,)).fetchone()
    if not gs or gs["status"] != "DECIDED":
        raise HTTPException(status_code=400, detail="Incident has not completed governance evaluation")

    if req.action:
        cmds = db.execute(
            "SELECT command_type FROM endpoint_commands WHERE parameters LIKE ?",
            (f'%"{incident_id}"%',)
        ).fetchall()
        dispatched_types = [c["command_type"].upper() for c in cmds]
        if req.action.upper() in dispatched_types:
            return {
                "acknowledged": True,
                "incident_id": incident_id,
                "approval_status": gs["approval_status"],
                "message": f"Action '{req.action}' already dispatched for this incident",
                "dispatched_count": 0,
                "dispatched_commands": []
            }
    elif gs["approval_status"] == "APPROVED":
        return {
            "acknowledged": True,
            "incident_id": incident_id,
            "approval_status": "APPROVED",
            "message": "Mitigation already approved",
            "dispatched_count": 0,
            "dispatched_commands": []
        }

    recommendations = []
    if inc["latest_analysis_id"]:
        an_row = db.execute("SELECT analysis_output FROM analyses WHERE analysis_id = ?", (inc["latest_analysis_id"],)).fetchone()
        if an_row:
            try:
                an_data = json.loads(an_row["analysis_output"])
                recommendations = an_data.get("recommendations", [])
            except Exception:
                pass

    from app.response_bridge import dispatch_governed_response
    dispatched = dispatch_governed_response(
        db,
        incident_id,
        recommendations=recommendations,
        approved_by=req.analyst_name or "soc_analyst",
        target_action=req.action,
        custom_params=req.custom_params
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    db.execute("""
        UPDATE governance_state
        SET approval_status = 'APPROVED', updated_at = ?
        WHERE incident_id = ?
    """, (now_iso, incident_id))
    db.commit()

    return {
        "acknowledged": True,
        "incident_id": incident_id,
        "approval_status": "APPROVED",
        "approved_by": req.analyst_name or "soc_analyst",
        "dispatched_count": len(dispatched),
        "dispatched_commands": dispatched
    }

@app.post("/api/v1/incidents/{incident_id}/governance/reject")
def reject_governance_mitigation(
    incident_id: str,
    req: GovernanceRejectionRequest,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    inc = db.execute("SELECT incident_id FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    gs = db.execute("SELECT * FROM governance_state WHERE incident_id = ?", (incident_id,)).fetchone()
    if not gs or gs["status"] != "DECIDED":
        raise HTTPException(status_code=400, detail="Incident has not completed governance evaluation")

    now_iso = datetime.now(timezone.utc).isoformat()
    db.execute("""
        UPDATE governance_state
        SET approval_status = 'REJECTED', updated_at = ?
        WHERE incident_id = ?
    """, (now_iso, incident_id))
    db.commit()

    return {
        "acknowledged": True,
        "incident_id": incident_id,
        "approval_status": "REJECTED",
        "rejected_by": req.analyst_name or "soc_analyst",
        "reason": req.reason
    }


# ---------------------------------------------------------
# Telemetry Device Management & Remote Commands
# ---------------------------------------------------------

@app.post("/api/v1/endpoints/heartbeat")
def receive_heartbeat(
    payload: EndpointHeartbeat,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    now_str = datetime.now(timezone.utc).isoformat()
    caps_json = json.dumps(payload.capabilities or [])

    # Upsert endpoint registry
    db.execute("""
        INSERT INTO endpoints (agent_id, hostname, os, ip_address, status, last_heartbeat, agent_version, capabilities)
        VALUES (?, ?, ?, ?, 'ONLINE', ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname,
            os = excluded.os,
            ip_address = excluded.ip_address,
            status = 'ONLINE',
            last_heartbeat = excluded.last_heartbeat,
            agent_version = excluded.agent_version,
            capabilities = excluded.capabilities
    """, (payload.agent_id, payload.hostname, payload.os, payload.ip_address, now_str, payload.agent_version, caps_json))

    # Retrieve pending commands for this agent
    cursor = db.execute("""
        SELECT * FROM endpoint_commands
        WHERE agent_id = ? AND status = 'PENDING'
        ORDER BY created_at ASC
    """, (payload.agent_id,))

    pending_commands = []
    cmd_ids_to_send = []
    for row in cursor.fetchall():
        d = dict(row)
        if d.get("parameters"):
            try:
                d["parameters"] = json.loads(d["parameters"])
            except Exception:
                pass
        if d.get("result"):
            try:
                d["result"] = json.loads(d["result"])
            except Exception:
                pass
        pending_commands.append(d)
        cmd_ids_to_send.append(d["command_id"])

    # Mark dispatched commands as SENT
    for cid in cmd_ids_to_send:
        db.execute("UPDATE endpoint_commands SET status = 'SENT', updated_at = ? WHERE command_id = ?", (now_str, cid))

    db.commit()
    return {"acknowledged": True, "agent_id": payload.agent_id, "commands": pending_commands}


@app.get("/api/v1/endpoints", response_model=List[EndpointInfo])
def list_endpoints(
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.execute("SELECT * FROM endpoints ORDER BY last_heartbeat DESC")
    endpoints = []
    now = datetime.now(timezone.utc)
    for row in cursor.fetchall():
        d = dict(row)
        try:
            d["capabilities"] = json.loads(d["capabilities"]) if d.get("capabilities") else []
        except Exception:
            d["capabilities"] = []

        try:
            hb_str = d["last_heartbeat"].replace("Z", "+00:00")
            hb_time = datetime.fromisoformat(hb_str)
            if hb_time.tzinfo is None:
                hb_time = hb_time.replace(tzinfo=timezone.utc)
            delta_sec = (now - hb_time).total_seconds()
            if delta_sec > 60:
                d["status"] = "OFFLINE"
            else:
                d["status"] = "ONLINE"
        except Exception:
            d["status"] = "OFFLINE"

        endpoints.append(EndpointInfo(**d))
    return endpoints


@app.post("/api/v1/endpoints/{agent_id}/commands", response_model=EndpointCommand, status_code=status.HTTP_201_CREATED)
def dispatch_command(
    agent_id: str,
    cmd_in: EndpointCommandCreate,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    ep = db.execute("SELECT 1 FROM endpoints WHERE agent_id = ?", (agent_id,)).fetchone()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint agent not found")

    cmd_id = str(uuid.uuid4())
    now_str = datetime.now(timezone.utc).isoformat()
    params_json = json.dumps(cmd_in.parameters or {})

    db.execute("""
        INSERT INTO endpoint_commands (command_id, agent_id, command_type, parameters, status, result, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'PENDING', NULL, ?, ?)
    """, (cmd_id, agent_id, cmd_in.command_type.upper(), params_json, now_str, now_str))
    db.commit()

    return EndpointCommand(
        command_id=cmd_id,
        agent_id=agent_id,
        command_type=cmd_in.command_type.upper(),
        parameters=cmd_in.parameters,
        status="PENDING",
        result=None,
        created_at=now_str,
        updated_at=now_str
    )


@app.post("/api/v1/endpoints/{agent_id}/commands/{command_id}/result")
def submit_command_result(
    agent_id: str,
    command_id: str,
    res: EndpointCommandResult,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    now_str = datetime.now(timezone.utc).isoformat()
    result_json = json.dumps(res.result or {})

    cursor = db.execute("""
        UPDATE endpoint_commands
        SET status = ?, result = ?, updated_at = ?
        WHERE command_id = ? AND agent_id = ?
    """, (res.status.upper(), result_json, now_str, command_id, agent_id))

    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Command not found for this agent")

    db.commit()
    return {"acknowledged": True, "command_id": command_id, "status": res.status.upper()}


@app.get("/api/v1/endpoints/{agent_id}/commands", response_model=List[EndpointCommand])
def get_endpoint_commands(
    agent_id: str,
    limit: int = 20,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.execute("""
        SELECT * FROM endpoint_commands
        WHERE agent_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (agent_id, limit))

    commands = []
    for row in cursor.fetchall():
        d = dict(row)
        if d.get("parameters"):
            try:
                d["parameters"] = json.loads(d["parameters"])
            except Exception:
                pass
        if d.get("result"):
            try:
                d["result"] = json.loads(d["result"])
            except Exception:
                pass
        commands.append(EndpointCommand(**d))
    return commands
