import asyncio
from fastapi import FastAPI, Depends, HTTPException, Header, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Optional, List, Tuple
import sqlite3
import os
import uuid
from datetime import datetime, timezone

from app.epoch_governance import (
    ingest_event_transactional,
    process_channel_transition,
    resolve_epoch_gap,
    allocate_recovery_epoch,
    get_conflicts_query
)

app = FastAPI(title="TGAM-SOC Central Ingestion")

cors_origins_env = os.getenv(
    "SOC_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173,http://localhost:3000,http://127.0.0.1:3000"
)
cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins_env != "*" else ["*"],
    allow_origin_regex=r"^https?://.*",
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
    if os.getenv("DISABLE_STARTUP_WORKERS") == "1":
        return
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
    conn = sqlite3.connect(database.DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def extract_bearer_token(authorization: Optional[str]) -> str:
    """
    Hardened Bearer token parser.
    Validates the Bearer scheme and extracts a non-empty token.
    Rejects missing, empty, whitespace-only, and malformed authorization headers with HTTP 401.
    """
    if not authorization or not isinstance(authorization, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )
    parts = authorization.strip().split()
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header; expected 'Bearer <token>'"
        )
    scheme, token = parts[0], parts[1]
    if scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme; expected 'Bearer'"
        )
    token = token.strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty Bearer token"
        )
    return token

def verify_token(authorization: Optional[str] = Header(None)) -> str:
    """
    Endpoint authentication dependency.
    Requires a configured, non-empty SOC_API_TOKEN.
    Validates Authorization Bearer token against endpoint credentials.
    Does NOT require administrator credentials to be configured.
    Fails closed for missing or invalid endpoint credentials.
    """
    endpoint_token = os.getenv("SOC_API_TOKEN", "dev-token-123")

    if not endpoint_token or not endpoint_token.strip():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Endpoint credentials not configured; failing closed"
        )
    token = extract_bearer_token(authorization)
    if token == endpoint_token.strip():
        return token

    # Also accept valid per-agent tokens for general endpoint operations
    agent_tokens_env = os.getenv("SOC_AGENT_API_TOKENS")
    if agent_tokens_env:
        try:
            tokens_map = json.loads(agent_tokens_env)
            if isinstance(tokens_map, dict):
                for aid, atok in tokens_map.items():
                    if isinstance(atok, str) and atok.strip() == token:
                        return token
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized"
    )

def derive_authenticated_agent(authorization: Optional[str]) -> Tuple[str, str]:
    """
    Derives authenticated agent identity from trusted server-side per-agent credentials.
    Returns (authenticated_agent_id, token).
    Fails closed:
    - Raises 401 if authorization header is missing, malformed, or presents an unknown/invalid token.
    - Raises 403 if caller presents the generic shared endpoint token (SOC_API_TOKEN), which cannot prove endpoint identity.
    - Raises 503 if SOC_AGENT_API_TOKENS is missing, empty, or malformed on the server.
    """
    token = extract_bearer_token(authorization)

    # Check server-side per-agent credential registry (SOC_AGENT_API_TOKENS)
    agent_tokens_env = os.getenv("SOC_AGENT_API_TOKENS")
    if not agent_tokens_env or not agent_tokens_env.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Per-agent credential mapping (SOC_AGENT_API_TOKENS) is not configured; endpoint transitions unavailable"
        )

    try:
        tokens_map = json.loads(agent_tokens_env)
        if not isinstance(tokens_map, dict):
            raise ValueError("SOC_AGENT_API_TOKENS must be a JSON object mapping agent_id to token")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Per-agent credential mapping (SOC_AGENT_API_TOKENS) is malformed: {e}"
        )

    # Reject generic shared endpoint token from proving specific agent identity
    endpoint_token = os.getenv("SOC_API_TOKEN", "dev-token-123")
    if endpoint_token and token == endpoint_token.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Shared endpoint token cannot be treated as proof of agent identity; per-agent credentials required"
        )

    matched_agent = None
    for aid, atok in tokens_map.items():
        if isinstance(atok, str) and atok.strip() == token:
            matched_agent = aid
            break

    if not matched_agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unmapped agent credentials"
        )

    return matched_agent, token

def verify_admin_token(authorization: Optional[str] = Header(None)) -> str:
    """
    Dedicated administrative authorization dependency (WP-1E.4S).
    Derives trusted server-side administrator identity.
    Fails closed if administrative credentials are missing, unconfigured, or identical to endpoint credentials.
    Explicitly rejects endpoint agent credentials from performing admin actions.
    """
    admin_token = os.getenv("SOC_ADMIN_API_TOKEN") or os.getenv("SOC_ADMIN_TOKEN")
    endpoint_token = os.getenv("SOC_API_TOKEN", "dev-token-123")

    if not admin_token or not admin_token.strip():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Administrative credentials not configured; failing closed"
        )
    if not endpoint_token or not endpoint_token.strip():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Endpoint credentials not configured; failing closed"
        )
    if admin_token.strip() == endpoint_token.strip():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Administrative credentials cannot be identical to endpoint credentials; failing closed"
        )

    token = extract_bearer_token(authorization)

    # Reject endpoint credentials (shared or per-agent) from performing administrative operations
    if token == endpoint_token.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Endpoint credentials cannot perform administrative operations"
        )

    agent_tokens_env = os.getenv("SOC_AGENT_API_TOKENS")
    if agent_tokens_env:
        try:
            tokens_map = json.loads(agent_tokens_env)
        except Exception:
            tokens_map = {}
        if isinstance(tokens_map, dict):
            for aid, atok in tokens_map.items():
                if isinstance(atok, str) and atok.strip() == token:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Endpoint credentials cannot perform administrative operations"
                    )

    if token != admin_token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid administrator credentials"
        )
    return "SOC_ADMIN"

async def _extract_body_bytes(request: Any) -> bytes:
    if isinstance(request, (bytes, bytearray)):
        return bytes(request)
    if isinstance(request, str):
        return request.encode("utf-8")
    if hasattr(request, "model_dump_json"):
        return request.model_dump_json().encode("utf-8")
    if isinstance(request, dict):
        return json.dumps(request).encode("utf-8")
    if hasattr(request, "body"):
        body = request.body
        if callable(body):
            res = body()
            if asyncio.iscoroutine(res):
                return await res
            return res
        return body
    return b""

@app.post("/api/v1/detection-events", status_code=status.HTTP_201_CREATED)
async def ingest_event(request: Request, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    try:
        raw_bytes = await _extract_body_bytes(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read request body: {e}")

    status_code, resp_data = ingest_event_transactional(db, raw_bytes)
    return JSONResponse(status_code=status_code, content=resp_data)

SUPPORTED_TRANSITION_TYPES = {
    "EPOCH_ADVANCE",
    "LOG_CLEARED_SECURITY_REMOTE",
    "LOG_CLEARED_SYSTEM",
    "ADMINISTRATIVE_GAP_RESOLUTION",
    "RECOVERY",
    "RECOVERY_RELEASE",
    "GAP_RESOLUTION",
}

class ChannelTransitionRequest(BaseModel):
    transition_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    source_channel: str = Field(..., min_length=1)
    target_channel: Optional[str] = None
    target_epoch: int = Field(..., ge=1)
    transition_type: str = "EPOCH_ADVANCE"
    witness_payload: Optional[Dict[str, Any]] = None
    identity_manifest: Optional[Dict[str, Any]] = None
    recovery_request_id: Optional[str] = None
    resolution_reason: Optional[str] = None
    authorized_by: Optional[str] = None
    status: Optional[str] = None
    payload: Optional[Any] = None

    class Config:
        extra = "allow"

    @validator("transition_id", "agent_id", "source_channel")
    def validate_non_empty_strings(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Field must be a non-empty string")
        return v.strip()

    @validator("transition_type")
    def validate_transition_type(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("'transition_type' must be a non-empty string")
        val_upper = v.strip()
        if val_upper not in SUPPORTED_TRANSITION_TYPES:
            raise ValueError(f"Unsupported transition_type '{v}'. Allowed types: {sorted(SUPPORTED_TRANSITION_TYPES)}")
        return val_upper

@app.post("/api/v1/events/transition")
async def receive_channel_transition(
    request: Request,
    transition: ChannelTransitionRequest,
    authorization: Optional[str] = Header(None),
    db: sqlite3.Connection = Depends(get_db)
):
    transition_dict = transition.dict()
    try:
        raw_bytes = await _extract_body_bytes(request)
        if raw_bytes:
            extra_dict = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(extra_dict, dict):
                for k, v in extra_dict.items():
                    if k not in transition_dict or transition_dict[k] is None:
                        transition_dict[k] = v
    except Exception:
        pass

    ttype = transition.transition_type
    from app.response_bridge import AUTHORIZED_RECOVERY_TRANSITION_TYPES

    # If submitting an administrative recovery transition, require admin authentication
    if ttype in AUTHORIZED_RECOVERY_TRANSITION_TYPES:
        try:
            admin_principal = verify_admin_token(authorization)
        except HTTPException as he:
            return JSONResponse(status_code=he.status_code, content={"detail": he.detail})
        # Server derives authenticated actor; caller-supplied actor/status cannot establish authorization
        status_code, resp_data = process_channel_transition(
            db, transition_dict, authenticated_actor=admin_principal
        )
    else:
        # Normal sequential advancement by endpoint agents
        claimed_agent_id = transition.agent_id

        try:
            auth_agent, token = derive_authenticated_agent(authorization)
        except HTTPException as he:
            return JSONResponse(status_code=he.status_code, content={"detail": he.detail})

        # Strict identity matching: authenticated identity MUST match claimed agent_id
        if auth_agent != claimed_agent_id:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": f"Authenticated endpoint identity '{auth_agent}' does not match transition agent '{claimed_agent_id}'"}
            )

        status_code, resp_data = process_channel_transition(
            db, transition_dict, authenticated_actor=auth_agent
        )

    return JSONResponse(status_code=status_code, content=resp_data)

@app.post("/api/v1/agents/{agent_id}/channels/{channel}/allocate_epoch")
async def allocate_epoch_endpoint(
    agent_id: str,
    channel: str,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: sqlite3.Connection = Depends(get_db)
):
    admin_token = os.getenv("SOC_ADMIN_API_TOKEN") or os.getenv("SOC_ADMIN_TOKEN")
    is_admin = False
    try:
        tok = extract_bearer_token(authorization)
        if admin_token and tok == admin_token.strip():
            is_admin = True
    except Exception:
        pass

    if not is_admin:
        try:
            auth_agent, token = derive_authenticated_agent(authorization)
        except HTTPException as he:
            return JSONResponse(status_code=he.status_code, content={"detail": he.detail})

        if auth_agent != agent_id:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": f"Authenticated endpoint identity '{auth_agent}' does not match path agent '{agent_id}'"}
            )

    raw_bytes = await _extract_body_bytes(request)
    try:
        body = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        return JSONResponse(status_code=400, content={"detail": f"Invalid JSON: {e}"})

    req_id = body.get("recovery_request_id")
    reason = body.get("recovery_reason")
    status_code, resp_data = allocate_recovery_epoch(db, req_id, agent_id, channel, reason)
    return JSONResponse(status_code=status_code, content=resp_data)

@app.post("/api/v1/agents/{agent_id}/channels/{channel}/resolve_gap")
async def resolve_gap_endpoint(
    agent_id: str,
    channel: str,
    request: Request,
    admin_principal: str = Depends(verify_admin_token),
    db: sqlite3.Connection = Depends(get_db)
):
    raw_bytes = await _extract_body_bytes(request)
    try:
        body = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        return JSONResponse(status_code=400, content={"detail": f"Invalid JSON: {e}"})

    target_epoch = body.get("target_epoch")
    reason = body.get("resolution_reason", "Administrative gap override")
    rec_req_id = body.get("recovery_request_id")
    # Derived from server authentication context (admin_principal), NEVER from caller JSON!
    status_code, resp_data = resolve_epoch_gap(
        db, agent_id, channel, target_epoch, reason,
        authorized_by=admin_principal,
        recovery_request_id=rec_req_id
    )
    return JSONResponse(status_code=status_code, content=resp_data)

@app.get("/api/v1/conflicts")
def get_all_conflicts_endpoint(
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    return get_conflicts_query(db)

@app.get("/api/v1/conflicts/{event_id}")
def get_event_conflicts_endpoint(
    event_id: str,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    return get_conflicts_query(db, event_id=event_id)

import json

@app.get("/api/v1/incidents", response_model=List[Incident])
def get_incidents(token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("""
        SELECT i.*, 
               gs.approval_status,
               gd.decision as governance_decision
        FROM incidents i
        LEFT JOIN governance_state gs ON i.incident_id = gs.incident_id
        LEFT JOIN governance_decisions gd ON gs.decision_id = gd.decision_id
        ORDER BY i.updated_at DESC LIMIT 100
    """)
    incidents = []
    rows = cursor.fetchall()
    for row in rows:
        d = dict(row)
        inc_id = d["incident_id"]
        cmds = db.execute("SELECT command_type FROM endpoint_commands WHERE parameters LIKE ?", (f'%"{inc_id}"%',)).fetchall()
        d["mitigation_dispatched_count"] = len(cmds)
        d["dispatched_command_types"] = [c["command_type"].upper() for c in cmds]
        incidents.append(Incident(**d))
    return incidents

@app.get("/api/v1/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str, token: str = Depends(verify_token), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("""
        SELECT i.*, 
               gs.approval_status,
               gd.decision as governance_decision
        FROM incidents i
        LEFT JOIN governance_state gs ON i.incident_id = gs.incident_id
        LEFT JOIN governance_decisions gd ON gs.decision_id = gd.decision_id
        WHERE i.incident_id = ?
    """, (incident_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    d = dict(row)
    cmds = db.execute("SELECT command_type FROM endpoint_commands WHERE parameters LIKE ?", (f'%"{incident_id}"%',)).fetchall()
    d["mitigation_dispatched_count"] = len(cmds)
    d["dispatched_command_types"] = [c["command_type"].upper() for c in cmds]
    return Incident(**d)

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


@app.delete("/api/v1/endpoints/{agent_id}")
def delete_endpoint(
    agent_id: str,
    token: str = Depends(verify_token),
    db: sqlite3.Connection = Depends(get_db)
):
    # Clean up associated commands first to satisfy foreign keys
    db.execute("DELETE FROM endpoint_commands WHERE agent_id = ?", (agent_id,))
    cursor = db.execute("DELETE FROM endpoints WHERE agent_id = ?", (agent_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Endpoint agent not found")
    db.commit()
    return {"acknowledged": True, "agent_id": agent_id, "deleted": True}


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
