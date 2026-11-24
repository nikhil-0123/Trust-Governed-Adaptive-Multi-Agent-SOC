import pytest
from fastapi.testclient import TestClient
import os
import tempfile
import sqlite3

import app.database
import app.main

@pytest.fixture(autouse=True)
def setup_env():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app.database.DB_PATH = db_path
    app.database.init_db()

    orig_api_token = os.environ.get("SOC_API_TOKEN")
    orig_admin_token = os.environ.get("SOC_ADMIN_API_TOKEN")
    os.environ["SOC_API_TOKEN"] = "dev-token-123"
    os.environ["SOC_ADMIN_API_TOKEN"] = "dev-admin-secret-token"

    yield

    if orig_api_token is not None:
        os.environ["SOC_API_TOKEN"] = orig_api_token
    else:
        os.environ.pop("SOC_API_TOKEN", None)

    if orig_admin_token is not None:
        os.environ["SOC_ADMIN_API_TOKEN"] = orig_admin_token
    else:
        os.environ.pop("SOC_ADMIN_API_TOKEN", None)

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except:
        pass

client = TestClient(app.main.app)

valid_event = {
    "detection_event_id": "test-123",
    "timestamp": "2026-10-03T20:00:00Z",
    "agent_id": "agent-1",
    "hostname": "PC-1",
    "os": "Windows",
    "source_event_id": "src-1",
    "detection_type": "windows_bruteforce_rule",
    "confidence": 1.0,
    "severity": "high",
    "detector_name": "test-detector",
    "evidence": {"user": "admin"}
}

def test_missing_auth():
    response = client.post("/api/v1/detection-events", json=valid_event)
    assert response.status_code == 401

def test_invalid_auth():
    headers = {"Authorization": "Bearer wrong-token"}
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 401

def test_valid_auth_invalid_schema():
    headers = {"Authorization": "Bearer dev-token-123"}
    invalid_event = valid_event.copy()
    del invalid_event["confidence"]
    response = client.post("/api/v1/detection-events", json=invalid_event, headers=headers)
    assert response.status_code == 422 # FastAPI validation error

def test_valid_ingestion():
    headers = {"Authorization": "Bearer dev-token-123"}
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["accepted"] is True
    assert data["duplicate"] is False
    assert data["detection_event_id"] == "test-123"

def test_duplicate_ingestion():
    headers = {"Authorization": "Bearer dev-token-123"}
    # Sent first time
    client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    # Sent again
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["accepted"] is True
    assert data["duplicate"] is True
    assert data["detection_event_id"] == "test-123"

# =========================================================================
# Task 4 — Complete Event Schema Validation Regression Tests
# =========================================================================

@pytest.mark.parametrize("missing_field", [
    "timestamp",
    "hostname",
    "source_event_id",
    "detection_type",
    "severity",
    "detector_name",
    "evidence"
])
def test_missing_required_fields_rejected(missing_field):
    headers = {"Authorization": "Bearer dev-token-123"}
    ev = valid_event.copy()
    del ev[missing_field]
    response = client.post("/api/v1/detection-events", json=ev, headers=headers)
    assert response.status_code == 422
    assert "Schema validation error" in response.json()["detail"] or "required" in response.json()["detail"]

def test_evidence_non_object_rejected():
    headers = {"Authorization": "Bearer dev-token-123"}
    ev = valid_event.copy()
    ev["evidence"] = "not a dictionary"
    response = client.post("/api/v1/detection-events", json=ev, headers=headers)
    assert response.status_code == 422

def test_confidence_boolean_rejected():
    headers = {"Authorization": "Bearer dev-token-123"}
    ev = valid_event.copy()
    ev["confidence"] = True
    response = client.post("/api/v1/detection-events", json=ev, headers=headers)
    assert response.status_code == 422
    assert "booleans are not allowed" in response.json()["detail"]

# =========================================================================
# Task 5 — Hardened Bearer Token Parsing Regression Tests
# =========================================================================

def test_bearer_non_bearer_scheme_rejected():
    headers = {"Authorization": "Basic dev-token-123"}
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 401
    assert "expected 'Bearer'" in response.json()["detail"]

def test_bearer_empty_token_rejected():
    for empty_header in ["Bearer", "Bearer ", "Bearer    "]:
        headers = {"Authorization": empty_header}
        response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
        assert response.status_code == 401

def test_bearer_malformed_multi_word_rejected():
    headers = {"Authorization": "Bearer token1 token2"}
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 401
    assert "Malformed Authorization header" in response.json()["detail"]

def test_bearer_extra_whitespace_accepted():
    headers = {"Authorization": "Bearer   dev-token-123   "}
    ev = valid_event.copy()
    ev["detection_event_id"] = "test-extra-whitespace"
    response = client.post("/api/v1/detection-events", json=ev, headers=headers)
    assert response.status_code == 201
    assert response.json()["accepted"] is True

def test_bearer_case_insensitive_scheme_accepted():
    headers = {"Authorization": "bearer dev-token-123"}
    ev = valid_event.copy()
    ev["detection_event_id"] = "test-case-insensitive"
    response = client.post("/api/v1/detection-events", json=ev, headers=headers)
    assert response.status_code == 201
    assert response.json()["accepted"] is True
