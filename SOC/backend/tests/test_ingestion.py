import pytest
from fastapi.testclient import TestClient
import os
import tempfile
import sqlite3

# Set env vars before importing app
temp_dir = tempfile.TemporaryDirectory()
db_path = os.path.join(temp_dir.name, "test_soc.db")
os.environ["SOC_DB_PATH"] = db_path
os.environ["SOC_API_TOKEN"] = "test-token"

from app.main import app

client = TestClient(app)

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
    headers = {"Authorization": "Bearer test-token"}
    invalid_event = valid_event.copy()
    del invalid_event["confidence"]
    response = client.post("/api/v1/detection-events", json=invalid_event, headers=headers)
    assert response.status_code == 422 # FastAPI validation error

def test_valid_ingestion():
    headers = {"Authorization": "Bearer test-token"}
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["accepted"] is True
    assert data["duplicate"] is False
    assert data["detection_event_id"] == "test-123"

def test_duplicate_ingestion():
    headers = {"Authorization": "Bearer test-token"}
    # Sent again
    response = client.post("/api/v1/detection-events", json=valid_event, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["accepted"] is True
    assert data["duplicate"] is True
    assert data["detection_event_id"] == "test-123"
