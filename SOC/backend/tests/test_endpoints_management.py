import pytest
import sqlite3
import os
import json
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from app.main import app, get_db, API_TOKEN
import app.database as database

TEST_DB = "test_endpoints_soc.db"

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", TEST_DB)
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass
    database.init_db()

    def override_get_db():
        conn = sqlite3.connect(TEST_DB)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass

client = TestClient(app)
headers = {"Authorization": f"Bearer {API_TOKEN}"}

def test_endpoint_heartbeat_and_listing():
    # Send initial heartbeat
    payload = {
        "agent_id": "win-agent-01",
        "hostname": "win-emp-pc",
        "os": "windows",
        "ip_address": "192.168.1.101",
        "agent_version": "1.0.0",
        "capabilities": ["EventLog_4625", "EventLog_4688"]
    }
    res = client.post("/api/v1/endpoints/heartbeat", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["acknowledged"] is True
    assert data["commands"] == []

    # Query list
    res_list = client.get("/api/v1/endpoints", headers=headers)
    assert res_list.status_code == 200
    eps = res_list.json()
    assert len(eps) == 1
    assert eps[0]["agent_id"] == "win-agent-01"
    assert eps[0]["status"] == "ONLINE"
    assert "EventLog_4625" in eps[0]["capabilities"]

def test_endpoint_command_lifecycle():
    # 1. Register agent
    client.post("/api/v1/endpoints/heartbeat", json={
        "agent_id": "ubuntu-agent-01",
        "hostname": "ubuntu-emp-pc",
        "os": "linux",
        "capabilities": ["AuthLog_SSH"]
    }, headers=headers)

    # 2. Dispatch command (PING)
    cmd_res = client.post("/api/v1/endpoints/ubuntu-agent-01/commands", json={
        "command_type": "PING",
        "parameters": {"test_id": 42}
    }, headers=headers)
    assert cmd_res.status_code == 201
    cmd = cmd_res.json()
    cmd_id = cmd["command_id"]
    assert cmd["status"] == "PENDING"
    assert cmd["command_type"] == "PING"

    # 3. Agent heartbeats again -> should pick up the command
    hb_res = client.post("/api/v1/endpoints/heartbeat", json={
        "agent_id": "ubuntu-agent-01",
        "hostname": "ubuntu-emp-pc",
        "os": "linux"
    }, headers=headers)
    hb_data = hb_res.json()
    assert len(hb_data["commands"]) == 1
    assert hb_data["commands"][0]["command_id"] == cmd_id

    # 4. Agent reports command execution result
    result_res = client.post(f"/api/v1/endpoints/ubuntu-agent-01/commands/{cmd_id}/result", json={
        "status": "EXECUTED",
        "result": {"pong": True, "latency_ms": 5}
    }, headers=headers)
    assert result_res.status_code == 200

    # 5. Verify command history
    hist_res = client.get("/api/v1/endpoints/ubuntu-agent-01/commands", headers=headers)
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert len(history) == 1
    assert history[0]["command_id"] == cmd_id
    assert history[0]["status"] == "EXECUTED"
    assert history[0]["result"]["pong"] is True

def test_endpoint_timeout_status():
    conn = sqlite3.connect(TEST_DB)
    # Insert endpoint with old timestamp (> 60s ago)
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    conn.execute("""
        INSERT INTO endpoints (agent_id, hostname, os, status, last_heartbeat)
        VALUES ('stale-agent', 'stale-pc', 'windows', 'ONLINE', ?)
    """, (old_time,))
    conn.commit()
    conn.close()

    res = client.get("/api/v1/endpoints", headers=headers)
    assert res.status_code == 200
    eps = [e for e in res.json() if e["agent_id"] == "stale-agent"]
    assert len(eps) == 1
    assert eps[0]["status"] == "OFFLINE"
