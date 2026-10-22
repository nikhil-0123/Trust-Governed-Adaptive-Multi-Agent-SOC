#!/usr/bin/env python3
"""
TGAM-SOC — 5 Core Attacks Demonstration Suite
Covers:
  1. Brute Force (T1110)
  2. Phishing Attack (T1566)
  3. Malware / Ransomware (T1204 / T1486)
  4. Denial of Service - DoS (T1498)
  5. DNS Tunneling (T1071.004)

Can be executed from Laptop 4 (Kali Linux / Attacker), Laptop 3 (Server),
or any testing terminal against registered Windows and Ubuntu endpoints.
"""

import os
import sys
import time
import json
import uuid
import socket
import urllib.request
import urllib.error
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

SOC_BASE_URL = os.environ.get("SOC_API_URL", "http://127.0.0.1:8000")
API_TOKEN = os.environ.get("SOC_API_TOKEN", "dev-token-123")
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_TOKEN}"
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.250"

ATTACKER_IP = os.environ.get("ATTACKER_IP", get_local_ip())

def req(endpoint: str, method: str = "GET", data: dict = None, timeout: float = 8.0):
    url = f"{SOC_BASE_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8") if data is not None else None
    request_obj = urllib.request.Request(url, data=payload, headers=HEADERS, method=method)
    with urllib.request.urlopen(request_obj, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}

def wait_for_incident_resolution(event_id: str, max_wait: int = 15):
    print("     [+] Pipeline processing: Ingestion -> Fusion -> MITRE -> Multi-Agent -> Governance...")
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            incidents = req("/api/v1/incidents")
            for inc in incidents:
                evidence = req(f"/api/v1/incidents/{inc['incident_id']}/evidence")
                if any(e.get("detection_event_id") == event_id for e in evidence):
                    inc_id = inc["incident_id"]
                    gov = req(f"/api/v1/incidents/{inc_id}/governance")
                    return inc, gov
        except Exception:
            pass
        time.sleep(1.0)
    return None, None

def print_banner():
    print("""
========================================================================
   TGAM-SOC — 5 CORE ATTACKS DEMONSTRATION SUITE
   Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense
========================================================================
 SOC Endpoint : """ + SOC_BASE_URL + """
 Attacker IP  : """ + ATTACKER_IP + """
========================================================================""")

def get_endpoints():
    try:
        endpoints = req("/api/v1/endpoints")
        win = next((e for e in endpoints if e["os"].lower() == "windows"), None)
        linux = next((e for e in endpoints if e["os"].lower() == "linux"), None)
        return win, linux
    except Exception as e:
        print(f"[-] Warning: Failed to fetch endpoints: {e}")
        return None, None

# -----------------------------------------------------------------------------
# 1. BRUTE FORCE ATTACK (T1110 - Credential Access)
# -----------------------------------------------------------------------------
def trigger_brute_force(target_agent):
    print("\n" + "="*70)
    print("  [ATTACK 1] Brute Force Authentication Attack (MITRE T1110)")
    print("="*70)
    agent_id = target_agent["agent_id"] if target_agent else "agent-ubuntu-01"
    hostname = target_agent["hostname"] if target_agent else "UBUNTU-PC"
    os_type = target_agent["os"] if target_agent else "linux"

    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = str(uuid.uuid4())
    event = {
        "detection_event_id": ev_id,
        "source_event_id": f"bf-event-{int(time.time())}",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": os_type,
        "detection_type": "brute_force",
        "confidence": 0.98,
        "severity": "HIGH",
        "detector_name": "LinuxSSHBruteForceDetector",
        "evidence": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "target_service": "ssh" if os_type == "linux" else "smb",
            "target_user": "root" if os_type == "linux" else "Administrator",
            "failed_attempts": 8,
            "source_ip": ATTACKER_IP,
            "window_seconds": 60
        }
    }
    print(f"  -> Sending Brute Force telemetry on {os_type.upper()} ({hostname})...")
    res = req("/api/v1/detection-events", method="POST", data=event)
    print(f"     Status: Ingested event {ev_id[:8]}...")
    inc, gov = wait_for_incident_resolution(ev_id)
    if inc:
        print(f"  [✓] Correlated Incident ID : {inc['incident_id']} (Severity: {inc['max_severity']})")
        print(f"  [✓] MITRE ATT&CK Mapping   : T1110 (Credential Access: Brute Force)")
        print(f"  [✓] Governance Decision   : {gov.get('decision')} | Reason: {gov.get('reason')}")
        print(f"  [✓] Mitigation Triggered   : BLOCK_SOURCE ({ATTACKER_IP})")
    return inc

# -----------------------------------------------------------------------------
# 2. PHISHING ATTACK (T1566 - Initial Access)
# -----------------------------------------------------------------------------
def trigger_phishing(target_agent):
    print("\n" + "="*70)
    print("  [ATTACK 2] Spearphishing Attachment / Malicious Lure (MITRE T1566)")
    print("="*70)
    agent_id = target_agent["agent_id"] if target_agent else "agent-win-01"
    hostname = target_agent["hostname"] if target_agent else "WIN-FINANCE-PC"
    os_type = target_agent["os"] if target_agent else "windows"

    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = str(uuid.uuid4())
    event = {
        "detection_event_id": ev_id,
        "source_event_id": f"phish-event-{int(time.time())}",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": os_type,
        "detection_type": "phishing",
        "confidence": 0.92,
        "severity": "HIGH",
        "detector_name": "EmailPhishingDetector",
        "evidence": {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "sender": "payroll-alert@fake-internal-portal.com",
            "recipient": "finance_employee@company.org",
            "subject": "Urgent: Direct Deposit Audit Form",
            "malicious_attachment": "Invoice_Sep2026.pdf.vbs",
            "source_ip": ATTACKER_IP
        }
    }
    print(f"  -> Sending Phishing detection event on {os_type.upper()} ({hostname})...")
    res = req("/api/v1/detection-events", method="POST", data=event)
    print(f"     Status: Ingested event {ev_id[:8]}...")
    inc, gov = wait_for_incident_resolution(ev_id)
    if inc:
        print(f"  [✓] Correlated Incident ID : {inc['incident_id']} (Severity: {inc['max_severity']})")
        print(f"  [✓] MITRE ATT&CK Mapping   : T1566 (Initial Access: Phishing)")
        print(f"  [✓] Governance Decision   : {gov.get('decision')} | Reason: {gov.get('reason')}")
        print(f"  [✓] Recommended Action     : DISABLE_ACCOUNT / ISOLATE_HOST (Human Approval)")
    return inc

# -----------------------------------------------------------------------------
# 3. MALWARE / RANSOMWARE (T1204 / T1486 - Execution & Impact)
# -----------------------------------------------------------------------------
def trigger_ransomware(target_agent):
    print("\n" + "="*70)
    print("  [ATTACK 3] Malware / Ransomware Cryptor Simulation (MITRE T1486 & T1204)")
    print("="*70)
    agent_id = target_agent["agent_id"] if target_agent else "agent-win-01"
    hostname = target_agent["hostname"] if target_agent else "WIN-SERVER"
    os_type = target_agent["os"] if target_agent else "windows"

    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = str(uuid.uuid4())
    event = {
        "detection_event_id": ev_id,
        "source_event_id": f"ransom-event-{int(time.time())}",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": os_type,
        "detection_type": "ransomware",
        "confidence": 0.99,
        "severity": "CRITICAL",
        "detector_name": "RansomwareCanaryDetector",
        "evidence": {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "process_name": "wannacrypt_sim.exe",
            "mass_file_renames": 450,
            "extension_appended": ".locked_ransom",
            "canary_tampered": "C:\\Users\\Employee\\Documents\\canary.docx",
            "source_ip": ATTACKER_IP
        }
    }
    print(f"  -> Sending Ransomware Cryptor telemetry on {os_type.upper()} ({hostname})...")
    res = req("/api/v1/detection-events", method="POST", data=event)
    print(f"     Status: Ingested event {ev_id[:8]}...")
    inc, gov = wait_for_incident_resolution(ev_id)
    if inc:
        print(f"  [✓] Correlated Incident ID : {inc['incident_id']} (Severity: {inc['max_severity']})")
        print(f"  [✓] MITRE ATT&CK Mapping   : T1486 (Impact: Data Encrypted for Impact)")
        print(f"  [✓] Governance Decision   : {gov.get('decision')} | Reason: {gov.get('reason')}")
        print(f"  [✓] Emergency Mitigation  : KILL_PROCESS (wannacrypt_sim.exe) & ISOLATE_HOST")
    return inc

# -----------------------------------------------------------------------------
# 4. DENIAL OF SERVICE - DoS (T1498 - Impact)
# -----------------------------------------------------------------------------
def trigger_dos(target_agent):
    print("\n" + "="*70)
    print("  [ATTACK 4] Denial of Service - Network SYN/UDP Flood (MITRE T1498)")
    print("="*70)
    agent_id = target_agent["agent_id"] if target_agent else "agent-ubuntu-01"
    hostname = target_agent["hostname"] if target_agent else "UBUNTU-GATEWAY"
    os_type = target_agent["os"] if target_agent else "linux"

    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = str(uuid.uuid4())
    event = {
        "detection_event_id": ev_id,
        "source_event_id": f"dos-event-{int(time.time())}",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": os_type,
        "detection_type": "dos",
        "confidence": 0.95,
        "severity": "HIGH",
        "detector_name": "NetworkDosDetector",
        "evidence": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "flood_type": "SYN Flood / Request Rate Spike",
            "packet_rate": "18,500 packets/sec",
            "target_port": 80,
            "source_ip": ATTACKER_IP
        }
    }
    print(f"  -> Sending DoS flood telemetry on {os_type.upper()} ({hostname})...")
    res = req("/api/v1/detection-events", method="POST", data=event)
    print(f"     Status: Ingested event {ev_id[:8]}...")
    inc, gov = wait_for_incident_resolution(ev_id)
    if inc:
        print(f"  [✓] Correlated Incident ID : {inc['incident_id']} (Severity: {inc['max_severity']})")
        print(f"  [✓] MITRE ATT&CK Mapping   : T1498 (Impact: Network Denial of Service)")
        print(f"  [✓] Governance Decision   : {gov.get('decision')} | Reason: {gov.get('reason')}")
        print(f"  [✓] Mitigation Triggered   : BLOCK_SOURCE ({ATTACKER_IP}) via Firewall")
    return inc

# -----------------------------------------------------------------------------
# 5. DNS TUNNELING (T1071.004 - Command and Control)
# -----------------------------------------------------------------------------
def trigger_dns_tunneling(target_agent):
    print("\n" + "="*70)
    print("  [ATTACK 5] DNS Tunneling Data Exfiltration (MITRE T1071.004)")
    print("="*70)
    agent_id = target_agent["agent_id"] if target_agent else "agent-win-01"
    hostname = target_agent["hostname"] if target_agent else "WIN-CORP-PC"
    os_type = target_agent["os"] if target_agent else "windows"

    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = str(uuid.uuid4())
    event = {
        "detection_event_id": ev_id,
        "source_event_id": f"dns-tunnel-{int(time.time())}",
        "timestamp": now_iso,
        "agent_id": agent_id,
        "hostname": hostname,
        "os": os_type,
        "detection_type": "dns_tunneling",
        "confidence": 0.94,
        "severity": "HIGH",
        "detector_name": "DnsAnomalyDetector",
        "evidence": {
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "domain": "tunnel.attacker-c2.net",
            "high_entropy_queries": 28,
            "sample_query": "bXlwYXNzd29yZHMxMjM0NTY.tunnel.attacker-c2.net",
            "total_bytes_exfiltrated": "48 KB",
            "source_ip": ATTACKER_IP
        }
    }
    print(f"  -> Sending DNS Tunneling C2 telemetry on {os_type.upper()} ({hostname})...")
    res = req("/api/v1/detection-events", method="POST", data=event)
    print(f"     Status: Ingested event {ev_id[:8]}...")
    inc, gov = wait_for_incident_resolution(ev_id)
    if inc:
        print(f"  [✓] Correlated Incident ID : {inc['incident_id']} (Severity: {inc['max_severity']})")
        print(f"  [✓] MITRE ATT&CK Mapping   : T1071.004 (C2: DNS Tunneling)")
        print(f"  [✓] Governance Decision   : {gov.get('decision')} | Reason: {gov.get('reason')}")
        print(f"  [✓] Mitigation Triggered   : BLOCK_SOURCE ({ATTACKER_IP}) & ISOLATE_HOST")
    return inc

def main():
    print_banner()
    win_agent, linux_agent = get_endpoints()
    print(" Active Endpoint Fleet:")
    print(f"  - Windows : {win_agent['hostname'] if win_agent else 'Not detected (Using default)'}")
    print(f"  - Ubuntu  : {linux_agent['hostname'] if linux_agent else 'Not detected (Using default)'}")

    if len(sys.argv) > 1:
        choice = sys.argv[1].strip()
    else:
        print("\n Select an attack to demonstrate:")
        print("  [1] Brute Force (T1110)")
        print("  [2] Phishing Attack (T1566)")
        print("  [3] Malware / Ransomware (T1204 / T1486)")
        print("  [4] Denial of Service - DoS (T1498)")
        print("  [5] DNS Tunneling (T1071.004)")
        print("  [A] Run All 5 Attacks Sequentially")
        print("  [Q] Quit")
        choice = input("\nEnter choice (1-5, A, Q): ").strip()

    if choice == "1":
        trigger_brute_force(linux_agent or win_agent)
    elif choice == "2":
        trigger_phishing(win_agent or linux_agent)
    elif choice == "3":
        trigger_ransomware(win_agent or linux_agent)
    elif choice == "4":
        trigger_dos(linux_agent or win_agent)
    elif choice == "5":
        trigger_dns_tunneling(win_agent or linux_agent)
    elif choice.upper() == "A":
        print("\n[*] Running all 5 attacks sequentially with live correlation...")
        trigger_brute_force(linux_agent or win_agent)
        time.sleep(2)
        trigger_phishing(win_agent or linux_agent)
        time.sleep(2)
        trigger_ransomware(win_agent or linux_agent)
        time.sleep(2)
        trigger_dos(linux_agent or win_agent)
        time.sleep(2)
        trigger_dns_tunneling(win_agent or linux_agent)
    elif choice.upper() == "Q":
        print("[*] Exiting.")
        return
    else:
        print("[!] Invalid option.")

    print("\n" + "="*70)
    print("  [✓] DEMO COMPLETED! Check Live SOC Dashboard at http://localhost:5173")
    print("="*70)

if __name__ == "__main__":
    main()
