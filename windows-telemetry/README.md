# TGAM-SOC — Windows Telemetry Subsystem Reference & Operational Guide

**Subsystem**: Windows Telemetry & Local Detection  
**Release Freeze**: Phase 2.4  
**Committed Baseline**: `21a080d` (`feat(windows-telemetry): enforce simulation isolation, MITRE integrity, and decoding safety for Phase 2.4 release freeze`)  
**Production Detector Version**: `1.1.0`  
**Contract Version**: `normalized_event_contract_v1`  
**Automated Regression Baseline**: 870 passed, 1 skipped, 0 failed  

---

## 1. Subsystem Architecture Overview

The Windows Telemetry Subsystem provides resilient, decentralized telemetry collection, normalization, local threat detection, and guaranteed at-least-once durable event forwarding to the Central SOC.

```
+-----------------------------------------------------------------------------------------+
|                                    WINDOWS ENDPOINT                                      |
|                                                                                         |
|  +-----------------------------------+        +--------------------------------------+  |
|  | Windows Event Channels            |        | Sysmon Operational Log               |  |
|  | - Security (4624, 4625, 4688, 4720|        | - EventID 1: Process Creation        |  |
|  | - System (EventID 104 Log Clear)  |        | - EventID 3: Network Connection      |  |
|  +-----------------+-----------------+        | - EventID 22: DNS Query              |  |
|                    |                          +------------------+-------------------+  |
|                    +--------------------+                        |                      |
|                                         v                        v                      |
|                       +--------------------------------------------------+              |
|                       |  Multichannel WindowsEventCollector Engine        |              |
|                       |  - Dual-probe reverse record ID queries          |              |
|                       |  - BOM & XML declaration strict decoder          |              |
|                       |  - Exponential failure backoff per channel       |              |
|                       |  - Cross-channel log clear witness verification  |              |
|                       +-------------------------+------------------------+              |
|                                                 | Raw XML Records                       |
|                                                 v                                       |
|                       +--------------------------------------------------+              |
|                       |  WindowsEventNormalizer                          |              |
|                       |  - Contract v1 schema mapping                    |              |
|                       |  - Canonical Source Event ID (SHA-256)           |              |
|                       +-------------------------+------------------------+              |
|                                                 | Normalized Events                     |
|                                                 v                                       |
|                       +--------------------------------------------------+              |
|                       |  DetectionEngine (Manifest v1.1.0)               |              |
|                       |  - Reconnaissance, Brute Force, LOLBins, Evasion |              |
|                       |  - Enriched detection evidence                   |              |
|                       +-------------------------+------------------------+              |
|                                                 | Detections                            |
|                                                 v                                       |
|                       +--------------------------------------------------+              |
|                       |  Durable Outbox SQLite Queue (WAL Mode)          |              |
|                       |  - Multi-process lock & atomic transactions      |              |
|                       |  - Checkpoint advancement decoupled from HTTP    |              |
|                       |  - Disk watermark protection & payload conflicts |              |
|                       +-------------------------+------------------------+              |
|                                                 |                                       |
|                     +---------------------------+---------------------------+           |
|                     |                                                       |           |
|                     v                                                       v           |
|  +-------------------------------------+             +-------------------------------+  |
|  | DeliveryWorker                      |             | HeartbeatWorker               |  |
|  | - Exponential retry with jitter     |             | - Periodic keep-alive (15s)   |  |
|  | - Auth backoff (401/403)            |             | - Dynamic capabilities sync   |  |
|  +------------------+------------------+             +---------------+---------------+  |
+---------------------|------------------------------------------------|------------------+
                      | POST /api/v1/detection-events                  | POST /api/v1/endpoints/heartbeat
                      v                                                v
+-----------------------------------------------------------------------------------------+
|                                    CENTRAL SOC BACKEND                                  |
|                                                                                         |
|   Ingestion API -> Fusion Engine -> MITRE ATT&CK Mapper -> Assessment -> Governance    |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Channels & Telemetry Sources

| Channel Name | Provider / Log Name | Event IDs Monitored | Security Purpose |
| :--- | :--- | :--- | :--- |
| **Windows Security** | `Security` | `4624`, `4625`, `4672`, `4688`, `4720`, `4726`, `4738`, `1102` | Logon auditing, privilege use, process creation, user account lifecycle, audit log clearing |
| **Windows System** | `System` | `104` | Authoritative witness for event log clearing operations across channels |
| **Sysmon Operational** | `Microsoft-Windows-Sysmon/Operational` | `1`, `3`, `22` | Deep endpoint visibility: Process creation with CLI args and parent hashes, outbound/inbound network connections, DNS resolution |

---

## 3. Sysmon Configuration Specification

The active Sysmon configuration is frozen at `config/sysmon_config.xml`:

- **Configuration Hash (SHA-256)**: `21D5D4420D8CB13427961131907A022AEE9965F048A11E8F3F0D93E7AE9D605E`
- **Supported Schema**: `4.90` (validated against installed Sysmon driver schema `4.91`)
- **Installed Host Service**: `Sysmon` (DisplayName: `Sysmon`, Status: `Running`)
- **Event Log Capacity**: 67,108,864 bytes (64 MB circular buffer)
- **Monitored Event IDs**:
  - `EventID 1`: ProcessCreate (ProcessGuid, Image, CommandLine, CurrentDirectory, User, Hashes, ParentImage, ParentCommandLine)
  - `EventID 3`: NetworkConnect (Protocol, SourceIp, SourcePort, DestinationIp, DestinationPort, DestinationHostname)
  - `EventID 22`: DnsQuery (QueryName, QueryStatus, QueryResults)
- **Clarification on Event ID 7 (ImageLoad)**:
  `sysmon_config.xml` **deliberately excludes** Event ID 7 (ImageLoad) to prevent event flooding and CPU degradation during high-rate DLL loading in enterprise endpoints.

---

## 4. Collection Engine & Polling Mechanics

1. **Dual-Probe Polling**:
   - *Probe 1 (Reverse Check)*: `wevtutil qe <Channel> /c:1 /rd:true /f:xml` queries the newest available record ID in the log.
   - *Probe 2 (Incremental Forward Batch)*: If the newest record ID exceeds the checkpoint, queries records newer than the checkpoint up to `WINDOWS_EVENT_BATCH_SIZE`.
2. **Channel Reset & Clear Witness Verification**:
   - If `newest_record_id < current_checkpoint`, a potential event log clear or rollover occurred.
   - The engine pauses ingestion and scans `Security` (Event 1102) and `System` (Event 104) for an authoritative log clear witness.
   - If a valid clear witness is found: advances channel epoch (`epoch += 1`), resets checkpoint safely, and resumes.
   - If no valid witness is found: fails closed, quarantines the channel, and raises `UnverifiedDiscontinuityError`.
3. **Lossless XML Decoding**:
   - XML Declaration parsing (`encoding="..."`).
   - Byte Order Mark (BOM) detection: `utf-8-sig`, `utf-16le`, `utf-16be`.
   - Candidate encodings: `utf-8`, `utf-16le`, `cp1252`, `mbcs`.
   - Structural validation: Rejects strings containing embedded null bytes (`\x00`) or missing root XML structure.
   - Quarantining: If undecodable, checks disk watermark before writing binary forensics atomically via `.tmp` file, `fsync()`, and `os.replace()`.

---

## 5. Normalization & Canonical Identity (Contract v1)

Every event is normalized strictly against `docs/contracts/normalized_event_contract_v1.schema.json`:

```json
{
  "event_id": "<canonical_sha256_hash>",
  "timestamp": "2026-11-26T15:00:00.000000Z",
  "agent_id": "1823ceae-c50b-4957-9b81-5cd05ac6af1d",
  "hostname": "WORKSTATION-01",
  "os": "windows",
  "event_type": "windows_security",
  "source_ip": "192.168.1.100",
  "username": "CORP\\Administrator",
  "severity": "HIGH",
  "detection_type": "windows_reconnaissance",
  "confidence": 0.85,
  "evidence": {
    "command_line": "whoami /all",
    "process_name": "whoami.exe",
    "parent_process": "powershell.exe",
    "mitre_technique_id": "T1033"
  }
}
```

### Identity Derivation
- `source_event_id`: Deterministic SHA-256 digest of `(agent_id, hostname, channel, epoch, record_id, timestamp, event_id)`.
- `detection_event_id`: Deterministic SHA-256 digest of `(source_event_id, detector_manifest_id, detector_version, detection_type)`.
- **Invariance Guarantee**: Replaying historical events with identical detector versions generates identical detection identities, ensuring backend deduplication and assessment idempotency.

---

## 6. Local Detection Engine & Manifest Policy

- **Current Detector Version**: `1.1.0` (frozen in Phase 2.4).
- **SemVer Compatibility Policy**:
  - In `PRODUCTION` mode, the pipeline strictly validates and requires detector version `1.1.0`. Incompatible historical versions (e.g. `1.0.0`) are rejected during startup.
- **Active Built-in Rule Set**:
  1. `windows_reconnaissance`: Detects system information discovery (`whoami`, `systeminfo`, `net user`, `nltest`, `ipconfig /all`).
  2. `windows_user_discovery`: Detects Active Directory / local user enumeration (`net user`, `net group`).
  3. `windows_bruteforce_rule`: Correlates repeated 4625 logon failures within temporal sliding window.
  4. `windows_powershell_execution`: Detects encoded, bypassed, or obfuscated PowerShell commands (`-enc`, `-ExecutionPolicy Bypass`).
  5. `windows_lolbin_download`: Detects Living-off-the-Land binaries downloading payloads (`certutil -urlcache`, `bitsadmin /transfer`).
  6. `windows_defense_evasion`: Detects service stopping, security tool tampering, or event log clearing.

---

## 7. Durable Outbox & Transport Delivery

1. **Storage Engine**: SQLite in Write-Ahead Logging (`WAL`) mode with `NORMAL` synchronous pragma.
2. **Concurrency**: Multi-process `WindowsProcessLock` with atomic acquisition, eliminating `SQLITE_BUSY` contention during parallel collection and delivery.
3. **Decoupled Checkpoints**: Checkpoint advancement occurs immediately after atomic insertion into the local outbox. Network outages cannot block event collection or checkpoint progress.
4. **Delivery Worker**:
   - Asynchronous background thread querying eligible pending events.
   - Exponential retry backoff with jitter on transient network failures (5xx, timeouts).
   - Dedicated authentication backoff on 401/403 responses.
   - HTTP 409 conflict preservation: conflicting payloads are moved to an audit table and never retransmitted destructively.
5. **Disk Watermark Protection**:
   - Checks available disk space prior to batch ingestion. If free space is below `WINDOWS_OUTBOX_DISK_WATERMARK_MB` (default: 500 MB), collection pauses safely until space is cleared or outbox is drained.

---

## 8. Governed Response Execution & Safety Safeguards

The endpoint includes `WindowsResponseExecutor` supporting governed mitigation actions dispatched by Central SOC governance:

| Mitigation Action | Local Execution Mechanism | Target Safeguards | Simulation Behavior |
| :--- | :--- | :--- | :--- |
| `BLOCK_SOURCE` | `netsh advfirewall firewall add rule` | Prohibits loopback/RFC 5735 (`127.0.0.1`, `::1`); validates IP syntax | Returns simulated command; zero firewall changes |
| `UNBLOCK_SOURCE` | `netsh advfirewall firewall delete rule` | Validates rule name prefix (`TGAM-SOC-Block-`) | Returns simulated command; zero firewall changes |
| `KILL_PROCESS` | `taskkill /F /PID` or `/IM` | Protected processes check (`csrss.exe`, `lsass.exe`, `services.exe`, `explorer.exe`, etc.); protects agent PID | Returns simulated command; zero process kills |
| `ISOLATE_HOST` | `netsh advfirewall` block outbound | Preserves Central SOC IP communication unconditionally | Returns simulated command; zero network disruption |
| `RESTORE_HOST` | Deletes isolation rules | Reverts isolation safely | Returns simulated command |
| `DISABLE_ACCOUNT` | `net user <user> /active:no` | Protected accounts check (`Administrator`, `SYSTEM`); machine account safeguard (`$` suffix prohibited); domain namespace restriction (`LOCAL_SAM` only) | Returns simulated command; zero account changes |

### Strict Simulation Mode Isolation
- If `simulation_mode == True` or `EXECUTION_MODE == "SIMULATION"`:
  All containment actions unconditionally enforce `simulate = True` regardless of incoming command parameters. Live commands are never executed in simulation mode.

---

## 9. Reproducible Deployment & Setup Guide

### Prerequisites
- Windows 10/11 or Windows Server 2019/2022.
- Python 3.10+ (tested on Python 3.12).
- Sysmon installed with schema `4.90+` and configuration `windows-telemetry/config/sysmon_config.xml`.
- Administrator privileges for live Security log access and network containment.

### Installation Steps

1. **Clone Repository**:
   ```powershell
   git clone https://github.com/nikhil-0123/Trust-Governed-Adaptive-Multi-Agent-SOC.git
   Set-Location Trust-Governed-Adaptive-Multi-Agent-SOC
   ```

2. **Configure Environment (`windows-telemetry/.env`)**:
   ```env
   APP_NAME="TGAM-SOC Windows Telemetry"
   APP_VERSION="0.1.0"
   ENVIRONMENT="production"
   EXECUTION_MODE="PRODUCTION"
   LOG_LEVEL="INFO"

   # Collector Settings
   WINDOWS_SECURITY_LOG_NAME="Security"
   WINDOWS_SYSTEM_LOG_NAME="System"
   WINDOWS_SYSMON_LOG_NAME="Microsoft-Windows-Sysmon/Operational"
   ENABLE_SYSTEM_COLLECTION="true"
   ENABLE_SYSMON_COLLECTION="true"
   WINDOWS_EVENT_BATCH_SIZE="100"
   WINDOWS_EVENT_POLL_INTERVAL_SECONDS="5"

   # Transport Settings
   SOC_API_URL="http://127.0.0.1:8000/api/v1/detection-events"
   SOC_AGENT_API_TOKEN="dev-token-123"
   WINDOWS_DETECTOR_VERSION="1.1.0"
   ```

3. **Install Dependencies**:
   ```powershell
   pip install -r windows-telemetry/requirements.txt
   ```

4. **Verify Endpoint Self-Test & Capabilities**:
   ```powershell
   python windows-telemetry/main.py --check-health
   ```

5. **Start Endpoint Telemetry Service**:
   ```powershell
   python windows-telemetry/main.py
   ```

---

## 10. Operational Performance Characteristics (Baseline Benchmark)

Measured under genuine Windows endpoint operation (`scratch/performance_baseline_results.json`):

| Metric | Measured Baseline | Operational Significance |
| :--- | :--- | :--- |
| **Process Resident Memory (RSS)** | 27.84 MB -> 32.91 MB (+5.07 MB) | Highly compact footprint; well within endpoint memory budgets (< 100 MB). |
| **CPU Utilization** | < 6.0% (0.219s user, 0.672s system over 15.5s) | Negligible CPU impact on endpoint user workflows. |
| **Polling Latency (p50)** | 235.03 ms | Sub-second polling cycle across all three channels. |
| **Polling Latency (p95)** | 282.58 ms | Predictable, bounded collection execution time. |
| **Outbox Storage Growth (Idle)** | 0 bytes DB, 0 bytes WAL | Zero disk churn when no new events match detection thresholds. |
| **Failure Isolation Backoff** | 2.0s -> 4.0s -> 8.0s -> ... -> 60.0s | Exponential backoff prevents CLI thrashing during un-elevated runs. |
