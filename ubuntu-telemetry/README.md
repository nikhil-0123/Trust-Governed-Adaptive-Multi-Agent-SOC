# TGAM-SOC Ubuntu Telemetry Endpoint

## Overview

The **TGAM-SOC Ubuntu Telemetry Endpoint** (`ubuntu-telemetry`) is a lightweight, zero-external-dependency endpoint security monitor designed for Ubuntu employee workstations.

It implements the local endpoint collection, normalization, local detection, and important-event filtering layers of the **Hybrid Decentralized Multi-Agent Architecture with Centralized Coordination & Governance**.

---

## 1. Architecture & Data Flow

```
[Ubuntu Host]
       │
       ├─► /var/log/auth.log (SSH, sudo, PAM) ──► AuthLogCollector
       ├─► /proc (Active Process Metadata)   ──► ProcessCollector
       └─► /proc/net/tcp (Listening Sockets)  ──► NetworkCollector
                                                       │
                                                       ▼
                                            UbuntuEventNormalizer
                                                       │
                                          Normalized Security Event (v1)
                                                       │
                                                       ▼
                                                DetectionEngine
                                     (LinuxSSHBruteForceRule, etc.)
                                                       │
                                                       ▼
                                            DetectionEventBuilder
                                          (Deterministic SHA256 ID)
                                                       │
                                      ┌────────────────┴────────────────┐
                                      ▼                                 ▼
                             Local JSONL Audit                 ImportantEventFilter
                            (detections.jsonl)             (HIGH, CRITICAL, MED>=0.8)
                                                                        │
                                                                        ▼
                                                                 Durable Outbox
                                                                  (outbox.db)
                                                                        │
                                                                        ▼
                                                                 TransportClient
                                                            (Authenticated HTTPS)
                                                                        │
                                                                        ▼
                                                              Central SOC Ingestion
                                                        (/api/v1/detection-events)
```

---

## 2. Supported Platforms & Telemetry Sources

### Supported Operating Systems:
- Ubuntu 20.04 LTS (Focal Fossa)
- Ubuntu 22.04 LTS (Jammy Jellyfish)
- Ubuntu 24.04 LTS (Noble Numbat)
- Debian 11/12

### Supported Sources:
1. **Authentication Log (`/var/log/auth.log`)**:
   - SSH login failures and successes (password and public key).
   - Invalid SSH user attempts.
   - Sudo authentication failures and elevated command execution.
   - Automatic log rotation detection and byte-offset checkpointing.
2. **Process Execution (`/proc`)**:
   - Process IDs, executable names, command lines.
   - Automatic secret sanitization (redaction of `--password`, `--token`, etc.).
3. **Network Sockets (`/proc/net/tcp`)**:
   - Listening TCP ports and established connections with zero network overhead.

---

## 3. Least-Privilege & Security Architecture

- **Zero Root Execution Required:**
  The agent user only requires read access to `/var/log/auth.log`. On standard Ubuntu systems, adding the service user to the existing `adm` group grants this permission without granting root:
  ```bash
  sudo usermod -a -G adm <telemetry_user>
  ```
- **Zero Attack Payloads / Remediation:**
  The collector performs observation and local detection only. It never executes shell commands on behalf of remote systems or modifies system configurations.
- **Untrusted Input Treatment:**
  All log lines and process strings are treated as untrusted input. Message lengths are bounded and malformed lines are safely handled without unhandled exceptions.
- **Credential Protection:**
  Passwords, keys, and authorization bearer tokens are never logged or stored in cleartext.

---

## 4. Configuration

Configure the agent using environment variables or a `.env` file:

```ini
# General
APP_NAME="TGAM-SOC Ubuntu Telemetry"
APP_VERSION=0.1.0
ENVIRONMENT=production
LOG_LEVEL=INFO

# Collector
AUTH_LOG_PATH=/var/log/auth.log
UBUNTU_EVENT_BATCH_SIZE=100
UBUNTU_EVENT_POLL_INTERVAL_SECONDS=5

# Central SOC API Transport
SOC_API_URL=https://soc.example.internal:8000/api/v1/detection-events
SOC_API_TOKEN=<CHANGE_ME_STATIC_BEARER_TOKEN>

# Filtering Thresholds
MEDIUM_CONFIDENCE_THRESHOLD=0.8
```

---

## 5. Installation & Systemd Service

### Step 1: Install Prerequisites
Python 3.10+ (Standard Library only; no external package dependencies required):
```bash
sudo apt update
sudo apt install -y python3
```

### Step 2: Deploy Code
```bash
git clone <repo_url> /opt/tgam-soc
cd /opt/tgam-soc/ubuntu-telemetry
```

### Step 3: Create Least-Privilege System User
```bash
sudo useradd -r -s /bin/false -d /var/lib/tgam-soc-telemetry -m tgam-agent
sudo usermod -a -G adm tgam-agent
sudo chown -R tgam-agent:tgam-agent /var/lib/tgam-soc-telemetry
```

### Step 4: Systemd Service Unit (`/etc/systemd/system/tgam-soc-ubuntu.service`)
```ini
[Unit]
Description=TGAM-SOC Ubuntu Telemetry Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tgam-agent
Group=tgam-agent
WorkingDirectory=/opt/tgam-soc/ubuntu-telemetry
Environment="DATA_DIR=/var/lib/tgam-soc-telemetry"
Environment="SOC_API_URL=https://soc.example.internal:8000/api/v1/detection-events"
Environment="SOC_API_TOKEN=<STATIC_TOKEN>"
ExecStart=/usr/bin/python3 /opt/tgam-soc/ubuntu-telemetry/main.py
Restart=always
RestartSec=10
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictNamespaces=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

### Step 5: Start and Enable
```bash
sudo systemctl daemon-reload
sudo systemctl enable tgam-soc-ubuntu.service
sudo systemctl start tgam-soc-ubuntu.service
```

---

## 6. Verification and Troubleshooting

- **Check Service Status:**
  ```bash
  sudo systemctl status tgam-soc-ubuntu.service
  ```
- **Inspect Service Logs:**
  ```bash
  sudo journalctl -u tgam-soc-ubuntu.service -f
  ```
- **Check Local Detection Audit:**
  ```bash
  cat /var/lib/tgam-soc-telemetry/detections/detections.jsonl
  ```
- **Verify Outbox Queue:**
  ```bash
  sqlite3 /var/lib/tgam-soc-telemetry/outbox.db "SELECT status, count(*) FROM outbox GROUP BY status;"
  ```
