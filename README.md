# Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense (TGAM-SOC)

An advanced, evidence-driven Security Operations Center (SOC) framework implementing a **Hybrid Decentralized Multi-Agent Architecture with Centralized Coordination and Human-in-the-Loop Governance**.

---

## 📌 Project Overview

Traditional Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platforms suffer from severe alert fatigue, high false-positive rates, and unconstrained autonomous responses that risk business disruption.

**TGAM-SOC** addresses these challenges by decoupling detection from central coordination:
1. **Edge-Level Detection**: Windows and Ubuntu endpoints perform local event normalization and high-confidence threat detection with a zero-telemetry-loss transactional outbox.
2. **Central Multi-Agent Coordination**: Central SOC correlates distributed events into unified incidents, enriches them with authoritative MITRE ATT&CK context, and calculates dual-axis Trust and Risk scores.
3. **Trust-Governed Remediation**: High-risk mitigations require explicit Human-in-the-Loop analyst authorization, while low-risk, high-trust actions can be safely auto-governed, closing the loop with automated endpoint firewall and process remediation.

---

## 🏗️ System Architecture & Operational Flow

```text
IT Endpoints (Windows / Ubuntu)
        │
        ▼
Local Telemetry Collection (EventLog / auth.log)
        │
        ▼
Schema Normalization (NormalizedEventContract v1.1)
        │
        ▼
Local Threat Detection (MITRE-aligned Rules)
        │
        ▼
Durable SQLite Outbox (At-least-once Delivery)
        │
        ▼
Central Ingestion API (FastAPI REST / Bearer Auth)
        │
        ▼
Evidence Fusion Engine (Graph / Entity Correlation)
        │
        ▼
MITRE ATT&CK Threat Context (Tactics & Techniques)
        │
        ▼
Dual-Axis Assessment (Mathematical Trust & Risk)
        │
        ▼
Multi-Agent Reasoning (Claim Extraction & Synthesis)
        │
        ▼
Trust-Governed Decision Engine (AUTO_APPROVE / HOLD)
        │
        ▼
Human-in-the-Loop Approval (Analyst Dashboard)
        │
        ▼
Closed-Loop Endpoint Mitigation (Firewall / Kill)
        │
        ▼
Real-Time Fleet Heatmap & Audit Verification
```

---

## 🧩 Project Modules

| Directory | Subsystem | Description |
| :--- | :--- | :--- |
| **`SOC/backend/`** | Central SOC Server | FastAPI application hosting ingestion APIs, database persistence, and autonomous multi-agent workers (`FusionWorker`, `MitreWorker`, `AssessmentWorker`, `ReasoningWorker`, `GovernanceWorker`). |
| **`SOC/dashboard/`** | Analyst Console | Modern React 19 glassmorphic dashboard featuring Incident Triage, Governance Approval Hub, MITRE ATT&CK Matrix Heatmap, and Fleet Manager. |
| **`windows-telemetry/`** | Windows Endpoint Agent | Lightweight Windows telemetry collector (EventLog 4625/4688), rule engine, local outbox, heartbeat worker, and `netsh`/`taskkill` response executor. |
| **`ubuntu-telemetry/`** | Linux Endpoint Agent | Zero-dependency Linux telemetry agent tailing `/var/log/auth.log`, detecting SSH brute-force/sudo anomalies, and enforcing `iptables` mitigations. |
| **`ubuntu-server-telemetry/`** | Server Endpoint Agent | Planned dedicated server instrumentation for web and infrastructure logs. |
| **`scripts/`** | Operational Tools | Standalone administration scripts, including `reset_soc_data.py` for one-click clean database re-initialization. |

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ & npm
- Supported OS: Windows 10/11, Ubuntu 20.04/22.04 LTS

---

### 1. Central SOC Backend Setup
```bash
cd SOC/backend

# Install dependencies
pip install -r requirements.txt

# Start backend server (listening on port 8000)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
- API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`

---

### 2. SOC Analyst Dashboard Setup
```bash
cd SOC/dashboard

# Install packages
npm install

# Start Vite dev server
npm run dev -- --host 0.0.0.0
```
- Dashboard Console: `http://localhost:5173`

---

### 3. Running Telemetry Endpoints

#### Windows Telemetry Agent:
```powershell
cd windows-telemetry
powershell -ExecutionPolicy Bypass -File .\agent.ps1 run
```

#### Ubuntu Telemetry Agent:
```bash
cd ubuntu-telemetry
sudo python3 main.py
```

---

### 4. Database Reset (Clean Baseline)
To reset the central SQLite database and clear all test events and telemetry devices back to a clean zero-incident baseline:
```bash
python scripts/reset_soc_data.py
```

---

## 🛡️ Key Capabilities

- **Normalized Event Contract**: Strict JSON Schema enforcement guaranteeing cross-platform telemetry interoperability.
- **MITRE ATT&CK Matrix Alignment**: Real-time fleet-wide tactic and technique heatmap visualization (`T1110`, `T1059.001`, `T1105`, `T1082`).
- **Mathematical Trust & Risk Bounding**: Bounded dual-axis scoring `[0.0, 1.0]` preventing autonomous runaway.
- **Zero-Hallucination Guardrails**: Multi-agent reasoning protected by deterministic evidence validation.
- **Audit-Trail Enforcement**: SQLite trigger-protected append-only governance decisions.
- **Closed-Loop Mitigation**: Inbound firewall blocking and malicious process termination with built-in non-destructive simulation modes.

---

## 📄 License & Attribution

Developed as an academic engineering research project for Advanced Cyber Defense and Multi-Agent Systems. For project synopses, research papers, and architectural presentations, refer to the project documentation repository.
