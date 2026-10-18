# TGAM-SOC Analyst Console Dashboard

Modern, high-density React & Vite dashboard for the **Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense** (`TGAM-SOC`).

---

## Architecture & Integration Overview

The SOC dashboard interfaces directly with the central FastAPI backend (`SOC/backend`) via authenticated REST APIs (`Authorization: Bearer <token>`).

### Implemented Pages

1. **SOC Overview (`overview`):**
   - KPI metrics: Total Correlated Incidents, Critical Alerts, Open/Active Cases, and AI Reasoning completion ratios.
   - Severity Distribution donut chart (powered by Recharts).
   - Real-time incident stream with chronological ordering, severity badges, and quick-inspection navigation.

2. **Incidents (`incidents`):**
   - Interactive, searchable, and filterable table with column sorting.
   - Filter by max severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and status (`OPEN`, `TRIAGED`, `DECIDED`).
   - Incident triage drawer providing case summary and routing to deep forensic views.

3. **Investigation (`investigation`):**
   - Correlated Entities breakdown (`IP`, `HOST`, `USER`, `PROCESS`).
   - MITRE ATT&CK mapping cards displaying technique IDs, tactics, mapping rules, and versioning.
   - Durable evidence timeline showing raw detection events, detector names, confidence scores, and JSON inspection modals.

4. **AI Analysis (`analysis`):**
   - Multi-agent reasoning synthesis output, structured findings, and hypotheses.
   - Model provenance, evaluation status, and timestamp audit information.
   - Raw JSON payload inspector.

5. **Trust & Governance (`governance`):**
   - Trust Score (0.0–1.0) and Risk Score (0.0–1.0) visual gauges with mathematical rationale explanations.
   - Authoritative Governance Decision badge (`AUTO_APPROVE`, `HUMAN_APPROVAL`, `HOLD`, `ESCALATE`) and policy rationale.
   - Complete end-to-end Provenance History audit trail.
   - Live architectural guardrail verification test demonstrating that manual write overrides are rejected by the backend (`HTTP 501 Not Implemented`).

6. **Endpoints (`endpoints`):**
   - Endpoint telemetry inventory for Windows Employee, Ubuntu Employee, and Ubuntu Server endpoint nodes.
   - Operating system identification, first/last seen timestamps, and active detector rules.
   - Remote command execution and command audit logs.

7. **MITRE ATT&CK Matrix (`mitre`):**
   - Fleet-wide MITRE ATT&CK Matrix heatmap displaying Tactics and Techniques coverage.
   - Real-time aggregation of observed technique frequencies across all incidents with direct incident navigation.

---

## API Mapping Reference

| Dashboard View | Backend API Endpoint | HTTP Method | Auth Required |
|---|---|---|---|
| Health / Ping | `/api/v1/incidents` | `GET` | Bearer Token |
| Incidents List | `/api/v1/incidents` | `GET` | Bearer Token |
| Incident Details | `/api/v1/incidents/{incident_id}` | `GET` | Bearer Token |
| Evidence Timeline | `/api/v1/incidents/{incident_id}/evidence` | `GET` | Bearer Token |
| Correlated Entities | `/api/v1/incidents/{incident_id}/entities` | `GET` | Bearer Token |
| MITRE Context | `/api/v1/incidents/{incident_id}/mitre` | `GET` | Bearer Token |
| Trust/Risk Assessment | `/api/v1/incidents/{incident_id}/assessment` | `GET` | Bearer Token |
| AI Reasoning Analysis | `/api/v1/incidents/{incident_id}/analysis` | `GET` | Bearer Token |
| Governance Decision | `/api/v1/incidents/{incident_id}/decision` | `GET` | Bearer Token |
| Provenance History | `/api/v1/incidents/{incident_id}/history` | `GET` | Bearer Token |
| Governed Mitigation Approve | `/api/v1/incidents/{incident_id}/governance/approve` | `POST` | Bearer Token |
| Governed Mitigation Reject | `/api/v1/incidents/{incident_id}/governance/reject` | `POST` | Bearer Token |
| Override Blocker Test | `/api/v1/incidents/{incident_id}/governance/override` | `POST` | Bearer Token (Returns 501) |
| Endpoints Inventory | `/api/v1/endpoints` | `GET` | Bearer Token |
| Endpoint Remote Commands | `/api/v1/endpoints/{agent_id}/commands` | `GET`, `POST` | Bearer Token |
| MITRE Fleet Heatmap | `/api/v1/mitre/matrix` | `GET` | Bearer Token |

---

## Safety and Governance Guardrails

1. **Read-Only / Append-Only Governance:** Governance decisions are immutable. The dashboard does not alter or erase decision history. Attempting manual overrides triggers an explicit 501 check confirming architecture compliance.
2. **Response Safety:** Autonomous endpoint remediation execution is disabled. No automated containment or destructive actions are dispatched.
3. **No Fabricated Telemetry:** When database records are absent or pending (e.g. analysis has not completed yet), the UI renders informative pending/empty states rather than inventing dummy events or scores.

---

## Development & Build Commands

```bash
# Navigate to dashboard directory
cd SOC/dashboard

# Install dependencies
npm install

# Start local development server
npm run dev

# Run linting check
npm run lint

# Compile production bundle
npm run build

# Preview production bundle
npm run preview
```
