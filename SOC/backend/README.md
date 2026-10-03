# TGAM-SOC Central Backend

## Step 6 Architecture (Central SOC Ingestion)

This backend implements the first entry point for the Central SOC: receiving `DetectionEvent`s from endpoints.

### Components
- **Ingestion API**: A FastAPI application listening at `/api/v1/detection-events`.
- **Authentication**: A simple static Bearer token configured via `SOC_API_TOKEN`.
- **Validation**: Incoming JSON is rigorously validated against the `DetectionEvent` Pydantic model (which enforces confidence bounds, required fields, etc.).
- **Persistence & Deduplication**: SQLite is used for minimal development persistence. It checks for the existence of `detection_event_id`. If the ID exists, it returns a 201 Created with `duplicate: true`. If new, it persists the event and returns `duplicate: false`.

### Central Delivery Acknowledgement
**Central delivery acknowledgement is independent of the Windows EventRecordID collection checkpoint.** 
The endpoint uses a durable local outbox with at-least-once delivery semantics. It expects a definitive HTTP 200/201 ACK from this backend before marking an event as delivered.

### Configuration
Configure using environment variables:
- `SOC_API_TOKEN`: Bearer token for endpoint authentication.
- `SOC_DB_PATH`: Path to SQLite database file.

See `.env.example` for details.

### How to Run Local Integration Test
1. Start the central SOC backend:
   ```bash
   cd SOC/backend
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. In another terminal, trigger the Windows Telemetry pipeline:
   ```bash
   cd windows-telemetry
   $env:SOC_API_TOKEN="dev-token-123"
   python main.py
   ```
3. Observe the outbox logs indicating successful delivery.

## Step 7 Architecture (Evidence Fusion Engine)

Step 7 implements deterministic Evidence Fusion. It groups related `DetectionEvent`s into unified `Incident` structures asynchronously.

### Architecture & Components
- **FusionWorker**: A background daemon thread that polls for new, un-fused events in the `events` table (tracked via `fusion_event_state`).
- **EvidenceFusionEngine**: Applies deterministic correlation rules to link events to incidents.
- **Database Tables**:
  - `fusion_event_state`: Tracks processing status (`PENDING`, `PROCESSING`, `PROCESSED`, `FAILED`) and attempts.
  - `incidents`: Contains unified incident lifecycle metadata (`max_severity`, `first_seen`, `last_seen`, `status`).
  - `incident_evidence`: Preserves provenance by linking `incident_id` to the original `detection_event_id`.
  - `incident_entities`: Stores extracted entities (`hostname`, `source_ip`, `username`, `agent_id`) for candidate lookup.

### Correlation Rules
Events are correlated deterministically:
1. **Entity**: Exact match on `hostname`. If `source_ip` is present in the new event, it must also match an existing `source_ip` for that incident. (Fallback to `hostname`-only if `source_ip` is missing, which is a weaker correlation).
2. **Temporal**: The new event's `timestamp` must be within `FUSION_TIME_WINDOW_SECONDS` of the incident's `last_seen`.
3. **Selection**: If multiple incidents match, the engine selects the one with the most recent `last_seen`.

If a match is found, evidence is **attached** and the incident's severity is escalated (LOW < MEDIUM < HIGH < CRITICAL). If no match is found, a **new incident** is created.

### Configuration
- `FUSION_TIME_WINDOW_SECONDS` (Default: 3600): The maximum time gap between related events.
- `FUSION_POLL_INTERVAL_SECONDS` (Default: 5): Worker polling interval.

*Note: These are configurable development parameters requiring future evaluation. They are not experimentally validated.*
