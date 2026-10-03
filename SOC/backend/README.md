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
