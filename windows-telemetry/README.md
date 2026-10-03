# TGAM-SOC Windows Telemetry (Foundation + Collector)

## 1. Purpose
This component serves as the lightweight telemetry collection agent for Windows endpoints in the Trust-Governed Adaptive Multi-Agent SOC.

## 2. Scope of Step 1 & 2
This release includes:
- **Step 1 Foundation**: Agent Identity Management, Configuration Handling, Structured Logging, Basic Lifecycle (Runtime), Health Reporting.
- **Step 2 Windows Event Collector**: Incremental collection of raw Windows Security logs via native `wevtutil`, stateful checkpoints, batch processing, and controlled first-run strategy.
- **Step 3 Normalizer**: Converts raw OS telemetry directly into the project's standard normalized contract (`v1.1`), ensuring stable deterministic identifiers.
- **Step 4 Detection Layer**: Framework for evaluating normalized events against deterministic rules and XGBoost models. Windows Brute Force rule is active.
- **Step 5 Detection Output Pipeline**: An internal pipeline orchestrator integrating the above steps, creating stable local `DetectionEvent`s (JSON Lines) from positive detections without any external network transmission.

## 3. What is NOT implemented yet
The following features are deferred to later steps and are intentionally not present:
- Isolation Forest/unknown attack detection
- SOC Response / Governance
- Important Event Filtering
- Network Connections/SOC API integration
- Advanced continuous polling loops

## 4. Architecture Position
```
Windows Event Sources
        |
        v
Windows Event Collector (Step 2)
        |
        v
Windows Event Normalizer (Step 3)
        |
        v
Windows Detection Layer (Step 4)
        |
        v
Future Detection Output
```

## 5. Directory Structure
The `windows-telemetry` directory contains modules for core runtime, config, collectors, normalizers, detection, and filtering.

## 6. Installation & Dependencies
No third-party libraries are required for the runtime foundation or collector. `wevtutil` is used natively.
Testing requires `pytest` (optional, as `unittest` is fully compatible).
```bash
python -m pip install -r requirements.txt
```

## 7. Configuration
Configuration is managed via environment variables. Copy `.env.example` to `.env` or set manually:
- `APP_NAME`, `APP_VERSION`, `ENVIRONMENT`, `LOG_LEVEL`, `DATA_DIR`
- `WINDOWS_SECURITY_LOG_NAME` (Default: "Security")
- `WINDOWS_EVENT_BATCH_SIZE` (Default: 100)
- `WINDOWS_EVENT_POLL_INTERVAL_SECONDS` (Default: 5)
- `WINDOWS_CHECKPOINT_DIR` (Default: `DATA_DIR/state`)

## 8. Permissions
Reading the **Windows Security Log** natively requires Administrator privileges. If run without admin rights, the collector will fail safely and log an access denied error.

## 9. Collector Behavior
- **First-Run Behavior:** By default, it queries the most recent event (`/c:1 /rd:true`) to establish the initial checkpoint. This avoids flooding memory with historical logs.
- **Checkpointing:** State is persistently stored as JSON in `WINDOWS_CHECKPOINT_DIR`. EventRecordID is used for incremental collection and checkpoint tracking. The collector advances its checkpoint only after successful downstream processing is explicitly confirmed by the surrounding pipeline.
- **Batch Processing:** Events are queried in chunks determined by `WINDOWS_EVENT_BATCH_SIZE`.
- **One-Shot Testing:** The `collect_once()` interface allows fetching a single batch for testing or programmatic triggering without infinite polling loops.
- **Identifiers:** The collector preserves both `EventRecordID` (sequential identifier for checkpoint tracking) and `EventID` (native Windows Event type, e.g. 4625).

## 10. Normalizer Behavior (Step 3)
- **Purpose**: Converts raw OS telemetry directly into the project's standard normalized contract (`v1.1`).
- **Flow**: Collector Output -> `WindowsEventNormalizer` -> Normalized Dictionary.
- **Contract Adherence**: Uses `normalized_event_contract_v1.schema.json`. Before detection, `detection_type` and `confidence` are strictly `null`.
- **Event Identity**: Generates a stable deterministic SHA-256 hash using `agent_id`, `hostname`, `log_name`, and `EventRecordID`. Note: `windows_event_id` is NOT used in the hash, as the hash identifies the specific event log record, not the category.
- **Evidence preservation**: `windows_event_id` (e.g. 4625) is preserved in `evidence.windows_event_id`. This is distinct from `record_id` (e.g. 12345), which is used for checkpointing.
- **Checkpoint Separation**: The normalizer strictly processes events; it does **not** manage or advance the collector's checkpoint.
- **Detection Boundary**: The normalizer does **not** evaluate risk or score attacks. It strictly maps source telemetry.

## 11. Detection Layer Behavior (Step 4)
- **Purpose**: A modular framework to evaluate normalized events and produce `DetectionResult` objects.
- **Flow**: Normalized Event -> `DetectionEngine` -> [Rules, ML Models] -> DetectionResult list.
- **State Management**: The brute-force rule uses bounded in-memory state tracking, sliding over a 60-second window. Keys combine `username` and `source_ip`.
- **Brute Force Rule Semantics**: Triggers on 5 Windows Event 4625 (Auth Failure) occurrences within 60 seconds. Once triggered, subsequent events within the same sliding window are safely suppressed to prevent duplicate alerts.
- **Note on intent**: This rule strictly analyzes telemetry. It does **not** perform authentication attacks.
- **XGBoost Detector**: The ML detector is currently in a safe `ModelNotAvailableError` state because no compatible `.model`, `.xgb`, or `.pkl` file exists in the repository.
- **Confidence Semantics**: Deterministic rules assign `confidence=1.0` to matches, while XGBoost uses raw model probabilities. `0.0` is never used as a proxy for "not detected."

## 12. Detection Event Output & Pipeline (Step 5)
- **Objective**: Establish the internal endpoint-to-SOC boundary using local files.
- **Pipeline Flow**: `WindowsEventCollector` → `WindowsEventNormalizer` → `DetectionEngine` → `DetectionEventBuilder` → `DetectionEventWriter`.
- **DetectionEvent Model**: A structured contract separate from the normalized telemetry contract, produced strictly upon positive detections. It includes a deterministic `detection_event_id` computed via `SHA-256(agent_id + source_event_id + detection_type + detector_name)`.
- **Duplicate Handling**: Step 4 naturally suppresses rapid brute-force alerts. The Step 5 ID calculation provides downstream SOC consumers a deterministic identifier for correlation without relying on a full-blown database at the endpoint.
- **JSONL Output**: The output is appended as JSON Lines (`.jsonl`) into a configurable directory (`DETECTION_OUTPUT_DIR`), maintaining a simple, append-only, filesystem-safe interface.
- **Checkpoint Safety**: Checkpoint progression exclusively depends on the entire required processing chain (normalization, detection, *and* output writing) completing safely. If an event fails at *any* stage, the pipeline halts batch processing and preserves the contiguous-success boundary. It does NOT skip or discard malformed events.
- **Network Boundaries**: Step 5 strictly produces local detection-event output. **It does not transmit events to the Central SOC.** External transport is reserved for future steps.

## 13. Current Limitations
- Isolation Forest/unknown attack detection is not yet implemented.
- SOC Response/Governance pipelines do not yet exist.
- Network transport does not yet exist.

## 14. Running the application
```bash
python main.py
```

## 11. Running tests
Tests are written using the standard `unittest` framework. Run them via:
```bash
python -m unittest discover -s tests
```

## 12. Expected health output
Upon execution, the log will output a health status JSON:
```json
{
    "status": "healthy",
    "agent_id": "uuid-string",
    "hostname": "MACHINE-NAME",
    "os": "Windows",
    "version": "0.1.0",
    "uptime_seconds": 0.05
}
```

## 13. Security boundaries
This application currently operates entirely locally. It does not scan external networks, attack other systems, modify security settings, or transmit any data externally. Event payloads are treated as untrusted strings.

## 14. Next implementation step
The next immediate step will be to implement the **normalizer** to align raw Windows events with the `normalized_event_contract_v1` specification.
