# TGAM-SOC Windows Telemetry (Foundation + Collector)

## 1. Purpose
This component serves as the lightweight telemetry collection agent for Windows endpoints in the Trust-Governed Adaptive Multi-Agent SOC.

## 2. Scope of Step 1 & 2
This release includes:
- **Step 1 Foundation**: Agent Identity Management, Configuration Handling, Structured Logging, Basic Lifecycle (Runtime), Health Reporting.
- **Step 2 Windows Event Collector**: Incremental collection of raw Windows Security logs via native `wevtutil`, stateful checkpoints, batch processing, and controlled first-run strategy.

## 3. What is NOT implemented yet
The following features are deferred to later steps and are intentionally not present:
- Telemetry Normalization (`normalized_event_contract_v1`)
- Detection Engines (XGBoost, Isolation Forest)
- Important Event Filtering
- Network Connections/SOC API integration
- Advanced continuous polling loops

## 4. Architecture Position
```
Windows Event Sources
        |
        v
Windows Event Collector (THIS MODULE)
        |
        v
Future Normalizer
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
- **Checkpointing:** State is persistently stored as JSON in `WINDOWS_CHECKPOINT_DIR`. The checkpoint is updated *only* after a successful batch query to prevent event loss.
- **Batch Processing:** Events are queried in chunks determined by `WINDOWS_EVENT_BATCH_SIZE`.
- **One-Shot Testing:** The `collect_once()` interface allows fetching a single batch for testing or programmatic triggering without infinite polling loops.

## 10. Running the application
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
