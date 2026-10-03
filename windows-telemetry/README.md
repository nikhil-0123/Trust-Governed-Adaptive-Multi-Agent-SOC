# TGAM-SOC Windows Telemetry (Foundation)

## 1. Purpose
This component serves as the lightweight telemetry collection agent for Windows endpoints in the Trust-Governed Adaptive Multi-Agent SOC.

## 2. Scope of Step 1
This release (Step 1) establishes the **Foundation**. It includes:
- Agent Identity Management
- Configuration Handling
- Structured Logging
- Basic Application Lifecycle (Runtime)
- Health/Status Reporting
- Target Environment Validation (Windows)

## 3. What is NOT implemented yet
The following features are deferred to later steps and are intentionally not present:
- Actual Windows Event Log collection (Collectors)
- Telemetry Normalization
- Detection Engines (XGBoost, Isolation Forest)
- Important Event Filtering
- Network Connections/SOC API integration
- Continuous polling loops

## 4. Directory Structure
The `windows-telemetry` directory contains modules for core runtime, config, collectors, normalizers, detection, and filtering.

## 5. Python Version/Runtime Assumptions
- Python 3.8+ 
- Operating System: Windows 10/11

## 6. Installation
No third-party libraries are required for the runtime foundation.
Testing requires `pytest` (optional, as `unittest` is fully compatible).
```bash
python -m pip install -r requirements.txt
```

## 7. Configuration
Configuration is managed via environment variables. Copy `.env.example` to `.env` or set manually:
- `APP_NAME`
- `APP_VERSION`
- `ENVIRONMENT`
- `LOG_LEVEL`
- `DATA_DIR`

## 8. Running the application
```bash
python main.py
```

## 9. Running tests
Tests are written using the standard `unittest` framework. Run them via:
```bash
python -m unittest discover -s tests
```

## 10. Expected health output
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

## 11. Security boundaries
This application currently operates entirely locally. It does not scan external networks, attack other systems, modify security settings, or transmit any data externally. 

## 12. Next implementation step
The next immediate step will be to implement specific Windows telemetry **collectors** (e.g. consuming Windows Event Logs) and the **normalizer** to align with the normalized event contract.
