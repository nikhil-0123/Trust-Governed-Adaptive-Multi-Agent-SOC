# TGAM-SOC Offline ML Pipeline (`ml/`)

Phase 3A establishes the reproducible offline dataset preparation and feature extraction foundation for Windows authentication anomaly detection (XGBoost).

## Scope & Strict Boundaries
- **Offline Only**: Scripts and tests under `ml/` operate offline over captured telemetry JSONL files and never deploy runtime models into the frozen Phase 2 `windows-telemetry/` collector.
- **No Unverified Labels**: Ground-truth labels require explicit `LabelAssignment` provenance (`scenario_id`, `label_source`, `telemetry_origin`). Deterministic `BruteForceRule` output is recorded solely as comparison metadata (`baseline_rule_bruteforce_detected`) and is never used as truth or model input.
- **Privacy & Sanitization**: Hostnames, source IPs, and verified `target_account_id` fields are HMAC-SHA256 pseudonymized before dataset export. Raw passwords, tokens, and raw XML are never written into dataset rows.
- **No Large Binary Artifacts in Git**: `/ml/data/`, `/ml/artifacts/`, `*.parquet`, `*.xgb`, `*.model`, and `*.joblib` are ignored via `.gitignore`.
