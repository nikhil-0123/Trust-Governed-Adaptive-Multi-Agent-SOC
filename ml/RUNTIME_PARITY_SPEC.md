# TGAM-SOC Authentication ML Runtime Parity Specification (Phase 3D / 3E)

- **Target Feature Schema**: `auth_anomaly_features_v1`
- **Offline Reference Implementation**: `ml/auth_anomaly/extractor.py` (`OfflineAuthFeatureExtractor`)
- **Production Target Module (Currently Frozen)**: `windows-telemetry/detection/features.py` (`AuthenticationFeatureExtractor`)

## 1. Current Gap Between Offline & Production Extractors
In frozen Phase 2.4 (`windows-telemetry/detection/features.py` L625–L633):
- `f5_logon_type_entropy_15m`, `f6_hour_of_day`, and `f7_is_off_hours` are **IMPLEMENTED**.
- `f1_failed_logins_1m`, `f2_failed_logins_5m`, `f3_failed_logins_15m`, and `f4_unique_users_per_ip_15m` are **STUBBED** and unconditionally return `FeatureMeasurement(value=None, is_available=False, reason=...)`.

Before XGBoost inference can execute online in Phase 3D/3E, `AuthenticationFeatureExtractor` must be upgraded to match `OfflineAuthFeatureExtractor` with bit-for-bit parity.

## 2. Strict Parity Guarantees Required in Phase 3D/3E

| Dimension | Exact Required Parity Specification |
| :--- | :--- |
| **Mathematical Definitions** | `f1`..`f3`: count of `AUTHENTICATION_FAILURE` (Event 4625) in `[t - W, t)` for `W in {60, 300, 900}`. `f4`: cardinality of `lower(target_account_id)` across all `4624` + `4625` records in `[t - 900, t)` where `domain_namespace != "UNVERIFIED"`. `f5`: Shannon entropy (bits, base 2, rounded 6 decimals) of `SUPPORTED_WINDOWS_LOGON_TYPES` in `[t - 900, t)`. `f6`: local `hour` `[0..23]` under configured `BusinessHoursConfig.iana_timezone`. `f7`: `0.0` iff workday and `work_start <= hour < work_end`, else `1.0`. |
| **Window Boundaries** | Strictly half-open `[t - W, t)`. Left boundary inclusive (`r.timestamp >= t - W`), right boundary exclusive (`r.timestamp < t`). Current event `t` is NEVER committed to `_entity_events` until AFTER feature calculation. |
| **Grouping Key** | `f"{destination_host}|{source_ip}"` where `source_ip` passed `IPValidationStatus.VALID` (loopback `127.0.0.1` / `::1`, unspecified, multicast, `-`, `None`, and malformed IPs are never grouped into `f1`–`f5`). `f1`–`f4` additionally require `identity_role == TARGET_USER` and `domain_status != "UNVERIFIED"`. |
| **Duplicate Handling** | Scoped `(host, dedup_hash)` LRU cache with event-time recovery horizon (`_dedup_compromised_until`). Duplicate triggers `DUPLICATE_EVENT` and `can_predict = False`. |
| **Missing-Value Semantics** | Never substitute `0.0` for missing/warm-up/gapped/unverified states. Emit `FeatureMeasurement(value=None, is_available=False, reason=...)` mapped to numeric `NaN` plus binary availability bit `f{i}_available = 0`. Genuine zero count (`is_available=True, value=0.0`) requires `t - coverage_start[host] >= W` with zero overlapping gaps. |
| **Timezone Semantics** | Both offline training (`DatasetBuildConfig.business_hours`) and live runtime must share an explicit `BusinessHoursConfig(iana_timezone=..., workdays=..., work_start_hour=..., work_end_hour=...)`; `business_hours=None` must fail closed on `f6` and `f7`. |
| **Watermark & Lateness** | Per-host monotonic `_entity_watermarks[host]`. Out-of-order late arrival (`t < wm`) with monotonic `record_id` marks `can_predict=False`; unverified `record_id` regression purges host state (`UNRESOLVED_RECORD_ORDERING_ANOMALY`). Authoritative Event `1102` calls `notify_log_cleared()`. |
| **Ordered `MODEL_INPUT_COLUMNS`** | Exact 17-column float vector order: `f1..f7`, `f1_available..f7_available`, `windows_event_id`, `is_auth_failure`, `logon_type`. Runtime inference must verify this list against model artifact metadata + SHA-256 digest before enabling predictions. |

## 3. Mandatory Pre-Integration Security Gate: Explicit `DATA_DIR` Overlap Defect
As observed during Phase 3A preflight, `windows-telemetry/config/settings.py` (line 111) uses `os.getenv("DATA_DIR", default_data_dir)` directly without appending an execution-mode isolated subdirectory or checking an `execution_mode.lock` marker.

**Required Remediation Prior to Phase 3D Runtime ML Enablement**:
1. Enforce mode isolation under explicit `DATA_DIR` (either append `f"telemetry_{mode.lower()}"` when non-production OR write/validate a mode lockfile failing closed on mismatch between `PRODUCTION` and `SIMULATION`/`TEST`/`EVALUATION`).
2. Keep `windows_auth_xgboost` predictions in **Shadow Logging Mode** first, verifying live `f1`–`f7` vectors match `OfflineAuthFeatureExtractor` replay on identical EVTX captures before emitting active alerts into `Outbox`.
3. Never weaken `DetectorManifest` / `TGAM-RCC-v1` canonical identity or WP-1E epoch governance, and never permit XGBoost outputs to bypass Central SOC Trust/Risk/Governance human-in-the-loop authorization.
