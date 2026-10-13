# Semester-I Evidence Collection Checklist

## 1. Purpose
This document provides a complete, reproducible checklist for collecting evidence of the "Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense" implementation completed during Semester-I. This is NOT a fully autonomous SOC yet. Approximately 40%+ of the overall project implementation has been completed during Semester-I, with the foundational SOC processing and governance pipeline implemented and validated.

## 2. Repository and Environment Prerequisites
- **Repository:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC`
- **Environment:** Windows (for Windows Telemetry), Python 3.12+
- **Packages:** `pytest`, `fastapi`, `uvicorn`, `pydantic`, `sqlite3`

## 3. Evidence Collection Rules
- Evidence must be captured from the actual implementation repository.
- Do NOT use old prototype repositories (e.g. `C:\soc-telemetry`, `C:\soc-server`).
- Screenshots should clearly show the commands run and their observable outputs.
- Never print or expose the actual `SOC_API_TOKEN` in screenshots. Use placeholders like `<configured-token>`.
- The recommended directory for evidence collection is `TGAM-SOC-Sem1-Evidence/` (created outside the source repository).

## 4. Evidence Package Structure (External)
It is recommended to organize the collected evidence outside the source repository as follows:
```text
TGAM-SOC-Sem1-Evidence/
├── 01_Project_Baseline
├── 02_Windows_Telemetry
├── 03_Local_Detection
├── 04_Central_Ingestion
├── 05_Evidence_Fusion
├── 06_MITRE
├── 07_Trust_Risk
├── 08_Multi_Agent_Reasoning
├── 09_Governance
├── 10_E2E_Testing
├── 11_Backend_Regression
├── 12_Windows_Regression
├── 13_Operational_APIs
├── 14_Security_Authentication
└── 15_Git_Release
```

---

## 5. Evidence Items

### E01 — Project Baseline
- **What must be demonstrated:** The core project structure and base initialization.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC`
- **Exact command:** 
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC
  Get-ChildItem -Force
  ```
- **Expected observable result:** Shows the project root containing `SOC`, `windows-telemetry`, `docs`, `tests`, `project.config.json`, etc.
- **What should be captured:** Screenshot of the directory structure.
- **What must NOT be claimed:** Do not claim the AI Factory or other workspaces are part of the product.

### E02 — Windows Telemetry
- **What must be demonstrated:** The Windows endpoint telemetry collector initialization and environment validation.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry`
- **Exact command:** 
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry
  python -m unittest tests.test_runtime.TestRuntime.test_runtime_startup_shutdown -v
  ```
- **Expected observable result:** Logs indicating successful initialization of TGAM-SOC Windows Telemetry and Agent Identity.
- **What should be captured:** Terminal output showing agent ID assignment and health status check.

### E03 — Normalized Event
- **What must be demonstrated:** Windows events are normalized to the `normalized_event_contract_v1` schema.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry`
- **Exact command:** 
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry
  python -m unittest tests.test_normalizer.TestWindowsEventNormalizer.test_normalize_valid_event -v
  ```
- **Expected observable result:** Test passing, proving events are normalized properly.

### E04 — Local Detection
- **What must be demonstrated:** Local endpoint anomaly detection (e.g., brute-force rules).
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry`
- **Exact command:** 
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry
  python -m unittest tests.test_detection.TestDetectionLayer.test_fifth_event_detection -v
  ```
- **Expected observable result:** Successful detection of multiple failed logins, crossing the boundary to trigger an alert.
- **What should be captured:** Screenshot of the passing test.

### E05 — Central SOC Ingestion
- **What must be demonstrated:** Ingestion of a `DetectionEvent` at the central SOC.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:** 
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_release_gate.py::TestReleaseGate::test_ingestion_fusion_independence -v
  ```
- **Expected observable result:** Valid events are successfully ingested and stored in the database.

### E06 — Evidence Fusion
- **What must be demonstrated:** Fusion of multiple detection events into a single incident entity.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_e2e_integration.py::TestE2EIntegration::test_e2e_multi_evidence_single_incident -v
  ```
- **Expected observable result:** Evidence fusion engine correlating multiple raw events into a single Incident ID.

### E07 — MITRE ATT&CK Context
- **What must be demonstrated:** Mapping fused incidents to MITRE ATT&CK tactics/techniques.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_mitre_worker.py::TestMitreWorker::test_successful_mapping -v
  ```
- **Expected observable result:** Threat context associated with the Incident ID based on its detection events.

### E08 — Trust/Risk Assessment
- **What must be demonstrated:** Generation of deterministic trust and risk scores for an incident.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_assessment_worker.py::TestAssessmentWorker::test_successful_assessment -v
  ```
- **Expected observable result:** Calculation of a composite risk score and evaluation of agent trust.

### E09 — Multi-Agent Reasoning
- **What must be demonstrated:** Verification and synthesis of claims by the Reasoning agent framework.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_verification_agent.py::TestVerificationAgent::test_valid_verified_result -v
  ```
- **Expected observable result:** Multi-agent reasoning verifying claims based purely on collected evidence.

### E10 — Governance
- **What must be demonstrated:** Deterministic governance appending immutable decisions based on reasoning outputs.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_governance.py -v
  ```
- **Expected observable result:** Strict state transitions where unverified evidence results in `HOLD` and fully verified allows `AUTO_APPROVE`.
- **What must NOT be claimed:** Analyst overrides altering existing records (must be append-only).

### E11 — Complete E2E Pipeline
- **What must be demonstrated:** The full pipeline end-to-end processing.
- **Pipeline Flow:** `Endpoint Telemetry -> Local Detection -> Detection Event -> Central SOC Ingestion -> Evidence Fusion -> MITRE ATT&CK Context -> Trust/Risk Assessment -> Multi-Agent Reasoning -> Governance -> Decision -> Operational API / Audit`
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_e2e_integration.py -v
  ```
- **Expected observable result:** 11 passed E2E tests, verifying complete pipeline integrity. Includes: `test_e2e_bruteforce_complete`, `test_e2e_multi_evidence_single_incident`, `test_e2e_unmapped_detection_no_mitre`, `test_e2e_insufficient_data_hold`, `test_e2e_contradicted_claim_reject`, `test_e2e_ab_supersession`, `test_failure_mitre_incident_survives`, `test_failure_assessment_mitre_survives`, `test_failure_reasoning_assessment_survives`, `test_failure_governance_analysis_survives`, `test_provenance_chain_complete`.

### E12 — Backend Regression
- **What must be demonstrated:** Full robustness of the central backend code.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/ -v
  ```
- **Expected observable result:** 183 passing tests (with typical Pydantic warnings).

### E13 — Windows Regression
- **What must be demonstrated:** Full robustness of the Windows telemetry endpoint code.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\windows-telemetry
  python -m unittest discover -s tests -v
  ```
- **Expected observable result:** 62 passed, 1 skipped (due to intended lack of admin permissions for security log checks).

### E14 — Operational APIs
- **What must be demonstrated:** Read-only SOC API layer providing query capabilities for incidents, assessments, and governance history.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_api_integration.py -v
  ```
- **Expected observable result:** 12 passed tests showing functional GET operations and blocked POST override operations (`501 Not Implemented`).

### E15 — Authentication
- **What must be demonstrated:** Secure API boundaries using static token validation.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_api_integration.py::TestAPIIntegration::test_unauthorized -v
  ```
- **Expected observable result:** `401 Unauthorized` for bad bearer tokens.

### E16 — Provenance / History
- **What must be demonstrated:** The API exposes an intact provenance chain (`detection_event_id` → `incident_id` → `context_id` → `assessment_id` → `analysis_id` → `decision_id`).
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_api_integration.py::TestAPIIntegration::test_provenance_history -v
  ```
- **Expected observable result:** Provenance history object correctly associating valid real IDs across the entire pipeline. No fake IDs are fabricated.

### E17 — Failure Isolation
- **What must be demonstrated:** The failure of one component (e.g., Reasoning) does not break previous component data (e.g., Assessment or Mitre).
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC\SOC\backend
  python -m pytest tests/test_e2e_integration.py::TestE2EIntegration::test_failure_reasoning_assessment_survives -v
  ```
- **Expected observable result:** Resilience and isolation proving micro-worker fault tolerance.

### E18 — Git Release State
- **What must be demonstrated:** A clean release state with committed history.
- **Relevant repository path:** `P:\Trust-Governed-Adaptive-Multi-Agent-SOC`
- **Exact command:**
  ```powershell
  cd P:\Trust-Governed-Adaptive-Multi-Agent-SOC
  git status
  git log --oneline --decorate -15
  git diff --check
  ```
- **Expected observable result:** Clean working tree, recent commits including Step 12A and Step 12B API releases (e.g., `feat: add Step 12B operational SOC APIs`).

---

## 6. Implementation Status Claims

### Implemented:
- Endpoint telemetry collection
- Normalization (Windows events)
- Local detection logic (e.g., duplicate suppression, multi-event windows)
- Central ingestion API
- Evidence fusion engine
- MITRE ATT&CK context mapping prototype
- Trust/Risk assessment prototype
- Multi-agent reasoning prototype (Verification & Synthesis logic)
- Deterministic append-only governance
- Provenance tracking
- E2E Integration tests covering all stages
- Operational APIs (Read-only incident retrieval)
- Token-based API Authentication

### Not Yet Implemented:
- Dashboard application
- Analyst UI
- Actual response execution (remediation actions)
- Threat memory layer
- Drift detection
- Adaptive learning / self-updating thresholds
- Federated learning
- MapReduce processing scale-out
- Production-grade external LLM integration

## 7. Recommended Screenshot Sequence

For presenting the Semester-I Report/PPT, collect screenshots in this order:

1. **Architecture/Pipeline (E11)** - Run E2E test suite to prove full pipeline automation.
2. **Windows Telemetry & Detection (E02, E04)** - Show telemetry startup and an isolated detection test to prove endpoint functionality.
3. **MITRE & Fusion (E06, E07)** - Show correlation functionality.
4. **Trust/Risk & Reasoning (E08, E09)** - Demonstrate the AI validation aspects of the system.
5. **Governance & Provenance (E10, E16)** - Show immutability and provenance tracking (critical for the core project thesis).
6. **Robustness (E12, E13, E17)** - Run overall regression test commands.
7. **APIs (E14)** - Demonstrate data accessibility via backend endpoints.
