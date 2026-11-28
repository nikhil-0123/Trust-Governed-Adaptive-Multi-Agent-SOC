# TGAM-SOC Dataset Selection & Qualification Registry (Phase 3B-P)

This document records verified provenance, licensing, schema compatibility, label integrity, storage planning, and formal qualification verdicts for public cybersecurity datasets evaluated alongside the native TGAM-SOC Windows authentication pilot.

> [!IMPORTANT]
> No frozen Phase 2 production telemetry files (`windows-telemetry/`, `SOC/backend/`) are modified, and no XGBoost model training is authorized in Phase 3B-P. Evidence is strictly separated into: **(a) Publisher Documentation**, **(b) Independent/Third-Party Claims**, and **(c) Locally Measured Results**.

---

## 1. Evidence & Security Posture

- **Windows Defender Real-Time Protection:** Verified enabled (`RealTimeProtectionEnabled: True`, `AntivirusEnabled: True`). Zero exclusions created; zero quarantined files restored.
- **Public Dataset Safety Rule:** All downloaded datasets are treated as untrusted research inputs and inspected read-only/passively (no executing embedded commands, scripts, or binaries).
- **Windows-APT 2025 v4 Blocker Metadata (`BLOCKED_BY_ENDPOINT_PROTECTION`):**
  - During passive download of `combined.csv` (`247,934,817` bytes expected), Windows Defender (`EventID 1117`, `2026-11-27T16:37:38.6360000Z`) quarantined the partial file at `65,732,608` bytes with severity **Severe**:
    - Threat Name: `Trojan:VBS/Boxter.HAB!MTB` (Threat ID `2147938472`)
    - Action: `Quarantine`
    - Reason: Plaintext Wazuh alert rows embed malicious adversary script/command strings from Caldera scenarios.
  - Per security constraints, `combined.csv` acquisition was halted and remains marked **`BLOCKED_BY_ENDPOINT_PROTECTION`**. Only non-executable documentation and manifest files (`README.md`, `checksums.sha256`, `scenario_manifest.csv`, `validation_summary.csv`) were retained under gitignored `ml/data/windows_apt_v4/`.
  - Investigation of publisher API `https://data.mendeley.com/public-api/datasets/b8fmtzvpy8/files?folder_id=root&version=4` confirmed 20 root entries totaling `480,859,935` bytes (`458.58 MB`) and no sanitized/feature-only non-payload replacement for the alert CSVs. (`/folders?version=4` returned HTTP 404, leaving `scenario_mapping_supplement/log_to_scenario_mapping.csv` unavailable via that API route.)

---

## 2. Dataset Summary & Compatibility Matrix

| Dataset | Publisher & Version | DOI / URL | License | Acquisition Status | Native `auth_anomaly_features_v1` Compatible? | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LANL Cyber1** | LANL / A. Kent (`LA-UR-15-23810`) + HF mirror `Taqui/lanl-cyber-datasets@b0a7c62188277218cec435d492ebc3d9b3cadbef` | `10.17021/1179829`<br>https://csr.lanl.gov/data/cyber1/ | CC0 1.0 | **Acquired & Qualified** (`auth.txt.gz` `7.63 GB`, `redteam.txt.gz` `4.85 KB`; `11.04M`-row Parquet subset built) | **No** (separate `lanl_auth_features_v1` only) | **PARTIAL PASS** (Offline Public Benchmark Ready w/ Caveats; Native Deployment **BLOCKED**) |
| **Windows-APT 2025 v4** | Univ. of Guelph / M. Mozaffari et al. (`v4`, `2026-07-03`) | `10.17632/b8fmtzvpy8.4`<br>https://data.mendeley.com/datasets/b8fmtzvpy8/4 | CC BY 4.0 | `BLOCKED_BY_ENDPOINT_PROTECTION` (`combined.csv`); Docs verified | **No** (Wazuh SIEM alert export CSV) | **BLOCKED** |
| **OTRF Security-Datasets** | Open Threat Research Forge (`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`) | https://github.com/OTRF/Security-Datasets | MIT | **Acquired & Audited Passively** (3 captures, `2.48 MB`) | **Schema/Rule Adapter Only** (`otrf_mordor_audit_v1`) | **APPROVED FOR SCHEMA/RULE TESTING ONLY** |
| **LANL Unified 2017** | LANL / Turcotte et al. (`LA-UR-17-20763`) | `10.1142/9781786345646_001`<br>https://csr.lanl.gov/data/2017/ | CC0 1.0 | `PENDING_MANUAL_OWNER_FORM` (Unprioritized) | **No** (no labels, no client IPs in 4624 JSON) | **REJECTED** |
| **UWF-ZeekData24** | Univ. of West Florida (`Data` 2025 10(5):59) | `10.3390/data10050059`<br>https://datasets.uwf.edu/ | CC BY 4.0 | Not Acquired (Domain Mismatch) | **No** (Zeek network flows, 0 host auth events) | **REJECTED** |
| **TGAM-SOC Native Lab** | TGAM-SOC Project (`v1.0.0` baseline pilot) | Local gitignored `ml/data/pilot_read_only/` | Internal | **Baseline Collected** (`1,153` 4624; `0` 4625) | **Yes** (`100%` contract match) | **CONDITIONAL** |

---

## 3. Detailed Verified Findings Per Dataset

### 3.1 LANL Cyber1 (`10.17021/1179829` — Phase 3B-P2 Verified)
- **Provenance & Checksums (`D:\TGAM-SOC-Datasets\lanl_cyber1\raw\`):**
  - `auth.txt.gz` (acquired via `Taqui/lanl-cyber-datasets` pinned revision `b0a7c62188277218cec435d492ebc3d9b3cadbef`): `7,626,505,158` B, SHA-256 `9c6b0cc261b0edd19324f6fd1839743224938a7f644ed202ca70bd70a89bf672` (exact match to HF LFS OID). Note HF's separate uncompressed `lanl-2015/auth.txt` (`31,666,995,200` B) is truncated, whereas `auth.txt.gz` decompresses cleanly (`gzip_eof_clean: true`) to `73,413,019,178` B (`sha256: 2c74a10affa0dafa336b6a5b0eebd6f6d8748b3136d10302fff41e7061023480`).
  - `redteam.txt.gz` (official LANL portal): `4,846` B, SHA-256 `606635837c684ad11e464075ecf97bc5df325ff7d7f64614d2d8c8af18051669` (exact match to HF LFS OID).
- **Complete Streaming Measurements (`1,051,430,459` rows, `0` malformed, `0` out-of-order, `0` adjacent duplicate rows):**
  - Outcomes: `Success = 1,038,590,151`, `Fail = 12,840,308` (`1.22%`).
  - Missingness (`?`): `0` missing in `su`, `du`, `sc`, `dc`, `ao`; `auth_type = 583,350,819` (`55.48%`); `logon_type = 147,250,039` (`14.00%`).
  - Orientations: `LogOn 468,170,253`, `LogOff 436,100,783`, `TGS 99,003,278`, `TGT 38,390,589`, `AuthMap 9,571,401`, `ScreenLock 99,556`, `ScreenUnlock 94,599`. Truncated `MICROSOFT_AUTHENTICATION_P*` prefix strings confirmed (`normalize_lanl_auth_type_family()` added).
  - Exact Red-Team Join: `749` total rows (`715` unique keys, `34` exact duplicate lines across `12` keys); `701/715` unique keys matched `702` unique auth events (`100%` via `destination_user`; `701` Success, `1` Fail; `100%` `NTLM Network LogOn`); `14` unique keys unmatched (`same-second alternate destination computer`); `1` collision (`2552687 U9263@DOM1 C17693->C828 Fail+Success`).
- **Reproducible 3-Block Parquet Subset (`D:\TGAM-SOC-Datasets\lanl_cyber1\processed\lanl_research_subset_v1.0.0.manifest.json`):**
  - `train_day8_h211_214`: `2,564,823` eval rows (`136` pos, `38.40 MB`, host `C17693`)
  - `val_day13_h323_327`: `5,511,547` eval rows (`53` pos, `86.07 MB`, hosts `C17693`, `C19932`, `C22409`)
  - `test_day29_h708_710`: `2,963,455` eval rows (`9` pos, `46.24 MB`, hosts `C17693`, `C19932`)
  - Total: `11,039,825` rows (`198` pos, `170,719,210` B Zstd Parquet) with `1,800s` per-block warmup lead-in and `4.5`-day / `15.8`-day inter-split separations; `test_vs_train = ["C17693"]` and `test_vs_val = ["C17693", "C19932"]` host overlap documented. See [BASELINE_METHODOLOGY.md](file:///P:/Trust-Governed-Adaptive-Multi-Agent-SOC/ml/lanl_benchmark/BASELINE_METHODOLOGY.md).
- **TGAM-SOC Role:** Ready strictly for constrained offline Phase 3C public-benchmark ablation experiments under `lanl_auth_features_v1` (**PARTIAL PASS**). Native Windows deployment remains **BLOCKED**.

### 3.2 Windows-APT 2025 v4 (`10.17632/b8fmtzvpy8.4`)
- **Locally Verified SHA-256 Digests (`ml/data/windows_apt_v4/`):**
  - `checksums.sha256`: `d9401239cc2c1b692edf480fb66dc561ac17be69e157e2789af13338be86aa17` (`1,762` B)
  - `README.md`: `02d192e575851bcf342a7abfb617b5bc219d8bb0f825e47a7ee4a0e97835822b` (`9,214` B) — matches `checksums.sha256`
  - `scenario_manifest.csv`: `77b881e662b2b912fa466a2510fb65597342b3869d0113118f49558dbb1fa81f` (`28,317` B) — matches `checksums.sha256`
  - `validation_summary.csv`: `61afe9da2c7ea32f6ab58a700163c0bbb23c0b8b70e5142580d4a3113d731781` (`7,318` B) — matches `checksums.sha256`
- **Inspected Header & Publisher Caveats:**
  - First 2 lines inspected prior to quarantine (`combined_part.dat`) show Elasticsearch/Wazuh alert-export columns (`_index=wazuh-alerts-4.x-*`, `_source.agent.name=Maryam`, `_source.rule.level=3`, `"Log file rotated."`).
  - `README.md` documents `Maryam` is the Wazuh manager host (non-attack infra), and v4's IDF-weighted `log_to_scenario_mapping.csv` maps `102,011` rows where `UNIQUE-MATCH + NARROWED` is only `6.2%`, leaving ~93.8% of alert rows without unique scenario attribution.
  - `scenario_manifest.csv` covers 36 APT scenarios (`S01`–`S36`); only a small subset (`S06`, `S07`, and lateral/credential scenarios) touches `T1110`/`T1078`/`T1021`, rather than raw OS authentication balances.

### 3.3 OTRF Security-Datasets (`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`)
- **Repository Revision & Licensing:** Commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` (`2023-09-20T14:42:56Z`), root `MIT License` (`Copyright (c) 2021 Open Threat Research Forge`). Individual YAML files declare no conflicting per-capture license.
- **Locally Audited Captures (`ml/data/otrf_samples/`, passive zip read only):**
  1. `SDWIN-201022042947` (`PurpleSharp Active Directory Playbook I`, `purplesharp_ad_playbook_I.zip`, `1,362,498` B, SHA-256 `2a2d80e7b8d8ee6821a1754118f3ab908b4bac84cf4ed3d018e281f631bd2870`):
     - `25,993` events over `54.047 s` (`2020-10-22T08:29:48.785Z` .. `08:30:42.832Z`).
     - Security Events: `4624 = 49` (all `LogonType="3"`), `4625 = 7` (all `LogonType="2"` via `LogonUser`), `4769 = 17`, `4776 = 7`.
     - `IpAddress`: `42` `"-"`/missing, `1` loopback, `13` private lab IPv4 (`172.18.38.6`, `172.18.39.5/6/7`).
     - `0` raw JSON duplicates, `0` `(Channel, Hostname, RecordNumber)` collisions.
  2. `SDWIN-190518211456` (`Empire Invoke PSRemoting`, `empire_psremoting_stager.zip`, `409,741` B, SHA-256 `214355730c8cf903f4423c96aa7459fed7b74258e2a6766b794ba316e9d3a46e`):
     - `2,744` events over `99.571 s` (`2020-09-20T21:08:28.399Z` .. `21:10:07.970Z`).
     - `4624 = 8` (`LogonType="3"`), `4625 = 0`; `IpAddress`: `3` `"-"`, `2` `::1`, `2` `fe80::...`, `1` `172.18.38.6`; `0` duplicates.
  3. `SDWIN-190319131123` (`Empire Over-Pass-The-Hash`, `empire_over_pth_patch_lsass.zip`, `829,257` B, SHA-256 `daee42bbd9f7c6265e5614ce468ec868a399ee03877456dd01ec34e3e06479e7`):
     - `10,271` events over `101.731 s` (`2020-09-22T02:13:37.997Z` .. `02:15:19.728Z`).
     - `4624 = 8` (`LogonType="3": 7`, `LogonType="9": 1` `NewCredentials`), `4625 = 0`; `IpAddress`: `4` `::1`, `2` `fe80::...`, `2` IPv4 (`172.18.38.5`, `172.18.39.5`); `0` duplicates.
- **Schema & Label Findings:** OTRF uses flat Winlogbeat/NXLog keys (`RecordNumber` instead of `EventRecordID`, lowercase `"security"` channel alongside `"Security"`, string `LogonType`, mixed short/FQDN `Hostname`). Crucially, all records have only `"tags": ["mordorDataset"]` and mix normal machine logons (`MORDORDC$`, `WEC$`) with attack steps—whole-capture malicious labeling is invalid.

### 3.4 LANL Unified Host & Network 2017 (`10.1142/9781786345646_001`) & UWF-ZeekData24 (`10.3390/data10050059`)
- **LANL 2017:** Daily host JSON (`wls_day-*.bz2`) contains Event IDs `4624`/`4625`, but publisher docs show no adversary/compromise ground-truth file and no client `IpAddress` in sample 4624 JSON. **Verdict: REJECTED** for supervised training.
- **UWF-ZeekData24:** Network-layer Zeek connection flows (`CC BY 4.0`, MITRE tactic-labeled) with zero Windows host OS authentication records. **Verdict: REJECTED** for endpoint authentication anomaly detection.

### 3.5 TGAM-SOC Native Windows Dataset (`auth_anomaly_features_v1`)
- Inspected manifest `host_pilot_auth_baseline_v1.0.0.manifest.json`: `1,153` genuine Windows `4624` records (`0` `4625`, `0` valid remote source IPs, `f1`–`f5` availability `0.0`, `label=1` count `0`). Contract parity is 100% aligned with `windows-telemetry/`, but training remains blocked until multi-host + remote-source `4624`/`4625` benign and authorized attack sessions are collected. **Verdict: CONDITIONAL**.

---

## 4. Storage & Manual LANL Acquisition Plan

### 4.1 Verified Free Disk Space & Directory Layout
- `C:\`: `109.87 GB` free / `334.71 GB`
- `D:\`: `46.70 GB` free / `120.47 GB` (Selected external dataset volume)
- `P:\`: `14.37 GB` free / `19.53 GB` (Repository workspace — do not place multi-GB corpora here)

Proposed directory tree outside Git tracking:
```text
D:\TGAM-SOC-Datasets\
├── lanl_cyber1\
│   ├── raw\
│   │   ├── auth.txt.gz       (~7.2 GB compressed — DO NOT decompress)
│   │   ├── redteam.txt.gz    (~4.8 KB compressed)
│   │   └── sha256_local.json (owner-computed SHA-256 checksums)
│   └── processed\            (streamed subset/parquet outputs + manifests)
├── otrf_cache\               (optional external mirror of MIT captures)
└── model_artifacts\          (future Phase 3C XGBoost checkpoints & eval reports)
```

### 4.2 Official Manual LANL Cyber1 Download Procedure (Owner Action Required)
Because `https://csr.lanl.gov/data/cyber1/` gates downloads via `#fence` (`POST /data-fence/token` requiring genuine owner email and research usage disclosure), automated submission is prohibited. The project owner should perform:
1. Open `https://csr.lanl.gov/data/cyber1/` in a trusted browser.
2. Fill in your authentic email address and academic research usage description for TGAM-SOC, then submit the form.
3. Once the tokenized URLs unlock on-page (`https://csr.lanl.gov/data-fence/<TOKEN>/auth/auth.txt.gz` and `redteam.txt.gz`), download **only** `auth.txt.gz` and `redteam.txt.gz` directly into `D:\TGAM-SOC-Datasets\lanl_cyber1\raw\`.
4. Do **not** paste or commit the session `<TOKEN>` into repository files, scripts, or logs, and do **not** decompress `auth.txt.gz` onto `P:` or `D:`.
5. Compute SHA-256 checksums (`Get-FileHash auth.txt.gz -Algorithm SHA256` and `redteam.txt.gz`) and feed compressed `.gz` paths directly to `ml.lanl_benchmark.pipeline.build_lanl_benchmark_dataset()`.
