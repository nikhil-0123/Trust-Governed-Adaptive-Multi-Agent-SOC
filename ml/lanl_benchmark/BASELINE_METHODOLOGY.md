# LANL Cyber1 Public Benchmark Baseline & Preregistered Evaluation Protocol (`lanl_auth_features_v1`)

> [!IMPORTANT]
> This methodology defines the preregistered offline Phase 3C public-benchmark protocol under research-only schema `lanl_auth_features_v1`. It does not alter frozen Phase 2 telemetry (`windows-telemetry/`, `SOC/backend/`), native `auth_anomaly_features_v1`, or canonical identities. Probability calibration and operational deployment threshold selection remain deferred.

---

## 1. Benchmark Target Definition & Scope Boundaries

- **Target Variable (`label`):** Authentication activity associated with released LANL Cyber1 `redteam.txt.gz` compromise annotations `(time_rel, user@domain, source_computer, destination_computer)`.
- **Scope Limitation:** Evaluates association with released red-team lateral/authentication events over 58 days. It must **NOT** be framed as comprehensive brute-force or password-spray detection (`701/702` corpus matches are `Success`-ful `NTLM`/`Network`/`LogOn` records).
- **Background Semantics:** Records carrying `UNMATCHED_NON_REDTEAM` must always be described explicitly as **unannotated enterprise background**, never independently proven benign enterprise traffic.
- **Failed-Authentication Bias:** Per publisher documentation, failed authentications (`Fail`) are included *only* for users that recorded at least one successful authentication in the corpus.
- **Chronological & Window Contract:** `LanlCausalFeatureExtractor` requires strictly non-decreasing chronological inputs (`time_rel >= watermark`, equal timestamps allowed with `[t - W, t)` self/tie exclusion) and enforces fixed `retention_seconds = 900` matching its `60s` (`1m`), `300s` (`5m`), and `900s` (`15m`) rolling features.

---

## 2. Four-Tier Baseline & Model Comparison (Phase 3C)

Fit any categorical encoders, imputers, and hyperparameters exclusively on development partitions (`train` / `val`). Never use the final test partition for feature selection, hyperparameter tuning, or threshold selection.

| Tier | Inputs & Decision Mechanism | Scientific Role | Native Runtime Distinction |
| :--- | :--- | :--- | :--- |
| **1. Deterministic Count Baseline (`lanl_count_threshold_v1`)** | Causal sliding counts (`lanl_fail_count_1m`, `lanl_fail_count_5m`, `lanl_fail_count_15m`, `lanl_auth_count_15m`, `lanl_unique_dst_hosts_per_src_15m`) with threshold rules + availability masks. | Non-ML baseline on PR-AUC / precision-recall / alerts-per-hour curves. | **NOT identical to Windows `BruteForceRule`**: aggregates on LANL computer/pair streams without native IPs, verified domain context, or Event `4625` semantics. |
| **2. Logistic Regression (`logreg_lanl_v1`)** | Standardized `LANL_MODEL_INPUT_COLUMNS` (`*_available` masks preserved; training-only categorical encoding & median imputation). | Interpretable linear comparison baseline. | Offline LANL benchmark only. |
| **3. Conservative XGBoost (`xgb_lanl_v1`)** | Constrained gradient-boosted trees over `LANL_MODEL_INPUT_COLUMNS` (shallow depth, regularization, native `NaN` missingness handling, no large search against Day 29). | Primary non-linear public benchmark candidate. | Trained strictly on `lanl_auth_features_v1`; zero runtime Windows deployment role. |
| **4. Rule-Plus-XGBoost Hybrid (`hybrid_rule_plus_xgb_lanl_v1`)** | Deterministic threshold score combined with `xgb_lanl_v1` ranking on unannotated vs red-team events under matched alert budgets. | Tests whether ML ranking adds signal over causal counts without rule-label circularity. | Offline benchmark evaluation only. |

---

## 3. Preregistered Mandatory Ablations & Sensitivity Analyses

Every Phase 3C experiment must freeze predictor column lists (`LANL_MODEL_INPUT_COLUMNS` strictly excluding `source_computer`, `destination_computer`, users, `record_seq`, `time_rel`, and `unavailable_reasons`), ambiguity policies, and partition SHA-256 hashes before evaluating predictions:

1. **Feature-Set Ablations:**
   - **Context-only:** `is_auth_failure`, `is_cross_host`, `auth_type_cat`, `logon_type_cat`, `auth_orientation_cat` (measures shortcut leverage from `NTLM`/`Network`/`LogOn`).
   - **Rolling-feature-only:** `lanl_fail_count_1m/5m/15m`, `lanl_auth_count_15m`, `lanl_unique_dest_users_15m`, `lanl_unique_dst_hosts_per_src_15m`, `lanl_logon_type_entropy_15m`, plus availability flags.
   - **Combined (`LANL_MODEL_INPUT_COLUMNS`)** evaluated **with and without `lanl_rel_hour_mod24`** (`lanl_rel_hour_available`), verifying sensitivity since `time_rel` is an offset lacking local timezone/wall-clock semantics.
   - Evaluate both over full unannotated background and stratified specifically within the `NTLM` + `Network` + `LogOn` slice.
2. **Label Sensitivity (Strict Primary vs Flagged Inclusive):**
   - **Primary Supervised View (`192` exact positives on closed v1.0.0 subset):** Exclude the `6` `AMBIGUOUS_MULTI_MATCH` rows (`3` val, `3` test) from training/selection/scoring while retaining them in causal `[t - W, t)` history. Split counts: Train `136`, Validation `50`, Test `6` (`11,039,819` total rows).
   - **Ambiguous-Inclusive Sensitivity (`198` positives):** Report secondary comparison retaining ambiguous rows (`Train: 136`, `Val: 53`, `Test: 9`), explicitly stating whether fitted weights were held fixed or re-fit.
3. **Host Concentration & Overlap Analysis:**
   - Report per-block and per-source-computer support (`C17693`, `C19932`, `C22409`, `C18025`) alongside host-grouped cross-validation / source-host holdout where support permits. Acknowledge binomial uncertainty on low-support blocks (e.g., `6` strict test positives on `C19932` alone means 1 event shifts recall by `16.7` percentage points).
4. **Matched Alert-Budget Metrics:**
   - Report PR-AUC alongside base prevalence, precision/recall/F1 at fixed validation-selected operating points, alerts per hour (`10`, `50`, `100` alerts/hour budgets), and Day-2 Hour-58 rare `C18025` (`3` events) descriptive probe.
   - Do **not** claim calibrated probabilities or transferable enterprise false-positive rates from annotation-enriched blocks without separate unenriched background sampling.

---

## 4. Candidate Chronological Expansion Periods (Verified Support Only — Not Yet Extracted)

Audited directly from existing corpus-wide red-team join results ([lanl_task4_join_audit.json](file:///P:/Trust-Governed-Adaptive-Multi-Agent-SOC/scratch/phase3b_evidence/lanl_task4_join_audit.json)) and `lanl_full_audit_stats.json` (zero corpus rescan or unnecessary dataset regeneration performed):

| Candidate Window (`floor(t/86400)`) | Verified Full-Day Exact Matches | Ambiguous Matches | Source Host Mix (Exact) | Prospective Phase 3C Role (Requires Pre-Registered Block Lengths Before Viewing Predictions) |
| :--- | :---: | :---: | :--- | :--- |
| **Days 1–9** (closed subset uses Day 8 H211–214: `136`) | `312` (`Day 8 = 261`) | `4` (`Day 9`) | `C17693: 303`, `C19932: 5`, `C18025: 3`, `C22409: 1` | Early training pool + Day-2 Hour-58 `C18025` rare-host case. |
| **Day 12** (`t = 1,036,800 .. 1,123,200`) | **`207`** | `0` | `C17693: 204`, `C19932: 1`, `C22409: 2` | High-support rolling development / validation fold (`19.87M` full-day events). |
| **Days 13–15** (closed subset uses Day 13 H323–327: `50`) | **`121`** (`72 + 23 + 26`) | `5` (`3 + 2 + 0`) | `C17693: 119`, `C19932: 2` (`+ C22409: 3` ambig) | Multi-day contiguous development folds (`59.33M` combined 3-day events). |
| **Days 26–29** (closed subset uses Day 29 H708–710: `6`) | **`43`** (`26 + 9 + 1 + 7`) | `4` (`0 + 0 + 1 + 3`) | `C17693: 34`, `C19932: 9` | Multi-day prospective late evaluation window (`76.09M` 4-day events) solving Day-29 single-host (`C19932`-only, `n=6`) statistical fragility if pre-committed before model evaluation. |
| **Quiet Background Windows** (e.g., Days `0, 3, 4, 10, 11, 16–19, 23–25, 30–57`) | `0` | `0` | `—` | Annotation-blind contiguous time samples paired cleanly to estimate alert burden without 27x annotation-period enrichment bias. |
