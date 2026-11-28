# TGAM-SOC development plan

## Decision record — 2026-11-28

**Phase 3B-P2 qualification is complete. Independent acceptance is a partial pass for exploratory offline LANL research on the three closed v1.0.0 partitions.** The ordered blocks satisfy the delivered identity, schema, label, chronology and embargo checks. Evidence limits the scope of tuning, calibration and generalization claims. The owner retains authority to start Phase 3C. No model has been trained in this acceptance.

| Item | Observed baseline |
|---|---|
| Repository | `P:\Trust-Governed-Adaptive-Multi-Agent-SOC`, branch `feature/collector-outbox-robustness`, HEAD `f3b6feed99328d8d8648f479ec2875136c409158`. |
| Synchronization | One registered worktree. Local main and both cached origin branch refs matched HEAD. Live remote and hosted checks were not queried. |
| Implementation state | Windows Phase 2.4 freeze at `21a080d`, followed by reconciliation and the per-agent authentication/logger cleanup at HEAD. Production Windows detector is 1.1.0. The offline ML tree is untracked. The unstaged .gitignore change adds research exclusions. A clean checkout at HEAD omits the ML handoff. |
| Handoff | Owner reported Antigravity finished. Process inspection found the IDE running and no matching active qualification job. Two observations of 265 tracked/untracked source and qualification files, including generated evidence and external outputs, matched in path, size and modification time. No competing root document was present. |
| Regression evidence | Saved P2 JUnit reports in `scratch/phase3b_evidence/`. Current browser, external LLM, scientific efficacy and production-readiness claims remain open. |

| Saved report | Collected | Passed | Failed | Skipped | Errors |
|---|---:|---:|---:|---:|---:|
| windows_telemetry_p2.junit.xml | 540 | 539 | 0 | 1 | 0 |
| soc_backend_p2.junit.xml | 331 | 331 | 0 | 0 | 0 |
| ml_tests_p2.junit.xml | 25 | 25 | 0 | 0 | 0 |
| **Combined** | **896** | **895** | **0** | **1** | **0** |

The Windows integration case was denied access to the Security log. Record that skip explicitly. The prior November 27 baseline was 892 passed across the same three suite families. Ubuntu, dashboard and end-to-end harness counts are separate. These saved runs cannot identify the untracked ML source by Git SHA.

Fresh acceptance run on Python 3.12.7 and PyArrow 22.0.0: `python -B -m pytest -q --tb=short -p no:cacheprovider --basetemp <fresh-temporary-directory> ml/tests/test_lanl_benchmark_pipeline.py` returned **10 passed, 0 failed, 0 skipped, 0 errors**. Initial temp-directory restrictions prevented startup, then caused five fixture setup errors on a first run of the whole file (five passed). The isolated rerun resolved all five. The focused result is separate from the 895.

## Work delivered

- Committed sources include the normalized contract/schema, Windows and Ubuntu telemetry agents, central FastAPI/SQLite ingestion and workers, incident fusion, MITRE, assessment, reasoning, governed response bridge and React dashboard. The Ubuntu main pipeline wires auth-log collection. Dedicated Ubuntu server instrumentation and a separate SOC manager have reserved paths only.
- Windows milestones delivered canonical identities and revision manifests, durable outbox/backpressure, fenced checkpoint/recovery, witness/epoch governance, multichannel scheduling, Sysmon evidence handling, evaluation routing and production version enforcement. Windows and Ubuntu have different delivery semantics.
- Phase 3A/3B working-tree deliverables include the offline native authentication collector, causal extractor, scenario/label attribution, pseudonymization, builder, manifests, splitting, public-data screening, OTRF adapter and tests. The genuine native pilot contains 1,153 successes, zero 4625 failures, zero positives and no valid remote IP observations. It cannot support supervised training.
- Phase 3B-P established the registry and separate LANL contract. P2 delivered bounded extraction, incremental features, independent annotation joins, typed Parquet partitions and a measured pilot. The registry is now version 1.1.0 and records ACQUIRED_AND_QUALIFIED_SUBSET and PARTIAL_PASS_BENCHMARK_READY. Its earlier pending-acquisition status is superseded. The manual-download section at the end of ml/DATASET_SELECTION.md is historical guidance.
- OTRF's three audited captures are approved for parser/schema/rule fixtures only. Windows-APT v4 remains blocked by endpoint protection and attribution limitations. LANL Unified 2017 and UWF-ZeekData24 are rejected for supervised native authentication training. Keep raw data and forensic artifacts external to the commit.

## Independent P2 artifact acceptance

External root is `D:\TGAM-SOC-Datasets\lanl_cyber1`. The processed manifest `processed/lanl_research_subset_v1.0.0.manifest.json` and its evidence copy have SHA-256 `f638bdc374cea96a01796730d0c9ca4cc84ccf0e546aaab3f363df371d9147ae`. This comparison establishes local integrity. The recorded compressed auth origin is mirror `Taqui/lanl-cyber-datasets@b0a7c62188277218cec435d492ebc3d9b3cadbef`, with SHA-256 `9c6b0cc261b0edd19324f6fd1839743224938a7f644ed202ca70bd70a89bf672`. The small annotation archive, recorded as obtained from LANL, independently rehashed to `606635837c684ad11e464075ecf97bc5df325ff7d7f64614d2d8c8af18051669`. The prior full-stream audit records 1,051,430,459 authentication rows and clean EOF. Acceptance read the three extracted blocks, the annotations and the closed outputs. It did not repeat the corpus scan or verify publisher infrastructure.

| Partition | Exported [start,end), relative seconds | Warm-up rows excluded | Exported rows | Exact positive | Ambiguous positive | Unmatched background |
|---|---|---:|---:|---:|---:|---:|
| Train, day 8 | [759600,774000) | 324,655 | 2,564,823 | 136 | 0 | 2,564,687 |
| Validation, day 13 | [1162800,1180800) | 576,054 | 5,511,547 | 50 | 3 | 5,511,494 |
| Test, day 29 | [2548800,2559600) | 471,869 | 2,963,455 | 6 | 3 | 2,963,446 |
| **Total** | Three chronological blocks | **1,372,578** | **11,039,825** | **192** | **6** | **11,039,627** |

| Closed output in processed/ | Bytes | SHA-256 verified against manifest and registry |
|---|---:|---|
| train_day8_h211_214_v1.0.0.parquet | 38,404,881 | be051227134e4b83187618fbfbe1d72d3b800912d344022dd82010f3771fe67c |
| val_day13_h323_327_v1.0.0.parquet | 86,071,594 | 5bf832b9b2ee609f8a126d05ea84e401ba7a99ebf39beae87371ff6bd0bbb45f |
| test_day29_h708_710_v1.0.0.parquet | 46,242,735 | 3ff7c87664929b12ebe4674691397cd815f1a38249316f97d600057aea0ae65f |

Reproduction inputs in `raw_blocks/` are train_day8.csv.gz (SHA-256 `60313ed183a5a0768ffe299722583fe0cee7c7a89ab21156794f856d4c53bc15`), val_day13.csv.gz (`a84af7a6e077dcbd7f24ac7549dd4b2b1d18349a5f1f61f3db5565c96eeea9cb`) and test_day29.csv.gz (`6337ef24cc8f1d4d2d96305df13d5314a3c68b52c07b03ef76e8a3f3e28f67ec`). The three extract starts are 757800, 1161000 and 2547000. Use separate freshly reset states, 900-second history and 1,800-second warm-up. Preserve ambiguous flags and the exact original order.

**Verification method.** PyArrow read all 223 row groups in batches of at most 32,768 streamed rows for the population audit. All three Arrow schemas matched get_lanl_pyarrow_schema() including field order, types and nullability. The 33 physical fields are 11 provenance, five observation context, eight features, eight masks and unavailable_reasons. Physical storage order differs from predictor order. Footer counts, actual row counts, sequential exported record_seq, mask/value consistency, timestamp order, min/max, label/status/multiplicity and recorded hashes were checked. A separate bounded pass reconstructed all nine authentication fields from the exports and compared ordered stream digests with the scored raw block lines. All matched. Exact-line sets scoped to one timestamp found zero duplicates in the ordered blocks, including warm-up. Disjoint extraction intervals exclude shared observations and window history. Measured gaps between scored intervals are 388,800 and 1,368,000 seconds.

**Predictor contract.** Use exactly these 21 LANL_MODEL_INPUT_COLUMNS in this order. Fit any categorical encoder on training data alone.

~~~text
lanl_fail_count_1m, lanl_fail_count_5m, lanl_fail_count_15m,
lanl_auth_count_15m, lanl_unique_dest_users_15m, lanl_unique_dst_hosts_per_src_15m,
lanl_logon_type_entropy_15m, lanl_rel_hour_mod24,
lanl_fail_1m_available, lanl_fail_5m_available, lanl_fail_15m_available,
lanl_auth_15m_available, lanl_unique_dest_users_15m_available,
lanl_unique_dst_hosts_per_src_15m_available, lanl_logon_type_entropy_15m_available,
lanl_rel_hour_available, is_auth_failure, is_cross_host, auth_type_cat,
logon_type_cat, auth_orientation_cat
~~~

Source/destination host and user IDs, record_seq, raw time, label/source, multiplicity, ambiguity, match status and unavailable_reasons are excluded. A blanket selection of numeric columns would leak outcome metadata.

**Independent labels.** Rejoined exported records at annotation seconds using (relative second, user, source host, destination host), considering both user fields and counting annotation and auth-hit multiplicity. Checked that every positive had an annotation and all matching rows had the correct label and ambiguity. The primary supervised view drops six ambiguous rows across fitting, selection and scoring, leaving 11,039,819 rows, including 192 exact positives. Keep all raw observations in the feature history. Report an additional flagged-inclusive analysis using 198 positives and document whether predictions were held fixed or fitting also changed. Unmatched activity is unannotated enterprise background. All 198 matched rows are NTLM/Network/LogOn. The sole matched failure is ambiguous.

**Causality.** An independent direct scan over [t-W,t) matched all eight feature values and masks on 437 ordered fixture events and six after explicit reset. Cases included ties, exact 60/300/900-second cutoffs, expiry, mixed hosts/users, missing identities/logon types, entropy and genuine zeros. Duplicate detection and malformed/missing parser inputs were checked. An independent raw-history calculation also matched all eight exported features on 36 selected rows from the three blocks, including positives. This is sample feature parity and exhaustive structural/label verification.

**Extractor limit (resolved 2026-11-28 corrective pass).** The ordinary ordered path incrementally inserts/expires each entry with amortized constant queue work, while entropy scans distinct logon types (and idle entity dictionaries have no global expiry). The prior unordered fallback paths (`has_out_of_order`, `_fallback_pair_window`) were removed in `ml/lanl_benchmark/features.py`: `LanlCausalFeatureExtractor` now enforces non-decreasing chronological input (`time_rel >= watermark`, allowing equal timestamps with strict `[t - W, t)` self/tie exclusion), rejects regressions (`ValueError`) before mutating state (verified on `(1, 1002, 901)` and a 1,001-row regression fixture), propagates errors cleanly through `iter_lanl_auth_lines(enforce_monotonic=True)`, `build_lanl_benchmark_dataset`, and `build_lanl_block_parquet_dataset` (unlinking aborted partial Parquet files), and enforces fixed `retention_seconds=900` across `LanlCausalFeatureExtractor`, `LanlBuildConfig`, and `LanlBlockSpec`. Ordered feature equivalence was verified across the first 20,000 `train_day8` evaluation rows after 324,655 warmup rows, preserving `lanl_research_subset_v1.0.0.manifest.json` (`f638bdc374cea96a01796730d0c9ca4cc84ccf0e546aaab3f363df371d9147ae`) untouched. See [BASELINE_METHODOLOGY.md](ml/lanl_benchmark/BASELINE_METHODOLOGY.md) for the preregistered Phase 3C exploratory evaluation protocol (`Day 12: 207`, `Days 13–15: 121`, `Days 26–29: 43` verified corpus exact matches).

## Phase 3C evaluation decision

| Proposed use | Readiness and gate |
|---|---|
| Exploratory training | Suitable for a bounded, reproducible LANL-only comparison of count thresholds, logistic regression and a conservatively specified XGBoost candidate, with a hybrid comparison if justified. Freeze schema, ambiguity policy and split hashes first. |
| Hyperparameter selection | Suitable only for a small predeclared comparison on development data. The 50 exact validation positives come from two hosts, 49 from C17693. Avoid large searches and repeated tuning against day 29. |
| Probability calibration | Insufficient evidence for transferable probabilities. Label-conditioned block selection alters prevalence and uncovered attacks can occur among the background. Require a separate representative calibration interval and report the precise annotation target. |
| Operational thresholds | Insufficient. Explore alert-volume tradeoffs descriptively. Select operational thresholds only with representative background periods, workload budgets, independently reviewed outcomes and separate validation. Native deployment requires native evidence. |
| Final scientific evaluation | Insufficient for broad effectiveness claims. Six exact test positives all come from C19932. One event changes recall by 16.7 percentage points, and same-host observations may be correlated. Publish support and uncertainty by block and host. |

The existing blocks were chosen with knowledge of annotation locations. Across selected blocks the inclusive match rate is 17.94 per million versus about 0.67 per million in the saved corpus join (702 matches), roughly 27-fold enrichment. Strict rates per million are 53.03, 9.07 and 2.02 for train, validation and test. The source host C17693 accounts for 701 of 749 publisher annotation lines and all 136 training positives. Inclusive positive host overlap differs from strict overlap: all six strict test positives are on a host with one strict validation positive and zero strict training positives. Identities are excluded from predictors, yet contextual proxies remain. The positive context also occurs among 137,299, 279,548 and 151,801 unmatched train/validation/test rows respectively.

**Better design using bounded blocks.** Use the existing annotation-second extract to budget collection without rescanning authentication data for this decision. A fresh join against it yields 689 exact matches across the corpus. Using relative day floor(t/86400), days 8 and 12 contain 261 and 207 exact matches. Days 13–15 contain 72, 23 and 26. Days 26–29 contain 26, 9, 1 and 7. These are full-day support counts, not guaranteed counts in shorter samples.

- Register a versioned block-selection protocol before inspecting model results. Use early periods through day 9 for training, several independent contiguous blocks around days 12–15 for rolling development folds, and later blocks such as days 20–29 for chronological evaluation. Set window length and external storage budget in advance. Keep selection probabilities or rules and population denominators. Event-rich blocks may support development. Add time-sampled, annotation-blind background periods, including quiet periods outside the annotated span, for alert-burden estimates. Keep deliberately enriched and time-sampled estimates separate.
- Provide fresh preceding warm-up, disjoint raw spans and at least a 900-second embargo at boundaries. Freeze a prospective held-out block schedule. Day 29 has already been inspected for support and context. Do not repeatedly consume it for decisions. The later period has few positives even at full-day coverage. If precision remains inadequate, narrow the claim or obtain independent data.
- Chronological evaluation measures later activity on the actual host mix. Separately hold out compromised source hosts when support permits, remove corresponding training rows according to the declared grouping, and report positives and background per fold. An hour-58 pilot includes rare C18025 activity and can be used as a small stress case after verifying exact labels. Do not require every chronological split to be host-disjoint or invent attack subclasses.
- Compare rolling-only, context-only and combined inputs, with/without relative hour, plus the deterministic baseline. Report performance within NTLM/Network/LogOn and on the full background. Report PR-AUC relative to observed prevalence, precision/recall and F1 at fixed validation thresholds, alerts per unit time and matched alert budget. Include per-block and per-host counts, and uncertainty at the independent group level where estimable. Treat probability calibration, threshold transfer and real-world false-positive rates as separate questions.

## Open findings in implementation order

| Priority / boundary | Confirmed evidence | Required closure |
|---|---|---|
| Before any operational containment | SOC/backend/app/response_bridge.py reserves governed leases. The manual dispatch path in app/main.py inserts a command separately. | Trace every command entry point, require appropriate authority and lease where applicable, then test denial, approval, concurrency and audit with safe simulated actions. Operational misuse was not tested. |
| Before runtime integration | windows-telemetry/config/settings.py directly accepts explicit DATA_DIR despite mode-specific defaults. | Enforce disjoint mode state or fail closed. Test explicit overlap, restart, existing data and all derived locations. No production-state collision was induced. |
| Before accepting replay-derived risk or active hybrid output | app/fusion.py can update maximum severity on historical attachment or reclassify an existing link. app/assessment.py uses primary-compatible evidence for trust and incident severity for risk. | Exercise duplicate and changed-revision ingestion through actual fusion and assessment. Preserve primary classification and agreed trust/risk invariants. No live score drift was measured. |
| General extractor monotonic & fixed-window enforcement | Prior fallback could emit false available zeros on late `(1, 1002, 901)` events, retain unpruned state, or allow `retention_seconds=1800`. | **Closed (2026-11-28 corrective pass):** Disordered fallback removed; non-decreasing chronological order and fixed `retention_seconds=900` enforced with fail-closed `ValueError` propagation and 4 targeted tests in `ml/tests/test_lanl_benchmark_pipeline.py`. Broad late-event out-of-order reconstruction remains intentionally out of scope. |
| Before claiming equivalent Ubuntu delivery | ubuntu-telemetry/transport/outbox.py returns at queue capacity and uses INSERT OR IGNORE by ID. Its caller can advance after a normal return. | Verify retry/checkpoint behavior under capacity and payload-conflict durability. Operational loss was not measured. |
| Before native inference | windows-telemetry/detection/features.py returns unavailable F1–F4. F5–F7 are conditional. xgboost_detector.py loads no model. | Accept native data, offline/serving parity and artifact validation and retain rule-only fallback. |
| Before current UI/provider claims | Later dashboard evidence is HTTP/API-level, the October browser report covers an older revision, and app/reasoning_provider.py selects the mock provider. | Obtain candidate-specific browser interactions and separate authorized external-provider verification with evidence validation and privacy controls. |
| Before release or reproducible publication | ML source is untracked, no tracked GitHub Actions workflow was found, and Ubuntu tests, dashboard contract test, local rules, simulation harnesses and most docs are ignored. | Commit a reviewed source candidate when authorized, identify missing test inputs, record versioned bounded extraction instructions, verify in a clean worktree and cite actual CI if configured. No production-readiness or ML effectiveness claim has been established. |

## Dependency and ownership gates

Antigravity is primary implementer. Codex independently verifies a fixed handoff and implements only a separately assigned scope. Copilot assists the writer inline. GitHub Actions supplies revision-specific automated evidence. The owner authorizes work, accepts milestones and approves commits and pushes.

| Phase | Depends on | Acceptance |
|---|---|---|
| 3B-P2 Authentic LANL qualification | Acquired inputs and LANL contract | Completed with the limited verdict and hashes above. |
| 3B-L Native lab dataset collection | Authorized isolated collection and independent label plan | Genuine multi-host remote 4624/4625 sessions, valid target roles, source IPs, sufficient causal coverage and independent benign and positive sessions across time and hosts. |
| 3C XGBoost training and evaluation | Accepted dataset for each separate track | LANL exploratory work may use P2 under the restrictions above. Native training waits for 3B-L. Freeze splits, baselines, allowed inputs, metrics, ambiguity policy and limitations. |
| 3D Runtime feature parity and model artifacts | Native 3C candidate and DATA_DIR correction | Native golden-stream parity for values, ordering and masks, with model hash, metadata, version and safe fallback tests. LANL artifacts have no deployment role. |
| 3E Shadow inference | Accepted 3D candidate | Measure availability, disagreement, failure and latency on authorized telemetry. Prove shadow outputs never create active detections or commands. |
| 3F Governed hybrid detection | Accepted shadow evidence, replay integrity and dispatch authorization | Verify revisioned alerts, independent evidence accounting, governance, leases, simulated response and rollback to rules. |
| 4 Transport security and mTLS | Accepted transport identity and rollout design | Prove peer identity, certificate trust, expiry/rotation/revocation, reconnect with queued work and preserved application authorization. |
| 5 Empirical research evaluation | Versioned system, data, safety gates and declared protocol | Report reproducible comparative results, uncertainty, sample support and limitations for the tested population. |

Reserve dedicated Ubuntu server instrumentation, separate manager implementation and external-provider expansion for approved scope. Federated learning, MapReduce and advanced adaptive learning remain disabled. No model promotion or operational change follows automatically from dataset acceptance.

## Commit preparation and definition of done

The verified 29-path Phase 3A/3B/3B-P source inventory below lists exact paths relative to each directory (3 root + 26 ML paths). It includes the reviewed `.gitignore` data-exclusion hunk and excludes external datasets, Parquet artifacts, virtual environments, databases, tokens, and `scratch/` evidence. Review the staged diff when the owner separately authorizes staging. Do not stage by directory or wildcard.

Proposed commit message (awaiting explicit owner authorization):
`feat(ml): qualify LANL authentication benchmark and establish reproducible research pipeline`

| Directory | Proposed files |
|---|---|
| Root | `.gitignore`, `AGENTS.md`, `PLANS.md` |
| ml/ | `__init__.py`, `README.md`, `DATASET_SELECTION.md`, `RUNTIME_PARITY_SPEC.md`, `dataset_registry.json`, `requirements.txt` |
| ml/auth_anomaly/ | `__init__.py`, `collector.py`, `dataset_builder.py`, `extractor.py`, `scenarios.py`, `schema.py`, `splitting.py` |
| ml/lanl_benchmark/ | `__init__.py`, `BASELINE_METHODOLOGY.md`, `features.py`, `labels.py`, `parser.py`, `pipeline.py`, `schema.py` |
| ml/public_datasets/ | `__init__.py`, `otrf_adapter.py` |
| ml/tests/ | `__init__.py`, `test_auth_dataset_pipeline.py`, `test_lanl_benchmark_pipeline.py`, `test_phase3b_collection_and_semantics.py` |

These 26 ML paths are sufficient to include the handed-off ML source inventory. Keep the external partitions and evidence outside Git. The fresh-checkout acceptance inputs are the pinned dependencies, these source/tests, the tracked Windows dependency modules and authorized external data for artifact verification. A maintained extraction recipe with block bounds, provenance, preprocessing/options and a versioned source revision is needed for a stronger rebuild claim. The local pilot/orchestration scripts under scratch are outside the staging list.

For broader clean-checkout verification, `/ubuntu-telemetry/tests/` and `SOC/dashboard/test_client_contract.js` are ignored, although the latter is invoked by npm test. The root `tests/simulation/` harnesses and local `docs/WINDOWS_TELEMETRY_SUBSYSTEM.md`/historical reports are also ignored. Review their scope and data exposure before a separate tracking decision. The ML-only commit does not require force-adding historical screenshots, execution evidence, old reports, or lab drivers. Tracked normalized contracts remain authoritative. Local Antigravity rules pointing to an immediate Windows-only target or a separate implemented manager are historical. Preserve their two-repository and safety provisions.

A milestone is done when the assigned writer identifies the candidate revision and inputs, demonstrates each phase gate, supplies targeted regressions for established defects, and hands off the evidence and residual risks. Release acceptance additionally requires clean-worktree verification, exact suite results, genuine versus simulated provenance, privacy checks and owner approval. Keep the source tree, evidence outputs and writer assignments distinct. Do not stage, commit, push or start a downstream phase as part of this documentation handoff.
