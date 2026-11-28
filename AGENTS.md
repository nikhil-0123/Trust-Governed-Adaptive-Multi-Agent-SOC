# TGAM-SOC engineering instructions

These instructions govern work in the Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense source repository. Use PLANS.md for dated status, evidence and phase gates. The project owner approves architecture, research claims, operational authority and release decisions.

## Purpose and repository map

TGAM-SOC studies whether distributed detection, evidence-backed reasoning and centrally governed response improve defensive investigation while limiting unsafe action. Measure effectiveness against declared baselines. A passing regression suite establishes specific software behavior.

| Location | Responsibility |
|---|---|
| `windows-telemetry/` | Python endpoint and PowerShell launcher. Security, System and Sysmon collection, normalization, rules, features, checkpoint and transition handling, JSONL output, SQLite outboxes, heartbeat and response executor. Start with `pipeline.py`. |
| `ubuntu-telemetry/` | Python agent and shell launcher. The main pipeline wires auth-log collection, normalization, detection and forwarding. Check call sites before attributing live behavior to the separate process and network collectors. |
| `SOC/backend/app/` | FastAPI, Pydantic and SQLite. Ingestion, epoch governance, evidence fusion, MITRE enrichment, assessment, analysis/verification/synthesis, governance and response bridge. |
| `SOC/dashboard/` | React/Vite analyst console, API client, Tailwind and Recharts. Views cover overview, incidents, investigation, MITRE, analysis, governance and endpoints. |
| `ml/auth_anomaly/`, `ml/lanl_benchmark/`, `ml/public_datasets/` | Offline native Windows research, LANL public benchmark and passive public-data adapters respectively. Use the dataset registry, schema modules, runtime parity spec and benchmark methodology. NumPy, pandas, scikit-learn, XGBoost and PyArrow belong to the offline environment. |
| `docs/contracts/`, `project.config.json` | Normalized event specification and JSON Schema, architecture and declared component locations. Reserved paths include `ubuntu-server-telemetry/` and `SOC/manager/`. Verify implementation from source. |
| Component tests, `tests/simulation/`, `scripts/` | Regressions, lab harnesses and administrative utilities. Check tracking and side effects before use. |
| `P:\TGAM-SOC-knowledge` | Separate design, research and planning repository. Read-only during source work unless separately assigned. Legacy prototypes require explicit approval for reuse. |

Detection runs at the endpoint. Central workers correlate eligible forwarded detections, add context, assess trust and risk, verify reasoning and apply governance. The dashboard exposes evidence and analyst decisions. Preserve the distinction between authorization, queueing, dispatch, execution and endpoint acknowledgment.

## Contracts, identities and replay

The normalized contract v1.1 requires `event_id`, `timestamp`, `agent_id`, `hostname`, `os`, `event_type`, `source_ip`, `username`, `severity`, `detection_type`, `confidence` and `evidence`. Preserve nullable fields. Raw observations carry null detection type and confidence. Assessed confidence lies in [0,1]. Version and review required-field changes across producers and consumers.

A normalized event identifies an observation. A successful detector result creates a separate DetectionEvent carrying its source_event_id, detection_event_id and detector evidence. Several detections can refer to one observation. Preserve source time, identity, channel, epoch and evidence provenance.

In the formulas below, H returns lowercase SHA-256 hex, RCC returns TGAM-RCC-v1 canonical UTF-8 bytes, and P joins the supplied field values with a literal pipe and encodes the result as UTF-8. Field names in manifests are exact.

~~~text
Windows v2 source = H(RCC({
  "agent_id": agent_id, "channel": channel, "epoch": epoch,
  "hostname": hostname, "identity_type": "source",
  "record_id": record_id, "schema_version": "2.0"
}))
Windows legacy source = H(P(agent_id, hostname, log_name, record_id))
Ubuntu source = H(P(agent_id, hostname, source_name, record_id))
Windows detector_revision = H(RCC(detector_manifest))
Windows v2 detection = H(P(agent_id, source_event_id, detection_type, detector_revision))
Windows v1 and current Ubuntu detection = H(P(agent_id, source_event_id, detection_type, detector_name))
payload_hash = H(RCC(complete_payload))
conflict_id = H(RCC({"conflict_type":"outbox_payload_collision", "event_id":id,
                     "hash_min":lesser_payload_hash, "hash_max":greater_payload_hash}))
~~~

Use the implementations in `windows-telemetry/canonical.py`, `normalizer/windows_event_normalizer.py`, `detection/manifest.py`, `output/builder.py`, their Ubuntu equivalents where present, and `SOC/backend/app/canonical.py`. Preserve UTF-16 code-unit key ordering, numeric restrictions, duplicate-key rejection on raw input and canonicalization fixtures. The v2 builder trims agent, channel and host strings. Require a genuine positive integer epoch and a nonnegative safe record ID under the existing validator. An absent authoritative epoch preserves the legacy source path. Reject invalid explicit epochs.

A detector manifest contains `detector_name`, `detector_version`, `rules_digest`, `thresholds`, `detector_config` and `model_artifact_digest`. Carry the manifest and revision digest into evidence. Review changes to rules, thresholds, output semantics and artifacts for revision and replay impact. Replaying historical evidence requires its original schema, effective detector revision, payload shape and epoch. A changed v2 revision can generate a new detection for the same source. Keep both auditable. Respect the Windows production version gate. Use isolated evaluation for historical detectors. Evaluation writes `detections_eval.jsonl` and bypasses the event outbox.

## Forwarding, checkpoints and epoch authority

- Engineer Windows forwarding for at-least-once delivery. Local output, durable outbox disposition and matching SOC acknowledgment have distinct meanings. Advance the channel checkpoint only through the contiguous successfully handled prefix. For each forwardable result, complete the required write and obtain a committed local disposition. Legitimate filtering and no-detection records may complete normally. Network availability is independent of local checkpoint progress.
- Preserve transaction boundaries, crash recovery, retry/backoff, acknowledgment validation, watermarks, quarantine and delivered-row retention. Preserve pending work, conflict records and transition notifications across migrations and maintenance. Stop before unresolved local write failures, failed quarantine persistence and backpressure. Apply the actual platform's guarantees when reporting results.
- For Windows and central ingestion, identical payloads under the same detection ID are idempotent. For an ID collision with unequal payload hashes, retain the original and record both payloads and hashes in deterministic order, durably, before signaling conflict. A committed local conflict audit is a disposition. A bare HTTP 409 gives insufficient evidence of successful delivery.
- Preserve per-channel checkpoint locking/fencing, integrity checks, atomic replacement, durable malformed/oversized-event journals and transition replay ledgers. Record-ID regression alone cannot authorize a new epoch. Validate Security 1102 or correctly targeted System 104 witnesses, apply each once, and preserve cross-channel mailbox and acknowledgment recovery. Fail closed on ambiguous witnesses.
- Central epoch authority is scoped to (agent_id, channel), starting at 1. Ordinary transitions advance one epoch. Future events freeze the affected scope on a gap. Retain delayed retired and legacy/unverified evidence with their status. Reject contradictory explicit epochs. Resolve gaps through authenticated sequential transitions or audited administrative resolution. Preserve scoped idempotent recovery allocation. Shared tokens and caller-supplied identity cannot authorize agent-specific transitions.

## Fusion, assessment, reasoning and action

- Fuse eligible events by source event time using the configured window and deterministic candidate selection. Preserve the (agent_id, source_event_id) incident anchor through concurrent processing and replay. Cross-endpoint domain-account correlation requires supporting domain identity. Scope local or unverified accounts to their endpoint.
- Preserve primary evidence. Classify a new revision of the same source as HISTORICAL_RE_EVALUATION at its existing incident. Reprocessing must neither inflate independent corroboration nor remove the original primary contribution. Test changes in severity, MITRE context and resulting scores through the actual fusion-to-assessment path.
- Compute trust from available evidence factors. The present evidence-quality factor uses primary-compatible evidence volume and mean confidence. Risk uses normalized severity and available distinct MITRE context. Renormalize weights over available factors. Persist input snapshots, exclusions, weights, explanations and formula/config versions. Never invent missing confidence, factors or independent support.
- Keep analysis, verification and synthesis distinct. Validate claims, references and ATT&CK attributions against stored evidence and the catalog. Record prompt/model versions, provider, uncertainty and failure. Mock results establish mock-provider behavior.
- Govern every operational response. Check evidence and epoch eligibility, authorized release provenance, verified claims, trust/risk, policy restrictions, allowed action and target. Respect HOLD, REJECT and HUMAN_APPROVAL. Auto-approval requires every applicable policy condition. Log any required analyst decision. Models, prompts and dashboard requests have no independent containment authority.
- Preserve the governed bridge's unique lease on (agent_id, incident_id, action_type). Reserve the lease, insert the command and bind its ID transactionally. Retries and concurrent dispatch must preserve uniqueness. Audit the target and endpoint result. Recheck every command entry point before claiming system-wide enforcement.

## Security and forensic handling

Keep security testing within the authorized defensive lab. Never weaken endpoint protection, add exclusions, restore quarantined payloads, execute dataset content or perform unauthorized testing. No destructive containment tests on real endpoints. Use inert fixtures and simulation for response tests. Keep production, test, simulation and evaluation identities, storage, checkpoints, outboxes and destinations isolated, including explicit path overrides.

Keep secrets, tokens, HMAC keys, operational databases, raw logs, acquisition URLs bearing tokens and sensitive evidence out of Git, reports, prompts and screenshots. Protect originals, access history, timestamps and hashes. Redact or pseudonymize research exports. Label genuine observations, controlled lab sessions, injected events, synthetic fixtures, mock output and simulated actions at capture and reporting time.

## ML research and promotion

1. Maintain distinct ordered allowlists for native `auth_anomaly_features_v1` and LANL `lanl_auth_features_v1`. A LANL artifact is research-only. Never infer Windows identity, event IDs, source IPs or business hours from LANL fields.
2. Require independent truth with event/scenario scope, label source and telemetry origin. Native rule output is baseline metadata. For LANL, primary fitting, tuning and scoring use exact unambiguous annotation matches against unannotated background. Exclude ambiguous observations from primary supervised rows and keep their raw observations in causal history. Report separately the sensitivity result that includes flagged matches. An unmatched record carries no independent benign adjudication.
3. Compute historical features on [t-W,t) before incorporating the observation. Exclude tied peers. Respect entity scope, warm-up, out-of-order input, eviction, duplication, gaps, timezone and masks. Separate a measured zero from an unavailable value. Verify bounds and late-event policy against a straightforward reference. Track implemented limitations in PLANS.md.
4. Preserve native ordering of F1–F7, their seven masks, windows_event_id, is_auth_failure and logon_type. Verify native training/serving parity on identical streams, including boundaries, invalid identities, clear events and restarts. Require profile and ordered column checks before enabling inference.
5. Record data release, license/access conditions, acquisition source, hashes and their authority, schema, parser/builder version, transforms, split/label policies and limitations. Freeze the data and model-input manifests. Keep data and binaries outside Git.
6. Use chronology and an embargo at least as long as the longest rolling window. Separate warm-up from scoring. Audit transaction, identity, scenario, host and historical-window overlap as applicable. Specify group-aware stress tests and their attainable support. Fit preprocessing on training data, select using validation and preserve a held-out evaluation. Report selection bias, prevalence, background semantics, uncertainty and unsupported populations. Never fabricate efficacy, latency or resource measurements.
7. Bind an approved native model to its digest, schema and exact column order, missingness policy, calibration/thresholds, dependency versions, training provenance and detector revision. Missing or invalid artifacts must preserve rule-only operation and explicit model-unavailable status. Require shadow inference before any active hybrid detection. Shadow output cannot dispatch alerts, decisions or commands.

## Implementation, tests and Git

Use component conventions, type hints at interfaces, validated configuration, explicit error handling and redacted structured logs with appropriate scope and identifiers. Preserve backward compatibility, deterministic ordering, retry semantics and recoverable state. Make minimal justified changes and isolate offline dependencies from endpoint runtime dependencies. Preserve the dashboard lockfile.

For each demonstrated defect require a targeted regression at the affected entry point. Exercise repeat, concurrent or partial-failure paths where relevant. Never weaken assertions to make a suite pass. Run Windows and backend pytest suites separately from their component roots with `python -m pytest tests`. From the repository root use `python -m pytest ml/tests` in the offline environment. Verify availability of Ubuntu tests and the dashboard's `npm test` script in the exact checkout. A browser claim requires a browser run. Keep simulated and live verification results separate.

Release acceptance requires an independent run from a clean candidate worktree with isolated runtime paths. Report revision, environment, command, exact passed/failed/skipped/error counts, skip reasons and untouched coverage. Distinguish saved reports from fresh runs.

| Participant | Ownership |
|---|---|
| Project owner | Assigns scope and writers, accepts evidence and milestones, approves operational changes, publication, commits and pushes. |
| Google Antigravity | Primary implementation, its assigned worktree and evidence-producing jobs. |
| OpenAI Codex CLI | Independent verification and assigned documentation. Implementation requires a separate explicit assignment. |
| GitHub Copilot | Inline assistance to the current writer. Suggestions receive normal review and tests. |
| GitHub Actions | Automated verification when a tracked workflow runs. Cite the run for the tested revision. |

At handoff record owner, base SHA, writable paths, worktree, active jobs, evidence locations and scope. One writer owns each file. Use separate worktrees, branches, runtime directories and output paths for concurrent authorized writes. A new worktree omits the active writer's untracked source. Verify the actual handed-off snapshot.

Inspect status and preserve unrelated edits. Stage only explicit reviewed paths and inspect the staged diff. Never commit datasets, model binaries, credentials, temporary qualification scripts or operational databases. No destructive Git operations or automatic commit or push. Local Antigravity rules preserve the two-repository boundary. Resolve stale phase or ownership statements using the owner's latest assignment and PLANS.md. Escalate genuine scope conflicts to the owner.
