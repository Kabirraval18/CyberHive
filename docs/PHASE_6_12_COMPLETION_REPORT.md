# CyberHive — Phases 6–12 Completion Report

## Implemented phases

### Phase 6 — Behavioral Feature Extraction

Implemented session-level behavioral evidence from stored Cowrie events. The extractor calculates event and command counts, unique command count, command diversity, repeated command ratio, ordered command sequences, session duration, mean command interval, command frequency, authentication statistics and sequence, discovery indicators, transfer indicators, persistence indicators, missing-timestamp indicators, and source-session repetition.

Undefined mathematical values remain explicitly undefined where appropriate. For example, mean command interval requires two valid adjacent timestamps, and command frequency requires a positive session duration.

### Phase 7 — Behavior Classification

Implemented deterministic rule-based classification with the following labels:

- Brute Force
- Reconnaissance / Discovery
- Payload Activity
- Interactive Exploration
- Persistence Attempt
- Insufficient Evidence

Classification stores evidence and a deterministic rule-derived confidence indicator. It does not claim malware identity, attacker identity, or threat-actor attribution.

### Phase 8 — Behavioral Clustering

Implemented lightweight scikit-learn KMeans clustering with StandardScaler normalization, a bounded data-driven cluster count, and `random_state=42` for reproducibility. Clustering is skipped when fewer than three analyzed sessions exist. No artificial anomaly score is produced.

### Phase 9 — Automation / Interactive Profiling

Implemented observable interaction profiling from command timing, command repetition, command diversity, and session duration. Output states are `likely automated`, `likely interactive`, `mixed`, and `insufficient data`. The result describes telemetry characteristics and does not prove human/bot identity.

### Phase 10 — Source Profiling

Implemented source-IP aggregation across observed sessions. Profiles summarize session volume, command volume, behavior distribution, automation distribution, highest observed stored risk when available, repeated activity, behavior signatures, and cached AbuseIPDB context. IP addresses are treated as telemetry source identifiers rather than personal identities.

### Phase 11 — Repeated Behavior / Correlation

Implemented deterministic SHA-256 behavior signatures from normalized command sequences, authentication sequences, protocol, and observable transfer activity. Implemented sequence similarity and repeated-signature/cross-source correlation without campaign or threat-actor attribution.

### Phase 12 — AbuseIPDB Integration

Implemented backend-only AbuseIPDB API v2 check integration with public-IP validation, cache lookup, configurable report age, normalized persistence in `IPIntelligence`, and explicit handling for invalid input, non-public IPs, missing configuration, timeouts, network failure, rate limiting, authentication errors, provider errors, malformed responses, and unexpected responses. Provider failures are isolated from core Cowrie ingestion.

## Processing integration

The existing Phase 5 processing pipeline remains the core boundary. Genuinely inserted Cowrie events determine affected sessions. The behavioral analyzer runs only for affected sessions when enabled, followed by optional reclustering when enough analyzed sessions exist.

Core telemetry persistence occurs before optional intelligence processing, so a failure in behavioral analysis, clustering, or external enrichment does not remove the underlying Cowrie telemetry.

## New API capabilities

- `/api/sessions/by-session-id/<session_id>`
- `/api/sessions/by-session-id/<session_id>/analysis`
- `/api/behavior/summary`
- `/api/behavior/correlations`
- `/api/behavior/similar/<session_id>`
- `/api/sources`
- `/api/sources/<source_ip>`
- `/api/threat-intelligence/status`
- `/api/threat-intelligence/abuseipdb?ip=<ip>`

## Validation performed

Static source validation completed successfully using Python compilation and AST parsing. The new phase-specific files pass whitespace/diff validation.

The uploaded SQLite dataset contains 11 sessions and 172 events. The Phase 6–11 algorithms were executed against those real stored records outside the Flask runtime and produced deterministic behavioral outputs, three clusters at the available dataset size, and repeated behavior signatures across sessions.

The uploaded frontend copy was not used as a distributable dependency tree because the included `node_modules` is platform-specific and its Vite executable is not runnable in the Linux validation environment. On Windows, install frontend dependencies with `npm install` or `npm ci` before starting Vite.

The full Flask/pytest suite could not be executed in the container because the uploaded environment is Windows-specific and the container cannot install the missing Flask dependencies from the network. Run `pytest -q` from the project's Windows virtual environment before final submission.

## Security verification

A source scan found no attacker-command execution through `os.system`, `subprocess.run`, `subprocess.Popen`, `eval`, or `exec` in the backend source. The configured development IP `192.168.56.101` is not embedded in backend/frontend application code; it is mentioned only in documentation as an example of the address that must not remain hard-coded.

## Submission archive exclusions

The clean submission archive excludes `.env`, `.git`, `.venv`, `frontend/node_modules`, `frontend/dist`, Python cache directories, pytest cache, and the runtime SQLite database. Real Cowrie demo JSON telemetry is retained under `data/cowrie_demo` for reproducibility.
