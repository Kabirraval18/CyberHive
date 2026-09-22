# CyberHive Phases 6–12 Implementation

## Scope

This document records the implementation boundary for Phases 6 through 12 of CyberHive. The existing Flask + React + SQLite + Cowrie architecture remains unchanged.

## Phase 6 — Behavioral Feature Extraction

Session-level features are derived from stored `CowrieEvent` records. The extractor preserves command order and calculates event counts, command counts, unique-command counts, command diversity, repeated-command ratio, session duration, mean time between timestamped commands, command frequency, authentication counts and sequence, discovery indicators, transfer indicators, persistence indicators, and source-session repetition.

Undefined metrics are represented explicitly where a mathematical value cannot be calculated. For example, mean command interval is `null` when fewer than two commands have valid adjacent timestamps, and command frequency is `null` when session duration is zero or unavailable.

## Phase 7 — Behavior Classification

Classification is deterministic and rule-based. The current taxonomy is:

- `Brute Force`
- `Reconnaissance / Discovery`
- `Payload Activity`
- `Interactive Exploration`
- `Persistence Attempt`
- `Insufficient Evidence`

Payload activity requires both a transfer-oriented command and observable transfer telemetry. Discovery classification requires multiple discovery-oriented observations spanning more than one discovery category. Interactive exploration is used as a fallback when the session has long, diverse, timestamped interaction without stronger behavior evidence.

The stored confidence is a deterministic rule-derived indicator, not a calibrated probability.

## Phase 8 — Behavioral Clustering

Session analyses are standardized with `StandardScaler` and grouped using reproducible scikit-learn `KMeans`. Clustering is skipped when fewer than three analyzed sessions exist. The selected cluster count is derived from the number of available sessions and is bounded to a small range suitable for the project's scale. A fixed `random_state=42` and explicit `n_init=10` are used for reproducibility.

No anomaly score is generated because KMeans itself does not provide a defensible anomaly score for this implementation.

## Phase 9 — Automation / Interactive Profiling

The profiler evaluates observable command timing, command repetition, command diversity, and session duration. It can return:

- `likely automated`
- `likely interactive`
- `mixed`
- `insufficient data`

The output describes interaction characteristics only. It does not claim to identify a human operator or bot with certainty.

## Phase 10 — Source Profiling

Source profiles aggregate stored sessions by source IP. The API exposes session count, command count, observed behavior distribution, automation distribution, highest stored risk when available, repeated activity, behavior-signature count, and cached AbuseIPDB context when available.

An IP address is treated as a telemetry source identifier only; it is not treated as proof of personal identity.

## Phase 11 — Repeated Behavior and Correlation

Each analyzed session receives a deterministic SHA-256 behavior signature derived from normalized command sequence, authentication sequence, protocol, and observable transfer activity.

CyberHive also calculates sequence similarity using deterministic `SequenceMatcher` comparisons. Correlation output identifies repeated exact signatures, cross-source repeated behavior, and similar session pairs. The terminology is deliberately limited to repeated or similar observed behavior and does not assert real-world threat-actor attribution.

## Phase 12 — AbuseIPDB Integration

AbuseIPDB is a backend-only enrichment provider. Requests use the documented API v2 `check` endpoint with the IP supplied through an encoded query parameter and the API key supplied in the `Key` header. Responses are normalized into `IPIntelligence` and cached by the existing `(ip_address, provider)` uniqueness rule.

Only globally routable IP addresses are queried. Loopback, private, reserved, documentation, multicast, and otherwise non-global addresses are rejected before any provider request is made. Provider errors are isolated from core telemetry processing.

The following provider conditions are handled explicitly: missing configuration, invalid IP, non-public IP, timeout, network failure, HTTP 429 rate limiting, credential rejection, other provider errors, malformed JSON, and unexpected response structures.

## Processing Integration

When `RUN_ANALYSIS_ON_INGEST=true`, the Phase 5 processing boundary now invokes the behavioral session analyzer for only genuinely affected sessions. Once session analysis completes, clustering is recomputed when `RUN_RECLUSTER_ON_INGEST=true` and enough analyzed sessions exist. Core telemetry ingestion remains the authoritative persistence step and is not rolled back by optional behavioral or enrichment failures.

## API additions

The following additive endpoints expose the new backend capabilities:

- `GET /api/sessions/by-session-id/<session_id>`
- `GET /api/sessions/by-session-id/<session_id>/analysis`
- `GET /api/behavior/summary`
- `GET /api/behavior/correlations`
- `GET /api/behavior/similar/<session_id>`
- `GET /api/sources`
- `GET /api/sources/<source_ip>`
- `GET /api/threat-intelligence/status`
- `GET /api/threat-intelligence/abuseipdb?ip=<ip>`

These endpoints return real stored telemetry and derived backend results; they do not fabricate data when categories are empty.

## Configuration additions

The new safe environment settings are:

```text
ABUSEIPDB_MAX_AGE_DAYS=90
RUN_ABUSEIPDB_ON_INGEST=true
```

The API key remains backend-only and must stay in `.env`.
