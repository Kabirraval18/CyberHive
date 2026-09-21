# CyberHive Database Design — Phase 4

## Purpose

Phase 4 extends the existing CyberHive SQLite persistence layer with storage for higher-level intelligence.

The existing `cowrie_events` and `attack_sessions` tables remain the core telemetry/session layer.

## Existing Core Tables

### `cowrie_events`

Stores normalized Cowrie telemetry.

Key fields:

- `id`
- `event_id`
- `session_id`
- `timestamp`
- `source_ip`
- `event_type`
- `username`
- `command`
- `metadata`
- `created_at`

### `attack_sessions`

Stores reconstructed Cowrie sessions.

Key fields:

- `id`
- `session_id`
- `source_ip`
- `protocol`
- `username`
- `authentication_result`
- `start_time`
- `end_time`
- `duration`
- `command_count`
- `created_at`

## Phase 4 Intelligence Tables

### `session_analyses`

Stores the latest behavioral analysis for a session.

Fields:

- `session_id`
- `behavior_label`
- `behavior_confidence`
- `behavioral_features`
- `automation_profile`
- `behavior_signature`
- `cluster_id`
- `anomaly_score`
- `analyzed_at`
- `created_at`

A session has at most one current analysis record.

### `ip_intelligence`

Stores cached external intelligence for an IP/provider pair.

Fields:

- `ip_address`
- `provider`
- `reputation`
- `abuse_confidence`
- `report_count`
- `country`
- `asn`
- `isp`
- `category_data`
- `provider_metadata`
- `retrieved_at`
- `expires_at`

The combination of `ip_address` and `provider` is unique.

### `risk_scores`

Stores explainable risk calculations.

Fields:

- `session_id`
- `score`
- `severity`
- `contributing_factors`
- `scoring_version`
- `calculated_at`

Multiple historical risk calculations may exist for one session.

### `mitre_mappings`

Stores evidence-backed MITRE ATT&CK mappings.

Fields:

- `session_id`
- `event_id`
- `command`
- `technique_id`
- `technique_name`
- `tactic`
- `evidence`
- `confidence`
- `created_at`

The mapping engine is implemented in a later phase.

### `alerts`

Stores dashboard alerts generated from later risk conditions.

Fields:

- `session_id`
- `risk_score`
- `severity`
- `title`
- `message`
- `acknowledged`
- `created_at`
- `acknowledged_at`

## Relationships

```text
AttackSession
    |
    +---- 1 : 1 ---- SessionAnalysis
    |
    +---- 1 : N ---- RiskScore
    |
    +---- 1 : N ---- MITREMapping
    |
    +---- 1 : N ---- Alert

IP address + provider
    |
    +---- 1 : 1 ---- IPIntelligence