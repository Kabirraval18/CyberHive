# CyberHive — Phases 13–21 Completion

## Implemented scope

- Phase 13: backend-only VirusTotal IP enrichment using the official VirusTotal API v3 IP report endpoint, provider-separated caching in `ip_intelligence`, safe normalization, error isolation and secret-safe status reporting.
- Phase 14: deterministic 0–100 risk scoring with versioned, persisted contributing factors and centralized severity thresholds.
- Phase 15: evidence-backed MITRE ATT&CK mapping for observed Cowrie commands, preserving event ID, command, evidence, technique, tactic and confidence.
- Phase 16: defensive recommendations generated from actual authentication, discovery, transfer and persistence evidence.
- Phase 17: backend investigation endpoint and responsive analyst investigation drawer covering session, behavior, events, external intelligence, risk, MITRE and recommendations.
- Phase 18: persistent risk-threshold alerts with deterministic duplicate suppression and acknowledgement.
- Phase 19: SMTP email notification after alert persistence, with failure isolation and secret-safe configuration.
- Phase 20: ReportLab session/summary PDFs and backend CSV session export using stored data.
- Phase 21: backend session authentication, password hashing, Administrator/Security Analyst roles, and administrator-only user management.

## Risk formula

The authoritative score is calculated only in `backend/analysis/risk.py` and is versioned as `1.0`.

| Evidence | Maximum contribution |
|---|---:|
| Failed authentication attempts | 25 |
| Behavior classification | 25 |
| Discovery activity | 15 |
| Transfer activity | 15 |
| High command frequency | 10 |
| High command repetition | 5 |
| AbuseIPDB reputation | 15 |
| VirusTotal detection ratio | 15 |

The final score is capped at 100. Severity is Low for 0–24, Medium for 25–49, High for 50–79 and Critical for 80–100. External intelligence contributes context; it does not replace Cowrie observations.

## Authentication

The backend is the authorization boundary. React visibility is not treated as security. Passwords are hashed using Werkzeug password hashing. Roles are `admin` and `analyst`. Initial administrator creation occurs during database initialization only when `ADMIN_PASSWORD` is configured.

## Remote Kali

The collector is represented by `scripts/collect_cowrie.ps1`. It reads `COWRIE_LOG_URL`, downloads to a temporary file, moves it to `cowrie_live.json`, invokes the existing parser and processing pipeline, and waits five seconds before the next poll. The same collector works with a VirtualBox Kali endpoint or a physical Kali endpoint reachable from Windows.

## Verification notes

Python source was syntax-compiled successfully in the build environment. The container could not execute the project's Windows `.venv`, so the full pytest suite must be run in the Windows development environment using `python -m pytest -q`. The frontend build could not be completed in the Linux container because the archived `node_modules` is missing Vite/Rolldown native bindings; run `npm install` and `npm run build` on Windows.

## Security constraints

No attacker command is executed by CyberHive. Provider keys, SMTP credentials, the Flask secret, and administrator bootstrap password belong only in `.env` or another secure environment. They must not be committed, bundled into React, returned by API endpoints, included in reports, or placed in screenshots.
