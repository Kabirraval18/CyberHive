from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import current_app

from backend.analysis.automation import profile_automation
from backend.analysis.classification import classify_behavior
from backend.analysis.features import (
    build_behavior_signature,
    extract_session_features,
)
from backend.extensions import db
from backend.intelligence.abuseipdb import lookup_abuseipdb
from backend.models import AttackSession, SessionAnalysis


def analyze_session(session_id: str, *, enrich_abuseipdb: bool | None = None) -> dict[str, Any]:
    session = AttackSession.query.filter_by(session_id=session_id).one_or_none()
    if session is None:
        raise ValueError(f"Session {session_id!r} was not found")

    features = extract_session_features(session)
    classification = classify_behavior(features)
    automation = profile_automation(features)
    signature = build_behavior_signature(features)

    features["classification_evidence"] = classification
    features["automation_profile"] = automation
    features["behavior_signature"] = signature

    analysis = session.analysis
    if analysis is None:
        analysis = SessionAnalysis(session_id=session.session_id)
        db.session.add(analysis)

    analysis.behavior_label = classification["label"]
    analysis.behavior_confidence = classification["confidence"]
    analysis.behavioral_features = features
    analysis.automation_profile = automation["profile"]
    analysis.behavior_signature = signature
    analysis.analyzed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    if enrich_abuseipdb is None:
        enrich_abuseipdb = bool(
            current_app.config.get("RUN_ABUSEIPDB_ON_INGEST", True)
            and current_app.config.get("ABUSEIPDB_ENABLED", True)
            and current_app.config.get("ABUSEIPDB_API_KEY")
        )

    enrichment = None
    if enrich_abuseipdb and session.source_ip and session.source_ip != "unknown":
        enrichment = lookup_abuseipdb(session.source_ip)

    db.session.commit()

    return {
        "session_id": session.session_id,
        "behavior_label": analysis.behavior_label,
        "behavior_confidence": analysis.behavior_confidence,
        "automation_profile": analysis.automation_profile,
        "behavior_signature": analysis.behavior_signature,
        "cluster_id": analysis.cluster_id,
        "behavioral_features": analysis.behavioral_features,
        "abuseipdb": enrichment,
    }
