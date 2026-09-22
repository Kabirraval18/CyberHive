from __future__ import annotations

from collections import Counter
from typing import Any

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent, IPIntelligence, RiskScore, SessionAnalysis


def _latest_risk(session: AttackSession) -> RiskScore | None:
    return session.risk_scores[0] if session.risk_scores else None


def build_source_profile(source_ip: str) -> dict[str, Any] | None:
    if not source_ip:
        return None

    sessions = (
        AttackSession.query
        .filter(AttackSession.source_ip == source_ip)
        .order_by(AttackSession.start_time.asc(), AttackSession.id.asc())
        .all()
    )
    if not sessions:
        return None

    behavior_counts: Counter[str] = Counter()
    automation_counts: Counter[str] = Counter()
    command_total = 0
    highest_risk = None
    risk_severity = None
    signatures: set[str] = set()

    for session in sessions:
        analysis = session.analysis

        if analysis is not None:
            behavioral_features = analysis.behavioral_features or {}
            analyzed_command_count = behavioral_features.get("command_count")

            if isinstance(analyzed_command_count, (int, float)) and analyzed_command_count >= 0:
                command_total += int(analyzed_command_count)
            else:
                command_total += int(session.command_count or 0)

            if analysis.behavior_label:
                behavior_counts[analysis.behavior_label] += 1

            if analysis.automation_profile:
                automation_counts[analysis.automation_profile] += 1

            if analysis.behavior_signature:
                signatures.add(analysis.behavior_signature)
        else:
            command_total += int(session.command_count or 0)

        risk = _latest_risk(session)
        if risk is not None:
            if highest_risk is None or risk.score > highest_risk:
                highest_risk = risk.score
                risk_severity = risk.severity

    intelligence = (
        IPIntelligence.query
        .filter_by(ip_address=source_ip, provider="abuseipdb")
        .one_or_none()
    )

    primary_behavior = (
        behavior_counts.most_common(1)[0][0]
        if behavior_counts
        else None
    )

    repeated_activity = len(sessions) > 1 or len(signatures) < len(
        [s.analysis for s in sessions if s.analysis and s.analysis.behavior_signature]
    )

    return {
        "source_ip": source_ip,
        "session_count": len(sessions),
        "command_count": command_total,
        "primary_behavior": primary_behavior,
        "behavior_distribution": dict(
            sorted(behavior_counts.items())
        ),
        "automation_distribution": dict(
            sorted(automation_counts.items())
        ),
        "highest_observed_risk": highest_risk,
        "highest_risk_severity": risk_severity,
        "repeated_activity": repeated_activity,
        "distinct_behavior_signatures": len(signatures),
        "country": intelligence.country if intelligence else None,
        "asn": intelligence.asn if intelligence else None,
        "isp": intelligence.isp if intelligence else None,
        "abuse_confidence": (
            intelligence.abuse_confidence if intelligence else None
        ),
        "abuse_report_count": (
            intelligence.report_count if intelligence else None
        ),
        "intelligence_retrieved_at": (
            intelligence.retrieved_at.isoformat()
            if intelligence and intelligence.retrieved_at
            else None
        ),
    }


def build_all_source_profiles() -> list[dict[str, Any]]:
    sources = (
        db.session.query(CowrieEvent.source_ip)
        .filter(CowrieEvent.source_ip.isnot(None))
        .distinct()
    )
    values = sorted(
        {
            value[0]
            for value in sources.all()
            if value[0]
        }
    )
    profiles = [
        profile for source_ip in values
        if (profile := build_source_profile(source_ip)) is not None
    ]
    return profiles
