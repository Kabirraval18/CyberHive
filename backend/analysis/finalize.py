from __future__ import annotations

from flask import current_app

from backend.extensions import db
from backend.models import AttackSession, Alert
from backend.intelligence.virustotal import lookup_virustotal
from backend.analysis.risk import calculate_risk
from backend.analysis.mitre import map_session
from backend.intelligence.email_alerts import send_alert_email


def finalize_session_intelligence(session_id):
    session = AttackSession.query.filter_by(
        session_id=session_id
    ).one_or_none()

    if not session:
        raise ValueError("Session not found")

    results = {}

    if (
        session.source_ip
        and session.source_ip != "unknown"
        and current_app.config.get("VIRUSTOTAL_ENABLED", True)
        and current_app.config.get("VIRUSTOTAL_API_KEY")
    ):
        results["virustotal"] = lookup_virustotal(session.source_ip)

    results["risk"] = calculate_risk(session_id)
    results["mitre"] = map_session(session_id)

    risk = results["risk"]

    threshold = int(
        current_app.config.get(
            "RISK_ALERT_THRESHOLD",
            80,
        )
    )

    alert = None

    if risk["score"] >= threshold:
        existing = (
            Alert.query
            .filter_by(session_id=session_id)
            .order_by(Alert.created_at.desc())
            .first()
        )

        if (
            existing is None
            or existing.risk_score != risk["score"]
            or existing.severity != risk["severity"]
        ):
            alert = Alert(
                session_id=session_id,
                risk_score=risk["score"],
                severity=risk["severity"],
                title=f'{risk["severity"]}-risk session detected',
                message=(
                    "Risk threshold crossed. "
                    + "; ".join(
                        factor["evidence"]
                        for factor in risk["contributing_factors"]
                    )
                ),
            )

            db.session.add(alert)
            db.session.commit()

            results["email"] = send_alert_email(
                alert,
                context={
                    "source_ip": session.source_ip,
                    "behavior": (
                        session.analysis.behavior_label
                        if session.analysis
                        else None
                    ),
                },
            )

        else:
            results["email"] = {
                "success": False,
                "status": "duplicate_alert_suppressed",
            }

    else:
        results["email"] = {
            "success": False,
            "status": "not_triggered",
        }

    return results