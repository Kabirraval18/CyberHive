from datetime import timezone

from flask import Blueprint, current_app, jsonify, request

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent, SessionAnalysis


api_bp = Blueprint("api", __name__)

def _serialize_datetime(value):
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.isoformat()

def _serialize_event(event: CowrieEvent) -> dict:
    return {
        "id": event.id,
        "event_id": event.event_id,
        "session_id": event.session_id,
        "timestamp": _serialize_datetime(event.timestamp),
        "source_ip": event.source_ip,
        "event_type": event.event_type,
        "username": event.username,
        "command": event.command,
        "event_metadata": event.event_metadata,
        "created_at": _serialize_datetime(event.created_at),
    }


def _serialize_session(session: AttackSession) -> dict:
    return {
        "id": session.id,
        "session_id": session.session_id,
        "source_ip": session.source_ip,
        "protocol": session.protocol,
        "username": session.username,
        "authentication_result": session.authentication_result,
        "start_time": _serialize_datetime(session.start_time),
        "end_time": _serialize_datetime(session.end_time),
        "duration": session.duration,
        "command_count": session.command_count,
        "created_at": _serialize_datetime(session.created_at),
    }



def _normalize_timestamp(timestamp):
    """
    Normalize a timestamp to UTC while preserving its precise
    date, hour, minute, second and microsecond values.

    Naive timestamps are treated as UTC.
    """
    if timestamp is None:
        return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


@api_bp.get("/api/events")
def get_events():
    events = (
        CowrieEvent.query
        .order_by(CowrieEvent.timestamp.desc())
        .all()
    )

    return jsonify({
        "success": True,
        "count": len(events),
        "events": [
            _serialize_event(event)
            for event in events
        ],
    }), 200


@api_bp.get("/api/events/<int:event_id>")
def get_event(event_id: int):
    event = db.session.get(CowrieEvent, event_id)

    if event is None:
        return jsonify({
            "success": False,
            "error": "Event not found",
        }), 404

    return jsonify({
        "success": True,
        "event": _serialize_event(event),
    }), 200


@api_bp.get("/api/sessions")
def get_sessions():
    sessions = (
        AttackSession.query
        .order_by(AttackSession.start_time.desc())
        .all()
    )

    return jsonify({
        "success": True,
        "count": len(sessions),
        "sessions": [
            _serialize_session(session)
            for session in sessions
        ],
    }), 200


@api_bp.get("/api/sessions/<int:session_id>")
def get_session(session_id: int):
    session = db.session.get(AttackSession, session_id)

    if session is None:
        return jsonify({
            "success": False,
            "error": "Session not found",
        }), 404

    return jsonify({
        "success": True,
        "session": _serialize_session(session),
    }), 200


def _build_dashboard_stats() -> dict:
    total_sessions = db.session.query(AttackSession).count()
    total_events = db.session.query(CowrieEvent).count()

    total_commands = (
        db.session.query(
            db.func.coalesce(
                db.func.sum(AttackSession.command_count),
                0,
            )
        )
        .scalar()
    )

    unique_source_ips = (
        db.session.query(
            db.func.count(
                db.func.distinct(CowrieEvent.source_ip)
            )
        )
        .scalar()
    )

    return {
        "total_sessions": total_sessions,
        "total_events": total_events,
        "total_commands": int(total_commands or 0),
        "unique_source_ips": int(unique_source_ips or 0),
    }


def _build_activity_analytics() -> list[dict]:
    """
    Build a chronological activity timeline using the exact
    timestamps stored in the database.

    Events use CowrieEvent.timestamp.

    Sessions use AttackSession.start_time.

    Session command_count is kept with the session activity
    because the database stores command_count at session level
    rather than storing a timestamp for every individual command.
    """
    activity = []

    events = (
        CowrieEvent.query
        .filter(CowrieEvent.timestamp.isnot(None))
        .all()
    )

    for event in events:
        timestamp = _normalize_timestamp(event.timestamp)

        activity.append({
            "timestamp": timestamp.isoformat(),
            "activity_type": "event",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "command": event.command,
        })

    sessions = (
        AttackSession.query
        .filter(AttackSession.start_time.isnot(None))
        .all()
    )

    for session in sessions:
        timestamp = _normalize_timestamp(session.start_time)

        activity.append({
            "timestamp": timestamp.isoformat(),
            "activity_type": "session",
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "protocol": session.protocol,
            "username": session.username,
            "command_count": session.command_count or 0,
        })

    activity.sort(key=lambda item: item["timestamp"])

    return activity


@api_bp.get("/api/analytics/activity")
def get_activity_analytics():
    activity = _build_activity_analytics()

    return jsonify({
        "success": True,
        "activity": activity,
    }), 200


@api_bp.get("/api/stats")
def get_stats():
    stats = _build_dashboard_stats()

    return jsonify({
        "success": True,
        "stats": stats,
    }), 200


@api_bp.get("/api/dashboard")
def get_dashboard():
    stats = _build_dashboard_stats()

    recent_events = (
        CowrieEvent.query
        .order_by(CowrieEvent.timestamp.desc())
        .limit(5)
        .all()
    )

    recent_sessions = (
        AttackSession.query
        .order_by(AttackSession.start_time.desc())
        .limit(5)
        .all()
    )

    return jsonify({
        "success": True,
        "stats": stats,
        "recent_events": [
            _serialize_event(event)
            for event in recent_events
        ],
        "recent_sessions": [
            _serialize_session(session)
            for session in recent_sessions
        ],
    }), 200
# ============================================================
# PHASE 6–12 BEHAVIORAL INTELLIGENCE API
# ============================================================


def _serialize_analysis(analysis):
    if analysis is None:
        return None

    return {
        "id": analysis.id,
        "session_id": analysis.session_id,
        "behavior_label": analysis.behavior_label,
        "behavior_confidence": analysis.behavior_confidence,
        "behavioral_features": analysis.behavioral_features,
        "automation_profile": analysis.automation_profile,
        "behavior_signature": analysis.behavior_signature,
        "cluster_id": analysis.cluster_id,
        "anomaly_score": analysis.anomaly_score,
        "analyzed_at": _serialize_datetime(analysis.analyzed_at),
        "created_at": _serialize_datetime(analysis.created_at),
    }


@api_bp.get("/api/sessions/by-session-id/<path:session_id>")
def get_session_by_cowrie_session_id(session_id: str):
    session = AttackSession.query.filter_by(
        session_id=session_id,
    ).one_or_none()

    if session is None:
        return jsonify({
            "success": False,
            "error": "Session not found",
        }), 404

    risk = session.risk_scores[0] if session.risk_scores else None

    return jsonify({
        "success": True,
        "session": _serialize_session(session),
        "analysis": _serialize_analysis(session.analysis),
        "latest_risk": (
            {
                "score": risk.score,
                "severity": risk.severity,
                "scoring_version": risk.scoring_version,
                "contributing_factors": risk.contributing_factors,
                "calculated_at": _serialize_datetime(risk.calculated_at),
            }
            if risk is not None
            else None
        ),
    }), 200


@api_bp.get("/api/sessions/by-session-id/<path:session_id>/analysis")
def get_session_analysis(session_id: str):
    analysis = SessionAnalysis.query.filter_by(
        session_id=session_id,
    ).one_or_none()

    if analysis is None:
        return jsonify({
            "success": False,
            "error": "Session analysis not found",
        }), 404

    return jsonify({
        "success": True,
        "analysis": _serialize_analysis(analysis),
    }), 200


@api_bp.get("/api/behavior/summary")
def get_behavior_summary():
    from backend.models import SessionAnalysis

    total_sessions = AttackSession.query.count()
    analyzed_sessions = SessionAnalysis.query.count()

    behavior_counts = {}
    for analysis in SessionAnalysis.query.all():
        label = analysis.behavior_label or "Unclassified"
        behavior_counts[label] = behavior_counts.get(label, 0) + 1

    automation_counts = {}
    for analysis in SessionAnalysis.query.all():
        profile = analysis.automation_profile or "insufficient data"
        automation_counts[profile] = automation_counts.get(profile, 0) + 1

    cluster_counts = {}
    for analysis in SessionAnalysis.query.filter(
        SessionAnalysis.cluster_id.isnot(None)
    ).all():
        cluster = str(analysis.cluster_id)
        cluster_counts[cluster] = cluster_counts.get(cluster, 0) + 1

    return jsonify({
        "success": True,
        "total_sessions": total_sessions,
        "analyzed_sessions": analyzed_sessions,
        "analysis_coverage": (
            round(analyzed_sessions / total_sessions, 6)
            if total_sessions
            else None
        ),
        "behavior_distribution": dict(sorted(behavior_counts.items())),
        "automation_distribution": dict(sorted(automation_counts.items())),
        "cluster_distribution": dict(sorted(cluster_counts.items())),
        "cluster_status": (
            "clustered"
            if cluster_counts
            else (
                "insufficient_data"
                if analyzed_sessions < 3
                else "no_cluster_assignments"
            )
        ),
    }), 200


@api_bp.get("/api/behavior/correlations")
def get_behavior_correlations():
    from backend.analysis.correlation import build_behavior_correlations

    raw_threshold = (request.args.get("threshold") or "0.70").strip()
    try:
        threshold = float(raw_threshold)
    except ValueError:
        return jsonify({
            "success": False,
            "error": "threshold must be a number between 0 and 1",
        }), 400

    if threshold < 0 or threshold > 1:
        return jsonify({
            "success": False,
            "error": "threshold must be between 0 and 1",
        }), 400

    return jsonify({
        "success": True,
        **build_behavior_correlations(
            similarity_threshold=threshold,
        ),
    }), 200


@api_bp.get("/api/behavior/similar/<path:session_id>")
def get_similar_sessions(session_id: str):
    from backend.analysis.correlation import find_similar_sessions

    if SessionAnalysis.query.filter_by(session_id=session_id).one_or_none() is None:
        return jsonify({
            "success": False,
            "error": "Session analysis not found",
        }), 404

    return jsonify({
        "success": True,
        "session_id": session_id,
        "similar_sessions": find_similar_sessions(session_id),
    }), 200


@api_bp.get("/api/sources")
def get_source_profiles():
    from backend.analysis.profiling import build_all_source_profiles

    profiles = build_all_source_profiles()

    return jsonify({
        "success": True,
        "count": len(profiles),
        "sources": profiles,
    }), 200


@api_bp.get("/api/sources/<path:source_ip>")
def get_source_profile(source_ip: str):
    from backend.analysis.profiling import build_source_profile

    profile = build_source_profile(source_ip)
    if profile is None:
        return jsonify({
            "success": False,
            "error": "Source IP not found",
        }), 404

    return jsonify({
        "success": True,
        "source": profile,
    }), 200


@api_bp.get("/api/threat-intelligence/status")
def get_threat_intelligence_status():
    abuse_key = bool(str(current_app.config.get("ABUSEIPDB_API_KEY") or "").strip())
    return jsonify({
        "success": True,
        "providers": {
            "abuseipdb": {
                "enabled": bool(current_app.config.get("ABUSEIPDB_ENABLED", True)),
                "configured": abuse_key,
            },
            "virustotal": {
                "enabled": bool(current_app.config.get("VIRUSTOTAL_ENABLED", True)),
                "configured": bool(
                    str(current_app.config.get("VIRUSTOTAL_API_KEY") or "").strip()
                ),
            },
        },
    }), 200


@api_bp.get("/api/threat-intelligence/abuseipdb")
def get_abuseipdb_intelligence():
    from backend.intelligence.abuseipdb import lookup_abuseipdb

    source_ip = (request.args.get("ip") or "").strip()
    if not source_ip:
        return jsonify({
            "success": False,
            "error": "ip query parameter is required",
        }), 400

    force_refresh = (request.args.get("refresh") or "false").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    result = lookup_abuseipdb(
        source_ip,
        force_refresh=force_refresh,
    )
    status_code = 200 if result.get("success") else {
        "invalid_ip": 400,
        "non_public_ip": 200,
        "disabled": 200,
        "not_configured": 503,
        "timeout": 504,
        "rate_limited": 429,
        "authentication_error": 502,
        "provider_error": 502,
        "provider_unavailable": 503,
        "malformed_response": 502,
        "unexpected_response": 502,
    }.get(result.get("status"), 502)

    return jsonify(result), status_code
