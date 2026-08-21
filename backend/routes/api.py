from datetime import timezone

from flask import Blueprint, jsonify

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent


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