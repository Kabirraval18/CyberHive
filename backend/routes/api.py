from flask import Blueprint, jsonify

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent


api_bp = Blueprint("api", __name__)


def _serialize_event(event: CowrieEvent) -> dict:
    return {
        "id": event.id,
        "event_id": event.event_id,
        "session_id": event.session_id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source_ip": event.source_ip,
        "event_type": event.event_type,
        "username": event.username,
        "command": event.command,
        "event_metadata": event.event_metadata,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


def _serialize_session(session: AttackSession) -> dict:
    return {
        "id": session.id,
        "session_id": session.session_id,
        "source_ip": session.source_ip,
        "protocol": session.protocol,
        "username": session.username,
        "authentication_result": session.authentication_result,
        "start_time": session.start_time.isoformat() if session.start_time else None,
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "duration": session.duration,
        "command_count": session.command_count,
        "created_at": session.created_at.isoformat() if session.created_at else None,
    }


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
        "events": [_serialize_event(event) for event in events],
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
        "sessions": [_serialize_session(session) for session in sessions],
    }), 200


@api_bp.get("/api/stats")
def get_stats():
    session_count = db.session.query(AttackSession).count()
    event_count = db.session.query(CowrieEvent).count()

    return jsonify({
        "success": True,
        "stats": {
            "total_sessions": session_count,
            "total_events": event_count,
        },
    }), 200
