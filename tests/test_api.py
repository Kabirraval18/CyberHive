from datetime import datetime, timezone

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent


def test_events_endpoint_returns_events(client):
    session = AttackSession(
        session_id="api-session-1",
        source_ip="203.0.113.50",
        protocol="SSH",
        username="root",
        start_time=datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),
        command_count=1,
    )

    event = CowrieEvent(
        event_id="api-event-1",
        session_id="api-session-1",
        timestamp=datetime(2026, 8, 19, 10, 1, tzinfo=timezone.utc),
        source_ip="203.0.113.50",
        event_type="cowrie.command.input",
        username="root",
        command="whoami",
        event_metadata='{"input": "whoami"}',
    )

    db.session.add(session)
    db.session.add(event)
    db.session.commit()

    response = client.get("/api/events")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["count"] == 1
    assert data["events"][0]["event_id"] == "api-event-1"
    assert data["events"][0]["command"] == "whoami"


def test_sessions_endpoint_returns_sessions(client):
    session = AttackSession(
        session_id="api-session-2",
        source_ip="203.0.113.60",
        protocol="SSH",
        username="admin",
        command_count=3,
    )

    db.session.add(session)
    db.session.commit()

    response = client.get("/api/sessions")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["count"] == 1
    assert data["sessions"][0]["session_id"] == "api-session-2"


def test_stats_endpoint_returns_counts(client):
    session = AttackSession(
        session_id="stats-session",
        source_ip="203.0.113.70",
        protocol="SSH",
        username="root",
        command_count=2,
    )

    event = CowrieEvent(
        event_id="stats-event",
        session_id="stats-session",
        event_type="cowrie.command.input",
        command="id",
    )

    db.session.add(session)
    db.session.add(event)
    db.session.commit()

    response = client.get("/api/stats")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["stats"]["total_sessions"] == 1
    assert data["stats"]["total_events"] == 1