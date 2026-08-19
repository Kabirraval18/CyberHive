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


def test_event_detail_endpoint_returns_event(client):
    event = CowrieEvent(
        event_id="detail-event-1",
        session_id="detail-session-1",
        timestamp=datetime(2026, 8, 19, 11, 0, tzinfo=timezone.utc),
        source_ip="203.0.113.80",
        event_type="cowrie.command.input",
        username="root",
        command="id",
    )

    db.session.add(event)
    db.session.commit()

    response = client.get(f"/api/events/{event.id}")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["event"]["id"] == event.id
    assert data["event"]["event_id"] == "detail-event-1"
    assert data["event"]["command"] == "id"


def test_event_detail_endpoint_returns_404_for_missing_event(client):
    response = client.get("/api/events/9999")

    assert response.status_code == 404

    data = response.get_json()

    assert data["success"] is False
    assert data["error"] == "Event not found"


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


def test_session_detail_endpoint_returns_session(client):
    session = AttackSession(
        session_id="detail-session-2",
        source_ip="203.0.113.90",
        protocol="SSH",
        username="root",
        command_count=4,
    )

    db.session.add(session)
    db.session.commit()

    response = client.get(f"/api/sessions/{session.id}")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["session"]["id"] == session.id
    assert data["session"]["session_id"] == "detail-session-2"
    assert data["session"]["command_count"] == 4


def test_session_detail_endpoint_returns_404_for_missing_session(client):
    response = client.get("/api/sessions/9999")

    assert response.status_code == 404

    data = response.get_json()

    assert data["success"] is False
    assert data["error"] == "Session not found"


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
        source_ip="203.0.113.70",
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
    assert data["stats"]["total_commands"] == 2
    assert data["stats"]["unique_source_ips"] == 1


def test_dashboard_endpoint_returns_stats_and_recent_data(client):
    session = AttackSession(
        session_id="dashboard-session",
        source_ip="203.0.113.100",
        protocol="SSH",
        username="root",
        start_time=datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc),
        command_count=3,
    )

    event = CowrieEvent(
        event_id="dashboard-event",
        session_id="dashboard-session",
        timestamp=datetime(2026, 8, 19, 12, 1, tzinfo=timezone.utc),
        source_ip="203.0.113.100",
        event_type="cowrie.command.input",
        username="root",
        command="uname -a",
    )

    db.session.add(session)
    db.session.add(event)
    db.session.commit()

    response = client.get("/api/dashboard")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True

    assert data["stats"]["total_sessions"] == 1
    assert data["stats"]["total_events"] == 1
    assert data["stats"]["total_commands"] == 3
    assert data["stats"]["unique_source_ips"] == 1

    assert len(data["recent_events"]) == 1
    assert data["recent_events"][0]["event_id"] == "dashboard-event"

    assert len(data["recent_sessions"]) == 1
    assert data["recent_sessions"][0]["session_id"] == "dashboard-session"