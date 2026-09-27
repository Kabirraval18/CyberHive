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


def test_activity_analytics_endpoint_returns_empty_activity(client):
    response = client.get("/api/analytics/activity")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["activity"] == []


def test_activity_analytics_endpoint_preserves_precise_timestamps(client):
    session_one = AttackSession(
        session_id="analytics-session-1",
        source_ip="203.0.113.110",
        protocol="SSH",
        username="root",
        start_time=datetime(
            2026,
            8,
            19,
            10,
            15,
            42,
            123456,
            tzinfo=timezone.utc,
        ),
        command_count=2,
    )

    session_two = AttackSession(
        session_id="analytics-session-2",
        source_ip="203.0.113.111",
        protocol="SSH",
        username="admin",
        start_time=datetime(
            2026,
            8,
            19,
            11,
            20,
            5,
            654321,
            tzinfo=timezone.utc,
        ),
        command_count=4,
    )

    event_one = CowrieEvent(
        event_id="analytics-event-1",
        session_id="analytics-session-1",
        timestamp=datetime(
            2026,
            8,
            19,
            10,
            16,
            23,
            111111,
            tzinfo=timezone.utc,
        ),
        source_ip="203.0.113.110",
        event_type="cowrie.command.input",
        username="root",
        command="whoami",
    )

    event_two = CowrieEvent(
        event_id="analytics-event-2",
        session_id="analytics-session-1",
        timestamp=datetime(
            2026,
            8,
            19,
            10,
            18,
            7,
            222222,
            tzinfo=timezone.utc,
        ),
        source_ip="203.0.113.110",
        event_type="cowrie.command.input",
        username="root",
        command="id",
    )

    event_three = CowrieEvent(
        event_id="analytics-event-3",
        session_id="analytics-session-2",
        timestamp=datetime(
            2026,
            8,
            19,
            11,
            21,
            19,
            333333,
            tzinfo=timezone.utc,
        ),
        source_ip="203.0.113.111",
        event_type="cowrie.command.input",
        username="admin",
        command="uname -a",
    )

    db.session.add(session_one)
    db.session.add(session_two)

    db.session.add(event_one)
    db.session.add(event_two)
    db.session.add(event_three)

    db.session.commit()

    response = client.get("/api/analytics/activity")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True

    activity = data["activity"]

    assert len(activity) == 5

    assert activity[0]["timestamp"] == (
        "2026-08-19T10:15:42.123456+00:00"
    )
    assert activity[0]["activity_type"] == "session"
    assert activity[0]["session_id"] == "analytics-session-1"
    assert activity[0]["command_count"] == 2

    assert activity[1]["timestamp"] == (
        "2026-08-19T10:16:23.111111+00:00"
    )
    assert activity[1]["activity_type"] == "event"
    assert activity[1]["event_id"] == "analytics-event-1"
    assert activity[1]["command"] == "whoami"

    assert activity[2]["timestamp"] == (
        "2026-08-19T10:18:07.222222+00:00"
    )
    assert activity[2]["activity_type"] == "event"
    assert activity[2]["event_id"] == "analytics-event-2"
    assert activity[2]["command"] == "id"

    assert activity[3]["timestamp"] == (
        "2026-08-19T11:20:05.654321+00:00"
    )
    assert activity[3]["activity_type"] == "session"
    assert activity[3]["session_id"] == "analytics-session-2"
    assert activity[3]["command_count"] == 4

    assert activity[4]["timestamp"] == (
        "2026-08-19T11:21:19.333333+00:00"
    )
    assert activity[4]["activity_type"] == "event"
    assert activity[4]["event_id"] == "analytics-event-3"
    assert activity[4]["command"] == "uname -a"

def test_session_filter_rejects_invalid_dates(app, client):
    response = client.get('/api/sessions/filter?start=not-a-date')
    assert response.status_code == 400
    assert 'valid ISO-8601' in response.get_json()['error']


def test_investigation_endpoint_returns_commands_and_authentication_events(
    app,
    client,
):
    from backend.extensions import db

    session = AttackSession(
        session_id="investigation-evidence-session",
        source_ip="127.0.0.1",
        protocol="ssh",
        username="root",
    )

    command_one = CowrieEvent(
        event_id="investigation-command-1",
        session_id="investigation-evidence-session",
        timestamp=datetime(
            2026,
            8,
            19,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        source_ip="127.0.0.1",
        event_type="cowrie.command.input",
        username="root",
        command="whoami",
    )

    command_two = CowrieEvent(
        event_id="investigation-command-2",
        session_id="investigation-evidence-session",
        timestamp=datetime(
            2026,
            8,
            19,
            10,
            0,
            1,
            tzinfo=timezone.utc,
        ),
        source_ip="127.0.0.1",
        event_type="cowrie.command.input",
        username="root",
        command="uname -a",
    )

    failed_login = CowrieEvent(
        event_id="investigation-login-failed",
        session_id="investigation-evidence-session",
        timestamp=datetime(
            2026,
            8,
            19,
            9,
            59,
            50,
            tzinfo=timezone.utc,
        ),
        source_ip="127.0.0.1",
        event_type="cowrie.login.failed",
        username="root",
    )

    successful_login = CowrieEvent(
        event_id="investigation-login-success",
        session_id="investigation-evidence-session",
        timestamp=datetime(
            2026,
            8,
            19,
            9,
            59,
            55,
            tzinfo=timezone.utc,
        ),
        source_ip="127.0.0.1",
        event_type="cowrie.login.success",
        username="root",
    )

    db.session.add(session)
    db.session.add(command_one)
    db.session.add(command_two)
    db.session.add(failed_login)
    db.session.add(successful_login)
    db.session.commit()

    response = client.get(
        "/api/sessions/by-session-id/"
        "investigation-evidence-session/investigation"
    )

    assert response.status_code == 200

    payload = response.get_json()

    assert payload["success"] is True

    assert payload["commands"] == [
        "whoami",
        "uname -a",
    ]

    assert len(
        payload["authentication_events"]
    ) == 2

    assert [
        event["event_type"]
        for event in payload["authentication_events"]
    ] == [
        "cowrie.login.failed",
        "cowrie.login.success",
    ]