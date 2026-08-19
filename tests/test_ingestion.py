import json
from datetime import datetime, timezone

import pytest

from backend.app import create_app
from backend.config import TestConfig
from backend.extensions import db
from backend.ingestion.cowrie_ingest import ingest_events
from backend.models import AttackSession, CowrieEvent


@pytest.fixture
def app():
    application = create_app(TestConfig)

    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def test_ingest_single_event_creates_event(app):
    event = {
        "event_id": "event-001",
        "session_id": "session-001",
        "timestamp": datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),
        "source_ip": "203.0.113.10",
        "event_type": "cowrie.command.input",
        "username": "root",
        "command": "whoami",
        "event_metadata": json.dumps(
            {
                "eventid": "cowrie.command.input",
                "session": "session-001",
                "src_ip": "203.0.113.10",
                "input": "whoami",
            }
        ),
    }

    with app.app_context():
        result = ingest_events([event])

        assert result == 1

        stored = CowrieEvent.query.filter_by(event_id="event-001").one()

        assert stored.session_id == "session-001"
        assert stored.source_ip == "203.0.113.10"
        assert stored.event_type == "cowrie.command.input"
        assert stored.command == "whoami"


def test_ingest_event_creates_attack_session(app):
    event = {
        "event_id": "event-002",
        "session_id": "session-002",
        "timestamp": datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),
        "source_ip": "203.0.113.20",
        "event_type": "cowrie.command.input",
        "username": "root",
        "command": "uname -a",
        "event_metadata": json.dumps(
            {
                "eventid": "cowrie.command.input",
                "session": "session-002",
                "src_ip": "203.0.113.20",
                "input": "uname -a",
            }
        ),
    }

    with app.app_context():
        ingest_events([event])

        session = AttackSession.query.filter_by(
            session_id="session-002"
        ).one()

        assert session.source_ip == "203.0.113.20"
        assert session.username == "root"
        assert session.command_count == 1


def test_ingest_multiple_events_reuses_session(app):
    events = [
        {
            "event_id": "event-003",
            "session_id": "session-003",
            "timestamp": datetime(
                2026, 8, 19, 10, 0, tzinfo=timezone.utc
            ),
            "source_ip": "203.0.113.30",
            "event_type": "cowrie.command.input",
            "username": "root",
            "command": "whoami",
            "event_metadata": "{}",
        },
        {
            "event_id": "event-004",
            "session_id": "session-003",
            "timestamp": datetime(
                2026, 8, 19, 10, 0, 1, tzinfo=timezone.utc
            ),
            "source_ip": "203.0.113.30",
            "event_type": "cowrie.command.input",
            "username": "root",
            "command": "uname -a",
            "event_metadata": "{}",
        },
    ]

    with app.app_context():
        ingest_events(events)

        sessions = AttackSession.query.filter_by(
            session_id="session-003"
        ).all()

        stored_events = CowrieEvent.query.filter_by(
            session_id="session-003"
        ).all()

        assert len(sessions) == 1
        assert len(stored_events) == 2
        assert sessions[0].command_count == 2


def test_ingest_duplicate_event_is_not_inserted_twice(app):
    event = {
        "event_id": "event-005",
        "session_id": "session-005",
        "timestamp": datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),
        "source_ip": "203.0.113.50",
        "event_type": "cowrie.command.input",
        "username": "root",
        "command": "id",
        "event_metadata": "{}",
    }

    with app.app_context():
        assert ingest_events([event]) == 1
        assert ingest_events([event]) == 0

        assert CowrieEvent.query.count() == 1
        assert AttackSession.query.count() == 1


def test_ingest_event_without_session_does_not_create_session(app):
    event = {
        "event_id": "event-006",
        "session_id": None,
        "timestamp": datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),
        "source_ip": "203.0.113.60",
        "event_type": "cowrie.startup",
        "username": None,
        "command": None,
        "event_metadata": "{}",
    }

    with app.app_context():
        assert ingest_events([event]) == 1

        stored = CowrieEvent.query.filter_by(event_id="event-006").one()

        assert stored.session_id is None
        assert AttackSession.query.count() == 0