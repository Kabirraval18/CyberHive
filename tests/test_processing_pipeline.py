from datetime import datetime, timezone

import pytest
from backend.ingestion.cowrie_ingest import ingest_events
from backend.app import create_app
from backend.config import TestConfig
from backend.extensions import db
from backend.models import AttackSession, CowrieEvent
from backend.processing.pipeline import process_cowrie_events


@pytest.fixture
def app():
    application = create_app(TestConfig)

    with application.app_context():
        db.create_all()

        yield application

        db.session.remove()
        db.drop_all()


def _event(
    event_id: str,
    session_id: str,
    command: str | None = None,
):
    return {
        "event_id": event_id,
        "session_id": session_id,
        "timestamp": datetime(
            2026,
            9,
            22,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        "source_ip": "203.0.113.10",
        "event_type": "cowrie.command.input",
        "username": "root",
        "command": command,
        "event_metadata": "{}",
    }


def test_processing_pipeline_ingests_single_event(app):
    with app.app_context():
        result = process_cowrie_events(
            [
                _event(
                    "processing-event-001",
                    "processing-session-001",
                    "whoami",
                )
            ]
        )

        assert result.inserted_events == 1

        assert result.affected_sessions == [
            "processing-session-001"
        ]

        assert (
            CowrieEvent.query.count()
            == 1
        )

        assert (
            AttackSession.query.count()
            == 1
        )


def test_processing_pipeline_handles_multiple_events(
    app,
):
    with app.app_context():
        result = process_cowrie_events(
            [
                _event(
                    "processing-event-002",
                    "processing-session-002",
                    "whoami",
                ),
                _event(
                    "processing-event-003",
                    "processing-session-002",
                    "uname -a",
                ),
                _event(
                    "processing-event-004",
                    "processing-session-003",
                    "id",
                ),
            ]
        )

        assert result.inserted_events == 3

        assert set(result.affected_sessions) == {
            "processing-session-002",
            "processing-session-003",
        }

        assert CowrieEvent.query.count() == 3
        assert AttackSession.query.count() == 2


def test_processing_pipeline_is_idempotent(
    app,
):
    events = [
        _event(
            "processing-event-005",
            "processing-session-005",
            "whoami",
        ),
        _event(
            "processing-event-006",
            "processing-session-005",
            "id",
        ),
    ]

    with app.app_context():
        first = process_cowrie_events(events)

        second = process_cowrie_events(events)

        assert first.inserted_events == 2
        assert second.inserted_events == 0

        assert CowrieEvent.query.count() == 2
        assert AttackSession.query.count() == 1


def test_processing_pipeline_handles_empty_input(
    app,
):
    with app.app_context():
        result = process_cowrie_events([])

        assert result.inserted_events == 0
        assert result.affected_sessions == []
        assert result.processing_errors == []

        assert CowrieEvent.query.count() == 0
        assert AttackSession.query.count() == 0


def test_processing_pipeline_handles_event_without_session(
    app,
):
    event = _event(
        "processing-event-007",
        "",
        None,
    )

    event["session_id"] = None
    event["event_type"] = "cowrie.startup"

    with app.app_context():
        result = process_cowrie_events([event])

        assert result.inserted_events == 1
        assert result.affected_sessions == []

        assert CowrieEvent.query.count() == 1
        assert AttackSession.query.count() == 0

def test_processing_pipeline_only_marks_new_events_as_affected(
    app,
):
    first_batch = [
        _event(
            "processing-event-008",
            "processing-session-008",
            "whoami",
        ),
        _event(
            "processing-event-009",
            "processing-session-008",
            "id",
        ),
    ]

    second_batch = [
        _event(
            "processing-event-008",
            "processing-session-008",
            "whoami",
        ),
        _event(
            "processing-event-009",
            "processing-session-008",
            "id",
        ),
        _event(
            "processing-event-010",
            "processing-session-009",
            "uname -a",
        ),
    ]

    with app.app_context():
        first = process_cowrie_events(first_batch)

        assert first.inserted_events == 2

        assert first.affected_sessions == [
            "processing-session-008"
        ]

        second = process_cowrie_events(second_batch)

        assert second.inserted_events == 1

        assert second.affected_sessions == [
            "processing-session-009"
        ]

        assert CowrieEvent.query.count() == 3

        assert AttackSession.query.count() == 2

def test_session_processor_receives_only_new_sessions(app):
    calls = []

    def processor(session_id):
        calls.append(session_id)

    first_batch = [
        _event(
            "processing-event-011",
            "processing-session-011",
            "whoami",
        ),
        _event(
            "processing-event-012",
            "processing-session-012",
            "id",
        ),
    ]

    second_batch = [
        _event(
            "processing-event-011",
            "processing-session-011",
            "whoami",
        ),
        _event(
            "processing-event-012",
            "processing-session-012",
            "id",
        ),
        _event(
            "processing-event-013",
            "processing-session-013",
            "uname -a",
        ),
    ]

    with app.app_context():
        first = process_cowrie_events(
            first_batch,
            session_processors=[processor],
        )

        assert first.inserted_events == 2

        assert set(calls) == {
            "processing-session-011",
            "processing-session-012",
        }

        calls.clear()

        second = process_cowrie_events(
            second_batch,
            session_processors=[processor],
        )

        assert second.inserted_events == 1

        assert calls == [
            "processing-session-013"
        ]

def test_duplicate_collector_run_does_not_trigger_processor(app):
    calls = []

    def processor(session_id):
        calls.append(session_id)

    events = [
        _event(
            "processing-event-014",
            "processing-session-014",
            "whoami",
        )
    ]

    with app.app_context():
        first = process_cowrie_events(
            events,
            session_processors=[processor],
        )

        second = process_cowrie_events(
            events,
            session_processors=[processor],
        )

        assert first.inserted_events == 1
        assert second.inserted_events == 0

        assert calls == [
            "processing-session-014"
        ]

        assert CowrieEvent.query.count() == 1

def test_optional_processor_failure_does_not_break_ingestion(app):
    def failing_processor(session_id):
        raise RuntimeError(
            "simulated behavioral processing failure"
        )

    event = _event(
        "processing-event-015",
        "processing-session-015",
        "whoami",
    )

    with app.app_context():
        result = process_cowrie_events(
            [event],
            session_processors=[failing_processor],
        )

        assert result.inserted_events == 1

        assert result.affected_sessions == [
            "processing-session-015"
        ]

        assert result.success is False

        assert len(result.processing_errors) == 1

        error = result.processing_errors[0]

        assert error["stage"] == "session_processor"

        assert error["session_id"] == (
            "processing-session-015"
        )

        assert error["error_type"] == "RuntimeError"

        assert (
            error["message"]
            == "simulated behavioral processing failure"
        )

        assert CowrieEvent.query.count() == 1

        assert AttackSession.query.count() == 1

def test_one_processor_failure_does_not_stop_other_processors(
    app,
):
    calls = []

    def failing_processor(session_id):
        calls.append(("failing", session_id))

        raise RuntimeError("first processor failed")

    def successful_processor(session_id):
        calls.append(("successful", session_id))

    event = _event(
        "processing-event-016",
        "processing-session-016",
        "id",
    )

    with app.app_context():
        result = process_cowrie_events(
            [event],
            session_processors=[
                failing_processor,
                successful_processor,
            ],
        )

        assert result.inserted_events == 1

        assert result.success is False

        assert calls == [
            (
                "failing",
                "processing-session-016",
            ),
            (
                "successful",
                "processing-session-016",
            ),
        ]

        assert len(result.processing_errors) == 1

def test_processing_session_without_command(app):
    event = _event(
        "processing-event-017",
        "processing-session-017",
        None,
    )

    with app.app_context():
        result = process_cowrie_events([event])

        assert result.inserted_events == 1

        assert result.affected_sessions == [
            "processing-session-017"
        ]

        stored_event = CowrieEvent.query.filter_by(
            event_id="processing-event-017"
        ).one()

        assert stored_event.command is None

        session = AttackSession.query.filter_by(
            session_id="processing-session-017"
        ).one()

        assert session.command_count == 0

def test_existing_ingestion_contract_is_preserved(app):
    events = [
        _event(
            "processing-event-019",
            "processing-session-019",
            "whoami",
        )
    ]

    with app.app_context():
        inserted = ingest_events(events)

        assert inserted == 1

        duplicate = ingest_events(events)

        assert duplicate == 0

        assert CowrieEvent.query.count() == 1