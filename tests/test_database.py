from datetime import datetime

import pytest
from sqlalchemy import inspect

from backend.app import create_app
from backend.config import TestConfig
from backend.db.init_db import init_db
from backend.extensions import db
from backend.models import AttackSession, CowrieEvent


@pytest.fixture
def app():
    application = create_app(TestConfig)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def test_create_app_initializes_database_extension(app):
    assert app.extensions.get("sqlalchemy") is not None


def test_attack_session_table_exists(app):
    with app.app_context():
        table_names = inspect(db.engine).get_table_names()
    assert "attack_sessions" in table_names


def test_cowrie_event_table_exists(app):
    with app.app_context():
        table_names = inspect(db.engine).get_table_names()
    assert "cowrie_events" in table_names


def test_insert_and_retrieve_attack_session(app):
    with app.app_context():
        session = AttackSession(
            session_id="abc123",
            source_ip="203.0.113.10",
            protocol="SSH",
            username="root",
            authentication_result="failed",
            start_time=datetime(2026, 8, 18, 10, 0, 0),
            command_count=2,
        )
        db.session.add(session)
        db.session.commit()

        retrieved = AttackSession.query.filter_by(session_id="abc123").one()

        assert retrieved.source_ip == "203.0.113.10"
        assert retrieved.protocol == "SSH"
        assert retrieved.username == "root"
        assert retrieved.command_count == 2


def test_insert_and_retrieve_cowrie_event(app):
    with app.app_context():
        event = CowrieEvent(
            event_id="evt-001",
            session_id="abc123",
            timestamp=datetime(2026, 8, 18, 10, 1, 0),
            source_ip="203.0.113.10",
            event_type="cowrie.command.input",
            username="root",
            command="uname -a",
            event_metadata='{"input": "uname -a"}',
        )
        db.session.add(event)
        db.session.commit()

        retrieved = CowrieEvent.query.filter_by(event_id="evt-001").one()

        assert retrieved.session_id == "abc123"
        assert retrieved.event_type == "cowrie.command.input"
        assert retrieved.command == "uname -a"
        assert retrieved.event_metadata == '{"input": "uname -a"}'


def test_database_can_be_initialized_more_than_once(app):
    with app.app_context():
        db.create_all()
        db.create_all()


def test_init_db_runs_without_error(tmp_path):
    db_path = tmp_path / "test_cyberhive.db"

    class TempConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path.as_posix()}"

    init_db(TempConfig)
    init_db(TempConfig)

    assert db_path.exists()

    application = create_app(TempConfig)

    with application.app_context():
        table_names = inspect(db.engine).get_table_names()

    assert "attack_sessions" in table_names
    assert "cowrie_events" in table_names

def test_attack_session_and_cowrie_event_relationship(app):
    with app.app_context():
        session = AttackSession(
            session_id="relationship-session",
            source_ip="203.0.113.20",
            protocol="SSH",
            username="root",
            authentication_result="failed",
            start_time=datetime(2026, 8, 18, 11, 0, 0),
            command_count=1,
        )

        event = CowrieEvent(
            event_id="relationship-event",
            session_id="relationship-session",
            timestamp=datetime(2026, 8, 18, 11, 0, 1),
            source_ip="203.0.113.20",
            event_type="cowrie.command.input",
            username="root",
            command="whoami",
            event_metadata='{"input": "whoami"}',
        )

        db.session.add(session)
        db.session.add(event)
        db.session.commit()

        session_from_db = (
            AttackSession.query
            .filter_by(session_id="relationship-session")
            .one()
        )

        event_from_db = (
            CowrieEvent.query
            .filter_by(event_id="relationship-event")
            .one()
        )

        assert event_from_db.attack_session == session_from_db
        assert event_from_db in session_from_db.events