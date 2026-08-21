import json
from datetime import datetime, timezone
from typing import Any, Iterable

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent

def _to_utc_naive(value: datetime | None) -> datetime | None:
    """
    Normalize a datetime to naive UTC.

    SQLite/SQLAlchemy may return DateTime values without tzinfo,
    while parsed Cowrie timestamps are timezone-aware. Converting
    everything to naive UTC gives us one consistent representation
    for database comparisons and storage.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value

    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _extract_protocol(event: dict[str, Any]) -> str:
    """Extract the protocol from event metadata when available."""
    metadata = event.get("event_metadata")

    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}

    if isinstance(metadata, dict):
        protocol = metadata.get("protocol")

        if isinstance(protocol, str) and protocol.strip():
            return protocol.strip()

    return "unknown"


def _get_or_create_session(
    event: dict[str, Any],
) -> AttackSession | None:
    """Return the AttackSession associated with an event."""
    session_id = event.get("session_id")

    if not session_id:
        return None

    session = AttackSession.query.filter_by(
        session_id=session_id
    ).one_or_none()

    if session is not None:
        return session

    session = AttackSession(
        session_id=session_id,
        source_ip=event.get("source_ip") or "unknown",
        protocol=_extract_protocol(event),
        username=event.get("username"),
        start_time=_to_utc_naive(event.get("timestamp")),
        command_count=0,
    )

    db.session.add(session)

    return session


def _update_session(
    session: AttackSession,
    event: dict[str, Any],
) -> None:
    """Update session-level information from an event."""

    timestamp = _to_utc_naive(event.get("timestamp"))

    if timestamp is not None:
        current_start = _to_utc_naive(session.start_time)
        current_end = _to_utc_naive(session.end_time)

        if current_start is None or timestamp < current_start:
            session.start_time = timestamp

        if current_end is None or timestamp > current_end:
            session.end_time = timestamp

    if session.source_ip == "unknown" and event.get("source_ip"):
        session.source_ip = event["source_ip"]

    if session.username is None and event.get("username"):
        session.username = event["username"]

    if session.protocol == "unknown":
        protocol = _extract_protocol(event)

        if protocol != "unknown":
            session.protocol = protocol

    if event.get("command") is not None:
        session.command_count += 1
        

def ingest_events(events: Iterable[dict[str, Any]]) -> int:
    """
    Persist normalized Cowrie events into the database.

    Returns the number of newly inserted events.
    """
    inserted_count = 0

    for event in events:
        event_id = event.get("event_id")

        if not event_id:
            raise ValueError("event is missing event_id")

        existing_event = CowrieEvent.query.filter_by(
            event_id=event_id
        ).one_or_none()

        if existing_event is not None:
            continue

        session = _get_or_create_session(event)

        stored_event = CowrieEvent(
            event_id=event_id,
            session_id=event.get("session_id"),
            timestamp=event.get("timestamp"),
            source_ip=event.get("source_ip"),
            event_type=event.get("event_type"),
            username=event.get("username"),
            command=event.get("command"),
            event_metadata=event.get("event_metadata"),
        )

        db.session.add(stored_event)

        if session is not None:
            _update_session(session, event)

        inserted_count += 1

    db.session.commit()

    return inserted_count