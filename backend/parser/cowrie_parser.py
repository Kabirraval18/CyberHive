import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def _parse_timestamp(value: Any) -> datetime | None:
    """Convert a Cowrie timestamp into a timezone-aware UTC datetime."""
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")

    normalized = value.strip()

    if not normalized:
        return None

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _fingerprint_event(event: dict[str, Any]) -> str:
    """Create a deterministic identifier for an exact event payload."""
    canonical = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw Cowrie event into the CyberHive event representation."""
    if not isinstance(raw_event, dict):
        raise ValueError("Cowrie event must be a JSON object")

    event_type = raw_event.get("eventid")

    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Cowrie event is missing eventid")

    normalized = {
        "session_id": raw_event.get("session"),
        "timestamp": _parse_timestamp(raw_event.get("timestamp")),
        "source_ip": raw_event.get("src_ip"),
        "event_type": event_type,
        "username": raw_event.get("username"),
        "command": raw_event.get("input"),
        "event_metadata": json.dumps(
            raw_event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
    }

    normalized["event_id"] = _fingerprint_event(raw_event)

    return normalized


def parse_cowrie_line(line: str) -> dict[str, Any] | None:
    """
    Parse one Cowrie JSONL record.

    Blank lines return None.
    Malformed JSON raises ValueError.
    """
    if not isinstance(line, str):
        raise TypeError("line must be a string")

    if not line.strip():
        return None

    try:
        raw_event = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid Cowrie JSON") from exc

    return _normalize_event(raw_event)


def parse_cowrie_lines(
    lines: Iterable[str],
    *,
    skip_duplicates: bool = True,
) -> list[dict[str, Any]]:
    """Parse multiple Cowrie JSONL records."""
    parsed_events: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()

    for line in lines:
        event = parse_cowrie_line(line)

        if event is None:
            continue

        event_id = event["event_id"]

        if skip_duplicates and event_id in seen_event_ids:
            continue

        seen_event_ids.add(event_id)
        parsed_events.append(event)

    return parsed_events


def parse_cowrie_file(
    path: str | Path,
    *,
    skip_duplicates: bool = True,
) -> list[dict[str, Any]]:
    """Parse a Cowrie JSONL file."""
    file_path = Path(path)

    with file_path.open("r", encoding="utf-8") as file:
        return parse_cowrie_lines(
            file,
            skip_duplicates=skip_duplicates,
        )