from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from backend.models import AttackSession, CowrieEvent


COMMAND_EVENT_TYPES = {
    "cowrie.command.input",
    "cowrie.command.failed",
}

AUTH_FAILED_EVENT = "cowrie.login.failed"
AUTH_SUCCESS_EVENT = "cowrie.login.success"
DOWNLOAD_EVENT_TYPES = {
    "cowrie.session.file_download",
}
UPLOAD_EVENT_TYPES = {
    "cowrie.session.file_upload",
}

DISCOVERY_COMMAND_PATTERNS = {
    "identity": (
        r"^whoami(?:\s.*)?$",
        r"^id(?:\s.*)?$",
    ),
    "system": (
        r"^uname(?:\s.*)?$",
        r"^hostname(?:\s.*)?$",
        r"^cat\s+/etc/(?:os-release|issue)$",
        r"^lscpu(?:\s.*)?$",
        r"^free(?:\s.*)?$",
    ),
    "filesystem": (
        r"^pwd(?:\s.*)?$",
        r"^ls(?:\s.*)?$",
        r"^find(?:\s.*)?$",
        r"^locate(?:\s.*)?$",
        r"^cat\s+/etc/passwd(?:\s.*)?$",
        r"^df(?:\s.*)?$",
        r"^mount(?:\s.*)?$",
    ),
    "process": (
        r"^ps(?:\s.*)?$",
        r"^top(?:\s.*)?$",
    ),
    "network": (
        r"^(?:ip|ifconfig|ss|netstat)(?:\s.*)?$",
    ),
    "account": (
        r"^(?:last|w)(?:\s.*)?$",
        r"^cat\s+/etc/shells(?:\s.*)?$",
    ),
}

TRANSFER_COMMAND_PATTERNS = (
    re.compile(r"(?:^|\s)wget(?:\s|$)", re.IGNORECASE),
    re.compile(r"(?:^|\s)curl(?:\s|$)", re.IGNORECASE),
    re.compile(r"(?:^|\s)(?:ftp|tftp|scp|sftp)(?:\s|$)", re.IGNORECASE),
)

PERSISTENCE_COMMAND_PATTERNS = (
    re.compile(r"\bcrontab\b", re.IGNORECASE),
    re.compile(r"\bsystemctl\s+(?:enable|start)\b", re.IGNORECASE),
    re.compile(r"\bupdate-rc\.d\b", re.IGNORECASE),
    re.compile(r"\b/etc/rc\.local\b", re.IGNORECASE),
    re.compile(r"\.ssh/authorized_keys", re.IGNORECASE),
    re.compile(r"\bssh-keygen\b", re.IGNORECASE),
)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def normalize_command(command: str | None) -> str | None:
    if command is None:
        return None
    normalized = re.sub(r"\s+", " ", command.strip()).lower()
    return normalized or None


def _ordered_events(events: Iterable[CowrieEvent]) -> list[CowrieEvent]:
    return sorted(
        events,
        key=lambda event: (
            event.timestamp is None,
            _as_utc(event.timestamp) or datetime.max.replace(tzinfo=timezone.utc),
            event.id or 0,
        ),
    )


def _matches_any(command: str, patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(command) for pattern in patterns)


def _discovery_categories(command: str) -> set[str]:
    categories: set[str] = set()
    for category, patterns in DISCOVERY_COMMAND_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, command, flags=re.IGNORECASE):
                categories.add(category)
                break
    return categories


def _event_counter(events: Iterable[CowrieEvent]) -> Counter[str]:
    return Counter(event.event_type for event in events if event.event_type)


def _timestamp_seconds(value: datetime | None) -> float | None:
    value_utc = _as_utc(value)
    if value_utc is None:
        return None
    return value_utc.timestamp()


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def extract_session_features(session: AttackSession) -> dict[str, Any]:
    """Derive deterministic, explainable features from stored Cowrie events."""

    events = _ordered_events(session.events.all())
    event_counts = _event_counter(events)

    commands = [
        event
        for event in events
        if event.event_type in COMMAND_EVENT_TYPES
        and normalize_command(event.command) is not None
    ]
    normalized_commands = [
        normalize_command(event.command)
        for event in commands
    ]
    normalized_commands = [
        command for command in normalized_commands if command is not None
    ]

    command_count = len(normalized_commands)
    unique_commands = list(dict.fromkeys(normalized_commands))
    unique_command_count = len(unique_commands)

    failed_logins = sum(
        1 for event in events if event.event_type == AUTH_FAILED_EVENT
    )
    successful_logins = sum(
        1 for event in events if event.event_type == AUTH_SUCCESS_EVENT
    )
    auth_attempt_count = failed_logins + successful_logins

    command_timestamps = [
        _timestamp_seconds(event.timestamp)
        for event in commands
    ]
    command_gaps = [
        right - left
        for left, right in zip(
            command_timestamps,
            command_timestamps[1:],
        )
        if left is not None
        and right is not None
        and right >= left
    ]

    start_seconds = _timestamp_seconds(session.start_time)
    end_seconds = _timestamp_seconds(session.end_time)
    duration_seconds: float | None = None
    if start_seconds is not None and end_seconds is not None and end_seconds >= start_seconds:
        duration_seconds = round(end_seconds - start_seconds, 6)

    event_start_seconds = next(
        (_timestamp_seconds(event.timestamp) for event in events if event.timestamp is not None),
        None,
    )
    event_end_seconds = next(
        (_timestamp_seconds(event.timestamp) for event in reversed(events) if event.timestamp is not None),
        None,
    )
    if duration_seconds is None and event_start_seconds is not None and event_end_seconds is not None:
        if event_end_seconds >= event_start_seconds:
            duration_seconds = round(event_end_seconds - event_start_seconds, 6)

    command_frequency_per_minute: float | None = None
    if duration_seconds is not None and duration_seconds > 0:
        command_frequency_per_minute = round(
            command_count / (duration_seconds / 60.0),
            6,
        )

    repeated_command_ratio = None
    unique_command_ratio = None
    if command_count > 0:
        repeated_command_ratio = round(
            (command_count - unique_command_count) / command_count,
            6,
        )
        unique_command_ratio = round(
            unique_command_count / command_count,
            6,
        )
    else:
        # No commands means no observed repetition/diversity.
        repeated_command_ratio = 0.0
        unique_command_ratio = 0.0

    discovery_categories: set[str] = set()
    discovery_command_count = 0
    transfer_command_count = 0
    persistence_command_count = 0

    for command in normalized_commands:
        categories = _discovery_categories(command)
        if categories:
            discovery_categories.update(categories)
            discovery_command_count += 1

        if _matches_any(command, TRANSFER_COMMAND_PATTERNS):
            transfer_command_count += 1

        if _matches_any(command, PERSISTENCE_COMMAND_PATTERNS):
            persistence_command_count += 1

    download_event_count = sum(
        1 for event in events if event.event_type in DOWNLOAD_EVENT_TYPES
    )
    upload_event_count = sum(
        1 for event in events if event.event_type in UPLOAD_EVENT_TYPES
    )
    transfer_event_count = download_event_count + upload_event_count

    authentication_timestamps = [
        _timestamp_seconds(event.timestamp)
        for event in events
        if event.event_type in {AUTH_FAILED_EVENT, AUTH_SUCCESS_EVENT}
    ]
    authentication_gaps = [
        right - left
        for left, right in zip(
            authentication_timestamps,
            authentication_timestamps[1:],
        )
        if left is not None
        and right is not None
        and right >= left
    ]

    source_session_count = None
    if session.source_ip and session.source_ip != "unknown":
        source_session_count = (
            AttackSession.query
            .filter(AttackSession.source_ip == session.source_ip)
            .count()
        )

    authentication_sequence = []
    for event in events:
        if event.event_type == AUTH_FAILED_EVENT:
            authentication_sequence.append("failed")
        elif event.event_type == AUTH_SUCCESS_EVENT:
            authentication_sequence.append("success")

    authentication_result = None
    if authentication_sequence:
        authentication_result = authentication_sequence[-1]
        if len(set(authentication_sequence)) > 1:
            authentication_result = "mixed"

    session.duration = duration_seconds
    if authentication_result is not None:
        session.authentication_result = authentication_result

    features: dict[str, Any] = {
        "schema_version": 1,
        "session_id": session.session_id,
        "source_ip": session.source_ip,
        "protocol": session.protocol,
        "username": session.username,
        "event_count": len(events),
        "event_type_counts": dict(sorted(event_counts.items())),
        "command_count": command_count,
        "unique_command_count": unique_command_count,
        "unique_command_ratio": unique_command_ratio,
        "repeated_command_ratio": repeated_command_ratio,
        "command_sequence": [
            event.command for event in commands if event.command is not None
        ],
        "normalized_command_sequence": normalized_commands,
        "session_duration_seconds": duration_seconds,
        "mean_time_between_commands_seconds": (
            round(_mean(command_gaps), 6) if command_gaps else None
        ),
        "command_frequency_per_minute": command_frequency_per_minute,
        "failed_login_count": failed_logins,
        "successful_login_count": successful_logins,
        "authentication_attempt_count": auth_attempt_count,
        "authentication_failure_ratio": (
            round(failed_logins / auth_attempt_count, 6)
            if auth_attempt_count > 0
            else None
        ),
        "mean_time_between_authentication_attempts_seconds": (
            round(_mean(authentication_gaps), 6)
            if authentication_gaps
            else None
        ),
        "authentication_sequence": authentication_sequence,
        "authentication_result": authentication_result,
        "discovery_command_count": discovery_command_count,
        "discovery_category_count": len(discovery_categories),
        "discovery_categories": sorted(discovery_categories),
        "transfer_command_count": transfer_command_count,
        "download_event_count": download_event_count,
        "upload_event_count": upload_event_count,
        "transfer_event_count": transfer_event_count,
        "persistence_command_count": persistence_command_count,
        "source_session_count": source_session_count,
        "has_missing_event_timestamps": any(
            event.timestamp is None for event in events
        ),
    }

    return features


def build_behavior_signature(features: dict[str, Any]) -> str:
    """Build a deterministic signature for repeated behavior correlation."""

    signature_payload = {
        "protocol": features.get("protocol"),
        "normalized_command_sequence": features.get(
            "normalized_command_sequence", []
        ),
        "authentication_sequence": features.get(
            "authentication_sequence", []
        ),
        "download_event_count": features.get("download_event_count", 0),
        "upload_event_count": features.get("upload_event_count", 0),
    }

    canonical = json.dumps(
        signature_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
