import json
from datetime import datetime, timezone

import pytest

from backend.parser.cowrie_parser import (
    parse_cowrie_file,
    parse_cowrie_line,
    parse_cowrie_lines,
)


def test_parse_valid_cowrie_event():
    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:00Z",
            "src_ip": "203.0.113.10",
            "username": "root",
            "input": "uname -a",
        }
    )

    event = parse_cowrie_line(line)

    assert event["session_id"] == "abc123"
    assert event["source_ip"] == "203.0.113.10"
    assert event["event_type"] == "cowrie.command.input"
    assert event["username"] == "root"
    assert event["command"] == "uname -a"
    assert event["timestamp"] == datetime(
        2026,
        8,
        19,
        10,
        0,
        tzinfo=timezone.utc,
    )


def test_parse_timestamp_with_offset_normalizes_to_utc():
    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "timestamp": "2026-08-19T12:00:00+02:00",
            "src_ip": "203.0.113.10",
            "input": "whoami",
        }
    )

    event = parse_cowrie_line(line)

    assert event["timestamp"] == datetime(
        2026,
        8,
        19,
        10,
        0,
        tzinfo=timezone.utc,
    )


def test_optional_fields_can_be_missing():
    line = json.dumps(
        {
            "eventid": "cowrie.login.failed",
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:00Z",
            "src_ip": "203.0.113.10",
        }
    )

    event = parse_cowrie_line(line)

    assert event["session_id"] == "abc123"
    assert event["source_ip"] == "203.0.113.10"
    assert event["username"] is None
    assert event["command"] is None


def test_blank_line_returns_none():
    assert parse_cowrie_line("") is None
    assert parse_cowrie_line("   ") is None


def test_malformed_json_raises_value_error():
    with pytest.raises(ValueError, match="invalid Cowrie JSON"):
        parse_cowrie_line('{"eventid": "cowrie.command.input"')


def test_non_object_json_raises_value_error():
    with pytest.raises(ValueError, match="Cowrie event must be a JSON object"):
        parse_cowrie_line('["not", "an", "event"]')


def test_missing_eventid_raises_value_error():
    line = json.dumps(
        {
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:00Z",
        }
    )

    with pytest.raises(ValueError, match="missing eventid"):
        parse_cowrie_line(line)


def test_invalid_timestamp_raises_value_error():
    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "timestamp": "not-a-timestamp",
        }
    )

    with pytest.raises(ValueError, match="invalid timestamp"):
        parse_cowrie_line(line)


def test_duplicate_events_are_skipped():
    event = {
        "eventid": "cowrie.command.input",
        "session": "abc123",
        "timestamp": "2026-08-19T10:00:00Z",
        "src_ip": "203.0.113.10",
        "input": "whoami",
    }

    line = json.dumps(event)

    parsed = parse_cowrie_lines([line, line])

    assert len(parsed) == 1

def test_duplicate_events_can_be_preserved():
    event = {
        "eventid": "cowrie.command.input",
        "session": "abc123",
        "timestamp": "2026-08-19T10:00:00Z",
        "src_ip": "203.0.113.10",
        "input": "whoami",
    }

    line = json.dumps(event)

    parsed = parse_cowrie_lines(
        [line, line],
        skip_duplicates=False,
    )

    assert len(parsed) == 2
    assert parsed[0]["event_id"] == parsed[1]["event_id"]

def test_distinct_events_in_same_session_are_preserved():
    event_one = {
        "eventid": "cowrie.command.input",
        "session": "abc123",
        "timestamp": "2026-08-19T10:00:00Z",
        "src_ip": "203.0.113.10",
        "input": "whoami",
    }

    event_two = {
        "eventid": "cowrie.command.input",
        "session": "abc123",
        "timestamp": "2026-08-19T10:00:01Z",
        "src_ip": "203.0.113.10",
        "input": "uname -a",
    }

    parsed = parse_cowrie_lines(
        [
            json.dumps(event_one),
            json.dumps(event_two),
        ]
    )

    assert len(parsed) == 2
    assert parsed[0]["command"] == "whoami"
    assert parsed[1]["command"] == "uname -a"
    assert parsed[0]["event_id"] != parsed[1]["event_id"]


def test_attacker_command_is_treated_as_data():
    malicious_command = "echo hacked; rm -rf /; $(whoami)"

    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:00Z",
            "src_ip": "203.0.113.10",
            "input": malicious_command,
        }
    )

    event = parse_cowrie_line(line)

    assert event["command"] == malicious_command

def test_attacker_payload_is_never_executed():
    malicious_command = (
        '"; __import__("os").system("echo SHOULD_NOT_RUN"); '
        '$(touch SHOULD_NOT_RUN)'
    )

    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:00Z",
            "src_ip": "203.0.113.10",
            "input": malicious_command,
        }
    )

    event = parse_cowrie_line(line)

    assert event["command"] == malicious_command

def test_event_id_is_deterministic():
    event = {
        "eventid": "cowrie.command.input",
        "session": "abc123",
        "timestamp": "2026-08-19T10:00:00Z",
        "src_ip": "203.0.113.10",
        "input": "whoami",
    }

    first = parse_cowrie_line(json.dumps(event))
    second = parse_cowrie_line(json.dumps(event))

    assert first["event_id"] == second["event_id"]


def test_parse_cowrie_file(tmp_path):
    log_file = tmp_path / "cowrie.json"

    events = [
        {
            "eventid": "cowrie.login.failed",
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:00Z",
            "src_ip": "203.0.113.10",
            "username": "root",
        },
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "timestamp": "2026-08-19T10:00:01Z",
            "src_ip": "203.0.113.10",
            "username": "root",
            "input": "whoami",
        },
    ]

    log_file.write_text(
        "\n".join(json.dumps(event) for event in events),
        encoding="utf-8",
    )

    parsed = parse_cowrie_file(log_file)

    assert len(parsed) == 2
    assert parsed[0]["event_type"] == "cowrie.login.failed"
    assert parsed[1]["command"] == "whoami"

