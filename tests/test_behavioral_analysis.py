from datetime import datetime, timedelta, timezone

import pytest

from backend.analysis.automation import profile_automation
from backend.analysis.classification import classify_behavior
from backend.analysis.clustering import (
    choose_cluster_count,
    cluster_feature_rows,
    recluster_session_analyses,
)
from backend.analysis.correlation import (
    build_behavior_correlations,
    find_similar_sessions,
    session_similarity,
)
from backend.analysis.features import (
    build_behavior_signature,
    extract_session_features,
)
from backend.analysis.profiling import build_source_profile
from backend.analysis.session_analyzer import analyze_session
from backend.extensions import db
from backend.models import AttackSession, CowrieEvent, SessionAnalysis


def _session(
    session_id="session-1",
    source_ip="203.0.113.10",
    start=None,
    end=None,
):
    session = AttackSession(
        session_id=session_id,
        source_ip=source_ip,
        protocol="ssh",
        username="root",
        start_time=start,
        end_time=end,
        command_count=0,
    )
    db.session.add(session)
    db.session.flush()
    return session


def _event(
    session_id,
    event_id,
    timestamp,
    event_type,
    *,
    command=None,
    source_ip="203.0.113.10",
    username="root",
):
    event = CowrieEvent(
        event_id=event_id,
        session_id=session_id,
        timestamp=timestamp,
        source_ip=source_ip,
        event_type=event_type,
        username=username,
        command=command,
        event_metadata="{}",
    )
    db.session.add(event)
    return event


def _commit():
    db.session.commit()


def test_feature_extraction_uses_ordered_events_and_real_timing(app):
    with app.app_context():
        start = datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
        session = _session(
            start=start.replace(tzinfo=None),
            end=(start + timedelta(seconds=30)).replace(tzinfo=None),
        )
        _event(session.session_id, "f-1", start, "cowrie.login.failed")
        _event(
            session.session_id,
            "f-2",
            start + timedelta(seconds=2),
            "cowrie.login.success",
        )
        _event(
            session.session_id,
            "f-3",
            start + timedelta(seconds=10),
            "cowrie.command.input",
            command="whoami",
        )
        _event(
            session.session_id,
            "f-4",
            start + timedelta(seconds=20),
            "cowrie.command.input",
            command="id",
        )
        _event(
            session.session_id,
            "f-5",
            start + timedelta(seconds=30),
            "cowrie.command.input",
            command="uname -a",
        )
        _commit()

        features = extract_session_features(session)

        assert features["command_count"] == 3
        assert features["unique_command_count"] == 3
        assert features["repeated_command_ratio"] == 0.0
        assert features["session_duration_seconds"] == 30.0
        assert features["mean_time_between_commands_seconds"] == 10.0
        assert features["command_frequency_per_minute"] == 6.0
        assert features["failed_login_count"] == 1
        assert features["successful_login_count"] == 1
        assert features["authentication_result"] == "mixed"
        assert features["discovery_category_count"] == 2
        assert features["command_sequence"] == [
            "whoami",
            "id",
            "uname -a",
        ]
        assert session.duration == 30.0
        assert session.authentication_result == "mixed"


def test_feature_extraction_handles_no_commands_and_zero_duration(app):
    with app.app_context():
        timestamp = datetime(2026, 9, 22, 10, 0)
        session = _session(
            session_id="session-empty",
            start=timestamp,
            end=timestamp,
        )
        _event(
            session.session_id,
            "f-empty",
            timestamp,
            "cowrie.login.failed",
        )
        _commit()

        features = extract_session_features(session)

        assert features["command_count"] == 0
        assert features["unique_command_count"] == 0
        assert features["mean_time_between_commands_seconds"] is None
        assert features["command_frequency_per_minute"] is None
        assert features["repeated_command_ratio"] == 0.0
        assert features["unique_command_ratio"] == 0.0


def test_feature_extraction_handles_missing_timestamps(app):
    with app.app_context():
        session = _session(session_id="session-missing-time")
        _event(
            session.session_id,
            "f-missing-1",
            None,
            "cowrie.command.input",
            command="whoami",
        )
        _event(
            session.session_id,
            "f-missing-2",
            datetime(2026, 9, 22, 10, 0),
            "cowrie.command.input",
            command="id",
        )
        _commit()

        features = extract_session_features(session)
        assert features["command_count"] == 2
        assert features["has_missing_event_timestamps"] is True
        assert features["mean_time_between_commands_seconds"] is None


def test_behavior_classification_reconnaissance(app):
    features = {
        "failed_login_count": 1,
        "successful_login_count": 1,
        "authentication_attempt_count": 2,
        "authentication_failure_ratio": 0.5,
        "transfer_command_count": 0,
        "transfer_event_count": 0,
        "download_event_count": 0,
        "upload_event_count": 0,
        "discovery_command_count": 3,
        "discovery_category_count": 3,
        "discovery_categories": ["filesystem", "identity", "system"],
        "persistence_command_count": 0,
        "command_count": 3,
        "unique_command_ratio": 1.0,
        "session_duration_seconds": 50,
        "mean_time_between_commands_seconds": 10,
    }

    result = classify_behavior(features)
    assert result["label"] == "Reconnaissance / Discovery"
    assert result["confidence"] > 0
    assert result["evidence"]


def test_behavior_classification_requires_observable_transfer_evidence():
    result = classify_behavior({
        "failed_login_count": 0,
        "authentication_attempt_count": 1,
        "authentication_failure_ratio": 0.0,
        "transfer_command_count": 1,
        "transfer_event_count": 0,
        "download_event_count": 0,
        "upload_event_count": 0,
        "discovery_command_count": 0,
        "discovery_category_count": 0,
        "discovery_categories": [],
        "persistence_command_count": 0,
        "command_count": 1,
        "unique_command_ratio": 1.0,
        "session_duration_seconds": 2,
        "mean_time_between_commands_seconds": None,
    })
    assert result["label"] == "Insufficient Evidence"


def test_behavior_classification_brute_force():
    result = classify_behavior({
        "failed_login_count": 5,
        "authentication_attempt_count": 5,
        "authentication_failure_ratio": 1.0,
        "transfer_command_count": 0,
        "transfer_event_count": 0,
        "download_event_count": 0,
        "upload_event_count": 0,
        "discovery_command_count": 0,
        "discovery_category_count": 0,
        "discovery_categories": [],
        "persistence_command_count": 0,
        "command_count": 0,
        "unique_command_ratio": 0.0,
        "session_duration_seconds": 3,
        "mean_time_between_commands_seconds": None,
    })
    assert result["label"] == "Brute Force"
    assert result["confidence"] > 0


def test_behavior_classification_payload_activity():
    result = classify_behavior({
        "failed_login_count": 0,
        "authentication_attempt_count": 1,
        "authentication_failure_ratio": 0.0,
        "transfer_command_count": 1,
        "transfer_event_count": 1,
        "download_event_count": 1,
        "upload_event_count": 0,
        "discovery_command_count": 0,
        "discovery_category_count": 0,
        "discovery_categories": [],
        "persistence_command_count": 0,
        "command_count": 1,
        "unique_command_ratio": 1.0,
        "session_duration_seconds": 12,
        "mean_time_between_commands_seconds": None,
    })
    assert result["label"] == "Payload Activity"


def test_automation_profiles_cover_expected_paths():
    assert profile_automation({
        "command_count": 4,
        "mean_time_between_commands_seconds": 0.8,
        "repeated_command_ratio": 0.75,
        "unique_command_ratio": 0.25,
        "session_duration_seconds": 4,
    })["profile"] == "likely automated"

    assert profile_automation({
        "command_count": 4,
        "mean_time_between_commands_seconds": 8,
        "repeated_command_ratio": 0,
        "unique_command_ratio": 1,
        "session_duration_seconds": 60,
    })["profile"] == "likely interactive"

    assert profile_automation({
        "command_count": 1,
        "mean_time_between_commands_seconds": None,
        "repeated_command_ratio": 0,
        "unique_command_ratio": 1,
        "session_duration_seconds": 10,
    })["profile"] == "insufficient data"


def test_behavior_signature_is_deterministic():
    features = {
        "protocol": "ssh",
        "normalized_command_sequence": ["whoami", "id"],
        "authentication_sequence": ["failed", "success"],
        "download_event_count": 0,
        "upload_event_count": 0,
    }
    assert build_behavior_signature(features) == build_behavior_signature(features)


def test_clustering_requires_enough_sessions():
    assert choose_cluster_count(0) is None
    assert choose_cluster_count(2) is None
    assert choose_cluster_count(3) == 2


def test_clustering_is_reproducible():
    rows = [
        (1, {"failed_login_count": 6, "successful_login_count": 0, "command_count": 0,
             "unique_command_count": 0, "session_duration_seconds": 5,
             "repeated_command_ratio": 0, "transfer_event_count": 0,
             "discovery_command_count": 0, "persistence_command_count": 0}),
        (2, {"failed_login_count": 5, "successful_login_count": 0, "command_count": 1,
             "unique_command_count": 1, "session_duration_seconds": 7,
             "repeated_command_ratio": 0, "transfer_event_count": 0,
             "discovery_command_count": 0, "persistence_command_count": 0}),
        (3, {"failed_login_count": 0, "successful_login_count": 1, "command_count": 6,
             "unique_command_count": 6, "session_duration_seconds": 120,
             "repeated_command_ratio": 0, "transfer_event_count": 1,
             "discovery_command_count": 4, "persistence_command_count": 0}),
        (4, {"failed_login_count": 0, "successful_login_count": 1, "command_count": 5,
             "unique_command_count": 5, "session_duration_seconds": 110,
             "repeated_command_ratio": 0, "transfer_event_count": 1,
             "discovery_command_count": 3, "persistence_command_count": 0}),
    ]
    first = cluster_feature_rows(rows)
    second = cluster_feature_rows(rows)
    assert first == second
    assert set(first) == {1, 2, 3, 4}


def test_session_analyzer_persists_analysis(app):
    with app.app_context():
        start = datetime(2026, 9, 22, 10, 0)
        session = _session(
            session_id="analysis-session",
            start=start,
            end=start + timedelta(seconds=40),
        )
        _event(session.session_id, "a-1", start, "cowrie.login.success")
        _event(
            session.session_id,
            "a-2",
            start + timedelta(seconds=20),
            "cowrie.command.input",
            command="whoami",
        )
        _event(
            session.session_id,
            "a-3",
            start + timedelta(seconds=40),
            "cowrie.command.input",
            command="id",
        )
        _commit()

        result = analyze_session(
            session.session_id,
            enrich_abuseipdb=False,
        )
        stored = SessionAnalysis.query.filter_by(
            session_id=session.session_id
        ).one()

        assert result["behavior_label"] == "Insufficient Evidence"
        assert stored.behavior_signature
        assert stored.behavioral_features["command_sequence"] == [
            "whoami",
            "id",
        ]


def test_recluster_persists_assignments(app):
    with app.app_context():
        for index in range(3):
            start = datetime(2026, 9, 22, 10, index)
            session = _session(
                session_id=f"cluster-{index}",
                source_ip=f"203.0.113.{10 + index}",
                start=start,
                end=start + timedelta(seconds=10 + index),
            )
            _event(
                session.session_id,
                f"c-{index}",
                start,
                "cowrie.command.input",
                command="whoami" if index < 2 else "ls",
            )
        _commit()

        for index in range(3):
            analyze_session(f"cluster-{index}", enrich_abuseipdb=False)

        result = recluster_session_analyses()
        assert result["status"] == "clustered"
        assert result["cluster_count"] is not None
        assert all(
            row.cluster_id is not None
            for row in SessionAnalysis.query.all()
        )


def test_source_profile_aggregates_sessions(app):
    with app.app_context():
        source = "198.51.100.77"
        for index in range(2):
            start = datetime(2026, 9, 22, 11, index)
            session = _session(
                session_id=f"source-{index}",
                source_ip=source,
                start=start,
                end=start + timedelta(seconds=20),
            )
            _event(
                session.session_id,
                f"s-{index}",
                start,
                "cowrie.command.input",
                command="whoami",
                source_ip=source,
            )
        _commit()

        analyze_session("source-0", enrich_abuseipdb=False)
        analyze_session("source-1", enrich_abuseipdb=False)

        profile = build_source_profile(source)
        assert profile["session_count"] == 2
        assert profile["command_count"] == 2
        assert profile["repeated_activity"] is True
        assert profile["primary_behavior"] == "Insufficient Evidence"


def test_correlation_finds_exact_repeated_behavior(app):
    with app.app_context():
        for index, source in enumerate(["198.51.100.1", "198.51.100.2"]):
            start = datetime(2026, 9, 22, 12, index)
            session = _session(
                session_id=f"corr-{index}",
                source_ip=source,
                start=start,
                end=start + timedelta(seconds=10),
            )
            _event(
                session.session_id,
                f"corr-{index}-1",
                start,
                "cowrie.command.input",
                command="whoami",
                source_ip=source,
            )
            _event(
                session.session_id,
                f"corr-{index}-2",
                start + timedelta(seconds=5),
                "cowrie.command.input",
                command="uname -a",
                source_ip=source,
            )
        _commit()

        analyze_session("corr-0", enrich_abuseipdb=False)
        analyze_session("corr-1", enrich_abuseipdb=False)

        correlations = build_behavior_correlations()
        assert correlations["repeated_signatures"]
        assert correlations["repeated_signatures"][0]["cross_source"] is True

        matches = find_similar_sessions("corr-0")
        assert matches[0]["session_id"] == "corr-1"
        assert matches[0]["same_signature"] is True
        assert session_similarity(
            SessionAnalysis.query.filter_by(session_id="corr-0").one(),
            SessionAnalysis.query.filter_by(session_id="corr-1").one(),
        ) == 1.0
