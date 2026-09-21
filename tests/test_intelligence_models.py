from datetime import datetime

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from backend.app import create_app
from backend.config import TestConfig
from backend.extensions import db
from backend.models import (
    Alert,
    AttackSession,
    IPIntelligence,
    MITREMapping,
    RiskScore,
    SessionAnalysis,
)


@pytest.fixture
def app():
    application = create_app(TestConfig)

    with application.app_context():
        db.create_all()
        yield application

        db.session.remove()
        db.drop_all()


@pytest.fixture
def session_record(app):
    with app.app_context():
        session = AttackSession(
            session_id="phase4-session",
            source_ip="198.51.100.10",
            protocol="SSH",
            username="root",
            command_count=4,
        )

        db.session.add(session)
        db.session.commit()

        return session.session_id


def test_sqlite_foreign_keys_are_enabled(app):
    with app.app_context():
        enabled = db.session.execute(
            text("PRAGMA foreign_keys")
        ).scalar()

    assert enabled == 1


def test_phase4_tables_are_created(app):
    with app.app_context():
        table_names = set(
            inspect(db.engine).get_table_names()
        )

    assert {
        "attack_sessions",
        "cowrie_events",
        "session_analyses",
        "ip_intelligence",
        "risk_scores",
        "mitre_mappings",
        "alerts",
    }.issubset(table_names)


def test_phase4_child_records_require_existing_session(app):
    with app.app_context():
        db.session.add(
            RiskScore(
                session_id="does-not-exist",
                score=50,
                severity="Medium",
                scoring_version="v1",
            )
        )

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()


def test_session_analysis_persists_structured_behavior_data(
    app,
    session_record,
):
    with app.app_context():
        analysis = SessionAnalysis(
            session_id=session_record,
            behavior_label="Reconnaissance / Discovery",
            behavior_confidence=0.92,
            behavioral_features={
                "command_count": 4,
                "unique_command_count": 3,
            },
            automation_profile="likely_interactive",
            behavior_signature="whoami|uname|ls|ps",
            cluster_id=2,
            anomaly_score=0.81,
            analyzed_at=datetime(
                2026,
                9,
                21,
                10,
                0,
                0,
            ),
        )

        db.session.add(analysis)
        db.session.commit()

        retrieved = SessionAnalysis.query.filter_by(
            session_id=session_record
        ).one()

        assert (
            retrieved.behavior_label
            == "Reconnaissance / Discovery"
        )

        assert (
            retrieved.behavior_confidence
            == pytest.approx(0.92)
        )

        assert (
            retrieved.behavioral_features[
                "command_count"
            ]
            == 4
        )

        assert retrieved.cluster_id == 2

        assert (
            retrieved.session.session_id
            == session_record
        )


def test_session_analysis_is_one_to_one_with_session(
    app,
    session_record,
):
    with app.app_context():
        db.session.add(
            SessionAnalysis(
                session_id=session_record,
                behavior_label="Reconnaissance / Discovery",
            )
        )

        db.session.commit()

        db.session.add(
            SessionAnalysis(
                session_id=session_record,
                behavior_label="Payload Activity",
            )
        )

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()


def test_ip_intelligence_is_cached_per_provider_and_ip(app):
    with app.app_context():
        db.session.add(
            IPIntelligence(
                ip_address="198.51.100.10",
                provider="abuseipdb",
                reputation=85.0,
                abuse_confidence=90,
                report_count=14,
                country="IN",
                asn="AS64500",
                isp="Example ISP",
                category_data={
                    "18": "Brute Force",
                },
                provider_metadata={
                    "source": "test-fixture",
                },
            )
        )

        db.session.commit()

        retrieved = IPIntelligence.query.filter_by(
            ip_address="198.51.100.10",
            provider="abuseipdb",
        ).one()

        assert retrieved.abuse_confidence == 90
        assert retrieved.report_count == 14

        assert (
            retrieved.category_data["18"]
            == "Brute Force"
        )

        assert (
            retrieved.provider_metadata["source"]
            == "test-fixture"
        )


def test_ip_intelligence_allows_same_ip_for_different_providers(
    app,
):
    with app.app_context():
        db.session.add_all(
            [
                IPIntelligence(
                    ip_address="198.51.100.11",
                    provider="abuseipdb",
                ),
                IPIntelligence(
                    ip_address="198.51.100.11",
                    provider="virustotal",
                ),
            ]
        )

        db.session.commit()

        assert (
            IPIntelligence.query.filter_by(
                ip_address="198.51.100.11"
            ).count()
            == 2
        )


def test_ip_intelligence_rejects_duplicate_provider_record(
    app,
):
    with app.app_context():
        db.session.add(
            IPIntelligence(
                ip_address="198.51.100.12",
                provider="abuseipdb",
            )
        )

        db.session.commit()

        db.session.add(
            IPIntelligence(
                ip_address="198.51.100.12",
                provider="abuseipdb",
            )
        )

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()


def test_risk_score_persists_explainable_factors(
    app,
    session_record,
):
    with app.app_context():
        db.session.add(
            RiskScore(
                session_id=session_record,
                score=86,
                severity="Critical",
                contributing_factors=[
                    "repeated authentication failures",
                    "reconnaissance commands",
                ],
                scoring_version="v1",
            )
        )

        db.session.commit()

        retrieved = RiskScore.query.filter_by(
            session_id=session_record
        ).one()

        assert retrieved.score == 86
        assert retrieved.severity == "Critical"

        assert (
            retrieved.contributing_factors[0]
            == "repeated authentication failures"
        )

        assert retrieved.scoring_version == "v1"


def test_risk_score_rejects_values_outside_zero_to_one_hundred(
    app,
    session_record,
):
    with app.app_context():
        db.session.add(
            RiskScore(
                session_id=session_record,
                score=101,
                severity="Invalid",
                scoring_version="v1",
            )
        )

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()


def test_mitre_mapping_preserves_command_evidence(
    app,
    session_record,
):
    with app.app_context():
        db.session.add(
            MITREMapping(
                session_id=session_record,
                event_id="cowrie-event-fingerprint",
                command="whoami",
                technique_id="T1033",
                technique_name="System Owner/User Discovery",
                tactic="Discovery",
                evidence="The session executed whoami.",
                confidence=0.98,
            )
        )

        db.session.commit()

        retrieved = MITREMapping.query.filter_by(
            session_id=session_record
        ).one()

        assert (
            retrieved.event_id
            == "cowrie-event-fingerprint"
        )

        assert retrieved.technique_id == "T1033"
        assert retrieved.tactic == "Discovery"

        assert (
            retrieved.evidence
            == "The session executed whoami."
        )

        assert (
            retrieved.session.session_id
            == session_record
        )


def test_alert_persists_acknowledgement_state(
    app,
    session_record,
):
    with app.app_context():
        db.session.add(
            Alert(
                session_id=session_record,
                risk_score=88,
                severity="Critical",
                title="High-risk session detected",
                message="Risk threshold was crossed.",
            )
        )

        db.session.commit()

        retrieved = Alert.query.filter_by(
            session_id=session_record
        ).one()

        assert retrieved.risk_score == 88
        assert retrieved.acknowledged is False
        assert retrieved.acknowledged_at is None


def test_deleting_session_cascades_phase4_records(
    app,
    session_record,
):
    with app.app_context():
        db.session.add_all(
            [
                SessionAnalysis(
                    session_id=session_record,
                    behavior_label="Reconnaissance / Discovery",
                ),
                RiskScore(
                    session_id=session_record,
                    score=64,
                    severity="Medium",
                    scoring_version="v1",
                ),
                MITREMapping(
                    session_id=session_record,
                    technique_id="T1033",
                    technique_name=(
                        "System Owner/User Discovery"
                    ),
                    tactic="Discovery",
                    evidence=(
                        "The session executed whoami."
                    ),
                ),
                Alert(
                    session_id=session_record,
                    risk_score=64,
                    severity="Medium",
                    title="Medium-risk session",
                    message="Stored for investigation.",
                ),
            ]
        )

        db.session.commit()

        session = AttackSession.query.filter_by(
            session_id=session_record
        ).one()

        db.session.delete(session)
        db.session.commit()

        assert SessionAnalysis.query.count() == 0
        assert RiskScore.query.count() == 0
        assert MITREMapping.query.count() == 0
        assert Alert.query.count() == 0