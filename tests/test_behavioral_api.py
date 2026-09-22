from datetime import datetime

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent, SessionAnalysis
from backend.analysis.session_analyzer import analyze_session


def _session_with_command(session_id, source_ip, command):
    start = datetime(2026, 9, 22, 10, 0)
    session = AttackSession(
        session_id=session_id,
        source_ip=source_ip,
        protocol="ssh",
        username="root",
        start_time=start,
        end_time=datetime(2026, 9, 22, 10, 1),
        command_count=1,
    )
    db.session.add(session)
    db.session.flush()
    db.session.add(
        CowrieEvent(
            event_id=f"{session_id}-event",
            session_id=session_id,
            timestamp=start,
            source_ip=source_ip,
            event_type="cowrie.command.input",
            username="root",
            command=command,
            event_metadata="{}",
        )
    )
    db.session.commit()
    return session


def test_behavior_summary_endpoint(app, client):
    with app.app_context():
        session = _session_with_command(
            "api-behavior-1",
            "198.51.100.80",
            "whoami",
        )
        analyze_session(session.session_id, enrich_abuseipdb=False)

        response = client.get("/api/behavior/summary")
        payload = response.get_json()

        assert response.status_code == 200
        assert payload["success"] is True
        assert payload["analyzed_sessions"] == 1
        assert "behavior_distribution" in payload


def test_session_analysis_endpoint(app, client):
    with app.app_context():
        session = _session_with_command(
            "api-analysis-1",
            "198.51.100.81",
            "id",
        )
        analyze_session(session.session_id, enrich_abuseipdb=False)

    response = client.get(
        "/api/sessions/by-session-id/api-analysis-1/analysis"
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["success"] is True
    assert payload["analysis"]["session_id"] == "api-analysis-1"
    assert payload["analysis"]["behavior_signature"]


def test_session_analysis_endpoint_returns_404(app, client):
    response = client.get(
        "/api/sessions/by-session-id/does-not-exist/analysis"
    )
    assert response.status_code == 404


def test_correlations_endpoint_validates_threshold(app, client):
    response = client.get("/api/behavior/correlations?threshold=2")
    payload = response.get_json()
    assert response.status_code == 400
    assert payload["success"] is False


def test_threat_intelligence_status_does_not_expose_keys(app, client):
    with app.app_context():
        app.config["ABUSEIPDB_API_KEY"] = "super-secret-value"
        app.config["VIRUSTOTAL_API_KEY"] = "another-secret"

    response = client.get("/api/threat-intelligence/status")
    payload = response.get_json()
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert payload["providers"]["abuseipdb"]["configured"] is True
    assert payload["providers"]["virustotal"]["configured"] is True
    assert "super-secret-value" not in body
    assert "another-secret" not in body


def test_abuseipdb_endpoint_handles_non_public_ip(app, client):
    with app.app_context():
        app.config["ABUSEIPDB_ENABLED"] = True
        app.config["ABUSEIPDB_API_KEY"] = "test-key"

    response = client.get(
        "/api/threat-intelligence/abuseipdb?ip=127.0.0.1"
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["success"] is False
    assert payload["status"] == "non_public_ip"
