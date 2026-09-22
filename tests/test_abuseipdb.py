from datetime import datetime, timedelta, timezone

import pytest

from backend.intelligence.abuseipdb import lookup_abuseipdb, validate_public_ip
from backend.models import IPIntelligence


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def _enable_provider(app):
    app.config["ABUSEIPDB_ENABLED"] = True
    app.config["ABUSEIPDB_API_KEY"] = "test-key"
    app.config["RUN_ABUSEIPDB_ON_INGEST"] = False
    app.config["INTEL_CACHE_SECONDS"] = 3600
    app.config["ABUSEIPDB_MAX_AGE_DAYS"] = 90


def test_invalid_ip_is_rejected(app):
    with app.app_context():
        result = lookup_abuseipdb("not-an-ip")
        assert result["success"] is False
        assert result["status"] == "invalid_ip"


def test_private_ip_is_not_queried(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)
        called = False

        def fail_get(*args, **kwargs):
            nonlocal called
            called = True
            raise AssertionError("private address must not be queried")

        monkeypatch.setattr("backend.intelligence.abuseipdb.requests.get", fail_get)
        result = lookup_abuseipdb("127.0.0.1")
        assert result["status"] == "non_public_ip"
        assert called is False


def test_successful_lookup_is_normalized_and_cached(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)
        calls = []

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse(
                200,
                {
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 42,
                        "totalReports": 17,
                        "countryCode": "US",
                        "countryName": "United States",
                        "isp": "Example ISP",
                        "asn": 15169,
                        "usageType": "Data Center/Web Hosting/Transit",
                        "domain": "example.net",
                        "isWhitelisted": False,
                        "isPublic": True,
                    }
                },
            )

        monkeypatch.setattr("backend.intelligence.abuseipdb.requests.get", fake_get)

        first = lookup_abuseipdb("8.8.8.8")
        second = lookup_abuseipdb("8.8.8.8")

        assert first["success"] is True
        assert first["status"] == "success"
        assert first["data"]["abuse_confidence"] == 42
        assert first["data"]["report_count"] == 17
        assert first["data"]["country"] == "United States"
        assert first["data"]["asn"] == "15169"
        assert second["status"] == "cached"
        assert len(calls) == 1
        assert IPIntelligence.query.count() == 1


def test_expired_cache_is_refreshed(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = IPIntelligence(
            ip_address="8.8.4.4",
            provider="abuseipdb",
            abuse_confidence=1,
            report_count=1,
            retrieved_at=now - timedelta(days=2),
            expires_at=now - timedelta(days=1),
        )
        from backend.extensions import db
        db.session.add(record)
        db.session.commit()

        monkeypatch.setattr(
            "backend.intelligence.abuseipdb.requests.get",
            lambda *args, **kwargs: FakeResponse(
                200,
                {"data": {
                    "ipAddress": "8.8.4.4",
                    "abuseConfidenceScore": 10,
                    "totalReports": 2,
                    "countryCode": "US",
                    "countryName": "United States",
                }},
            ),
        )

        result = lookup_abuseipdb("8.8.4.4")
        assert result["status"] == "success"
        assert result["data"]["abuse_confidence"] == 10
        assert IPIntelligence.query.count() == 1


def test_timeout_is_isolated(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)

        import requests

        def fake_get(*args, **kwargs):
            raise requests.Timeout("simulated")

        monkeypatch.setattr("backend.intelligence.abuseipdb.requests.get", fake_get)
        result = lookup_abuseipdb("1.1.1.1")
        assert result["success"] is False
        assert result["status"] == "timeout"
        assert IPIntelligence.query.count() == 0


def test_rate_limit_is_handled(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)
        monkeypatch.setattr(
            "backend.intelligence.abuseipdb.requests.get",
            lambda *args, **kwargs: FakeResponse(429, {"errors": []}),
        )
        result = lookup_abuseipdb("1.1.1.1")
        assert result["status"] == "rate_limited"


def test_authentication_failure_is_handled(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)
        monkeypatch.setattr(
            "backend.intelligence.abuseipdb.requests.get",
            lambda *args, **kwargs: FakeResponse(401, {"errors": []}),
        )
        result = lookup_abuseipdb("1.1.1.1")
        assert result["status"] == "authentication_error"


def test_malformed_response_is_handled(app, monkeypatch):
    with app.app_context():
        _enable_provider(app)
        monkeypatch.setattr(
            "backend.intelligence.abuseipdb.requests.get",
            lambda *args, **kwargs: FakeResponse(200, {"unexpected": True}),
        )
        result = lookup_abuseipdb("1.1.1.1")
        assert result["status"] == "malformed_response"


def test_disabled_and_unconfigured_provider_do_not_call_network(app, monkeypatch):
    with app.app_context():
        app.config["ABUSEIPDB_ENABLED"] = False
        app.config["ABUSEIPDB_API_KEY"] = ""
        monkeypatch.setattr(
            "backend.intelligence.abuseipdb.requests.get",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("network call should not occur")
            ),
        )
        disabled = lookup_abuseipdb("8.8.8.8")
        assert disabled["status"] == "disabled"

        app.config["ABUSEIPDB_ENABLED"] = True
        unconfigured = lookup_abuseipdb("8.8.8.8")
        assert unconfigured["status"] == "not_configured"


def test_public_ip_validation_accepts_global_address():
    assert str(validate_public_ip("8.8.8.8")) == "8.8.8.8"
