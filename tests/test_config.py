from backend.config import Config, TestConfig


def test_secret_key_exists():
    assert Config.SECRET_KEY


def test_database_uri_exists():
    assert Config.SQLALCHEMY_DATABASE_URI


def test_test_config_uses_memory_database():
    assert (
        TestConfig.SQLALCHEMY_DATABASE_URI
        == "sqlite:///:memory:"
    )


def test_risk_threshold_is_valid():
    assert 0 <= Config.RISK_ALERT_THRESHOLD <= 100


def test_frontend_origin_exists():
    assert Config.FRONTEND_ORIGIN


def test_smtp_port_is_integer():
    assert isinstance(Config.SMTP_PORT, int)

def test_default_risk_threshold_matches_project_configuration():
    assert Config.RISK_ALERT_THRESHOLD == 40


def test_session_lifetime_is_positive():
    assert Config.SESSION_LIFETIME_SECONDS >= 60


def test_dashboard_refresh_interval_is_safe():
    assert Config.DASHBOARD_REFRESH_INTERVAL_MS >= 1000
