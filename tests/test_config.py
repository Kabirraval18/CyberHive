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