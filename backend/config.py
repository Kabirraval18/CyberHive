import os
from pathlib import Path

from dotenv import load_dotenv


# ------------------------------------------------------------
# Project paths
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    value = value.strip().lower()

    if value in {"true", "1", "yes", "y", "on"}:
        return True

    if value in {"false", "0", "no", "n", "off"}:
        return False

    return default


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return int(value.strip())
    except ValueError:
        return default


# ------------------------------------------------------------
# Application configuration
# ------------------------------------------------------------

class Config:

    # Flask
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "development-only-change-me",
    )

    DEBUG = _get_bool(
        "FLASK_DEBUG",
        False,
    )

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///data/cyberhive.db",
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --------------------------------------------------------
    # Cowrie
    # --------------------------------------------------------

    COWRIE_LOG_PATH = os.getenv(
        "COWRIE_LOG_PATH",
        "",
    ).strip()

    RUN_ANALYSIS_ON_INGEST = _get_bool(
        "RUN_ANALYSIS_ON_INGEST",
        True,
    )

    RUN_RECLUSTER_ON_INGEST = _get_bool(
        "RUN_RECLUSTER_ON_INGEST",
        True,
    )

    # --------------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------------

    ABUSEIPDB_API_KEY = os.getenv(
        "ABUSEIPDB_API_KEY",
        "",
    ).strip()

    VIRUSTOTAL_API_KEY = os.getenv(
        "VIRUSTOTAL_API_KEY",
        "",
    ).strip()

    ABUSEIPDB_ENABLED = _get_bool(
        "ABUSEIPDB_ENABLED",
        True,
    )

    VIRUSTOTAL_ENABLED = _get_bool(
        "VIRUSTOTAL_ENABLED",
        True,
    )

    INTEL_CACHE_SECONDS = _get_int(
        "INTEL_CACHE_SECONDS",
        86400,
    )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    RISK_ALERT_THRESHOLD = _get_int(
        "RISK_ALERT_THRESHOLD",
        80,
    )

    RISK_ALERT_THRESHOLD = max(
        0,
        min(RISK_ALERT_THRESHOLD, 100),
    )

    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    EMAIL_ALERTS_ENABLED = _get_bool(
        "EMAIL_ALERTS_ENABLED",
        False,
    )

    SMTP_HOST = os.getenv(
        "SMTP_HOST",
        "",
    ).strip()

    SMTP_PORT = _get_int(
        "SMTP_PORT",
        587,
    )

    SMTP_USERNAME = os.getenv(
        "SMTP_USERNAME",
        "",
    ).strip()

    SMTP_PASSWORD = os.getenv(
        "SMTP_PASSWORD",
        "",
    )

    SMTP_FROM = os.getenv(
        "SMTP_FROM",
        "",
    ).strip()

    ALERT_EMAIL_RECIPIENTS = [
        email.strip()
        for email in os.getenv(
            "ALERT_EMAIL_RECIPIENTS",
            "",
        ).split(",")
        if email.strip()
    ]

    # --------------------------------------------------------
    # Frontend
    # --------------------------------------------------------

    FRONTEND_ORIGIN = os.getenv(
        "FRONTEND_ORIGIN",
        "http://localhost:5173",
    ).strip()

    # --------------------------------------------------------
    # Logging
    # --------------------------------------------------------

    LOG_LEVEL = os.getenv(
        "LOG_LEVEL",
        "INFO",
    ).strip().upper()


# ------------------------------------------------------------
# Test configuration
# ------------------------------------------------------------

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"