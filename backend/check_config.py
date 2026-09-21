from backend.config import Config


def mask_secret(value: str) -> str:
    if not value:
        return "<not configured>"

    if len(value) <= 8:
        return "*" * len(value)

    return (
        value[:4]
        + "*" * (len(value) - 8)
        + value[-4:]
    )


def main():
    print("=" * 60)
    print("CyberHive Configuration Check")
    print("=" * 60)

    print("\nFlask")
    print("-" * 60)

    print("DEBUG:", Config.DEBUG)
    print(
        "SECRET_KEY:",
        mask_secret(Config.SECRET_KEY),
    )

    print("\nDatabase")
    print("-" * 60)

    print(
        "DATABASE_URL:",
        Config.SQLALCHEMY_DATABASE_URI,
    )

    print("\nCowrie")
    print("-" * 60)

    print(
        "COWRIE_LOG_PATH:",
        Config.COWRIE_LOG_PATH or "<not configured>",
    )

    print(
        "RUN_ANALYSIS_ON_INGEST:",
        Config.RUN_ANALYSIS_ON_INGEST,
    )

    print(
        "RUN_RECLUSTER_ON_INGEST:",
        Config.RUN_RECLUSTER_ON_INGEST,
    )

    print("\nThreat Intelligence")
    print("-" * 60)

    print(
        "AbuseIPDB enabled:",
        Config.ABUSEIPDB_ENABLED,
    )

    print(
        "AbuseIPDB key:",
        mask_secret(Config.ABUSEIPDB_API_KEY),
    )

    print(
        "VirusTotal enabled:",
        Config.VIRUSTOTAL_ENABLED,
    )

    print(
        "VirusTotal key:",
        mask_secret(Config.VIRUSTOTAL_API_KEY),
    )

    print(
        "Cache:",
        Config.INTEL_CACHE_SECONDS,
        "seconds",
    )

    print("\nRisk")
    print("-" * 60)

    print(
        "Risk alert threshold:",
        Config.RISK_ALERT_THRESHOLD,
    )

    print("\nEmail")
    print("-" * 60)

    print(
        "Email alerts enabled:",
        Config.EMAIL_ALERTS_ENABLED,
    )

    print(
        "SMTP host:",
        Config.SMTP_HOST or "<not configured>",
    )

    print(
        "SMTP port:",
        Config.SMTP_PORT,
    )

    print(
        "Recipients:",
        Config.ALERT_EMAIL_RECIPIENTS
        or "<not configured>",
    )

    print("\nFrontend")
    print("-" * 60)

    print(
        "Frontend origin:",
        Config.FRONTEND_ORIGIN,
    )

    print("\n" + "=" * 60)
    print("Configuration check complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()