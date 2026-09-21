from datetime import datetime, timezone

from backend.extensions import db


class IPIntelligence(db.Model):
    """
    Cache normalized external threat-intelligence information
    for each IP/provider pair.
    """

    __tablename__ = "ip_intelligence"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False,
        index=True,
    )

    provider = db.Column(
        db.String(32),
        nullable=False,
        index=True,
    )

    reputation = db.Column(
        db.Float,
        nullable=True,
    )

    abuse_confidence = db.Column(
        db.Integer,
        nullable=True,
    )

    report_count = db.Column(
        db.Integer,
        nullable=True,
    )

    country = db.Column(
        db.String(64),
        nullable=True,
    )

    asn = db.Column(
        db.String(64),
        nullable=True,
    )

    isp = db.Column(
        db.String(256),
        nullable=True,
    )

    category_data = db.Column(
        db.JSON,
        nullable=True,
    )

    provider_metadata = db.Column(
        db.JSON,
        nullable=True,
    )

    retrieved_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    __table_args__ = (
        db.UniqueConstraint(
            "ip_address",
            "provider",
            name="uq_ip_intelligence_ip_provider",
        ),
        db.CheckConstraint(
            "abuse_confidence IS NULL OR "
            "(abuse_confidence >= 0 AND abuse_confidence <= 100)",
            name="ck_ip_intelligence_abuse_confidence_range",
        ),
        db.CheckConstraint(
            "report_count IS NULL OR report_count >= 0",
            name="ck_ip_intelligence_report_count_non_negative",
        ),
    )