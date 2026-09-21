from datetime import datetime, timezone

from backend.extensions import db


class MITREMapping(db.Model):
    """
    Persist evidence-backed MITRE ATT&CK mappings.
    """

    __tablename__ = "mitre_mappings"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    session_id = db.Column(
        db.String(128),
        db.ForeignKey(
            "attack_sessions.session_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # Stores the deterministic Cowrie event fingerprint
    # when the mapping is associated with a specific event.
    event_id = db.Column(
        db.String(128),
        nullable=True,
        index=True,
    )

    command = db.Column(
        db.Text,
        nullable=True,
    )

    technique_id = db.Column(
        db.String(32),
        nullable=False,
        index=True,
    )

    technique_name = db.Column(
        db.String(256),
        nullable=False,
    )

    tactic = db.Column(
        db.String(128),
        nullable=True,
        index=True,
    )

    evidence = db.Column(
        db.Text,
        nullable=False,
    )

    confidence = db.Column(
        db.Float,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        db.CheckConstraint(
            "confidence IS NULL OR "
            "(confidence >= 0 AND confidence <= 1)",
            name="ck_mitre_mapping_confidence_range",
        ),
    )

    session = db.relationship(
        "AttackSession",
        back_populates="mitre_mappings",
    )