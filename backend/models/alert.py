from datetime import datetime, timezone

from backend.extensions import db


class Alert(db.Model):
    """
    Persist dashboard alerts generated from
    analyzed session evidence.
    """

    __tablename__ = "alerts"

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

    risk_score = db.Column(
        db.Integer,
        nullable=False,
        index=True,
    )

    severity = db.Column(
        db.String(32),
        nullable=False,
        index=True,
    )

    title = db.Column(
        db.String(256),
        nullable=False,
    )

    message = db.Column(
        db.Text,
        nullable=False,
    )

    acknowledged = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    acknowledged_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    __table_args__ = (
        db.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_alert_risk_score_range",
        ),
    )

    session = db.relationship(
        "AttackSession",
        back_populates="alerts",
    )