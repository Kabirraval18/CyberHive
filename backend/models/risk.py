from datetime import datetime, timezone

from backend.extensions import db


class RiskScore(db.Model):
    """
    Persist an explainable risk calculation for
    an attack session.
    """

    __tablename__ = "risk_scores"

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

    score = db.Column(
        db.Integer,
        nullable=False,
        index=True,
    )

    severity = db.Column(
        db.String(32),
        nullable=False,
        index=True,
    )

    contributing_factors = db.Column(
        db.JSON,
        nullable=True,
    )

    scoring_version = db.Column(
        db.String(32),
        nullable=False,
    )

    calculated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        db.CheckConstraint(
            "score >= 0 AND score <= 100",
            name="ck_risk_score_range",
        ),
    )

    session = db.relationship(
        "AttackSession",
        back_populates="risk_scores",
    )