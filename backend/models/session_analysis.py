from datetime import datetime, timezone

from backend.extensions import db


class SessionAnalysis(db.Model):
    """
    Persist the latest behavioral analysis associated
    with an attack session.
    """

    __tablename__ = "session_analyses"

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
        unique=True,
        index=True,
    )

    behavior_label = db.Column(
        db.String(128),
        nullable=True,
        index=True,
    )

    behavior_confidence = db.Column(
        db.Float,
        nullable=True,
    )

    behavioral_features = db.Column(
        db.JSON,
        nullable=True,
    )

    automation_profile = db.Column(
        db.String(64),
        nullable=True,
    )

    behavior_signature = db.Column(
        db.String(128),
        nullable=True,
        index=True,
    )

    cluster_id = db.Column(
        db.Integer,
        nullable=True,
        index=True,
    )

    anomaly_score = db.Column(
        db.Float,
        nullable=True,
    )

    analyzed_at = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.CheckConstraint(
            "behavior_confidence IS NULL OR "
            "(behavior_confidence >= 0 AND behavior_confidence <= 1)",
            name="ck_session_analysis_confidence_range",
        ),
    )

    session = db.relationship(
        "AttackSession",
        back_populates="analysis",
        uselist=False,
    )