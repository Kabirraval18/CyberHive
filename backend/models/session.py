from datetime import datetime, timezone

from backend.extensions import db


class AttackSession(db.Model):
    __tablename__ = "attack_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(128), nullable=False, unique=True, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    protocol = db.Column(db.String(32), nullable=False)
    username = db.Column(db.String(256), nullable=True)
    authentication_result = db.Column(db.String(64), nullable=True)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)
    command_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(
    db.DateTime,
    nullable=False,
    default=lambda: datetime.now(timezone.utc),
)

    events = db.relationship(
        "CowrieEvent",
        back_populates="attack_session",
        primaryjoin="AttackSession.session_id == foreign(CowrieEvent.session_id)",
        lazy="dynamic",
    )
