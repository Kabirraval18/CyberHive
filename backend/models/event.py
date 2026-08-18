from datetime import datetime, timezone

from backend.extensions import db


class CowrieEvent(db.Model):
    __tablename__ = "cowrie_events"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(128), nullable=True, index=True)
    session_id = db.Column(db.String(128), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=True, index=True)
    source_ip = db.Column(db.String(45), nullable=True)
    event_type = db.Column(db.String(128), nullable=False, index=True)
    username = db.Column(db.String(256), nullable=True)
    command = db.Column(db.Text, nullable=True)
    event_metadata = db.Column("metadata", db.Text, nullable=True)
    created_at = db.Column(
    db.DateTime,
    nullable=False,
    default=lambda: datetime.now(timezone.utc),
)

    attack_session = db.relationship(
        "AttackSession",
        back_populates="events",
        primaryjoin="AttackSession.session_id == foreign(CowrieEvent.session_id)",
        viewonly=True,
    )
