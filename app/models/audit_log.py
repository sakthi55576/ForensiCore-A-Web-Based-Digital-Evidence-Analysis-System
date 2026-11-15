from datetime import datetime

from app import db


class AuditLog(db.Model):
    """
    Append-only chain-of-custody log (who / when / what / from where).
    """

    __tablename__ = "audit_logs"

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        nullable=True
    )

    user_name = db.Column(
        db.String(100),
        nullable=True
    )

    case_id = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    evidence_id = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    action = db.Column(
        db.String(40),
        nullable=False
    )

    details = db.Column(
        db.Text,
        nullable=True
    )

    ip_address = db.Column(
        db.String(64),
        nullable=True
    )
