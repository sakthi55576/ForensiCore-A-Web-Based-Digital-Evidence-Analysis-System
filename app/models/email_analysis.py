from datetime import datetime

from app import db


class EmailAnalysis(db.Model):

    __tablename__ = "email_analysis"

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.id"),
        nullable=False
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("cases.id"),
        nullable=False
    )

    evidence = db.relationship(
        "Evidence",
        backref=db.backref(
            "email_analysis",
            lazy=True
        )
    )

    file_hash = db.Column(
        db.String(64),
        nullable=True
    )

    hash_algorithm = db.Column(
        db.String(20),
        default="SHA-256"
    )

    analysis_data = db.Column(
        db.Text,
        nullable=True
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    risk_level = db.Column(
        db.String(20),
        default="LOW"
    )

    findings = db.Column(
        db.Text,
        nullable=True
    )

    analyzed_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )