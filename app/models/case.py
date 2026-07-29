from app import db
from datetime import datetime


class Case(db.Model):

    __tablename__ = "cases"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    case_number = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    case_title = db.Column(
        db.String(200),
        nullable=False
    )

    investigator_name = db.Column(
        db.String(100)
    )

    investigation_date = db.Column(
        db.Date,
        default=datetime.utcnow
    )

    case_summary = db.Column(
        db.Text
    )

    status = db.Column(
        db.String(30),
        default="Open"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )