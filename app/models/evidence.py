from app import db
from datetime import datetime


class Evidence(db.Model):

    __tablename__ = "evidence"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    case_id = db.Column(
        db.Integer,
        nullable=False
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        nullable=False
    )

    file_type = db.Column(
        db.String(50)
    )

    file_size = db.Column(
        db.BigInteger
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    status = db.Column(
        db.String(30),
        default="Uploaded"
    )