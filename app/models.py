from datetime import datetime
from app import db


class Evidence(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(200),
        nullable=False
    )

    file_path = db.Column(
        db.String(300)
    )

    md5_hash = db.Column(
        db.String(100)
    )

    sha1_hash = db.Column(
        db.String(100)
    )

    sha256_hash = db.Column(
        db.String(100)
    )

    risk_level = db.Column(
        db.String(50)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )