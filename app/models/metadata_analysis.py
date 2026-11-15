from app import db
from app.models._types import big_text
from datetime import datetime


class MetadataAnalysis(db.Model):

    __tablename__ = "metadata_analysis"


    id = db.Column(
        db.Integer,
        primary_key=True
    )


    evidence_id = db.Column(
        db.Integer,
        nullable=False
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


    metadata_data = db.Column(
        big_text()
    )


    risk_level = db.Column(
        db.String(50)
    )


    risk_score = db.Column(
        db.Integer,
        default=0
    )


    observations = db.Column(
        big_text()
    )


    analyzed_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )