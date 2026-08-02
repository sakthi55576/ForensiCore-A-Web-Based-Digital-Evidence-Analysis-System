from app import db
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
        db.Text
    )


    risk_level = db.Column(
        db.String(50)
    )


    observations = db.Column(
        db.Text
    )


    analyzed_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )