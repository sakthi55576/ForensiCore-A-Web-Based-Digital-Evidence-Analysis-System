from app import db
from datetime import datetime


class Evidence(db.Model):

    __tablename__ = "evidence"

    # ==========================================
    # EVIDENCE ID
    # ==========================================

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )


    # ==========================================
    # CASE RELATIONSHIP
    # ==========================================

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("cases.id"),
        nullable=False
    )


    # ==========================================
    # CASE OBJECT RELATIONSHIP
    # ==========================================

    case = db.relationship(
        "Case",
        backref=db.backref(
            "evidence",
            lazy=True
        )
    )


    # ==========================================
    # ORIGINAL FILE NAME
    # ==========================================

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )


    # ==========================================
    # STORED FILE NAME
    # ==========================================

    stored_filename = db.Column(
        db.String(255),
        nullable=False
    )


    # ==========================================
    # FILE TYPE
    # ==========================================

    file_type = db.Column(
        db.String(50),
        nullable=True
    )


    # ==========================================
    # FILE SIZE
    # ==========================================

    file_size = db.Column(
        db.BigInteger,
        nullable=True
    )


    # ==========================================
    # UPLOAD TIME
    # ==========================================

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


    # ==========================================
    # EVIDENCE STATUS
    # ==========================================

    status = db.Column(
        db.String(30),
        default="Uploaded"
    )