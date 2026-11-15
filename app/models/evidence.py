from datetime import datetime

from app import db


class Evidence(db.Model):

    __tablename__ = "evidence"

    # ==========================================
    # IDENTITY
    # ==========================================

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("cases.id"),
        nullable=False
    )

    case = db.relationship(
        "Case",
        backref=db.backref(
            "evidence",
            lazy=True
        )
    )

    # ==========================================
    # FILE INFORMATION
    # ==========================================

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        nullable=False
    )

    # MIME type derived from the file CONTENT
    file_type = db.Column(
        db.String(80),
        nullable=True
    )

    file_size = db.Column(
        db.BigInteger,
        nullable=True
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    uploaded_by = db.Column(
        db.Integer,
        nullable=True
    )

    status = db.Column(
        db.String(30),
        default="Uploaded"
    )

    # ==========================================
    # CONTENT-BASED TYPE DETECTION
    #
    # image | email | browser_history | sqlite |
    # text | pdf | archive | executable | unknown
    # ==========================================

    detected_type = db.Column(
        db.String(30),
        nullable=True
    )

    detected_label = db.Column(
        db.String(80),
        nullable=True
    )

    # True when the file extension does not match
    # what the file content really is.
    extension_mismatch = db.Column(
        db.Boolean,
        default=False
    )

    # ==========================================
    # EVIDENCE INTEGRITY (hashes recorded at
    # acquisition time)
    # ==========================================

    md5_hash = db.Column(
        db.String(32),
        nullable=True
    )

    sha256_hash = db.Column(
        db.String(64),
        nullable=True
    )

    # "At upload"  -> hashed the moment it was uploaded
    # "Post-hoc"   -> baseline recorded later (migration)
    hash_baseline = db.Column(
        db.String(20),
        nullable=True
    )

    hash_recorded_at = db.Column(
        db.DateTime,
        nullable=True
    )

    # Verified | Tampered | Missing | Unchecked
    integrity_status = db.Column(
        db.String(20),
        default="Unchecked"
    )

    last_verified_at = db.Column(
        db.DateTime,
        nullable=True
    )
