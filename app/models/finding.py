from datetime import datetime

from app import db


class Finding(db.Model):
    """
    One forensic indicator produced by an analyzer.

    Every analyzer (metadata, email, browser) writes its results here in
    the same shape, so the case page, risk engine and PDF report all
    read one common source.
    """

    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    case_id = db.Column(db.Integer, nullable=False, index=True)
    evidence_id = db.Column(db.Integer, nullable=False, index=True)

    # metadata | email | browser
    module = db.Column(db.String(20), nullable=False)

    # INFO | LOW | MEDIUM | HIGH
    severity = db.Column(db.String(10), nullable=False, default="INFO")

    category = db.Column(db.String(80))
    title = db.Column(db.String(255), nullable=False)
    detail = db.Column(db.Text)

    # Points this indicator added to the module risk score
    points = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TimelineEvent(db.Model):
    """
    A dated event extracted from evidence (photo taken, email sent,
    file downloaded, search made ...). event_time is always stored
    in UTC; time_note explains how it was normalised.
    """

    __tablename__ = "timeline_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    case_id = db.Column(db.Integer, nullable=False, index=True)
    evidence_id = db.Column(db.Integer, nullable=False, index=True)

    module = db.Column(db.String(20), nullable=False)

    event_type = db.Column(db.String(30))

    event_time = db.Column(db.DateTime, nullable=False, index=True)

    title = db.Column(db.String(255), nullable=False)
    detail = db.Column(db.Text)

    # Optional: LOW | MEDIUM | HIGH when the event itself is a finding
    severity = db.Column(db.String(10))

    time_note = db.Column(db.String(120))
