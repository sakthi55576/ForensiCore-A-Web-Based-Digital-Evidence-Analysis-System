"""Persist analyzer findings + timeline events and read them back."""

from app import db
from app.models.finding import Finding, TimelineEvent

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def severity_from_points(points):

    if points >= 30:
        return "HIGH"

    if points >= 15:
        return "MEDIUM"

    if points > 0:
        return "LOW"

    return "INFO"


def level_from_score(score):

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def make_finding(title, detail="", points=0, category="", severity=None):

    return {
        "severity": severity or severity_from_points(points),
        "category": category,
        "title": title,
        "detail": detail,
        "points": points
    }


def replace_findings(evidence, module, findings, events):

    """
    Store the results of the LATEST analysis of this evidence.
    Older derived rows for the same evidence + module are replaced
    (the audit log keeps the history of every analysis run).
    """

    try:

        Finding.query.filter_by(
            evidence_id=evidence.id,
            module=module
        ).delete()

        TimelineEvent.query.filter_by(
            evidence_id=evidence.id,
            module=module
        ).delete()

        for item in findings:

            db.session.add(Finding(
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                module=module,
                severity=item["severity"],
                category=(item.get("category") or "")[:80],
                title=item["title"][:255],
                detail=item.get("detail") or "",
                points=item.get("points") or 0
            ))

        for event in events:

            db.session.add(TimelineEvent(
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                module=module,
                event_type=event.get("type"),
                event_time=event["time"],
                title=event["title"][:255],
                detail=event.get("detail") or "",
                severity=event.get("severity"),
                time_note=event.get("time_note")
            ))

        db.session.commit()

    except Exception as error:

        db.session.rollback()

        print("Saving findings failed:", error)


def case_findings(case_id):

    rows = (
        Finding.query
        .filter_by(case_id=case_id)
        .all()
    )

    rows.sort(
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            -(f.points or 0),
            f.id
        )
    )

    return rows


def case_timeline(case_id, limit=400):

    return (
        TimelineEvent.query
        .filter_by(case_id=case_id)
        .order_by(TimelineEvent.event_time.desc())
        .limit(limit)
        .all()
    )
