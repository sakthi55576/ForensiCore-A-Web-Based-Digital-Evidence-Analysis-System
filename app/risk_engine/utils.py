"""
Case-level risk assessment.

How the overall risk is decided
-------------------------------
The old engine AVERAGED the module scores. Averaging hides serious
findings (email 90 + metadata 0 = 45) and even counted a module that
was never run as 0. The new engine:

  * looks at every piece of evidence (the latest analysis of each one),
    not only the newest analysis of each module
  * uses the HIGHEST module score as the overall score, because a
    single strong indicator matters even when other evidence is clean
  * adds +10 when two or more different modules independently
    reach at least MEDIUM (corroboration)
  * shows modules that were not analysed as "Not analyzed", not as 0
"""

from sqlalchemy import func

from app import db
from app.models.browser_analysis import BrowserAnalysis
from app.models.email_analysis import EmailAnalysis
from app.models.evidence import Evidence
from app.models.metadata_analysis import MetadataAnalysis
from app.utils.filetype import ANALYZER_FOR_KIND
from app.utils.findings import case_findings, level_from_score

MODULES = [
    ("metadata", "Metadata Analyzer", "bi-image", "image"),
    ("email", "Email Analyzer", "bi-envelope", "email"),
    ("browser", "Browser Analyzer", "bi-globe2", "browser_history"),
]


def _latest_per_evidence(model, evidence_ids, case_id=None):

    """Latest analysis row of each evidence (two simple queries)."""

    if not evidence_ids:
        return []

    latest = (
        db.session.query(func.max(model.id))
        .filter(model.evidence_id.in_(evidence_ids))
        .group_by(model.evidence_id)
        .all()
    )

    latest_ids = [row[0] for row in latest if row[0] is not None]

    if not latest_ids:
        return []

    return model.query.filter(model.id.in_(latest_ids)).all()


def build_case_risk(case_id):

    evidence_list = (
        Evidence.query
        .filter_by(case_id=case_id)
        .order_by(Evidence.id)
        .all()
    )

    by_id = {e.id: e for e in evidence_list}

    ids = list(by_id)

    models = {
        "metadata": MetadataAnalysis,
        "email": EmailAnalysis,
        "browser": BrowserAnalysis,
    }

    modules = {}

    for key, label, icon, kind in MODULES:

        rows = _latest_per_evidence(models[key], ids)

        rows = [r for r in rows if r.risk_score is not None]

        entry = {
            "key": key,
            "label": label,
            "icon": icon,
            "analyzed": bool(rows),
            "count": len(rows),
            "score": None,
            "level": None,
            "driver": None,
            "items": []
        }

        for row in rows:

            evidence = by_id.get(row.evidence_id)

            entry["items"].append({
                "evidence_id": row.evidence_id,
                "name": evidence.original_filename if evidence else "?",
                "score": row.risk_score,
                "level": row.risk_level
            })

        if rows:

            top = max(rows, key=lambda r: r.risk_score)

            entry["score"] = top.risk_score
            entry["level"] = level_from_score(top.risk_score)

            evidence = by_id.get(top.evidence_id)

            entry["driver"] = (
                evidence.original_filename if evidence else None
            )

        modules[key] = entry

    scores = [
        m["score"] for m in modules.values() if m["analyzed"]
    ]

    overall_score = max(scores) if scores else 0

    corroborated = sum(1 for s in scores if s >= 40) >= 2

    if corroborated:
        overall_score = min(overall_score + 10, 100)

    overall_level = level_from_score(overall_score) if scores else None

    findings = case_findings(case_id)

    notable = [f for f in findings if f.severity != "INFO"]

    # Evidence that can be analysed but has not been yet
    analysed_ids = {
        item["evidence_id"]
        for m in modules.values() for item in m["items"]
    }

    pending = [
        e for e in evidence_list
        if e.detected_type in ANALYZER_FOR_KIND
        and e.id not in analysed_ids
    ]

    if not scores:
        explanation = (
            "No evidence has been analysed yet, so no risk level can "
            "be given."
        )
    elif corroborated:
        explanation = (
            "The overall score is the highest module score plus 10, "
            "because at least two different modules independently "
            "reached MEDIUM or higher."
        )
    else:
        explanation = (
            "The overall score is the highest module score, so one "
            "serious indicator is never averaged away by clean "
            "evidence."
        )

    return {
        "modules": modules,
        "analyzed_modules": len(scores),
        "overall_score": overall_score,
        "overall_level": overall_level,
        "corroborated": corroborated,
        "explanation": explanation,
        "findings": findings,
        "notable_findings": notable,
        "pending": pending,
        "evidence_total": len(evidence_list)
    }


def risk_for_report(risk):

    """The dict layout the PDF generator expects."""

    def score(key):
        entry = risk["modules"][key]
        return entry["score"] if entry["analyzed"] else 0

    def level(key):
        entry = risk["modules"][key]
        return entry["level"] if entry["analyzed"] else "Not analyzed"

    return {
        "Overall Score": risk["overall_score"],
        "Overall Risk Level": risk["overall_level"] or "Not analyzed",
        "Metadata Score": score("metadata"),
        "Metadata Risk": level("metadata"),
        "Email Score": score("email"),
        "Email Risk": level("email"),
        "Browser Score": score("browser"),
        "Browser Risk": level("browser"),
        "Findings": [
            "[{}] {}".format(f.severity, f.title)
            for f in risk["notable_findings"][:25]
        ],
        "Method": risk["explanation"]
    }
