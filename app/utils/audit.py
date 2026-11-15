"""
Chain-of-custody audit log.

Every important action (upload, verification, analysis, report...) is
written to the `audit_logs` table with who did it, when, from which IP
address and on which case / evidence.

The log is append-only: no route in ForensiCore edits or deletes rows.
"""

from flask import session, request, has_request_context

from app import db
from app.models.audit_log import AuditLog
from app.utils.timeutil import utcnow

# ------------------------------------------------------------------
# How each action is displayed in the UI:  (label, icon, tone)
# ------------------------------------------------------------------

ACTION_META = {
    "LOGIN":              ("Signed in",                 "bi-box-arrow-in-right", "neutral"),
    "LOGOUT":             ("Signed out",                "bi-box-arrow-right",    "neutral"),
    "LOGIN_FAILED":       ("Failed sign-in",            "bi-shield-exclamation", "warn"),
    "LOGIN_LOCKED":       ("Sign-in locked",            "bi-lock",               "danger"),
    "CASE_CREATED":       ("Case created",              "bi-folder-plus",        "accent"),
    "EVIDENCE_UPLOADED":  ("Evidence acquired",         "bi-upload",             "accent"),
    "HASH_BASELINE":      ("Hash baseline recorded",    "bi-fingerprint",        "accent"),
    "DUPLICATE_DETECTED": ("Duplicate evidence",        "bi-copy",               "warn"),
    "EXTENSION_MISMATCH": ("Extension mismatch",        "bi-exclamation-diamond","warn"),
    "INTEGRITY_VERIFIED": ("Integrity verified",        "bi-shield-check",       "ok"),
    "INTEGRITY_FAILED":   ("Integrity check FAILED",    "bi-shield-x",           "danger"),
    "ANALYSIS_RUN":       ("Analysis performed",        "bi-cpu",                "accent"),
    "ANALYSIS_BLOCKED":   ("Analysis blocked",          "bi-slash-circle",       "danger"),
    "REPORT_GENERATED":   ("Report generated",          "bi-file-earmark-pdf",   "accent"),
}


def action_meta(action):

    return ACTION_META.get(
        action,
        (action.replace("_", " ").title(), "bi-dot", "neutral")
    )


def log_action(
    action,
    case_id=None,
    evidence_id=None,
    details="",
    user_id=None,
    user_name=None
):

    """
    Append one entry to the audit log.

    NOTE: this commits the database session, so call it AFTER the
    main change has been committed. It never raises: a logging
    problem must not break the investigator's action.
    """

    ip_address = None

    if has_request_context():

        user_id = user_id or session.get("user_id")
        user_name = user_name or session.get("full_name")
        ip_address = request.remote_addr

    details = (details or "")[:2000]

    try:

        entry = AuditLog(
            created_at=utcnow(),
            user_id=user_id,
            user_name=(user_name or "")[:100],
            case_id=case_id,
            evidence_id=evidence_id,
            action=action,
            details=details,
            ip_address=ip_address
        )

        db.session.add(entry)
        db.session.commit()

        return entry

    except Exception as error:

        db.session.rollback()

        print("Audit log write failed:", error)

        return None
