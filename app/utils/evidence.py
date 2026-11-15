"""
Evidence handling shared by every module:

    * where evidence files live
    * ownership-checked lookup
    * integrity verification (re-hash and compare)
    * the "integrity gate" that runs before every analysis
"""

import os
import stat

from flask import flash, session

from app import db
from app.config import Config
from app.models.case import Case
from app.models.evidence import Evidence
from app.utils.audit import log_action
from app.utils.filetype import ANALYZER_FOR_KIND, KIND_INFO
from app.utils.hashing import compute_hashes
from app.utils.timeutil import utcnow


# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------

def ensure_evidence_folder():

    os.makedirs(Config.EVIDENCE_UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(Config.REPORT_FOLDER, exist_ok=True)


def evidence_path(evidence):

    return os.path.join(
        Config.EVIDENCE_UPLOAD_FOLDER,
        evidence.stored_filename
    )


def lock_file(path):

    """Make the stored evidence copy read-only."""

    try:
        os.chmod(
            path,
            stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        )
    except OSError:
        pass


# ------------------------------------------------------------------
# Ownership-checked lookups
# ------------------------------------------------------------------

def get_owned_case_or_404(case_id):

    return (
        Case.query
        .filter_by(
            id=case_id,
            user_id=session["user_id"]
        )
        .first_or_404()
    )


def get_owned_evidence_or_404(evidence_id):

    return (
        Evidence.query
        .join(Case, Evidence.case_id == Case.id)
        .filter(
            Evidence.id == evidence_id,
            Case.user_id == session["user_id"]
        )
        .first_or_404()
    )


def user_evidence(case_id=None, kinds=None):

    """Evidence the logged-in user may see, newest first."""

    query = (
        Evidence.query
        .join(Case, Evidence.case_id == Case.id)
        .filter(Case.user_id == session["user_id"])
    )

    if case_id:
        query = query.filter(Evidence.case_id == case_id)

    if kinds:
        query = query.filter(Evidence.detected_type.in_(kinds))

    return query.order_by(Evidence.id.desc()).all()


# ------------------------------------------------------------------
# Integrity verification
# ------------------------------------------------------------------

def verify_evidence(evidence):

    """
    Re-hash the stored file and compare with the hashes recorded
    when the evidence was acquired.

    Returns dict: status, ok, message, expected, actual
    """

    path = evidence_path(evidence)

    now = utcnow()

    expected = evidence.sha256_hash
    actual = None

    if not os.path.exists(path):

        status = "Missing"
        ok = False
        message = "The stored evidence file could not be found."

    elif not evidence.sha256_hash:

        # No baseline yet (should only happen for very old records)
        hashes = compute_hashes(path)

        evidence.md5_hash = hashes["md5"]
        evidence.sha256_hash = hashes["sha256"]
        evidence.hash_baseline = "Post-hoc"
        evidence.hash_recorded_at = now

        expected = actual = hashes["sha256"]
        status = "Verified"
        ok = True
        message = (
            "No earlier hash existed, so a baseline was "
            "recorded now."
        )

        _commit(evidence, now, status)

        log_action(
            "HASH_BASELINE",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            details="Post-hoc baseline sha256={}".format(
                hashes["sha256"]
            )
        )

        return {
            "status": status,
            "ok": ok,
            "message": message,
            "expected": expected,
            "actual": actual
        }

    else:

        hashes = compute_hashes(path)

        actual = hashes["sha256"]

        same = (
            hashes["sha256"] == evidence.sha256_hash
            and (
                not evidence.md5_hash
                or hashes["md5"] == evidence.md5_hash
            )
        )

        if same:
            status = "Verified"
            ok = True
            message = (
                "MD5 and SHA-256 match the values recorded "
                "at acquisition."
            )
        else:
            status = "Tampered"
            ok = False
            message = (
                "The file no longer matches the hashes recorded "
                "at acquisition. It has been modified."
            )

    _commit(evidence, now, status)

    if ok:

        log_action(
            "INTEGRITY_VERIFIED",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            details="sha256 match: {}".format(actual)
        )

    else:

        log_action(
            "INTEGRITY_FAILED",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            details="status={} expected={} actual={}".format(
                status,
                expected,
                actual or "n/a"
            )
        )

    return {
        "status": status,
        "ok": ok,
        "message": message,
        "expected": expected,
        "actual": actual
    }


def _commit(evidence, now, status):

    evidence.integrity_status = status
    evidence.last_verified_at = now

    if status == "Verified" and evidence.status == "Integrity Failed":
        evidence.status = "Uploaded"

    if status in ("Tampered", "Missing"):
        evidence.status = "Integrity Failed"

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


# ------------------------------------------------------------------
# Integrity gate - runs before EVERY analysis
# ------------------------------------------------------------------

def integrity_gate(evidence, module_label):

    """
    Verify evidence before it is analysed.

    Returns (allowed, file_path). When the evidence is tampered or
    missing the analysis is blocked, flashed and written to the
    audit log.
    """

    result = verify_evidence(evidence)

    if result["ok"]:
        return True, evidence_path(evidence)

    flash(
        "{} was blocked: integrity check {} for '{}'. {}".format(
            module_label,
            result["status"].upper(),
            evidence.original_filename,
            result["message"]
        ),
        "danger"
    )

    log_action(
        "ANALYSIS_BLOCKED",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        details="{} refused: evidence {}".format(
            module_label,
            result["status"]
        )
    )

    return False, None


def record_analysis(evidence, module_label, details=""):

    """Mark evidence as analysed and write the audit entry."""

    evidence.status = "Analyzed"

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    session["active_case_id"] = evidence.case_id

    log_action(
        "ANALYSIS_RUN",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        details="{}: {}".format(module_label, details)
    )


# ------------------------------------------------------------------
# Helpers for templates
# ------------------------------------------------------------------

def analyzer_for(evidence):

    """(endpoint, label) of the analyzer for this evidence, or None."""

    return ANALYZER_FOR_KIND.get(evidence.detected_type)


def kind_icon(evidence):

    return KIND_INFO.get(
        evidence.detected_type or "unknown",
        KIND_INFO["unknown"]
    )[1]
