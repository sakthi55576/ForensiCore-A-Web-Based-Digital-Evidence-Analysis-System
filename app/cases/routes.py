import os
import uuid

from flask import (
    current_app,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename

from . import cases
from app import db
from app.models.audit_log import AuditLog
from app.models.case import Case
from app.models.evidence import Evidence
from app.utils.audit import log_action
from app.utils.auth import login_required, safe_next
from app.utils.correlate import find_correlations
from app.utils.evidence import (
    ensure_evidence_folder,
    evidence_path,
    get_owned_case_or_404,
    get_owned_evidence_or_404,
    lock_file,
    verify_evidence
)
from app.config import Config
from app.utils.filetype import detect_file_type, ANALYZER_FOR_KIND
from app.utils.findings import case_findings, case_timeline
from app.utils.hashing import compute_hashes
from app.utils.timeutil import utcnow
from app.risk_engine.utils import build_case_risk

# ==========================================
# ALLOWED EVIDENCE FILE TYPES
# ==========================================

ALLOWED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".tif", ".tiff",
    ".eml", ".db", ".sqlite", ".sqlite3",
    ".csv", ".txt", ".json", ".html"
}


def allowed_evidence_file(filename):

    extension = os.path.splitext(filename)[1].lower()

    # Chrome / Edge "History" has no extension
    return extension in ALLOWED_EXTENSIONS or extension == ""


def next_case_number():

    year = utcnow().year

    number = (db.session.query(db.func.max(Case.id)).scalar() or 0) + 1

    while True:

        candidate = "CASE-{}-{:04d}".format(year, number)

        if not Case.query.filter_by(case_number=candidate).first():
            return candidate

        number += 1


# ==========================================
# DASHBOARD
# ==========================================

@cases.route("/")
@login_required
def dashboard():

    user_cases = (
        Case.query
        .filter_by(user_id=session["user_id"])
        .order_by(Case.id.desc())
        .all()
    )

    case_ids = [c.id for c in user_cases]

    evidence_all = (
        Evidence.query.filter(Evidence.case_id.in_(case_ids)).all()
        if case_ids else []
    )

    stats = {
        "cases": len(user_cases),
        "evidence": len(evidence_all),
        "verified": sum(
            1 for e in evidence_all if e.integrity_status == "Verified"
        ),
        "alerts": [
            e for e in evidence_all
            if e.integrity_status in ("Tampered", "Missing")
        ],
        "pending": [
            e for e in evidence_all
            if e.detected_type in ANALYZER_FOR_KIND
            and e.status == "Uploaded"
            and e.integrity_status != "Tampered"
        ]
    }

    activity = (
        AuditLog.query
        .filter(AuditLog.case_id.in_(case_ids))
        .order_by(AuditLog.id.desc())
        .limit(8)
        .all()
        if case_ids else []
    )

    case_lookup = {c.id: c for c in user_cases}

    return render_template(
        "cases/dashboard.html",
        cases=user_cases,
        stats=stats,
        activity=activity,
        case_lookup=case_lookup
    )


# ==========================================
# CREATE CASE
# ==========================================

@cases.route("/create", methods=["GET", "POST"])
@login_required
def create_case():

    if request.method == "POST":

        title = request.form.get("case_title", "").strip()

        if not title:

            flash("Case title is required.", "danger")

            return render_template(
                "cases/create_case.html",
                case_number=next_case_number()
            )

        new_case = None

        # case_number is UNIQUE: if two investigators create a case at
        # the same moment, take the next number and try again.
        for _attempt in range(5):

            candidate = Case(
                user_id=session["user_id"],
                case_number=next_case_number(),
                case_title=title,
                investigator_name=(
                    request.form.get("investigator_name", "").strip()
                    or session.get("full_name", "")
                ),
                case_summary=request.form.get("case_summary", "").strip()
            )

            try:

                db.session.add(candidate)
                db.session.commit()

                new_case = candidate

                break

            except IntegrityError:

                db.session.rollback()

        if new_case is None:

            flash("Could not create the case. Please try again.", "danger")

            return render_template(
                "cases/create_case.html",
                case_number=next_case_number()
            )

        session["active_case_id"] = new_case.id

        log_action(
            "CASE_CREATED",
            case_id=new_case.id,
            details="{} - {}".format(new_case.case_number, title)
        )

        flash("Case created successfully.", "success")

        return redirect(
            url_for("cases.case_details", case_id=new_case.id)
        )

    return render_template(
        "cases/create_case.html",
        case_number=next_case_number()
    )


# ==========================================
# CASE WORKSPACE
# ==========================================

@cases.route("/<int:case_id>")
@login_required
def case_details(case_id):

    case = get_owned_case_or_404(case_id)

    session["active_case_id"] = case.id

    evidence_list = (
        Evidence.query
        .filter_by(case_id=case.id)
        .order_by(Evidence.id.desc())
        .all()
    )

    findings = case_findings(case.id)
    timeline = case_timeline(case.id)

    audit_entries = (
        AuditLog.query
        .filter_by(case_id=case.id)
        .order_by(AuditLog.id.desc())
        .limit(300)
        .all()
    )

    risk = build_case_risk(case.id)

    return render_template(
        "cases/case_details.html",
        case=case,
        evidence_list=evidence_list,
        findings=findings,
        timeline=timeline,
        correlations=find_correlations(timeline),
        audit_entries=audit_entries,
        risk=risk,
        assumed_offset=Config.ASSUMED_LOCAL_UTC_OFFSET_MIN
    )


# ==========================================
# ADD EVIDENCE  (hash at acquisition)
# ==========================================

@cases.route("/<int:case_id>/evidence/add", methods=["GET", "POST"])
@login_required
def add_evidence(case_id):

    case = get_owned_case_or_404(case_id)

    if request.method == "GET":
        return render_template("cases/add_evidence.html", case=case)

    again = redirect(url_for("cases.add_evidence", case_id=case.id))

    file = request.files.get("evidence")

    if not file or not file.filename:

        flash("Please select an evidence file.", "danger")

        return again

    original_filename = secure_filename(file.filename)

    if not original_filename:

        flash("Invalid evidence filename.", "danger")

        return again

    if not allowed_evidence_file(original_filename):

        flash("Unsupported evidence file type.", "danger")

        return again

    extension = os.path.splitext(original_filename)[1].lower()

    stored_filename = uuid.uuid4().hex + (extension or ".history")

    ensure_evidence_folder()

    stored_path = os.path.join(
        Config.EVIDENCE_UPLOAD_FOLDER, stored_filename
    )

    # ---- 1. save exactly what was uploaded ----

    try:

        file.save(stored_path)

        # ---- 2. hash + detect type from the saved bytes ----

        hashes = compute_hashes(stored_path)

        detected = detect_file_type(stored_path, original_filename)

        size = os.path.getsize(stored_path)

    except Exception as error:

        if os.path.exists(stored_path):
            os.remove(stored_path)

        current_app.logger.error("Evidence upload failed: %s", error)

        flash("Evidence upload failed. Please try again; if it keeps happening, check the file.", "danger")

        return again

    duplicate = (
        Evidence.query
        .filter_by(case_id=case.id, sha256_hash=hashes["sha256"])
        .first()
    )

    now = utcnow()

    evidence = Evidence(
        case_id=case.id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_type=detected["mime"],
        file_size=size,
        status="Uploaded",
        uploaded_by=session["user_id"],
        detected_type=detected["kind"],
        detected_label=detected["label"],
        extension_mismatch=detected["extension_mismatch"],
        md5_hash=hashes["md5"],
        sha256_hash=hashes["sha256"],
        hash_baseline="At upload",
        hash_recorded_at=now,
        integrity_status="Verified",
        last_verified_at=now
    )

    try:

        db.session.add(evidence)
        db.session.commit()

    except Exception as error:

        db.session.rollback()

        os.remove(stored_path)

        current_app.logger.error("Evidence upload failed: %s", error)

        flash("Evidence upload failed. Please try again; if it keeps happening, check the file.", "danger")

        return again

    # ---- 3. lock the stored copy (read-only) ----

    lock_file(stored_path)

    # ---- 4. chain of custody ----

    log_action(
        "EVIDENCE_UPLOADED",
        case_id=case.id,
        evidence_id=evidence.id,
        details=(
            "{} | {} bytes | type={} | md5={} | sha256={}"
        ).format(
            original_filename, size, detected["kind"],
            hashes["md5"], hashes["sha256"]
        )
    )

    if detected["extension_mismatch"]:

        log_action(
            "EXTENSION_MISMATCH",
            case_id=case.id,
            evidence_id=evidence.id,
            details=detected["note"]
        )

        flash(detected["note"], "warning")

    if duplicate:

        log_action(
            "DUPLICATE_DETECTED",
            case_id=case.id,
            evidence_id=evidence.id,
            details="Identical to evidence #{}".format(duplicate.id)
        )

        flash(
            "This file is identical (same SHA-256) to evidence #{} "
            "'{}' already in this case.".format(
                duplicate.id, duplicate.original_filename
            ),
            "warning"
        )

    flash("Evidence acquired and hashed successfully.", "success")

    return redirect(
        url_for(
            "cases.evidence_detail",
            case_id=case.id,
            evidence_id=evidence.id
        )
    )


# ==========================================
# EVIDENCE RECEIPT / DETAIL
# ==========================================

@cases.route("/<int:case_id>/evidence/<int:evidence_id>")
@login_required
def evidence_detail(case_id, evidence_id):

    case = get_owned_case_or_404(case_id)

    evidence = get_owned_evidence_or_404(evidence_id)

    if evidence.case_id != case.id:
        return redirect(url_for("cases.dashboard"))

    entries = (
        AuditLog.query
        .filter_by(evidence_id=evidence.id)
        .order_by(AuditLog.id.desc())
        .limit(100)
        .all()
    )

    uploader = None

    if evidence.uploaded_by:

        from app.models.user import User

        uploader = db.session.get(User, evidence.uploaded_by)

    return render_template(
        "cases/evidence_detail.html",
        case=case,
        evidence=evidence,
        entries=entries,
        uploader=uploader
    )


# ==========================================
# VERIFY INTEGRITY  (re-hash and compare)
# ==========================================

@cases.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@login_required
def verify(evidence_id):

    evidence = get_owned_evidence_or_404(evidence_id)

    result = verify_evidence(evidence)

    flash(
        "{}: {}".format(
            "Integrity verified" if result["ok"] else
            "INTEGRITY CHECK FAILED ({})".format(result["status"]),
            result["message"]
        ),
        "success" if result["ok"] else "danger"
    )

    return redirect(
        safe_next(request.form.get("next"))
        or url_for("cases.case_details", case_id=evidence.case_id)
    )
