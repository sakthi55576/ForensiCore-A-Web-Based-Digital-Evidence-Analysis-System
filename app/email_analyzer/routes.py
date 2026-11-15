import json

from flask import (
    current_app,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from app import db
from app.models.email_analysis import EmailAnalysis

from . import email

from .utils import analyze_eml

from app.utils.auth import login_required
from app.utils.evidence import (
    get_owned_case_or_404,
    get_owned_evidence_or_404,
    integrity_gate,
    record_analysis,
    user_evidence
)
from app.utils.findings import replace_findings

MODULE_LABEL = "Email Analyzer"


def make_json_safe(data):

    try:
        return json.loads(json.dumps(data, default=str))
    except Exception:
        return str(data)


@email.route("/")
@login_required
def upload():

    case_id = request.args.get("case_id", type=int)

    case = get_owned_case_or_404(case_id) if case_id else None

    return render_template(
        "email/upload.html",
        evidence_list=user_evidence(
            case_id=case.id if case else None,
            kinds=["email"]
        ),
        case_id=case_id,
        case=case
    )


@email.route("/analyze/<int:evidence_id>", methods=["POST"])
@login_required
def analyze(evidence_id):

    evidence = get_owned_evidence_or_404(evidence_id)

    back = redirect(
        url_for("email.upload", case_id=evidence.case_id)
    )

    if evidence.detected_type != "email":

        flash(
            "This evidence is not an email message (.eml), so the "
            "Email Analyzer cannot process it.",
            "warning"
        )

        return back

    allowed, file_path = integrity_gate(evidence, MODULE_LABEL)

    if not allowed:
        return back

    try:

        email_data = analyze_eml(file_path)

    except Exception as error:

        current_app.logger.error("Email analysis failed: %s", error)

        flash("Email analysis failed. Please try again; if it keeps happening, check the file.", "danger")

        return back

    findings = email_data.pop("_findings", [])
    events = email_data.pop("_events", [])

    email_data["File Name"] = evidence.original_filename
    email_data["Stored File Name"] = evidence.stored_filename
    email_data["Evidence ID"] = evidence.id
    email_data["Case ID"] = evidence.case_id
    email_data["File Hash"] = evidence.sha256_hash
    email_data["Hash Algorithm"] = "SHA-256"
    email_data["MD5"] = evidence.md5_hash

    safe_data = make_json_safe(email_data)

    try:

        analysis = EmailAnalysis(
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            file_hash=evidence.sha256_hash,
            hash_algorithm="SHA-256",
            analysis_data=json.dumps(safe_data),
            risk_score=safe_data.get("Risk Score", 0),
            risk_level=safe_data.get("Risk Level", "LOW"),
            findings=json.dumps(safe_data.get("Findings", []))
        )

        db.session.add(analysis)
        db.session.commit()

    except Exception as error:

        db.session.rollback()

        current_app.logger.error("Unable to save email analysis: %s", error)

        flash("Unable to save email analysis. Please try again; if it keeps happening, check the file.", "danger")

        return back

    replace_findings(evidence, "email", findings, events)

    record_analysis(
        evidence,
        MODULE_LABEL,
        "analysis #{} -> {} ({}/100)".format(
            analysis.id,
            safe_data.get("Risk Level"),
            safe_data.get("Risk Score")
        )
    )

    return render_template(
        "email/result.html",
        email_data=safe_data,
        evidence=evidence
    )
