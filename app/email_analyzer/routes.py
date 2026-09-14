import os
import json

from flask import (
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash
)

from app.models.evidence import Evidence

from . import email

from .utils import (
    analyze_email,
    extract_eml_header,
    generate_file_hash
)


# ==========================================
# EVIDENCE UPLOAD FOLDER
# ==========================================

EVIDENCE_UPLOAD_FOLDER = "app/uploads/evidence"

os.makedirs(
    EVIDENCE_UPLOAD_FOLDER,
    exist_ok=True
)


# ==========================================
# SUPPORTED EMAIL EXTENSION
# ==========================================

SUPPORTED_EMAIL_EXTENSIONS = {
    ".eml"
}


# ==========================================
# MAKE DATA JSON SAFE
# ==========================================

def make_json_safe(data):

    try:

        return json.loads(
            json.dumps(
                data,
                default=str
            )
        )

    except Exception:

        return str(data)


# ==========================================
# EMAIL ANALYZER PAGE
# ==========================================

@email.route("/")
def upload():

    # --------------------------------------
    # Login check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # --------------------------------------
    # Get Case ID from URL
    # --------------------------------------

    case_id = request.args.get(
        "case_id",
        type=int
    )


    # ======================================
    # CASE-SPECIFIC EMAIL EVIDENCE
    # ======================================

    if case_id:

        email_evidence = Evidence.query.filter_by(
            case_id=case_id
        ).order_by(
            Evidence.id.desc()
        ).all()


        email_evidence = [

            evidence

            for evidence in email_evidence

            if os.path.splitext(
                evidence.original_filename
            )[1].lower()

            in SUPPORTED_EMAIL_EXTENSIONS

        ]


    # ======================================
    # ALL EMAIL EVIDENCE
    # ======================================

    else:

        all_evidence = Evidence.query.order_by(
            Evidence.id.desc()
        ).all()


        email_evidence = [

            evidence

            for evidence in all_evidence

            if os.path.splitext(
                evidence.original_filename
            )[1].lower()

            in SUPPORTED_EMAIL_EXTENSIONS

        ]


    # --------------------------------------
    # Display Email Evidence
    # --------------------------------------

    return render_template(

        "email/upload.html",

        evidence_list=email_evidence,

        case_id=case_id

    )


# ==========================================
# EMAIL ANALYSIS
# ==========================================

@email.route(
    "/analyze/<int:evidence_id>",
    methods=["GET"]
)
def analyze(evidence_id):


    # --------------------------------------
    # Login check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # --------------------------------------
    # Get Evidence
    # --------------------------------------

    evidence = Evidence.query.get_or_404(
        evidence_id
    )


    # --------------------------------------
    # Verify EML file
    # --------------------------------------

    extension = os.path.splitext(
        evidence.original_filename
    )[1].lower()


    if extension not in SUPPORTED_EMAIL_EXTENSIONS:

        flash(
            "This evidence type is not supported by the Email Analyzer.",
            "warning"
        )

        return redirect(
            url_for(
                "email.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # GET STORED EVIDENCE FILE
    # ======================================

    file_path = os.path.join(
        EVIDENCE_UPLOAD_FOLDER,
        evidence.stored_filename
    )


    # --------------------------------------
    # Check File Exists
    # --------------------------------------

    if not os.path.exists(file_path):

        flash(
            "Stored email evidence file was not found.",
            "danger"
        )

        return redirect(
            url_for(
                "email.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # EXTRACT EMAIL HEADER
    # ======================================

    try:

        header_text = extract_eml_header(
            file_path
        )

    except Exception as e:

        flash(
            f"Email header extraction failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for(
                "email.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # ANALYZE EMAIL
    # ======================================

    try:

        email_data = analyze_email(
            header_text
        )

    except Exception as e:

        flash(
            f"Email analysis failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for(
                "email.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # GENERATE FILE HASH
    # ======================================

    try:

        file_hash = generate_file_hash(
            file_path
        )

    except Exception:

        file_hash = "Not Available"


    # ======================================
    # ADD EVIDENCE INFORMATION
    # ======================================

    email_data["File Name"] = (
        evidence.original_filename
    )


    email_data["Stored File Name"] = (
        evidence.stored_filename
    )


    email_data["Evidence ID"] = (
        evidence.id
    )


    email_data["Case ID"] = (
        evidence.case_id
    )


    email_data["File Hash"] = (
        file_hash
    )


    email_data["Hash Algorithm"] = (
        "SHA-256"
    )


    # ======================================
    # MAKE JSON SAFE
    # ======================================

    safe_email_data = make_json_safe(
        email_data
    )


    # ======================================
    # EMAIL RISK SCORE
    # ======================================

    email_score = safe_email_data.get(
        "Risk Score",
        0
    )


    # ======================================
    # EMAIL RISK LEVEL
    # ======================================

    email_level = safe_email_data.get(
        "Risk Level",
        "LOW"
    )


    # ======================================
    # EMAIL FINDINGS
    # ======================================

    email_findings = safe_email_data.get(
        "Findings",
        []
    )


    # ======================================
    # STORE EMAIL REPORT IN SESSION
    # ======================================

    session["email_report"] = {

        "evidence_id":
        evidence.id,

        "case_id":
        evidence.case_id,

        "email_data":
        safe_email_data

    }


    # ======================================
    # STORE EMAIL RISK
    # ======================================

    session["email_risk"] = {

        "Evidence ID":
        evidence.id,

        "Case ID":
        evidence.case_id,

        "Risk Score":
        email_score,

        "Risk Level":
        email_level,

        "Findings":
        email_findings

    }


    # ======================================
    # DISPLAY EMAIL RESULT
    # ======================================

    return render_template(

        "email/result.html",

        email_data=safe_email_data,

        evidence=evidence

    )