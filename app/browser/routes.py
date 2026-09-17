import os
import json
import sqlite3

from flask import (
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash
)

from app import db
from app.models.evidence import Evidence
from app.models.browser_analysis import BrowserAnalysis
from app.models.case import Case

from . import browser

from .utils import (
    extract_history,
    get_top_websites,
    get_browsing_timeline,
    generate_file_hash,
    analyze_browser_risk
)


# ==========================================
# PROJECT PATH
# ==========================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)


# ==========================================
# EVIDENCE UPLOAD FOLDER
# ==========================================

EVIDENCE_UPLOAD_FOLDER = os.path.join(
    PROJECT_ROOT,
    "app",
    "uploads",
    "evidence"
)


os.makedirs(
    EVIDENCE_UPLOAD_FOLDER,
    exist_ok=True
)


# ==========================================
# JSON SAFE CONVERSION
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
# BROWSER HISTORY DATABASE VALIDATION
# ==========================================

def is_browser_history_database(file_path):

    connection = None

    try:

        connection = sqlite3.connect(
            file_path
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'urls'
            """
        )

        result = cursor.fetchone()

        if result:

            return True

        return False

    except Exception as e:

        print(
            "Browser Database Validation Error:",
            e
        )

        return False

    finally:

        if connection:

            connection.close()


# ==========================================
# BROWSER HISTORY ANALYZER HOME
# ==========================================

@browser.route("/")
def upload():

    # --------------------------------------
    # Login Check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # --------------------------------------
    # Optional Case ID
    # --------------------------------------

    case_id = request.args.get(
        "case_id",
        type=int
    )


    # ======================================
    # GET CASE EVIDENCE
    # ======================================

    if case_id:

        # ----------------------------------
        # SECURITY CHECK
        # Verify that the selected case
        # belongs to the logged-in user.
        # ----------------------------------

        case = (

            Case.query

            .filter_by(
                id=case_id,
                user_id=session["user_id"]
            )

            .first_or_404()

        )


        browser_evidence = (

            Evidence.query

            .filter_by(
                case_id=case.id
            )

            .order_by(
                Evidence.id.desc()
            )

            .all()

        )

    else:

        # ----------------------------------
        # IMPORTANT:
        # Get evidence ONLY from cases
        # owned by the logged-in user.
        # ----------------------------------

        browser_evidence = (

            Evidence.query

            .join(
                Case,
                Evidence.case_id == Case.id
            )

            .filter(
                Case.user_id == session["user_id"]
            )

            .order_by(
                Evidence.id.desc()
            )

            .all()

        )


    # ======================================
    # SHOW ONLY BROWSER HISTORY EVIDENCE
    # ======================================

    valid_browser_evidence = []


    for evidence in browser_evidence:

        file_path = os.path.join(
            EVIDENCE_UPLOAD_FOLDER,
            evidence.stored_filename
        )


        # ----------------------------------
        # File must exist
        # ----------------------------------

        if not os.path.exists(file_path):

            continue


        # ----------------------------------
        # Primary identification
        # ----------------------------------

        if (
            evidence.file_type
            == "application/x-browser-history"
        ):

            valid_browser_evidence.append(
                evidence
            )

            continue


        # ----------------------------------
        # Secondary identification
        # ----------------------------------

        if is_browser_history_database(
            file_path
        ):

            valid_browser_evidence.append(
                evidence
            )


    # --------------------------------------
    # Render Browser Module
    # --------------------------------------

    return render_template(

        "browser/upload.html",

        evidence_list=valid_browser_evidence,

        case_id=case_id

    )


# ==========================================
# ANALYZE BROWSER HISTORY
# ==========================================

@browser.route(
    "/analyze/<int:evidence_id>",
    methods=["GET"]
)
def analyze(evidence_id):

    # --------------------------------------
    # Login Check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # ======================================
    # GET EVIDENCE WITH OWNERSHIP CHECK
    # ======================================

    # --------------------------------------
    # Evidence belongs to a Case.
    #
    # Therefore verify:
    #
    # Evidence ID
    # +
    # Parent Case belongs to
    # logged-in investigator.
    # --------------------------------------

    evidence = (

        Evidence.query

        .join(
            Case,
            Evidence.case_id == Case.id
        )

        .filter(

            Evidence.id == evidence_id,

            Case.user_id == session["user_id"]

        )

        .first_or_404()

    )


    # --------------------------------------
    # Build Stored File Path
    # --------------------------------------

    file_path = os.path.join(
        EVIDENCE_UPLOAD_FOLDER,
        evidence.stored_filename
    )


    # --------------------------------------
    # Check File Exists
    # --------------------------------------

    if not os.path.exists(file_path):

        flash(
            "Stored evidence file was not found.",
            "danger"
        )

        return redirect(
            url_for(
                "browser.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # VALIDATE BROWSER HISTORY DATABASE
    # ======================================

    if not is_browser_history_database(
        file_path
    ):

        flash(
            "This evidence is not a valid "
            "Chrome / Edge browser history database.",
            "warning"
        )

        return redirect(
            url_for(
                "browser.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # GENERATE SHA-256 HASH
    # ======================================

    try:

        file_hash = generate_file_hash(
            file_path
        )

    except Exception as e:

        flash(
            f"Hash generation failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for(
                "browser.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # EXTRACT BROWSER HISTORY
    # ======================================

    try:

        history_data = extract_history(
            file_path
        )

    except Exception as e:

        flash(
            f"Browser history extraction failed: "
            f"{str(e)}",
            "danger"
        )

        return redirect(
            url_for(
                "browser.upload",
                case_id=evidence.case_id
            )
        )


    # --------------------------------------
    # Check Extraction Error
    # --------------------------------------

    if history_data.get("Error"):

        flash(
            "Browser history database could not "
            "be analyzed. Please verify that the "
            "evidence is a valid browser history "
            "database.",
            "danger"
        )

        return redirect(
            url_for(
                "browser.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # TOP WEBSITES
    # ======================================

    try:

        top_sites = get_top_websites(
            history_data
        )

    except Exception as e:

        top_sites = []

        print(
            "Top Website Analysis Error:",
            e
        )


    # ======================================
    # BROWSING TIMELINE
    # ======================================

    try:

        timeline = get_browsing_timeline(
            history_data
        )

    except Exception as e:

        timeline = []

        print(
            "Timeline Analysis Error:",
            e
        )


    # ======================================
    # BROWSER RISK ANALYSIS
    # ======================================

    try:

        risk_data = analyze_browser_risk(
            history_data
        )

    except Exception as e:

        risk_data = {

            "Risk Score": 0,

            "Risk Level": "LOW",

            "Risk Breakdown": [],

            "Findings": [

                f"Risk analysis error: {str(e)}"

            ],

            "Forensic Interpretation":
                "Risk assessment could not be "
                "completed."

        }


    # ======================================
    # MAKE DATA JSON SAFE
    # ======================================

    safe_history_data = make_json_safe(
        history_data
    )


    safe_top_sites = make_json_safe(
        top_sites
    )


    safe_timeline = make_json_safe(
        timeline
    )


    safe_risk_data = make_json_safe(
        risk_data
    )


    # ======================================
    # ADD EVIDENCE INFORMATION
    # ======================================

    safe_risk_data["Evidence ID"] = (
        evidence.id
    )


    safe_risk_data["Case ID"] = (
        evidence.case_id
    )


    # ======================================
    # GET RISK DETAILS
    # ======================================

    browser_score = safe_risk_data.get(
        "Risk Score",
        0
    )


    browser_level = safe_risk_data.get(
        "Risk Level",
        "LOW"
    )


    browser_findings = safe_risk_data.get(
        "Findings",
        []
    )


    # ======================================
    # SAVE BROWSER ANALYSIS TO DATABASE
    # ======================================

    try:

        analysis = BrowserAnalysis(

            evidence_id=evidence.id,

            case_id=evidence.case_id,

            file_hash=file_hash,

            hash_algorithm="SHA-256",

            history_data=json.dumps(
                safe_history_data
            ),

            top_sites=json.dumps(
                safe_top_sites
            ),

            timeline=json.dumps(
                safe_timeline
            ),

            risk_data=json.dumps(
                safe_risk_data
            ),

            risk_score=browser_score,

            risk_level=browser_level,

            findings=json.dumps(
                browser_findings
            )

        )


        db.session.add(
            analysis
        )

        db.session.commit()


        print(
            "\n=========================================="
        )

        print(
            "BROWSER ANALYSIS SAVED TO DATABASE"
        )

        print(
            "Analysis ID:",
            analysis.id
        )

        print(
            "Evidence ID:",
            evidence.id
        )

        print(
            "Case ID:",
            evidence.case_id
        )

        print(
            "Risk Score:",
            browser_score
        )

        print(
            "Risk Level:",
            browser_level
        )

        print(
            "==========================================\n"
        )


    except Exception as e:

        db.session.rollback()


        print(
            "Browser Analysis DB Save Error:",
            e
        )


        flash(
            f"Unable to save browser analysis: "
            f"{str(e)}",
            "danger"
        )


        return redirect(
            url_for(
                "browser.upload",
                case_id=evidence.case_id
            )
        )


    # ======================================
    # SAVE BROWSER REPORT IN SESSION
    # ======================================

    session["browser_report"] = {

        "evidence_id":
            evidence.id,

        "case_id":
            evidence.case_id,

        "history_file":
            evidence.original_filename,

        "stored_file":
            evidence.stored_filename,

        "history_data":
            safe_history_data,

        "top_sites":
            safe_top_sites,

        "timeline":
            safe_timeline,

        "file_hash":
            file_hash,

        "risk_data":
            safe_risk_data

    }


    # ======================================
    # DEBUG INFORMATION
    # ======================================

    print(
        "\n=========================================="
    )


    print(
        "BROWSER REPORT SESSION SAVED"
    )


    print(
        "Evidence ID:",
        evidence.id
    )


    print(
        "Case ID:",
        evidence.case_id
    )


    print(
        "History File:",
        evidence.original_filename
    )


    print(
        "Total URLs:",
        safe_history_data.get(
            "Total URLs",
            0
        )
    )


    print(
        "Risk Data:",
        safe_risk_data
    )


    print(
        "==========================================\n"
    )


    # ======================================
    # RENDER RESULT PAGE
    # ======================================

    return render_template(

        "browser/result.html",

        evidence=evidence,

        history_data=safe_history_data,

        top_sites=safe_top_sites,

        timeline=safe_timeline,

        history_file=
            evidence.original_filename,

        file_hash=file_hash,

        risk_data=safe_risk_data

    )


# ==========================================
# FULL BROWSER HISTORY
# ==========================================

@browser.route(
    "/history"
)
def full_history():

    # --------------------------------------
    # Login Check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # --------------------------------------
    # Get Evidence ID
    # --------------------------------------

    evidence_id = request.args.get(
        "evidence_id",
        type=int
    )


    if not evidence_id:

        return "Evidence ID not specified"


    # ======================================
    # GET EVIDENCE WITH OWNERSHIP CHECK
    # ======================================

    evidence = (

        Evidence.query

        .join(
            Case,
            Evidence.case_id == Case.id
        )

        .filter(

            Evidence.id == evidence_id,

            Case.user_id == session["user_id"]

        )

        .first_or_404()

    )


    # --------------------------------------
    # Build File Path
    # --------------------------------------

    file_path = os.path.join(
        EVIDENCE_UPLOAD_FOLDER,
        evidence.stored_filename
    )


    # --------------------------------------
    # Check File
    # --------------------------------------

    if not os.path.exists(file_path):

        return (
            "History evidence file not found"
        )


    # --------------------------------------
    # Validate Browser Database
    # --------------------------------------

    if not is_browser_history_database(
        file_path
    ):

        return (
            "The selected evidence is not "
            "a valid browser history database"
        )


    # --------------------------------------
    # Extract Full History
    # --------------------------------------

    history_data = extract_history(
        file_path
    )


    # --------------------------------------
    # Render History Page
    # --------------------------------------

    return render_template(

        "browser/history.html",

        history_data=history_data,

        evidence=evidence

    )