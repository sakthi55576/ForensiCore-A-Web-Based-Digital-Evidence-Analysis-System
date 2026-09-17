import json

from flask import (
    render_template,
    session,
    redirect,
    url_for,
    request
)

from app.models.metadata_analysis import MetadataAnalysis
from app.models.email_analysis import EmailAnalysis
from app.models.browser_analysis import BrowserAnalysis
from app.models.evidence import Evidence
from app.models.case import Case

from . import risk_engine

from .utils import generate_overall_risk_report


# ==========================================
# RISK ENGINE DASHBOARD
# ==========================================

@risk_engine.route("/")
def risk_dashboard():

    # --------------------------------------
    # Login Check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # ======================================
    # GET CASE ID
    # ======================================

    case_id = request.args.get(
        "case_id",
        type=int
    )


    # --------------------------------------
    # Get Case ID from existing sessions
    # --------------------------------------

    if not case_id:

        metadata_report = session.get(
            "metadata_report",
            {}
        )

        email_report = session.get(
            "email_report",
            {}
        )

        browser_report = session.get(
            "browser_report",
            {}
        )


        if metadata_report:

            case_id = metadata_report.get(
                "case_id"
            )


        if not case_id and email_report:

            case_id = email_report.get(
                "case_id"
            )


        if not case_id and browser_report:

            case_id = browser_report.get(
                "case_id"
            )


    # ======================================
    # CASE VALIDATION
    # ======================================

    case = None

    if case_id:

        # ----------------------------------
        # IMPORTANT:
        # Only allow the logged-in user
        # to access their own case.
        # ----------------------------------

        case = Case.query.filter_by(
            id=case_id,
            user_id=session["user_id"]
        ).first()


    # ======================================
    # NO CASE FOUND
    # ======================================

    if not case:

        overall_risk = {

            "Metadata Risk": "LOW",

            "Metadata Score": 0,

            "Email Score": 0,

            "Browser Score": 0,

            "Overall Score": 0,

            "Overall Risk Level": "LOW",

            "Findings": [

                "No case has been selected "
                "for risk assessment."

            ]

        }


        return render_template(

            "risk_engine/result.html",

            overall_risk=overall_risk,

            metadata_risk="LOW",

            metadata_score=0,

            email_data={},

            browser_data={},

            case=None

        )


    # ======================================
    # GET LATEST METADATA ANALYSIS
    # ======================================

    metadata_analysis = (

        MetadataAnalysis.query

        .join(

            Evidence,

            MetadataAnalysis.evidence_id
            == Evidence.id

        )

        .filter(

            Evidence.case_id == case.id

        )

        .order_by(

            MetadataAnalysis.id.desc()

        )

        .first()

    )


    # ======================================
    # GET LATEST EMAIL ANALYSIS
    # ======================================

    email_analysis = (

        EmailAnalysis.query

        .filter_by(

            case_id=case.id

        )

        .order_by(

            EmailAnalysis.id.desc()

        )

        .first()

    )


    # ======================================
    # GET LATEST BROWSER ANALYSIS
    # ======================================

    browser_analysis = (

        BrowserAnalysis.query

        .filter_by(

            case_id=case.id

        )

        .order_by(

            BrowserAnalysis.id.desc()

        )

        .first()

    )


    # ======================================
    # METADATA RISK
    # ======================================

    metadata_score = 0

    metadata_level = "LOW"


    if metadata_analysis:

        metadata_score = (

            metadata_analysis.risk_score

            or 0

        )

        metadata_level = (

            metadata_analysis.risk_level

            or "LOW"

        )


    # ======================================
    # EMAIL DATA
    # ======================================

    email_data = {}


    if email_analysis:

        try:

            email_data = json.loads(

                email_analysis.analysis_data

                or "{}"

            )

        except Exception:

            email_data = {}


        email_data["Risk Score"] = (

            email_analysis.risk_score

            or 0

        )


        email_data["Risk Level"] = (

            email_analysis.risk_level

            or "LOW"

        )


        try:

            email_data["Findings"] = json.loads(

                email_analysis.findings

                or "[]"

            )

        except Exception:

            email_data["Findings"] = []


        email_data["Evidence ID"] = (

            email_analysis.evidence_id

        )


        email_data["Case ID"] = (

            email_analysis.case_id

        )


        email_data["File Hash"] = (

            email_analysis.file_hash

            or "Not Available"

        )


        email_data["Hash Algorithm"] = (

            email_analysis.hash_algorithm

            or "SHA-256"

        )


    # ======================================
    # BROWSER DATA
    # ======================================

    browser_data = {}


    if browser_analysis:

        try:

            history_data = json.loads(

                browser_analysis.history_data

                or "{}"

            )

        except Exception:

            history_data = {}


        try:

            top_sites = json.loads(

                browser_analysis.top_sites

                or "[]"

            )

        except Exception:

            top_sites = []


        try:

            timeline = json.loads(

                browser_analysis.timeline

                or "[]"

            )

        except Exception:

            timeline = []


        try:

            risk_data = json.loads(

                browser_analysis.risk_data

                or "{}"

            )

        except Exception:

            risk_data = {}


        try:

            findings = json.loads(

                browser_analysis.findings

                or "[]"

            )

        except Exception:

            findings = []


        browser_evidence = (

            browser_analysis.evidence

        )


        if browser_evidence:

            history_file = (

                browser_evidence.original_filename

            )

            stored_file = (

                browser_evidence.stored_filename

            )

        else:

            history_file = "Not Available"

            stored_file = "Not Available"


        browser_data = {

            "Evidence ID":

                browser_analysis.evidence_id,

            "Case ID":

                browser_analysis.case_id,

            "history_file":

                history_file,

            "stored_file":

                stored_file,

            "history_data":

                history_data,

            "top_sites":

                top_sites,

            "timeline":

                timeline,

            "file_hash":

                browser_analysis.file_hash

                or "Not Available",

            "risk_data":

                risk_data,

            "Risk Score":

                browser_analysis.risk_score

                or 0,

            "Risk Level":

                browser_analysis.risk_level

                or "LOW",

            "Findings":

                findings

        }


    # ======================================
    # GENERATE OVERALL RISK
    # ======================================

    overall_risk = generate_overall_risk_report(

        metadata_score=metadata_score,

        metadata_risk=metadata_level,

        email_data=email_data,

        browser_data=browser_data

    )


    # ======================================
    # STORE OVERALL RISK
    # ======================================

    session["overall_risk_report"] = {

        "Overall Score":

            overall_risk.get(

                "Overall Score",

                0

            ),

        "Overall Risk Level":

            overall_risk.get(

                "Overall Risk Level",

                "LOW"

            ),

        "Metadata Score":

            overall_risk.get(

                "Metadata Score",

                0

            ),

        "Email Score":

            overall_risk.get(

                "Email Score",

                0

            ),

        "Browser Score":

            overall_risk.get(

                "Browser Score",

                0

            ),

        "Findings":

            overall_risk.get(

                "Findings",

                []

            ),

        "case_id":

            case.id

    }


    # ======================================
    # DEBUG
    # ======================================

    print(

        "\n=========================================="

    )


    print(

        "DATABASE BASED RISK ASSESSMENT"

    )


    print(

        "Case ID:",

        case.id

    )


    print(

        "Case Number:",

        case.case_number

    )


    print(

        "Metadata Analysis:",

        bool(metadata_analysis)

    )


    print(

        "Metadata Score:",

        metadata_score

    )


    print(

        "Metadata Level:",

        metadata_level

    )


    print(

        "Email Analysis:",

        bool(email_analysis)

    )


    print(

        "Email Score:",

        email_data.get(

            "Risk Score",

            0

        )

    )


    print(

        "Browser Analysis:",

        bool(browser_analysis)

    )


    print(

        "Browser Score:",

        browser_data.get(

            "Risk Score",

            0

        )

    )


    print(

        "Overall Score:",

        overall_risk.get(

            "Overall Score",

            0

        )

    )


    print(

        "Overall Risk:",

        overall_risk.get(

            "Overall Risk Level",

            "LOW"

        )

    )


    print(

        "==========================================\n"

    )


    # ======================================
    # DISPLAY RESULT
    # ======================================

    return render_template(

        "risk_engine/result.html",

        overall_risk=overall_risk,

        metadata_risk=metadata_level,

        metadata_score=metadata_score,

        email_data=email_data,

        browser_data=browser_data,

        case=case

    )