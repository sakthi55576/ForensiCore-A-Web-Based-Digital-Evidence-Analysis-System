import json

from flask import (
    render_template,
    session
)

from . import risk_engine
from .utils import generate_overall_risk_report


# ==========================================
# OVERALL RISK ENGINE
# ==========================================

@risk_engine.route("/")
def risk_dashboard():

    # ======================================
    # GET METADATA REPORT
    # ======================================

    metadata_report = session.get(
        "metadata_report",
        {}
    )


    # ======================================
    # GET EMAIL REPORT
    # ======================================

    email_report = session.get(
        "email_report",
        {}
    )


    # ======================================
    # GET BROWSER REPORT
    # ======================================

    browser_report = session.get(
        "browser_report",
        {}
    )


    # ======================================
    # EXTRACT DATA
    # ======================================

    metadata_data = metadata_report.get(
        "risk_level",
        "LOW"
    )


    email_data = email_report.get(
        "email_data",
        {}
    )


    browser_data = browser_report.get(
        "risk_data",
        {}
    )


    # ======================================
    # GENERATE OVERALL RISK
    # ======================================

    overall_risk = generate_overall_risk_report(

        metadata_risk=metadata_data,

        email_data=email_data,

        browser_data=browser_data

    )


    # ======================================
    # STORE OVERALL RISK
    # ======================================

    session["overall_risk_report"] = {

        "overall_score":
        overall_risk.get(
            "Overall Score",
            0
        ),

        "overall_level":
        overall_risk.get(
            "Overall Risk Level",
            "LOW"
        ),

        "findings":
        overall_risk.get(
            "Findings",
            []
        )

    }


    # ======================================
    # DISPLAY RISK DASHBOARD
    # ======================================

    return render_template(

        "risk_engine/result.html",

        overall_risk=overall_risk,

        metadata_risk=metadata_data,

        email_data=email_data,

        browser_data=browser_data

    )