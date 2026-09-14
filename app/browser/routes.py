import os

from flask import (
    render_template,
    request,
    session
)

from werkzeug.utils import secure_filename

from . import browser

from .utils import (
    extract_history,
    get_top_websites,
    get_browsing_timeline,
    generate_file_hash,
    analyze_browser_risk
)


# ==========================================
# PROJECT ROOT
# ==========================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)


# ==========================================
# BROWSER UPLOAD FOLDER
# ==========================================

UPLOAD_FOLDER = os.path.join(
    PROJECT_ROOT,
    "app",
    "uploads",
    "browser"
)


os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ==========================================
# BROWSER UPLOAD PAGE
# ==========================================

@browser.route("/")
def upload():

    return render_template(
        "browser/upload.html"
    )


# ==========================================
# ANALYZE BROWSER HISTORY
# ==========================================

@browser.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    # --------------------------------------
    # Check uploaded file
    # --------------------------------------

    if "history_file" not in request.files:

        return "No browser history file uploaded"


    file = request.files["history_file"]


    if file.filename == "":

        return "No selected file"


    # --------------------------------------
    # Secure filename
    # --------------------------------------

    filename = secure_filename(
        file.filename
    )


    # --------------------------------------
    # File path
    # --------------------------------------

    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )


    # --------------------------------------
    # Save browser evidence
    # --------------------------------------

    file.save(
        file_path
    )


    # ======================================
    # SHA-256 HASH
    # ======================================

    file_hash = generate_file_hash(
        file_path
    )


    # ======================================
    # EXTRACT BROWSER HISTORY
    # ======================================

    history_data = extract_history(
        file_path
    )


    # ======================================
    # TOP VISITED WEBSITES
    # ======================================

    top_sites = get_top_websites(
        history_data
    )


    # ======================================
    # BROWSING TIMELINE
    # ======================================

    timeline = get_browsing_timeline(
        history_data
    )


    # ======================================
    # BROWSER RISK ASSESSMENT
    # ======================================

    risk_data = analyze_browser_risk(
        history_data
    )


    # ======================================
    # STORE BROWSER REPORT IN SESSION
    # ======================================

    session["browser_report"] = {

        "history_file": filename,

        "history_data": history_data,

        "top_sites": top_sites,

        "timeline": timeline,

        "file_hash": file_hash,

        "risk_data": risk_data

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
        "History File:",
        filename
    )

    print(
        "Total URLs:",
        history_data.get(
            "Total URLs",
            0
        )
    )

    print(
        "Risk Data:",
        risk_data
    )

    print(
        "==========================================\n"
    )


    # ======================================
    # DISPLAY RESULT PAGE
    # ======================================

    return render_template(

        "browser/result.html",

        history_data=history_data,

        top_sites=top_sites,

        timeline=timeline,

        history_file=filename,

        file_hash=file_hash,

        risk_data=risk_data

    )


# ==========================================
# VIEW FULL HISTORY
# ==========================================

@browser.route(
    "/history"
)
def full_history():

    history_file = request.args.get(
        "file"
    )


    # --------------------------------------
    # Check filename
    # --------------------------------------

    if not history_file:

        return "History file not specified"


    # --------------------------------------
    # Security: secure filename
    # --------------------------------------

    history_file = secure_filename(
        history_file
    )


    # --------------------------------------
    # Browser evidence path
    # --------------------------------------

    file_path = os.path.join(
        UPLOAD_FOLDER,
        history_file
    )


    # --------------------------------------
    # Check file exists
    # --------------------------------------

    if not os.path.exists(
        file_path
    ):

        return "History file not found"


    # --------------------------------------
    # Extract history
    # --------------------------------------

    history_data = extract_history(
        file_path
    )


    # --------------------------------------
    # Display complete history
    # --------------------------------------

    return render_template(

        "browser/history.html",

        history_data=history_data

    )