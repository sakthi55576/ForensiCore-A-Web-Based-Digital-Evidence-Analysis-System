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


UPLOAD_FOLDER = "app/uploads/browser"


if not os.path.exists(UPLOAD_FOLDER):

    os.makedirs(UPLOAD_FOLDER)


@browser.route("/")
def upload():

    return render_template(
        "browser/upload.html"
    )


@browser.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    if "history_file" not in request.files:

        return "No browser history file uploaded"


    file = request.files["history_file"]


    if file.filename == "":

        return "No selected file"


    filename = secure_filename(
        file.filename
    )


    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )


    file.save(file_path)


    # --------------------------------
    # SHA-256 Evidence Integrity
    # --------------------------------

    file_hash = generate_file_hash(
        file_path
    )


    # --------------------------------
    # Browser History Extraction
    # --------------------------------

    history_data = extract_history(
        file_path
    )


    # --------------------------------
    # Top Visited Websites
    # --------------------------------

    top_sites = get_top_websites(
        history_data
    )


    # --------------------------------
    # Browsing Timeline
    # --------------------------------

    timeline = get_browsing_timeline(
        history_data
    )


    # --------------------------------
    # Browser Risk Assessment
    # --------------------------------

    risk_data = analyze_browser_risk(
        history_data
    )


    # --------------------------------
    # Store Browser Analysis
    # --------------------------------

    session["browser_report"] = {

        "history_data": history_data,

        "top_sites": top_sites,

        "timeline": timeline,

        "history_file": filename,

        "file_hash": file_hash,

        "risk_data": risk_data

    }


    # --------------------------------
    # Display Browser Result
    # --------------------------------

    return render_template(

        "browser/result.html",

        history_data=history_data,

        top_sites=top_sites,

        timeline=timeline,

        history_file=filename,

        file_hash=file_hash,

        risk_data=risk_data

    )


@browser.route("/history")
def full_history():

    history_file = request.args.get(
        "file"
    )


    if not history_file:

        return "History file not specified"


    file_path = os.path.join(
        UPLOAD_FOLDER,
        history_file
    )


    if not os.path.exists(file_path):

        return "History file not found"


    history_data = extract_history(
        file_path
    )


    return render_template(

        "browser/history.html",

        history_data=history_data

    )