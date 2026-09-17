import os
import uuid
import mimetypes

from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from werkzeug.utils import secure_filename

from . import cases
from app import db
from app.models.case import Case
from app.models.evidence import Evidence


# ==========================================
# EVIDENCE UPLOAD FOLDER
# ==========================================

EVIDENCE_UPLOAD_FOLDER = "app/uploads/evidence"

os.makedirs(
    EVIDENCE_UPLOAD_FOLDER,
    exist_ok=True
)


# ==========================================
# ALLOWED EVIDENCE FILE TYPES
# ==========================================

ALLOWED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".tif",
    ".tiff",
    ".eml",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".csv",
    ".txt",
    ".json",
    ".html"
}


# ==========================================
# EVIDENCE FILE VALIDATION
# ==========================================

def allowed_evidence_file(filename):

    extension = os.path.splitext(
        filename
    )[1].lower()

    # --------------------------------------
    # Normal extension-based evidence
    # --------------------------------------

    if extension in ALLOWED_EXTENSIONS:
        return True

    # --------------------------------------
    # Browser History files such as:
    #
    # Chrome: History
    # Edge:   History
    #
    # These files have no extension.
    # --------------------------------------

    if extension == "":
        return True

    return False


# ==========================================
# DASHBOARD
# ==========================================

@cases.route("/")
def dashboard():

    if "user_id" not in session:
        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------
    # Show ONLY logged-in user's cases
    # --------------------------------------

    all_cases = (
        Case.query
        .filter_by(
            user_id=session["user_id"]
        )
        .order_by(
            Case.id.desc()
        )
        .all()
    )

    return render_template(
        "cases/dashboard.html",
        cases=all_cases
    )


# ==========================================
# CREATE CASE
# ==========================================

@cases.route(
    "/create",
    methods=["GET", "POST"]
)
def create_case():

    if "user_id" not in session:
        return redirect(
            url_for("auth.login")
        )

    if request.method == "POST":

        # ----------------------------------
        # Generate Case Number
        # ----------------------------------

        last_case = (
            Case.query
            .order_by(
                Case.id.desc()
            )
            .first()
        )

        if last_case:

            case_number = (
                f"CASE-2026-{last_case.id + 1:04d}"
            )

        else:

            case_number = "CASE-2026-0001"

        # ----------------------------------
        # Create Case
        # ----------------------------------

        new_case = Case(

            # IMPORTANT:
            # Automatically assign case
            # to currently logged-in user.
            user_id=session["user_id"],

            case_number=case_number,

            case_title=request.form[
                "case_title"
            ],

            # Investigator is the logged-in user
            investigator_name=session.get(
                "full_name",
                ""
            ),

            case_summary=request.form[
                "case_summary"
            ]
        )

        db.session.add(
            new_case
        )

        db.session.commit()

        flash(
            "Case created successfully.",
            "success"
        )

        return redirect(
            url_for("cases.dashboard")
        )

    return render_template(
        "cases/create_case.html"
    )


# ==========================================
# CASE DETAILS
# ==========================================

@cases.route(
    "/<int:case_id>"
)
def case_details(case_id):

    if "user_id" not in session:
        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------
    # IMPORTANT SECURITY CHECK
    #
    # User can access ONLY their own case.
    # --------------------------------------

    case = (
        Case.query
        .filter_by(
            id=case_id,
            user_id=session["user_id"]
        )
        .first_or_404()
    )

    # --------------------------------------
    # Get evidence belonging to this case
    # --------------------------------------

    evidence_list = (
        Evidence.query
        .filter_by(
            case_id=case.id
        )
        .order_by(
            Evidence.id.desc()
        )
        .all()
    )

    return render_template(
        "cases/case_details.html",
        case=case,
        evidence_list=evidence_list
    )


# ==========================================
# ADD EVIDENCE PAGE
# ==========================================

@cases.route(
    "/<int:case_id>/evidence/add",
    methods=["GET", "POST"]
)
def add_evidence(case_id):

    if "user_id" not in session:
        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------
    # IMPORTANT SECURITY CHECK
    #
    # Evidence can be added ONLY to a case
    # owned by the logged-in investigator.
    # --------------------------------------

    case = (
        Case.query
        .filter_by(
            id=case_id,
            user_id=session["user_id"]
        )
        .first_or_404()
    )

    if request.method == "POST":

        # ----------------------------------
        # Check file
        # ----------------------------------

        if "evidence" not in request.files:

            flash(
                "No evidence file selected.",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )

        file = request.files[
            "evidence"
        ]

        # ----------------------------------
        # Check filename
        # ----------------------------------

        if not file.filename:

            flash(
                "Please select an evidence file.",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )

        original_filename = secure_filename(
            file.filename
        )

        if not original_filename:

            flash(
                "Invalid evidence filename.",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )

        # ----------------------------------
        # Check evidence type
        # ----------------------------------

        if not allowed_evidence_file(
            original_filename
        ):

            flash(
                "Unsupported evidence file type.",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )

        # ----------------------------------
        # Generate stored filename
        # ----------------------------------

        extension = os.path.splitext(
            original_filename
        )[1].lower()

        # ----------------------------------
        # Browser History files have
        # no extension.
        #
        # Give them a safe internal
        # extension so the stored filename
        # remains unique and identifiable.
        # ----------------------------------

        if extension == "":

            stored_filename = (
                f"{uuid.uuid4().hex}.history"
            )

        else:

            stored_filename = (
                f"{uuid.uuid4().hex}"
                f"{extension}"
            )

        stored_path = os.path.join(
            EVIDENCE_UPLOAD_FOLDER,
            stored_filename
        )

        # ----------------------------------
        # Save evidence
        # ----------------------------------

        try:

            file.save(
                stored_path
            )

        except Exception as e:

            flash(
                f"Evidence upload failed: {str(e)}",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )

        # ----------------------------------
        # File size
        # ----------------------------------

        file_size = os.path.getsize(
            stored_path
        )

        # ----------------------------------
        # File type
        # ----------------------------------

        file_type = (
            mimetypes.guess_type(
                original_filename
            )[0]
            or "application/octet-stream"
        )

        # ----------------------------------
        # Special handling for browser
        # history files with no extension
        # ----------------------------------

        if extension == "":

            file_type = (
                "application/x-browser-history"
            )

        # ----------------------------------
        # Create Evidence record
        # ----------------------------------

        evidence = Evidence(

            case_id=case.id,

            original_filename=original_filename,

            stored_filename=stored_filename,

            file_type=file_type,

            file_size=file_size,

            status="Uploaded"
        )

        # ----------------------------------
        # Save database record
        # ----------------------------------

        try:

            db.session.add(
                evidence
            )

            db.session.commit()

        except Exception as e:

            db.session.rollback()

            if os.path.exists(
                stored_path
            ):

                os.remove(
                    stored_path
                )

            flash(
                f"Unable to save evidence record: "
                f"{str(e)}",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )

        # ----------------------------------
        # Success
        # ----------------------------------

        flash(
            "Evidence uploaded successfully.",
            "success"
        )

        return redirect(
            url_for(
                "cases.case_details",
                case_id=case.id
            )
        )

    return render_template(
        "cases/add_evidence.html",
        case=case
    )