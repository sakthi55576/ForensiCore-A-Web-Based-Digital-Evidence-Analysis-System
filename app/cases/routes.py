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


def allowed_evidence_file(filename):

    extension = os.path.splitext(
        filename
    )[1].lower()

    return extension in ALLOWED_EXTENSIONS


# ==========================================
# DASHBOARD
# ==========================================

@cases.route("/")
def dashboard():

    if "user_id" not in session:
        return redirect(
            url_for("auth.login")
        )

    all_cases = Case.query.all()

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

        last_case = Case.query.order_by(
            Case.id.desc()
        ).first()

        if last_case:

            case_number = (
                f"CASE-2026-{last_case.id + 1:04d}"
            )

        else:

            case_number = "CASE-2026-0001"


        new_case = Case(

            case_number=case_number,

            case_title=request.form[
                "case_title"
            ],

            investigator_name=request.form[
                "investigator_name"
            ],

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


    case = Case.query.get_or_404(
        case_id
    )


    evidence_list = Evidence.query.filter_by(
        case_id=case.id
    ).order_by(
        Evidence.id.desc()
    ).all()


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


    case = Case.query.get_or_404(
        case_id
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
        # Check file extension
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
        # Generate unique stored filename
        # ----------------------------------

        extension = os.path.splitext(
            original_filename
        )[1].lower()


        stored_filename = (
            f"{uuid.uuid4().hex}{extension}"
        )


        stored_path = os.path.join(
            EVIDENCE_UPLOAD_FOLDER,
            stored_filename
        )


        # ----------------------------------
        # Save file
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
        # File information
        # ----------------------------------

        file_size = os.path.getsize(
            stored_path
        )


        file_type = (
            mimetypes.guess_type(
                original_filename
            )[0]
            or "application/octet-stream"
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
                f"Unable to save evidence record: {str(e)}",
                "danger"
            )

            return redirect(
                url_for(
                    "cases.add_evidence",
                    case_id=case.id
                )
            )


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