import os
import json

from flask import (
    render_template,
    session,
    redirect,
    url_for,
    flash
)

from app import db
from app.models.evidence import Evidence
from app.models.metadata_analysis import MetadataAnalysis

from . import metadata

from .utils import (
    generate_hashes,
    extract_image_metadata,
    get_file_information,
    generate_observations,
    calculate_metadata_risk,
    validate_image_file
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
# SUPPORTED IMAGE EXTENSIONS
# ==========================================

SUPPORTED_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".tif",
    ".tiff"
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
# METADATA ANALYZER
# ==========================================

@metadata.route("/")
def upload():

    # --------------------------------------
    # Login check
    # --------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )


    # --------------------------------------
    # Get all evidence
    # --------------------------------------

    all_evidence = Evidence.query.order_by(
        Evidence.id.desc()
    ).all()


    # --------------------------------------
    # Filter image evidence only
    # --------------------------------------

    image_evidence = []

    for evidence in all_evidence:

        extension = os.path.splitext(
            evidence.original_filename
        )[1].lower()

        if extension in SUPPORTED_IMAGE_EXTENSIONS:

            image_evidence.append(
                evidence
            )


    # --------------------------------------
    # Display evidence selection page
    # --------------------------------------

    return render_template(
        "metadata/upload.html",
        evidence_list=image_evidence
    )


# ==========================================
# ANALYZE EXISTING EVIDENCE
# ==========================================

@metadata.route(
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
    # Get evidence record
    # --------------------------------------

    evidence = Evidence.query.get_or_404(
        evidence_id
    )


    # --------------------------------------
    # Verify image evidence
    # --------------------------------------

    extension = os.path.splitext(
        evidence.original_filename
    )[1].lower()

    if extension not in SUPPORTED_IMAGE_EXTENSIONS:

        flash(
            "This evidence type is not supported by the Metadata Analyzer.",
            "warning"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # --------------------------------------
    # Get stored evidence file
    # --------------------------------------

    file_path = os.path.join(
        EVIDENCE_UPLOAD_FOLDER,
        evidence.stored_filename
    )


    # --------------------------------------
    # Check stored file
    # --------------------------------------

    if not os.path.exists(file_path):

        flash(
            "Stored evidence file was not found.",
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # ======================================
    # VALIDATE IMAGE
    # ======================================

    try:

        is_valid, validation_message = validate_image_file(
            file_path
        )

    except Exception as e:

        flash(
            f"Evidence validation failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    if not is_valid:

        flash(
            validation_message,
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # ======================================
    # HASH GENERATION
    # ======================================

    try:

        hashes = generate_hashes(
            file_path
        )

    except Exception as e:

        flash(
            f"Hash generation failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # ======================================
    # METADATA EXTRACTION
    # ======================================

    try:

        metadata_data = extract_image_metadata(
            file_path
        )

    except Exception as e:

        flash(
            f"Metadata extraction failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # ======================================
    # FILE INFORMATION
    # ======================================

    try:

        file_info = get_file_information(
            file_path
        )

    except Exception as e:

        flash(
            f"File information extraction failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # ======================================
    # FORENSIC OBSERVATIONS
    # ======================================

    try:

        observations = generate_observations(
            metadata_data
        )

    except Exception as e:

        observations = [
            f"Observation generation error: {str(e)}"
        ]


    # ======================================
    # METADATA RISK ANALYSIS
    # ======================================

    try:

        risk_result = calculate_metadata_risk(
            metadata_data
        )

    except Exception as e:

        risk_result = {

            "score": 0,

            "level": "LOW",

            "reasons": [
                f"Risk calculation error: {str(e)}"
            ],

            "breakdown": []

        }


    # ======================================
    # RISK SCORE
    # ======================================

    risk_score = risk_result.get(
        "score",
        0
    )


    # ======================================
    # RISK LEVEL
    # ======================================

    risk_level = risk_result.get(
        "level",
        "LOW"
    )


    # ======================================
    # RISK INDICATORS
    # ======================================

    risk_reasons = risk_result.get(
        "reasons",
        []
    )


    # ======================================
    # RISK BREAKDOWN
    # ======================================

    risk_breakdown = risk_result.get(
        "breakdown",
        []
    )


    # ======================================
    # JSON SAFE DATA
    # ======================================

    safe_metadata = make_json_safe(
        metadata_data
    )


    safe_hashes = make_json_safe(
        hashes
    )


    safe_file_info = make_json_safe(
        file_info
    )


    safe_observations = make_json_safe(
        observations
    )


    safe_risk_reasons = make_json_safe(
        risk_reasons
    )


    safe_risk_breakdown = make_json_safe(
        risk_breakdown
    )


    # ======================================
    # SAVE DATABASE RECORD
    # ======================================

    try:

        analysis = MetadataAnalysis(

            evidence_id=evidence.id,

            md5_hash=safe_hashes.get(
                "MD5"
            ),

            sha1_hash=safe_hashes.get(
                "SHA1"
            ),

            sha256_hash=safe_hashes.get(
                "SHA256"
            ),

            metadata_data=json.dumps(
                safe_metadata
            ),

            risk_level=risk_level,

            observations=json.dumps(
                safe_observations
            )

        )


        db.session.add(
            analysis
        )

        db.session.commit()


    except Exception as e:

        db.session.rollback()

        flash(
            f"Database save failed: {str(e)}",
            "danger"
        )

        return redirect(
            url_for("metadata.upload")
        )


    # ======================================
    # STORE REPORT IN SESSION
    # ======================================

    session["metadata_report"] = {

        "evidence_id":
        evidence.id,

        "case_id":
        evidence.case_id,

        "filename":
        evidence.original_filename,

        "hashes":
        safe_hashes,

        "metadata":
        safe_metadata,

        "file_info":
        safe_file_info,

        "observations":
        safe_observations,

        "risk_score":
        risk_score,

        "risk_level":
        risk_level,

        "risk_reasons":
        safe_risk_reasons,

        "risk_breakdown":
        safe_risk_breakdown

    }


    # ======================================
    # DISPLAY RESULT
    # ======================================

    return render_template(

        "metadata/result.html",

        evidence=evidence,

        filename=evidence.original_filename,

        hashes=safe_hashes,

        metadata=safe_metadata,

        file_info=safe_file_info,

        observations=safe_observations,

        risk_score=risk_score,

        risk_level=risk_level,

        risk_reasons=safe_risk_reasons,

        risk_breakdown=safe_risk_breakdown

    )