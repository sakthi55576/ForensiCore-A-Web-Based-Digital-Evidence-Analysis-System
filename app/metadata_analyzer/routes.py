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
from app.models.metadata_analysis import MetadataAnalysis

from . import metadata

from .utils import (
    extract_image_metadata,
    get_file_information,
    generate_observations,
    calculate_metadata_risk,
    validate_image_file,
    build_events
)

from app.utils.auth import login_required
from app.utils.evidence import (
    get_owned_case_or_404,
    get_owned_evidence_or_404,
    integrity_gate,
    record_analysis,
    user_evidence
)
from app.utils.findings import replace_findings

MODULE_LABEL = "Metadata Analyzer"


def make_json_safe(data):

    try:
        return json.loads(json.dumps(data, default=str))
    except Exception:
        return str(data)


# ==========================================
# EVIDENCE PICKER
# ==========================================

@metadata.route("/")
@login_required
def upload():

    case_id = request.args.get("case_id", type=int)

    case = get_owned_case_or_404(case_id) if case_id else None

    return render_template(
        "metadata/upload.html",
        evidence_list=user_evidence(
            case_id=case.id if case else None,
            kinds=["image"]
        ),
        case_id=case_id,
        case=case
    )


# ==========================================
# ANALYZE
# ==========================================

@metadata.route("/analyze/<int:evidence_id>", methods=["POST"])
@login_required
def analyze(evidence_id):

    evidence = get_owned_evidence_or_404(evidence_id)

    back = redirect(
        url_for("metadata.upload", case_id=evidence.case_id)
    )

    if evidence.detected_type != "image":

        flash(
            "This evidence is not an image, so the Metadata "
            "Analyzer cannot process it.",
            "warning"
        )

        return back

    # -------- integrity gate (re-hash before analysis) --------

    allowed, file_path = integrity_gate(evidence, MODULE_LABEL)

    if not allowed:
        return back

    is_valid, message = validate_image_file(file_path)

    if not is_valid:
        flash(message, "danger")
        return back

    # -------- analysis --------

    try:

        metadata_data = extract_image_metadata(file_path)
        file_info = get_file_information(
            file_path, evidence.original_filename
        )
        observations = generate_observations(metadata_data)
        risk = calculate_metadata_risk(metadata_data)
        events = build_events(metadata_data, evidence.original_filename)

    except Exception as error:

        current_app.logger.error("Metadata analysis failed: %s", error)

        flash("Metadata analysis failed. Please try again; if it keeps happening, check the file.", "danger")
        return back

    hashes = {
        "MD5": evidence.md5_hash,
        "SHA256": evidence.sha256_hash
    }

    safe_metadata = make_json_safe(metadata_data)
    safe_observations = make_json_safe(observations)

    try:

        analysis = MetadataAnalysis(
            evidence_id=evidence.id,
            md5_hash=evidence.md5_hash,
            sha1_hash=None,
            sha256_hash=evidence.sha256_hash,
            metadata_data=json.dumps(safe_metadata),
            risk_level=risk["level"],
            risk_score=risk["score"],
            observations=json.dumps(safe_observations)
        )

        db.session.add(analysis)
        db.session.commit()

    except Exception as error:

        db.session.rollback()

        current_app.logger.error("Unable to save analysis: %s", error)

        flash("Unable to save analysis. Please try again; if it keeps happening, check the file.", "danger")

        return back

    replace_findings(
        evidence, "metadata", risk["findings"], events
    )

    record_analysis(
        evidence,
        MODULE_LABEL,
        "analysis #{} -> {} ({}/100)".format(
            analysis.id, risk["level"], risk["score"]
        )
    )

    return render_template(
        "metadata/result.html",
        evidence=evidence,
        filename=evidence.original_filename,
        hashes=hashes,
        metadata=safe_metadata,
        file_info=make_json_safe(file_info),
        observations=safe_observations,
        risk_score=risk["score"],
        risk_level=risk["level"],
        risk_reasons=make_json_safe(risk["reasons"]),
        risk_breakdown=make_json_safe(risk["breakdown"])
    )
