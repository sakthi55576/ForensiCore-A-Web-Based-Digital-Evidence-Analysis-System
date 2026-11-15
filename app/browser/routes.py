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
from app.models.browser_analysis import BrowserAnalysis

from . import browser

from .utils import analyze_browser, extract_history, FULL_HISTORY_LIMIT

from app.utils.auth import login_required
from app.utils.evidence import (
    get_owned_case_or_404,
    get_owned_evidence_or_404,
    integrity_gate,
    record_analysis,
    user_evidence
)
from app.utils.findings import replace_findings

MODULE_LABEL = "Browser Analyzer"


def make_json_safe(data):

    try:
        return json.loads(json.dumps(data, default=str))
    except Exception:
        return str(data)


@browser.route("/")
@login_required
def upload():

    case_id = request.args.get("case_id", type=int)

    case = get_owned_case_or_404(case_id) if case_id else None

    return render_template(
        "browser/upload.html",
        evidence_list=user_evidence(
            case_id=case.id if case else None,
            kinds=["browser_history"]
        ),
        case_id=case_id,
        case=case
    )


@browser.route("/analyze/<int:evidence_id>", methods=["POST"])
@login_required
def analyze(evidence_id):

    evidence = get_owned_evidence_or_404(evidence_id)

    back = redirect(
        url_for("browser.upload", case_id=evidence.case_id)
    )

    if evidence.detected_type != "browser_history":

        flash(
            "This evidence is not a Chrome/Edge history database, so "
            "the Browser Analyzer cannot process it.",
            "warning"
        )

        return back

    allowed, file_path = integrity_gate(evidence, MODULE_LABEL)

    if not allowed:
        return back

    try:

        result = analyze_browser(file_path)

    except Exception as error:

        current_app.logger.error("Browser analysis failed: %s", error)

        flash("Browser analysis failed. Please try again; if it keeps happening, check the file.", "danger")

        return back

    history_data = make_json_safe(result["history_data"])
    top_sites = make_json_safe(result["top_sites"])
    timeline = make_json_safe(result["timeline"])
    risk_data = make_json_safe(result["risk_data"])

    try:

        analysis = BrowserAnalysis(
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            file_hash=evidence.sha256_hash,
            hash_algorithm="SHA-256",
            history_data=json.dumps(history_data),
            top_sites=json.dumps(top_sites),
            timeline=json.dumps(timeline),
            risk_data=json.dumps(risk_data),
            risk_score=risk_data["Risk Score"],
            risk_level=risk_data["Risk Level"],
            findings=json.dumps(risk_data["Findings"])
        )

        db.session.add(analysis)
        db.session.commit()

    except Exception as error:

        db.session.rollback()

        current_app.logger.error("Unable to save browser analysis: %s", error)

        flash("Unable to save browser analysis. Please try again; if it keeps happening, check the file.", "danger")

        return back

    replace_findings(
        evidence, "browser", result["findings"], result["events"]
    )

    record_analysis(
        evidence,
        MODULE_LABEL,
        "analysis #{} -> {} ({}/100)".format(
            analysis.id,
            risk_data["Risk Level"],
            risk_data["Risk Score"]
        )
    )

    return render_template(
        "browser/result.html",
        evidence=evidence,
        history_data=history_data,
        top_sites=top_sites,
        timeline=timeline,
        risk_data=risk_data,
        file_hash=evidence.sha256_hash,
        md5_hash=evidence.md5_hash
    )


@browser.route("/history/<int:evidence_id>")
@login_required
def full_history(evidence_id):

    evidence = get_owned_evidence_or_404(evidence_id)

    if evidence.detected_type != "browser_history":

        flash("This evidence is not a browser history database.", "warning")

        return redirect(
            url_for("browser.upload", case_id=evidence.case_id)
        )

    allowed, file_path = integrity_gate(evidence, "Full History View")

    if not allowed:

        return redirect(
            url_for("browser.upload", case_id=evidence.case_id)
        )

    history_data = extract_history(file_path, limit=FULL_HISTORY_LIMIT)

    return render_template(
        "browser/history.html",
        evidence=evidence,
        history_data=history_data,
        limit=FULL_HISTORY_LIMIT
    )
