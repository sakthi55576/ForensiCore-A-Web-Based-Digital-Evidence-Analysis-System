import json
import os

from flask import (
    current_app,
    send_file,
    session,
    redirect,
    url_for,
    flash,
    request
)

from . import reports
from .pdf_generator import generate_forensic_report

from app.config import Config
from app.models.audit_log import AuditLog
from app.models.browser_analysis import BrowserAnalysis
from app.models.email_analysis import EmailAnalysis
from app.models.evidence import Evidence
from app.models.metadata_analysis import MetadataAnalysis
from app.risk_engine.utils import build_case_risk, risk_for_report
from app.utils.audit import action_meta, log_action
from app.utils.auth import login_required
from app.utils.correlate import find_correlations
from app.utils.evidence import ensure_evidence_folder, get_owned_case_or_404
from app.utils.findings import SEVERITY_ORDER, case_findings, case_timeline


def load_json(value, default):

    try:

        if not value:
            return default

        if isinstance(value, (dict, list)):
            return value

        return json.loads(value)

    except Exception:
        return default


def human_size(size):

    size = size or 0

    if size >= 1024 * 1024:
        return "{:.2f} MB".format(size / (1024 * 1024))

    return "{:.1f} KB".format(size / 1024)


def stamp(moment):

    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "n/a"


def latest_for_case(model, case_id):

    """Latest analysis row of the case (via the evidence table)."""

    return (
        model.query
        .join(Evidence, model.evidence_id == Evidence.id)
        .filter(Evidence.case_id == case_id)
        .order_by(model.id.desc())
        .first()
    )


@reports.route("/generate")
@login_required
def generate_report():

    case_id = (
        request.args.get("case_id", type=int)
        or session.get("active_case_id")
    )

    if not case_id:

        flash(
            "Open a case first, then generate its report from the "
            "Report tab.",
            "info"
        )

        return redirect(url_for("cases.dashboard"))

    case = get_owned_case_or_404(case_id)

    case_data = {
        "Case ID": case.case_number,
        "Case Title": case.case_title,
        "Investigator": case.investigator_name,
        "Investigation Date": case.investigation_date or "Not Available",
        "Case Status": case.status or "Open",
        "Case Summary": case.case_summary or "Not Available",
        "System": "ForensiCore: A Digital Evidence Analyzer",
        "Report Type": "Final Consolidated Forensic Report"
    }

    evidence_list = (
        Evidence.query.filter_by(case_id=case.id)
        .order_by(Evidence.id).all()
    )

    by_id = {e.id: e for e in evidence_list}

    # ---------------- metadata ----------------

    metadata_data = {}

    metadata_analysis = latest_for_case(MetadataAnalysis, case.id)

    if metadata_analysis:

        evidence = by_id.get(metadata_analysis.evidence_id)

        metadata_data = load_json(metadata_analysis.metadata_data, {})

        observations = load_json(metadata_analysis.observations, [])

        metadata_data["Evidence ID"] = metadata_analysis.evidence_id
        metadata_data["Case ID"] = case.id
        metadata_data["File Name"] = (
            evidence.original_filename if evidence else "Not Available"
        )
        metadata_data["MD5"] = (
            evidence.md5_hash if evidence else "Not Available"
        )
        metadata_data["SHA-256"] = (
            evidence.sha256_hash if evidence else "Not Available"
        )
        metadata_data["Risk Score"] = metadata_analysis.risk_score or 0
        metadata_data["Risk Level"] = metadata_analysis.risk_level or "LOW"
        metadata_data["Observations"] = (
            " ".join(observations)
            if isinstance(observations, list) else str(observations)
        ) or "No observations available."

    # ---------------- email ----------------

    email_data = {}

    email_analysis = (
        EmailAnalysis.query.filter_by(case_id=case.id)
        .order_by(EmailAnalysis.id.desc()).first()
    )

    if email_analysis:

        email_data = load_json(email_analysis.analysis_data, {})

        email_data["Evidence ID"] = email_analysis.evidence_id
        email_data["Case ID"] = email_analysis.case_id
        email_data["File Hash"] = email_analysis.file_hash or "Not Available"
        email_data["Hash Algorithm"] = (
            email_analysis.hash_algorithm or "SHA-256"
        )
        email_data["Risk Score"] = email_analysis.risk_score or 0
        email_data["Risk Level"] = email_analysis.risk_level or "LOW"
        email_data["Findings"] = load_json(email_analysis.findings, [])

    # ---------------- browser ----------------

    browser_data = {}

    browser_analysis = (
        BrowserAnalysis.query.filter_by(case_id=case.id)
        .order_by(BrowserAnalysis.id.desc()).first()
    )

    if browser_analysis:

        browser_evidence = by_id.get(browser_analysis.evidence_id)

        browser_data = {
            "Evidence ID": browser_analysis.evidence_id,
            "Case ID": browser_analysis.case_id,
            "history_file": (
                browser_evidence.original_filename
                if browser_evidence else "Not Available"
            ),
            "stored_file": (
                browser_evidence.stored_filename
                if browser_evidence else "Not Available"
            ),
            "history_data": load_json(browser_analysis.history_data, {}),
            "top_sites": load_json(browser_analysis.top_sites, []),
            "timeline": load_json(browser_analysis.timeline, [])[:40],
            "file_hash": browser_analysis.file_hash or "Not Available",
            "risk_data": load_json(browser_analysis.risk_data, {}),
            "Risk Score": browser_analysis.risk_score or 0,
            "Risk Level": browser_analysis.risk_level or "LOW",
            "Findings": load_json(browser_analysis.findings, [])
        }

    # ---------------- overall risk (always from the database) ----------------

    risk = build_case_risk(case.id)

    overall_risk_data = risk_for_report(risk)

    # ---------------- integrity / custody / findings / timeline ----------------

    integrity_rows = [
        {
            "id": e.id,
            "name": e.original_filename,
            "type": e.detected_label or e.detected_type or "Unknown",
            "size": human_size(e.file_size),
            "md5": e.md5_hash or "n/a",
            "sha256": e.sha256_hash or "n/a",
            "baseline": e.hash_baseline or "n/a",
            "recorded_at": stamp(e.hash_recorded_at),
            "status": e.integrity_status or "Unchecked",
            "verified_at": stamp(e.last_verified_at)
        }
        for e in evidence_list
    ]

    audit_rows = (
        AuditLog.query.filter_by(case_id=case.id)
        .order_by(AuditLog.id.asc()).all()
    )

    custody_rows = [
        {
            "time": stamp(a.created_at),
            "user": a.user_name or "system",
            "action": action_meta(a.action)[0],
            "details": a.details or ""
        }
        for a in audit_rows
    ]

    all_findings = case_findings(case.id)

    findings_rows = [
        {
            "severity": f.severity,
            "module": f.module.title(),
            "title": f.title,
            "detail": f.detail or ""
        }
        for f in sorted(
            all_findings,
            key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)
        )
    ]

    events = case_timeline(case.id)

    timeline_rows = [
        {
            "time": stamp(ev.event_time),
            "module": ev.module.title(),
            "title": ev.title,
            "note": ev.time_note or ""
        }
        for ev in sorted(events, key=lambda ev: ev.event_time)
    ]

    correlation_rows = []

    for item in find_correlations(events):

        anchor = item["anchor"]

        correlation_rows.append(
            "{} ({}) is within {} minutes of: {}".format(
                anchor.title,
                stamp(anchor.event_time),
                item["window"],
                "; ".join(n.title for n in item["nearby"][:3])
            )
        )

    # ---------------- build PDF ----------------

    ensure_evidence_folder()

    pdf_filename = "ForensiCore_{}_Final_Forensic_Report.pdf".format(
        case.case_number
    )

    pdf_path = os.path.join(Config.REPORT_FOLDER, pdf_filename)

    try:

        generate_forensic_report(
            pdf_path,
            case_data=case_data,
            metadata_data=metadata_data,
            email_data=email_data,
            browser_data=browser_data,
            overall_risk_data=overall_risk_data,
            integrity_rows=integrity_rows,
            custody_rows=custody_rows,
            findings_rows=findings_rows,
            timeline_rows=timeline_rows,
            correlation_rows=correlation_rows
        )

    except Exception as error:

        print("PDF generation error:", error)

        current_app.logger.error("PDF generation failed: %s", error)

        flash("PDF generation failed. Please try again; if it keeps happening, check the file.", "danger")

        return redirect(
            url_for("cases.case_details", case_id=case.id)
        )

    log_action(
        "REPORT_GENERATED",
        case_id=case.id,
        details=pdf_filename
    )

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=pdf_filename
    )
