"""The heart of ForensiCore: tamper detection on stored evidence."""

import os

from app import db
from app.config import Config
from app.models import AuditLog, Case, Evidence
from app.utils.evidence import integrity_gate, verify_evidence
from app.utils.hashing import compute_hashes
from app.utils.timeutil import utcnow


def make_evidence(user, content=b"original evidence"):

    case = Case(
        user_id=user.id,
        case_number="CASE-TEST-0001",
        case_title="Test case",
    )
    db.session.add(case)
    db.session.commit()

    os.makedirs(Config.EVIDENCE_UPLOAD_FOLDER, exist_ok=True)

    stored = "abc123.txt"
    path = os.path.join(Config.EVIDENCE_UPLOAD_FOLDER, stored)

    with open(path, "wb") as handle:
        handle.write(content)

    hashes = compute_hashes(path)

    evidence = Evidence(
        case_id=case.id,
        original_filename="note.txt",
        stored_filename=stored,
        status="Uploaded",
        detected_type="text",
        md5_hash=hashes["md5"],
        sha256_hash=hashes["sha256"],
        hash_baseline="At upload",
        hash_recorded_at=utcnow(),
        integrity_status="Verified",
    )
    db.session.add(evidence)
    db.session.commit()

    return evidence, path


def actions():
    return [row.action for row in AuditLog.query.order_by(AuditLog.id)]


def test_untouched_file_verifies(user):

    evidence, _ = make_evidence(user)

    result = verify_evidence(evidence)

    assert result["ok"] is True
    assert result["status"] == "Verified"
    assert "INTEGRITY_VERIFIED" in actions()


def test_modified_file_is_detected_as_tampered(user):

    evidence, path = make_evidence(user)

    # someone edits the stored file outside the application
    with open(path, "wb") as handle:
        handle.write(b"original evidencE")

    result = verify_evidence(evidence)

    assert result["ok"] is False
    assert result["status"] == "Tampered"
    assert evidence.status == "Integrity Failed"
    assert "INTEGRITY_FAILED" in actions()


def test_tampered_file_blocks_analysis(app, user):

    evidence, path = make_evidence(user)

    with open(path, "ab") as handle:
        handle.write(b"x")

    with app.test_request_context():

        allowed, file_path = integrity_gate(evidence, "Test Analyzer")

    assert allowed is False
    assert file_path is None
    assert "ANALYSIS_BLOCKED" in actions()


def test_restoring_the_original_bytes_verifies_again(user):

    evidence, path = make_evidence(user)

    with open(path, "wb") as handle:
        handle.write(b"changed")

    assert verify_evidence(evidence)["status"] == "Tampered"

    with open(path, "wb") as handle:
        handle.write(b"original evidence")

    assert verify_evidence(evidence)["status"] == "Verified"


def test_deleted_file_is_reported_missing(user):

    evidence, path = make_evidence(user)

    os.remove(path)

    result = verify_evidence(evidence)

    assert result["ok"] is False
    assert result["status"] == "Missing"
