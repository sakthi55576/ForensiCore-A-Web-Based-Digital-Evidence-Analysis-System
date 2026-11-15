from app import db
from app.models import AuditLog
from app.utils.audit import action_meta, log_action


def test_log_action_records_who_what_and_details(user):

    entry = log_action(
        "CASE_CREATED",
        case_id=1,
        details="CASE-2026-0001 - Test",
        user_id=user.id,
        user_name=user.full_name,
    )

    saved = db.session.get(AuditLog, entry.id)

    assert saved.action == "CASE_CREATED"
    assert saved.user_name == "Test Investigator"
    assert saved.case_id == 1
    assert saved.created_at is not None


def test_entries_keep_their_order(user):

    for action in ("LOGIN", "CASE_CREATED", "EVIDENCE_UPLOADED"):
        log_action(action, user_id=user.id)

    rows = AuditLog.query.order_by(AuditLog.id).all()

    assert [r.action for r in rows] == [
        "LOGIN", "CASE_CREATED", "EVIDENCE_UPLOADED"
    ]


def test_unknown_action_still_has_a_label():

    label, _icon, _tone = action_meta("SOMETHING_NEW")

    assert label == "Something New"
