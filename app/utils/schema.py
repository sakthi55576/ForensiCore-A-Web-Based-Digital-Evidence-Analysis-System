"""
Automatic, safe database upgrade.

`db.create_all()` creates missing TABLES but never adds new columns to
tables that already exist. When ForensiCore starts against an older
database this module:

    1. adds the new evidence-integrity columns
    2. widens the analyzer JSON columns to LONGTEXT (MySQL)
    3. records a hash baseline for evidence uploaded before this
       version (marked "Post-hoc" so it is never mistaken for a
       hash taken at acquisition time)

It is idempotent - running it again changes nothing.
"""

import os

from sqlalchemy import inspect, text

from app import db
from app.config import Config


NEW_EVIDENCE_COLUMNS = [
    ("uploaded_by",        "INTEGER NULL"),
    ("detected_type",      "VARCHAR(30) NULL"),
    ("detected_label",     "VARCHAR(80) NULL"),
    ("extension_mismatch", "BOOLEAN DEFAULT 0"),
    ("md5_hash",           "VARCHAR(32) NULL"),
    ("sha256_hash",        "VARCHAR(64) NULL"),
    ("hash_baseline",      "VARCHAR(20) NULL"),
    ("hash_recorded_at",   "DATETIME NULL"),
    ("integrity_status",   "VARCHAR(20) NULL"),
    ("last_verified_at",   "DATETIME NULL"),
]

LONGTEXT_COLUMNS = {
    "browser_analysis": [
        "history_data", "top_sites", "timeline",
        "risk_data", "findings"
    ],
    "email_analysis": ["analysis_data", "findings"],
    "metadata_analysis": ["metadata_data", "observations"],
}


def ensure_schema():

    try:

        inspector = inspect(db.engine)

        tables = inspector.get_table_names()

        # ---------------- evidence columns ----------------

        if "evidence" in tables:

            existing = {
                column["name"]
                for column in inspector.get_columns("evidence")
            }

            for name, ddl in NEW_EVIDENCE_COLUMNS:

                if name not in existing:

                    db.session.execute(
                        text(
                            "ALTER TABLE evidence "
                            "ADD COLUMN {} {}".format(name, ddl)
                        )
                    )

                    print("Schema: added evidence.{}".format(name))

            db.session.commit()

        # ---------------- MySQL LONGTEXT ----------------

        if db.engine.dialect.name == "mysql":

            for table, columns in LONGTEXT_COLUMNS.items():

                if table not in tables:
                    continue

                current = {
                    column["name"]: column["type"]
                    for column in inspector.get_columns(table)
                }

                for column in columns:

                    column_type = current.get(column)

                    if (
                        column_type is not None
                        and type(column_type).__name__ == "TEXT"
                    ):

                        db.session.execute(
                            text(
                                "ALTER TABLE {} MODIFY COLUMN "
                                "{} LONGTEXT NULL".format(
                                    table, column
                                )
                            )
                        )

                        print(
                            "Schema: widened {}.{} to LONGTEXT"
                            .format(table, column)
                        )

            db.session.commit()

        _backfill_existing_evidence()

    except Exception as error:

        db.session.rollback()

        print("Schema upgrade warning:", error)


def _backfill_existing_evidence():

    from app.models.case import Case
    from app.models.evidence import Evidence
    from app.utils.audit import log_action
    from app.utils.evidence import evidence_path, lock_file
    from app.utils.filetype import detect_file_type
    from app.utils.hashing import compute_hashes
    from app.utils.timeutil import utcnow

    pending = (
        Evidence.query
        .filter(
            (Evidence.sha256_hash.is_(None))
            | (Evidence.detected_type.is_(None))
        )
        .all()
    )

    if not pending:
        return

    for evidence in pending:

        path = evidence_path(evidence)

        if not os.path.exists(path):

            evidence.integrity_status = "Missing"
            continue

        changed_hash = False

        if not evidence.sha256_hash:

            hashes = compute_hashes(path)

            evidence.md5_hash = hashes["md5"]
            evidence.sha256_hash = hashes["sha256"]
            evidence.hash_baseline = "Post-hoc"
            evidence.hash_recorded_at = utcnow()
            evidence.integrity_status = "Verified"
            evidence.last_verified_at = utcnow()

            changed_hash = True

        if not evidence.detected_type:

            detected = detect_file_type(
                path,
                evidence.original_filename
            )

            evidence.detected_type = detected["kind"]
            evidence.detected_label = detected["label"]
            evidence.extension_mismatch = detected[
                "extension_mismatch"
            ]
            evidence.file_type = detected["mime"]

        if evidence.uploaded_by is None:

            case = db.session.get(Case, evidence.case_id)

            if case:
                evidence.uploaded_by = case.user_id

        lock_file(path)

        db.session.commit()

        if changed_hash:

            log_action(
                "HASH_BASELINE",
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                details=(
                    "Post-hoc baseline recorded during upgrade. "
                    "sha256={}"
                ).format(evidence.sha256_hash),
                user_id=evidence.uploaded_by,
                user_name="System upgrade"
            )

    db.session.commit()

    print(
        "Schema: hash baseline recorded for {} existing "
        "evidence file(s).".format(len(pending))
    )
