"""Shared column types."""

from sqlalchemy.dialects.mysql import LONGTEXT

from app import db


def big_text():
    """
    Text column that becomes LONGTEXT on MySQL.

    Plain MySQL TEXT holds only 64 KB, which is too small for the
    JSON stored by the analyzers (browser history, headers, ...).
    """

    return db.Text().with_variant(
        LONGTEXT(),
        "mysql"
    )
