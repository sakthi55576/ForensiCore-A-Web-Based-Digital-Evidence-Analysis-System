"""
Read-only SQLite access for evidence files.

Opening an evidence database with the default sqlite3.connect() can
create journal / WAL files or touch the database, which would change
the file and therefore its hash. This helper opens it strictly
read-only and 'immutable', so analysis can never modify evidence.
"""

import sqlite3
from pathlib import Path


def open_readonly(file_path):

    uri = Path(file_path).resolve().as_uri()

    return sqlite3.connect(
        f"{uri}?mode=ro&immutable=1",
        uri=True
    )
