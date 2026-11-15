"""
Content-based file type detection.

The file extension is only a claim. ForensiCore reads the first bytes
(magic numbers) to decide what a file really is, then compares that
with what the extension claims.
"""

import os
import re

# ------------------------------------------------------------------
# Display information for every kind ForensiCore understands
# ------------------------------------------------------------------

KIND_INFO = {
    "image":           ("Image",                    "bi-file-earmark-image"),
    "email":           ("Email message (.eml)",     "bi-envelope"),
    "browser_history": ("Browser history database", "bi-globe2"),
    "sqlite":          ("SQLite database",          "bi-database"),
    "text":            ("Text / data file",         "bi-file-earmark-text"),
    "pdf":             ("PDF document",             "bi-file-earmark-pdf"),
    "archive":         ("Archive",                  "bi-file-earmark-zip"),
    "executable":      ("Executable program",       "bi-cpu"),
    "unknown":         ("Unknown binary",           "bi-file-earmark"),
}

# Which analyzer handles which kind
ANALYZER_FOR_KIND = {
    "image":           ("metadata.analyze", "Metadata Analyzer"),
    "email":           ("email.analyze",    "Email Analyzer"),
    "browser_history": ("browser.analyze",  "Browser Analyzer"),
}

# Extension -> the kind that extension CLAIMS to be
CLAIMED_KIND = {
    ".jpg": "image",
    ".jpeg": "image",
    ".png": "image",
    ".tif": "image",
    ".tiff": "image",
    ".eml": "email",
    ".db": "sqlite",
    ".sqlite": "sqlite",
    ".sqlite3": "sqlite",
    ".history": "sqlite",
    "": "sqlite",          # Chrome/Edge "History" has no extension
    ".csv": "text",
    ".txt": "text",
    ".json": "text",
    ".html": "text",
}

EMAIL_HEADER_RE = re.compile(
    rb"^(from|to|subject|date|received|return-path|delivered-to|"
    rb"message-id|mime-version|content-type|x-[\w-]+):",
    re.IGNORECASE | re.MULTILINE
)


def _read_head(file_path, size=8192):

    with open(file_path, "rb") as file:
        return file.read(size)


def _sqlite_tables(file_path):

    """Read-only, immutable open so evidence is never modified."""

    from app.utils.sqliteutil import open_readonly

    connection = None

    try:

        connection = open_readonly(file_path)

        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()

        return {row[0] for row in rows}

    except Exception:
        return set()

    finally:
        if connection:
            connection.close()


def _looks_like_text(head):

    if not head:
        return True

    if b"\x00" in head:
        return False

    printable = sum(
        1 for byte in head
        if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128
    )

    return printable / len(head) > 0.95


def detect_kind(file_path):

    """Return (kind, mime) based on file CONTENT only."""

    head = _read_head(file_path)

    # ---------------- images ----------------
    if head.startswith(b"\xff\xd8\xff"):
        return "image", "image/jpeg"

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image", "image/png"

    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "image", "image/tiff"

    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image", "image/gif"

    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image", "image/webp"

    if head.startswith(b"BM") and len(head) > 14 and _looks_like_text(head) is False:
        return "image", "image/bmp"

    # ---------------- sqlite ----------------
    if head.startswith(b"SQLite format 3\x00"):

        tables = _sqlite_tables(file_path)

        if "urls" in tables and "visits" in tables:
            return "browser_history", "application/x-browser-history"

        return "sqlite", "application/vnd.sqlite3"

    # ---------------- documents / archives / programs ----------------
    if head.startswith(b"%PDF-"):
        return "pdf", "application/pdf"

    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "archive", "application/zip"

    if head.startswith(b"Rar!"):
        return "archive", "application/vnd.rar"

    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "archive", "application/x-7z-compressed"

    if head.startswith(b"\x1f\x8b"):
        return "archive", "application/gzip"

    if head.startswith(b"MZ"):
        return "executable", "application/x-msdownload"

    if head.startswith(b"\x7fELF"):
        return "executable", "application/x-elf"

    # ---------------- text based ----------------
    if _looks_like_text(head):

        if len(EMAIL_HEADER_RE.findall(head)) >= 2:
            return "email", "message/rfc822"

        return "text", "text/plain"

    return "unknown", "application/octet-stream"


def detect_file_type(file_path, original_filename=""):

    """
    Full detection result.

    Returns a dict:
        kind, label, icon, mime,
        extension_mismatch (bool), note (str)
    """

    kind, mime = detect_kind(file_path)

    label, icon = KIND_INFO.get(kind, KIND_INFO["unknown"])

    extension = os.path.splitext(original_filename)[1].lower()

    claimed = CLAIMED_KIND.get(extension)

    mismatch = False
    note = ""

    if claimed:

        # A sqlite claim is satisfied by both plain sqlite
        # and browser-history databases.
        satisfied = (
            kind == claimed
            or (claimed == "sqlite" and kind == "browser_history")
            or (claimed == "text" and kind in ("text", "email"))
        )

        if not satisfied:

            mismatch = True

            note = (
                "The file extension '{}' suggests "
                "'{}', but the file content is '{}'."
            ).format(
                extension or "(none)",
                KIND_INFO.get(claimed, ("?",))[0],
                label
            )

    return {
        "kind": kind,
        "label": label,
        "icon": icon,
        "mime": mime,
        "extension_mismatch": mismatch,
        "note": note
    }
