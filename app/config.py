import os
from dotenv import load_dotenv

load_dotenv()

# ==========================================
# PROJECT PATHS
# ==========================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

UPLOAD_ROOT = os.path.join(
    BASE_DIR,
    "app",
    "uploads"
)


class Config:

    SECRET_KEY = os.getenv("SECRET_KEY")

    MYSQL_HOST = os.getenv("DB_HOST")
    MYSQL_USER = os.getenv("DB_USER")
    MYSQL_PASSWORD = os.getenv("DB_PASSWORD")
    MYSQL_DATABASE = os.getenv("DB_NAME")

    # ---------------------------------------
    # Evidence storage (single absolute path
    # used by every module)
    # ---------------------------------------

    EVIDENCE_UPLOAD_FOLDER = os.path.join(
        UPLOAD_ROOT,
        "evidence"
    )

    REPORT_FOLDER = os.path.join(
        UPLOAD_ROOT,
        "reports"
    )

    # Maximum evidence upload size (MB)
    MAX_UPLOAD_MB = int(
        os.getenv("MAX_UPLOAD_MB", "256")
    )

    # ---------------------------------------
    # Email analyzer: geolocate public sender
    # IPs using the external ipinfo.io service.
    # Set ENABLE_IP_LOOKUP=0 in .env to keep the
    # analysis fully offline.
    # ---------------------------------------

    ENABLE_IP_LOOKUP = (
        os.getenv("ENABLE_IP_LOOKUP", "0") == "1"
    )

    # ---------------------------------------
    # Photos store their capture time WITHOUT a
    # timezone. When correlating them with emails
    # and browser history (UTC) this offset is
    # assumed unless the photo states its own.
    # 330 = India Standard Time (UTC+05:30)
    # ---------------------------------------

    ASSUMED_LOCAL_UTC_OFFSET_MIN = int(
        os.getenv("ASSUMED_LOCAL_UTC_OFFSET_MIN", "330")
    )

    # Flask debug mode. OFF by default; set FLASK_DEBUG=1 in .env
    # only on your own machine while developing.
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    # ---------------------------------------
    # Login protection: after MAX_LOGIN_ATTEMPTS wrong passwords
    # the sign-in is locked for LOGIN_LOCKOUT_MINUTES.
    # ---------------------------------------

    MAX_LOGIN_ATTEMPTS = int(
        os.getenv("MAX_LOGIN_ATTEMPTS", "5")
    )

    LOGIN_LOCKOUT_MINUTES = int(
        os.getenv("LOGIN_LOCKOUT_MINUTES", "5")
    )
