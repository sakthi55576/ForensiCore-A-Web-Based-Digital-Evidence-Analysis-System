from urllib.parse import quote_plus

from flask import Flask, session, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy

from app.config import Config

db = SQLAlchemy()


def create_app(test_config=None):

    app = Flask(__name__)

    # ==========================
    # Application Configuration
    # ==========================

    test_config = test_config or {}

    if (
        not test_config.get("SECRET_KEY")
        and (not Config.SECRET_KEY or len(Config.SECRET_KEY) < 16)
    ):

        raise RuntimeError(
            "SECRET_KEY is missing or too short. Copy .env.example "
            "to .env and set a long random value:\n"
            "  python -c \"import secrets; "
            "print(secrets.token_hex(32))\""
        )

    app.config["SECRET_KEY"] = Config.SECRET_KEY

    password = quote_plus(Config.MYSQL_PASSWORD or "")

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://"
        f"{Config.MYSQL_USER}:"
        f"{password}@"
        f"{Config.MYSQL_HOST}/"
        f"{Config.MYSQL_DATABASE}"
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["MAX_CONTENT_LENGTH"] = (
        Config.MAX_UPLOAD_MB * 1024 * 1024
    )

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Tests pass their own settings (e.g. an in-memory SQLite DB)
    app.config.update(test_config)

    # ==========================
    # Initialize Database
    # ==========================

    db.init_app(app)

    # ==========================
    # Security (CSRF on every POST)
    # ==========================

    from app.utils.auth import init_csrf

    init_csrf(app)

    # ==========================
    # Blueprints
    # ==========================

    from app.auth import auth
    from app.cases import cases
    from app.metadata_analyzer import metadata
    from app.email_analyzer import email
    from app.browser import browser
    from app.risk_engine import risk_engine
    from app.reports import reports

    app.register_blueprint(auth)
    app.register_blueprint(cases)
    app.register_blueprint(metadata)
    app.register_blueprint(email)
    app.register_blueprint(browser, url_prefix="/browser")
    app.register_blueprint(risk_engine)
    app.register_blueprint(reports)

    # ==========================
    # Database Models
    # ==========================

    from app import models  # noqa: F401  (registers every table)

    # ==========================
    # Create / upgrade database
    # ==========================

    with app.app_context():

        db.create_all()

        from app.utils.evidence import ensure_evidence_folder
        from app.utils.schema import ensure_schema

        ensure_evidence_folder()
        ensure_schema()

    # ==========================
    # Template helpers
    # ==========================

    from app.models.case import Case
    from app.utils.audit import action_meta
    from app.utils.evidence import analyzer_for, kind_icon

    @app.context_processor
    def inject_globals():

        active_case = None

        case_id = session.get("active_case_id")

        if case_id and session.get("user_id"):

            active_case = Case.query.filter_by(
                id=case_id,
                user_id=session["user_id"]
            ).first()

        return {
            "active_case": active_case,
            "analyzer_for": analyzer_for,
            "kind_icon": kind_icon,
            "action_meta": action_meta
        }

    @app.template_filter("utc")
    def format_utc(value):

        if not value:
            return "—"

        return value.strftime("%d %b %Y, %H:%M:%S") + " UTC"

    @app.template_filter("filesize")
    def format_filesize(size):

        size = size or 0

        if size >= 1024 * 1024:
            return "{:.2f} MB".format(size / (1024 * 1024))

        if size >= 1024:
            return "{:.1f} KB".format(size / 1024)

        return "{} B".format(size)

    @app.template_filter("shorthash")
    def short_hash(value):

        if not value:
            return "—"

        return "{}…{}".format(value[:10], value[-6:])

    # ==========================
    # Errors
    # ==========================

    @app.errorhandler(413)
    def too_large(error):

        flash(
            "The file is larger than the {} MB upload limit."
            .format(Config.MAX_UPLOAD_MB),
            "danger"
        )

        return redirect(request.referrer or url_for("cases.dashboard"))

    # ==========================
    # Home Route
    # ==========================

    @app.route("/")
    def home():

        if session.get("user_id"):
            return redirect(url_for("cases.dashboard"))

        return redirect(url_for("auth.login"))

    return app
