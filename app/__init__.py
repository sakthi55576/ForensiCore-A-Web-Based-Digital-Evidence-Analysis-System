from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import quote_plus

from app.config import Config


db = SQLAlchemy()


def create_app():

    app = Flask(__name__)


    # ==========================
    # Application Configuration
    # ==========================

    app.config["SECRET_KEY"] = Config.SECRET_KEY

    password = quote_plus(
        Config.MYSQL_PASSWORD
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://"
        f"{Config.MYSQL_USER}:"
        f"{password}@"
        f"{Config.MYSQL_HOST}/"
        f"{Config.MYSQL_DATABASE}"
    )

    app.config[
        "SQLALCHEMY_TRACK_MODIFICATIONS"
    ] = False


    # ==========================
    # Initialize Database
    # ==========================

    db.init_app(app)


    # ==========================
    # Authentication Module
    # ==========================

    from app.auth import auth

    app.register_blueprint(
        auth
    )


    # ==========================
    # Case Management Module
    # ==========================

    from app.cases import cases

    app.register_blueprint(
        cases
    )


    # ==========================
    # Metadata Analyzer Module
    # ==========================

    from app.metadata_analyzer import metadata

    app.register_blueprint(
        metadata
    )


    # ==========================
    # Email Analyzer Module
    # ==========================

    from app.email_analyzer import email

    app.register_blueprint(
        email
    )


    # ==========================
    # Browser History Analyzer
    # ==========================

    from app.browser import browser

    app.register_blueprint(
        browser,
        url_prefix="/browser"
    )


    # ==========================
    # Risk Engine Module
    # ==========================

    from app.risk_engine import risk_engine

    app.register_blueprint(
        risk_engine
    )


    # ==========================
    # Final Reports Module
    # ==========================

    from app.reports import reports

    app.register_blueprint(
        reports
    )


    # ==========================
    # Database Models
    # ==========================

    from app.models import Evidence

    from app.models.metadata_analysis import (
        MetadataAnalysis
    )


    # ==========================
    # Create Database Tables
    # ==========================

    with app.app_context():

        db.create_all()


    # ==========================
    # Home Route
    # ==========================

    @app.route("/")
    def home():

        return (
            "ForensiCore is Running "
            "Successfully 🚀"
        )


    return app