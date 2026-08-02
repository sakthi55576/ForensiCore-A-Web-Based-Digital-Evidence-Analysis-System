from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import quote_plus

from app.config import Config

db = SQLAlchemy()


def create_app():

    app = Flask(__name__)

    app.config["SECRET_KEY"] = Config.SECRET_KEY

    password = quote_plus(Config.MYSQL_PASSWORD)

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://{Config.MYSQL_USER}:{password}@{Config.MYSQL_HOST}/{Config.MYSQL_DATABASE}"
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    # Authentication Module
    from app.auth import auth
    app.register_blueprint(auth)

    # Case Management Module
    from app.cases import cases
    app.register_blueprint(cases)

    from app.metadata_analyzer import metadata
    app.register_blueprint(metadata)  

    from app.email_analyzer import email
    app.register_blueprint(email)
    # Database Models
    from app.models import Evidence
    from app.models.metadata_analysis import MetadataAnalysis
    with app.app_context():
        db.create_all()

    @app.route("/")
    def home():
        return "ForensiCore is Running Successfully 🚀"

    return app