"""Shared test setup: a throw-away app with its own SQLite database."""

import pytest
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import Config
from app.models import User


@pytest.fixture
def app(tmp_path, monkeypatch):

    # Evidence / report files go to a temporary folder, never to app/uploads
    monkeypatch.setattr(
        Config, "EVIDENCE_UPLOAD_FOLDER", str(tmp_path / "evidence")
    )
    monkeypatch.setattr(
        Config, "REPORT_FOLDER", str(tmp_path / "reports")
    )

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-only-for-the-test-suite-1234",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///{}".format(
            tmp_path / "test.db"
        ),
    })

    # forget login failures left over from an earlier test
    from app.auth import routes as auth_routes
    auth_routes._failures.clear()

    with app.app_context():
        yield app
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(app):

    account = User(
        full_name="Test Investigator",
        email="inv@example.com",
        password=generate_password_hash("correct-password"),
    )

    db.session.add(account)
    db.session.commit()

    return account


def csrf_token(client):
    """Open the login page (this creates the CSRF token) and return it."""

    client.get("/login")

    with client.session_transaction() as session:
        return session["_csrf"]


def login(client, email="inv@example.com", password="correct-password"):

    return client.post(
        "/login",
        data={
            "email": email,
            "password": password,
            "csrf_token": csrf_token(client),
        },
    )
