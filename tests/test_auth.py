from app.config import Config
from app.models import AuditLog

from conftest import csrf_token, login


def test_login_with_correct_password(client, user):

    response = login(client)

    assert response.status_code == 302

    with client.session_transaction() as session:
        assert session["user_id"] == user.id


def test_login_with_wrong_password_is_rejected(client, user):

    response = login(client, password="wrong")

    assert response.status_code == 200

    with client.session_transaction() as session:
        assert "user_id" not in session


def test_login_locks_after_too_many_failures(client, user):

    for _ in range(Config.MAX_LOGIN_ATTEMPTS):
        login(client, password="wrong")

    # even the CORRECT password is refused while locked
    login(client, password="correct-password")

    with client.session_transaction() as session:
        assert "user_id" not in session

    actions = [row.action for row in AuditLog.query.all()]

    assert "LOGIN_FAILED" in actions
    assert "LOGIN_LOCKED" in actions


def test_dashboard_needs_login(client):

    response = client.get("/")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_analyze_does_not_accept_get(client, user):

    login(client)

    for module in ("metadata", "email", "browser"):

        response = client.get("/{}/analyze/1".format(module))

        assert response.status_code == 405


def test_post_without_csrf_token_is_refused(client, user):

    login(client)

    response = client.post("/metadata/analyze/1")

    # redirected with a "security token" message, nothing was analysed
    assert response.status_code == 302
