"""Login decorator, CSRF protection and safe-redirect helper."""

import hmac
import secrets
from functools import wraps
from urllib.parse import urlparse

from flask import (
    session,
    redirect,
    url_for,
    request,
    flash
)
from markupsafe import Markup


# ------------------------------------------------------------------
# Login required
# ------------------------------------------------------------------

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("auth.login")
            )

        return view(*args, **kwargs)

    return wrapped


# ------------------------------------------------------------------
# CSRF protection (every POST form carries a hidden token)
# ------------------------------------------------------------------

def csrf_token():

    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)

    return session["_csrf"]


def csrf_input():

    return Markup(
        '<input type="hidden" name="csrf_token" value="{}">'
        .format(csrf_token())
    )


def init_csrf(app):

    app.jinja_env.globals.update(
        csrf_token=csrf_token,
        csrf_input=csrf_input
    )

    @app.before_request
    def protect_post_requests():

        if request.method not in (
            "POST", "PUT", "PATCH", "DELETE"
        ):
            return None

        sent = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or ""
        )

        expected = session.get("_csrf", "")

        if not expected or not hmac.compare_digest(
            sent, expected
        ):

            flash(
                "Your security token was missing or expired. "
                "Please try again.",
                "danger"
            )

            return redirect(
                safe_next(request.referrer)
                or url_for("auth.login")
            )

        return None


# ------------------------------------------------------------------
# Only allow redirects to pages inside this application
# ------------------------------------------------------------------

def safe_next(target):

    if not target:
        return None

    parsed = urlparse(target)

    # Allow same-site absolute URLs and plain relative paths
    if parsed.netloc and parsed.netloc != request.host:
        return None

    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return None

    path = parsed.path or "/"

    if not path.startswith("/") or path.startswith("//"):
        return None

    return (
        path
        + ("?" + parsed.query if parsed.query else "")
        + ("#" + parsed.fragment if parsed.fragment else "")
    )
