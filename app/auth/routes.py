import threading
import time

from flask import render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from . import auth
from app import db
from app.models import User
from app.config import Config
from app.utils.audit import log_action

# ------------------------------------------------------------------
# Simple brute-force protection (kept in memory, per IP + email).
# ------------------------------------------------------------------

_failures = {}
_failures_lock = threading.Lock()


def _key(email):

    return (request.remote_addr, email)


def _locked_seconds(email):

    """Seconds left on the lock for this IP + email (0 = not locked)."""

    with _failures_lock:

        entry = _failures.get(_key(email))

        if not entry:
            return 0

        count, first_time = entry

        window = Config.LOGIN_LOCKOUT_MINUTES * 60

        if time.time() - first_time > window:
            _failures.pop(_key(email), None)
            return 0

        if count >= Config.MAX_LOGIN_ATTEMPTS:
            return int(window - (time.time() - first_time)) + 1

        return 0


def _record_failure(email):

    with _failures_lock:

        count, first_time = _failures.get(_key(email), (0, time.time()))

        _failures[_key(email)] = (count + 1, first_time)

        return count + 1


def _clear_failures(email):

    with _failures_lock:
        _failures.pop(_key(email), None)



@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        wait = _locked_seconds(email)

        if wait:

            flash(
                "Too many failed attempts. Try again in {} minute(s)."
                .format(max(1, wait // 60 + (1 if wait % 60 else 0))),
                "danger"
            )

            return render_template("auth/login.html")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            _clear_failures(email)

            session.clear()
            session["user_id"] = user.id
            session["full_name"] = user.full_name
            session["email"] = user.email

            log_action(
                "LOGIN",
                details="Signed in from {}".format(request.remote_addr),
                user_id=user.id,
                user_name=user.full_name
            )

            flash("Login successful!", "success")

            return redirect(url_for("cases.dashboard"))

        attempts = _record_failure(email)

        log_action(
            "LOGIN_LOCKED" if attempts >= Config.MAX_LOGIN_ATTEMPTS
            else "LOGIN_FAILED",
            details="Failed sign-in for '{}' ({} attempt(s))".format(
                email[:80], attempts
            )
        )

        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html")


@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not full_name or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("auth/register.html")

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("auth.login"))

        hashed_password = generate_password_hash(password)

        user = User(
            full_name=full_name,
            email=email,
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please login.", "success")

        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth.route("/logout")
def logout():

    if session.get("user_id"):

        log_action(
            "LOGOUT",
            details="Signed out"
        )

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("auth.login"))
