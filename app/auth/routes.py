from flask import render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from . import auth
from app import db
from app.models import User


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            session.clear()
            session["user_id"] = user.id
            session["full_name"] = user.full_name
            session["email"] = user.email

            flash("Login successful!", "success")

            return redirect(url_for("cases.dashboard"))

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

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("auth.login"))