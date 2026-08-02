import os

from flask import render_template, request

from . import email
from .utils import analyze_email


UPLOAD_FOLDER = "app/uploads"


@email.route("/")
def upload():

    return render_template("email/upload.html")


@email.route("/analyze", methods=["POST"])
def analyze():

    header_text = request.form["email_header"]

    email_data = analyze_email(header_text)

    return render_template(

        "email/result.html",

        email_data=email_data

    )