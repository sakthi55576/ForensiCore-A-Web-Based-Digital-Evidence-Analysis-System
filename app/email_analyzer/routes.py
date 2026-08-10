import os

from flask import render_template, request

from werkzeug.utils import secure_filename

from . import email

from .utils import (
    analyze_email,
    extract_eml_header,
    generate_file_hash
)


UPLOAD_FOLDER = "app/uploads"


# Create upload folder if not exists

if not os.path.exists(UPLOAD_FOLDER):

    os.makedirs(UPLOAD_FOLDER)



@email.route("/")
def upload():

    return render_template(
        "email/upload.html"
    )



@email.route("/analyze", methods=["POST"])
def analyze():


    email_data = None


    # Check .eml file upload

    if "email_file" in request.files:


        file = request.files["email_file"]


        if file.filename != "":


            filename = secure_filename(
                file.filename
            )


            upload_path = os.path.join(
                UPLOAD_FOLDER,
                filename
            )


            file.save(
                upload_path
            )


            # Extract header from .eml

            header_text = extract_eml_header(
                upload_path
            )


            email_data = analyze_email(
                header_text
            )


            # Evidence information

            email_data["File Name"] = filename


            email_data["File Hash"] = generate_file_hash(
                upload_path
            )


            email_data["Hash Algorithm"] = "SHA-256"



    # Header paste option

    if email_data is None:


        header_text = request.form.get(
            "email_header"
        )


        email_data = analyze_email(
            header_text
        )


        email_data["File Name"] = "Manual Header Input"


        email_data["File Hash"] = "Not Available"


        email_data["Hash Algorithm"] = "SHA-256"



    return render_template(

        "email/result.html",

        email_data=email_data

    )