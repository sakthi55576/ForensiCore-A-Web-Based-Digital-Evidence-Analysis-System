import os

from flask import render_template, request

from . import email

from .utils import (
    analyze_email,
    extract_eml_header
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


    header_text = ""



    # Check .eml file upload

    if "email_file" in request.files:


        file = request.files["email_file"]



        if file and file.filename.endswith(".eml"):


            file_path = os.path.join(

                UPLOAD_FOLDER,

                file.filename

            )


            file.save(file_path)



            header_text = extract_eml_header(

                file_path

            )




    # If no .eml file, use pasted header


    if not header_text:


        header_text = request.form.get(

            "email_header",

            ""

        )



    email_data = analyze_email(

        header_text

    )



    return render_template(

        "email/result.html",

        email_data=email_data

    )