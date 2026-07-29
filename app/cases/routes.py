from flask import render_template, request, redirect, url_for, flash
from . import cases
from app import db
from app.models.case import Case
from datetime import datetime


@cases.route("/")
def dashboard():

    all_cases = Case.query.all()

    return render_template(
        "cases/dashboard.html",
        cases=all_cases
    )


@cases.route("/create", methods=["GET", "POST"])
def create_case():

    if request.method == "POST":

        last_case = Case.query.order_by(
            Case.id.desc()
        ).first()


        if last_case:
            case_number = f"CASE-2026-{last_case.id+1:04d}"
        else:
            case_number = "CASE-2026-0001"


        new_case = Case(

            case_number=case_number,

            case_title=request.form["case_title"],

            investigator_name=request.form["investigator_name"],

            case_summary=request.form["case_summary"]

        )


        db.session.add(new_case)

        db.session.commit()


        return redirect(
            url_for("cases.dashboard")
        )


    return render_template(
        "cases/create_case.html"
    )