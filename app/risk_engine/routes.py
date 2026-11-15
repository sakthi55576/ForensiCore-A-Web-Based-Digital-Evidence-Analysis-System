from flask import (
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from . import risk_engine

from app.models.case import Case
from app.utils.auth import login_required
from app.utils.evidence import get_owned_case_or_404
from .utils import build_case_risk


@risk_engine.route("/")
@login_required
def risk_dashboard():

    case_id = (
        request.args.get("case_id", type=int)
        or session.get("active_case_id")
    )

    if not case_id:

        cases = (
            Case.query
            .filter_by(user_id=session["user_id"])
            .order_by(Case.id.desc())
            .all()
        )

        return render_template(
            "risk_engine/result.html",
            case=None,
            cases=cases,
            risk=None
        )

    case = get_owned_case_or_404(case_id)

    session["active_case_id"] = case.id

    return render_template(
        "risk_engine/result.html",
        case=case,
        cases=[],
        risk=build_case_risk(case.id)
    )
