from flask import Blueprint

cases = Blueprint(
    "cases",
    __name__,
    url_prefix="/cases"
)

from . import routes