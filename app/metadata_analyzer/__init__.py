from flask import Blueprint

metadata = Blueprint(
    "metadata",
    __name__,
    url_prefix="/metadata"
)

from . import routes