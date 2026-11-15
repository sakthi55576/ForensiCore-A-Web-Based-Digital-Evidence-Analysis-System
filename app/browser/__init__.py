from flask import Blueprint

browser = Blueprint(
    "browser",
    __name__,
    template_folder="../templates/browser"
)

from . import routes