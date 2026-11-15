from flask import Blueprint


# ==========================================
# RISK ENGINE BLUEPRINT
# ==========================================

risk_engine = Blueprint(
    "risk_engine",
    __name__,
    url_prefix="/risk"
)


# ==========================================
# IMPORT ROUTES
# ==========================================

from . import routes