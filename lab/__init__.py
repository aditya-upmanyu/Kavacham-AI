"""KAVACHAM LAB — backend package.

Isolated Flask Blueprint so Product A (KAVACHAM AI) stays untouched.
"""

from flask import Blueprint

lab_bp = Blueprint("lab", __name__, url_prefix="/lab")

from lab import routes  # noqa: E402,F401  (register routes on import)
