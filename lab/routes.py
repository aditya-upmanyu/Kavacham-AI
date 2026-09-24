"""KAVACHAM LAB — HTTP routes.

Phase 3 (Lab shell) + Phase 4 (Command Center).

Response convention follows version2.txt Section 49:
    success -> {"success": true,  "data": ..., "meta": ...}
    error   -> {"success": false, "error": {"code", "message"}}

Product A's existing flat-JSON APIs are intentionally left untouched
(Section 48: follow the established convention, don't rewrite working APIs).
"""

import os
import time

from flask import jsonify, render_template, request

from lab import lab_bp
from lab import health as health_service


# ---------------------------------------------------------------------------
# Shared navigation model (Section 12)
# ---------------------------------------------------------------------------
# Only modules that actually exist are listed. Sections are added as their
# pages land, so the sidebar never contains dead navigation (Section 81).

NAV_STRUCTURE = [
    {
        "group": "COMMAND CENTER",
        "links": [
            {"id": "command-center", "label": "Command Center", "url": "/lab", "ready": True},
        ],
    },
]


def _nav_for(current_id):
    """Return nav structure with active flags applied."""
    out = []
    for group in NAV_STRUCTURE:
        links = []
        for item in group["links"]:
            clone = dict(item)
            clone["active"] = (item["id"] == current_id)
            links.append(clone)
        out.append({"group": group["group"], "links": links})
    return out


def _shell_context(**kwargs):
    """Base context shared by every Lab page."""
    ctx = {
        "nav": _nav_for(kwargs.pop("nav_id", None)),
        "system_status": None,
        "system_status_key": "unknown",
        "last_health_check": None,
        "health_error": None,
    }

    # Real backend timestamp + status for the header (Section 11).
    # Never fabricate these values.
    try:
        started = time.perf_counter()
        report = health_service.run_health_checks()
        data = report["data"]
        ctx["system_status"] = data["overall_status"]
        ctx["system_status_key"] = data["overall_status_key"]
        ctx["last_health_check"] = data["checked_at"]
        ctx["health_duration_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        ctx["health_summary"] = data["summary"]
    except Exception:
        ctx["system_status"] = "SERVICE UNAVAILABLE"
        ctx["system_status_key"] = "unavailable"
        ctx["last_health_check"] = None
        ctx["health_error"] = "HEALTH_CHECK_FAILED"

    ctx.update(kwargs)
    return ctx


def api_error(code, message, status=400):
    return jsonify({"success": False, "error": {"code": code, "message": message}}), status


def api_ok(data, meta=None, status=200):
    payload = {"success": True, "data": data}
    if meta is not None:
        payload["meta"] = meta
    return jsonify(payload), status


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@lab_bp.route("/", strict_slashes=False)
def command_center():
    return render_template("lab/command_center.html", **_shell_context(
        nav_id="command-center",
        page_title="Command Center",
    ))


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@lab_bp.route("/api/health")
def api_health():
    """Real per-service health (Section 51)."""
    try:
        report = health_service.run_health_checks()
    except Exception:
        return api_error("HEALTH_CHECK_FAILED",
                         "System health could not be determined.", 503)
    return api_ok(report["data"], report.get("meta"))


@lab_bp.route("/api/alerts")
def api_alerts():
    """Operational alerts derived from live backend conditions (Section 52)."""
    try:
        alerts = health_service.get_alerts()
    except Exception:
        return api_error("ALERT_QUERY_FAILED", "Alerts could not be retrieved.", 503)
    return api_ok({"alerts": alerts, "count": len(alerts)})


@lab_bp.route("/api/command-center")
def api_command_center():
    """Aggregate real Command Center data (Sections 13, 14, 51, 52, 63).

    Counts are only reported when a real query can produce them. While the
    persistence layer is absent, case/evidence counts are reported as null
    with an explicit availability flag — never fabricated zeroes.
    """
    from flask import session

    started = time.perf_counter()

    try:
        report = health_service.run_health_checks()
        health_data = report["data"]
    except Exception:
        return api_error("HEALTH_CHECK_FAILED",
                         "System health could not be determined.", 503)

    try:
        alerts = health_service.get_alerts()
    except Exception:
        alerts = []

    # --- Model health: real values from metrics.json, not guesses ---
    model_health = {"available": False, "metrics": None}
    try:
        import app as app_module
        metrics = getattr(app_module, "metrics_data", {}) or {}
        model_loaded = getattr(app_module, "model", None) is not None
        model_health = {
            "available": bool(model_loaded and metrics),
            "loaded": bool(model_loaded),
            "model_name": metrics.get("model_name"),
            "model_version": metrics.get("model_version"),
            "decision_threshold": getattr(app_module, "SPAM_DECISION_THRESHOLD", None),
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1_score": metrics.get("f1_score"),
            "false_positive_rate": metrics.get("false_positive_rate"),
            "hard_test_spam_recall": metrics.get("hard_test_spam_recall"),
            "trained_at": metrics.get("trained_at"),
            "source": "metrics.json",
        }
    except Exception:
        model_health = {"available": False, "loaded": False,
                        "error": "MODEL_METRICS_UNAVAILABLE"}

    # --- Case / evidence counts: only if the data layer exists ---
    db_path = os.path.join(health_service.BASE_DIR, "kavacham_lab.db")
    db_exists = os.path.exists(db_path)
    active_cases = None
    evidence_records = None
    if db_exists:
        try:
            import sqlite3
            conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=2.0)
            try:
                cur = conn.execute(
                    "SELECT count(*) FROM cases WHERE status NOT IN ('RESOLVED','ARCHIVED')")
                active_cases = cur.fetchone()[0]
                cur = conn.execute("SELECT count(*) FROM evidence")
                evidence_records = cur.fetchone()[0]
            finally:
                conn.close()
        except Exception:
            active_cases = None
            evidence_records = None

    # --- Recent analyses: real session history from Product A ---
    recent = []
    history_available = False
    try:
        history = session.get("analysis_history") or []
        history_available = True
        for item in history[:8]:
            recent.append({
                "id": item.get("id"),
                "subject": item.get("subject") or "(No Subject)",
                "classification": item.get("classification"),
                "risk_score": item.get("risk_score"),
                "timestamp": item.get("timestamp"),
                "type": item.get("type", "email"),
            })
    except Exception:
        history_available = False

    duration = (time.perf_counter() - started) * 1000.0

    return api_ok({
        "health": health_data,
        "alerts": alerts,
        "model_health": model_health,
        "counts": {
            "active_cases": active_cases,
            "evidence_records": evidence_records,
            "persistence_available": db_exists,
            "persistence_status": "OPERATIONAL" if db_exists else "NOT CONFIGURED",
        },
        "recent_analyses": {
            "items": recent,
            "count": len(recent) if history_available else None,
            "available": history_available,
        },
        "generated_at": health_service._now_iso(),
    }, {"duration_ms": round(duration, 2)})


@lab_bp.route("/api/meta")
def api_meta():
    """Static, non-fabricated reference data used by the shell."""
    return api_ok({
        "nav": NAV_STRUCTURE,
        "product": "KAVACHAM LAB",
        "subtitle": "Cyber Investigation & Threat Intelligence",
        "environment": "SECURE",
        "access_level": "RESTRICTED",
        "generated_at": health_service._now_iso(),
    })


@lab_bp.errorhandler(404)
def lab_not_found(_e):
    if request.path.startswith("/lab/api/"):
        return api_error("NOT_FOUND", "Resource not found.", 404)
    return api_error("NOT_FOUND", "Lab page not found.", 404)
