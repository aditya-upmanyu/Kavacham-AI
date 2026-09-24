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
from lab import case_service
from lab import evidence_service


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
    {
        "group": "INVESTIGATIONS",
        "links": [
            {"id": "active-cases", "label": "Active Cases", "url": "/lab/cases", "ready": True},
            {"id": "new-investigation", "label": "New Investigation", "url": "/lab/cases/new", "ready": True},
        ],
    },
    {
        "group": "EVIDENCE",
        "links": [
            {"id": "evidence-vault", "label": "Evidence Vault", "url": "/lab/evidence", "ready": True},
            {"id": "evidence-intake", "label": "Evidence Intake", "url": "/lab/evidence/new", "ready": True},
        ],
    },
    {
        "group": "SYSTEM",
        "links": [
            {"id": "audit-log", "label": "Audit Log", "url": "/lab/audit", "ready": True},
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
# Case pages (Sections 16, 17, 18)
# ---------------------------------------------------------------------------

@lab_bp.route("/cases", strict_slashes=False)
def case_list_page():
    return render_template("lab/cases.html", **_shell_context(
        nav_id="active-cases",
        page_title="Active Cases",
    ))


@lab_bp.route("/cases/new", strict_slashes=False)
def case_new_page():
    return render_template("lab/case_new.html", **_shell_context(
        nav_id="new-investigation",
        page_title="New Investigation",
        ref=case_service.reference_data(),
    ))


@lab_bp.route("/cases/<case_ref>", strict_slashes=False)
def case_detail_page(case_ref):
    return render_template("lab/case_detail.html", **_shell_context(
        nav_id="active-cases",
        page_title=case_ref,
        case_ref=case_ref,
    ))


@lab_bp.route("/audit", strict_slashes=False)
def audit_page():
    return render_template("lab/audit.html", **_shell_context(
        nav_id="audit-log",
        page_title="Audit Log",
    ))


# ---------------------------------------------------------------------------
# Evidence pages (Sections 19, 20)
# ---------------------------------------------------------------------------

@lab_bp.route("/evidence", strict_slashes=False)
def evidence_vault_page():
    return render_template("lab/evidence.html", **_shell_context(
        nav_id="evidence-vault",
        page_title="Evidence Vault",
    ))


@lab_bp.route("/evidence/new", strict_slashes=False)
def evidence_intake_page():
    return render_template("lab/evidence_new.html", **_shell_context(
        nav_id="evidence-intake",
        page_title="Evidence Intake",
        ref=evidence_service.reference_data(),
    ))


@lab_bp.route("/evidence/<evidence_ref>", strict_slashes=False)
def evidence_detail_page(evidence_ref):
    return render_template("lab/evidence_detail.html", **_shell_context(
        nav_id="evidence-vault",
        page_title=evidence_ref,
        evidence_ref=evidence_ref,
    ))


# ---------------------------------------------------------------------------
# API — cases (Section 48/49)
# ---------------------------------------------------------------------------

def _client_ip():
    from flask import request
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _case_error(exc):
    """Map a CaseError onto the Section 49 error envelope."""
    status = 404 if exc.code == "CASE_NOT_FOUND" else 400
    if exc.code == "INVALID_TRANSITION":
        status = 409
    return api_error(exc.code, exc.message, status)


@lab_bp.route("/api/cases", methods=["GET"])
def api_cases_list():
    from flask import request
    try:
        data = case_service.list_cases(
            status=(request.args.get("status") or "").strip() or None,
            priority=(request.args.get("priority") or "").strip() or None,
            case_type=(request.args.get("case_type") or "").strip() or None,
            search=(request.args.get("q") or "").strip() or None,
            limit=request.args.get("limit", 50),
            offset=request.args.get("offset", 0))
    except Exception:
        return api_error("CASE_QUERY_FAILED", "Cases could not be retrieved.", 500)
    return api_ok(data)


@lab_bp.route("/api/cases", methods=["POST"])
def api_cases_create():
    from flask import request
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("INVALID_PAYLOAD", "A JSON body is required.", 400)
    try:
        case = case_service.create_case(payload, ip_address=_client_ip())
    except case_service.CaseError as exc:
        return _case_error(exc)
    except Exception:
        return api_error("CASE_CREATE_FAILED", "The case could not be created.", 500)
    return api_ok({"case": case}, status=201)


@lab_bp.route("/api/cases/<case_ref>", methods=["GET"])
def api_cases_get(case_ref):
    try:
        case = case_service.get_case(case_ref)
    except case_service.CaseError as exc:
        return _case_error(exc)
    except Exception:
        return api_error("CASE_READ_FAILED", "The case could not be retrieved.", 500)
    return api_ok({"case": case})


@lab_bp.route("/api/cases/<case_ref>", methods=["PATCH"])
def api_cases_update(case_ref):
    from flask import request
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("INVALID_PAYLOAD", "A JSON body is required.", 400)
    try:
        case = case_service.update_case(case_ref, payload,
                                        ip_address=_client_ip())
    except case_service.CaseError as exc:
        return _case_error(exc)
    except Exception:
        return api_error("CASE_UPDATE_FAILED", "The case could not be updated.", 500)
    return api_ok({"case": case})


@lab_bp.route("/api/cases/<case_ref>/notes", methods=["POST"])
def api_cases_note(case_ref):
    from flask import request
    payload = request.get_json(silent=True) or {}
    try:
        note = case_service.add_note(case_ref, payload.get("body"),
                                     ip_address=_client_ip())
    except case_service.CaseError as exc:
        return _case_error(exc)
    except Exception:
        return api_error("NOTE_CREATE_FAILED", "The note could not be saved.", 500)
    return api_ok({"note": note}, status=201)


@lab_bp.route("/api/cases/meta", methods=["GET"])
def api_cases_meta():
    """Enum + transition reference data for the UI."""
    return api_ok(case_service.reference_data())


@lab_bp.route("/api/audit", methods=["GET"])
def api_audit():
    from flask import request
    try:
        data = case_service.list_audit(
            limit=request.args.get("limit", 100),
            action=(request.args.get("action") or "").strip() or None,
            target_ref=(request.args.get("target") or "").strip() or None)
    except Exception:
        return api_error("AUDIT_QUERY_FAILED", "Audit log could not be retrieved.", 500)
    return api_ok(data)


# ---------------------------------------------------------------------------
# API — evidence (Sections 19, 20, 22, 23, 48/49)
# ---------------------------------------------------------------------------

def _evidence_error(exc):
    """Map an EvidenceError onto the Section 49 error envelope."""
    status = getattr(exc, "status", 400)
    return api_error(exc.code, exc.message, status)


@lab_bp.route("/api/evidence", methods=["GET"])
def api_evidence_list():
    from flask import request
    try:
        data = evidence_service.list_evidence(
            case_ref=(request.args.get("case") or "").strip() or None,
            evidence_type=(request.args.get("type") or "").strip() or None,
            search=(request.args.get("q") or "").strip() or None,
            limit=request.args.get("limit", 50),
            offset=request.args.get("offset", 0))
    except Exception:
        return api_error("EVIDENCE_QUERY_FAILED", "Evidence records could not be retrieved.", 500)
    return api_ok(data)


@lab_bp.route("/api/evidence", methods=["POST"])
def api_evidence_create():
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("INVALID_PAYLOAD", "A JSON body is required.", 400)
    try:
        evidence = evidence_service.accept_evidence(
            payload, ip_address=_client_ip())
    except evidence_service.EvidenceError as exc:
        return _evidence_error(exc)
    except Exception:
        return api_error("EVIDENCE_CREATE_FAILED",
                         "The evidence could not be accepted.", 500)
    return api_ok({"evidence": evidence}, status=201)


@lab_bp.route("/api/evidence/meta", methods=["GET"])
def api_evidence_meta():
    """Accepted types and file-security limits for the intake form."""
    return api_ok(evidence_service.reference_data())


@lab_bp.route("/api/evidence/<evidence_ref>", methods=["GET"])
def api_evidence_get(evidence_ref):
    try:
        evidence_service.record_view(evidence_ref, actor="analyst")
        evidence = evidence_service.get_evidence(evidence_ref)
    except evidence_service.EvidenceError as exc:
        return _evidence_error(exc)
    except Exception:
        return api_error("EVIDENCE_READ_FAILED",
                         "The evidence record could not be retrieved.", 500)
    return api_ok({"evidence": evidence})


@lab_bp.route("/api/evidence/<evidence_ref>/custody", methods=["GET"])
def api_evidence_custody(evidence_ref):
    try:
        data = evidence_service.get_custody(evidence_ref)
    except evidence_service.EvidenceError as exc:
        return _evidence_error(exc)
    except Exception:
        return api_error("CUSTODY_QUERY_FAILED",
                         "Chain of custody could not be retrieved.", 500)
    return api_ok(data)


@lab_bp.route("/api/evidence/<evidence_ref>/verify", methods=["POST"])
def api_evidence_verify(evidence_ref):
    try:
        result = evidence_service.verify_integrity(evidence_ref)
    except evidence_service.EvidenceError as exc:
        return _evidence_error(exc)
    except Exception:
        return api_error("INTEGRITY_CHECK_FAILED",
                         "Integrity could not be verified.", 500)
    return api_ok({"verification": result})


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
