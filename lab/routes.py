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
from functools import wraps

from flask import jsonify, render_template, request, send_file

from lab import lab_bp
from lab import health as health_service
from lab import case_service
from lab import db as lab_db
from lab import evidence_service
from lab import analysis_service
from lab import intel_service
from lab import risk_service
from lab import report_service
from lab import search_service
from lab import security
from lab import obs

obs.init_blueprint(lab_bp)


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
        "group": "ANALYSIS",
        "links": [
            {"id": "analysis-workbench", "label": "Analysis Workbench", "url": "/lab/analysis", "ready": True},
            {"id": "run-analysis", "label": "Run Analysis", "url": "/lab/analysis/new", "ready": True},
        ],
    },
    {
        "group": "THREAT INTELLIGENCE",
        "links": [
            {"id": "ioc-intelligence", "label": "IOC Intelligence", "url": "/lab/intel/iocs", "ready": True},
            {"id": "bulk-ioc", "label": "Bulk IOC", "url": "/lab/intel/bulk", "ready": True},
        ],
    },
    {
        "group": "INTELLIGENCE",
        "links": [
            {"id": "correlation", "label": "Correlation", "url": "/lab/intel/correlation", "ready": True},
            {"id": "attack-chains", "label": "Attack Chains", "url": "/lab/intel/attack-chains", "ready": True},
            {"id": "entity-graph", "label": "Entity Graph", "url": "/lab/intel/graph", "ready": True},
            {"id": "risk-assessment", "label": "Risk Assessment", "url": "/lab/risk", "ready": True},
        ],
    },
    {
        "group": "REPORTING",
        "links": [
            {"id": "investigation-reports", "label": "Investigation Reports", "url": "/lab/reports", "ready": True},
            {"id": "export-center", "label": "Export Center", "url": "/lab/reports/exports", "ready": True},
            {"id": "evidence-manifest", "label": "Evidence Manifest", "url": "/lab/reports/manifest", "ready": True},
        ],
    },
    {
        "group": "SYSTEM",
        "links": [
            {"id": "system-health", "label": "System Health", "url": "/lab/health", "ready": True},
            {"id": "settings", "label": "Settings", "url": "/lab/settings", "ready": True},
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
        "current_role": security.current_role(),
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


def _require_permission(permission):
    """Server-side RBAC gate (version2.txt BI).

    Frontend hiding is NOT authorization: every mutating API is gated here
    by the current role's effective permissions. With no login surface the
    current role resolves to the default ANALYST through
    security.current_role(); the check itself always runs.
    """

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not security.authorize(security.current_role(), permission):
                return api_error(
                    "FORBIDDEN",
                    "Current role lacks the required permission (%s)."
                    % permission, 403)
            return fn(*args, **kwargs)

        return wrapper

    return deco


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
# Phase 13 — Health & Observability pages (Sections BO/BP)
# ---------------------------------------------------------------------------

@lab_bp.route("/health", strict_slashes=False)
def system_health_page():
    return render_template("lab/health.html", **_shell_context(
        nav_id="system-health",
        page_title="System Health",
    ))


@lab_bp.route("/settings", strict_slashes=False)
def settings_page():
    return render_template("lab/settings.html", **_shell_context(
        nav_id="settings",
        page_title="Settings",
    ))


@lab_bp.route("/api/providers")
def api_providers():
    """Provider configuration states for Settings (BP). Booleans only."""
    try:
        providers = health_service.provider_statuses()
    except Exception:
        return api_error("PROVIDER_STATUS_FAILED",
                         "Provider status could not be determined.", 503)
    return api_ok({"providers": providers, "count": len(providers)})


@lab_bp.route("/api/search")
def api_search():
    """Global command search (Section O): grouped, capped, linkable."""
    from flask import request
    try:
        data = search_service.search(
            (request.args.get("q") or ""),
            only=(request.args.get("type") or "").strip().lower() or None)
    except Exception:
        return api_error("SEARCH_FAILED", "Search could not be completed.", 500)
    return api_ok(data)


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
# Analysis pages (Sections 29-41)
# ---------------------------------------------------------------------------

@lab_bp.route("/analysis", strict_slashes=False)
def analysis_workbench_page():
    return render_template("lab/analysis.html", **_shell_context(
        nav_id="analysis-workbench",
        page_title="Analysis Workbench",
        types=analysis_service.ANALYSIS_TYPES,
        registry=analysis_service.ANALYSIS_REGISTRY,
    ))


@lab_bp.route("/analysis/new", strict_slashes=False)
def analysis_run_page():
    return render_template("lab/analysis_new.html", **_shell_context(
        nav_id="run-analysis",
        page_title="Run Analysis",
        types=analysis_service.ANALYSIS_TYPES,
        registry=analysis_service.ANALYSIS_REGISTRY,
        evidence_types=evidence_service.EVIDENCE_TYPES,
    ))


@lab_bp.route("/analysis/<analysis_ref>", strict_slashes=False)
def analysis_detail_page(analysis_ref):
    return render_template("lab/analysis_detail.html", **_shell_context(
        nav_id="analysis-workbench",
        page_title=analysis_ref,
        analysis_ref=analysis_ref,
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
@_require_permission("case:create")
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
@_require_permission("case:update")
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
@_require_permission("case:update")
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
@_require_permission("evidence:create")
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
@_require_permission("evidence:verify")
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
# API — analysis (Sections 29-41, 48)
# ---------------------------------------------------------------------------

def _analysis_error(exc):
    status = getattr(exc, "status", 400)
    return api_error(exc.code, exc.message, status)


@lab_bp.route("/api/analysis/meta", methods=["GET"])
def api_analysis_meta():
    try:
        data = analysis_service.reference_data()
    except Exception:
        return api_error("ANALYSIS_META_FAILED",
                         "Analysis registry could not be retrieved.", 500)
    return api_ok(data)


@lab_bp.route("/api/analysis", methods=["GET"])
def api_analysis_list():
    from flask import request
    try:
        data = analysis_service.list_analyses(
            case_ref=(request.args.get("case") or "").strip() or None,
            evidence_ref=(request.args.get("evidence") or "").strip() or None,
            analysis_type=(request.args.get("type") or "").strip() or None,
            status=(request.args.get("status") or "").strip() or None,
            search=(request.args.get("q") or "").strip() or None,
            limit=request.args.get("limit", 50),
            offset=request.args.get("offset", 0))
    except Exception:
        return api_error("ANALYSIS_QUERY_FAILED",
                         "Analysis records could not be retrieved.", 500)
    return api_ok(data)


@lab_bp.route("/api/analysis", methods=["POST"])
@_require_permission("analysis:run")
def api_analysis_create():
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("INVALID_PAYLOAD", "A JSON body is required.", 400)
    try:
        analysis = analysis_service.run_analysis(
            (payload.get("evidence_ref") or "").strip(),
            (payload.get("analysis_type") or "").strip(),
            actor="analyst",
            ip_address=_client_ip())
    except analysis_service.AnalysisError as exc:
        return _analysis_error(exc)
    except Exception:
        return api_error("ANALYSIS_RUN_FAILED",
                         "The analysis could not be completed.", 500)
    return api_ok({"analysis": analysis}, status=201)


@lab_bp.route("/api/analysis/<analysis_ref>", methods=["GET"])
def api_analysis_get(analysis_ref):
    try:
        analysis = analysis_service.get_analysis(analysis_ref)
    except analysis_service.AnalysisError as exc:
        return _analysis_error(exc)
    except Exception:
        return api_error("ANALYSIS_READ_FAILED",
                         "The analysis record could not be retrieved.", 500)
    return api_ok({"analysis": analysis})


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
    # The configured database path (env override aware), never a guess.
    db_path = lab_db.DB_PATH
    db_exists = os.path.exists(db_path)
    active_cases = None
    evidence_records = None
    high_risk_findings = None
    unreviewed_evidence = None
    ioc_alerts = None
    integrity_alerts = None
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
                # --- BQ mission-board tiles: real queries, never fabricated ---
                cur = conn.execute(
                    "SELECT count(*) FROM cases WHERE "
                    "(risk_score IS NOT NULL AND risk_score >= 61) "
                    "OR risk_level = 'HIGH'")
                high_risk_findings = cur.fetchone()[0]
                cur = conn.execute(
                    "SELECT count(*) FROM evidence e WHERE NOT EXISTS "
                    "(SELECT 1 FROM analyses a "
                    "WHERE a.evidence_id = e.evidence_id)")
                unreviewed_evidence = cur.fetchone()[0]
                cur = conn.execute(
                    "SELECT count(*) FROM alerts WHERE "
                    "title LIKE '%IOC%' OR message LIKE '%IOC%' "
                    "OR source LIKE '%IOC%'")
                ioc_alerts = cur.fetchone()[0]
                cur = conn.execute(
                    "SELECT count(*) FROM evidence "
                    "WHERE integrity_state != 'VERIFIED'")
                integrity_alerts = cur.fetchone()[0]
            finally:
                conn.close()
        except Exception:
            active_cases = None
            evidence_records = None
            high_risk_findings = None
            unreviewed_evidence = None
            ioc_alerts = None
            integrity_alerts = None

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

    # --- BQ: provider alerts = integration services not OPERATIONAL ---
    provider_alerts = None
    try:
        provider_alerts = sum(
            1 for svc in health_data.get("services", [])
            if svc.get("group") == "integration"
            and svc.get("status_key") != "operational")
    except Exception:
        provider_alerts = None

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
        "operations": {
            "available": db_exists,
            "active_investigations": active_cases,
            "high_risk_findings": high_risk_findings,
            "unreviewed_evidence": unreviewed_evidence,
            "ioc_alerts": ioc_alerts,
            "provider_alerts": provider_alerts,
            "integrity_alerts": integrity_alerts,
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


# ---------------------------------------------------------------------------
# Phase 8 — intelligence pages (Sections 24-28)
# ---------------------------------------------------------------------------

@lab_bp.route("/intel/iocs", strict_slashes=False)
def intel_iocs_page():
    return render_template("lab/intel_iocs.html", **_shell_context(
        nav_id="ioc-intelligence",
        page_title="IOC Intelligence",
        intel_types=intel_service.IOC_TYPES,
    ))


@lab_bp.route("/intel/bulk", strict_slashes=False)
def intel_bulk_page():
    return render_template("lab/intel_bulk.html", **_shell_context(
        nav_id="bulk-ioc",
        page_title="Bulk IOC Investigation",
    ))


@lab_bp.route("/intel/correlation", strict_slashes=False)
def intel_correlation_page():
    return render_template("lab/intel_correlation.html", **_shell_context(
        nav_id="correlation",
        page_title="Cross-Case Correlation",
    ))


@lab_bp.route("/intel/attack-chains", strict_slashes=False)
def intel_chains_page():
    return render_template("lab/intel_chains.html", **_shell_context(
        nav_id="attack-chains",
        page_title="Attack Chains",
    ))


@lab_bp.route("/intel/graph", strict_slashes=False)
def intel_graph_page():
    return render_template("lab/intel_graph.html", **_shell_context(
        nav_id="entity-graph",
        page_title="Entity Graph",
    ))


# ---------------------------------------------------------------------------
# Phase 8 — intelligence APIs (Sections 26-28)
# ---------------------------------------------------------------------------

@lab_bp.route("/api/intel/iocs", methods=["GET"])
def api_intel_iocs():
    try:
        data = intel_service.list_iocs(
            search=(request.args.get("q") or "").strip() or None,
            ioc_type=(request.args.get("type") or "").strip() or None,
            case_ref=(request.args.get("case") or "").strip() or None,
            status=(request.args.get("status") or "").strip() or None,
            limit=request.args.get("limit", 100),
            offset=request.args.get("offset", 0))
    except Exception:
        return api_error("IOC_QUERY_FAILED",
                         "Indicators could not be retrieved.", 500)
    return api_ok(data)


@lab_bp.route("/api/intel/iocs/<int:ioc_id>", methods=["GET"])
def api_intel_ioc_get(ioc_id):
    try:
        data = intel_service.get_ioc(ioc_id)
    except intel_service.IntelError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("IOC_READ_FAILED",
                         "The indicator could not be retrieved.", 500)
    return api_ok({"ioc": data})


@lab_bp.route("/api/intel/iocs/<int:ioc_id>", methods=["PATCH"])
@_require_permission("intel:update")
def api_intel_ioc_patch(ioc_id):
    payload = request.get_json(silent=True) or {}
    status = (payload.get("status") or "").strip()
    try:
        data = intel_service.set_ioc_status(
            ioc_id, status, actor="analyst", ip_address=_client_ip())
    except intel_service.IntelError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("IOC_UPDATE_FAILED",
                         "The indicator could not be updated.", 500)
    return api_ok({"ioc": data})


@lab_bp.route("/api/intel/iocs/<int:ioc_id>/cases", methods=["POST"])
@_require_permission("intel:update")
def api_intel_ioc_add_case(ioc_id):
    payload = request.get_json(silent=True) or {}
    case_ref = (payload.get("case_ref") or "").strip()
    try:
        data = intel_service.add_ioc_to_case(
            ioc_id, case_ref, actor="analyst", ip_address=_client_ip())
    except intel_service.IntelError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("IOC_LINK_FAILED",
                         "The indicator could not be linked.", 500)
    return api_ok({"ioc": data}, status=201)


@lab_bp.route("/api/intel/sync", methods=["POST"])
@_require_permission("intel:sync")
def api_intel_sync():
    try:
        data = intel_service.sync_iocs(actor="analyst",
                                       ip_address=_client_ip())
    except Exception:
        return api_error("IOC_SYNC_FAILED",
                         "The vault scan could not be completed.", 500)
    return api_ok(data)


@lab_bp.route("/api/intel/bulk/preview", methods=["POST"])
def api_intel_bulk_preview():
    """Bulk IOC preview (AN): extract + count, read-only, never persists."""
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("INVALID_PAYLOAD", "A JSON body is required.", 400)
    try:
        data = intel_service.bulk_preview(payload.get("text") or "")
    except Exception:
        return api_error("BULK_PREVIEW_FAILED",
                         "The pasted text could not be scanned.", 500)
    return api_ok(data)


@lab_bp.route("/api/intel/bulk/investigate", methods=["POST"])
@_require_permission("case:create")
def api_intel_bulk_investigate():
    """Bulk IOC investigate (AN): case + MESSAGE evidence + ledger sync."""
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("INVALID_PAYLOAD", "A JSON body is required.", 400)
    try:
        data = intel_service.bulk_investigate(
            payload.get("text") or "",
            title=payload.get("title"),
            case_type=payload.get("case_type") or "OTHER",
            actor="analyst", ip_address=_client_ip())
    except intel_service.IntelError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("BULK_INVESTIGATE_FAILED",
                         "The bulk investigation could not be opened.", 500)
    return api_ok(data, status=201)


@lab_bp.route("/api/intel/correlation", methods=["GET"])
def api_intel_correlation():
    try:
        data = intel_service.correlation()
    except Exception:
        return api_error("CORRELATION_FAILED",
                         "Correlation could not be computed.", 500)
    return api_ok(data)


@lab_bp.route("/api/intel/graph", methods=["GET"])
def api_intel_graph():
    try:
        data = intel_service.entity_graph(
            (request.args.get("case") or "").strip() or None)
    except intel_service.IntelError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("GRAPH_FAILED",
                         "The entity graph could not be built.", 500)
    return api_ok(data)


@lab_bp.route("/api/intel/attack-chain", methods=["GET"])
def api_intel_chain():
    try:
        data = intel_service.attack_chain(
            (request.args.get("case") or "").strip() or None)
    except intel_service.IntelError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("CHAIN_FAILED",
                         "The attack chain could not be derived.", 500)
    return api_ok(data)


@lab_bp.route("/api/intel/network", methods=["GET"])
def api_intel_network():
    """Keyless DNS + RDAP lookup for one domain (AG). Never raises."""
    from lab import network_intel
    domain = (request.args.get("domain") or "").strip().lower()
    if not domain:
        return api_error("VALIDATION_FAILED", "domain is required.")
    try:
        data = network_intel.lookup(domain)
    except Exception:
        return api_error("NETWORK_LOOKUP_FAILED",
                         "Network intelligence is unavailable.", 500)
    return api_ok(data)


# ---------------------------------------------------------------------------
# Phase 9 — central risk engine (Sections AZ, BA)
# ---------------------------------------------------------------------------

@lab_bp.route("/risk", strict_slashes=False)
def risk_page():
    return render_template("lab/risk.html", **_shell_context(
        nav_id="risk-assessment",
        page_title="Risk Assessment",
        risk_levels=risk_service.RISK_LEVELS,
    ))


@lab_bp.route("/api/risk")
def api_risk():
    """Risk register (?case= omitted) or one case's full assessment."""
    case_ref = (request.args.get("case") or "").strip() or None
    try:
        data = (risk_service.case_risk(case_ref) if case_ref
                else risk_service.risk_register())
    except risk_service.RiskError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("RISK_COMPUTE_FAILED",
                         "Risk could not be computed.", 500)
    return api_ok(data)


# ---------------------------------------------------------------------------
# Phase 10/11 — reporting (Sections 42, 43, 69, 70, BF, BG)
# ---------------------------------------------------------------------------

@lab_bp.route("/reports", strict_slashes=False)
def reports_page():
    return render_template("lab/reports.html", **_shell_context(
        nav_id="investigation-reports",
        page_title="Investigation Reports",
        report_sections=report_service.REPORT_SECTIONS,
    ))


@lab_bp.route("/reports/<report_ref>", strict_slashes=False)
def report_detail_page(report_ref):
    return render_template("lab/report_detail.html", **_shell_context(
        nav_id="investigation-reports",
        page_title=report_ref,
        report_ref=report_ref,
    ))


@lab_bp.route("/reports/exports", strict_slashes=False)
def export_center_page():
    return render_template("lab/export_center.html", **_shell_context(
        nav_id="export-center",
        page_title="Export Center",
    ))


@lab_bp.route("/reports/manifest", strict_slashes=False)
def manifest_page():
    return render_template("lab/manifest.html", **_shell_context(
        nav_id="evidence-manifest",
        page_title="Evidence Manifest",
    ))


@lab_bp.route("/api/reports", methods=["GET"])
def api_reports_list():
    case_ref = (request.args.get("case") or "").strip() or None
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    try:
        data = report_service.list_reports(case_ref=case_ref, limit=limit,
                                           offset=offset)
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("REPORT_QUERY_FAILED",
                         "Reports could not be listed.", 500)
    return api_ok(data)


@lab_bp.route("/api/reports", methods=["POST"])
@_require_permission("report:create")
def api_reports_generate():
    payload = request.get_json(silent=True) or {}
    case_ref = (payload.get("case_ref") or "").strip()
    if not case_ref:
        return api_error("VALIDATION_FAILED", "case_ref is required.")
    try:
        data = report_service.generate_report(case_ref, actor="analyst",
                                              ip_address=_client_ip())
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("REPORT_GENERATION_FAILED",
                         "The report could not be generated.", 500)
    return api_ok(data, status=201)


@lab_bp.route("/api/reports/<report_ref>", methods=["GET"])
def api_reports_detail(report_ref):
    try:
        data = report_service.get_report(report_ref)
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("REPORT_READ_FAILED",
                         "The report could not be read.", 500)
    return api_ok(data)


@lab_bp.route("/api/reports/<report_ref>/csv", methods=["GET"])
def api_reports_csv(report_ref):
    """IOC table CSV export for the report's case (BF: CSV where appropriate)."""
    try:
        report = report_service.get_report(report_ref)
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    if not report.get("content"):
        return api_error("REPORT_CONTENT_UNAVAILABLE",
                         "The report content is unavailable.", 404)
    case_ref = report["content"]["case"]["case_ref"]
    csv_text = report_service.case_ioc_csv(case_ref)
    return (
        csv_text,
        200,
        {"Content-Type": "text/csv; charset=utf-8",
         "Content-Disposition":
             "attachment; filename=%s-iocs.csv" % report_ref},
    )


@lab_bp.route("/api/cases/<case_ref>/export", methods=["POST"])
@_require_permission("report:export")
def api_case_export(case_ref):
    try:
        data = report_service.export_case(case_ref, actor="analyst",
                                          ip_address=_client_ip())
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("EXPORT_FAILED", "The export package could not be "
                         "created.", 500)
    return api_ok(data, status=201)


@lab_bp.route("/api/exports", methods=["GET"])
def api_exports_list():
    try:
        data = report_service.list_exports()
    except Exception:
        return api_error("EXPORT_QUERY_FAILED",
                         "Export packages could not be listed.", 500)
    return api_ok(data)


@lab_bp.route("/api/exports/<export_ref>", methods=["GET"])
def api_exports_detail(export_ref):
    try:
        data = report_service.get_export(export_ref)
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("EXPORT_READ_FAILED",
                         "The export package could not be read.", 500)
    return api_ok(data)


@lab_bp.route("/api/exports/<export_ref>/verify", methods=["POST"])
@_require_permission("report:verify")
def api_exports_verify(export_ref):
    try:
        data = report_service.verify_export(export_ref)
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    except Exception:
        return api_error("EXPORT_VERIFY_FAILED",
                         "The export package could not be verified.", 500)
    return api_ok(data)


@lab_bp.route("/api/exports/<export_ref>/download", methods=["GET"])
def api_exports_download(export_ref):
    try:
        data = report_service.get_export(export_ref)
    except report_service.ReportError as exc:
        return api_error(exc.code, exc.message)
    path = data.get("storage_path")
    if not data.get("file_present") or not path:
        return api_error("EXPORT_FILE_MISSING",
                         "The package file is missing.", 404)
    exports_root = os.path.abspath(report_service.EXPORTS_DIR)
    if not os.path.abspath(path).startswith(exports_root):
        return api_error("EXPORT_PATH_INVALID", "Invalid package path.", 400)
    return send_file(path, as_attachment=True,
                     download_name="%s.zip" % export_ref,
                     mimetype="application/zip")


@lab_bp.errorhandler(404)
def lab_not_found(_e):
    if request.path.startswith("/lab/api/"):
        return api_error("NOT_FOUND", "Resource not found.", 404)
    return api_error("NOT_FOUND", "Lab page not found.", 404)
