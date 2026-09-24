"""
lab/report_service.py
=====================
KAVACHAM LAB — Phase 10/11 reporting (version2.txt 42, 43, 69, 70, BF, BG).

Investigation reports (KAV-RPT-2026-00001) built from the BF 15-section
structure, evidence manifests in the BG row shape, and deterministic
export packages (stdlib zipfile — no new dependencies) that can be
integrity-verified per Section 70.

Everything in a report is composed exclusively from stored records. Where
a provider or local stage was unavailable at analysis time the report says
so (Sections H, 63). No fake signatures, no implied certification (42/69).
"""

import csv
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timezone

from lab import db
from lab import intel_service
from lab import risk_service
from lab import case_service

# ---------------------------------------------------------------------------
# Storage + identifiers
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_ROOT = os.environ.get("KAVACHAM_LAB_STORAGE") or os.path.join(
    BASE_DIR, "lab_storage")
REPORTS_DIR = os.path.join(STORAGE_ROOT, "reports")
EXPORTS_DIR = os.path.join(STORAGE_ROOT, "exports")

ENGINE = "kavacham-reporting"
ENGINE_VERSION = "1.0.0"

# BF — report sections (order matters, matches the spec exactly).
REPORT_SECTIONS = [
    "Case Summary", "Executive Summary", "Incident Classification",
    "Evidence", "IOC Table", "Timeline", "Technical Findings",
    "Threat Intelligence", "ML Findings", "Correlation", "Risk Assessment",
    "Limitations", "Defensive Recommendations", "Evidence Manifest",
    "Report Metadata",
]

# Providers per version2.txt X/Y — reported honestly (configured or not).
PROVIDERS = [
    "VirusTotal", "AbuseIPDB", "Shodan", "Censys", "URLScan", "HaveIBeenPwned",
    "WebRisk", "RDAP", "DNS",
]

_VT_ENV = "VIRUSTOTAL_API_KEY"

_MAX_RECOMMENDATIONS = 6


class ReportError(Exception):
    """Error carrying a Section 49 error code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# References (real counters, same pattern as cases/evidence)
# ---------------------------------------------------------------------------

def _next_report_ref():
    year = datetime.now(timezone.utc).strftime("%Y")
    like = "KAV-RPT-%s-%%" % year
    row = db.query_one(
        "SELECT report_ref FROM reports WHERE report_ref LIKE ? "
        "ORDER BY report_ref DESC LIMIT 1", (like,))
    seq = 1
    if row:
        last = (row.get("report_ref") or "").rsplit("-", 1)[-1]
        if last.isdigit():
            seq = int(last) + 1
    return "KAV-RPT-%s-%05d" % (year, seq)


def _next_export_ref():
    year = datetime.now(timezone.utc).strftime("%Y")
    like = "KAV-EXP-%s-%%" % year
    row = db.query_one(
        "SELECT export_ref FROM export_packages WHERE export_ref LIKE ? "
        "ORDER BY export_ref DESC LIMIT 1", (like,))
    seq = 1
    if row:
        last = (row.get("export_ref") or "").rsplit("-", 1)[-1]
        if last.isdigit():
            seq = int(last) + 1
    return "KAV-EXP-%s-%05d" % (year, seq)


def _resolve_case(case_ref):
    if isinstance(case_ref, int) or (
            isinstance(case_ref, str) and case_ref.isdigit()):
        case = db.query_one("SELECT * FROM cases WHERE case_id = ?",
                            (int(case_ref),))
    else:
        case = db.query_one("SELECT * FROM cases WHERE case_ref = ?",
                            (str(case_ref),))
    if not case:
        raise ReportError("CASE_NOT_FOUND", "The requested case does not exist.")
    return case


# ---------------------------------------------------------------------------
# Stored-fact readers
# ---------------------------------------------------------------------------

def _evidence_rows(case_id):
    return db.query(
        "SELECT evidence_ref, evidence_type, title, sha256, original_filename, "
        "acquired_at, source FROM evidence WHERE case_id = ? "
        "ORDER BY acquired_at ASC", (case_id,))


def _analysis_rows(case_id):
    return db.query(
        "SELECT a.analysis_id, a.analysis_ref, a.analysis_type, a.status, "
        "a.verdict, a.risk_score, a.confidence, a.source, a.engine_version, "
        "a.payload_json, a.created_at, e.evidence_ref, e.sha256, "
        "e.acquired_at AS acquisition_time "
        "FROM analyses a LEFT JOIN evidence e ON a.evidence_id = e.evidence_id "
        "WHERE a.case_id = ? ORDER BY a.created_at ASC", (case_id,))


def _findings_for(analysis_id):
    return db.query(
        "SELECT finding_type, severity, title, detail, evidence_ref, source "
        "FROM analysis_findings WHERE analysis_id = ? "
        "ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 "
        "WHEN 'LOW' THEN 2 ELSE 3 END, finding_id", (analysis_id,))


def _ioc_rows(case_id):
    return db.query(
        "SELECT i.ioc_type, i.value, i.severity, i.status, i.source, "
        "i.first_seen, i.last_seen FROM iocs i "
        "JOIN case_iocs ci ON ci.ioc_id = i.ioc_id "
        "WHERE ci.case_id = ? ORDER BY i.ioc_type ASC, i.value ASC",
        (case_id,))


def _timeline_rows(case_id):
    return db.query(
        "SELECT event_type, title, detail, actor, source, occurred_at "
        "FROM timeline_events WHERE case_id = ? "
        "ORDER BY occurred_at ASC, event_id ASC", (case_id,))


def _intel_stage_counts(analysis_rows):
    """Honest count of how many analyses lacked external threat intel."""
    total = 0
    unavailable = 0
    for r in analysis_rows:
        total += 1
        try:
            payload = json.loads(r.get("payload_json") or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        for stage in payload.get("stages") or []:
            if (stage.get("name") == "Threat intelligence"
                    and stage.get("status") == "unavailable"):
                unavailable += 1
                break
    return total, unavailable


# ---------------------------------------------------------------------------
# Manifest rows (BG shape)
# ---------------------------------------------------------------------------

def manifest_rows(analysis_rows, export_ref=None):
    """One row per stored analysis in the BG shape."""
    rows = []
    for r in analysis_rows:
        rows.append({
            "case_id": None,          # filled by caller with the case ref
            "export_id": export_ref or "",
            "evidence_id": r.get("evidence_ref") or "",
            "analysis_id": r.get("analysis_ref") or "",
            "sha256": r.get("sha256") or "",
            "acquisition_time": r.get("acquisition_time") or "",
            "analysis_time": r.get("created_at") or "",
            "engine": r.get("engine_version") or "",
            "source": r.get("source") or "",
            "result": "%s (%s)" % (r.get("verdict") or "",
                                   r.get("risk_score") if r.get("risk_score")
                                   is not None else ""),
        })
    return rows


# ---------------------------------------------------------------------------
# Report content (BF 15 sections, all from stored facts)
# ---------------------------------------------------------------------------

def _executive_summary(case, evidence_rows, analysis_rows, ioc_rows, risk):
    lines = [
        "Case %s (%s) is %s with priority %s. Opened %s."
        % (case["case_ref"], case["case_type"], case["status"],
           case["priority"], case["created_at"]),
        "%d evidence item(s), %d analysis run(s) and %d indicator(s) are "
        "recorded for this case." % (len(evidence_rows),
                                     len(analysis_rows), len(ioc_rows)),
        "Central risk engine scores this case %d (%s)."
        % (risk["risk_score"], risk["risk_level"]),
    ]
    if risk["primary_classification"]:
        lines.append("Primary classification: %s."
                     % risk["primary_classification"])
    intel_t, intel_u = _intel_stage_counts(analysis_rows)
    if intel_u:
        lines.append("External threat intelligence was unavailable for %d of "
                     "%d analyses." % (intel_u, intel_t))
    return lines


def _recommendations(case, ioc_rows, risk):
    recs = []
    seen = set()
    for ioc in ioc_rows:
        if ioc["status"] == "VERIFIED" and ioc["value"] not in seen:
            seen.add(ioc["value"])
            recs.append(
                "Review verified indicator %s (%s) and apply blocking "
                "controls where the organisation's policy permits."
                % (ioc["value"], ioc["ioc_type"]))
    if risk["risk_level"] == "HIGH":
        recs.append("Containment is warranted: case %s is rated HIGH by the "
                    "central risk engine." % case["case_ref"])
    recs.append("Retain evidence and the custody chain per retention policy; "
                "original evidence must not be altered.")
    return recs[:_MAX_RECOMMENDATIONS]


def build_report_content(case_ref, report_ref=None):
    """Compose the BF 15-section report strictly from stored records."""
    case = _resolve_case(case_ref)
    case_id = case["case_id"]

    evidence_rows = _evidence_rows(case_id)
    analysis_rows = _analysis_rows(case_id)
    ioc_rows = _ioc_rows(case_id)
    timeline = _timeline_rows(case_id)
    intel_t, intel_u = _intel_stage_counts(analysis_rows)

    risk = risk_service.case_risk(case["case_ref"])

    # --- correlation: only rows touching this case's IOCs ---
    correlation = []
    try:
        all_corr = intel_service.correlation()
        my_ioc_ids = {r["ioc_id"] for r in db.query(
            "SELECT ioc_id FROM case_iocs WHERE case_id = ?", (case_id,))}
        correlation = [c for c in all_corr.get("correlations") or []
                       if c.get("ioc_id") in my_ioc_ids]
    except Exception:
        correlation = []

    vt_configured = bool(os.environ.get(_VT_ENV))
    providers = [
        {"provider": p, "status": "CONFIGURED" if (
            p == "VirusTotal" and vt_configured) else "NOT CONFIGURED"}
        for p in PROVIDERS]

    # --- technical findings (analysis findings, evidence-linked) ---
    technical_findings = []
    for r in analysis_rows:
        for f in _findings_for(r["analysis_id"]):
            technical_findings.append({
                "analysis_ref": r["analysis_ref"],
                "analysis_type": r["analysis_type"],
                "evidence_ref": r.get("evidence_ref"),
                "severity": f["severity"],
                "title": f["title"],
                "detail": f.get("detail"),
                "source": f.get("source"),
            })

    # --- ML findings (per-analysis verdicts) ---
    ml_findings = [{
        "analysis_ref": r["analysis_ref"],
        "analysis_type": r["analysis_type"],
        "verdict": r["verdict"],
        "status": r["status"],
        "risk_score": r["risk_score"],
        "confidence": r["confidence"],
        "source": r["source"],
        "engine_version": r["engine_version"],
        "created_at": r["created_at"],
        "evidence_ref": r.get("evidence_ref"),
    } for r in analysis_rows]

    manifest = manifest_rows(analysis_rows, export_ref="")
    for m in manifest:
        m["case_id"] = case["case_ref"]
    manifest.sort(key=lambda m: (m["analysis_id"], m["evidence_id"]))

    return {
        "report_ref": report_ref,
        "case": {
            "case_ref": case["case_ref"],
            "title": case["title"],
            "description": case.get("description"),
            "case_type": case["case_type"],
            "status": case["status"],
            "priority": case["priority"],
            "assigned_investigator": case.get("assigned_investigator"),
            "opened_at": case["created_at"],
            "updated_at": case["updated_at"],
        },
        "sections": REPORT_SECTIONS,
        # BF section payloads
        "case_summary": {
            "case_ref": case["case_ref"], "title": case["title"],
            "case_type": case["case_type"], "status": case["status"],
            "priority": case["priority"],
            "assigned_investigator": case.get("assigned_investigator"),
            "created_at": case["created_at"],
            "counts": {
                "evidence": len(evidence_rows),
                "analyses": len(analysis_rows),
                "iocs": len(ioc_rows),
                "timeline_events": len(timeline),
            },
        },
        "executive_summary": _executive_summary(
            case, evidence_rows, analysis_rows, ioc_rows, risk),
        "incident_classification": {
            "primary": risk["primary_classification"],
            "classifications": risk["classifications"],
        },
        "evidence": evidence_rows,
        "ioc_table": ioc_rows,
        "timeline": timeline,
        "technical_findings": technical_findings,
        "threat_intelligence": {
            "providers": providers,
            "analyses_total": intel_t,
            "analyses_without_intel": intel_u,
            "note": ("Threat intelligence was unavailable during "
                     "%d analysis run(s); absence of reputation data is not "
                     "proof of cleanliness." % intel_u) if intel_u else
                    "Threat intelligence was available for all local stages.",
        },
        "ml_findings": ml_findings,
        "correlation": correlation,
        "risk_assessment": {
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "primary_classification": risk["primary_classification"],
            "components": risk["components"],
            "explanations": risk["explanations"],
            "limitations": risk["limitations"],
        },
        "limitations": risk["limitations"],
        "defensive_recommendations": _recommendations(
            case, ioc_rows, risk),
        "evidence_manifest": manifest,
        "report_metadata": {
            "engine": ENGINE,
            "engine_version": ENGINE_VERSION,
            "generated_at": _now(),
            "sections": REPORT_SECTIONS,
        },
    }


def _write_json(dirpath, filename, data):
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, filename), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Reports CRUD
# ---------------------------------------------------------------------------

def generate_report(case_ref, actor="analyst", ip_address=None):
    """Create + persist a KAV-RPT report for a case (42/BF)."""
    case = _resolve_case(case_ref)
    report_ref = _next_report_ref()
    content = build_report_content(case["case_ref"], report_ref=report_ref)
    content["report_metadata"]["generated_at"] = _now()

    storage_name = "%s.json" % report_ref
    _write_json(REPORTS_DIR, storage_name, content)

    db.execute(
        "INSERT INTO reports(report_ref, case_id, title, format, status, "
        "storage_path, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (report_ref, case["case_id"],
         "Investigation report — %s" % case["case_ref"],
         "JSON", "GENERATED",
         os.path.join(REPORTS_DIR, storage_name), actor, _now()))
    case_service.audit("REPORT_GENERATED", action="REPORT_GENERATED",
                       target_type="case", target_ref=case["case_ref"],
                       detail="Generated %s" % report_ref, actor=actor,
                       ip_address=ip_address)
    return {"report_ref": report_ref, "case_ref": case["case_ref"],
            "content": content}


def get_report(report_ref):
    """Report row + persisted content, or an explicit unavailable state."""
    row = db.query_one("SELECT * FROM reports WHERE report_ref = ?",
                       (report_ref,))
    if not row:
        raise ReportError("REPORT_NOT_FOUND", "The report does not exist.")
    content = None
    if row.get("storage_path") and os.path.exists(row["storage_path"]):
        try:
            with open(row["storage_path"], "r", encoding="utf-8") as fh:
                content = json.load(fh)
        except (OSError, ValueError):
            content = None
    elif row.get("storage_path"):
        content = None
    return {
        "report_ref": row["report_ref"],
        "case_id": row["case_id"],
        "title": row["title"],
        "format": row["format"],
        "status": row["status"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "content_available": content is not None,
        "content": content,
    }


def list_reports(case_ref=None, limit=100, offset=0):
    limit = max(1, min(int(limit or 100), 200))
    offset = max(0, int(offset or 0))
    where, params = "", []
    if case_ref:
        case = _resolve_case(case_ref)
        where, params = "WHERE case_id = ?", [case["case_id"]]
    rows = db.query(
        "SELECT report_ref, case_id, title, format, status, created_by, "
        "created_at FROM reports %s ORDER BY created_at DESC, report_id DESC "
        "LIMIT ? OFFSET ?" % where, params + [limit, offset])
    total = db.query_one(
        "SELECT COUNT(*) AS n FROM reports %s" % where, params)["n"]
    items = []
    for r in rows:
        case = db.query_one("SELECT case_ref FROM cases WHERE case_id = ?",
                            (r["case_id"],))
        items.append({
            "report_ref": r["report_ref"],
            "case_ref": case["case_ref"] if case else "",
            "title": r["title"],
            "format": r["format"],
            "status": r["status"],
            "created_by": r["created_by"],
            "created_at": r["created_at"],
        })
    return {"items": items, "total": total}


def case_ioc_csv(case_ref):
    """IOC table as CSV (BF: CSV where appropriate)."""
    case = _resolve_case(case_ref)
    rows = _ioc_rows(case["case_id"])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["IOC_TYPE", "VALUE", "SEVERITY", "STATUS", "SOURCE",
                     "FIRST_SEEN", "LAST_SEEN"])
    for r in rows:
        writer.writerow([r["ioc_type"], r["value"], r["severity"],
                         r["status"], r["source"], r["first_seen"],
                         r["last_seen"]])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Export packages (70, BG)
# ---------------------------------------------------------------------------

def _package_items(case_ref, export_ref, report_content):
    case = _resolve_case(case_ref)
    case_id = case["case_id"]
    analysis_rows = _analysis_rows(case_id)
    manifest = manifest_rows(analysis_rows, export_ref=export_ref)
    for m in manifest:
        m["case_id"] = case["case_ref"]

    audit = db.query(
        "SELECT event_type, actor, action, target_type, target_ref, detail, "
        "created_at FROM audit_logs WHERE (target_type = 'case' AND "
        "target_ref = ?) OR target_ref = ? ORDER BY created_at ASC",
        (case["case_ref"], case["case_ref"]))

    payload = {
        "export": {
            "export_id": export_ref, "case_id": case["case_ref"],
            "exported_at": _now(), "engine": ENGINE,
            "engine_version": ENGINE_VERSION,
            "source": "KAVACHAM LAB export package (Section 70)",
        },
        "manifest": {  # called "evidence_manifest" inside report too
            "rows": manifest, "count": len(manifest),
        },
    }

    items = [
        ("metadata.json", json.dumps({
            "export_id": export_ref, "case_id": case["case_ref"],
            "exported_at": payload["export"]["exported_at"],
            "contents": ["manifest.json", "report.json", "iocs.csv",
                         "timeline.json", "analysis_results.json",
                         "audit.json", "metadata.json"],
            "integrity": "package sha256 is stored in the export record; "
                         "recompute at /lab/api/exports/<ref>/verify",
        }, indent=2, ensure_ascii=False)),
        ("manifest.json", json.dumps(
            {"evidence_manifest": manifest,
             "export_id": export_ref, "case_id": case["case_ref"],
             "exported_at": payload["export"]["exported_at"]},
            indent=2, ensure_ascii=False)),
        ("report.json", json.dumps(report_content, indent=2,
                                   ensure_ascii=False)),
        ("iocs.csv", case_ioc_csv(case["case_ref"])),
        ("timeline.json", json.dumps(_timeline_rows(case_id), indent=2,
                                     ensure_ascii=False)),
        ("analysis_results.json", json.dumps([
            {"analysis_ref": r["analysis_ref"],
             "analysis_type": r["analysis_type"], "verdict": r["verdict"],
             "status": r["status"], "risk_score": r["risk_score"],
             "evidence_ref": r.get("evidence_ref"),
             "created_at": r["created_at"],
             "findings": _findings_for(r["analysis_id"])}
            for r in analysis_rows], indent=2, ensure_ascii=False)),
        ("audit.json", json.dumps(audit, indent=2, ensure_ascii=False)),
    ]
    return payload, items


def export_case(case_ref, actor="analyst", ip_address=None):
    """Build + persist a deterministic export package (Section 70)."""
    case = _resolve_case(case_ref)

    # The package must contain a REPORT (70); auto-generate if absent.
    report_row = db.query_one(
        "SELECT report_ref FROM reports WHERE case_id = ? "
        "ORDER BY created_at DESC, report_id DESC LIMIT 1", (case["case_id"],))
    if report_row:
        report_ref = report_row["report_ref"]
        report = get_report(report_ref)
        report_content = report["content"]
    else:
        report = generate_report(case["case_ref"], actor=actor,
                                 ip_address=ip_address)
        report_ref = report["report_ref"]
        report_content = report["content"]

    export_ref = _next_export_ref()
    payload, items = _package_items(case["case_ref"], export_ref,
                                    report_content)

    os.makedirs(EXPORTS_DIR, exist_ok=True)
    zip_path = os.path.join(EXPORTS_DIR, "%s.zip" % export_ref)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in sorted(items, key=lambda x: x[0]):
            zf.writestr(arcname, data)

    sha = hashlib.sha256()
    with open(zip_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    sha256 = sha.hexdigest()
    sidecar = "%s.sha256" % export_ref
    with open(os.path.join(EXPORTS_DIR, sidecar), "w", encoding="utf-8") as fh:
        fh.write("%s  %s\n" % (sha256, os.path.basename(zip_path)))

    db.execute(
        "INSERT INTO export_packages(export_ref, case_id, report_ref, "
        "storage_path, sha256, item_count, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (export_ref, case["case_id"], report_ref, zip_path, sha256,
         len(items), actor, _now()))
    case_service.audit("REPORT_EXPORTED", action="REPORT_EXPORTED",
                       target_type="case", target_ref=case["case_ref"],
                       detail="Exported package %s (sha256 %s…)"
                              % (export_ref, sha256[:12]), actor=actor,
                       ip_address=ip_address)

    return {
        "export_ref": export_ref,
        "case_ref": case["case_ref"],
        "report_ref": report_ref,
        "sha256": sha256,
        "item_count": len(items),
        "storage_path": zip_path,
        "exported_at": _now(),
        "manifest": payload["manifest"],
    }


def list_exports(limit=100, offset=0):
    limit = max(1, min(int(limit or 100), 200))
    offset = max(0, int(offset or 0))
    rows = db.query(
        "SELECT ep.export_ref, ep.case_id, ep.report_ref, ep.sha256, "
        "ep.item_count, ep.created_by, ep.created_at, c.case_ref "
        "FROM export_packages ep LEFT JOIN cases c ON c.case_id = ep.case_id "
        "ORDER BY ep.created_at DESC, ep.export_id DESC LIMIT ? OFFSET ?",
        (limit, offset))
    total = db.query_one("SELECT COUNT(*) AS n FROM export_packages")["n"]
    items = [{
        "export_ref": r["export_ref"], "case_ref": r["case_ref"] or "",
        "report_ref": r["report_ref"], "sha256": r["sha256"],
        "item_count": r["item_count"], "created_by": r["created_by"],
        "created_at": r["created_at"],
    } for r in rows]
    return {"items": items, "total": total}


def get_export(export_ref):
    row = db.query_one(
        "SELECT ep.*, c.case_ref FROM export_packages ep "
        "LEFT JOIN cases c ON c.case_id = ep.case_id "
        "WHERE ep.export_ref = ?", (export_ref,))
    if not row:
        raise ReportError("EXPORT_NOT_FOUND", "The export package does not exist.")
    manifest = None
    try:
        with zipfile.ZipFile(row["storage_path"], "r") as zf:
            with zf.open("manifest.json") as fh:
                manifest = json.loads(fh.read().decode("utf-8"))
    except (OSError, KeyError, ValueError):
        manifest = None
    return {
        "export_ref": row["export_ref"],
        "case_ref": row["case_ref"],
        "report_ref": row["report_ref"],
        "sha256": row["sha256"],
        "item_count": row["item_count"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "file_present": bool(row["storage_path"])
        and os.path.exists(row["storage_path"]),
        "manifest": manifest,
        "storage_path": row["storage_path"],
    }


def verify_export(export_ref):
    """Recompute the package hash and zip integrity (BG/Section 70)."""
    row = db.query_one("SELECT * FROM export_packages WHERE export_ref = ?",
                       (export_ref,))
    if not row:
        raise ReportError("EXPORT_NOT_FOUND", "The export package does not exist.")
    path = row["storage_path"]
    if not path or not os.path.exists(path):
        return {"export_ref": export_ref, "status": "MISSING",
                "message": "The stored package file is missing."}

    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    recomputed = sha.hexdigest()

    zip_ok = None
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zip_ok = zf.testzip()
    except zipfile.BadZipFile:
        zip_ok = "bad zip"

    if recomputed != row["sha256"] or zip_ok is not None:
        return {
            "export_ref": export_ref, "status": "MISMATCH",
            "stored_sha256": row["sha256"], "recomputed_sha256": recomputed,
            "zip_check": zip_ok,
            "message": "Package integrity check failed.",
        }
    return {
        "export_ref": export_ref, "status": "VERIFIED",
        "stored_sha256": row["sha256"], "recomputed_sha256": recomputed,
        "zip_check": "ok",
        "message": "Package integrity verified (sha256 match, zip OK).",
    }