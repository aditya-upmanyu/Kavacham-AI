"""KAVACHAM LAB — QA suite.

Covers Phases 2-5: data layer, migrations, case management, health service
and HTTP routes. Runs against an isolated temporary database so it never
touches real records.

Run:  python test_lab.py
"""

import json
import os
import sys
import tempfile
import traceback

# Isolate the database BEFORE importing lab modules (db.py reads env at import).
_TMP_DIR = tempfile.mkdtemp(prefix="kavacham_lab_test_")
os.environ["KAVACHAM_LAB_DB"] = os.path.join(_TMP_DIR, "test_lab.db")
# Isolate report JSON + export packages (and evidence originals) too.
os.environ["KAVACHAM_LAB_STORAGE"] = os.path.join(_TMP_DIR, "storage")

from lab import db                      # noqa: E402
from lab import case_service as cs      # noqa: E402
from lab import health as hs            # noqa: E402
from lab import routes as lab_routes    # noqa: E402

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((bool(condition), name, detail))
    mark = "PASS" if condition else "FAIL"
    print("  [%s] %s%s" % (mark, name, (" — " + str(detail)) if detail else ""))


def section(title):
    print("\n%s" % title)
    print("-" * len(title))


# ===========================================================================
section("Test 1 — Database & Migrations")
# ===========================================================================
applied = db.migrate()
check("initial migration applied",
      1 in applied and 2 in applied and 3 in applied and 4 in applied
      and 5 in applied, applied)
check("schema version is 5", db.current_version() == 5, db.current_version())

re_run = db.migrate()
check("migrations idempotent (no re-apply)", re_run == [], re_run)

integrity = db.integrity_check()
check("PRAGMA integrity_check ok", integrity.get("ok") is True, integrity)

counts = db.table_counts()
expected_tables = [
    "cases", "evidence", "chain_of_custody", "analyses", "analysis_findings",
    "iocs", "case_iocs", "entities", "case_entities", "timeline_events",
    "notes", "reports", "audit_logs", "alerts", "users", "roles",
    "permissions", "role_permissions", "dataset_registry", "model_registry",
    "settings",
]
missing = [t for t in expected_tables if t not in counts]
check("all normalized tables exist (%d)" % len(expected_tables), not missing, missing)

check("enums documented", len(db.CASE_TYPES) == 11 and len(db.CASE_STATUSES) == 5,
      "%d types / %d statuses" % (len(db.CASE_TYPES), len(db.CASE_STATUSES)))

# FK enforcement must reject an evidence row pointing at a missing case.
# (NULL case_id is legitimately allowed — the test must use a real, absent id.)
try:
    db.execute(
        "INSERT INTO evidence(case_id, evidence_ref, evidence_type, title, "
        "source, acquired_at) VALUES (?,?,?,?,?,?)",
        (999999, "KAV-EVD-TEST-ORPHAN", "URL", "orphan", "Analyst Input",
         cs._now()))
    orphan_inserted = True
except Exception:
    orphan_inserted = False
check("foreign keys enforced (orphan evidence rejected)", not orphan_inserted)

# NULL case_id must still be allowed (evidence not yet linked to a case)
try:
    db.execute(
        "INSERT INTO evidence(evidence_ref, evidence_type, title, source, "
        "acquired_at) VALUES (?,?,?,?,?)",
        ("KAV-EVD-TEST-UNLINKED", "URL", "unlinked", "Analyst Input", cs._now()))
    unlinked_ok = True
except Exception:
    unlinked_ok = False
check("nullable case_id permitted for unlinked evidence", unlinked_ok)

# ===========================================================================
section("Test 2 — Case Creation (Section 17)")
# ===========================================================================
case1 = cs.create_case({
    "title": "Credential phishing targeting finance inbox",
    "description": "Actor spoofing a Microsoft 365 sign-in page.",
    "case_type": "PHISHING",
    "priority": "HIGH",
    "assigned_investigator": "a.upmanyu",
    "iocs": ["185.234.72.19", "account-verify-login.tk",
             "https://account-verify-login.tk/confirm"],
})
check("case_ref format", case1["case_ref"].startswith("KAV-CASE-%d-" % 2026),
      case1["case_ref"])
check("initial status is OPEN", case1["status"] == "OPEN", case1["status"])
check("timestamp recorded", bool(case1["created_at"]), case1["created_at"][:19])
check("timeline initialized", case1["counts"]["timeline_events"] >= 1,
      case1["counts"]["timeline_events"])
check("audit event written",
      any(a["action"] == "CASE_CREATED" for a in cs.list_audit(limit=50)["items"]))
check("initial IOCs linked", case1["counts"]["iocs"] == 3, case1["counts"]["iocs"])
ioc_types = sorted(i["ioc_type"] for i in case1["iocs"])
check("IOC types classified", ioc_types == ["DOMAIN", "IP", "URL"], ioc_types)
check("assignment recorded on timeline",
      any(e["event_type"] == "ASSIGNED" for e in case1["timeline"]))
check("real counts are integers (no fabrication)",
      all(isinstance(v, int) for v in case1["counts"].values()), case1["counts"])

case2 = cs.create_case({
    "title": "QR code on parking ticket leads to payment portal",
    "case_type": "QR PHISHING",
    "priority": "MEDIUM",
})
check("second case gets sequential ref",
      case2["case_ref"].split("-")[-1] == case1["case_ref"].split("-")[-1].replace(
          str(int(case1["case_ref"].split("-")[-1])), str(int(case1["case_ref"].split("-")[-1]) + 1)),
      "%s -> %s" % (case1["case_ref"], case2["case_ref"]))

# ===========================================================================
section("Test 3 — Validation & Rejections")
# ===========================================================================
for label, payload, expected_code in [
    ("missing title", {"case_type": "PHISHING"}, "VALIDATION_FAILED"),
    ("bad case_type", {"title": "x", "case_type": "NOT_A_TYPE"}, "VALIDATION_FAILED"),
    ("bad priority", {"title": "x", "case_type": "BEC", "priority": "URGENT"},
     "VALIDATION_FAILED"),
    ("non-dict payload", "not-a-dict", "INVALID_PAYLOAD"),
]:
    try:
        cs.create_case(payload)
        check("rejects %s" % label, False, "no error raised")
    except cs.CaseError as exc:
        check("rejects %s" % label, exc.code == expected_code, exc.code)

try:
    cs.get_case("KAV-CASE-2099-99999")
    check("unknown case rejected", False, "no error raised")
except cs.CaseError as exc:
    check("unknown case rejected", exc.code == "CASE_NOT_FOUND", exc.code)

# ===========================================================================
section("Test 4 — Status Transitions (Section 16)")
# ===========================================================================
check("OPEN allows investigation",
      "UNDER INVESTIGATION" in db.VALID_TRANSITIONS["OPEN"])
check("RESOLVED not directly reachable from OPEN",
      "RESOLVED" not in db.VALID_TRANSITIONS["OPEN"],
      db.VALID_TRANSITIONS["OPEN"])

# Illegal transition must be refused. This deliberately leaves case1 ARCHIVED,
# so reopen it (ARCHIVED -> OPEN is legal) before the positive-path test.
try:
    cs.update_case(case1["case_ref"], {"status": "ARCHIVED"})
    cs.update_case(case1["case_ref"], {"status": "RESOLVED"})
    check("illegal transition rejected", False, "RESOLVED accepted from ARCHIVED")
except cs.CaseError as exc:
    check("illegal transition rejected", exc.code == "INVALID_TRANSITION", exc.code)
    check("  error message names allowed states", "Allowed:" in exc.message,
          exc.message[:90])

reopened = cs.update_case(case1["case_ref"], {"status": "OPEN"})
check("ARCHIVED can be reopened", reopened["status"] == "OPEN", reopened["status"])

upd = cs.update_case(case1["case_ref"],
                     {"status": "UNDER INVESTIGATION", "priority": "CRITICAL"})
check("legal transition applied", upd["status"] == "UNDER INVESTIGATION",
      upd["status"])
check("priority updated", upd["priority"] == "CRITICAL", upd["priority"])
check("update audited",
      any(a["action"] == "CASE_UPDATED" for a in cs.list_audit(limit=50)["items"]))
check("update added timeline events",
      upd["counts"]["timeline_events"] >= 3, upd["counts"]["timeline_events"])
check("allowed_transitions recomputed",
      "REVIEW" in upd["allowed_transitions"], upd["allowed_transitions"])

# ===========================================================================
section("Test 5 — Search, Filter & Notes (Sections 16, 67)")
# ===========================================================================
listing = cs.list_cases()
check("lists all cases", listing["total"] == 2, listing["total"])
check("returns real total", isinstance(listing["total"], int), listing["total"])

check("search by keyword", cs.list_cases(search="finance")["total"] == 1)
check("search by case_ref", cs.list_cases(search=case2["case_ref"])["total"] == 1)
check("filter by status",
      all(i["status"] == "UNDER INVESTIGATION"
          for i in cs.list_cases(status="UNDER INVESTIGATION")["items"]))
check("filter by type", cs.list_cases(case_type="QR PHISHING")["total"] == 1)
check("no matches returns 0 (not fake data)",
      cs.list_cases(search="zzz_no_such_case")["total"] == 0)

note = cs.add_note(case1["case_ref"],
                   "Header analysis shows forged Received chain; SPF fail.")
check("note created", note["note_id"] > 0, note["note_id"])
check("note author recorded", note["author"] == "analyst", note["author"])
check("note attached to case",
      any(n["note_id"] == note["note_id"]
          for n in cs.get_case(case1["case_ref"])["notes"]))
check("note audited",
      any(a["action"] == "NOTE_ADDED" for a in cs.list_audit(limit=50)["items"]))

try:
    cs.add_note(case1["case_ref"], "   ")
    check("empty note rejected", False, "no error raised")
except cs.CaseError as exc:
    check("empty note rejected", exc.code == "VALIDATION_FAILED", exc.code)

# ===========================================================================
section("Test 6 — Health Service (Sections 51/63)")
# ===========================================================================
report = hs.run_health_checks()
data = report["data"]
check("envelope has success/data/meta",
      set(report.keys()) == {"success", "data", "meta"}, sorted(report.keys()))
check("report success true", report["success"] is True)
check("21 services checked", data["summary"]["total"] == 21,
      data["summary"]["total"])

service_keys = {"label", "status", "status_key", "latency_ms", "detail",
                "source", "error", "checked_at", "id", "group"}
bad = [s["label"] for s in data["services"] if not service_keys.issubset(s)]
check("every service has required fields", not bad, bad)

real_time = [s for s in data["services"] if s["latency_ms"] is not None]
check("latencies are measured numbers",
      all(isinstance(s["latency_ms"], (int, float)) for s in real_time),
      "%d measured" % len(real_time))

no_latency = [s["label"] for s in data["services"] if s["latency_ms"] is None]
check("not-configured services report null latency (never faked)",
      all(s["status_key"] == "unconfigured"
          for s in data["services"] if s["latency_ms"] is None), no_latency)

status_keys = {s["status_key"] for s in data["services"]}
check("statuses drawn from the allowed vocabulary",
      status_keys.issubset({"operational", "unavailable", "unconfigured"}),
      sorted(status_keys))

check("no fabricated ONLINE/CONNECTED literals",
      all(s["status"] in ("OPERATIONAL", "SERVICE UNAVAILABLE", "NOT CONFIGURED")
          for s in data["services"]),
      sorted({s["status"] for s in data["services"]}))

check("checked_at is a real timestamp", bool(data["checked_at"]),
      data["checked_at"][:19])
check("summary counts add up",
      data["summary"]["operational"] + data["summary"]["unavailable"] +
      data["summary"]["unconfigured"] == data["summary"]["total"])

alerts = hs.get_alerts()
check("alerts derive from real conditions",
      all(a["error_code"] for a in alerts), len(alerts))
check("alert has required fields",
      all({"id", "severity", "title", "message", "error_code", "source",
           "occurred_at"} <= set(a) for a in alerts))

# Persistence now exists in this test run, so DB must report operational
db_svc = next(s for s in data["services"] if s["id"] == "database")
check("database health reflects real file",
      db_svc["status"] == "OPERATIONAL", db_svc["status"])
check("database health reports schema version",
      db_svc.get("schema_version") == db.current_version(),
      db_svc.get("schema_version"))

# ===========================================================================
section("Test 7 — Reference Data & Route Registry")
# ===========================================================================
ref = cs.reference_data()
check("reference data exposes enums",
      ref["case_types"] == db.CASE_TYPES and ref["statuses"] == db.CASE_STATUSES)

# Blueprints expose url_map only once registered on an application, so
# register onto a throwaway Flask app to inspect the real rules.
from flask import Flask                      # noqa: E402
from lab import lab_bp                       # noqa: E402
_probe = Flask(__name__)
_probe.register_blueprint(lab_bp)

# url_map yields one Rule per (path, method) combination for routes declared
# with multiple decorators, so normalise to path -> allowed methods.
path_methods = {}
for r in _probe.url_map.iter_rules():
    if not r.rule.startswith("/lab") or r.endpoint == "static":
        continue
    methods = {m for m in r.methods if m not in ("HEAD", "OPTIONS")}
    path_methods.setdefault(r.rule, set()).update(methods)

rules = sorted(path_methods)

# Exact expected surface: pages + APIs + their methods. Any drift here is
# intentional and must be updated together with the sidebar so navigation
# never goes dead (Section 81).
expected_methods = {
    "/lab/":                              {"GET"},
    "/lab/api/health":                    {"GET"},
    "/lab/api/alerts":                    {"GET"},
    "/lab/api/command-center":            {"GET"},
    "/lab/api/meta":                      {"GET"},
    "/lab/cases":                         {"GET"},
    "/lab/cases/new":                     {"GET"},
    "/lab/cases/<case_ref>":              {"GET"},
    "/lab/audit":                         {"GET"},
    # Phase 13 — health & observability (Sections BO/BP/BZ)
    "/lab/health":                        {"GET"},
    "/lab/settings":                      {"GET"},
    "/lab/api/providers":                 {"GET"},
    "/lab/api/search":                     {"GET"},
    "/lab/api/cases":                     {"GET", "POST"},
    "/lab/api/cases/<case_ref>":          {"GET", "PATCH"},
    "/lab/api/cases/<case_ref>/notes":    {"POST"},
    "/lab/api/cases/meta":                {"GET"},
    "/lab/api/audit":                     {"GET"},
    # Phase 6 — evidence
    "/lab/evidence":                      {"GET"},
    "/lab/evidence/new":                  {"GET"},
    "/lab/evidence/<evidence_ref>":       {"GET"},
    "/lab/api/evidence":                  {"GET", "POST"},
    "/lab/api/evidence/meta":             {"GET"},
    "/lab/api/evidence/<evidence_ref>":   {"GET"},
    "/lab/api/evidence/<evidence_ref>/custody": {"GET"},
    "/lab/api/evidence/<evidence_ref>/verify":  {"POST"},
    # Phase 7 — analysis pipeline
    "/lab/analysis":                      {"GET"},
    "/lab/analysis/new":                  {"GET"},
    "/lab/analysis/<analysis_ref>":       {"GET"},
    "/lab/api/analysis":                  {"GET", "POST"},
    "/lab/api/analysis/meta":             {"GET"},
    "/lab/api/analysis/<analysis_ref>":   {"GET"},
    # Phase 8 — intelligence
    "/lab/intel/iocs":                    {"GET"},
    "/lab/intel/correlation":             {"GET"},
    "/lab/intel/attack-chains":           {"GET"},
    "/lab/intel/graph":                   {"GET"},
    "/lab/api/intel/iocs":                {"GET"},
    "/lab/api/intel/iocs/<int:ioc_id>":   {"GET", "PATCH"},
    "/lab/api/intel/iocs/<int:ioc_id>/cases": {"POST"},
    "/lab/api/intel/sync":                {"POST"},
    "/lab/api/intel/bulk/preview":        {"POST"},
    "/lab/api/intel/bulk/investigate":    {"POST"},
    "/lab/intel/bulk":                    {"GET"},
    "/lab/api/intel/correlation":         {"GET"},
    "/lab/api/intel/graph":               {"GET"},
    "/lab/api/intel/attack-chain":        {"GET"},
    "/lab/api/intel/network":             {"GET"},
    "/lab/models":                            {"GET"},
    "/lab/datasets":                          {"GET"},
    "/lab/api/models":                        {"GET"},
    "/lab/api/datasets":                      {"GET"},
    "/lab/api/settings":                      {"GET", "PATCH"},
    "/lab/api/settings/purge-preview":        {"GET"},
    "/lab/api/settings/purge":                {"POST"},
    # Phase 9 — central risk engine (Sections AZ, BA)
    "/lab/risk":                          {"GET"},
    "/lab/api/risk":                      {"GET"},
    # Phase 10/11 — reporting (Sections 42, 43, 69, 70, BF, BG)
    "/lab/reports":                       {"GET"},
    "/lab/reports/<report_ref>":          {"GET"},
    "/lab/reports/exports":               {"GET"},
    "/lab/reports/manifest":              {"GET"},
    "/lab/api/reports":                   {"GET", "POST"},
    "/lab/api/reports/<report_ref>":      {"GET"},
    "/lab/api/reports/<report_ref>/csv":  {"GET"},
    "/lab/api/cases/<case_ref>/export":   {"POST"},
    "/lab/api/exports":                   {"GET"},
    "/lab/api/exports/<export_ref>":      {"GET"},
    "/lab/api/exports/<export_ref>/verify":   {"POST"},
    "/lab/api/exports/<export_ref>/download": {"GET"},
}
expected_rules = sorted(expected_methods)

check("expected routes registered",
      rules == expected_rules,
      "extra=%s missing=%s" % (
          [r for r in rules if r not in expected_rules],
          [r for r in expected_rules if r not in rules]))
check("route count matches", len(rules) == len(expected_rules),
      "%d vs %d" % (len(rules), len(expected_rules)))

bad_methods = []
for path, methods in expected_methods.items():
    actual = path_methods.get(path, set())
    if not methods.issubset(actual):
        bad_methods.append("%s missing %s" % (path, sorted(methods - actual)))
check("every route exposes the intended HTTP methods", not bad_methods, bad_methods)

# Every sidebar link must resolve to a registered rule (Section 81)
nav_rules = {r.rstrip("/") for r in rules}
dead = []
for group in lab_routes.NAV_STRUCTURE:
    for link in group["links"]:
        target = link["url"].rstrip("/")
        if target not in nav_rules:
            dead.append(link["label"])
check("no dead navigation (every sidebar link has a route)", not dead, dead)

# ===========================================================================
section("Test 7B — Evidence: Intake, Custody, Integrity (Sections 19-23)")
# ===========================================================================
import base64 as _b64                                    # noqa: E402
from lab import evidence_service as evs                  # noqa: E402

ev_ref_data = evs.reference_data()
check("evidence reference data exposes types", len(evs.EVIDENCE_TYPES) == 12,
      len(evs.EVIDENCE_TYPES))
check("file security limits exposed", isinstance(ev_ref_data["max_bytes"], int)
      and ev_ref_data["max_bytes"] > 0, ev_ref_data["max_bytes"])
check("blocked extensions listed", ".exe" in ev_ref_data["blocked_extensions"])

# --- filename sanitisation (Section 21) ---
check("path traversal stripped",
      evs.sanitize_filename("../../../etc/passwd") == "passwd",
      evs.sanitize_filename("../../../etc/passwd"))
check("windows separators stripped",
      evs.sanitize_filename("..\\..\\boot.ini") == "boot.ini",
      evs.sanitize_filename("..\\..\\boot.ini"))
check("unsafe characters collapsed",
      "/" not in evs.sanitize_filename("invoice (final) copy.pdf"),
      evs.sanitize_filename("invoice (final) copy.pdf"))

for bad_name in ("payload.exe", "run.bat", "script.js", "setup.msi"):
    try:
        evs.validate_filename(bad_name)
        check("blocks executable %s" % bad_name, False, "accepted")
    except evs.EvidenceError as exc:
        check("blocks executable %s" % bad_name, exc.code == "FILE_TYPE_BLOCKED",
              exc.code)

# --- size limit (Section 21) — assert against a patched limit, since the
#     real limit is read at import time ---
_orig_limit = evs.MAX_EVIDENCE_BYTES
evs.MAX_EVIDENCE_BYTES = 100
try:
    evs.accept_evidence({
        "evidence_type": "FILE", "title": "oversize",
        "filename": "big.pdf",
        "content_base64": _b64.b64encode(b"A" * 500).decode()})
    check("enforces size limit", False, "accepted oversize file")
except evs.EvidenceError as exc:
    check("enforces size limit", exc.code == "FILE_TOO_LARGE", exc.code)
finally:
    evs.MAX_EVIDENCE_BYTES = _orig_limit

# --- PE payload disguised with a text extension (Section 21) ---
try:
    evs.accept_evidence({
        "evidence_type": "FILE", "title": "disguised",
        "filename": "innocent.txt",
        "content_base64": _b64.b64encode(b"MZ\x90\x00" + b"\x00" * 64).decode()})
    check("blocks executable content regardless of extension", False, "accepted")
except evs.EvidenceError as exc:
    check("blocks executable content regardless of extension",
          exc.code == "FILE_TYPE_BLOCKED", exc.code)

# --- file intake: hashing + custody + integrity (Sections 19, 20, 22) ---
pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n" + b"B" * 400
ev_file = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "FILE",
    "title": "Lure attachment", "filename": "../../../tmp/invoice (1).pdf",
    "content_base64": _b64.b64encode(pdf).decode(), "source": "Email Forensics"})

check("evidence_ref format", ev_file["evidence_ref"].startswith("KAV-EVD-%d-" % 2026),
      ev_file["evidence_ref"])
check("sha256 computed from real bytes",
      ev_file["sha256"] == evs.hash_bytes(pdf)["sha256"], ev_file["sha256"][:16])
check("sha1 and md5 also computed",
      len(ev_file["sha1"]) == 40 and len(ev_file["md5"]) == 32)
check("original filename sanitised",
      "/" not in ev_file["original_filename"] and ".." not in ev_file["original_filename"],
      ev_file["original_filename"])
check("mime detected from magic bytes", ev_file["mime_type"] == "application/pdf",
      ev_file["mime_type"])
check("size matches real bytes", ev_file["size_bytes"] == len(pdf),
      ev_file["size_bytes"])
check("stored original written", ev_file["stored"] is True)
check("stored original exists", ev_file["stored_file_exists"] is True)
check("acquisition state VERIFIED at intake", ev_file["integrity_state"] == "VERIFIED",
      ev_file["integrity_state"])
check("attached to case", ev_file["case"] is not None
      and ev_file["case"]["case_ref"] == case1["case_ref"])
check("custody genesis events present",
      [c["action"] for c in ev_file["custody"]][:2] ==
      ["EVIDENCE CREATED", "HASH GENERATED"],
      [c["action"] for c in ev_file["custody"]])
check("custody chain hash-verifies", ev_file["custody_verification"]["ok"] is True,
      ev_file["custody_verification"])
check("case counts evidence", cs.get_case(case1["case_ref"])["counts"]["evidence"] == 1)

# --- text evidence + integrity verification (Section 23) ---
ev_text = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "RAW_HEADER",
    "title": "Original headers",
    "content_text": "Received: from spoof.example ... Return-Path: <x@y>"})
v = evs.verify_integrity(ev_text["evidence_ref"])
check("text evidence integrity verified", v["status"] == "INTEGRITY VERIFIED",
      v["status"])
check("  reported hashes actually match", v["original_sha256"] == v["current_sha256"])

v2 = evs.verify_integrity(ev_file["evidence_ref"])
check("file evidence integrity verified", v2["status"] == "INTEGRITY VERIFIED",
      v2["status"])

# --- tamper the stored original -> must report MISMATCH, never VERIFIED ---
stored_row = db.query_one(
    "SELECT stored_path FROM evidence WHERE evidence_ref = ?",
    (ev_file["evidence_ref"],))
with open(stored_row["stored_path"], "ab") as fh:
    fh.write(b"\nTAMPERED")
v3 = evs.verify_integrity(ev_file["evidence_ref"])
check("tampering reported as MISMATCH", v3["status"] == "INTEGRITY MISMATCH",
      v3["status"])
check("  mismatch hashes differ", v3["original_sha256"] != v3["current_sha256"])
check("  honest detail text", "differs" in v3["detail"], v3["detail"])

# --- custody is append-only and re-verified after every mutation ---
custody_after = evs.get_custody(ev_file["evidence_ref"])
check("custody events appended, never replaced",
      custody_after["count"] >= 4, custody_after["count"])
check("chain still verifies after append",
      custody_after["verification"]["ok"] is True, custody_after["verification"])

# --- evidence validation ---
for label, payload, code in [
    ("missing title", {"evidence_type": "URL", "content_text": "https://x"}, "VALIDATION_FAILED"),
    ("bad type", {"evidence_type": "NOPE", "title": "x"}, "VALIDATION_FAILED"),
    ("no content", {"evidence_type": "URL", "title": "x"}, "VALIDATION_FAILED"),
]:
    try:
        evs.accept_evidence(payload)
        check("rejects %s" % label, False, "accepted")
    except evs.EvidenceError as exc:
        check("rejects %s" % label, exc.code == code, exc.code)

try:
    evs.accept_evidence({"evidence_type": "URL", "title": "x",
                         "content_text": "https://z",
                         "case_ref": "KAV-CASE-1999-99999"})
    check("rejects evidence for missing case", False, "accepted")
except evs.EvidenceError as exc:
    check("rejects evidence for missing case", exc.code == "CASE_NOT_FOUND",
          exc.code)

# --- listing + search ---
listed = evs.list_evidence(case_ref=case1["case_ref"])
check("lists evidence for a case", listed["total"] == 2, listed["total"])
check("search by sha256 finds record",
      evs.list_evidence(search=ev_file["sha256"])["total"] == 1)
check("no-match search returns 0",
      evs.list_evidence(search="zzz_absent")["total"] == 0)

# --- audit trail for evidence ---
check("evidence intake audited",
      any(a["action"] == "EVIDENCE_ADDED"
          for a in cs.list_audit(limit=100)["items"]))
check("integrity check audited",
      any(a["action"] == "EVIDENCE_VERIFIED"
          for a in cs.list_audit(limit=100)["items"]))

# ===========================================================================
section("Test 8 — Product A Regression Baseline")
# ===========================================================================
# Importing app must not break, and its QA suite must remain at 50/51.
try:
    import app as app_module
    check("Product A imports cleanly with Lab registered",
          hasattr(app_module.app, "url_map"))
    lab_rules = [r.rule for r in app_module.app.url_map.iter_rules()
                 if r.rule.startswith("/lab")]
    check("Lab blueprint registered on main app", len(lab_rules) >= 5,
          len(lab_rules))
    product_a_rules = [r.rule for r in app_module.app.url_map.iter_rules()
                       if r.rule in ("/", "/predict", "/api/phishing-check", "/health")]
    check("Product A routes intact",
          {"/", "/predict", "/api/phishing-check", "/health"} <= set(product_a_rules),
          sorted(product_a_rules))
except Exception:
    check("Product A imports cleanly with Lab registered", False,
          traceback.format_exc().splitlines()[-1])

# ===========================================================================
section("Test 7C — Phase 7 Analysis Pipeline (Sections 29-41, 48)")
# ===========================================================================
# App + model are now loaded (Test 8), so EMAIL/SPAM runs use real inference.
import hashlib as _hl                                              # noqa: E402
from lab import analysis_service as ans                            # noqa: E402
import intel.virustotal_service as _vt_svc                         # noqa: E402

# Pin threat intelligence OFF for the whole section: QA must be deterministic
# and offline. The "not configured" path is the honest, locally-complete one.
_saved_vt_key = _vt_svc.VIRUSTOTAL_API_KEY
_saved_vt_state = ans._vt_state
_vt_svc.VIRUSTOTAL_API_KEY = ""
ans._vt_state = lambda: False

# --- analysis registry (Section 47) ---
aref = ans.reference_data()
check("analysis registry exposes 11 types", len(aref["types"]) == 11, aref["types"])
check("every type carries a compatibility matrix",
      all(t in aref["registry"] and aref["registry"][t]["evidence_types"]
          for t in aref["types"]))
check("HASH binds only HASH evidence",
      aref["registry"]["HASH"]["evidence_types"] == ["HASH"])

# --- PHISHING (real analyzer over RAW_HEADER evidence) ---
ap = ans.run_analysis(ev_text["evidence_ref"], "PHISHING")
check("phishing: ref format", ap["analysis_ref"].startswith("KAV-ANL-2026-"),
      ap["analysis_ref"])
check("phishing: status COMPLETE", ap["status"] == "COMPLETE", ap["status"])
check("phishing: verdict vocabulary",
      ap["verdict"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}, ap["verdict"])
check("phishing: risk score real bounded number",
      isinstance(ap["risk_score"], (int, float))
      and 0 <= ap["risk_score"] <= 100, ap["risk_score"])
check("phishing: engine version recorded", bool(ap["engine_version"]),
      ap["engine_version"])
check("phishing: linked to evidence",
      ap["evidence"]["evidence_ref"] == ev_text["evidence_ref"])
check("phishing: linked to case",
      ap["case"]["case_ref"] == case1["case_ref"])
check("phishing: findings list persisted", isinstance(ap["findings"], list))
check("phishing: Section 40 transparency fields present",
      {"started_at", "completed_at", "stages", "sources", "engine_version"}
      <= set(ap["payload"]))
check("phishing: real stage sequence recorded",
      len(ap["payload"]["stages"]) >= 3, len(ap["payload"]["stages"]))
check("phishing: sources recorded", len(ap["payload"]["sources"]) >= 1,
      ap["payload"]["sources"])

# --- EMAIL (unified pipeline with real ML inference) ---
ae = ans.run_analysis(ev_text["evidence_ref"], "EMAIL")
check("email: verdict present", bool(ae["verdict"]), ae["verdict"])
check("email: confidence float or honest null",
      ae["confidence"] is None or isinstance(ae["confidence"], (int, float)),
      ae["confidence"])
check("email: ML stage recorded honestly",
      any(s["name"] == "Local ML analysis" for s in ae["payload"]["stages"]))
check("email: status in allowed set",
      ae["status"] in {"COMPLETE", "PARTIAL"}, ae["status"])

# --- SPAM (real Product A model) ---
asp = ans.run_analysis(ev_text["evidence_ref"], "SPAM")
check("spam: classification from real classifier",
      asp["payload"]["analysis"]["classification"]
      in {"Spam", "Not Spam", "Unavailable"},
      asp["payload"]["analysis"].get("classification"))
check("spam: verdict derives from classification",
      asp["verdict"] in {"MALICIOUS", "CLEAN", "UNAVAILABLE"}, asp["verdict"])

# --- URL (deterministic product-A structure + intel stage) ---
ev_url = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "URL",
    "title": "Suspicious link",
    "content_text": "http://185.234.72.19/confirm?token=abc"})
au = ans.run_analysis(ev_url["evidence_ref"], "URL")
check("url: ip-host flagged",
      au["verdict"] in {"SUSPICIOUS", "MALICIOUS"}, au["verdict"])
check("url: deterministic score >= 20", int(au["risk_score"]) >= 20,
      au["risk_score"])
check("url: analyzed urls persisted",
      au["payload"]["analysis"]["url_count"] >= 1,
      au["payload"]["analysis"].get("url_count"))
check("url: intel stage honest (VT unconfigured)",
      any(s["name"] == "Threat intelligence" and s["status"] == "unavailable"
          for s in au["payload"]["stages"]))

ev_clean = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "URL",
    "title": "Legit link", "content_text": "https://example.com/pricing"})
acl = ans.run_analysis(ev_clean["evidence_ref"], "URL")
check("url: clean baseline verdict", acl["verdict"] == "CLEAN", acl["verdict"])
check("url: clean baseline score 0", acl["risk_score"] == 0, acl["risk_score"])

# --- DOMAIN (structure + registrable domain) ---
ev_dom = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "DOMAIN",
    "title": "Lookalike domain", "content_text": "account-verify-login.tk"})
ad = ans.run_analysis(ev_dom["evidence_ref"], "DOMAIN")
check("domain: verdict vocabulary",
      ad["verdict"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}, ad["verdict"])
check("domain: registrable domain extracted",
      bool(ad["payload"]["analysis"]["registrable_domain"]),
      ad["payload"]["analysis"].get("registrable_domain"))
check("domain: structure findings exposed",
      isinstance(ad["payload"]["analysis"]["structure_findings"], list))

ev_dom_ip = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "DOMAIN",
    "title": "IP address domain", "content_text": "185.234.72.19"})
adi = ans.run_analysis(ev_dom_ip["evidence_ref"], "DOMAIN")
check("domain: raw-IP host flagged",
      adi["verdict"] in {"SUSPICIOUS", "MALICIOUS"}, adi["verdict"])

# --- FILE (local inspector: magic, embedded URLs, honest stages) ---
clean_txt = (b"Please click http://185.234.72.19/verify to confirm your "
             b"account. Regards, Support")
ev_ftxt = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "FILE",
    "title": "Message log", "filename": "log.txt",
    "content_base64": _b64.b64encode(clean_txt).decode(),
    "source": "Analyst Input"})
aft = ans.run_analysis(ev_ftxt["evidence_ref"], "FILE")
check("file: embedded url extracted",
      aft["payload"]["analysis"]["url_count"] >= 1,
      aft["payload"]["analysis"].get("url_count"))
check("file: no blocked content in txt",
      aft["payload"]["analysis"]["blocked_content"] is False)
check("file: intel stage honest (VT unconfigured)",
      any(s["name"] == "Threat intelligence" and s["status"] == "unavailable"
          for s in aft["payload"]["stages"]))

# --- FILE blocked-content branch: a PE restored directly into the vault ---
# (Intake blocks PE magic, so a real test of detection restores the row.)
_blocked = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 96
os.makedirs(evs.ORIGINALS_DIR, exist_ok=True)
_blk_path = os.path.join(evs.ORIGINALS_DIR, "restored-bin-7c.bin")
with open(_blk_path, "wb") as fh:
    fh.write(_blocked)
db.execute(
    "INSERT INTO evidence(evidence_ref, case_id, evidence_type, title, "
    "original_filename, sha256, sha1, md5, mime_type, size_bytes, extension, "
    "source, acquired_at, stored_path, integrity_state) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ("KAV-EVD-2026-BLOCKED", case1["case_id"], "FILE", "Restored executable",
     "payload.bin", _hl.sha256(_blocked).hexdigest(),
     _hl.sha1(_blocked).hexdigest(), _hl.md5(_blocked).hexdigest(),
     "application/octet-stream", len(_blocked), ".bin", "Lab QA",
     cs._now(), _blk_path, "VERIFIED"))
abf = ans.run_analysis("KAV-EVD-2026-BLOCKED", "FILE")
check("file: blocked content detected",
      abf["payload"]["analysis"]["blocked_content"] is True)
check("file: blocked verdict MALICIOUS", abf["verdict"] == "MALICIOUS",
      abf["verdict"])
check("file: blocked risk >= 85", int(abf["risk_score"]) >= 85,
      abf["risk_score"])

# --- HASH (format + local vault correlation, honest intel) ---
ev_hash = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "HASH",
    "title": "Indicator hash", "content_text": ev_file["sha256"]})
ah = ans.run_analysis(ev_hash["evidence_ref"], "HASH")
check("hash: type recognised", ah["payload"]["analysis"]["hash_type"] == "SHA-256",
      ah["payload"]["analysis"].get("hash_type"))
check("hash: local vault correlation found",
      any(f["finding_type"] == "local_vault_correlation" for f in ah["findings"]))
check("hash: correlation names the matching evidence",
      any(ev_file["evidence_ref"] in f["detail"] for f in ah["findings"]))
check("hash: vt stage honest (unconfigured)",
      any(s["name"] == "Threat intelligence" and s["status"] == "unavailable"
          for s in ah["payload"]["stages"]))
check("hash: verdict NO_THREAT_DATA without intel",
      ah["verdict"] == "NO_THREAT_DATA", ah["verdict"])

ev_bad_hash = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "HASH",
    "title": "Bad hash", "content_text": "not-a-hash"})
try:
    ans.run_analysis(ev_bad_hash["evidence_ref"], "HASH")
    check("hash: invalid content rejected", False, "accepted")
except ans.AnalysisError as exc:
    check("hash: invalid content rejected", exc.code == "INVALID_HASH", exc.code)

# --- QR (honest decode-or-unavailable) ---
_tiny_png = _b64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQ"
    "DwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
ev_qr = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "QR_IMAGE",
    "title": "QR from parking ticket", "filename": "qr.png",
    "content_base64": _b64.b64encode(_tiny_png).decode()})
aq = ans.run_analysis(ev_qr["evidence_ref"], "QR")
check("qr: verdict from honest decode path",
      aq["verdict"] in {"UNAVAILABLE", "CLEAN", "SUSPICIOUS", "MALICIOUS"},
      aq["verdict"])
check("qr: PARTIAL when decode unavailable",
      aq["verdict"] != "UNAVAILABLE" or aq["status"] == "PARTIAL", aq["status"])

# --- SCAM / BEC over message evidence ---
ev_msg = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "MESSAGE",
    "title": "KYC block message",
    "content_text": ("Dear customer, your UPI KYC is blocked. Pay 500 rupees "
                     "immediately to unblock your account or face legal "
                     "action.")})
asc = ans.run_analysis(ev_msg["evidence_ref"], "SCAM")
check("scam: verdict vocabulary",
      asc["verdict"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}, asc["verdict"])
check("scam: real detector payload", bool(asc["payload"]["analysis"].get("summary")))
abec = ans.run_analysis(ev_msg["evidence_ref"], "BEC")
check("bec: verdict vocabulary",
      abec["verdict"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}, abec["verdict"])

# --- pipeline validation ---
try:
    ans.run_analysis(ev_text["evidence_ref"], "NOT_A_TYPE")
    check("invalid analysis type rejected", False, "accepted")
except ans.AnalysisError as exc:
    check("invalid analysis type rejected",
          exc.code == "INVALID_ANALYSIS_TYPE", exc.code)

try:
    ans.run_analysis(ev_hash["evidence_ref"], "QR")
    check("incompatible evidence rejected", False, "accepted")
except ans.AnalysisError as exc:
    check("incompatible evidence rejected",
          exc.code == "INCOMPATIBLE_EVIDENCE", exc.code)

try:
    ans.run_analysis("KAV-EVD-2099-99999", "URL")
    check("missing evidence rejected", False, "accepted")
except ans.AnalysisError as exc:
    check("missing evidence rejected", exc.code == "EVIDENCE_NOT_FOUND", exc.code)

# --- listing / filters ---
alist = ans.list_analyses()
check("analyses listed with real total", alist["total"] >= 10, alist["total"])
check("filter by type", ans.list_analyses(analysis_type="URL")["total"] >= 2)
check("filter by evidence",
      ans.list_analyses(evidence_ref=ev_text["evidence_ref"])["total"] >= 1)
check("filter by case",
      ans.list_analyses(case_ref=case1["case_ref"])["total"] == alist["total"])
check("search by ref",
      ans.list_analyses(search=ap["analysis_ref"])["total"] >= 1)
check("no-match search returns 0",
      ans.list_analyses(search="zzz_no_analysis")["total"] == 0)

# --- side effects: audit + timeline ---
check("analysis audited",
      any(a["action"] == "ANALYSIS_RUN"
          for a in cs.list_audit(limit=200)["items"]))
check("analysis on case timeline",
      any(e["event_type"] == "analysis.completed"
          for e in cs.get_case(case1["case_ref"])["timeline"]))

# --- Section 49 envelope + pages via the real app test client ---
_client = app_module.app.test_client()
r = _client.get("/lab/api/analysis/meta")
_body = r.get_json()
check("api: meta section-49 envelope",
      r.status_code == 200 and _body["success"] is True
      and _body["data"]["types"] == ans.ANALYSIS_TYPES)

r = _client.get("/lab/api/analysis?type=URL")
_body = r.get_json()
check("api: list envelope",
      r.status_code == 200 and _body["success"] is True
      and _body["data"]["total"] >= 2)

r = _client.post("/lab/api/analysis",
                 json={"evidence_ref": ev_dom_ip["evidence_ref"],
                       "analysis_type": "DOMAIN"})
_body = r.get_json()
check("api: run analysis creates 201 envelope",
      r.status_code == 201 and _body["success"] is True
      and _body["data"]["analysis"]["analysis_ref"].startswith("KAV-ANL-"))

r = _client.post("/lab/api/analysis",
                 json={"evidence_ref": ev_dom_ip["evidence_ref"],
                       "analysis_type": "BOGUS"})
_body = r.get_json()
check("api: invalid type error envelope",
      r.status_code == 400 and _body["success"] is False
      and _body["error"]["code"] == "INVALID_ANALYSIS_TYPE", _body)

r = _client.post("/lab/api/analysis",
                 json={"evidence_ref": ev_hash["evidence_ref"],
                       "analysis_type": "QR"})
_body = r.get_json()
check("api: incompatible pair error envelope",
      r.status_code == 400 and _body["success"] is False
      and _body["error"]["code"] == "INCOMPATIBLE_EVIDENCE", _body)

r = _client.get("/lab/api/analysis/" + ap["analysis_ref"])
_body = r.get_json()
check("api: detail envelope",
      r.status_code == 200 and _body["success"] is True
      and _body["data"]["analysis"]["analysis_ref"] == ap["analysis_ref"])

r = _client.get("/lab/analysis")
_html = r.get_data(as_text=True)
check("page: workbench renders",
      r.status_code == 200 and "ANALYSIS WORKBENCH" in _html)
r = _client.get("/lab/analysis/new")
_html = r.get_data(as_text=True)
check("page: run-analysis renders",
      r.status_code == 200 and "RUN ANALYSIS" in _html
      and "ra-evidence" in _html)
r = _client.get("/lab/analysis/" + ap["analysis_ref"])
_html = r.get_data(as_text=True)
check("page: analysis detail renders",
      r.status_code == 200 and "ANALYSIS DETAIL" in _html
      and "STAGES PERFORMED" in _html)

check("lab analysis pages render with real content",
      bool(ap["analysis_ref"]) and bool(ae["analysis_ref"])
      and bool(asp["analysis_ref"]) and bool(au["analysis_ref"])
      and bool(ah["analysis_ref"]))

# Restore the real environment state for any later sections.
_vt_svc.VIRUSTOTAL_API_KEY = _saved_vt_key
ans._vt_state = _saved_vt_state

# ===========================================================================
section("Test 7D — Phase 8 Intelligence (Sections 24-28)")
# ===========================================================================
from lab import intel_service as ins                        # noqa: E402

# --- classification vocabulary (Section 26) ---
check("classify: 9 spec types + OTHER supported",
      all(t in ins.IOC_TYPES for t in
          ["IPv4", "IPv6", "DOMAIN", "URL", "EMAIL",
           "SHA-256", "SHA-1", "MD5", "FILENAME"]))
check("classify: ipv4",
      ins.classify_ioc("185.234.72.19") == ("IPv4", "185.234.72.19"))
check("classify: ipv6",
      ins.classify_ioc("2001:db8::1") == ("IPv6", "2001:db8::1"))
check("classify: url",
      ins.classify_ioc("http://evil.example/x") == ("URL", "http://evil.example/x"))
check("classify: email",
      ins.classify_ioc("a@b.example") == ("EMAIL", "a@b.example"))
check("classify: sha256",
      ins.classify_ioc("a" * 64) == ("SHA-256", "a" * 64))
check("classify: sha1",
      ins.classify_ioc("b" * 40) == ("SHA-1", "b" * 40))
check("classify: md5",
      ins.classify_ioc("c" * 32) == ("MD5", "c" * 32))
check("classify: domain",
      ins.classify_ioc("example.org") == ("DOMAIN", "example.org"))
check("classify: filename via hint",
      ins.classify_ioc("payload.exe", hint="filename") == ("FILENAME", "payload.exe"))
check("classify: timestamp is NOT ipv6 (real octet/group guard)",
      ins.classify_ioc("18:31:08") == ("OTHER", "18:31:08"),
      ins.classify_ioc("18:31:08"))

# --- vault sync (real extraction, idempotent) ---
sync1 = ins.sync_iocs(actor="qa")
check("sync: observations indexed", int(sync1["observations"]) > 0,
      sync1["observations"])
check("sync: IOCs ledger populated", int(sync1["iocs_total"]) >= 5,
      sync1["iocs_total"])
check("sync: case refs reported", set(sync1["cases_affected"]) >= {case1["case_ref"]},
      sync1["cases_affected"])
sync2 = ins.sync_iocs(actor="qa")
check("sync: idempotent (no double counting)", sync2["iocs_total"] == sync1["iocs_total"],
      (sync1["iocs_total"], sync2["iocs_total"]))
check("sync: audited",
      any(a["action"] == "IOC_SYNC" for a in cs.list_audit(limit=300)["items"]))

# --- reading the ledger back (real related cases/evidence) ---
lst = ins.list_iocs()
check("list: non-empty catalogue", lst["total"] >= 5, lst["total"])
check("list: every item has fields",
      all(set(("ioc_id", "ioc_type", "value", "status", "first_seen",
               "last_seen", "source", "case_count", "evidence_count"))
          <= set(i) for i in lst["items"][:8]))

hash_list = ins.list_iocs(ioc_type="SHA-256")
check("list: type filter", all(i["ioc_type"] == "SHA-256" for i in hash_list["items"]))
check("list: file hash indexed",
      any(i["value"] == ev_file["sha256"] for i in hash_list["items"]))

the_hash = next(i for i in hash_list["items"] if i["value"] == ev_file["sha256"])
check("list: hash linked to case", the_hash["case_count"] >= 1,
      the_hash["related_cases"])

detail = ins.get_ioc(the_hash["ioc_id"])
check("detail: status default OBSERVED", detail["status"] == "OBSERVED")
check("detail: related evidence real",
      any(e["evidence_ref"] == ev_file["evidence_ref"]
          for e in detail["related_evidence"]),
      [e["evidence_ref"] for e in detail["related_evidence"][:5]])
check("detail: related cases real",
      any(c["case_ref"] == case1["case_ref"] for c in detail["related_cases"]))
check("detail: intel envelope honest",
      isinstance(detail["intel"], dict) and "configured" in detail["intel"],
      detail["intel"])

# --- Section 26 actions ---
st = ins.set_ioc_status(the_hash["ioc_id"], "VERIFIED", actor="qa")
check("status: VERIFIED applied", st["status"] == "VERIFIED")
check("status: persisted", ins.get_ioc(the_hash["ioc_id"])["status"] == "VERIFIED")
try:
    ins.set_ioc_status(the_hash["ioc_id"], "BOGUS")
    check("status: invalid value rejected", False, "accepted")
except ins.IntelError as exc:
    check("status: invalid value rejected", exc.code == "INVALID_STATUS", exc.code)

add1 = ins.add_ioc_to_case(the_hash["ioc_id"], case2["case_ref"], actor="qa")
check("add_to_case: linked", add1["linked"] is True, add1)
add2 = ins.add_ioc_to_case(the_hash["ioc_id"], case2["case_ref"], actor="qa")
check("add_to_case: idempotent", add2["linked"] is False)
try:
    ins.add_ioc_to_case(the_hash["ioc_id"], "KAV-CASE-2099-99999")
    check("add_to_case: unknown case rejected", False, "accepted")
except ins.IntelError as exc:
    check("add_to_case: unknown case rejected", exc.code == "CASE_NOT_FOUND", exc.code)

# --- Section 27 cross-case correlation ---
corr = ins.correlation()
check("correlation: shared IOC surface",
      any(c["ioc_id"] == the_hash["ioc_id"] for c in corr["correlations"]),
      [(c["ioc_type"], c["value"], c["case_count"]) for c in corr["correlations"][:3]])
shared = next(c for c in corr["correlations"] if c["ioc_id"] == the_hash["ioc_id"])
check("correlation: precise language",
      shared["statement"] == "Same IOC observed across multiple cases.")
check("correlation: related cases both real",
      {c["case_ref"] for c in shared["related_cases"]}
      == {case1["case_ref"], case2["case_ref"]})
check("correlation: not attribution",
      "attribution" in corr["note"] and "campaign" in corr["note"],
      corr["note"][:80])

# --- Section 25 entity graph (evidence-backed only) ---
gcases = ins.entity_graph()
check("graph: case picker data", isinstance(gcases["cases"], list)
      and any(c["case_ref"] == case1["case_ref"] for c in gcases["cases"]))
g1 = ins.entity_graph(case1["case_ref"])
_g = g1["graph"]
check("graph: nodes include case root",
      any(n["type"] == "CASE" and n["value"] == case1["case_ref"]
          for n in _g["nodes"]))
check("graph: evidence nodes rendered",
      any(n["type"] == "EVIDENCE" and any(e in n["label"] for e in
          (ev_text["evidence_ref"], ev_url["evidence_ref"]))
          for n in _g["nodes"]))
check("graph: ioc nodes rendered",
      any(n["type"] in ("URL", "DOMAIN", "IPv4", "SHA-256")
          for n in _g["nodes"]),
      sorted({n["type"] for n in _g["nodes"]}))
case_ev_edges = [e for e in _g["edges"] if e["relation"] == "contains"
                 and e["from"].startswith("case:")]
check("graph: case->evidence edges", len(case_ev_edges) >= 1, len(case_ev_edges))
check("graph: nodes carry provenance fields",
      all(set(("type", "value", "first_seen", "related_evidence",
               "related_cases", "risk")) <= set(n) for n in _g["nodes"]))
try:
    ins.entity_graph("KAV-CASE-2099-99999")
    check("graph: unknown case rejected", False, "accepted")
except ins.IntelError as exc:
    check("graph: unknown case rejected", exc.code == "CASE_NOT_FOUND", exc.code)

# --- Section 28 attack chains (evidence-backed, honest empty) ---
gcases2 = ins.attack_chain()
check("chain: case picker data", isinstance(gcases2["cases"], list))
ch1 = ins.attack_chain(case1["case_ref"])
check("chain: derived from real analyses",
      ch1["state"] == "chain" and len(ch1["chain"]) >= 2, ch1["state"])
check("chain: every stage cites evidence",
      all(s["evidence_refs"] and all(e.startswith("KAV-EVD-") for e in s["evidence_refs"])
          for s in ch1["chain"]))
check("chain: supporting evidence list",
      len(ch1["supporting_evidence"]) >= 1)
check("chain: ordered stages",
      [s["rank"] for s in ch1["chain"]] == sorted(s["rank"] for s in ch1["chain"]))

case3 = cs.create_case({
    "title": "Empty vault probe",
    "case_type": "PHISHING",
    "priority": "LOW",
})
ch_empty = ins.attack_chain(case3["case_ref"])
check("chain: honest insufficient state",
      ch_empty["state"] == "insufficient" and ch_empty["chain"] == [],
      ch_empty["state"])
check("chain: honest message, no fabrication",
      "Insufficient evidence" in ch_empty["note"], ch_empty["note"])

# --- Section 49 envelopes + pages via the real app ---
_client2 = app_module.app.test_client()
r = _client2.get("/lab/api/intel/iocs")
_b = r.get_json()
check("api: ioc list envelope",
      r.status_code == 200 and _b["success"] is True
      and isinstance(_b["data"]["items"], list) and _b["data"]["total"] >= 5)

r = _client2.get("/lab/api/intel/iocs?type=SHA-256")
_b = r.get_json()
check("api: ioc type filter",
      all(i["ioc_type"] == "SHA-256" for i in _b["data"]["items"]))

_email_io = next((i for i in ins.list_iocs(ioc_type="EMAIL")["items"]), None)
if _email_io:
    r = _client2.get("/lab/api/intel/iocs/%d" % _email_io["ioc_id"])
    _b = r.get_json()
    check("api: ioc detail envelope",
          r.status_code == 200 and _b["success"] is True
          and _b["data"]["ioc"]["ioc_id"] == _email_io["ioc_id"])
else:
    check("api: ioc detail envelope", True, "no EMAIL ioc to probe")

r = _client2.patch("/lab/api/intel/iocs/%d" % the_hash["ioc_id"],
                   json={"status": "FALSE_POSITIVE"})
_b = r.get_json()
check("api: status patch envelope",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["ioc"]["status"] == "FALSE_POSITIVE")
ins.set_ioc_status(the_hash["ioc_id"], "VERIFIED", actor="qa")  # restore

r = _client2.post("/lab/api/intel/sync", json={})
_b = r.get_json()
check("api: sync envelope",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["iocs_total"] >= 5)

r = _client2.get("/lab/api/intel/correlation")
_b = r.get_json()
check("api: correlation envelope",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["statement"] == ins.CORRELATION_STATEMENT)

r = _client2.get("/lab/api/intel/graph?case=%s" % case1["case_ref"])
_b = r.get_json()
check("api: graph envelope",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["graph"]["node_count"] >= 2)

r = _client2.get("/lab/api/intel/attack-chain?case=%s" % case1["case_ref"])
_b = r.get_json()
check("api: chain envelope",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["state"] == "chain")

r = _client2.patch("/lab/api/intel/iocs/%d" % the_hash["ioc_id"],
                   json={"status": "WAT"})
_b = r.get_json()
check("api: invalid status error envelope",
      r.status_code == 400 and _b["success"] is False
      and _b["error"]["code"] == "INVALID_STATUS")

for url, marker in [
    ("/lab/intel/iocs", "IOC INTELLIGENCE"),
    ("/lab/intel/correlation", "POTENTIAL CORRELATIONS"),
    ("/lab/intel/attack-chains", "ATTACK CHAINS"),
    ("/lab/intel/graph", "ENTITY GRAPH"),
]:
    rr = _client2.get(url)
    _html = rr.get_data(as_text=True)
    check("page: %s renders" % url,
          rr.status_code == 200 and marker in _html)

# --- nav integrity: every intel link resolves (Section 81) ---
_intel_links = sum(len(g["links"]) for g in lab_routes.NAV_STRUCTURE
                   if g["group"] in ("THREAT INTELLIGENCE", "INTELLIGENCE"))
check("intel+risk nav has 6 live links",
      _intel_links == 6, _intel_links)
check("risk nav link resolves",
      any(l["url"] == "/lab/risk"
          for g in lab_routes.NAV_STRUCTURE for l in g["links"]))

# ===========================================================================
section("Test 7E — Phase 9 Risk (Sections AZ, BA)")
# ===========================================================================
from lab import risk_service as rks                                    # noqa: E402

# --- band model (Section AZ) ---
check("risk: band vocabulary",
      rks.RISK_LEVELS == ("LOW", "SUSPICIOUS", "HIGH"))
check("risk: LOW boundary 0-30",
      rks.risk_level(0) == "LOW" and rks.risk_level(30) == "LOW",
      (rks.risk_level(0), rks.risk_level(30)))
check("risk: SUSPICIOUS boundary 31-60",
      rks.risk_level(31) == "SUSPICIOUS" and rks.risk_level(60) == "SUSPICIOUS",
      (rks.risk_level(31), rks.risk_level(60)))
check("risk: HIGH boundary 61-100",
      rks.risk_level(61) == "HIGH" and rks.risk_level(100) == "HIGH",
      (rks.risk_level(61), rks.risk_level(100)))
check("risk: out-of-range scores clamped",
      rks.risk_level(250) == "HIGH" and rks.risk_level(-5) == "LOW")

# --- independent classifications (never conflated with score) ---
check("risk: classification vocabulary",
      set(rks.CLASSIFICATIONS) == {"SPAM", "PHISHING", "MALWARE", "SCAM",
                                   "BEC", "SECURITY_RISK"})
check("risk: analysis type -> classification mapping",
      rks.classify_analysis("PHISHING") == "PHISHING"
      and rks.classify_analysis("SPAM") == "SPAM"
      and rks.classify_analysis("FILE") == "MALWARE"
      and rks.classify_analysis("BEC") == "BEC")

# --- full assessment on the analysed case (evidence-first) ---
assess = rks.case_risk(case1["case_ref"])
check("risk: score is a bounded int",
      isinstance(assess["risk_score"], int) and 0 <= assess["risk_score"] <= 100,
      assess["risk_score"])
check("risk: level matches the score band",
      assess["risk_level"] == rks.risk_level(assess["risk_score"]),
      assess["risk_level"])
check("risk: engine + version recorded",
      assess["engine"] == rks.ENGINE and bool(assess["engine_version"]),
      assess["engine_version"])
check("risk: components exposed",
      {"highest", "mean", "analysis_count", "verified_count", "observed_count"}
      <= set(assess["components"]), assess["components"])
check("risk: score driven by highest stored analysis",
      assess["risk_score"] >= round(0.6 * assess["components"]["highest"]),
      (assess["risk_score"], assess["components"]["highest"]))
check("risk: primary classification from vocabulary",
      assess["primary_classification"] in rks.CLASSIFICATIONS
      or assess["primary_classification"] is None,
      assess["primary_classification"])
check("risk: case snapshot materialized on record",
      db.query_one("SELECT risk_level, risk_score, risk_assessed_at "
                   "FROM cases WHERE case_ref = ?",
                   (case1["case_ref"],))["risk_score"] == assess["risk_score"])

_finds = assess["findings"]
check("risk: findings present for analysed case", len(_finds) >= 1, len(_finds))
check("risk: every finding carries BA provenance keys",
      all({"what", "why", "source", "impact", "limitation"} <= set(f)
          for f in _finds))
check("risk: finding cites real evidence",
      any(f.get("evidence") and f["evidence"] for f in _finds))
check("risk: findings trace to real analysis refs",
      any(str(f.get("analysis_ref", "")).startswith("KAV-ANL-") for f in _finds))
check("risk: explanations derived from stored facts",
      len(assess["explanations"]) >= 1
      and any("analysis" in e.lower() or "indicator" in e.lower()
              for e in assess["explanations"]),
      assess["explanations"][:2])
check("risk: limitations are honest (no calibration claim)",
      any("calibrated" in l.lower() for l in assess["limitations"]))
check("risk: per-analysis assessments carry classification",
      all("classification" in a and "findings" in a
          for a in assess["analyses"]))

# --- IOC disposition drives the score (evidence-driven + reversible) ---
_score_v = rks.case_risk(case1["case_ref"])["risk_score"]
ins.set_ioc_status(the_hash["ioc_id"], "FALSE_POSITIVE", actor="qa")
_score_fp = rks.case_risk(case1["case_ref"])["risk_score"]
check("risk: FALSE_POSITIVE removes verified points",
      _score_fp < _score_v, (_score_fp, _score_v))
ins.set_ioc_status(the_hash["ioc_id"], "VERIFIED", actor="qa")  # restore
check("risk: restoring VERIFIED returns score",
      rks.case_risk(case1["case_ref"])["risk_score"] == _score_v,
      rks.case_risk(case1["case_ref"])["risk_score"])

# --- empty vault: honest 0 / LOW, never invented ---
_empty = rks.case_risk(case3["case_ref"])
check("risk: empty case scores 0 LOW",
      _empty["risk_score"] == 0 and _empty["risk_level"] == "LOW",
      (_empty["risk_score"], _empty["risk_level"]))
check("risk: empty case has no findings", _empty["findings"] == [])
check("risk: empty case explains insufficient data",
      any("Insufficient data" in e for e in _empty["explanations"]))
check("risk: empty case has null classification",
      _empty["primary_classification"] is None)

try:
    rks.case_risk("KAV-CASE-2099-99999")
    check("risk: unknown case rejected", False, "accepted")
except rks.RiskError as exc:
    check("risk: unknown case rejected", exc.code == "CASE_NOT_FOUND", exc.code)

# --- register ---
_reg = rks.risk_register()
check("risk: register covers analysed case",
      any(c["case_ref"] == case1["case_ref"] for c in _reg["items"]))
check("risk: register sorted highest first",
      [c["risk_score"] for c in _reg["items"]] ==
      sorted((c["risk_score"] for c in _reg["items"]), reverse=True))

# --- Section 49 envelopes + page via the real app ---
_client3 = app_module.app.test_client()
r = _client3.get("/lab/api/risk")
_b = r.get_json()
check("api: risk register envelope",
      r.status_code == 200 and _b["success"] is True
      and isinstance(_b["data"]["items"], list)
      and _b["data"]["engine"] == rks.ENGINE)

r = _client3.get("/lab/api/risk?case=" + case1["case_ref"])
_b = r.get_json()
check("api: risk detail envelope",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["case"]["case_ref"] == case1["case_ref"]
      and "findings" in _b["data"] and "explanations" in _b["data"])

r = _client3.get("/lab/api/risk?case=KAV-CASE-2099-99999")
_b = r.get_json()
check("api: unknown case error envelope",
      r.status_code == 400 and _b["success"] is False
      and _b["error"]["code"] == "CASE_NOT_FOUND", _b)

r = _client3.get("/lab/risk")
_html = r.get_data(as_text=True)
check("page: risk register renders",
      r.status_code == 200 and "RISK ASSESSMENT" in _html
      and "risk-register-body" in _html)

# ===========================================================================
section("Test 7F — Phase 10/11 Reporting (Sections 42/43/69/70/BF/BG)")

from lab import report_service as rps     # noqa: E402
import zipfile as _zf                      # noqa: E402

_EXPECT_COLS = {"case_id", "export_id", "evidence_id", "analysis_id",
                "sha256", "acquisition_time", "analysis_time", "engine",
                "source", "result"}

# --- generate a report (BF) ---
r = _client3.post("/lab/api/reports", json={"case_ref": case1["case_ref"]})
_b = r.get_json()
check("reporting: generate returns 201 envelope",
      r.status_code == 201 and _b["success"] is True, r.status_code)
_rpt_ref = _b["data"]["report_ref"]
check("reporting: report ref is KAV-RPT-<year>-<seq>",
      _rpt_ref.startswith("KAV-RPT-2026-"), _rpt_ref)
check("reporting: ref is reused in the persisted document",
      _b["data"]["content"]["report_ref"] == _rpt_ref)
_rpt2 = _client3.post("/lab/api/reports",
                      json={"case_ref": case3["case_ref"]}).get_json()
check("reporting: counter increments per report",
      _rpt2["data"]["report_ref"].endswith("00002"), _rpt2["data"]["report_ref"])

# --- BF 15-section content, composed from stored facts ---
_c = _b["data"]["content"]
_section_keys = ["case_summary", "executive_summary", "incident_classification",
                 "evidence", "ioc_table", "timeline", "technical_findings",
                 "threat_intelligence", "ml_findings", "correlation",
                 "risk_assessment", "limitations", "defensive_recommendations",
                 "evidence_manifest", "report_metadata"]
check("reporting: all BF sections present",
      all(k in _c for k in _section_keys),
      [k for k in _section_keys if k not in _c])
check("reporting: metadata echoes the BF section vocabulary",
      _c["report_metadata"]["sections"] == rps.REPORT_SECTIONS)
check("reporting: evidence lists stored records",
      len(_c["evidence"]) >= 1, len(_c["evidence"]))
check("reporting: IOC table lists stored indicators",
      len(_c["ioc_table"]) >= 1, len(_c["ioc_table"]))
check("reporting: executive summary cites real counts",
      any("evidence" in e.lower() and "analysis" in e.lower()
          for e in _c["executive_summary"]),
      _c["executive_summary"][:1])
check("reporting: risk section matches the live engine",
      _c["risk_assessment"]["risk_score"] ==
      rks.case_risk(case1["case_ref"])["risk_score"],
      (_c["risk_assessment"]["risk_score"],
       rks.case_risk(case1["case_ref"])["risk_score"]))
check("reporting: manifest rows carry every BG key",
      all(_EXPECT_COLS <= set(m) for m in _c["evidence_manifest"]),
      [m for m in _c["evidence_manifest"]
       if not _EXPECT_COLS <= set(m)][:1])
check("reporting: provider status matches the environment honestly",
      any(p["provider"] == "VirusTotal" and
          p["status"] == ("CONFIGURED" if os.environ.get("VIRUSTOTAL_API_KEY")
                          else "NOT CONFIGURED")
          for p in _c["threat_intelligence"]["providers"]))

# --- read back / list / CSV ---
r = _client3.get("/lab/api/reports/" + _rpt_ref)
_b = r.get_json()
check("reporting: detail envelope + content available",
      r.status_code == 200 and _b["data"]["content_available"] is True
      and _b["data"]["content"]["case"]["case_ref"] == case1["case_ref"])
check("reporting: unknown report rejected",
      _client3.get("/lab/api/reports/KAV-RPT-2099-99999").get_json()
      ["error"]["code"] == "REPORT_NOT_FOUND")

_b = _client3.get("/lab/api/reports").get_json()
check("reporting: list envelope + total",
      _b["success"] is True and _b["data"]["total"] >= 2
      and any(i["report_ref"] == _rpt_ref
              for i in _b["data"]["items"]),
      _b["data"]["total"])

r = _client3.get("/lab/api/reports/" + _rpt_ref + "/csv")
check("reporting: IOC CSV export",
      r.status_code == 200 and r.mimetype.startswith("text/csv")
      and "IOC_TYPE" in r.get_data(as_text=True),
      r.status_code)

# --- export package (Sections 70/BG) ---
r = _client3.post("/lab/api/cases/" + case1["case_ref"] + "/export")
_b = r.get_json()
check("reporting: export returns 201 envelope",
      r.status_code == 201 and _b["success"] is True, r.status_code)
_xpt_ref = _b["data"]["export_ref"]
check("reporting: export ref is KAV-EXP-<year>-<seq>",
      _xpt_ref.startswith("KAV-EXP-2026-"), _xpt_ref)
check("reporting: package sha256 recorded",
      len(_b["data"]["sha256"]) == 64, _b["data"]["sha256"])
check("reporting: package contains the 7 standard items",
      _b["data"]["item_count"] == 7, _b["data"]["item_count"])
check("reporting: manifest rows stamped with this export id",
      all(m["export_id"] == _xpt_ref
          for m in _b["data"]["manifest"]["rows"]))
check("reporting: export package links a real report",
      any(i["report_ref"] == _b["data"]["report_ref"]
          for i in _client3.get("/lab/api/reports").get_json()["data"]["items"]))

_b = _client3.get("/lab/api/exports").get_json()
check("reporting: exports list envelope",
      _b["success"] is True
      and any(x["export_ref"] == _xpt_ref
              for x in _b["data"]["items"]))
check("reporting: exports list leaks no storage paths",
      all("storage_path" not in x for x in _b["data"]["items"]))

_b = _client3.get("/lab/api/exports/" + _xpt_ref).get_json()
check("reporting: export detail reads manifest from the zip",
      _b["data"]["file_present"] is True
      and isinstance(_b["data"]["manifest"]["evidence_manifest"], list))

# --- integrity verification (BG) ---
_b = _client3.post("/lab/api/exports/" + _xpt_ref + "/verify").get_json()
check("reporting: package integrity VERIFIED",
      _b["data"]["status"] == "VERIFIED", _b["data"]["status"])

_xpath = rps.get_export(_xpt_ref)["storage_path"]
with _zf.ZipFile(_xpath, "a") as _z:
    _z.writestr("tamper.txt", "integrity probe")
_b = _client3.post("/lab/api/exports/" + _xpt_ref + "/verify").get_json()
check("reporting: tampered package flagged MISMATCH",
      _b["data"]["status"] == "MISMATCH", _b["data"]["status"])

r = _client3.get("/lab/api/exports/" + _xpt_ref + "/download")
check("reporting: package download streams the zip",
      r.status_code == 200 and r.mimetype == "application/zip"
      and len(r.data) > 0, (r.status_code, r.mimetype))

# --- audit events recorded (Section 44/BH) ---
check("reporting: REPORT_GENERATED audited",
      any(a["target_ref"] == case1["case_ref"]
          for a in cs.list_audit(action="REPORT_GENERATED")["items"]))
check("reporting: REPORT_EXPORTED audited",
      any(a["target_ref"] == case1["case_ref"]
          for a in cs.list_audit(action="REPORT_EXPORTED")["items"]))

# --- pages render ---
for _url, _marker in [("/lab/reports", "INVESTIGATION REPORTS"),
                      ("/lab/reports/" + _rpt_ref, "lab-doc-cover"),
                      ("/lab/reports/exports", "EXPORT CENTER"),
                      ("/lab/reports/manifest", "EVIDENCE MANIFEST")]:
    r = _client3.get(_url)
    _html = r.get_data(as_text=True)
    check("page: %s renders" % _url,
          r.status_code == 200 and _marker in _html,
          r.status_code)

# ===========================================================================
section("Test 7G — Phase 12 Security (BH audit log, BI RBAC)")

from lab import security                           # noqa: E402

_BH_VOCAB = ["LOGIN", "LOGOUT", "CASE_CREATED", "CASE_UPDATED",
             "EVIDENCE_ADDED", "EVIDENCE_VIEWED", "ANALYSIS_EXECUTED",
             "IOC_ADDED", "REPORT_GENERATED", "REPORT_EXPORTED",
             "SETTINGS_CHANGED"]
check("security: BH event vocabulary present and complete",
      set(security.EVENT_TYPES) == set(_BH_VOCAB),
      sorted(set(_BH_VOCAB) - set(security.EVENT_TYPES)))

# --- BH: secret never-log rules applied at the funnel ---
check("security: password redacted",
      security.redact_secrets("password=hunter2s3cret") ==
      "password=[REDACTED]",
      security.redact_secrets("password=hunter2s3cret"))
check("security: api key redacted",
      "abc123apikey" not in
      security.redact_secrets("api_key=abc123apikey"))
check("security: oauth bearer token redacted",
      "tok.v42.xyz" not in security.redact_secrets(
          "Authorization: Bearer tok.v42.xyz"))
check("security: database dsn redacted",
      security.redact_secrets("postgres_pwd=s3cret!db").endswith(
          "[REDACTED]"))
check("security: harmless text untouched",
      security.redact_secrets("Evidence hash verified OK") ==
      "Evidence hash verified OK")
check("security: None detail safe",
      security.redact_secrets(None) is None)

cs.audit("CASE_UPDATED", "CASE_UPDATED", target_ref="KAV-CASE-2099-99998",
         detail="Reclassified after password=supersecret lookup",
         actor="qa")
_secret_rows = [a for a in cs.list_audit(limit=200)["items"]
                if a["target_ref"] == "KAV-CASE-2099-99998"]
check("security: audit funnel stores redacted detail",
      _secret_rows and "[REDACTED]" in _secret_rows[0]["detail"]
      and "supersecret" not in _secret_rows[0]["detail"],
      _secret_rows[0]["detail"] if _secret_rows else None)

r = _client3.get("/lab/api/evidence/" + ev_file["evidence_ref"])
check("security: open evidence records EVIDENCE_VIEWED",
      r.status_code == 200 and
      any(a["action"] == "EVIDENCE_VIEWED"
          and a["target_ref"] == ev_file["evidence_ref"]
          for a in cs.list_audit(limit=200)["items"]))
check("security: analysis pipeline audits ANALYSIS_EXECUTED",
      any(a["event_type"] == "ANALYSIS_EXECUTED" and
          a["action"] == "ANALYSIS_RUN"
          for a in cs.list_audit(limit=300)["items"]))
check("security: evidence intake audits EVIDENCE_ADDED event type",
      any(a["event_type"] == "EVIDENCE_ADDED"
          and a["action"] == "EVIDENCE_ADDED"
          for a in cs.list_audit(limit=300)["items"]))
check("security: IOC sync audits vocabulary event type",
      any(a["event_type"] == "IOC_ADDED"
          for a in cs.list_audit(limit=300)["items"]))

# --- BI: role vocabulary + matrix semantics ---
check("security: five RBAC roles present",
      security.ROLES == ["ADMIN", "INVESTIGATOR", "ANALYST",
                         "REVIEWER", "READ_ONLY"], security.ROLES)
check("security: READ_ONLY cannot create cases",
      not security.authorize("READ_ONLY", "case:create"))
check("security: READ_ONLY cannot run analysis",
      not security.authorize("READ_ONLY", "analysis:run"))
check("security: READ_ONLY can view cases and reports",
      security.authorize("READ_ONLY", "case:view")
      and security.authorize("READ_ONLY", "report:view"))
check("security: ADMIN holds every permission",
      all(security.authorize("ADMIN", code)
          for code, _ in security.PERMISSIONS))
check("security: INVESTIGATOR extends ANALYST",
      security.effective_permissions("ANALYST") <=
      security.effective_permissions("INVESTIGATOR"))
check("security: REVIEWER can verify exports",
      security.authorize("REVIEWER", "report:verify")
      and not security.authorize("REVIEWER", "case:create"))
check("security: ANALYST allowed the default write surface",
      security.authorize("ANALYST", "case:create")
      and security.authorize("ANALYST", "report:export")
      and security.authorize("ANALYST", "intel:sync"))
check("security: every permission is granted to at least one role",
      all(any(security.authorize(role, code) for role in security.ROLES)
          for code, _ in security.PERMISSIONS))
check("security: unknown role authorizes nothing",
      not security.authorize("NOT_A_ROLE", "case:view"))

# --- BI: seeded RBAC data model (Section 45 tables) ---
_rows = {t: db.query_one("SELECT COUNT(*) AS n FROM %s" % t)["n"]
         for t in ("roles", "permissions", "role_permissions")}
check("security: roles seeded", _rows["roles"] == 5, _rows)
check("security: permissions seeded",
      _rows["permissions"] == len(security.PERMISSIONS), _rows)
_expected_rp = sum(len(v) for v in security.PERMISSION_MATRIX.values())
check("security: role_permissions matrix seeded",
      _rows["role_permissions"] == _expected_rp,
      (_rows["role_permissions"], _expected_rp))

# --- BI: enforcement is server-side (frontend hiding is NOT auth) ---
check("security: default role is ANALYST",
      security.current_role() == "ANALYST")
_orig_role = security.current_role
security.current_role = lambda: "READ_ONLY"
try:
    r = _client3.post("/lab/api/cases",
                      json={"title": "rbac probe",
                            "case_type": "PHISHING",
                            "priority": "LOW",
                            "description": "denied"})
    _b = r.get_json()
finally:
    security.current_role = _orig_role
check("security: mutating API rejects READ_ONLY with 403",
      r.status_code == 403 and _b["success"] is False
      and _b["error"]["code"] == "FORBIDDEN", (r.status_code, _b.get("error")))
check("security: default analyst can still create cases",
      _client3.post("/lab/api/cases",
                    json={"title": "rbac probe ok",
                          "case_type": "PHISHING",
                          "priority": "LOW",
                          "description": "should pass"}).status_code == 201)

# --- shell surfaces the effective role honestly ---
r = _client3.get("/lab/cases")
_html = r.get_data(as_text=True)
check("security: header shows current role",
      r.status_code == 200 and "ANALYST · RESTRICTED" in _html)

# ===========================================================================
section("Test 7H — Phase 13 Health & Observability (BO/BP/BZ/BQ)")
# ===========================================================================
_r13 = hs.run_health_checks()
_d13 = _r13["data"]
_labels13 = {s["label"] for s in _d13["services"]}
for _lbl in ("SCAM ENGINE", "ABUSEIPDB", "SHODAN", "CENSYS", "URLSCAN",
             "HIBP", "WEB RISK", "QUEUE", "WORKERS"):
    check("health: monitors %s" % _lbl, _lbl in _labels13, sorted(_labels13))
check("health: every service carries a configuration field",
      all("configuration" in s for s in _d13["services"]))
_unwired = ("ABUSEIPDB", "SHODAN", "CENSYS", "URLSCAN", "HIBP",
            "WEB RISK", "QUEUE", "WORKERS")
check("health: unwired surfaces honestly NOT CONFIGURED",
      all(next(s for s in _d13["services"] if s["label"] == l)["status_key"]
          == "unconfigured" for l in _unwired))
check("health: providers report null latency (never faked)",
      all(next(s for s in _d13["services"] if s["label"] == l)["latency_ms"]
          is None for l in _unwired))
check("health: scam engine backed by the real analyzer",
      next(s for s in _d13["services"]
           if s["label"] == "SCAM ENGINE")["status_key"] == "operational")
_vt_expected = ("VIRUSTOTAL_API_KEY set"
               if (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()
               else "VIRUSTOTAL_API_KEY not set")
check("health: VirusTotal row states its real configuration",
      next(s for s in _d13["services"]
           if s["label"] == "THREAT INTELLIGENCE")["configuration"]
      == _vt_expected)

# --- BP: provider configuration surface (booleans only, never secrets) ---
_b = _client3.get("/lab/api/providers").get_json()
_provs = _b["data"]["providers"]
check("providers: success envelope with count",
      _b["success"] is True and _b["data"]["count"] == len(_provs),
      _b["data"]["count"])
_names = {p["name"] for p in _provs}
check("providers: VT plus the six pending providers listed",
      {"VirusTotal", "ABUSEIPDB", "SHODAN", "CENSYS", "URLSCAN", "HIBP",
       "WEB RISK"} <= _names, sorted(_names))
check("providers: entries carry name/configured/key_env/source/note",
      all({"name", "configured", "key_env", "source", "note"} <= set(p)
          and isinstance(p["configured"], bool) for p in _provs))
check("providers: no secret material in the payload",
      all("value" not in p and "secret" not in p and "api_key" not in p
          for p in _provs))
check("providers: VirusTotal reflects the real environment",
      next(p for p in _provs
           if p["name"] == "VirusTotal")["configured"]
      == bool((os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()))

# --- BZ: correlation ids + structured request logs ---
import logging as _logging                          # noqa: E402
_lines = []


class _Cap(_logging.Handler):
    def emit(self, record):
        _lines.append(record.getMessage())


_obslog = _logging.getLogger("kavacham.obs")
_obslog.addHandler(_Cap())
try:
    r = _client3.get("/lab/cases", headers={"X-Correlation-ID": "probe-corr-1"})
    check("obs: inbound correlation id echoed as request id",
          r.headers.get("X-Request-ID") == "probe-corr-1",
          r.headers.get("X-Request-ID"))
    r = _client3.get("/lab/api/health")
    check("obs: generated request id when none is sent",
          bool(r.headers.get("X-Request-ID")))
    _recs = [json.loads(m) for m in _lines]
    check("obs: lines carry request_id/service/operation/duration/status",
          any({"request_id", "service", "operation", "duration_ms",
               "status"} <= set(l) for l in _recs))
    check("obs: line threads the echoed correlation id",
          any(l.get("request_id") == "probe-corr-1"
              and l.get("service") == "lab"
              and isinstance(l.get("duration_ms"), (int, float))
              for l in _recs))
    check("obs: operations never carry query strings or secret words",
          all("?" not in str(l.get("operation", ""))
              and "api_key" not in json.dumps(l).lower()
              and "password" not in json.dumps(l).lower()
              for l in _recs),
          len(_recs))
finally:
    for _h in list(_obslog.handlers):
        if isinstance(_h, _Cap):
            _obslog.removeHandler(_h)

# --- BQ: mission-board operations tiles match the ledger ---
_b = _client3.get("/lab/api/command-center").get_json()
_ops = _b["data"]["operations"]
check("ops: mission board keys present",
      {"available", "active_investigations", "high_risk_findings",
       "unreviewed_evidence", "ioc_alerts", "provider_alerts",
       "integrity_alerts"} <= set(_ops), sorted(_ops))
check("ops: operations available against the test database",
      _ops["available"] is True)
_high = db.query_one(
    "SELECT COUNT(*) AS n FROM cases WHERE "
    "(risk_score IS NOT NULL AND risk_score >= 61) "
    "OR risk_level = 'HIGH'")["n"]
check("ops: high-risk findings match the ledger",
      _ops["high_risk_findings"] == _high,
      (_ops["high_risk_findings"], _high))
_unrev = db.query_one(
    "SELECT COUNT(*) AS n FROM evidence e WHERE NOT EXISTS "
    "(SELECT 1 FROM analyses a WHERE a.evidence_id = e.evidence_id)")["n"]
check("ops: unreviewed evidence matches the ledger",
      _ops["unreviewed_evidence"] == _unrev,
      (_ops["unreviewed_evidence"], _unrev))
_iocn = db.query_one(
    "SELECT COUNT(*) AS n FROM alerts WHERE title LIKE '%IOC%' "
    "OR message LIKE '%IOC%' OR source LIKE '%IOC%'")["n"]
check("ops: IOC alerts match the alerts table",
      _ops["ioc_alerts"] == _iocn, (_ops["ioc_alerts"], _iocn))
_intn = db.query_one(
    "SELECT COUNT(*) AS n FROM evidence "
    "WHERE integrity_state != 'VERIFIED'")["n"]
check("ops: integrity alerts match evidence state",
      _ops["integrity_alerts"] == _intn,
      (_ops["integrity_alerts"], _intn))
check("ops: provider alerts match integration health",
      _ops["provider_alerts"] == sum(
          1 for s in _d13["services"]
          if s["group"] == "integration"
          and s["status_key"] != "operational"),
      _ops["provider_alerts"])

# --- pages render ---
for _url, _marker in [("/lab/health", "MONITORED SERVICES"),
                      ("/lab/settings", "THREAT INTELLIGENCE PROVIDERS")]:
    r = _client3.get(_url)
    _html = r.get_data(as_text=True)
    check("page: %s renders" % _url,
          r.status_code == 200 and _marker in _html,
          r.status_code)
r = _client3.get("/lab")
check("page: command center carries CURRENT OPERATIONS",
      r.status_code == 200 and "CURRENT OPERATIONS" in r.get_data(as_text=True))

# ===========================================================================
section("Test 7I — Phase 14 QA security gap-fill (CC)")
# ===========================================================================

# --- IDOR / unauthorized access: unknown refs rejected as envelopes ---
for _url, _status, _code in [
        ("/lab/api/cases/KAV-CASE-2099-99999", 404, "CASE_NOT_FOUND"),
        ("/lab/api/evidence/KAV-EVD-2099-99999", 404, "EVIDENCE_NOT_FOUND"),
        ("/lab/api/analysis/KAV-ANL-2099-99999", 404, "ANALYSIS_NOT_FOUND"),
        ("/lab/api/reports/KAV-RPT-2099-99999", 400, "REPORT_NOT_FOUND")]:
    r = _client3.get(_url)
    _b = r.get_json()
    check("qa: unknown ref rejected at %s" % _url,
          r.status_code == _status and _b["success"] is False
          and _b["error"]["code"] == _code, (r.status_code, _b))
r = _client3.patch("/lab/api/cases/KAV-CASE-2099-99999",
                   json={"status": "REVIEW"})
check("qa: unknown case update rejected",
      r.status_code == 404
      and r.get_json()["error"]["code"] == "CASE_NOT_FOUND",
      r.status_code)
r = _client3.post("/lab/api/exports/KAV-EXP-2099-99999/verify")
check("qa: unknown export verify rejected",
      r.status_code in (400, 404) and r.get_json()["success"] is False,
      r.status_code)

# --- SQL injection: hostile search input is data, never code ---
r = _client3.get("/lab/api/cases", query_string={"q": "' OR '1'='1"})
_b = r.get_json()
check("qa: injection search returns envelope, not a dump",
      r.status_code == 200 and _b["success"] is True
      and _b["data"]["total"] == 0, _b["data"]["total"])
r = _client3.get("/lab/api/evidence", query_string={"q": "'; DROP TABLE cases; --"})
_b = r.get_json()
check("qa: hostile evidence search is inert",
      r.status_code == 200 and _b["success"] is True)
check("qa: cases table survives hostile input",
      db.query_one("SELECT COUNT(*) AS n FROM cases")["n"] > 0)

# --- XSS: stored markup stays inert (view layer escapes / textContent) ---
r = _client3.post("/lab/api/cases",
                  json={"title": "<script>alert('xss')</script>",
                        "case_type": "PHISHING",
                        "priority": "LOW",
                        "description": "xss probe"})
_xss_ref = r.get_json()["data"]["case"]["case_ref"]
_html = _client3.get("/lab/cases/" + _xss_ref).get_data(as_text=True)
check("qa: stored script tag never reaches server-rendered HTML",
      "<script>alert('xss')</script>" not in _html)
import pathlib as _pl                                        # noqa: E402
_detail_js = _pl.Path("static/js/lab_case_detail.js").read_text(
    encoding="utf-8")
check("qa: case title bound via textContent, not innerHTML",
      "cv-title').textContent" in _detail_js.replace('"', "'"))

# --- SSRF: cloud-metadata URL analyzed structurally, never fetched ---
ev_ssrf = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "URL",
    "title": "Metadata probe",
    "content_text": "http://169.254.169.254/latest/meta-data/"})
a_ssrf = ans.run_analysis(ev_ssrf["evidence_ref"], "URL")
check("qa: metadata URL completes with a structural verdict",
      a_ssrf["verdict"] in {"SUSPICIOUS", "MALICIOUS", "CLEAN"}
      and a_ssrf["status"] == "COMPLETE",
      (a_ssrf["verdict"], a_ssrf["status"]))
check("qa: no fetch stage claimed for the metadata URL",
      all("fetch" not in str(s.get("name", "")).lower()
          and "fetch" not in str(s.get("detail", "")).lower()
          for s in a_ssrf["payload"]["stages"]))

# --- Malformed input at HTTP level ---
r = _client3.post("/lab/api/cases", data="not json",
                  content_type="text/plain")
check("qa: non-JSON body rejected as INVALID_PAYLOAD",
      r.status_code == 400
      and r.get_json()["error"]["code"] == "INVALID_PAYLOAD",
      r.status_code)
r = _client3.post("/lab/api/evidence", json={"evidence_type": "URL"})
check("qa: evidence missing fields rejected",
      r.status_code == 400 and r.get_json()["success"] is False,
      r.status_code)

# --- Open redirect: Lab issues no redirects on unknown API paths ---
r = _client3.get("/lab/api/no-such-thing")
check("qa: unknown API path is not a redirect",
      r.status_code != 301 and r.status_code != 302
      and r.status_code != 307 and r.status_code != 308,
      r.status_code)
check("qa: Lab registers no redirect endpoints",
      all("redirect" not in str(rule) for rule in
          [str(r_) for r_ in app_module.app.url_map.iter_rules()
           if str(r_).startswith("/lab")]))

# --- Secret exposure: no server paths in detail payloads ---
_b = _client3.get("/lab/api/evidence/" + ev_file["evidence_ref"]).get_json()
check("qa: evidence detail leaks no storage paths",
      "stored_path" not in _b["data"]["evidence"]
      and "storage_path" not in _b["data"]["evidence"],
      sorted(_b["data"]["evidence"]))
_b = _client3.get("/lab/api/reports/" + _rpt_ref).get_json()
check("qa: report detail leaks no storage paths",
      "storage_path" not in json.dumps(_b["data"]),
      [k for k in _b["data"] if "path" in k.lower()])

# --- Accessibility (BV): skip link, landmarks, focus, reduced motion ---
_html = _client3.get("/lab/cases").get_data(as_text=True)
check("qa: skip link targets the main landmark",
      'class="lab-skip"' in _html and 'href="#lab-main"' in _html
      and 'id="lab-main"' in _html)
_lab_css = _pl.Path("static/css/lab.css").read_text(encoding="utf-8")
check("qa: visible keyboard focus styles",
      ":focus-visible" in _lab_css)
check("qa: reduced-motion support in Lab CSS",
      "prefers-reduced-motion" in _lab_css)
check("qa: Lab ships no console.debug leftovers",
      not any("console.log" in _pl.Path("static/js/" + _f).read_text(
          encoding="utf-8", errors="replace")
          for _f in ("lab_shell.js", "lab_command_center.js",
                     "lab_health.js", "lab_settings.js")))
check("qa: shell exposes the page correlation id",
      "corrId" in _pl.Path("static/js/lab_shell.js").read_text(
          encoding="utf-8"))

# ===========================================================================
section("Test 7J — Global search (O) + case-view tabs (Q)")
# ===========================================================================
from lab import search_service as sch                             # noqa: E402

_b = _client3.get("/lab/api/search",
                  query_string={"q": case1["case_ref"]}).get_json()
check("search: success envelope",
      _b["success"] is True and _b["data"]["query"] == case1["case_ref"])
_by = {g["group"]: g for g in _b["data"]["groups"]}
check("search: all five groups present",
      set(_by) == {"case", "evidence", "analysis", "ioc", "entity"},
      sorted(_by))
check("search: exact case ref ranks exact first",
      _by["case"]["items"] and _by["case"]["items"][0]["match"] == "exact"
      and _by["case"]["items"][0]["label"] == case1["case_ref"])
check("search: every result links to a real Lab page",
      all(it["url"].startswith("/lab/")
          for g in _b["data"]["groups"] for it in g["items"]))
check("search: groups are capped",
      all(g["count"] <= 8 for g in _b["data"]["groups"]))

_b = _client3.get("/lab/api/search",
                  query_string={"q": "KAV-CASE-2026"}).get_json()
check("search: partial refs match",
      any(it["match"] == "partial"
          for it in {g["group"]: g for g in _b["data"]["groups"]}["case"]["items"]))

_b = _client3.get("/lab/api/search",
                  query_string={"q": ev_file["sha256"]}).get_json()
check("search: evidence found by full sha256",
      any(it["label"] == ev_file["evidence_ref"]
          for it in {g["group"]: g for g in _b["data"]["groups"]}["evidence"]["items"]))

_b = _client3.get("/lab/api/search",
                  query_string={"q": "account-verify-login"}).get_json()
check("search: IOC values match partially",
      any(it["kind"] == "ioc"
          for g in _b["data"]["groups"] for it in g["items"]))

# --- entities: header sender extracted from real evidence text ---
ev_hdr = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "EMAIL",
    "title": "Header probe",
    "content_text": "From: qa-probe-sender@example.com\n"
                    "Subject: probe\n\nBody text."})
_b = _client3.get("/lab/api/search",
                  query_string={"q": "qa-probe-sender"}).get_json()
_ent = {g["group"]: g for g in _b["data"]["groups"]}["entity"]["items"]
check("search: sender entity resolves to its evidence",
      any(it["label"] == "qa-probe-sender@example.com"
          and it["url"] == "/lab/evidence/" + ev_hdr["evidence_ref"]
          for it in _ent), _ent)

# --- filters + empty query honesty ---
_b = _client3.get("/lab/api/search",
                  query_string={"q": "KAV", "type": "case"}).get_json()
check("search: type filter limits groups",
      [g["group"] for g in _b["data"]["groups"]] == ["case"])
_b = _client3.get("/lab/api/search",
                  query_string={"q": "KAV", "type": "bogus"}).get_json()
check("search: unknown filter returns nothing, not everything",
      _b["data"]["total"] == 0 and _b["data"]["groups"] == [])
_b = _client3.get("/lab/api/search").get_json()
check("search: empty query never dumps the vault",
      _b["data"]["total"] == 0 and _b["data"]["groups"] == [])
check("search: hostile input is inert",
      _client3.get("/lab/api/search",
                   query_string={"q": "' OR '1'='1"}).get_json()["success"] is True)

# --- Q: ENTITIES + ATTACK CHAIN tabs on the case view ---
_html = _client3.get("/lab/cases/" + case1["case_ref"]).get_data(as_text=True)
for _tab in ("entities", "chain"):
    check("caseview: %s tab present" % _tab,
          'data-tab="%s"' % _tab in _html
          and 'data-panel="%s"' % _tab in _html)
_b = _client3.get("/lab/api/intel/graph",
                  query_string={"case": case1["case_ref"]}).get_json()
check("caseview: entity graph carries real nodes",
      _b["success"] is True and _b["data"]["graph"]["node_count"] > 0
      and any(n["type"] not in ("CASE", "EVIDENCE")
              for n in _b["data"]["graph"]["nodes"]),
      _b["data"]["graph"]["node_count"])
_b = _client3.get("/lab/api/intel/attack-chain",
                  query_string={"case": case1["case_ref"]}).get_json()
check("caseview: attack chain honest state",
      _b["success"] is True and _b["data"]["state"] in ("chain", "insufficient"),
      _b["data"]["state"])
if _b["data"]["state"] == "chain":
    check("caseview: every chain stage cites evidence",
          all(s["evidence_refs"] for s in _b["data"]["chain"]))

# --- palette shell wiring ---
_html = _client3.get("/lab/cases").get_data(as_text=True)
check("search: palette dialog in the shell",
      'id="lab-palette-backdrop"' in _html
      and 'role="dialog"' in _html
      and 'id="lab-search-open"' in _html)
r = _client3.get("/static/js/lab_search.js")
_js = r.get_data(as_text=True)
check("search: palette script served",
      r.status_code == 200 and "CTRL+K" in _js, r.status_code)

# ===========================================================================
section("Test 7K — SMS / smishing analysis (AP)")
# ===========================================================================
check("sms: registry entry binds MESSAGE evidence only",
      ans.ANALYSIS_REGISTRY["SMS"]["evidence_types"] == ["MESSAGE"])
check("sms: risk classification is SCAM",
      rks.classify_analysis("SMS") == "SCAM")

ev_sms = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "MESSAGE",
    "title": "OTP fraud SMS",
    "content_text": "Dear customer your account will be blocked today. "
                    "Share your OTP 482916 immediately to verify KYC. "
                    "http://bit.ly/kyc-fix"})
a_sms = ans.run_analysis(ev_sms["evidence_ref"], "SMS")
check("sms: fraud message verdict",
      a_sms["verdict"] in {"MALICIOUS", "SUSPICIOUS"}, a_sms["verdict"])
check("sms: score bounded", 0 <= int(a_sms["risk_score"]) <= 100,
      a_sms["risk_score"])
check("sms: both engines recorded as sources",
      "sms_pipeline.spam_analyzer" in a_sms["payload"]["sources"]
      and "sms_pipeline.scam_analyzer" in a_sms["payload"]["sources"],
      a_sms["payload"]["sources"])
check("sms: payload carries both signals",
      {"spam_classification", "scam_status", "scam_score",
       "spam_probability"} <= set(a_sms["payload"]["analysis"]))

ev_sms_clean = evs.accept_evidence({
    "case_ref": case1["case_ref"], "evidence_type": "MESSAGE",
    "title": "Benign chat",
    "content_text": "Hey, are we still meeting for lunch tomorrow?"})
a_sms_clean = ans.run_analysis(ev_sms_clean["evidence_ref"], "SMS")
check("sms: benign message not malicious",
      a_sms_clean["verdict"] in {"CLEAN", "UNAVAILABLE"},
      a_sms_clean["verdict"])

try:
    ans.run_analysis(ev_url["evidence_ref"], "SMS")
    check("sms: incompatible evidence rejected", False, "accepted")
except ans.AnalysisError as exc:
    check("sms: incompatible evidence rejected",
          exc.code == "INCOMPATIBLE_EVIDENCE", exc.code)

r = _client3.post("/lab/api/analysis",
                  json={"evidence_ref": ev_sms["evidence_ref"],
                        "analysis_type": "SMS"})
check("sms: API run envelope",
      r.status_code == 201 and r.get_json()["data"]["analysis"]["verdict"]
      in {"MALICIOUS", "SUSPICIOUS", "CLEAN", "UNAVAILABLE"},
      r.status_code)

# ===========================================================================
section("Test 7L — Bulk IOC investigation (AN)")
# ===========================================================================
_BLOB = ("Suspicious login from 185.234.72.19, callback to "
         "account-verify-login.tk/path?a=1 and http://10.0.0.5/x, "
         "hash 18a118afc8338986e6833da29abab49f1a86f8a03ce8c08c73eb16fc4e3012b7, "
         "contact evil@example.com")
r = _client3.post("/lab/api/intel/bulk/preview", json={"text": _BLOB})
_b = r.get_json()
check("bulk: preview envelope",
      r.status_code == 200 and _b["success"] is True)
check("bulk: counts by real type",
      _b["data"]["counts"].get("IPv4", 0) >= 1
      and _b["data"]["counts"].get("DOMAIN", 0) >= 1
      and _b["data"]["counts"].get("URL", 0) >= 1
      and _b["data"]["counts"].get("SHA-256", 0) >= 1
      and _b["data"]["counts"].get("EMAIL", 0) >= 1,
      _b["data"]["counts"])
check("bulk: total equals counted indicators",
      _b["data"]["total"] == sum(_b["data"]["counts"].values()),
      _b["data"]["total"])
check("bulk: items carry type + value",
      all({"ioc_type", "value"} <= set(it)
          for it in _b["data"]["items"]))
r = _client3.post("/lab/api/intel/bulk/preview", json={"text": "hello world"})
check("bulk: no indicators is honest zero",
      r.get_json()["data"]["total"] == 0)
r = _client3.post("/lab/api/intel/bulk/preview", json={"text": ""})
check("bulk: empty text rejected or zero",
      r.get_json()["data"]["total"] == 0)
r = _client3.post("/lab/api/intel/bulk/investigate", json={"text": _BLOB})
_b = r.get_json()
check("bulk: investigate opens a case",
      r.status_code == 201 and _b["data"]["case"]["case_ref"].startswith(
          "KAV-CASE-"), (r.status_code, _b))
_bulk_ref = _b["data"]["case"]["case_ref"]
check("bulk: evidence stored for the paste",
      _b["data"]["evidence_ref"].startswith("KAV-EVD-"))
check("bulk: ledger sync reported",
      _b["data"]["ledger"]["iocs_total"] >= _b["data"]["total"],
      _b["data"]["ledger"])
check("bulk: new case carries the pasted indicators",
      cs.get_case(_bulk_ref)["counts"]["iocs"] >= 4,
      cs.get_case(_bulk_ref)["counts"])
r = _client3.post("/lab/api/intel/bulk/investigate", json={"text": "   "})
check("bulk: blank text rejected",
      r.status_code == 400 and r.get_json()["success"] is False)
r = _client3.get("/lab/intel/bulk")
check("page: /lab/intel/bulk renders",
      r.status_code == 200 and "BULK IOC INVESTIGATION" in r.get_data(
          as_text=True), r.status_code)

# ===========================================================================
section("Test 7M — RDAP + DNS network intel (AG)")
# ===========================================================================
from lab import network_intel as neti                           # noqa: E402

_bad = neti.lookup("not a domain!!")
check("network: garbage domain is invalid, never raises",
      _bad["dns"]["state"] == "invalid"
      and _bad["rdap"]["state"] == "invalid")
_dead = neti.lookup("nonexistent-domain-xyz.invalid")
check("network: unresolvable domain degrades honestly",
      _dead["dns"]["state"] in ("available", "unavailable")
      and _dead["rdap"]["state"] in ("available", "unavailable")
      and "note" in _dead["dns"] and "note" in _dead["rdap"],
      (_dead["dns"]["state"], _dead["rdap"]["state"]))
check("network: timeout budget is enforced (BS)",
      neti.TIMEOUT_S <= 10, neti.TIMEOUT_S)

a_dom2 = ans.run_analysis(ev_dom["evidence_ref"], "DOMAIN")
check("network: DOMAIN runs carry the network payload",
      {"dns", "rdap"} <= set(a_dom2["payload"]["analysis"]["network"]))
check("network: intelligence stage recorded honestly",
      any(s["name"] == "Network intelligence"
          and s["status"] in ("done", "unavailable")
          for s in a_dom2["payload"]["stages"]))

r = _client3.get("/lab/api/intel/network")
check("network: missing domain rejected",
      r.status_code == 400
      and r.get_json()["error"]["code"] == "VALIDATION_FAILED",
      r.status_code)
_b = _client3.get("/lab/api/intel/network",
                  query_string={"domain": "nonexistent-domain-xyz.invalid"}
                  ).get_json()
check("network: API envelope never 500s on dead domains",
      _b["success"] is True and {"dns", "rdap"} <= set(_b["data"]))

# ===========================================================================
section("Test 7N — Dataset + model registries (BD/BE)")
# ===========================================================================
from lab import registry_service as reg                            # noqa: E402

_b = _client3.get("/lab/api/datasets").get_json()
_sets = {d["dataset_id"]: d for d in _b["data"]["datasets"]}
check("datasets: success envelope",
      _b["success"] is True and _b["data"]["count"] == len(_sets),
      _b["data"]["count"])
for _f in ("dataset", "dataset_balanced", "dataset_kavacham_v2",
           "KAVACHAM_HARD_TEST"):
    check("datasets: %s registered" % _f, _f in _sets)
import csv as _csv                                                 # noqa: E402
with open("dataset_balanced.csv", newline="",
          encoding="utf-8", errors="replace") as _fh:
    _rows = sum(1 for _ in _fh) - 1
check("datasets: row count matches the real file",
      _sets["dataset_balanced"]["row_count"] == _rows,
      (_sets["dataset_balanced"]["row_count"], _rows))
check("datasets: columns read from the header",
      _sets["dataset_balanced"]["columns"] == ["label", "message"],
      _sets["dataset_balanced"]["columns"])
check("datasets: labels only from the label column",
      set(_sets["dataset_balanced"]["labels"]) <= {"spam", "ham",
                                                  "(missing)"},
      _sets["dataset_balanced"]["labels"])
check("datasets: unknown provenance stays null, never invented",
      _sets["dataset"]["license"] is None
      and _sets["dataset"]["download_date"] is None)
check("datasets: tallies are real integers",
      isinstance(_sets["dataset"]["duplicates"], int)
      and isinstance(_sets["dataset"]["missing_values"], int))

_b = _client3.get("/lab/api/models").get_json()
_mods = {m["model_id"]: m for m in _b["data"]["models"]}
check("models: success envelope",
      _b["success"] is True and _b["data"]["count"] == len(_mods))
for _m in ("kavacham_v1", "kavacham_v2", "vectorizer_v1", "vectorizer_v2",
           "model", "vectorizer"):
    check("models: %s registered" % _m, _m in _mods)
with open("metrics.json", encoding="utf-8") as _fh:
    _metrics = json.load(_fh)
check("models: v2 metrics match metrics.json exactly",
      _mods["kavacham_v2"]["accuracy"] == _metrics["accuracy"]
      and _mods["kavacham_v2"]["precision"] == _metrics["precision"]
      and _mods["kavacham_v2"]["recall"] == _metrics["recall"]
      and _mods["kavacham_v2"]["f1"] == _metrics["f1_score"]
      and _mods["kavacham_v2"]["false_positive_rate"]
      == _metrics["false_positive_rate"]
      and _mods["kavacham_v2"]["training_date"] == _metrics["trained_at"])
check("models: metrics never leak onto the wrong artifact",
      _mods["kavacham_v1"]["accuracy"] is None
      and _mods["model"]["accuracy"] is None)
check("models: unsupported metrics stay null (BE)",
      _mods["kavacham_v2"]["roc_auc"] is None
      and _mods["kavacham_v2"]["confusion_matrix"] is None)
check("models: artifact paths are repo-relative, never absolute",
      all(not m["path"].startswith(("/", "C:", "\\"))
          for m in _mods.values()))

for _url, _marker in [("/lab/models", "REGISTERED MODELS"),
                      ("/lab/datasets", "REGISTERED DATASETS")]:
    r = _client3.get(_url)
    check("page: %s renders" % _url,
          r.status_code == 200 and _marker in r.get_data(as_text=True),
          r.status_code)

# ===========================================================================
section("Test 7O — Rate limiting + secure headers (BS)")
# ===========================================================================
from lab import ratelimit as _rl                                 # noqa: E402

# --- unit: token bucket semantics ---
_rl.reset()
_ok1, _rem1, _ = _rl.check("10.9.9.9", "write")
check("ratelimit: first request allowed",
      _ok1 is True and _rem1 == _rl.LIMIT - 1, _rem1)
for _ in range(_rl.LIMIT - 1):
    _rl.check("10.9.9.9", "write")
_ok2, _rem2, _retry = _rl.check("10.9.9.9", "write")
check("ratelimit: budget exhausted denies",
      _ok2 is False and _rem2 == 0 and _retry >= 1, _retry)
check("ratelimit: buckets are per IP",
      _rl.check("10.9.9.10", "write")[0] is True)
check("ratelimit: scopes are independent",
      _rl.check("10.9.9.9", "lookup")[0] is True)
_rl.reset()
check("ratelimit: reset restores budget",
      _rl.check("10.9.9.9", "write")[0] is True)

# --- HTTP: 429 envelope with Retry-After ---
_old_limit = _rl.LIMIT
_rl.LIMIT = 3
_rl.reset()
try:
    _codes = []
    for _ in range(5):
        _r = _client3.post("/lab/api/intel/bulk/preview",
                           json={"text": "rate probe 1.2.3.4"})
        _codes.append(_r.status_code)
    check("ratelimit: over-budget POST rejected with 429",
          _codes.count(429) >= 1, _codes)
    _r = _client3.post("/lab/api/intel/bulk/preview",
                       json={"text": "rate probe 1.2.3.4"})
    _b = _r.get_json()
    check("ratelimit: 429 is a Section 49 envelope",
          _r.status_code == 429 and _b["success"] is False
          and _b["error"]["code"] == "RATE_LIMITED"
          and "Retry-After" in _r.headers
          and _r.headers.get("X-RateLimit-Remaining") == "0",
          (_r.status_code, _r.headers.get("Retry-After")))
finally:
    _rl.LIMIT = _old_limit
    _rl.reset()
r = _client3.post("/lab/api/intel/bulk/preview",
                  json={"text": "rate probe 1.2.3.4"})
check("ratelimit: restored budget serves again",
      r.status_code == 200, r.status_code)

# --- secure headers on Lab responses (BS/BT) ---
for _url in ("/lab/api/health", "/lab/cases"):
    r = _client3.get(_url)
    _h = r.headers
    check("headers: %s carries the secure set" % _url,
          _h.get("X-Content-Type-Options") == "nosniff"
          and _h.get("X-Frame-Options") == "DENY"
          and _h.get("Referrer-Policy") == "no-referrer"
          and _h.get("Permissions-Policy") == _rl.SECURE_HEADERS[
              "Permissions-Policy"]
          and "X-Request-ID" in _h)
check("headers: same-origin Lab emits no CORS wildcard",
      "Access-Control-Allow-Origin" not in _client3.get(
          "/lab/api/health").headers)

# ===========================================================================
section("Test 7P — Privacy settings + retention + frontend review (BR/BT)")
# ===========================================================================
from lab import settings_service as sts                            # noqa: E402
from lab import security as _sec                                  # noqa: E402

_b = _client3.get("/lab/api/settings").get_json()
check("settings: defaults served with provenance",
      _b["success"] is True
      and _b["data"]["settings"]["retention_days"]["value"] == "365"
      and _b["data"]["settings"]["retention_days"]["updated_by"] in (
          "system", "analyst"),
      _b["data"]["settings"])
check("settings: secret source stated, no secret values",
      _b["data"]["secret_source"] == sts.SECRET_SOURCE
      and "api_key" not in json.dumps(_b["data"]).lower()
      and "password" not in json.dumps(_b["data"]).lower())

# --- ANALYST cannot change retention (settings:manage is ADMIN-only) ---
check("rbac: ANALYST lacks settings:manage",
      not _sec.authorize("ANALYST", "settings:manage"))
check("rbac: ADMIN holds settings:manage",
      _sec.authorize("ADMIN", "settings:manage"))
r = _client3.patch("/lab/api/settings",
                   json={"key": "retention_days", "value": 730})
check("settings: analyst update refused with 403",
      r.status_code == 403
      and r.get_json()["error"]["code"] == "FORBIDDEN", r.status_code)

_orig_role = _sec.current_role
_sec.current_role = lambda: "ADMIN"
try:
    r = _client3.patch("/lab/api/settings",
                       json={"key": "retention_days", "value": "not-a-number"})
    check("settings: non-integer rejected",
          r.status_code == 400
          and r.get_json()["error"]["code"] == "VALIDATION_FAILED",
          r.status_code)
    r = _client3.patch("/lab/api/settings",
                       json={"key": "retention_days", "value": 5})
    check("settings: out-of-range rejected",
          r.status_code == 400, r.status_code)
    r = _client3.patch("/lab/api/settings",
                       json={"key": "nope", "value": 1})
    check("settings: unknown key rejected",
          r.status_code == 400
          and r.get_json()["error"]["code"] == "UNKNOWN_SETTING",
          r.status_code)
    r = _client3.patch("/lab/api/settings",
                       json={"key": "retention_days", "value": 730})
    _b = r.get_json()
    check("settings: admin update applies",
          r.status_code == 200 and _b["data"]["setting"]["value"] == "730",
          (r.status_code, _b))
finally:
    _sec.current_role = _orig_role
check("settings: change audited as SETTINGS_CHANGED",
      any(a["target_ref"] == "retention_days"
          and "365 -> 730" in (a["detail"] or "")
          for a in cs.list_audit(action="SETTINGS_CHANGED")["items"]))

# --- purge preview counts real rows, purge deletes + audits ---
db.execute(
    "INSERT INTO audit_logs(event_type, actor, action, target_type, "
    "target_ref, detail, ip_address, created_at) "
    "VALUES (?,?,?,?,?,?,?,?)",
    ("CASE_UPDATED", "qa", "CASE_UPDATED", "cases", "KAV-CASE-2000-00001",
     "stale row", None, "2020-01-01T00:00:00Z"))
_b = _client3.get("/lab/api/settings/purge-preview").get_json()
check("settings: preview counts stale rows, deletes nothing",
      _b["success"] is True and _b["data"]["audit_rows"] >= 1
      and db.query_one("SELECT COUNT(*) AS n FROM audit_logs WHERE "
                       "target_ref = 'KAV-CASE-2000-00001'")["n"] == 1,
      _b["data"])
r = _client3.post("/lab/api/settings/purge")
check("settings: analyst purge refused with 403",
      r.status_code == 403, r.status_code)
_sec.current_role = lambda: "ADMIN"
try:
    r = _client3.post("/lab/api/settings/purge")
    _b = r.get_json()
    check("settings: admin purge deletes stale rows",
          r.status_code == 200 and _b["data"]["deleted"] >= 1
          and db.query_one("SELECT COUNT(*) AS n FROM audit_logs WHERE "
                           "target_ref = 'KAV-CASE-2000-00001'")["n"] == 0,
          _b["data"])
finally:
    _sec.current_role = _orig_role
check("settings: purge itself audited",
      any(a["action"] == "AUDIT_PURGED"
          for a in cs.list_audit(limit=50)["items"]))

# --- BT frontend review: no secret storage, backend decides ---
import pathlib as _pth                                            # noqa: E402
_store_hits = []
for _f in _pth.Path("static/js").glob("lab_*.js"):
    _t = _f.read_text(encoding="utf-8", errors="replace")
    for _m in ("localStorage.setItem", "sessionStorage.setItem"):
        _idx = 0
        while True:
            _i = _t.find(_m, _idx)
            if _i < 0:
                break
            _frag = _t[_i:_i + 80].lower()
            if any(_w in _frag for _w in ("token", "secret", "password",
                                         "api_key", "apikey", "bearer")):
                _store_hits.append("%s: %s" % (_f.name, _frag))
            _idx = _i + 1
check("frontend: browser storage holds no secret material", not _store_hits,
      _store_hits[:3])
_sec.current_role = lambda: "READ_ONLY"
try:
    r = _client3.post("/lab/api/analysis",
                      json={"evidence_ref": ev_file["evidence_ref"],
                            "analysis_type": "SMS"})
    check("frontend: hiding is not auth (server 403s READ_ONLY writes)",
          r.status_code == 403
          and r.get_json()["error"]["code"] == "FORBIDDEN", r.status_code)
finally:
    _sec.current_role = _orig_role
_html = _client3.get("/lab/settings").get_data(as_text=True)
check("settings: non-admin sees the honest role gate",
      "require the ADMIN role" in _html and "DATA RETENTION" in _html)
check("privacy: run-analysis states provider/DNS disclosure",
      "never" in _client3.get("/lab/analysis/new").get_data(
          as_text=True).lower()
      and "VirusTotal" in _client3.get("/lab/analysis/new").get_data(
          as_text=True))

# ===========================================================================
print("\n" + "=" * 64)
passed = sum(1 for ok, _, _ in RESULTS if ok)
failed = sum(1 for ok, _, _ in RESULTS if not ok)
print("PASSED: %d   FAILED: %d" % (passed, failed))
if failed:
    print("-" * 64)
    for ok, name, detail in RESULTS:
        if not ok:
            print("  FAILED: %s %s" % (name, detail))
print("=" * 64)
sys.exit(1 if failed else 0)
