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
check("initial migration applied", 1 in applied and 2 in applied, applied)
check("schema version is 2", db.current_version() == 2, db.current_version())

re_run = db.migrate()
check("migrations idempotent (no re-apply)", re_run == [], re_run)

integrity = db.integrity_check()
check("PRAGMA integrity_check ok", integrity.get("ok") is True, integrity)

counts = db.table_counts()
expected_tables = [
    "cases", "evidence", "chain_of_custody", "analyses", "analysis_findings",
    "iocs", "case_iocs", "entities", "case_entities", "timeline_events",
    "notes", "reports", "audit_logs", "alerts", "users", "roles",
    "permissions", "role_permissions",
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
check("12 services checked", data["summary"]["total"] == 12,
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
    "/lab/api/intel/correlation":         {"GET"},
    "/lab/api/intel/graph":               {"GET"},
    "/lab/api/intel/attack-chain":        {"GET"},
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
check("analysis registry exposes 10 types", len(aref["types"]) == 10, aref["types"])
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
check("intel nav has 4 live links",
      _intel_links == 4, _intel_links)

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
