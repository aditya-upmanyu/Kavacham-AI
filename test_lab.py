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
check("initial migration applied", 1 in applied, applied)
check("schema version is 1", db.current_version() == 1, db.current_version())

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
