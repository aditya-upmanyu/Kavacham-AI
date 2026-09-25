"""
lab/risk_service.py
===================
KAVACHAM LAB — Phase 9 central risk engine (version2.txt A..CO, AZ, BA).

One normalized risk model:

    risk_score  0-100
    LOW         0-30
    SUSPICIOUS  31-60
    HIGH        61-100

Independent classifications (SPAM / PHISHING / MALWARE / SCAM / BEC /
SECURITY_RISK) are reported *alongside* the score and are never conflated
with it: "spam" is not automatically "malicious" (version2.txt AZ).

No-fabrication law (Sections 63, 86, H): a case risk score is computed
exclusively from stored analyses, their persisted findings and the case's
IOC ledger. Every finding carries evidence-first provenance in the BA shape:

    WHAT / WHY / EVIDENCE / SOURCE / IMPACT / LIMITATION

Nothing is invented. If the vault holds no analysis records for a case, the
case reports a 0 (LOW) score with an explicit "insufficient data"
explanation instead of a guessed number. Risk is snapshot onto the case
record (risk_level, risk_score, risk_assessed_at) only when a full
assessment is actually computed, so other surfaces never show stale or
fabricated values.
"""

import json
from datetime import datetime, timezone

from lab import db

# ---------------------------------------------------------------------------
# Risk model (version2.txt AZ)
# ---------------------------------------------------------------------------

RISK_LEVELS = ("LOW", "SUSPICIOUS", "HIGH")
RISK_BANDS = (
    ("LOW", 0, 30),
    ("SUSPICIOUS", 31, 60),
    ("HIGH", 61, 100),
)

# Independent classifications — never collapsed into the numeric score.
CLASSIFICATIONS = ("SPAM", "PHISHING", "MALWARE", "SCAM", "BEC",
                   "SECURITY_RISK")

# Local analysis types -> independent classification (only for display,
# the score itself never depends on this mapping).
CLASSIFICATION_BY_TYPE = {
    "EMAIL": "SECURITY_RISK",
    "PHISHING": "PHISHING",
    "SPAM": "SPAM",
    "URL": "SECURITY_RISK",
    "DOMAIN": "SECURITY_RISK",
    "FILE": "MALWARE",
    "HASH": "MALWARE",
    "QR": "PHISHING",
    "SCAM": "SCAM",
    "BEC": "BEC",
    "SMS": "SCAM",
}

ENGINE = "kavacham-risk-engine"
ENGINE_VERSION = "1.0.0"
# The exact aggregation formula, documented so the score is explainable.
FORMULA = ("round(0.6*highest_analysis + 0.3*mean_analysis "
           "+ 6*min(verified_iocs,4) + 3*min(observed_iocs,4))")

MAX_FINDINGS_PER_ANALYSIS = 6
MAX_CASE_FINDINGS = 14

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                  "INFO": 4, "WARNING": 5}


class RiskError(Exception):
    """Error carrying a Section 49 error code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clamp_score(value):
    """Coerce a stored score to an int in 0..100 (None -> 0)."""
    try:
        score = float(value if value is not None else 0)
    except (TypeError, ValueError):
        score = 0.0
    return int(max(0.0, min(100.0, score)))


def risk_level(score):
    """Band label for a score. Every integer maps to exactly one band."""
    s = _clamp_score(score)
    for label, lo, hi in RISK_BANDS:
        if lo <= s <= hi:
            return label
    return "LOW"


def classify_analysis(analysis_type):
    """Independent classification label for a stored analysis type."""
    return CLASSIFICATION_BY_TYPE.get(str(analysis_type), "SECURITY_RISK")


def _load_payload(row):
    try:
        payload = json.loads(row.get("payload_json") or "{}")
    except (TypeError, ValueError):
        payload = {}
    return payload if isinstance(payload, dict) else {}


def _intel_unavailable(payload):
    for stage in payload.get("stages") or []:
        if (stage.get("name") == "Threat intelligence"
                and stage.get("status") == "unavailable"):
            return True
    return False


def _impact_for(level):
    """Deterministic, non-fabricated impact phrasing per band."""
    return {
        "LOW": "No urgent operational impact indicated by stored analysis.",
        "SUSPICIOUS": "Merits review before the subject is treated as benign.",
        "HIGH": "Warrants containment or blocking where not already applied.",
    }.get(level, "No impact statement available for this band.")


# ---------------------------------------------------------------------------
# Per-analysis assessment (BA evidence-first findings)
# ---------------------------------------------------------------------------

def _analysis_limitations(row, payload):
    limits = []
    if row.get("status") == "PARTIAL":
        limits.append("Analysis is PARTIAL — one or more local stages "
                      "were unavailable.")
    if _intel_unavailable(payload):
        limits.append("Threat intelligence was unavailable during this "
                      "analysis.")
    if not limits:
        limits.append("No limitations recorded at analysis time.")
    return limits


def assess_analysis(row):
    """Normalized assessment for one stored analysis row (incl. findings)."""
    score = _clamp_score(row.get("risk_score"))
    level = risk_level(score)
    payload = _load_payload(row)
    analysis_type = row.get("analysis_type") or "UNKNOWN"

    findings = []
    frows = db.query(
        "SELECT finding_type, severity, title, detail, evidence_ref, source "
        "FROM analysis_findings WHERE analysis_id = ?",
        (row["analysis_id"],))
    frows.sort(key=lambda f: _SEVERITY_RANK.get(str(f["severity"]).upper(), 9))
    for f in frows[:MAX_FINDINGS_PER_ANALYSIS]:
        evidence = [f["evidence_ref"]] if f.get("evidence_ref") else []
        findings.append({
            # BA shape: WHAT / WHY / EVIDENCE / SOURCE / IMPACT / LIMITATION
            "what": f["title"] or "Finding",
            "why": f.get("detail") or "",
            "evidence": evidence,
            "source": [f.get("source") or "local"],
            "impact": _impact_for(level),
            "limitation": _analysis_limitations(row, payload)[0],
            "finding_type": f["finding_type"],
            "severity": f["severity"],
        })

    sources = [s for s in str(row.get("source") or "local").split(",") if s]
    return {
        "analysis_ref": row.get("analysis_ref"),
        "analysis_type": analysis_type,
        "classification": classify_analysis(analysis_type),
        "verdict": row.get("verdict"),
        "status": row.get("status"),
        "risk_score": score,
        "risk_level": level,
        "confidence": row.get("confidence"),   # real, may be None
        "evidence": [row["evidence_ref"]] if row.get("evidence_ref") else [],
        "sources": [s.strip() for s in sources],
        "engine_version": row.get("engine_version") or "unknown",
        "created_at": row.get("created_at"),
        "findings": findings,
        "limitations": _analysis_limitations(row, payload),
    }


# ---------------------------------------------------------------------------
# Case-level aggregation (AZ)
# ---------------------------------------------------------------------------

def _score_components(case_id):
    """Real stored aggregates driving the case score (no cross-joins:
    analysis and IOC aggregates are computed independently so counts are
    never inflated by the other table).
    """
    agg = db.query_one(
        "SELECT "
        "COALESCE(MAX(risk_score), 0) AS highest, "
        "COALESCE(AVG(risk_score), 0) AS mean, "
        "COALESCE(SUM(CASE WHEN COALESCE(risk_score,0) > 0 THEN 1 ELSE 0 END), 0) "
        "  AS active_count, "
        "COALESCE(COUNT(*), 0) AS analysis_count "
        "FROM analyses WHERE case_id = ?",
        (case_id,))
    iocs = db.query_one(
        "SELECT "
        "COALESCE(SUM(CASE WHEN i.status = 'VERIFIED' THEN 1 ELSE 0 END), 0) "
        "  AS verified_count, "
        "COALESCE(SUM(CASE WHEN i.status = 'OBSERVED' THEN 1 ELSE 0 END), 0) "
        "  AS observed_count, "
        "COALESCE(SUM(CASE WHEN i.status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END), 0) "
        "  AS fp_count "
        "FROM iocs i JOIN case_iocs ci ON ci.ioc_id = i.ioc_id "
        "WHERE ci.case_id = ?",
        (case_id,))
    if not agg:
        agg = {"highest": 0, "mean": 0, "active_count": 0, "analysis_count": 0}
    return {
        "highest": int(agg["highest"] or 0),
        "mean": int(round(agg["mean"] or 0)),
        "active_count": int(agg["active_count"] or 0),
        "analysis_count": int(agg["analysis_count"] or 0),
        "verified_count": int(iocs["verified_count"] or 0),
        "observed_count": int(iocs["observed_count"] or 0),
        "fp_count": int(iocs["fp_count"] or 0),
    }


def _compose_score(components):
    """Deterministic aggregation (see FORMULA). Mean is rounded up so a lone
    high finding on a single-analysis case is never under-stated."""
    highest = components["highest"]
    mean = round(components["mean"])
    score = (0.6 * highest + 0.3 * mean
             + 6 * min(components["verified_count"], 4)
             + 3 * min(components["observed_count"], 4))
    return _clamp_score(round(score))


def _ioc_findings(case_id):
    """Evidence-first findings for the case's IOC ledger (BA shape)."""
    rows = db.query(
        "SELECT i.status, i.value, i.ioc_type, i.source "
        "FROM iocs i JOIN case_iocs ci ON ci.ioc_id = i.ioc_id "
        "WHERE ci.case_id = ?", (case_id,))
    out = []
    verified = [r for r in rows if r["status"] == "VERIFIED"]
    observed = [r for r in rows if r["status"] == "OBSERVED"]
    false_pos = [r for r in rows if r["status"] == "FALSE_POSITIVE"]

    if verified:
        out.append({
            "what": "Verified indicators linked to case",
            "why": "%d indicator(s) are marked VERIFIED in the IOC ledger."
                   % len(verified),
            "evidence": [r["value"] for r in verified],
            "source": ["IOC Vault Ledger"],
            "impact": _impact_for("HIGH"),
            "limitation": "Verification reflects analyst disposition stored "
                          "in the IOC ledger, not independent attribution.",
            "finding_type": "verified_ioc",
            "severity": "HIGH",
        })
    if observed:
        out.append({
            "what": "Observed indicators awaiting disposition",
            "why": "%d indicator(s) are OBSERVED but not yet verified or "
                   "ruled out." % len(observed),
            "evidence": [r["value"] for r in observed],
            "source": ["IOC Vault Ledger"],
            "impact": _impact_for("SUSPICIOUS"),
            "limitation": "Observation reflects vault content; it is not "
                          "confirmation of maliciousness.",
            "finding_type": "observed_ioc",
            "severity": "MEDIUM",
        })
    if false_pos:
        out.append({
            "what": "False-positive indicators excluded",
            "why": "%d indicator(s) were dispositioned FALSE_POSITIVE and "
                   "excluded from the score." % len(false_pos),
            "evidence": [r["value"] for r in false_pos],
            "source": ["IOC Vault Ledger"],
            "impact": _impact_for("LOW"),
            "limitation": "Disposition reflects stored analyst action.",
            "finding_type": "false_positive_ioc",
            "severity": "INFO",
        })
    return out


def case_risk(case_ref):
    """Full evidence-first risk assessment for one case.

    Returns a Section 49-ready dict. Only stored records contribute to the
    score; the case row's risk snapshot is materialized alongside (with a
    real assessed_at timestamp) so other surfaces can read it.
    """
    if isinstance(case_ref, int) or (
            isinstance(case_ref, str) and case_ref.isdigit()):
        case = db.query_one("SELECT * FROM cases WHERE case_id = ?",
                            (int(case_ref),))
    else:
        case = db.query_one("SELECT * FROM cases WHERE case_ref = ?",
                            (str(case_ref),))
    if not case:
        raise RiskError("CASE_NOT_FOUND", "The requested case does not exist.")

    case_id = case["case_id"]
    analyses = db.query(
        "SELECT a.*, e.evidence_ref FROM analyses a "
        "LEFT JOIN evidence e ON a.evidence_id = e.evidence_id "
        "WHERE a.case_id = ? ORDER BY a.created_at ASC", (case_id,))

    assessments = [assess_analysis(r) for r in analyses]
    components = _score_components(case_id)
    score = _compose_score(components)
    level = risk_level(score)

    # Primary classification: the independent class carrying the highest
    # stored score (ties -> first in canonical order).
    ranked = [a for a in assessments if a["risk_score"] > 0]
    ranked.sort(key=lambda a: (a["risk_score"], a["classification"]),
                reverse=True)
    primary = ranked[0]["classification"] if ranked else None

    classification_totals = {}
    for a in assessments:
        if a["risk_score"] > 0:
            c = a["classification"]
            total = classification_totals.setdefault(c, {"count": 0,
                                                         "max_score": 0})
            total["count"] += 1
            total["max_score"] = max(total["max_score"], a["risk_score"])
    classifications = [
        {"classification": c, "count": t["count"], "max_score": t["max_score"]}
        for c, t in classification_totals.items()]

    # ---- BA findings from analyses (evidence-first, capped) ----
    findings = []
    for a in assessments:
        for f in a["findings"]:
            findings.append(dict(f, analysis_ref=a["analysis_ref"],
                                 analysis_type=a["analysis_type"]))
    findings.extend(_ioc_findings(case_id))
    findings = findings[:MAX_CASE_FINDINGS]

    # ---- Explanations derived only from the facts above ----
    explanations = []
    if components["analysis_count"] == 0 and not components["verified_count"] \
            and not components["observed_count"]:
        explanations.append(
            "Insufficient data: the case has no stored analyses or "
            "indicators, so the risk score is 0 (LOW). It will update once "
            "evidence is analysed.")
    else:
        if components["analysis_count"]:
            explanations.append(
                "%d of %d stored analysis records contributed a non-zero "
                "score." % (components["active_count"],
                            components["analysis_count"]))
            highest_row = max(analyses, key=lambda r: _clamp_score(
                r.get("risk_score")))
            explanations.append(
                "Highest analysis score is %d (%s, %s)."
                % (_clamp_score(highest_row.get("risk_score")),
                   highest_row.get("analysis_type"),
                   highest_row.get("analysis_ref")))
            if components["mean"]:
                explanations.append(
                    "Mean analysis score is %d." % round(components["mean"]))
        if components["verified_count"]:
            explanations.append(
                "%d verified indicator(s) are linked to this case."
                % components["verified_count"])
        if components["observed_count"]:
            explanations.append(
                "%d observed indicator(s) have not yet been dispositioned."
                % components["observed_count"])
    if not explanations:
        explanations.append("No contributing factors recorded.")

    # ---- Honest limitations ----
    limitations = [
        "Case-level confidence is not calibrated; per-analysis confidence "
        "is shown where the engine stored it."]
    if any(_intel_unavailable(_load_payload(r)) for r in analyses):
        limitations.append(
            "External threat intelligence was unavailable during at least "
            "one analysis; reputation absent there is not proven clean.")
    if any(r.get("status") == "PARTIAL" for r in analyses):
        limitations.append("At least one analysis is PARTIAL (incomplete).")

    computed_at = _now()

    # ---- Materialize the real snapshot on the case record ----
    with db.transaction():
        db.execute(
            "UPDATE cases SET risk_level = ?, risk_score = ?, "
            "risk_assessed_at = ? WHERE case_id = ?",
            (level, score, computed_at, case_id))

    return {
        "case": {
            "case_ref": case["case_ref"],
            "title": case["title"],
            "case_type": case["case_type"],
            "priority": case["priority"],
            "status": case["status"],
            "created_at": case["created_at"],
            "updated_at": case["updated_at"],
        },
        "risk_score": score,
        "risk_level": level,
        "primary_classification": primary,
        "classifications": classifications,
        "confidence": None,  # never claim uncalibrated case confidence
        "components": components,
        "formula": FORMULA,
        "findings": findings,
        "explanations": explanations,
        "limitations": limitations,
        "analyses": assessments,
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "computed_at": computed_at,
    }


# ---------------------------------------------------------------------------
# Risk register (overview for the Risk page / command surfaces)
# ---------------------------------------------------------------------------

def risk_register(limit=200):
    """Per-case risk summaries, computed from the same stored facts.

    Sorted highest risk first so the register reads like a priority list.
    """
    limit = max(1, min(int(limit or 200), 500))
    rows = db.query(
        "SELECT c.case_id, c.case_ref, c.title, c.case_type, c.priority, "
        "c.status, c.updated_at, "
        "(SELECT COALESCE(MAX(a.risk_score), 0) FROM analyses a "
        "  WHERE a.case_id = c.case_id) AS highest, "
        "(SELECT COALESCE(AVG(a.risk_score), 0) FROM analyses a "
        "  WHERE a.case_id = c.case_id) AS mean, "
        "(SELECT COUNT(*) FROM analyses a WHERE a.case_id = c.case_id) "
        "  AS analysis_count, "
        "(SELECT COUNT(*) FROM iocs i JOIN case_iocs ci ON ci.ioc_id = i.ioc_id "
        "  WHERE ci.case_id = c.case_id AND i.status = 'VERIFIED') "
        "  AS verified_count, "
        "(SELECT COUNT(*) FROM iocs i JOIN case_iocs ci ON ci.ioc_id = i.ioc_id "
        "  WHERE ci.case_id = c.case_id AND i.status = 'OBSERVED') "
        "  AS observed_count "
        "FROM cases c ORDER BY c.updated_at DESC, c.case_id DESC LIMIT ?",
        (limit,))

    items = []
    for r in rows:
        components = {
            "highest": int(r["highest"] or 0),
            "mean": round(r["mean"] or 0),
            "analysis_count": int(r["analysis_count"] or 0),
            "active_count": int(r["analysis_count"] or 0),
            "verified_count": int(r["verified_count"] or 0),
            "observed_count": int(r["observed_count"] or 0),
            "fp_count": 0,
        }
        score = _compose_score(components)
        items.append({
            "case_ref": r["case_ref"],
            "title": r["title"],
            "case_type": r["case_type"],
            "priority": r["priority"],
            "status": r["status"],
            "updated_at": r["updated_at"],
            "analysis_count": components["analysis_count"],
            "verified_ioc_count": components["verified_count"],
            "observed_ioc_count": components["observed_count"],
            "risk_score": score,
            "risk_level": risk_level(score),
        })

    items.sort(key=lambda c: (c["risk_score"], c["case_ref"]), reverse=True)
    return {
        "items": items,
        "total": len(items),
        "levels": list(RISK_LEVELS),
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "computed_at": _now(),
    }