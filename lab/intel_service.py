"""
lab/intel_service.py
====================
KAVACHAM LAB — Phase 8 intelligence (Sections 24-28, 47).

Real, evidence-backed indicators only. Every IOC shown originates from one
of three truthful sources:

  * analyst IOC lists on case creation    (case_service, "Analyst Input")
  * the evidence vault itself             (values actually observed in
                                           evidence content / metadata)
  * analysis payloads                     (values appearing in real run
                                           findings & verdict payloads)

`sync_iocs()` re-scans the vault and upserts what it actually finds. No IOC
is invented, extrapolated or guessed (Section 63).

Sections implemented here:
  26  IOC intelligence      — catalogue, search, status workflow, provenance
  27  Cross-case correlation — same IOC in 2+ cases -> POTENTIAL CORRELATION
                               with precise language; correlation != attribution
  25  Investigation graph   — evidence-backed node graph; relationships are
                               only rendered when a real link exists
  28  Attack chains         — sequence of stages, each gated on supporting
                               evidence/analysis; "insufficient evidence" is
                               reported honestly instead of inventing a chain
"""

import json
import os
import re
import urllib.parse
from datetime import datetime, timezone

from lab import db

# ---------------------------------------------------------------------------
# Section 26 — supported IOC types
# ---------------------------------------------------------------------------
IOC_TYPES = [
    "IPv4", "IPv6", "DOMAIN", "URL", "EMAIL",
    "SHA-256", "SHA-1", "MD5", "FILENAME", "OTHER",
]

IOC_STATUSES = ["OBSERVED", "VERIFIED", "FALSE_POSITIVE"]

CHAIN_RANK = {  # attack-chain ordering (lower renders first)
    "SENDER IMPERSONATION": 10,
    "SOCIAL ENGINEERING": 11,
    "PAYMENT REQUEST": 12,
    "ACCOUNT CHANGE": 13,
    "EMAIL OBSERVED": 20,
    "SUSPICIOUS EMAIL": 21,
    "QR CODE": 25,
    "URL OBSERVED": 30,
    "SUSPICIOUS URL": 31,
    "MALICIOUS URL": 32,
    "FILE OBSERVED": 32,
    "MALICIOUS ATTACHMENT": 33,
    "DOMAIN OBSERVED": 40,
    "SUSPICIOUS DOMAIN": 41,
    "HASH OBSERVED": 42,
    "MALWARE HASH": 43,
    "HOST IP": 50,
}

# Real finding types produced by Product A analyzers (Sections 29-41).
IMPERSONATION_FINDINGS = {
    "sender_impersonation", "brand_impersonation", "reply_to_mismatch",
    "return_path_mismatch", "brand_free_mail_mismatch", "domain_mismatch",
    "impersonation", "spoofed_sender", "sender_mismatch",
}
SOCIAL_ENGINEERING_FINDINGS = {
    "credential_harvesting", "nigerian_scam", "urgency", "pressure",
    "financial_request", "social_engineering", "scam_pattern",
}
BEC_FINDINGS = {"payment_request", "account_change", "payroll_change",
                "invoice_fraud", "fund_transfer"}

IMPERSONATION = frozenset(IMPERSONATION_FINDINGS)
SOCIAL = frozenset(SOCIAL_ENGINEERING_FINDINGS)
BEC = frozenset(BEC_FINDINGS)


def _now():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Classification (Section 26 vocabulary)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>'\"\u201c\u201d，。、；：]+", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9._%+-])")
_IPV4_CAND_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
    r"|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)")
_SHA256_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
_SHA1_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
_MD5_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9@.:/_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![A-Za-z0-9._-])", re.IGNORECASE)


def _strip_url(url):
    raw = url.rstrip(".,;:!?)]}\"'")
    if raw.endswith((")", "]")) and raw.count("(") < raw.count(")"):
        return raw[:-1]
    return raw


def _valid_ipv4(candidate):
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


def _valid_ipv6(candidate):
    value = candidate.lower().strip()
    if "%" in value:                       # zone id (e.g. fe80::1%eth0)
        value = value.split("%", 1)[0]
    if value.count(":") < 2:
        return False
    if "::" in value:
        if value.count("::") != 1:
            return False
        return True                        # :: form is structurally valid
    groups = value.split(":")
    if len(groups) != 8:
        return False
    return all(re.fullmatch(r"[0-9a-f]{1,4}", g) for g in groups)


def classify_ioc(value, hint=None):
    """Return (ioc_type, normalized_value) for a single literal.

    hint may be "filename" when the value is a stored file's original name
    (the only context where FILENAME is a truthful classification).
    """
    raw = (value or "").strip()
    if not raw:
        return "OTHER", raw

    if hint == "filename":
        return "FILENAME", raw

    low = raw.lower()
    if low.startswith(("http://", "https://")):
        return "URL", _strip_url(raw)

    if _EMAIL_RE.fullmatch(raw):
        return "EMAIL", raw.lower()

    if ":" in raw and _IPV6_RE.fullmatch(raw.replace("[", "").replace("]", "")) \
            and _valid_ipv6(raw.replace("[", "").replace("]", "")):
        return "IPv6", raw.lower()

    if _IPV4_CAND_RE.fullmatch(raw) and _valid_ipv4(raw):
        return "IPv4", raw

    if _SHA256_RE.fullmatch(raw):
        return "SHA-256", raw.lower()
    if _SHA1_RE.fullmatch(raw):
        return "SHA-1", raw.lower()
    if _MD5_RE.fullmatch(raw):
        return "MD5", raw.lower()

    if _DOMAIN_RE.fullmatch(low) and low.count(".") >= 1:
        return "DOMAIN", low.rstrip(".")

    return "OTHER", raw


def _extract_urls(text):
    out = []
    for m in _URL_RE.findall(text):
        url = _strip_url(m)
        # cut trailing closing bracket if unbalanced
        while url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1]
        while url.endswith("]") and url.count("[") < url.count("]"):
            url = url[:-1]
        if url.startswith(("http://", "https://")):
            out.append(url)
    return out


def extract_ioc_values(text, filename_hint=None):
    """Real regex extraction of IOC (type, value) pairs from a text blob.

    Returns a deduplicated list of (ioc_type, normalized_value).
    """
    if not text:
        return []
    text = text.replace("\x00", " ")
    found = []

    # URLs -> also capture host as DOMAIN / IPv4 node
    url_values = set()
    for url in _extract_urls(text):
        found.append(("URL", url))
        url_values.add(url)
        try:
            host = urllib.parse.urlparse(url).hostname
        except Exception:
            host = None
        if not host:
            continue
        if _IPV4_CAND_RE.fullmatch(host) and _valid_ipv4(host):
            found.append(("IPv4", host))
        elif _DOMAIN_RE.fullmatch(host.lower()):
            found.append(("DOMAIN", host.lower().rstrip(".")))

    # emails
    for m in _EMAIL_RE.findall(text):
        found.append(("EMAIL", m.lower()))

    # IPv4 (strict octet validation)
    for m in _IPV4_CAND_RE.findall(text):
        if _valid_ipv4(m):
            found.append(("IPv4", m))

    # IPv6
    for m in _IPV6_RE.findall(text):
        cand = m.replace("[", "").replace("]", "")
        if _valid_ipv6(cand):
            found.append(("IPv6", cand.lower()))

    # hashes (longest first; lookarounds prevent substring matches)
    for m in _SHA256_RE.findall(text):
        found.append(("SHA-256", m.lower()))
    for m in _SHA1_RE.findall(text):
        found.append(("SHA-1", m.lower()))
    for m in _MD5_RE.findall(text):
        found.append(("MD5", m.lower()))

    # standalone domains (not inside URLs / emails — lookarounds handle that)
    for m in _DOMAIN_RE.findall(text):
        domain = m.lower().rstrip(".")
        if domain.count(".") >= 1 and not _valid_ipv4(domain):
            # skip values already captured as URL hosts
            if not any(d == domain for t, d in found if t == "DOMAIN"):
                found.append(("DOMAIN", domain))

    if filename_hint:
        found.append(("FILENAME", filename_hint))

    # dedupe preserving first occurrence
    seen = set()
    deduped = []
    for t, v in found:
        key = (t, v)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    return deduped


# ---------------------------------------------------------------------------
# Vault sync — the single source of truth for the IOC ledger
# ---------------------------------------------------------------------------

def _evidence_text(ev):
    """Real text sources for an evidence row (content, title, stored file)."""
    parts = []
    if ev.get("title"):
        parts.append(ev["title"])
    if ev.get("content_text"):
        parts.append(ev["content_text"])
    stored = ev.get("stored_path")
    if stored and os.path.exists(stored):
        try:
            with open(stored, "rb") as fh:
                parts.append(fh.read(65536).decode("utf-8", "replace"))
        except Exception:
            pass
    return parts


def _upsert_ioc(conn, ioc_type, value, source, seen_at):
    conn.execute(
        "INSERT INTO iocs(ioc_type, value, severity, source, first_seen, "
        "last_seen, status) VALUES (?,?,?,?,?,?,'OBSERVED') "
        "ON CONFLICT(ioc_type, value) DO UPDATE SET "
        "last_seen = MAX(last_seen, excluded.last_seen), "
        "first_seen = MIN(first_seen, excluded.first_seen)",
        (ioc_type, value, "UNKNOWN", source, seen_at, seen_at))
    row = conn.execute(
        "SELECT ioc_id FROM iocs WHERE ioc_type = ? AND value = ?",
        (ioc_type, value)).fetchone()
    return row["ioc_id"]


def _link_case_ioc(conn, case_id, ioc_id):
    if case_id is None:
        return False
    cur = conn.execute(
        "INSERT OR IGNORE INTO case_iocs(case_id, ioc_id) VALUES (?,?)",
        (case_id, ioc_id))
    return cur.rowcount > 0


def sync_iocs(actor="analyst", ip_address=None):
    """Re-scan the whole vault (evidence + analysis payloads) and upsert the
    IOC ledger with what was actually observed. Idempotent. Audit it."""
    started = _now()
    created = 0
    new_case_links = {}
    ioc_count = 0

    with db.transaction() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM iocs").fetchone()["c"]

        # ---- evidence vault ----
        for row in conn.execute("SELECT * FROM evidence").fetchall():
            ev = dict(row)
            cid = ev.get("case_id")
            texts = _evidence_text(ev)
            found = []
            for t in texts:
                found.extend(extract_ioc_values(t))
            if ev.get("evidence_type") == "FILE":
                if ev.get("original_filename"):
                    found.append(("FILENAME", ev["original_filename"]))
                for col, ioc_t in (("sha256", "SHA-256"),
                                   ("sha1", "SHA-1"), ("md5", "MD5")):
                    if ev.get(col):
                        found.append((ioc_t, ev[col]))
            for ioc_type, value in found:
                new_link = _link_case_ioc(
                    conn, cid,
                    _upsert_ioc(conn, ioc_type, value,
                                "Vault scan (%s)" % ev.get("evidence_ref",
                                                           "evidence"),
                                ev.get("acquired_at") or started))
                if new_link and cid is not None:
                    new_case_links.setdefault(cid, 0)
                    new_case_links[cid] += 1
                ioc_count += 1

        # ---- analysis payloads (real findings text) ----
        for row in conn.execute(
                "SELECT a.analysis_id, a.case_id, a.evidence_id, "
                "e.evidence_ref, a.payload_json, a.created_at "
                "FROM analyses a "
                "LEFT JOIN evidence e ON e.evidence_id = a.evidence_id").fetchall():
            an = dict(row)
            blob = an.get("payload_json") or ""
            found = extract_ioc_values(blob)
            for ioc_type, value in found:
                new_link = _link_case_ioc(
                    conn, an.get("case_id"),
                    _upsert_ioc(conn, ioc_type, value,
                                "Analysis payload (%s)"
                                % (an.get("evidence_ref") or "analysis"),
                                an.get("created_at") or started))
                if new_link and an.get("case_id") is not None:
                    new_case_links.setdefault(an["case_id"], 0)
                    new_case_links[an["case_id"]] += 1
                ioc_count += 1

        # created = rows added in this run (iocs table size delta is read
        # before the upsert loops above, so this is a real count).
        # --- audit the sync ---
        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("IOC_ADDED", actor, "IOC_SYNC", "iocs", "vault",
             "Rescanned vault; %d observations upserted (info-collecting)"
             % ioc_count, ip_address, started))

        after = conn.execute("SELECT COUNT(*) AS c FROM iocs").fetchone()["c"]
        created = after - before

        # --- timeline events: cases that gained new indicators ---
        for cid, count in sorted(new_case_links.items()):
            conn.execute(
                "INSERT INTO timeline_events(case_id, event_type, title, "
                "detail, actor, source, occurred_at, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (cid, "IOC_ADDED", "Indicator added",
                 "%d new indicator(s) observed during vault sync." % count,
                 actor, "Vault scan", started, started))

    total = db.query_one("SELECT COUNT(*) AS c FROM iocs")["c"]
    affected = []
    for cid in sorted(new_case_links):
        row = db.query_one("SELECT case_ref FROM cases WHERE case_id = ?", (cid,))
        if row:
            affected.append(row["case_ref"])

    return {
        "iocs_total": total,
        "observations": ioc_count,
        "created": created,
        "cases_affected": affected,
        "case_count": len(affected),
        "ran_at": started,
        "actor": actor,
    }


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def _related_cases_for_ioc(conn, ioc_id):
    return [dict(r) for r in conn.execute(
        "SELECT c.case_ref, c.title, c.status, c.case_type, c.created_at "
        "FROM case_iocs ci JOIN cases c ON c.case_id = ci.case_id "
        "WHERE ci.ioc_id = ? ORDER BY c.created_at", (ioc_id,)).fetchall()]


def _related_evidence_for_ioc(conn, ioc_id, limit=8):
    row = conn.execute(
        "SELECT ioc_type, value FROM iocs WHERE ioc_id = ?", (ioc_id,)).fetchone()
    if not row:
        return [], 0
    ioc_type, value = row["ioc_type"], row["value"]
    low = value.lower()
    params = [low, low, value, value, value, low]
    rows = conn.execute(
        "SELECT evidence_id, evidence_ref, evidence_type, title, case_id, "
        "acquired_at FROM evidence "
        "WHERE instr(lower(COALESCE(content_text,'')), ?) > 0 "
        "   OR instr(lower(COALESCE(title,'')), ?) > 0 "
        "   OR sha256 = ? OR sha1 = ? OR md5 = ? "
        "   OR lower(COALESCE(original_filename,'')) = ? "
        "ORDER BY acquired_at DESC LIMIT %d" % (limit + 20),
        tuple(params)).fetchall()
    items = []
    for r in rows:
        items.append({
            "evidence_id": r["evidence_id"],
            "evidence_ref": r["evidence_ref"],
            "evidence_type": r["evidence_type"],
            "title": r["title"],
            "case_id": r["case_id"],
            "acquired_at": r["acquired_at"],
        })
    return items[:limit], len(rows)


def _risk_of_evidence(conn, evidence_ids):
    """Real, analysis-derived risk: max risk_score across analyses of these
    evidence rows (or 0 when none exist)."""
    if not evidence_ids:
        return 0
    marks = ",".join("?" * len(evidence_ids))
    row = conn.execute(
        "SELECT MAX(risk_score) AS m FROM analyses "
        "WHERE evidence_id IN (%s)" % marks,
        tuple(evidence_ids)).fetchone()
    return row["m"] if row and row["m"] is not None else 0


def _severity_from_risk(risk):
    if risk is None or risk <= 0:
        return "UNKNOWN"
    if risk >= 75:
        return "CRITICAL"
    if risk >= 50:
        return "HIGH"
    if risk >= 25:
        return "MEDIUM"
    if risk >= 10:
        return "LOW"
    return "UNKNOWN"


class IntelError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def list_iocs(search=None, ioc_type=None, case_ref=None, status=None,
              limit=100, offset=0):
    """Section 26 catalogue with real RELATED CASES / RELATED EVIDENCE."""
    where = []
    params = []
    if ioc_type:
        where.append("i.ioc_type = ?")
        params.append(ioc_type)
    if status:
        where.append("i.status = ?")
        params.append(status)
    if search:
        term = "%" + search.strip().lower() + "%"
        where.append(
            "(instr(lower(i.value), ?) > 0 OR i.ioc_id IN ("
            "SELECT ci.ioc_id FROM case_iocs ci "
            "JOIN cases c ON c.case_id = ci.case_id "
            "WHERE instr(lower(c.case_ref), ?) > 0))")
        params += [search.strip().lower(), term]
    if case_ref:
        where.append("i.ioc_id IN (SELECT ci.ioc_id FROM case_iocs ci "
                     "JOIN cases c ON c.case_id = ci.case_id "
                     "WHERE c.case_ref = ?)")
        params.append(case_ref)

    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(
        "SELECT COUNT(*) AS c FROM iocs i %s" % clause, tuple(params))["c"]

    rows = db.query(
        "SELECT i.* FROM iocs i %s ORDER BY i.last_seen DESC "
        "LIMIT ? OFFSET ?" % clause,
        tuple(params) + (int(limit), int(offset)))

    items = []
    with db.transaction() as conn:
        for r in rows:
            cases = _related_cases_for_ioc(conn, r["ioc_id"])
            evidence, ev_total = _related_evidence_for_ioc(conn, r["ioc_id"])
            case_count = len(cases)
            ev_ids = [e["evidence_id"] for e in evidence]
            risk = _risk_of_evidence(conn, ev_ids) if ev_ids else 0
            items.append({
                "ioc_id": r["ioc_id"],
                "ioc_type": r["ioc_type"],
                "value": r["value"],
                "severity": r.get("severity") or "UNKNOWN",
                "derived_severity": _severity_from_risk(risk),
                "risk": risk,
                "status": r.get("status") or "OBSERVED",
                "source": r["source"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "case_count": case_count,
                "related_cases": [c["case_ref"] for c in cases],
                "evidence_count": ev_total,
                "top_evidence": [e["evidence_ref"] for e in evidence[:5]],
            })
    return {"items": items, "total": total}


def get_ioc(ioc_id):
    row = db.query_one(
        "SELECT i.* FROM iocs i WHERE i.ioc_id = ?", (int(ioc_id),))
    if not row:
        raise IntelError("IOC_NOT_FOUND", "Indicator not found.")

    with db.transaction() as conn:
        cases = _related_cases_for_ioc(conn, row["ioc_id"])
        evidence, ev_total = _related_evidence_for_ioc(conn, row["ioc_id"])
        ev_ids = [e["evidence_id"] for e in evidence]
        risk = _risk_of_evidence(conn, ev_ids) if ev_ids else 0

        analyses = []
        if ev_ids:
            marks = ",".join("?" * len(ev_ids))
            for a in conn.execute(
                    "SELECT a.analysis_ref, a.analysis_type, a.verdict, "
                    "a.risk_score, e.evidence_ref, a.created_at "
                    "FROM analyses a "
                    "LEFT JOIN evidence e ON e.evidence_id = a.evidence_id "
                    "WHERE a.evidence_id IN (%s) ORDER BY a.created_at DESC"
                    % marks, tuple(ev_ids)).fetchall():
                analyses.append(dict(a))

        intel = _ioc_intel(conn, row["ioc_id"])

    return {
        "ioc_id": row["ioc_id"],
        "ioc_type": row["ioc_type"],
        "value": row["value"],
        "severity": row.get("severity") or "UNKNOWN",
        "derived_severity": _severity_from_risk(risk),
        "risk": risk,
        "status": row.get("status") or "OBSERVED",
        "source": row["source"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "related_cases": cases,
        "related_evidence": evidence,
        "evidence_total": ev_total,
        "case_count": len(cases),
        "related_analyses": analyses,
        "intel": intel,
    }


def _ioc_intel(conn, ioc_id):
    """Optional real external intel for hash/URL IOCs. Returns an honest
    envelope with configured/available flags — never fabricated data."""
    row = conn.execute(
        "SELECT ioc_type, value FROM iocs WHERE ioc_id = ?", (ioc_id,)).fetchone()
    if not row:
        return None
    try:
        import intel.virustotal_service as vt
        status = vt.availability_status()
    except Exception:
        status = {"configured": False}
    if not status.get("configured"):
        return {"provider": "VirusTotal", "configured": False,
                "verdict": None, "note": "VIRUSTOTAL_API_KEY not configured."}
    try:
        if row["ioc_type"] == "SHA-256":
            result = vt.lookup_hash(row["value"])
        elif row["ioc_type"] == "URL":
            result = vt.lookup_url(row["value"])
        else:
            return {"provider": "VirusTotal", "configured": True,
                    "verdict": None,
                    "note": "No VirusTotal lookup for %s indicators."
                    % row["ioc_type"]}
    except Exception:
        return {"provider": "VirusTotal", "configured": True,
                "verdict": None, "error": "lookup failed"}
    if not result or result.get("data") is None:
        return {"provider": "VirusTotal", "configured": True,
                "verdict": None,
                "note": result.get("note") or "No verdict returned."}
    data = result["data"]
    return {
        "provider": "VirusTotal",
        "configured": True,
        "available": True,
        "verdict": data.get("verdict"),
        "malicious": data.get("malicious"),
        "reputation": data.get("reputation"),
        "note": result.get("note", ""),
    }


# ---------------------------------------------------------------------------
# Section 26 actions
# ---------------------------------------------------------------------------

def set_ioc_status(ioc_id, status, actor="analyst", ip_address=None):
    status = (status or "").strip().upper()
    if status not in IOC_STATUSES:
        raise IntelError(
            "INVALID_STATUS",
            "status must be one of: %s." % ", ".join(IOC_STATUSES))
    row = db.query_one("SELECT value FROM iocs WHERE ioc_id = ?", (int(ioc_id),))
    if not row:
        raise IntelError("IOC_NOT_FOUND", "Indicator not found.")
    with db.transaction() as conn:
        conn.execute("UPDATE iocs SET status = ? WHERE ioc_id = ?",
                     (status, int(ioc_id)))
        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("IOC_UPDATED", actor, "IOC_STATUS", "ioc", str(ioc_id),
             "Status of %s set to %s." % (row["value"], status),
             ip_address, _now()))
    return {"ioc_id": int(ioc_id), "status": status, "value": row["value"]}


def add_ioc_to_case(ioc_id, case_ref, actor="analyst", ip_address=None):
    """Section 26 action 'ADD TO CASE' — real, audited, idempotent."""
    ioc = db.query_one("SELECT ioc_id, value FROM iocs WHERE ioc_id = ?",
                       (int(ioc_id),))
    if not ioc:
        raise IntelError("IOC_NOT_FOUND", "Indicator not found.")
    case = db.query_one("SELECT case_id, case_ref FROM cases WHERE case_ref = ?",
                        (case_ref,))
    if not case:
        raise IntelError("CASE_NOT_FOUND", "Unknown case reference.")
    with db.transaction() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO case_iocs(case_id, ioc_id) VALUES (?,?)",
            (case["case_id"], ioc["ioc_id"]))
        linked = cur.rowcount > 0
        conn.execute(
            "INSERT INTO timeline_events(case_id, event_type, title, detail, "
            "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (case["case_id"], "IOC_ADDED", "Indicator added",
             "Indicator %s (%s) linked to this case by analyst."
             % (ioc["value"], _ioc_type_label(ioc["ioc_id"])),
             actor, "Analyst action", _now(), _now()))
        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("IOC_ADDED", actor, "IOC_ADD_TO_CASE",
             "ioc", "%s->%s" % (case["case_ref"], ioc["ioc_id"]),
             "Indicator %s linked to %s." % (ioc["value"], case["case_ref"]),
             ip_address, _now()))
    return {"ioc_id": ioc["ioc_id"], "case_ref": case["case_ref"],
            "linked": linked, "value": ioc["value"]}


def _ioc_type_label(ioc_id):
    row = db.query_one("SELECT ioc_type FROM iocs WHERE ioc_id = ?", (ioc_id,))
    return (row or {}).get("ioc_type", "IOC")


# ---------------------------------------------------------------------------
# Section 27 — cross-case correlation
# ---------------------------------------------------------------------------

CORRELATION_STATEMENT = "Same IOC observed across multiple cases."
CORRELATION_NOTE = (
    "Correlation is not attribution. A shared indicator shows overlap in "
    "observed material only; it does not prove a shared attacker, campaign "
    "or organization.")

def correlation():
    rows = db.query(
        "SELECT ci.ioc_id, i.ioc_type, i.value, i.severity, i.status, "
        "COUNT(DISTINCT ci.case_id) AS case_count "
        "FROM case_iocs ci JOIN iocs i ON i.ioc_id = ci.ioc_id "
        "GROUP BY ci.ioc_id HAVING case_count >= 2 "
        "ORDER BY case_count DESC, i.last_seen DESC")
    out = []
    for r in rows:
        cases = db.query(
            "SELECT c.case_ref, c.title, c.status, c.case_type "
            "FROM case_iocs ci JOIN cases c ON c.case_id = ci.case_id "
            "WHERE ci.ioc_id = ? ORDER BY c.created_at", (r["ioc_id"],))
        out.append({
            "ioc_id": r["ioc_id"],
            "ioc_type": r["ioc_type"],
            "value": r["value"],
            "status": r["status"],
            "case_count": r["case_count"],
            "statement": CORRELATION_STATEMENT,
            "related_cases": cases,
        })
    return {"correlations": out, "total": len(out),
            "statement": CORRELATION_STATEMENT, "note": CORRELATION_NOTE}


# ---------------------------------------------------------------------------
# Section 25 — evidence-backed investigation graph
# ---------------------------------------------------------------------------

def _sender_entities(text):
    """Real sender/return-path/reply-to entities from header-style text."""
    out = []
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        for prefix, kind in (("from:", "SENDER"), ("sender:", "SENDER"),
                             ("return-path:", "RETURN-PATH"),
                             ("reply-to:", "REPLY-TO")):
            if line.lower().startswith(prefix):
                value = line[len(prefix):].strip().strip("<>").strip()
                m = _EMAIL_RE.search(value)
                if m:
                    out.append((kind, m.group(0).lower()))
                break
    return out


def entity_graph(case_ref=None):
    """Section 25: nodes/edges derived strictly from vault relations.

    Relationships rendered are only: case contains evidence, case linked to
    IOC, and evidence contains IOC / header sender entity. Nothing inferred.
    """
    if not case_ref:
        # For pickers: real case list (with real IOC/evidence counts).
        cases = db.query(
            "SELECT c.case_ref, c.title, c.status, c.case_type, c.created_at, "
            "(SELECT COUNT(DISTINCT ci.ioc_id) FROM case_iocs ci "
            "   WHERE ci.case_id = c.case_id) AS ioc_count, "
            "(SELECT COUNT(*) FROM evidence e "
            "   WHERE e.case_id = c.case_id) AS evidence_count "
            "FROM cases c ORDER BY c.created_at DESC")
        return {"cases": cases, "graph": None, "case_ref": None}

    case = db.query_one("SELECT * FROM cases WHERE case_ref = ?", (case_ref,))
    if not case:
        raise IntelError("CASE_NOT_FOUND", "Unknown case reference.")

    nodes = {}
    edges = []
    conn = db.get_conn()

    nodes["case:%s" % case["case_id"]] = {
        "id": "case:%s" % case["case_id"],
        "type": "CASE", "label": case["case_ref"], "value": case["case_ref"],
        "title": case["title"], "first_seen": case["created_at"],
        "last_seen": case["updated_at"], "risk": None,
        "related_evidence": [], "related_cases": [], "analyses": [],
    }

    # ---- evidence nodes ----
    evidence_rows = [dict(r) for r in conn.execute(
        "SELECT e.* FROM evidence e WHERE e.case_id = ? ORDER BY e.acquired_at",
        (case["case_id"],)).fetchall()]
    analyses_by_ev = {}
    for a in conn.execute(
            "SELECT analysis_id, evidence_id, analysis_ref, analysis_type, "
            "verdict, risk_score, created_at FROM analyses "
            "WHERE case_id = ? ORDER BY created_at", (case["case_id"],)).fetchall():
        analyses_by_ev.setdefault(a["evidence_id"], []).append(dict(a))

    for ev in evidence_rows:
        eid = "evidence:%s" % ev["evidence_id"]
        ev_analyses = analyses_by_ev.get(ev["evidence_id"], [])
        risk = max([a["risk_score"] or 0 for a in ev_analyses] or [0])
        nodes[eid] = {
            "id": eid, "type": "EVIDENCE",
            "evidence_type": ev["evidence_type"],
            "label": ev["evidence_ref"], "value": ev["evidence_ref"],
            "title": ev["title"], "first_seen": ev["acquired_at"],
            "last_seen": ev["acquired_at"], "risk": risk or None,
            "related_evidence": [ev["evidence_ref"]],
            "related_cases": [case["case_ref"]],
            "analyses": [{
                "analysis_ref": a["analysis_ref"],
                "analysis_type": a["analysis_type"],
                "verdict": a["verdict"], "risk_score": a["risk_score"],
                "created_at": a["created_at"],
            } for a in ev_analyses],
            "status": (ev.get("integrity_state") or "VERIFIED"),
        }
        edges.append({"from": "case:%s" % case["case_id"], "to": eid,
                      "relation": "contains"})

        # sender entities from header-like text (real)
        for kind, email in _sender_entities(ev.get("content_text") or ""):
            sid = "entity:%s:%s" % (kind, email)
            if sid not in nodes:
                nodes[sid] = {
                    "id": sid, "type": kind, "label": email, "value": email,
                    "kind": kind, "first_seen": ev["acquired_at"],
                    "last_seen": ev["acquired_at"], "risk": risk or None,
                    "related_evidence": [], "related_cases": [],
                    "analyses": [a["analysis_ref"] for a in ev_analyses],
                }
            if kind == "SENDER":
                edges.append({"from": eid, "to": sid, "relation": "sent by"})
            else:
                edges.append({"from": eid, "to": sid,
                              "relation": kind.lower().replace("_", " ")})

    # ---- IOC nodes (only those genuinely linked to this case) ----
    ioc_rows = [dict(r) for r in conn.execute(
        "SELECT i.ioc_id, i.ioc_type, i.value, i.status, i.first_seen, "
        "i.last_seen FROM case_iocs ci JOIN iocs i ON i.ioc_id = ci.ioc_id "
        "WHERE ci.case_id = ?", (case["case_id"],)).fetchall()]

    for ioc in ioc_rows:
        iid = "ioc:%s" % ioc["ioc_id"]
        cases = _related_cases_for_ioc(conn, ioc["ioc_id"])
        evidence, _ = _related_evidence_for_ioc(conn, ioc["ioc_id"])
        ev_ids = [e["evidence_id"] for e in evidence]
        risk = _risk_of_evidence(conn, ev_ids) if ev_ids else 0
        nodes[iid] = {
            "id": iid, "type": ioc["ioc_type"], "label": ioc["value"],
            "value": ioc["value"], "status": ioc["status"],
            "first_seen": ioc["first_seen"], "last_seen": ioc["last_seen"],
            "risk": risk or None,
            "related_evidence": [e["evidence_ref"] for e in evidence[:8]],
            "related_cases": [c["case_ref"] for c in cases],
            "analyses": [],
        }
        edges.append({"from": "case:%s" % case["case_id"], "to": iid,
                      "relation": "linked indicator"})
        ev_refs = {e["evidence_ref"] for e in evidence}
        for ev in evidence_rows:
            if ev["evidence_ref"] in ev_refs:
                edges.append({"from": "evidence:%s" % ev["evidence_id"],
                              "to": iid, "relation": "contains"})

    return {
        "case_ref": case["case_ref"],
        "cases": None,
        "graph": {
            "case_ref": case["case_ref"],
            "case_title": case["title"],
            "nodes": list(nodes.values()),
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "note": "Graph edges are rendered only where a real vault relation "
                    "exists (case→evidence, case→indicator, evidence→indicator).",
        },
    }


# ---------------------------------------------------------------------------
# Section 28 — evidence-backed attack chain
# ---------------------------------------------------------------------------

def _chain_stages_for_case(conn, case_id):
    """Real stage nodes derived from the case's evidence + analyses.

    A stage is included only when its supporting evidence/analysis exists;
    otherwise it is omitted (Section 28: only render when supported).
    """
    evidence = [dict(r) for r in conn.execute(
        "SELECT e.* FROM evidence e WHERE e.case_id = ? ORDER BY e.acquired_at",
        (case_id,)).fetchall()]
    if not evidence:
        return []

    ev_by_id = {e["evidence_id"]: e for e in evidence}
    findings_by_ref = {}
    for f in conn.execute(
            "SELECT af.* FROM analysis_findings af JOIN analyses a "
            "ON a.analysis_id = af.analysis_id WHERE a.case_id = ?",
            (case_id,)).fetchall():
        findings_by_ref.setdefault(f["evidence_ref"], []).append(dict(f))

    analyses_by_ev = {}
    for a in conn.execute(
            "SELECT * FROM analyses WHERE case_id = ?", (case_id,)).fetchall():
        analyses_by_ev.setdefault(a["evidence_id"], []).append(dict(a))

    iocs = [dict(r) for r in conn.execute(
        "SELECT i.ioc_type, i.value, i.ioc_id FROM case_iocs ci "
        "JOIN iocs i ON i.ioc_id = ci.ioc_id WHERE ci.case_id = ?",
        (case_id,)).fetchall()]

    ioc_values = {i["value"].lower() for i in iocs}
    ioc_by_type = {}
    for i in iocs:
        ioc_by_type.setdefault(i["ioc_type"], []).append(i)

    stages = []
    seen_labels = set()

    def add(label, kind, ev_ids, an_ids, risk):
        if label in seen_labels:
            return
        seen_labels.add(label)
        stages.append({
            "label": label, "kind": kind,
            "evidence_refs": sorted({ev_by_id[i]["evidence_ref"]
                                     for i in ev_ids if i in ev_by_id}),
            "analysis_refs": sorted(set(an_ids)),
            "risk": risk,
            "rank": CHAIN_RANK.get(label, 99),
        })

    for eid, ev in ev_by_id.items():
        etype = ev["evidence_type"]
        findings = findings_by_ref.get(ev.get("evidence_ref") or "", [])
        anas = analyses_by_ev.get(eid, [])
        ftypes = {f["finding_type"] for f in findings}
        risk = max([a.get("risk_score") or 0 for a in anas] or [0])
        an_ids = [a["analysis_ref"] for a in anas]

        if etype in ("EMAIL", "RAW_HEADER", "MESSAGE"):
            if ftypes & IMPERSONATION:
                add("SENDER IMPERSONATION", "impersonation", [eid], an_ids, risk)
            if ftypes & SOCIAL:
                add("SOCIAL ENGINEERING", "social", [eid], an_ids, risk)
            if ftypes & BEC:
                for btype in ("payment_request", "account_change"):
                    if btype in ftypes:
                        add("PAYMENT REQUEST" if btype == "payment_request"
                            else "ACCOUNT CHANGE", "bec", [eid], an_ids, risk)
            verdicts = [a.get("verdict") for a in anas]
            if any(v in ("MALICIOUS", "SUSPICIOUS") for v in verdicts) or risk >= 50:
                add("SUSPICIOUS EMAIL", "email", [eid], an_ids, risk)
            else:
                add("EMAIL OBSERVED", "email", [eid], an_ids, risk)
            continue

        if etype == "URL":
            verdicts = [a.get("verdict") for a in anas]
            if any(v == "MALICIOUS" for v in verdicts) or risk >= 75:
                add("MALICIOUS URL", "url", [eid], an_ids, risk)
            elif any(v == "SUSPICIOUS" for v in verdicts) or risk >= 50:
                add("SUSPICIOUS URL", "url", [eid], an_ids, risk)
            else:
                add("URL OBSERVED", "url", [eid], an_ids, risk)
            continue

        if etype in ("FILE", "ATTACHMENT"):
            blocked = False
            risk = 0
            for a in anas:
                try:
                    payload = json.loads(a.get("payload_json") or "{}") or {}
                except Exception:
                    payload = {}
                sub = payload.get("analysis") or {}
                if sub.get("blocked_content"):
                    blocked = True
                risk = max(risk, int(sub.get("risk_score") or 0))
            if blocked or risk >= 50:
                add("MALICIOUS ATTACHMENT", "file", [eid], an_ids, risk)
            else:
                add("FILE OBSERVED", "file", [eid], an_ids, risk)
            continue

        if etype in ("HASH",):
            add("HASH OBSERVED", "hash", [eid], an_ids, risk)
            continue

        if etype in ("QR_IMAGE", "SCREENSHOT"):
            add("QR CODE", "qr", [eid], an_ids, risk)
            continue

    # IOC-driven stages (URL/DOMAIN/IP/hash entities observed in the case)
    url_iocs = ioc_by_type.get("URL", [])
    if url_iocs:
        iids = [i["ioc_id"] for i in url_iocs]
        evs_for = []
        for eid, ev in ev_by_id.items():
            if any(i["value"].lower() in (ev.get("content_text") or "").lower()
                   for i in url_iocs):
                evs_for.append(eid)
        if not evs_for:
            evs_for = list(ev_by_id.keys())  # case-linked URL IOC w/o direct text
        add("URL OBSERVED", "url", evs_for, [], 0)

    for dt in ("DOMAIN",):
        for i in ioc_by_type.get(dt, []):
            suspicious = False
            refs = []
            for eid, ev in ev_by_id.items():
                if i["value"].lower() in (ev.get("content_text") or "").lower():
                    refs.append(eid)
            if refs:
                suspicious = any(
                    a.get("verdict") in ("SUSPICIOUS", "MALICIOUS")
                    for a in analyses_by_ev.get(refs[0], [])) if refs else False
            else:
                # domain with no direct text match — check URL host structure
                for u in url_iocs:
                    if u["value"].lower().endswith("." + i["value"]) \
                            or u["value"].lower() == i["value"]:
                        suspicious = True
                        break
            if suspicious:
                add("SUSPICIOUS DOMAIN", "domain", refs or list(ev_by_id), [], 0)
            else:
                add("DOMAIN OBSERVED", "domain", refs or list(ev_by_id), [], 0)

    ip_iocs = ioc_by_type.get("IPv4", []) + ioc_by_type.get("IPv6", [])
    if ip_iocs:
        refs = []
        for eid, ev in ev_by_id.items():
            if any(i["value"] in (ev.get("content_text") or "")
                   for i in ip_iocs):
                refs.append(eid)
        add("HOST IP", "ip", refs or list(ev_by_id), [], 0)

    hash_iocs = ioc_by_type.get("SHA-256", []) + ioc_by_type.get("SHA-1", []) \
        + ioc_by_type.get("MD5", [])
    if hash_iocs:
        add("HASH OBSERVED", "hash", list(ev_by_id), [], 0)

    stages.sort(key=lambda s: s["rank"])
    return stages


def attack_chain(case_ref=None):
    """Section 28: ordered, evidence-backed chain for one case."""
    if not case_ref:
        cases = db.query(
            "SELECT c.case_ref, c.title, c.status, "
            "(SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.case_id) "
            "AS evidence_count FROM cases c ORDER BY c.created_at DESC")
        return {"cases": cases, "chain": None, "case_ref": None,
                "note": "Select a case to derive its evidence-backed chain."}

    case = db.query_one("SELECT * FROM cases WHERE case_ref = ?", (case_ref,))
    if not case:
        raise IntelError("CASE_NOT_FOUND", "Unknown case reference.")

    conn = db.get_conn()
    stages = _chain_stages_for_case(conn, case["case_id"])
    supporting = []
    seen = set()
    for s in stages:
        for ref in s["evidence_refs"]:
            if ref not in seen:
                seen.add(ref)
                row = db.query_one(
                    "SELECT evidence_ref, evidence_type, title FROM evidence "
                    "WHERE evidence_ref = ?", (ref,))
                if row:
                    supporting.append(dict(row))

    if len(stages) < 2:
        return {
            "case_ref": case["case_ref"],
            "chain": [],
            "supporting_evidence": supporting,
            "state": "insufficient",
            "note": "Insufficient evidence to infer an attack chain for this "
                    "case. Chains are only rendered from relationships that "
                    "existing evidence and analysis actually support.",
        }

    return {
        "case_ref": case["case_ref"],
        "chain": stages,
        "supporting_evidence": supporting,
        "state": "chain",
        "note": "Every stage above is backed by the listed evidence and, "
                "where available, the analysis run against it.",
    }