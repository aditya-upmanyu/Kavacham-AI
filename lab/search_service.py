"""KAVACHAM LAB — global command search (Section O).

Searches case / evidence / analysis references, IOC values and sender
entities. Exact matches rank before partial matches; every row links to
a real page (never a dead result). Empty queries return empty groups —
never a full dump. Only stdlib + the existing data layer.
"""

import re

from lab import db

GROUPS = ("case", "evidence", "analysis", "ioc", "entity")
PER_GROUP = 8

_EMAIL_LINE_RE = re.compile(
    r"^(?:from|sender|return-path|reply-to)\s*:\s*<?"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?\s*$",
    re.IGNORECASE | re.MULTILINE)


def _like(term):
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace(
        "_", "\\_") + "%"


def _cases(q):
    exact = db.query(
        "SELECT case_ref, title, case_type, status FROM cases "
        "WHERE case_ref = ? ORDER BY created_at DESC", (q,)) or []
    partial = db.query(
        "SELECT case_ref, title, case_type, status FROM cases "
        "WHERE (case_ref LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\') "
        "AND case_ref != ? ORDER BY created_at DESC LIMIT ?",
        (_like(q), _like(q), q, PER_GROUP)) or []
    out = [{
        "kind": "case", "match": "exact", "label": r["case_ref"],
        "sub": "%s · %s" % (r["title"], r["status"]),
        "url": "/lab/cases/%s" % r["case_ref"],
    } for r in exact]
    out += [{
        "kind": "case", "match": "partial", "label": r["case_ref"],
        "sub": "%s · %s" % (r["title"], r["status"]),
        "url": "/lab/cases/%s" % r["case_ref"],
    } for r in partial]
    return out[:PER_GROUP]


def _evidence(q):
    exact = db.query(
        "SELECT evidence_ref, title, evidence_type FROM evidence "
        "WHERE evidence_ref = ? OR sha256 = ? ORDER BY acquired_at DESC",
        (q, q)) or []
    partial = db.query(
        "SELECT evidence_ref, title, evidence_type FROM evidence "
        "WHERE (evidence_ref LIKE ? ESCAPE '\\' "
        "OR title LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\') "
        "AND evidence_ref != ? AND sha256 != ? "
        "ORDER BY acquired_at DESC LIMIT ?",
        (_like(q), _like(q), _like(q), q, q, PER_GROUP)) or []
    out = [{
        "kind": "evidence", "match": "exact", "label": r["evidence_ref"],
        "sub": "%s · %s" % (r["title"], r["evidence_type"]),
        "url": "/lab/evidence/%s" % r["evidence_ref"],
    } for r in exact]
    out += [{
        "kind": "evidence", "match": "partial", "label": r["evidence_ref"],
        "sub": "%s · %s" % (r["title"], r["evidence_type"]),
        "url": "/lab/evidence/%s" % r["evidence_ref"],
    } for r in partial]
    return out[:PER_GROUP]


def _analyses(q):
    exact = db.query(
        "SELECT analysis_ref, analysis_type, verdict FROM analyses "
        "WHERE analysis_ref = ? ORDER BY created_at DESC", (q,)) or []
    partial = db.query(
        "SELECT analysis_ref, analysis_type, verdict FROM analyses "
        "WHERE analysis_ref LIKE ? ESCAPE '\\' AND analysis_ref != ? "
        "ORDER BY created_at DESC LIMIT ?",
        (_like(q), q, PER_GROUP)) or []
    out = [{
        "kind": "analysis", "match": "exact", "label": r["analysis_ref"],
        "sub": "%s · %s" % (r["analysis_type"], r["verdict"] or "—"),
        "url": "/lab/analysis/%s" % r["analysis_ref"],
    } for r in exact]
    out += [{
        "kind": "analysis", "match": "partial", "label": r["analysis_ref"],
        "sub": "%s · %s" % (r["analysis_type"], r["verdict"] or "—"),
        "url": "/lab/analysis/%s" % r["analysis_ref"],
    } for r in partial]
    return out[:PER_GROUP]


def _iocs(q):
    exact = db.query(
        "SELECT ioc_type, value, status FROM iocs WHERE value = ? LIMIT ?",
        (q, PER_GROUP)) or []
    partial = db.query(
        "SELECT ioc_type, value, status FROM iocs "
        "WHERE value LIKE ? ESCAPE '\\' AND value != ? LIMIT ?",
        (_like(q), q, PER_GROUP)) or []
    out = [{
        "kind": "ioc", "match": "exact",
        "label": r["value"][:80],
        "sub": "%s · %s" % (r["ioc_type"], r["status"]),
        "url": "/lab/intel/iocs",
    } for r in exact]
    out += [{
        "kind": "ioc", "match": "partial",
        "label": r["value"][:80],
        "sub": "%s · %s" % (r["ioc_type"], r["status"]),
        "url": "/lab/intel/iocs",
    } for r in partial]
    return out[:PER_GROUP]


def _entities(q):
    """Sender entities: EMAIL IOCs plus header senders in evidence text."""
    out = []
    seen = set()
    needle = q.lower()
    for r in db.query(
            "SELECT value FROM iocs WHERE ioc_type = 'EMAIL' AND "
            "value LIKE ? ESCAPE '\\' LIMIT ?",
            (_like(q), PER_GROUP)) or []:
        email = (r["value"] or "").lower()
        if email and email not in seen:
            seen.add(email)
            out.append({
                "kind": "entity", "match": "exact" if email == needle else "partial",
                "label": email, "sub": "EMAIL indicator",
                "url": "/lab/intel/iocs",
            })
    if len(out) < PER_GROUP:
        for r in db.query(
                "SELECT evidence_ref, content_text FROM evidence "
                "WHERE content_text LIKE '%@%' ORDER BY acquired_at DESC "
                "LIMIT 200") or []:
            for m in _EMAIL_LINE_RE.finditer(r["content_text"] or ""):
                email = m.group(1).lower()
                if needle in email and email not in seen:
                    seen.add(email)
                    out.append({
                        "kind": "entity",
                        "match": "exact" if email == needle else "partial",
                        "label": email,
                        "sub": "SENDER · %s" % r["evidence_ref"],
                        "url": "/lab/evidence/%s" % r["evidence_ref"],
                    })
                    if len(out) >= PER_GROUP:
                        break
            if len(out) >= PER_GROUP:
                break
    return out


_BUILDERS = {
    "case": (_cases, "CASES"),
    "evidence": (_evidence, "EVIDENCE"),
    "analysis": (_analyses, "ANALYSES"),
    "ioc": (_iocs, "INDICATORS"),
    "entity": (_entities, "ENTITIES"),
}


def search(query, only=None):
    """Run the global search. Returns grouped, capped, linkable results."""
    q = (query or "").strip()
    if not q:
        return {"query": "", "groups": [], "total": 0}
    wanted = [g for g in GROUPS if only in (None, "", g)] if only else list(GROUPS)
    if only and only not in GROUPS:
        return {"query": q, "groups": [], "total": 0}
    groups = []
    total = 0
    for name in wanted:
        build, title = _BUILDERS[name]
        try:
            items = build(q)
        except Exception:
            items = []
        groups.append({"group": name, "title": title, "items": items,
                       "count": len(items)})
        total += len(items)
    return {"query": q, "groups": groups, "total": total}
