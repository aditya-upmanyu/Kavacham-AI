"""KAVACHAM LAB — case management service.

Sections 16 (Case Management), 17 (Creation Workflow), 18 (Case Command View),
24 (Timeline), 44 (Audit Log), 67 (Investigation Notes).

Every mutation writes an audit event and, where meaningful, a timeline event.
Case IDs are generated as KAV-CASE-<year>-<seq> from a real row counter.
"""

from datetime import datetime, timezone

from lab import db

ACTOR_DEFAULT = "analyst"


def _now():
    return datetime.now(timezone.utc).isoformat()


class CaseError(Exception):
    """Domain error carrying an API error code (Section 49)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

def reference_data():
    return {
        "case_types": list(db.CASE_TYPES),
        "statuses": list(db.CASE_STATUSES),
        "priorities": list(db.CASE_PRIORITIES),
        "transitions": {k: list(v) for k, v in db.VALID_TRANSITIONS.items()},
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _next_case_ref():
    """KAV-CASE-2026-00001 — sequence from a real count of existing rows."""
    year = datetime.now(timezone.utc).year
    row = db.query_one("SELECT COUNT(*) AS n FROM cases")
    seq = (row["n"] if row else 0) + 1
    # Avoid collision if rows were deleted.
    while True:
        ref = "KAV-CASE-%04d-%05d" % (year, seq)
        existing = db.query_one("SELECT 1 AS x FROM cases WHERE case_ref = ?", (ref,))
        if not existing:
            return ref
        seq += 1


def audit(event_type, action, target_type=None, target_ref=None,
          detail=None, actor=ACTOR_DEFAULT, ip_address=None):
    """Write an audit log entry (Section 44)."""
    db.execute(
        "INSERT INTO audit_logs(event_type, actor, action, target_type, "
        "target_ref, detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (event_type, actor, action, target_type, target_ref, detail,
         ip_address, _now()))


def add_timeline_event(case_id, event_type, title, detail=None,
                       actor=ACTOR_DEFAULT, source="Analyst Input",
                       occurred_at=None):
    """Initialize/extend the case timeline (Section 24)."""
    ts = occurred_at or _now()
    db.execute(
        "INSERT INTO timeline_events(case_id, event_type, title, detail, "
        "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (case_id, event_type, title, detail, actor, source, ts, _now()))
    return ts


# ---------------------------------------------------------------------------
# Creation (Section 17)
# ---------------------------------------------------------------------------

def create_case(payload, actor=ACTOR_DEFAULT, ip_address=None):
    """Create a case with full workflow side-effects.

    On creation: generate case ID, record timestamp, create audit event,
    initialize timeline, initialize case relationships. Never creates a
    partial record silently — all writes happen in one transaction.
    """
    if not isinstance(payload, dict):
        raise CaseError("INVALID_PAYLOAD", "Case payload must be an object.")

    title = (payload.get("title") or "").strip()
    if not title:
        raise CaseError("VALIDATION_FAILED", "A case title is required.")
    if len(title) > 200:
        raise CaseError("VALIDATION_FAILED", "Title must be 200 characters or fewer.")

    case_type = (payload.get("case_type") or "").strip().upper()
    if case_type not in db.CASE_TYPES:
        raise CaseError("VALIDATION_FAILED",
                        "case_type must be one of: %s" % ", ".join(db.CASE_TYPES))

    priority = (payload.get("priority") or "MEDIUM").strip().upper()
    if priority not in db.CASE_PRIORITIES:
        raise CaseError("VALIDATION_FAILED",
                        "priority must be one of: %s" % ", ".join(db.CASE_PRIORITIES))

    status = "OPEN"
    description = (payload.get("description") or "").strip() or None
    assigned = (payload.get("assigned_investigator") or "").strip() or None
    iocs = payload.get("iocs") or []

    now = _now()
    case_ref = _next_case_ref()

    with db.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO cases(case_ref, title, description, case_type, priority, "
            "status, created_at, updated_at, assigned_investigator, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (case_ref, title, description, case_type, priority, status,
             now, now, assigned, actor))
        case_id = cur.lastrowid

        # Initialize timeline (Section 17)
        conn.execute(
            "INSERT INTO timeline_events(case_id, event_type, title, detail, "
            "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (case_id, "CASE_CREATED", "Case opened",
             "Investigation %s created with type %s and priority %s."
             % (case_ref, case_type, priority),
             actor, "Analyst Input", now, now))

        if assigned:
            conn.execute(
                "INSERT INTO timeline_events(case_id, event_type, title, detail, "
                "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (case_id, "ASSIGNED", "Investigator assigned",
                 "Assigned to %s." % assigned, actor, "Analyst Input", now, now))

        # Initial indicators (Section 17 step 3) — real values only
        for raw in iocs:
            value = str(raw).strip()
            if not value:
                continue
            ioc_type = _classify_ioc(value)
            conn.execute(
                "INSERT OR IGNORE INTO iocs(ioc_type, value, severity, source, "
                "first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                (ioc_type, value, "UNKNOWN", "Analyst Input", now, now))
            conn.execute(
                "INSERT OR IGNORE INTO case_iocs(case_id, ioc_id) "
                "SELECT ?, ioc_id FROM iocs WHERE ioc_type = ? AND value = ?",
                (case_id, ioc_type, value))

        # Audit event (Section 44)
        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
            ("CASE", actor, "CASE_CREATED", "case", case_ref,
             "Created case %s (%s)" % (case_ref, case_type), ip_address, now))

    return get_case(case_id, actor=actor)


def _classify_ioc(value):
    """Best-effort IOC typing from a real literal value — no guessing of risk."""
    import re
    v = value.strip().lower()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "IP"
    if v.startswith(("http://", "https://")):
        return "URL"
    if "@" in v and " " not in v:
        return "EMAIL"
    if re.match(r"^[a-f0-9]{32}$", v):
        return "MD5"
    if re.match(r"^[a-f0-9]{40}$", v):
        return "SHA1"
    if re.match(r"^[a-f0-9]{64}$", v):
        return "SHA256"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
        return "DOMAIN"
    return "OTHER"


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def _case_row(row):
    """Shape a case row for the API, with real related counts."""
    case_id = row["case_id"]
    counts = db.query_one(
        "SELECT "
        "(SELECT COUNT(*) FROM evidence WHERE case_id = ?) AS evidence, "
        "(SELECT COUNT(*) FROM case_iocs WHERE case_id = ?) AS iocs, "
        "(SELECT COUNT(*) FROM analyses WHERE case_id = ?) AS analyses, "
        "(SELECT COUNT(*) FROM notes WHERE case_id = ?) AS notes, "
        "(SELECT COUNT(*) FROM timeline_events WHERE case_id = ?) AS events",
        (case_id, case_id, case_id, case_id, case_id))
    return {
        "case_id": case_id,
        "case_ref": row["case_ref"],
        "title": row["title"],
        "description": row["description"],
        "case_type": row["case_type"],
        "priority": row["priority"],
        "status": row["status"],
        "risk_level": row.get("risk_level"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "closed_at": row.get("closed_at"),
        "assigned_investigator": row.get("assigned_investigator"),
        "created_by": row.get("created_by"),
        "counts": {
            "evidence": counts["evidence"],
            "iocs": counts["iocs"],
            "analyses": counts["analyses"],
            "notes": counts["notes"],
            "timeline_events": counts["events"],
        },
        "allowed_transitions": list(db.VALID_TRANSITIONS.get(row["status"], [])),
    }


def list_cases(status=None, priority=None, case_type=None, search=None,
               limit=50, offset=0):
    """Filtered case list with real counts."""
    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))

    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if priority:
        where.append("priority = ?")
        params.append(priority)
    if case_type:
        where.append("case_type = ?")
        params.append(case_type)
    if search:
        like = "%%%s%%" % str(search).strip()
        where.append("(case_ref LIKE ? OR title LIKE ? OR description LIKE ?)")
        params.extend([like, like, like])

    clause = (" WHERE " + " AND ".join(where)) if where else ""

    total_row = db.query_one("SELECT COUNT(*) AS n FROM cases" + clause, tuple(params))
    total = total_row["n"] if total_row else 0

    rows = db.query(
        "SELECT * FROM cases" + clause +
        " ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset))

    return {
        "items": [_case_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + len(rows)) < total,
    }


def get_case(case_ref, actor=ACTOR_DEFAULT):
    """Fetch a case by numeric id or case_ref, with related records."""
    if isinstance(case_ref, int) or (isinstance(case_ref, str) and case_ref.isdigit()):
        row = db.query_one("SELECT * FROM cases WHERE case_id = ?", (int(case_ref),))
    else:
        row = db.query_one("SELECT * FROM cases WHERE case_ref = ?", (str(case_ref),))
    if not row:
        raise CaseError("CASE_NOT_FOUND", "The requested case does not exist.")

    data = _case_row(row)
    cid = data["case_id"]

    data["timeline"] = [dict(r) for r in db.query(
        "SELECT * FROM timeline_events WHERE case_id = ? "
        "ORDER BY occurred_at ASC, event_id ASC", (cid,))]
    data["notes"] = [dict(r) for r in db.query(
        "SELECT * FROM notes WHERE case_id = ? ORDER BY created_at DESC", (cid,))]
    data["iocs"] = [dict(r) for r in db.query(
        "SELECT i.* FROM iocs i JOIN case_iocs ci ON ci.ioc_id = i.ioc_id "
        "WHERE ci.case_id = ? ORDER BY i.severity DESC, i.ioc_type", (cid,))]
    data["evidence"] = [dict(r) for r in db.query(
        "SELECT evidence_id, evidence_ref, evidence_type, title, sha256, "
        "mime_type, size_bytes, source, acquired_at, integrity_state "
        "FROM evidence WHERE case_id = ? ORDER BY acquired_at DESC", (cid,))]
    data["analyses"] = [dict(r) for r in db.query(
        "SELECT analysis_id, analysis_ref, analysis_type, status, verdict, "
        "risk_score, confidence, source, created_at "
        "FROM analyses WHERE case_id = ? ORDER BY created_at DESC", (cid,))]
    data["reports"] = [dict(r) for r in db.query(
        "SELECT report_id, report_ref, title, format, status, created_at "
        "FROM reports WHERE case_id = ? ORDER BY created_at DESC", (cid,))]
    return data


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

def update_case(case_ref, payload, actor=ACTOR_DEFAULT, ip_address=None):
    """Update mutable case fields with audit + timeline side-effects."""
    if not isinstance(payload, dict):
        raise CaseError("INVALID_PAYLOAD", "Patch payload must be an object.")

    existing = get_case(case_ref, actor=actor)
    cid = existing["case_id"]
    now = _now()
    changes = []

    sets, params = [], []

    if "title" in payload:
        title = (payload.get("title") or "").strip()
        if not title:
            raise CaseError("VALIDATION_FAILED", "A case title is required.")
        if title != existing["title"]:
            sets.append("title = ?")
            params.append(title)
            changes.append("title")

    if "description" in payload:
        desc = (payload.get("description") or "").strip() or None
        if desc != existing["description"]:
            sets.append("description = ?")
            params.append(desc)
            changes.append("description")

    if "priority" in payload:
        priority = (payload.get("priority") or "").strip().upper()
        if priority not in db.CASE_PRIORITIES:
            raise CaseError("VALIDATION_FAILED",
                            "priority must be one of: %s" % ", ".join(db.CASE_PRIORITIES))
        if priority != existing["priority"]:
            sets.append("priority = ?")
            params.append(priority)
            changes.append("priority: %s -> %s" % (existing["priority"], priority))

    if "assigned_investigator" in payload:
        assigned = (payload.get("assigned_investigator") or "").strip() or None
        if assigned != existing["assigned_investigator"]:
            sets.append("assigned_investigator = ?")
            params.append(assigned)
            changes.append("assignment: %s -> %s"
                           % (existing["assigned_investigator"] or "unassigned",
                              assigned or "unassigned"))

    if "case_type" in payload:
        case_type = (payload.get("case_type") or "").strip().upper()
        if case_type not in db.CASE_TYPES:
            raise CaseError("VALIDATION_FAILED",
                            "case_type must be one of: %s" % ", ".join(db.CASE_TYPES))
        if case_type != existing["case_type"]:
            sets.append("case_type = ?")
            params.append(case_type)
            changes.append("case_type: %s -> %s" % (existing["case_type"], case_type))

    new_status = None
    if "status" in payload:
        status = (payload.get("status") or "").strip().upper()
        if status not in db.CASE_STATUSES:
            raise CaseError("VALIDATION_FAILED",
                            "status must be one of: %s" % ", ".join(db.CASE_STATUSES))
        allowed = db.VALID_TRANSITIONS.get(existing["status"], [])
        if status != existing["status"] and status not in allowed:
            raise CaseError(
                "INVALID_TRANSITION",
                "Cannot move a case from %s to %s. Allowed: %s"
                % (existing["status"], status,
                   ", ".join(allowed) if allowed else "none"))
        if status != existing["status"]:
            new_status = status
            sets.append("status = ?")
            params.append(status)
            changes.append("status: %s -> %s" % (existing["status"], status))
            if status in ("RESOLVED", "ARCHIVED"):
                sets.append("closed_at = ?")
                params.append(now)
            else:
                sets.append("closed_at = NULL")

    if not sets:
        return existing

    sets.append("updated_at = ?")
    params.append(now)
    params.append(cid)

    with db.transaction() as conn:
        conn.execute(
            "UPDATE cases SET %s WHERE case_id = ?" % ", ".join(sets), tuple(params))

        detail = "; ".join(changes)
        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
            ("CASE", actor, "CASE_UPDATED", "case", existing["case_ref"],
             detail, ip_address, now))
        conn.execute(
            "INSERT INTO timeline_events(case_id, event_type, title, detail, "
            "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (cid, "CASE_UPDATED", "Case updated", detail, actor,
             "Analyst Input", now, now))
        if new_status:
            conn.execute(
                "INSERT INTO timeline_events(case_id, event_type, title, detail, "
                "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (cid, "STATUS_CHANGED", "Status changed to %s" % new_status,
                 detail, actor, "Analyst Input", now, now))

    return get_case(cid, actor=actor)


def add_note(case_ref, body, author=ACTOR_DEFAULT, ip_address=None):
    """Append an investigation note (Section 67)."""
    body = (body or "").strip()
    if not body:
        raise CaseError("VALIDATION_FAILED", "A note body is required.")
    if len(body) > 5000:
        raise CaseError("VALIDATION_FAILED", "Note must be 5000 characters or fewer.")

    existing = get_case(case_ref, actor=author)
    now = _now()
    with db.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO notes(case_id, author, body, created_at, updated_at) "
            "VALUES (?,?,?,?,?)", (existing["case_id"], author, body, now, now))
        note_id = cur.lastrowid
        conn.execute(
            "UPDATE cases SET updated_at = ? WHERE case_id = ?",
            (now, existing["case_id"]))
        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
            ("NOTE", author, "NOTE_ADDED", "case", existing["case_ref"],
             "Note %d added (%d chars)" % (note_id, len(body)), ip_address, now))

    return {"note_id": note_id, "case_ref": existing["case_ref"],
            "author": author, "body": body, "created_at": now}


def list_audit(limit=100, action=None, target_ref=None):
    """Audit log read (Section 44)."""
    limit = max(1, min(int(limit or 100), 500))
    where, params = [], []
    if action:
        where.append("action = ?")
        params.append(action)
    if target_ref:
        where.append("target_ref = ?")
        params.append(target_ref)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = db.query(
        "SELECT * FROM audit_logs" + clause + " ORDER BY created_at DESC LIMIT ?",
        tuple(params) + (limit,))
    return {"items": rows, "count": len(rows), "limit": limit}
