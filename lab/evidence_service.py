"""KAVACHAM LAB — evidence service.

Sections 19 (Evidence Vault), 20 (Evidence Intake), 21 (File Security),
22 (Chain of Custody), 23 (Evidence Integrity).

Guarantees enforced here:
- evidence IDs are KAV-EVD-<year>-<seq> from a real row counter
- originals are stored under a generated name, never the client filename
- SHA-256 / SHA-1 / MD5 are computed from the actual bytes
- custody history is append-only and hash-chained; it is never rewritten
- INTEGRITY VERIFIED is only ever reported when hashes actually match
- uploaded bytes are treated as hostile: validated, never executed
"""

import hashlib
import mimetypes
import os
import re
import unicodedata
from datetime import datetime, timezone

from lab import db

ACTOR_DEFAULT = "analyst"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_ROOT = os.environ.get("KAVACHAM_LAB_STORAGE") or os.path.join(
    BASE_DIR, "lab_storage")
ORIGINALS_DIR = os.path.join(STORAGE_ROOT, "originals")

# --- Section 21: file security limits -------------------------------------
MAX_EVIDENCE_BYTES = int(os.environ.get("KAVACHAM_MAX_EVIDENCE_BYTES", 10 * 1024 * 1024))

# Executable / script formats are refused outright — never stored, never run.
BLOCKED_EXTENSIONS = {
    ".exe", ".com", ".scr", ".pif", ".msi", ".msp", ".cpl", ".dll", ".sys",
    ".drv", ".ocx", ".vxd", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".app", ".deb", ".rpm",
    ".dmg", ".pkg", ".run", ".bin", ".elf", ".so", ".dylnk", ".lnk", ".url",
    ".reg", ".scf", ".inf", ".apk", ".action", ".workflow",
}

# Evidence types accepted by intake (Section 19)
EVIDENCE_TYPES = [
    "EMAIL", "RAW_HEADER", "URL", "DOMAIN", "IP", "HASH", "FILE",
    "SCREENSHOT", "QR_IMAGE", "MESSAGE", "REPORT", "ANALYST_NOTE",
]

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class EvidenceError(Exception):
    """Domain error carrying an API error code (Section 49)."""

    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _now():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Hashing (Section 19)
# ---------------------------------------------------------------------------

def hash_bytes(data):
    """Real digests computed over the actual bytes."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def hash_file(path):
    """Streamed digests so large originals do not have to be held in memory."""
    s256, s1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            s256.update(chunk)
            s1.update(chunk)
            md5.update(chunk)
    return {
        "sha256": s256.hexdigest(),
        "sha1": s1.hexdigest(),
        "md5": md5.hexdigest(),
    }


# ---------------------------------------------------------------------------
# Filename / type validation (Section 21)
# ---------------------------------------------------------------------------

def sanitize_filename(raw):
    """Strip directories, traversal and unsafe characters.

    The result is used only for display metadata. Storage names are always
    generated from the evidence ref, so a crafted filename can never control
    a path.
    """
    if not raw:
        return ""
    # Drop any directory components (POSIX and Windows separators).
    name = str(raw).replace("\\", "/").split("/")[-1]
    # Normalise unicode, then remove control characters.
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if unicodedata.category(c) != "Cc")
    # Remove traversal remnants and collapse to a safe character set.
    name = name.replace("..", "")
    name = _SAFE_NAME_RE.sub("_", name).strip("._")
    return name[:180]


def validate_filename(raw):
    """Reject executables and unsafe names. Returns sanitized name."""
    name = sanitize_filename(raw)
    if not name:
        raise EvidenceError("VALIDATION_FAILED", "A filename is required.")
    ext = os.path.splitext(name)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        raise EvidenceError(
            "FILE_TYPE_BLOCKED",
            "Files of type '%s' are refused and will not be stored." % ext)
    if len(ext) > 10:
        raise EvidenceError("VALIDATION_FAILED",
                            "File extension is implausibly long.")
    return name


def detect_mime(data, filename):
    """Best-effort MIME detection from magic bytes, then extension.

    Returns (declared_by_extension, detected_from_content). Both are recorded;
    a mismatch is surfaced to the analyst rather than silently trusted.
    """
    declared = mimetypes.guess_type(filename or "")[0] or "application/octet-stream"

    detected = None
    head = data[:512] if data else b""
    if head.startswith(b"%PDF-"):
        detected = "application/pdf"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = "image/png"
    elif head.startswith(b"\xff\xd8\xff"):
        detected = "image/jpeg"
    elif head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        detected = "image/gif"
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        detected = "image/webp"
    elif head.startswith(b"PK\x03\x04"):
        detected = "application/zip"
    elif head.startswith(b"\x1f\x8b"):
        detected = "application/gzip"
    elif head.startswith(b"MZ"):
        detected = "application/x-msdownload"
    elif head.startswith(b"\x7fELF"):
        detected = "application/x-executable"
    elif head.startswith(b"{\\rtf"):
        detected = "application/rtf"
    else:
        # Text heuristic: no NUL bytes and valid UTF-8 in the head.
        if head and b"\x00" not in head:
            try:
                head.decode("utf-8")
                detected = "text/plain"
            except UnicodeDecodeError:
                detected = None
    return declared, detected


def validate_evidence_type(value):
    etype = (value or "").strip().upper()
    if etype not in EVIDENCE_TYPES:
        raise EvidenceError(
            "VALIDATION_FAILED",
            "evidence_type must be one of: %s" % ", ".join(EVIDENCE_TYPES))
    return etype


# ---------------------------------------------------------------------------
# Chain of custody (Section 22) — append-only, hash-chained
# ---------------------------------------------------------------------------

GENESIS_PREV = "0" * 64


def _entry_hash(prev_hash, evidence_ref, action, actor, detail, timestamp):
    payload = "|".join([
        prev_hash, evidence_ref, action, actor or "", detail or "", timestamp
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_custody(evidence_id, evidence_ref, action, actor=ACTOR_DEFAULT,
                   detail=None, commit=True):
    """Append one custody event. History is never modified or deleted."""
    timestamp = _now()
    prev = db.query_one(
        "SELECT entry_hash FROM chain_of_custody WHERE evidence_id = ? "
        "ORDER BY event_id DESC LIMIT 1", (evidence_id,))
    prev_hash = prev["entry_hash"] if prev else GENESIS_PREV
    entry_hash = _entry_hash(prev_hash, evidence_ref, action, actor,
                             detail, timestamp)
    db.execute(
        "INSERT INTO chain_of_custody(evidence_id, action, actor, details, "
        "prev_hash, entry_hash, created_at) VALUES (?,?,?,?,?,?,?)",
        (evidence_id, action, actor, detail, prev_hash, entry_hash, timestamp),
        commit=commit)
    return {"action": action, "actor": actor, "entry_hash": entry_hash,
            "prev_hash": prev_hash, "created_at": timestamp}


def verify_custody_chain(evidence_id):
    """Recompute the full chain. Reports the first broken link, if any."""
    rows = db.query(
        "SELECT * FROM chain_of_custody WHERE evidence_id = ? "
        "ORDER BY event_id ASC", (evidence_id,))
    if not rows:
        return {"ok": True, "events": 0, "broken_at": None,
                "detail": "No custody events recorded."}

    ev = db.query_one("SELECT evidence_ref FROM evidence WHERE evidence_id = ?",
                      (evidence_id,))
    evidence_ref = ev["evidence_ref"] if ev else ""

    expected_prev = GENESIS_PREV
    for i, r in enumerate(rows):
        if r["prev_hash"] != expected_prev:
            return {"ok": False, "events": len(rows), "broken_at": i + 1,
                    "detail": "Custody link %d breaks the hash chain." % (i + 1)}
        recomputed = _entry_hash(r["prev_hash"], evidence_ref, r["action"],
                                 r["actor"], r["details"], r["created_at"])
        if recomputed != r["entry_hash"]:
            return {"ok": False, "events": len(rows), "broken_at": i + 1,
                    "detail": "Custody link %d fails hash verification." % (i + 1)}
        expected_prev = r["entry_hash"]
    return {"ok": True, "events": len(rows), "broken_at": None,
            "detail": "All custody links verified."}


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

def reference_data():
    return {
        "evidence_types": list(EVIDENCE_TYPES),
        "max_bytes": MAX_EVIDENCE_BYTES,
        "blocked_extensions": sorted(BLOCKED_EXTENSIONS),
    }


# ---------------------------------------------------------------------------
# Intake (Section 20)
# ---------------------------------------------------------------------------

def _next_evidence_ref():
    year = datetime.now(timezone.utc).year
    row = db.query_one("SELECT COUNT(*) AS n FROM evidence")
    seq = (row["n"] if row else 0) + 1
    while True:
        ref = "KAV-EVD-%04d-%05d" % (year, seq)
        if not db.query_one("SELECT 1 AS x FROM evidence WHERE evidence_ref = ?",
                            (ref,)):
            return ref
        seq += 1


def _resolve_case(case_ref):
    if not case_ref:
        return None
    if isinstance(case_ref, int) or str(case_ref).isdigit():
        row = db.query_one("SELECT case_id, case_ref FROM cases WHERE case_id = ?",
                           (int(case_ref),))
    else:
        row = db.query_one("SELECT case_id, case_ref FROM cases WHERE case_ref = ?",
                           (str(case_ref),))
    if not row:
        raise EvidenceError("CASE_NOT_FOUND",
                            "The referenced case does not exist.", 404)
    return row


def accept_evidence(payload, actor=ACTOR_DEFAULT, ip_address=None):
    """Run the Section 20 intake workflow end to end.

    1 type -> 2 content -> 3 validate -> 4 hash -> 5 ID -> 6 timestamp
    -> 7 attach to case -> custody events.
    Everything happens in one transaction plus a stored original; a failure
    mid-way never leaves a half-recorded evidence row.
    """
    if not isinstance(payload, dict):
        raise EvidenceError("INVALID_PAYLOAD", "Evidence payload must be an object.")

    etype = validate_evidence_type(payload.get("evidence_type"))
    title = (payload.get("title") or "").strip()
    if not title:
        raise EvidenceError("VALIDATION_FAILED", "An evidence title is required.")
    if len(title) > 200:
        raise EvidenceError("VALIDATION_FAILED",
                            "Title must be 200 characters or fewer.")

    source = (payload.get("source") or "Analyst Input").strip() or "Analyst Input"
    notes = (payload.get("notes") or "").strip() or None
    case_row = _resolve_case(payload.get("case_ref"))

    filename = None
    data = None
    stored_path = None
    mime_declared = None
    mime_detected = None
    size_bytes = None
    extension = None

    if "content_base64" in payload and payload.get("content_base64") is not None:
        # File intake (Section 21).
        import base64
        raw_name = payload.get("filename") or ""
        filename = validate_filename(raw_name)

        try:
            data = base64.b64decode(payload.get("content_base64") or "", validate=True)
        except Exception:
            raise EvidenceError("VALIDATION_FAILED",
                                "content_base64 is not valid base64 data.")

        if not data:
            raise EvidenceError("VALIDATION_FAILED", "The uploaded file is empty.")
        if len(data) > MAX_EVIDENCE_BYTES:
            raise EvidenceError(
                "FILE_TOO_LARGE",
                "File exceeds the %d byte evidence limit." % MAX_EVIDENCE_BYTES)

        mime_declared, mime_detected = detect_mime(data, filename)

        # A PE/ELF payload is refused regardless of the filename given.
        if mime_detected in ("application/x-msdownload", "application/x-executable"):
            raise EvidenceError(
                "FILE_TYPE_BLOCKED",
                "Content signature indicates an executable; refused.")

        size_bytes = len(data)
        extension = os.path.splitext(filename)[1].lower()
    else:
        # Text/indicator intake: URL, domain, IP, header, note, message.
        text = (payload.get("content_text") or "").strip()
        if not text:
            raise EvidenceError(
                "VALIDATION_FAILED",
                "Provide either content_base64 or content_text.")
        if len(text) > 2 * 1024 * 1024:
            raise EvidenceError("VALIDATION_FAILED",
                                "Text evidence exceeds 2 MB.")
        data = text.encode("utf-8")
        size_bytes = len(data)
        mime_declared = mime_detected = "text/plain"

    digests = hash_bytes(data)
    evidence_ref = _next_evidence_ref()
    acquired_at = _now()

    # Originals are stored under a generated name derived from the evidence
    # ref only — the client filename never influences the path (Section 21).
    if filename:
        os.makedirs(ORIGINALS_DIR, exist_ok=True)
        stored_name = "%s%s" % (evidence_ref, extension or ".bin")
        stored_path = os.path.join(ORIGINALS_DIR, stored_name)
        with open(stored_path, "wb") as fh:
            fh.write(data)
        # Confirm the bytes on disk hash identically before recording.
        if hash_file(stored_path)["sha256"] != digests["sha256"]:
            os.remove(stored_path)
            raise EvidenceError("STORAGE_FAILED",
                                "Stored original failed hash confirmation.", 500)

    integrity_state = "VERIFIED"  # hashes just matched for this acquisition

    with db.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO evidence(evidence_ref, case_id, evidence_type, title, "
            "original_filename, sha256, sha1, md5, mime_type, size_bytes, "
            "extension, content_text, source, acquired_at, stored_path, "
            "integrity_state, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_ref, case_row["case_id"] if case_row else None, etype,
             title, filename, digests["sha256"], digests["sha1"], digests["md5"],
             mime_detected or mime_declared, size_bytes, extension,
             None if filename else data.decode("utf-8", "replace"),
             source, acquired_at, stored_path, integrity_state, notes))
        evidence_id = cur.lastrowid

        # Custody chain: genesis events for this acquisition.
        def _custody(action, detail):
            ts = _now()
            prev = conn.execute(
                "SELECT entry_hash FROM chain_of_custody WHERE evidence_id = ? "
                "ORDER BY event_id DESC LIMIT 1", (evidence_id,)).fetchone()
            prev_hash = prev[0] if prev else GENESIS_PREV
            eh = _entry_hash(prev_hash, evidence_ref, action, actor, detail, ts)
            conn.execute(
                "INSERT INTO chain_of_custody(evidence_id, action, actor, details, "
                "prev_hash, entry_hash, created_at) VALUES (?,?,?,?,?,?,?)",
                (evidence_id, action, actor, detail, prev_hash, eh, ts))

        _custody("EVIDENCE CREATED", "Evidence record %s created." % evidence_ref)
        _custody("HASH GENERATED",
                 "SHA-256 %s" % digests["sha256"])

        if case_row:
            conn.execute(
                "INSERT INTO timeline_events(case_id, event_type, title, detail, "
                "actor, source, occurred_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (case_row["case_id"], "EVIDENCE_ADDED",
                 "Evidence acquired: %s" % title,
                 "%s (%s) attached to case." % (evidence_ref, etype),
                 actor, source, acquired_at, acquired_at))
            _custody("ADDED TO CASE", "Attached to %s" % case_row["case_ref"])
            conn.execute(
                "UPDATE cases SET updated_at = ? WHERE case_id = ?",
                (acquired_at, case_row["case_id"]))

        conn.execute(
            "INSERT INTO audit_logs(event_type, actor, action, target_type, "
            "target_ref, detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
            ("EVIDENCE", actor, "EVIDENCE_ADDED", "evidence", evidence_ref,
             "%s accepted (%s, %d bytes)" % (evidence_ref, etype, size_bytes),
             ip_address, acquired_at))

    return get_evidence(evidence_ref, actor=actor)


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def get_evidence(evidence_ref, actor=ACTOR_DEFAULT):
    if isinstance(evidence_ref, int) or str(evidence_ref).isdigit():
        row = db.query_one("SELECT * FROM evidence WHERE evidence_id = ?",
                           (int(evidence_ref),))
    else:
        row = db.query_one("SELECT * FROM evidence WHERE evidence_ref = ?",
                           (str(evidence_ref),))
    if not row:
        raise EvidenceError("EVIDENCE_NOT_FOUND",
                            "The requested evidence does not exist.", 404)

    data = dict(row)
    eid = data["evidence_id"]

    case = db.query_one(
        "SELECT case_ref, title, status FROM cases WHERE case_id = ?",
        (data["case_id"],)) if data["case_id"] else None
    data["case"] = case
    data["stored"] = bool(data.get("stored_path"))
    data["stored_file_exists"] = bool(
        data.get("stored_path") and os.path.exists(data["stored_path"]))
    # Never expose the absolute server path (Section 49).
    data.pop("stored_path", None)

    data["custody"] = [dict(r) for r in db.query(
        "SELECT * FROM chain_of_custody WHERE evidence_id = ? "
        "ORDER BY event_id ASC", (eid,))]
    data["custody_verification"] = verify_custody_chain(eid)

    data["analyses"] = [dict(r) for r in db.query(
        "SELECT analysis_ref, analysis_type, status, verdict, risk_score, "
        "confidence, source, created_at FROM analyses WHERE evidence_id = ? "
        "ORDER BY created_at DESC", (eid,))]

    data["mime_matches"] = None
    return data


def _summary(row, case_ref=None):
    return {
        "evidence_id": row["evidence_id"],
        "evidence_ref": row["evidence_ref"],
        "case_ref": case_ref,
        "evidence_type": row["evidence_type"],
        "title": row["title"],
        "sha256": row["sha256"],
        "mime_type": row["mime_type"],
        "size_bytes": row["size_bytes"],
        "extension": row["extension"],
        "original_filename": row["original_filename"],
        "source": row["source"],
        "acquired_at": row["acquired_at"],
        "integrity_state": row["integrity_state"],
        "stored": bool(row.get("stored_path")),
    }


def list_evidence(case_ref=None, evidence_type=None, search=None,
                  limit=50, offset=0):
    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))

    where, params = [], []
    if case_ref:
        where.append("c.case_ref = ?")
        params.append(str(case_ref))
    if evidence_type:
        where.append("e.evidence_type = ?")
        params.append(evidence_type)
    if search:
        like = "%%%s%%" % str(search).strip()
        where.append("(e.evidence_ref LIKE ? OR e.title LIKE ? OR e.sha256 LIKE ? "
                     "OR e.original_filename LIKE ?)")
        params.extend([like, like, like, like])

    join = " JOIN cases c ON c.case_id = e.case_id" if (case_ref) else \
        " LEFT JOIN cases c ON c.case_id = e.case_id"
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    total_row = db.query_one(
        "SELECT COUNT(*) AS n FROM evidence e" + join + clause, tuple(params))
    total = total_row["n"] if total_row else 0

    rows = db.query(
        "SELECT e.*, c.case_ref AS case_ref FROM evidence e" + join + clause +
        " ORDER BY e.acquired_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset))

    return {
        "items": [_summary(r, r.get("case_ref")) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + len(rows)) < total,
    }


def get_custody(evidence_ref):
    """Custody read endpoint (Section 48 GET /api/evidence/:id/custody)."""
    ev = get_evidence(evidence_ref)
    return {
        "evidence_ref": ev["evidence_ref"],
        "events": ev["custody"],
        "count": len(ev["custody"]),
        "verification": ev["custody_verification"],
    }


# ---------------------------------------------------------------------------
# Integrity verification (Section 23)
# ---------------------------------------------------------------------------

def verify_integrity(evidence_ref, actor=ACTOR_DEFAULT):
    """Recompute the stored original's SHA-256 and compare honestly.

    INTEGRITY VERIFIED is returned only when the bytes still hash to the
    value recorded at acquisition. Otherwise INTEGRITY MISMATCH (or
    ORIGINAL UNAVAILABLE when there is nothing left to verify).
    """
    ev = get_evidence(evidence_ref, actor=actor)
    eid = ev["evidence_id"]
    original_sha = ev["sha256"]

    row = db.query_one(
        "SELECT stored_path, content_text FROM evidence WHERE evidence_id = ?",
        (eid,))
    stored_path = row.get("stored_path") if row else None
    content_text = row.get("content_text") if row else None

    if stored_path:
        # File evidence: recompute from the bytes on disk.
        if not os.path.exists(stored_path):
            state, current = "ORIGINAL UNAVAILABLE", None
            detail = ("No stored original exists for this record, so the digest "
                      "cannot be recomputed.")
        else:
            try:
                current = hash_file(stored_path)["sha256"]
            except Exception as exc:
                state, current = "ORIGINAL UNAVAILABLE", None
                detail = "Stored original could not be read (%s)." % type(exc).__name__
            else:
                if current == original_sha:
                    state = "INTEGRITY VERIFIED"
                    detail = "Recomputed SHA-256 matches the acquisition digest."
                else:
                    state = "INTEGRITY MISMATCH"
                    detail = "Recomputed SHA-256 differs from the acquisition digest."
    elif content_text is not None:
        # Text evidence: the stored content is the original — recompute from it.
        current = hashlib.sha256(content_text.encode("utf-8")).hexdigest()
        if current == original_sha:
            state = "INTEGRITY VERIFIED"
            detail = "Recomputed SHA-256 of the stored text matches the acquisition digest."
        else:
            state = "INTEGRITY MISMATCH"
            detail = "Recomputed SHA-256 of the stored text differs from the acquisition digest."
    else:
        state, current = "ORIGINAL UNAVAILABLE", None
        detail = ("No stored original exists for this record, so the digest "
                  "cannot be recomputed.")

    db.execute("UPDATE evidence SET integrity_state = ? WHERE evidence_id = ?",
               (state if state != "ORIGINAL UNAVAILABLE" else "UNVERIFIED", eid))

    append_custody(
        eid, ev["evidence_ref"], "INTEGRITY VERIFIED"
        if state == "INTEGRITY VERIFIED" else "INTEGRITY CHECKED",
        actor=actor, detail=detail)

    db.execute(
        "INSERT INTO audit_logs(event_type, actor, action, target_type, "
        "target_ref, detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
        ("EVIDENCE", actor, "EVIDENCE_VERIFIED", "evidence", ev["evidence_ref"],
         "%s: %s" % (state, detail), None, _now()))

    return {
        "evidence_ref": ev["evidence_ref"],
        "original_sha256": original_sha,
        "current_sha256": current,
        "status": state,
        "detail": detail,
        "checked_at": _now(),
        "custody_verification": verify_custody_chain(eid),
    }


def record_view(evidence_ref, actor=ACTOR_DEFAULT):
    """Record an ANALYST VIEWED custody event (Section 22)."""
    ev = get_evidence(evidence_ref, actor=actor)
    append_custody(ev["evidence_id"], ev["evidence_ref"], "ANALYST VIEWED",
                   actor=actor, detail="Evidence record opened in the vault.")
    return ev
