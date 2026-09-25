"""KAVACHAM LAB — settings store + retention enforcement (Section BR).

Retention is a real stored setting (default 365 days), changeable by
ADMIN roles with every change audited as SETTINGS_CHANGED. Purging
deletes only audit rows older than the cutoff, reports a real count,
and audits the purge itself. Nothing is deleted silently or on a
schedule (no scheduler exists — see WORKERS/BACKGROUND JOBS).
"""

from datetime import datetime, timedelta, timezone

from lab import db

DEFAULTS = {
    "retention_days": "365",
}

RETENTION_MIN = 30
RETENTION_MAX = 3650

SECRET_SOURCE = "environment (.env / process environment)"


class SettingsError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_defaults():
    """Insert missing default settings (idempotent)."""
    now = _now()
    for key, value in DEFAULTS.items():
        db.execute(
            "INSERT OR IGNORE INTO settings(key, value, updated_at, "
            "updated_by) VALUES (?,?,?,?)",
            (key, value, now, "system"))


def get_all():
    """All settings with provenance (never secret values — none stored)."""
    ensure_defaults()
    out = {}
    for key, default in DEFAULTS.items():
        row = db.query_one("SELECT * FROM settings WHERE key = ?", (key,))
        out[key] = {
            "value": row["value"],
            "default": default,
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
        }
    return out


def get(key):
    """Single setting value (string) or its default."""
    ensure_defaults()
    row = db.query_one("SELECT value FROM settings WHERE key = ?", (key,))
    if row:
        return row["value"]
    return DEFAULTS.get(key)


def set_setting(key, value, actor="analyst"):
    """Validate, persist and audit a setting change. Returns the row."""
    from lab import case_service  # deferred: settings -> audit funnel

    ensure_defaults()
    if key not in DEFAULTS:
        raise SettingsError("UNKNOWN_SETTING",
                            "Unknown setting: %s." % key)
    if key == "retention_days":
        try:
            days = int(str(value).strip())
        except (TypeError, ValueError):
            raise SettingsError("VALIDATION_FAILED",
                                "retention_days must be an integer.")
        if not RETENTION_MIN <= days <= RETENTION_MAX:
            raise SettingsError(
                "VALIDATION_FAILED",
                "retention_days must be between %d and %d."
                % (RETENTION_MIN, RETENTION_MAX))
        value = str(days)
    old = get(key)
    now = _now()
    db.execute(
        "UPDATE settings SET value = ?, updated_at = ?, updated_by = ? "
        "WHERE key = ?", (value, now, actor, key))
    case_service.audit(
        "SETTINGS_CHANGED", "SETTINGS_CHANGED", target_type="settings",
        target_ref=key, detail="%s: %s -> %s" % (key, old, value),
        actor=actor)
    return {"key": key, "value": value, "updated_at": now,
            "updated_by": actor}


def _cutoff():
    try:
        days = int(get("retention_days") or DEFAULTS["retention_days"])
    except (TypeError, ValueError):
        days = int(DEFAULTS["retention_days"])
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def purge_preview():
    """Count audit rows past retention (reports only, deletes nothing)."""
    cutoff = _cutoff()
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE created_at < ?",
        (cutoff,))
    return {"cutoff": cutoff,
            "retention_days": get("retention_days"),
            "audit_rows": row["n"] if row else 0}


def purge_audit(actor="analyst"):
    """Delete audit rows past retention. Returns the real deleted count."""
    from lab import case_service  # deferred: settings -> audit funnel

    cutoff = _cutoff()
    with db.transaction() as conn:
        cur = conn.execute(
            "DELETE FROM audit_logs WHERE created_at < ?", (cutoff,))
        deleted = cur.rowcount if cur.rowcount is not None else 0
    case_service.audit(
        "SETTINGS_CHANGED", "AUDIT_PURGED", target_type="audit_logs",
        target_ref="retention",
        detail="Purged %d audit row(s) older than %s." % (deleted, cutoff),
        actor=actor)
    return {"deleted": deleted, "cutoff": cutoff}
