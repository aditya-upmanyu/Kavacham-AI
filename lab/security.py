"""
lab/security.py
===============
KAVACHAM LAB — Phase 12 security (version2.txt BH audit log, BI RBAC).

BH — audit vocabulary and secret-free logging:
* EVENT_TYPES is the required event vocabulary (11 entries). Callers must
  use these values; detail strings are redacted at the audit funnel for
  passwords / API keys / OAuth tokens / session secrets / DB credentials.
* case_service.audit() is the single funnel and always redacts.

BI — server-side RBAC:
* Roles ADMIN / INVESTIGATOR / ANALYST / REVIEWER / READ_ONLY with an
  explicit permission matrix enforced on the backend (frontend hiding is
  NOT authorization). Roles + permissions + role_permissions rows are
  seeded into the schema-v1 RBAC tables by db.bootstrap().
* No login surface exists yet, so current_role() resolves to the default
  ANALYST role through a single adapter point; the enforcement checks run
  on every mutating route regardless. When LOGIN lands, only this adapter
  changes — the checks already live server-side.
"""

import re
from datetime import datetime, timezone

# --- BH: required audit event vocabulary ----------------------------------
EVENT_TYPES = [
    "LOGIN", "LOGOUT",
    "CASE_CREATED", "CASE_UPDATED",
    "EVIDENCE_ADDED", "EVIDENCE_VIEWED",
    "ANALYSIS_EXECUTED",
    "IOC_ADDED",
    "REPORT_GENERATED", "REPORT_EXPORTED",
    "SETTINGS_CHANGED",
]

# Extra real events the Lab records beyond the minimum vocabulary.
EVENT_TYPES_EXTENDED = EVENT_TYPES + [
    "NOTE_ADDED", "EVIDENCE_VERIFIED", "IOC_UPDATED", "IOC_SYNC",
]

# --- BH: anything matching these markers is redacted before persistence --
_SECRET_MARKERS = re.compile(
    r"(?i)(password|passwd|pwd|api[_-]?key|apikey|token|oauth|secret|"
    r"session[_-]?id|authorization|bearer|access[_-]?key|private[_-]?key|"
    r"dsn|credential|db[_-]?password|mysql[_-]?pwd|postgres[_-]?pwd|"
    r"mongodb[_-]?uri)\s*[=:]\s*[^\s,;\"']+")

_SECRET_BEARER = re.compile(r"(?i)(bearer\s+)[a-z0-9._\-]+")


def redact_secrets(text):
    """Return *text* with secret-like values replaced by [REDACTED].

    Never-log rules (BH): passwords, API keys, OAuth tokens, session
    secrets, database credentials. A plain string is returned unchanged;
    None stays None.
    """
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    text = _SECRET_BEARER.sub(r"\1[REDACTED]", text)
    text = _SECRET_MARKERS.sub(lambda m: m.group(1) + "=[REDACTED]", text)
    return text


# --- BI: roles & permission matrix ---------------------------------------
ROLES = ["ADMIN", "INVESTIGATOR", "ANALYST", "REVIEWER", "READ_ONLY"]

PERMISSIONS = [
    ("case:view", "View cases and their records"),
    ("case:create", "Open new investigations"),
    ("case:update", "Update cases, notes, timeline"),
    ("evidence:view", "View evidence vault and custody"),
    ("evidence:create", "Accept new evidence"),
    ("evidence:verify", "Run evidence integrity verification"),
    ("analysis:view", "View analyses and findings"),
    ("analysis:run", "Execute the analysis pipeline"),
    ("intel:view", "View IOC intelligence surfaces"),
    ("intel:update", "Manage IOC disposition and case links"),
    ("intel:sync", "Rescan vault for indicators"),
    ("risk:view", "View the risk register and assessments"),
    ("report:view", "View reports and export packages"),
    ("report:create", "Generate investigation reports"),
    ("report:export", "Build and download export packages"),
    ("report:verify", "Verify export package integrity"),
    ("audit:view", "Read the audit log"),
    ("settings:manage", "Manage Lab settings"),
]

_READ = {"case:view", "evidence:view", "analysis:view", "intel:view",
         "risk:view", "report:view", "audit:view"}

_WRITE = {"case:create", "case:update", "evidence:create", "analysis:run",
          "intel:update", "intel:sync", "report:create", "report:export",
          "evidence:verify", "report:verify"}

PERMISSION_MATRIX = {
    "READ_ONLY": _READ,
    "REVIEWER": _READ | {"evidence:verify", "report:verify"},
    "ANALYST": _READ | _WRITE,
    "INVESTIGATOR": _READ | _WRITE,
    "ADMIN": _READ | {p for p, _ in PERMISSIONS},
}


def effective_permissions(role):
    """Permissions granted to a role (unknown role -> empty set)."""
    return set(PERMISSION_MATRIX.get(role, set()))


def authorize(role, permission):
    """Server-side check: may *role* perform *permission*?"""
    return permission in effective_permissions(role)


def permission_codes():
    return [code for code, _ in PERMISSIONS]


# --- current actor resolution ---------------------------------------------
_DEFAULT_ROLE = "ANALYST"


def default_role():
    """Role used until a LOGIN surface exists (single adapter point)."""
    return _DEFAULT_ROLE


def current_role():
    """Role of the current session actor. See module docstring (BI)."""
    return default_role()


# --- seed the schema-v1 RBAC tables (idempotent) --------------------------
def seed_rbac():
    """Insert roles / permissions / role_permissions rows (Section 45).

    Safe to call on every boot: existing rows are left untouched.
    """
    from lab import db  # deferred import avoids the db -> security cycle
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for name in ROLES:
        db.execute(
            "INSERT OR IGNORE INTO roles(name, description, created_at) "
            "VALUES (?,?,?)",
            (name, "RBAC role (version2.txt BI)", now))
    for code, desc in PERMISSIONS:
        db.execute(
            "INSERT OR IGNORE INTO permissions(code, description) "
            "VALUES (?,?)", (code, desc))
    for role, perms in PERMISSION_MATRIX.items():
        role_row = db.query_one("SELECT role_id FROM roles WHERE name = ?",
                                (role,))
        if not role_row:
            continue
        for code in sorted(perms):
            perm_row = db.query_one(
                "SELECT permission_id FROM permissions WHERE code = ?",
                (code,))
            if perm_row:
                db.execute(
                    "INSERT OR IGNORE INTO role_permissions(role_id, "
                    "permission_id) VALUES (?,?)",
                    (role_row["role_id"], perm_row["permission_id"]))
    return {"roles": len(ROLES),
            "permissions": len(PERMISSIONS),
            "role_permissions": sum(len(v) for v in PERMISSION_MATRIX.values())}