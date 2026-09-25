"""KAVACHAM LAB — SQLite data layer.

Section 46 (Database Architecture):
- normalized entities with foreign keys, indexes, constraints, timestamps
- proper unique identifiers and relationships
- migrations: schema changes are applied through an ordered, versioned
  migration list, never by hand-editing a live schema

Uses stdlib sqlite3 so no new dependency is introduced (Section 82).
"""

import os
import sqlite3
import threading
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("KAVACHAM_LAB_DB") or os.path.join(BASE_DIR, "kavacham_lab.db")

_lock = threading.Lock()
_local = threading.local()


def utcnow():
    """Timezone-aware UTC timestamp stored as ISO-8601 text."""
    return datetime.now(timezone.utc).isoformat()


def _connect():
    """One connection per thread, with FK enforcement enabled."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 15000")
        _local.conn = conn
    return conn


def get_conn():
    return _connect()


def close_conn():
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.conn = None


def query(sql, params=()):
    """Return list[dict]."""
    conn = _connect()
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def query_one(sql, params=()):
    conn = _connect()
    cur = conn.execute(sql, params)
    row = cur.fetchone()
    return dict(row) if row else None


def execute(sql, params=(), commit=True):
    """Execute a statement, return rowcount."""
    conn = _connect()
    cur = conn.execute(sql, params)
    if commit:
        conn.commit()
    return cur.rowcount


def executescript(script, commit=True):
    conn = _connect()
    conn.executescript(script)
    if commit:
        conn.commit()


def transaction():
    """Context manager wrapping commit/rollback."""
    conn = _connect()

    class _Tx:
        def __enter__(self):
            return conn

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                conn.commit()
            else:
                conn.rollback()
            return False

    return _Tx()


# ---------------------------------------------------------------------------
# Migrations — ordered, versioned, idempotent (Section 46)
# ---------------------------------------------------------------------------

# Each entry: (version, description, sql)
# SQL must be safe to re-run only via the schema_migrations guard below.
MIGRATIONS = [
    (1, "core identity, cases, evidence, analysis, intelligence, audit", """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at  TEXT NOT NULL
        );

        -- ---------- users & RBAC (Section 45) ----------
        CREATE TABLE IF NOT EXISTS roles (
            role_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS permissions (
            permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
            code          TEXT NOT NULL UNIQUE,
            description   TEXT
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id       INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
            permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_id)
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL UNIQUE,
            display_name TEXT,
            email        TEXT,
            role_id      INTEGER REFERENCES roles(role_id) ON DELETE SET NULL,
            is_active    INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );

        -- ---------- cases (Section 16) ----------
        CREATE TABLE IF NOT EXISTS cases (
            case_id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_ref             TEXT NOT NULL UNIQUE,
            title                TEXT NOT NULL,
            description          TEXT,
            case_type            TEXT NOT NULL,
            priority             TEXT NOT NULL DEFAULT 'MEDIUM',
            status               TEXT NOT NULL DEFAULT 'OPEN',
            risk_level           TEXT,
            created_at           TEXT NOT NULL,
            updated_at           TEXT NOT NULL,
            assigned_investigator TEXT,
            created_by           TEXT,
            closed_at            TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cases_status    ON cases(status);
        CREATE INDEX IF NOT EXISTS idx_cases_priority  ON cases(priority);
        CREATE INDEX IF NOT EXISTS idx_cases_type      ON cases(case_type);
        CREATE INDEX IF NOT EXISTS idx_cases_created   ON cases(created_at DESC);

        -- ---------- evidence (Section 19) ----------
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_ref    TEXT NOT NULL UNIQUE,
            case_id         INTEGER REFERENCES cases(case_id) ON DELETE SET NULL,
            evidence_type   TEXT NOT NULL,
            title           TEXT NOT NULL,
            original_filename TEXT,
            sha256          TEXT,
            sha1            TEXT,
            md5             TEXT,
            mime_type       TEXT,
            size_bytes      INTEGER,
            extension       TEXT,
            content_text    TEXT,
            source          TEXT NOT NULL DEFAULT 'Analyst Input',
            acquired_at     TEXT NOT NULL,
            stored_path     TEXT,
            integrity_state TEXT NOT NULL DEFAULT 'VERIFIED',
            notes           TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_case   ON evidence(case_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
        CREATE INDEX IF NOT EXISTS idx_evidence_type   ON evidence(evidence_type);

        -- ---------- chain of custody (Section 22) ----------
        CREATE TABLE IF NOT EXISTS chain_of_custody (
            event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id  INTEGER NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            action       TEXT NOT NULL,
            actor        TEXT NOT NULL,
            details      TEXT,
            prev_hash    TEXT,
            entry_hash   TEXT NOT NULL,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody(evidence_id, created_at);

        -- ---------- analyses & findings ----------
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_ref  TEXT NOT NULL UNIQUE,
            case_id       INTEGER REFERENCES cases(case_id) ON DELETE SET NULL,
            evidence_id   INTEGER REFERENCES evidence(evidence_id) ON DELETE SET NULL,
            analysis_type TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'COMPLETE',
            verdict       TEXT,
            risk_score    REAL,
            confidence    REAL,
            source        TEXT NOT NULL,
            engine_version TEXT,
            payload_json  TEXT,
            created_at    TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_analyses_case    ON analyses(case_id);
        CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);

        CREATE TABLE IF NOT EXISTS analysis_findings (
            finding_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id  INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
            finding_type TEXT NOT NULL,
            severity     TEXT NOT NULL,
            title        TEXT NOT NULL,
            detail       TEXT,
            evidence_ref TEXT,
            source       TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_analysis ON analysis_findings(analysis_id);

        -- ---------- intelligence (Sections 26, 46) ----------
        CREATE TABLE IF NOT EXISTS iocs (
            ioc_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type     TEXT NOT NULL,
            value        TEXT NOT NULL,
            severity     TEXT NOT NULL DEFAULT 'UNKNOWN',
            source       TEXT NOT NULL,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            UNIQUE (ioc_type, value)
        );

        CREATE INDEX IF NOT EXISTS idx_iocs_value  ON iocs(value);
        CREATE INDEX IF NOT EXISTS idx_iocs_sev    ON iocs(severity);

        CREATE TABLE IF NOT EXISTS case_iocs (
            case_id INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            ioc_id  INTEGER NOT NULL REFERENCES iocs(ioc_id) ON DELETE CASCADE,
            PRIMARY KEY (case_id, ioc_id)
        );

        CREATE TABLE IF NOT EXISTS entities (
            entity_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type  TEXT NOT NULL,
            value        TEXT NOT NULL,
            UNIQUE (entity_type, value)
        );

        CREATE TABLE IF NOT EXISTS case_entities (
            case_id   INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            entity_id INTEGER NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
            PRIMARY KEY (case_id, entity_id)
        );

        -- ---------- timeline (Section 24) ----------
        CREATE TABLE IF NOT EXISTS timeline_events (
            event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     INTEGER REFERENCES cases(case_id) ON DELETE CASCADE,
            event_type  TEXT NOT NULL,
            title       TEXT NOT NULL,
            detail      TEXT,
            actor       TEXT,
            source      TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline_events(case_id, occurred_at);

        -- ---------- notes (Section 67) ----------
        CREATE TABLE IF NOT EXISTS notes (
            note_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    INTEGER REFERENCES cases(case_id) ON DELETE CASCADE,
            author     TEXT NOT NULL,
            body       TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id, created_at DESC);

        -- ---------- reports (Section 42) ----------
        CREATE TABLE IF NOT EXISTS reports (
            report_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            report_ref  TEXT NOT NULL UNIQUE,
            case_id     INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            title       TEXT NOT NULL,
            format      TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'GENERATED',
            storage_path TEXT,
            created_by  TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id);

        -- ---------- audit log (Section 44) ----------
        CREATE TABLE IF NOT EXISTS audit_logs (
            audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT NOT NULL,
            actor       TEXT NOT NULL,
            action      TEXT NOT NULL,
            target_type TEXT,
            target_ref  TEXT,
            detail      TEXT,
            ip_address  TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_logs(action);
        CREATE INDEX IF NOT EXISTS idx_audit_target   ON audit_logs(target_type, target_ref);

        -- ---------- alerts (Section 52) ----------
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            severity     TEXT NOT NULL,
            title        TEXT NOT NULL,
            message      TEXT NOT NULL,
            error_code   TEXT,
            source       TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
    """),
    (2, "ioc status workflow", """
        -- Section 26: each IOC carries an analyst-managed STATUS
        -- (OBSERVED / VERIFIED / FALSE_POSITIVE). Auto-detected IOCs start
        -- OBSERVED; VIRUSTOTAL/analyst actions may promote or demote them.
        ALTER TABLE iocs ADD COLUMN status TEXT NOT NULL DEFAULT 'OBSERVED';

        CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status);
    """),
    (3, "case risk snapshot (central risk engine), Section AZ", """
        ALTER TABLE cases ADD COLUMN risk_score REAL;
        ALTER TABLE cases ADD COLUMN risk_assessed_at TEXT;
        CREATE INDEX IF NOT EXISTS idx_cases_risk ON cases(risk_level);
    """),
    (4, "export packages (reporting / export center), Sections 70/BG", """
        CREATE TABLE IF NOT EXISTS export_packages (
            export_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            export_ref   TEXT NOT NULL UNIQUE,
            case_id      INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            report_ref   TEXT,
            storage_path TEXT NOT NULL,
            sha256       TEXT,
            item_count   INTEGER NOT NULL DEFAULT 0,
            created_by   TEXT,
            created_at   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_exports_case ON export_packages(case_id);
        CREATE INDEX IF NOT EXISTS idx_exports_created ON export_packages(created_at DESC);
    """),
    (5, "dataset/model registries (BD/BE) + lab settings store", """
        CREATE TABLE IF NOT EXISTS dataset_registry (
            dataset_id             TEXT PRIMARY KEY,
            name                   TEXT NOT NULL,
            source                 TEXT,
            license                TEXT,
            version                TEXT,
            download_date          TEXT,
            row_count              INTEGER,
            columns_json           TEXT,
            labels_json            TEXT,
            class_distribution_json TEXT,
            duplicates             INTEGER,
            missing_values         INTEGER,
            training_usage         TEXT,
            model_usage            TEXT,
            registered_at          TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS model_registry (
            model_id               TEXT PRIMARY KEY,
            name                   TEXT NOT NULL,
            path                   TEXT NOT NULL,
            kind                   TEXT,
            dataset_id             TEXT REFERENCES dataset_registry(dataset_id),
            dataset_version        TEXT,
            training_date          TEXT,
            features               TEXT,
            accuracy               REAL,
            precision              REAL,
            recall                 REAL,
            f1                     REAL,
            roc_auc                REAL,
            false_positive_rate    REAL,
            false_negative_rate    REAL,
            confusion_matrix_json  TEXT,
            registered_at          TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_models_dataset ON model_registry(dataset_id);
        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT 'analyst'
        );
    """),
]

# Constraint / enum documentation (enforced at service layer, verified by tests).
CASE_TYPES = [
    "PHISHING", "MALWARE", "FINANCIAL FRAUD", "ACCOUNT TAKEOVER", "BEC",
    "SCAM", "MALICIOUS WEBSITE", "SUSPICIOUS EMAIL", "CREDENTIAL THEFT",
    "QR PHISHING", "OTHER",
]
CASE_STATUSES = ["OPEN", "UNDER INVESTIGATION", "REVIEW", "RESOLVED", "ARCHIVED"]
CASE_PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

VALID_TRANSITIONS = {
    "OPEN": ["UNDER INVESTIGATION", "REVIEW", "ARCHIVED"],
    "UNDER INVESTIGATION": ["REVIEW", "RESOLVED", "OPEN"],
    "REVIEW": ["UNDER INVESTIGATION", "RESOLVED", "ARCHIVED"],
    "RESOLVED": ["UNDER INVESTIGATION", "ARCHIVED"],
    "ARCHIVED": ["OPEN"],
}


def current_version():
    """Highest applied migration version, or 0 when the DB is uninitialised."""
    try:
        row = query_one("SELECT MAX(version) AS v FROM schema_migrations")
    except Exception:
        return 0
    if not row:
        return 0
    return row.get("v") or 0


def migrate(verbose=False):
    """Apply pending migrations inside a lock. Returns applied versions."""
    applied = []
    with _lock:
        conn = _connect()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, description TEXT NOT NULL, "
            "applied_at TEXT NOT NULL)")
        conn.commit()

        cur = conn.execute("SELECT version FROM schema_migrations")
        done = {r[0] for r in cur.fetchall()}

        for version, description, sql in MIGRATIONS:
            if version in done:
                continue
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations(version, description, applied_at) "
                "VALUES (?, ?, ?)",
                (version, description, utcnow()))
            conn.commit()
            applied.append(version)
            if verbose:
                print("[lab] migration %d applied: %s" % (version, description))
    return applied


def integrity_check():
    """Real PRAGMA integrity_check — used by the health service."""
    try:
        row = query_one("PRAGMA integrity_check")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    value = None
    if row:
        value = list(row.values())[0] if row else None
    return {"ok": value == "ok", "result": value}


def table_counts():
    """Real row counts for the tables that exist."""
    counts = {}
    conn = _connect()
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [r[0] for r in cur.fetchall()]
    for t in tables:
        try:
            cur = conn.execute("SELECT count(*) FROM %s" % t)
            counts[t] = cur.fetchone()[0]
        except Exception:
            counts[t] = None
    return counts


def health_check():
    """Section 51 database health: status, latency, last check, error state."""
    import time
    started = time.perf_counter()
    if not os.path.exists(DB_PATH):
        return {
            "status": "NOT CONFIGURED", "status_key": "unconfigured",
            "latency_ms": None, "error": None,
            "detail": "No database file present.",
            "path": os.path.basename(DB_PATH),
        }
    try:
        row = query_one("SELECT count(*) AS n FROM schema_migrations")
        version = row["n"] if row else 0
        integrity = integrity_check()
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "SERVICE UNAVAILABLE", "status_key": "unavailable",
            "latency_ms": round(elapsed, 2), "error": "DB_QUERY_FAILED",
            "detail": "Database read failed: %s" % type(exc).__name__,
            "path": os.path.basename(DB_PATH),
        }
    elapsed = (time.perf_counter() - started) * 1000.0
    if not integrity.get("ok"):
        return {
            "status": "SERVICE UNAVAILABLE", "status_key": "unavailable",
            "latency_ms": round(elapsed, 2), "error": "DB_INTEGRITY_FAILED",
            "detail": "PRAGMA integrity_check reported: %s" % integrity.get("result"),
            "path": os.path.basename(DB_PATH),
        }
    return {
        "status": "OPERATIONAL", "status_key": "operational",
        "latency_ms": round(elapsed, 2), "error": None,
        "detail": "Read query + integrity check succeeded.",
        "path": os.path.basename(DB_PATH),
        "schema_version": version,
        "integrity": integrity.get("result"),
    }


def bootstrap():
    """Create/migrate the database if needed. Safe to call repeatedly."""
    migrate()
    # Seed RBAC roles/permissions/matrix into the schema-v1 tables (BI).
    # Deferred import avoids the db -> security module cycle.
    from lab import security
    security.seed_rbac()
    # Register on-disk datasets + models (BD/BE). Deferred for the same
    # reason; each scan is idempotent and skips missing files.
    from lab import registry_service
    registry_service.seed_registries()
