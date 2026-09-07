"""
SQLite database layer for CyberTrace-Lite.
Defines the schema (users, events, risk_scores, alerts, auth_users,
audit_log) and helper functions used by the pipeline (to persist
results) and the Flask app (to read data for the dashboard).
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "cybertrace.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    first_seen TEXT,
    last_seen TEXT,
    total_events INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT,
    event_type TEXT,
    login_status TEXT,
    resource TEXT,
    download_count INTEGER DEFAULT 0,
    session_duration_min REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    failed_logins INTEGER DEFAULT 0,
    unusual_time_events INTEGER DEFAULT 0,
    distinct_ip_count INTEGER DEFAULT 0,
    resource_access_count INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    rapid_event_count INTEGER DEFAULT 0,
    sensitive_resource_count INTEGER DEFAULT 0,
    concurrent_ip_overlap INTEGER DEFAULT 0,
    rule_score INTEGER DEFAULT 0,
    rule_triggers TEXT,
    anomaly_score REAL DEFAULT 0,
    is_anomaly INTEGER DEFAULT 0,
    final_score REAL DEFAULT 0,
    classification TEXT,
    shap_explanation TEXT,
    UNIQUE(username, date)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    alert_type TEXT,
    message TEXT,
    severity TEXT,
    notified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Dashboard login accounts. Deliberately a separate table from `users`
-- (the monitored population) so a pipeline `reset_db()` never touches
-- login credentials.
CREATE TABLE IF NOT EXISTS auth_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Security/administrative audit trail. Also never wiped by reset_db().
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Tracks which (username, date, alert_type) incidents already triggered an
-- email/webhook notification. `alerts` itself is rebuilt from scratch on
-- every pipeline run (reset_db), so this survives independently to stop
-- the same incident from re-notifying on every "Regenerate" click.
CREATE TABLE IF NOT EXISTS notified_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    notified_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, date, alert_type)
);

CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_risk_username ON risk_scores(username);
CREATE INDEX IF NOT EXISTS idx_alerts_date ON alerts(date);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
"""


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _column_names(conn, table: str) -> set:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn):
    """Lightweight additive migration for tables that persist across
    resets (auth_users, alerts) so existing databases from earlier runs
    of this project pick up new columns without losing data."""
    auth_cols = _column_names(conn, "auth_users")
    if "role" not in auth_cols:
        conn.execute("ALTER TABLE auth_users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'")
        conn.execute("UPDATE auth_users SET role = 'admin' WHERE username = 'admin'")

    alert_cols = _column_names(conn, "alerts")
    if "notified" not in alert_cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN notified INTEGER DEFAULT 0")

    risk_cols = _column_names(conn, "risk_scores")
    for col in ("sensitive_resource_count", "concurrent_ip_overlap"):
        if col not in risk_cols:
            conn.execute(f"ALTER TABLE risk_scores ADD COLUMN {col} INTEGER DEFAULT 0")
    if "shap_explanation" not in risk_cols:
        conn.execute("ALTER TABLE risk_scores ADD COLUMN shap_explanation TEXT")

    conn.commit()


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate(conn)
    conn.close()


def seed_default_admin(default_username: str = "admin", default_password: str = "admin123"):
    """Create a default dashboard login account (role=admin) the first
    time the app runs, if no login accounts exist yet. Change this
    password with:
        python manage_users.py reset-password admin <new_password>
    """
    from werkzeug.security import generate_password_hash

    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) AS c FROM auth_users").fetchone()["c"]
    if count == 0:
        conn.execute(
            "INSERT INTO auth_users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (default_username, generate_password_hash(default_password)),
        )
        conn.commit()
    conn.close()


def get_user_role(username: str):
    conn = get_connection()
    row = conn.execute("SELECT role FROM auth_users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row["role"] if row else None


def log_audit(username: str, action: str, detail: str = ""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (username, action, detail) VALUES (?, ?, ?)",
        (username, action, detail),
    )
    conn.commit()
    conn.close()


def reset_db():
    """Drop and recreate the monitored-data tables - used before each
    pipeline run so the dashboard always reflects the latest generated
    dataset. Login accounts (auth_users) and the audit trail
    (audit_log) are intentionally left untouched."""
    conn = get_connection()
    conn.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS events;
        DROP TABLE IF EXISTS risk_scores;
        DROP TABLE IF EXISTS alerts;
    """)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
