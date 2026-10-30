import sqlite3
import json
from contextlib import contextmanager
from pathlib import Path


DEFAULT_RULES = [
    ("auth_failure", "Authentication failure", "A failed or denied authentication event.", "Low"),
    ("brute_force", "Repeated authentication failures", "Five failures from a source/account in ten minutes.", "High"),
    ("password_guessing", "Password guessing pattern", "Five failures against at least three accounts in ten minutes.", "High"),
    ("success_after_failures", "Successful login after failures", "A success follows three failures for one account/source.", "High"),
    ("privilege_change", "Privileged account activity", "An event explicitly records privilege elevation.", "High"),
    ("port_scan", "Port/service scan", "An event explicitly identifies scanning or service probing.", "Medium"),
    ("suspicious_port", "Configured sensitive service activity", "A configured service port occurs with a suspicious context.", "Medium"),
    ("denied_connections", "Repeated denied connections", "Five denied connections to one destination/service in ten minutes.", "Medium"),
    ("high_volume", "High-volume event anomaly", "One hundred events from a source in five minutes.", "Medium"),
    ("suspicious_egress", "Suspicious outbound activity", "An event explicitly indicates suspicious outbound traffic.", "Medium"),
    ("malware_indicator", "Malware indicator", "The event explicitly identifies a malware-related indicator.", "Critical"),
    ("suspicious_combination", "Multi-stage suspicious activity", "Malware and egress indicators correlate within thirty minutes.", "High"),
]


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid TEXT,
    fingerprint TEXT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL DEFAULT '',
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    source_file TEXT NOT NULL,
    is_synthetic INTEGER NOT NULL DEFAULT 0,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_uid TEXT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    confidence REAL NOT NULL DEFAULT 0.5,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('New','Open','Investigating','Contained','Resolved','Closed')),
    source_ip TEXT NOT NULL DEFAULT '',
    assigned_analyst TEXT NOT NULL DEFAULT '',
    first_observed TEXT,
    last_observed TEXT,
    resolution_summary TEXT NOT NULL DEFAULT '',
    severity_rationale TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence TEXT NOT NULL,
    event_ids TEXT NOT NULL DEFAULT '[]',
    matching_conditions TEXT NOT NULL DEFAULT '{}',
    rationale TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New','Acknowledged','Investigating','Resolved')),
    fingerprint TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(event_id, rule_id)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author TEXT NOT NULL DEFAULT 'Local analyst',
    text TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS incident_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    actor TEXT NOT NULL DEFAULT 'Local analyst',
    field TEXT NOT NULL,
    old_value TEXT NOT NULL,
    new_value TEXT NOT NULL,
    rationale TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS analysis_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_uid TEXT NOT NULL UNIQUE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS agent_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS generated_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_uid TEXT NOT NULL UNIQUE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    configuration TEXT NOT NULL DEFAULT '{}'
);
"""

MIGRATION_COLUMNS = {
    "events": {
        "event_uid": "TEXT",
        "fingerprint": "TEXT",
        "source_port": "INTEGER",
        "dest_port": "INTEGER",
        "protocol": "TEXT NOT NULL DEFAULT ''",
        "hostname": "TEXT NOT NULL DEFAULT ''",
        "result": "TEXT NOT NULL DEFAULT ''",
        "message": "TEXT NOT NULL DEFAULT ''",
        "is_synthetic": "INTEGER NOT NULL DEFAULT 0",
        "ingested_at": "TEXT",
    },
    "incidents": {
        "incident_uid": "TEXT",
        "confidence": "REAL NOT NULL DEFAULT 0.5",
        "assigned_analyst": "TEXT NOT NULL DEFAULT ''",
        "first_observed": "TEXT",
        "last_observed": "TEXT",
        "resolution_summary": "TEXT NOT NULL DEFAULT ''",
        "severity_rationale": "TEXT NOT NULL DEFAULT ''",
    },
    "alerts": {
        "confidence": "REAL NOT NULL DEFAULT 0.5",
        "event_ids": "TEXT NOT NULL DEFAULT '[]'",
        "matching_conditions": "TEXT NOT NULL DEFAULT '{}'",
        "rationale": "TEXT NOT NULL DEFAULT ''",
        "status": "TEXT NOT NULL DEFAULT 'New'",
        "fingerprint": "TEXT",
    },
    "notes": {"author": "TEXT NOT NULL DEFAULT 'Local analyst'"},
}


@contextmanager
def connect(database):
    connection = sqlite3.connect(database, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _columns(connection, table):
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def init_db(database):
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout = 15000")
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.executescript(SCHEMA.replace("PRAGMA foreign_keys = ON;", ""))
        for table, columns in MIGRATION_COLUMNS.items():
            current = _columns(connection, table)
            for name, definition in columns.items():
                if name not in current:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        event_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone()["sql"]
        if "UNIQUE(fingerprint)" in event_schema.replace(" ", ""):
            connection.execute(
                """CREATE TABLE events_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_uid TEXT, fingerprint TEXT,
                    timestamp TEXT NOT NULL, source_ip TEXT NOT NULL, dest_ip TEXT NOT NULL DEFAULT '',
                    source_port INTEGER, dest_port INTEGER, protocol TEXT NOT NULL DEFAULT '',
                    event_type TEXT NOT NULL, username TEXT NOT NULL DEFAULT '',
                    hostname TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
                    result TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '',
                    raw_json TEXT NOT NULL, source_file TEXT NOT NULL, is_synthetic INTEGER NOT NULL DEFAULT 0,
                    ingested_at TEXT NOT NULL, created_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """INSERT INTO events_v2 SELECT id,event_uid,fingerprint,timestamp,source_ip,dest_ip,
                   source_port,dest_port,protocol,event_type,username,hostname,action,result,message,
                   raw_json,source_file,is_synthetic,COALESCE(ingested_at,created_at),created_at FROM events"""
            )
            connection.execute("DROP TABLE events")
            connection.execute("ALTER TABLE events_v2 RENAME TO events")
        incident_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
        ).fetchone()["sql"]
        if "'Contained'" not in incident_schema or "'New'" not in incident_schema:
            connection.execute(
                """CREATE TABLE incidents_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_uid TEXT, title TEXT NOT NULL, summary TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
                    confidence REAL NOT NULL DEFAULT 0.5,
                    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('New','Open','Investigating','Contained','Resolved','Closed')),
                    source_ip TEXT NOT NULL DEFAULT '', assigned_analyst TEXT NOT NULL DEFAULT '',
                    first_observed TEXT, last_observed TEXT,
                    resolution_summary TEXT NOT NULL DEFAULT '', severity_rationale TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                )"""
            )
            columns = _columns(connection, "incidents")
            fields = ["id", "title", "summary", "severity", "status", "source_ip", "created_at", "updated_at"]
            fields += [name for name in ("incident_uid", "confidence", "assigned_analyst", "first_observed",
                                         "last_observed", "resolution_summary", "severity_rationale") if name in columns]
            select = ", ".join(fields)
            connection.execute(f"INSERT INTO incidents_v2 ({select}) SELECT {select} FROM incidents")
            connection.execute("DROP TABLE incidents")
            connection.execute("ALTER TABLE incidents_v2 RENAME TO incidents")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id)")
        connection.execute(
            "UPDATE events SET ingested_at = created_at WHERE ingested_at IS NULL"
        )
        connection.execute(
            "UPDATE incidents SET incident_uid = 'SWX-LEGACY-' || printf('%06d', id) WHERE incident_uid IS NULL"
        )
        for rule_id, name, description, severity in DEFAULT_RULES:
            connection.execute(
                """INSERT OR IGNORE INTO detection_rules(rule_id,name,description,severity,enabled,configuration)
                   VALUES(?,?,?,?,1,?)""",
                (rule_id, name, description, severity,
                 json.dumps({"source": "bundled-default", "version": 1})),
            )
        default_settings = {
            "max_events_per_import": "10000",
            "deduplicate_events": "true",
            "dashboard_refresh_seconds": "30",
            "analysis_mode": "local-deterministic",
        }
        for key, value in default_settings.items():
            connection.execute("INSERT OR IGNORE INTO app_settings(key,value) VALUES(?,?)", (key, value))
        connection.commit()
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError("Database migration found inconsistent references.")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
