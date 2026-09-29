"""环境事件响应服务的 SQLite 模式和事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS env_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('duty','commander','reviewer','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zones (
    zone_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    zone_type TEXT NOT NULL,
    business TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    signal_source TEXT NOT NULL,
    signal_detail_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'monitoring'
        CHECK (state IN ('monitoring','controlling','recovering','released','closed')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    current_assessment_id INTEGER,
    created_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    source_id TEXT NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('field_retest','third_party','calibration','other')),
    title TEXT NOT NULL,
    affected_zone_ids_json TEXT NOT NULL,
    cleared_zone_ids_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL CHECK (severity IN ('watch','minor','major','critical')),
    detail_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    submitted_by TEXT NOT NULL REFERENCES env_users(user_id),
    submitted_at TEXT NOT NULL,
    UNIQUE (incident_id, source_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_incident
ON evidence(incident_id, evidence_id);

CREATE TABLE IF NOT EXISTS assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    basis_evidence_ids_json TEXT NOT NULL,
    affected_zone_ids_json TEXT NOT NULL,
    severity TEXT NOT NULL,
    containment_level TEXT NOT NULL,
    change_direction TEXT NOT NULL
        CHECK (change_direction IN ('initial','expanded','narrowed','unchanged')),
    change_reason TEXT NOT NULL,
    change_added_json TEXT NOT NULL,
    change_removed_json TEXT NOT NULL,
    evidence_set_sha256 TEXT NOT NULL CHECK (length(evidence_set_sha256) = 64),
    decided_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (incident_id, revision)
);

CREATE TABLE IF NOT EXISTS measures (
    measure_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    measure_type TEXT NOT NULL CHECK (measure_type IN ('isolation','dispatch','repair')),
    title TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('pending','in_progress','completed','cancelled')),
    responsible_id TEXT NOT NULL REFERENCES env_users(user_id),
    due_at TEXT,
    completed_at TEXT,
    result_note TEXT,
    supersedes_measure_id INTEGER REFERENCES measures(measure_id),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_measures_incident_status
ON measures(incident_id, status, measure_id);

CREATE TABLE IF NOT EXISTS measure_zone_links (
    measure_id INTEGER NOT NULL REFERENCES measures(measure_id),
    zone_id TEXT NOT NULL REFERENCES zones(zone_id),
    PRIMARY KEY (measure_id, zone_id)
);

CREATE TABLE IF NOT EXISTS release_reviews (
    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    incident_revision INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
    note TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES env_users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES env_users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_reviews_incident
ON release_reviews(incident_id, review_id);

CREATE TABLE IF NOT EXISTS env_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_env_audit_entity
ON env_audit_events(entity_type, entity_id, event_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "env_users", "zones", "incidents", "evidence", "assessments",
    "measures", "measure_zone_links", "release_reviews", "env_audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用外键、WAL 与忙等待。"""

    connection = sqlite3.connect(str(path), isolation_level=None, timeout=10, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    initialize(connection)
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化全部表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
