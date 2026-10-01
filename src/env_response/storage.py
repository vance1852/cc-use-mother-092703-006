"""环境事件响应服务的 SQLite 模式和事务辅助。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS env_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('duty','field','dispatcher','remediation','reviewer','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    contaminant TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'watch' CHECK(severity IN ('watch','elevated','serious')),
    state TEXT NOT NULL DEFAULT 'open'
        CHECK(state IN ('open','contained','remediating','review_pending','reopened','closed')),
    current_zones_json TEXT NOT NULL DEFAULT '[]',
    current_revision INTEGER NOT NULL DEFAULT 0,
    latest_assessment_id INTEGER,
    created_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state);

-- 证据：监测告警、现场复测、第三方分析、设备校准等。source_ref 在事件内唯一，
-- 并发重复提交依靠 UNIQUE(incident_id, source_ref) 去重。
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    source_ref TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('monitor_alert','field_retest','third_party','calibration','manual')),
    origin TEXT NOT NULL,
    reading_json TEXT NOT NULL,
    observed_zones_json TEXT NOT NULL,
    finding TEXT NOT NULL DEFAULT 'positive' CHECK(finding IN ('positive','cleared')),
    disputes_json TEXT NOT NULL DEFAULT '[]',
    note TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
    recorded_by TEXT NOT NULL REFERENCES env_users(user_id),
    recorded_at TEXT NOT NULL,
    UNIQUE(incident_id, source_ref)
);

CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id, evidence_id);

-- 现场记录：按来源编号去重，同一 source_ref 只接受第一次提交。
CREATE TABLE IF NOT EXISTS field_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    source_ref TEXT NOT NULL,
    evidence_id INTEGER REFERENCES evidence(evidence_id),
    zone_code TEXT NOT NULL,
    reading TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    submitted_by TEXT NOT NULL REFERENCES env_users(user_id),
    submitted_at TEXT NOT NULL,
    deduped INTEGER NOT NULL DEFAULT 0,
    UNIQUE(incident_id, source_ref)
);

CREATE INDEX IF NOT EXISTS idx_field_records_pending
ON field_records(incident_id, evidence_id);

-- 带证据版本的事件判断；每次新增证据产生一个版本，并解释影响区域的变化理由。
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision INTEGER NOT NULL,
    evidence_id INTEGER NOT NULL REFERENCES evidence(evidence_id),
    result TEXT NOT NULL CHECK(result IN ('confirmed','downgraded','dismissed')),
    zones_json TEXT NOT NULL,
    added_zones_json TEXT NOT NULL,
    removed_zones_json TEXT NOT NULL,
    change_reason TEXT NOT NULL,
    basis_json TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, revision)
);

-- 管控措施：区域隔离与资源调度；版本随判断推进，扩区自动覆盖新区域。
CREATE TABLE IF NOT EXISTS measures (
    measure_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    kind TEXT NOT NULL CHECK(kind IN ('zone_isolation','resource_dispatch')),
    title TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    zones_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active'
        CHECK(state IN ('active','lifted','cancelled')),
    revision INTEGER NOT NULL DEFAULT 1,
    owner_id TEXT NOT NULL REFERENCES env_users(user_id),
    due_at TEXT,
    lifted_at TEXT,
    created_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_measures_active
ON measures(incident_id, state, due_at);

-- 修复任务；全部完成不代表自动解除管控。
CREATE TABLE IF NOT EXISTS remediation_tasks (
    task_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    zone_code TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','in_progress','done','verified','cancelled')),
    assignee_id TEXT NOT NULL REFERENCES env_users(user_id),
    due_at TEXT,
    completed_at TEXT,
    completed_by TEXT REFERENCES env_users(user_id),
    revision INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL REFERENCES env_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_incident ON remediation_tasks(incident_id, state, due_at);

-- 解除管控申请与授权复核。
CREATE TABLE IF NOT EXISTS closure_reviews (
    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    request_note TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES env_users(user_id),
    requested_at TEXT NOT NULL,
    verdict TEXT,
    review_note TEXT NOT NULL DEFAULT '',
    reviewer_id TEXT REFERENCES env_users(user_id),
    reviewed_at TEXT,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','rejected'))
);

CREATE INDEX IF NOT EXISTS idx_reviews_incident ON closure_reviews(incident_id, review_id);

CREATE TABLE IF NOT EXISTS env_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
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


def connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(path), isolation_level=None, timeout=10, check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    initialize(connection)
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


@contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()
