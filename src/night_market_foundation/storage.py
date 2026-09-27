"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_reports (
    report_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    zone TEXT NOT NULL,
    category TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    location TEXT NOT NULL,
    public_summary TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    sensitive_json TEXT NOT NULL,
    reporter_id TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    zone TEXT NOT NULL,
    category TEXT NOT NULL,
    level INTEGER NOT NULL CHECK(level >= 1),
    status TEXT NOT NULL CHECK(status IN ('open', 'closed')),
    public_summary TEXT NOT NULL,
    commander_id TEXT NOT NULL REFERENCES actors(actor_id),
    opened_from_report_id TEXT NOT NULL REFERENCES incident_reports(report_id),
    created_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS incident_report_links (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    report_id TEXT NOT NULL REFERENCES incident_reports(report_id),
    link_type TEXT NOT NULL CHECK(link_type IN ('origin', 'merged', 'supplementary')),
    linked_by TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, report_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS incident_report_links_one_incident
    ON incident_report_links(report_id);
CREATE TABLE IF NOT EXISTS merge_candidates (
    candidate_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    report_id TEXT NOT NULL REFERENCES incident_reports(report_id),
    rule TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'confirmed', 'rejected')),
    proposed_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    UNIQUE(incident_id, report_id)
);
CREATE TABLE IF NOT EXISTS escalations (
    escalation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    from_level INTEGER NOT NULL,
    to_level INTEGER NOT NULL,
    fact_refs_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actor_qualifications (
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    qualification TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (actor_id, qualification)
);
CREATE TABLE IF NOT EXISTS support_requests (
    support_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    assignee_id TEXT NOT NULL REFERENCES actors(actor_id),
    required_qualifications_json TEXT NOT NULL,
    responsibility_snapshot_json TEXT NOT NULL,
    note TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open', 'acknowledged', 'completed', 'cancelled')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_actions (
    action_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    title TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES actors(actor_id),
    status TEXT NOT NULL CHECK(status IN ('pending', 'in_progress', 'done', 'cancelled')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS handovers (
    handover_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    from_commander_id TEXT NOT NULL,
    to_commander_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'expired', 'cancelled')),
    initiated_by TEXT NOT NULL,
    initiated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS handovers_one_pending
    ON handovers(incident_id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS closures (
    closure_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    status TEXT NOT NULL CHECK(status IN ('pending', 'confirmed', 'rejected')),
    proposed_by TEXT NOT NULL,
    proposed_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS closures_one_pending
    ON closures(incident_id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS reopen_requests (
    reopen_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    report_id TEXT NOT NULL REFERENCES incident_reports(report_id),
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS reopen_requests_one_pending
    ON reopen_requests(incident_id) WHERE status='pending';
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
