"""跨专区事件指挥模块的 SQLite 表结构。

事件模块复用基础模块的 organizations/actors/sites 与审计链、幂等回执表，
不修改基础表语义；本结构只新增事件指挥所需的表，并在服务初始化时幂等执行。
"""

from __future__ import annotations

INCIDENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    incident_id TEXT,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    occurred_at TEXT NOT NULL,
    location_text TEXT NOT NULL,
    public_summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    health_info TEXT NOT NULL DEFAULT '',
    contact_info TEXT NOT NULL DEFAULT '',
    reporter_id TEXT NOT NULL REFERENCES actors(actor_id),
    received_at TEXT NOT NULL,
    is_late INTEGER NOT NULL DEFAULT 0 CHECK(is_late IN (0, 1)),
    late_kind TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_site ON reports(site_id, received_at);
CREATE INDEX IF NOT EXISTS idx_reports_incident ON reports(incident_id);

CREATE TABLE IF NOT EXISTS merge_candidates (
    candidate_id TEXT PRIMARY KEY,
    source_report_id TEXT NOT NULL REFERENCES reports(report_id),
    target_report_id TEXT NOT NULL REFERENCES reports(report_id),
    rule_name TEXT NOT NULL,
    score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
    status TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    decided_by TEXT,
    incident_id TEXT REFERENCES incidents(incident_id),
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    UNIQUE(source_report_id, target_report_id)
);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON merge_candidates(status);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    level TEXT NOT NULL,
    status TEXT NOT NULL,
    public_status TEXT NOT NULL,
    current_commander_id TEXT NOT NULL REFERENCES actors(actor_id),
    commander_since TEXT NOT NULL,
    commander_until TEXT,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    closed_at TEXT,
    version INTEGER NOT NULL CHECK(version >= 1)
);

CREATE TABLE IF NOT EXISTS escalations (
    escalation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    from_level TEXT NOT NULL,
    to_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    fact_report_ids_json TEXT NOT NULL,
    fact_action_ids_json TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES actors(actor_id),
    decided_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL
);

-- 已被引用过的现场事实：同一事件内同一事实只能支撑一次升级
CREATE TABLE IF NOT EXISTS incident_used_facts (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    fact_kind TEXT NOT NULL CHECK(fact_kind IN ('report', 'action')),
    fact_id TEXT NOT NULL,
    used_in TEXT NOT NULL,
    PRIMARY KEY(incident_id, fact_kind, fact_id)
);

CREATE TABLE IF NOT EXISTS action_items (
    action_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES actors(actor_id),
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    result_note TEXT NOT NULL DEFAULT '',
    closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON action_items(incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_owner ON action_items(owner_id, status);

CREATE TABLE IF NOT EXISTS responder_qualifications (
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    qualification_code TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    granted_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(actor_id, qualification_code)
);

CREATE TABLE IF NOT EXISTS support_requests (
    support_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    requesting_commander_id TEXT NOT NULL REFERENCES actors(actor_id),
    responder_id TEXT NOT NULL REFERENCES actors(actor_id),
    responder_role TEXT NOT NULL,
    qualification_code TEXT NOT NULL,
    status TEXT NOT NULL,
    responsibility_snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    frozen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    fulfilled_at TEXT
);

CREATE TABLE IF NOT EXISTS handovers (
    handover_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    from_commander_id TEXT NOT NULL REFERENCES actors(actor_id),
    to_commander_id TEXT NOT NULL REFERENCES actors(actor_id),
    status TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS closures (
    closure_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    requested_by TEXT NOT NULL REFERENCES actors(actor_id),
    reviewed_by TEXT REFERENCES actors(actor_id),
    status TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence_supplements (
    supplement_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    report_id TEXT NOT NULL REFERENCES reports(report_id),
    added_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reopen_applications (
    application_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    report_id TEXT NOT NULL REFERENCES reports(report_id),
    requested_by TEXT NOT NULL REFERENCES actors(actor_id),
    status TEXT NOT NULL,
    decided_by TEXT REFERENCES actors(actor_id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT
);

-- 事件与审计事件的因果链关联：业务对象可由此还原合并、升级、调援、交接、结案全过程
CREATE TABLE IF NOT EXISTS incident_audit_links (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL REFERENCES audit_events(sequence),
    PRIMARY KEY(incident_id, sequence)
);
"""


def ensure_incident_schema(connection) -> None:
    """幂等创建事件模块全部数据表。"""

    connection.executescript(INCIDENT_SCHEMA)
