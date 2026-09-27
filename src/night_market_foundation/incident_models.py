"""跨专区事件指挥模块在边界使用的只读数据对象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Report:
    """志愿者或一线人员提交的原始报告，独立存档、永不覆盖。"""

    report_id: str
    incident_id: str | None  # 确认合并后填入；未合并时为 None，但始终可单独追查
    site_id: str
    occurred_at: str
    location_text: str
    public_summary: str
    evidence_fingerprint: str
    health_info: str
    contact_info: str
    reporter_id: str
    received_at: str
    is_late: bool


@dataclass(frozen=True)
class MergeCandidate:
    """关联规则提出的合并候选；只有指挥确认才真正组成共同事件。"""

    candidate_id: str
    source_report_id: str
    target_report_id: str
    rule_name: str
    score: int
    status: str
    proposed_by: str
    decided_by: str | None
    incident_id: str | None
    rationale: str


@dataclass(frozen=True)
class Incident:
    """经值班指挥确认组成的共同事件。"""

    incident_id: str
    site_id: str
    level: str
    status: str
    public_status: str
    current_commander_id: str
    commander_since: str
    commander_until: str | None
    created_by: str
    created_at: str
    version: int


@dataclass(frozen=True)
class Escalation:
    """一次等级升级，必须引用新的现场事实（报告或行动结果）。"""

    escalation_id: str
    incident_id: str
    from_level: str
    to_level: str
    fact_report_ids: tuple[str, ...]
    fact_action_ids: tuple[str, ...]
    reason: str
    requested_by: str
    decided_by: str
    created_at: str


@dataclass(frozen=True)
class ActionItem:
    """事件下的行动项。任何时刻都有明确责任人，持久化以防悬空。"""

    action_id: str
    incident_id: str
    title: str
    status: str
    owner_id: str
    created_by: str
    created_at: str
    closed_at: str | None


@dataclass(frozen=True)
class SupportRequest:
    """跨专区调援请求；创建时冻结责任清单并核验被调人员资格。"""

    support_id: str
    incident_id: str
    requesting_commander_id: str
    responder_id: str
    responder_role: str
    qualification_code: str
    status: str
    responsibility_snapshot: tuple[str, ...]
    frozen_at: str
    created_at: str


@dataclass(frozen=True)
class Handover:
    """有期限的指挥权交接。"""

    handover_id: str
    incident_id: str
    from_commander_id: str
    to_commander_id: str
    status: str
    valid_from: str
    valid_until: str
    completed_at: str | None
    reason: str


@dataclass(frozen=True)
class Closure:
    """结案申请与另一名复核者的确认。"""

    closure_id: str
    incident_id: str
    requested_by: str
    reviewed_by: str | None
    status: str
    note: str
    created_at: str
    decided_at: str | None


@dataclass(frozen=True)
class ReopenApplication:
    """结案后迟到报告发起的复开申请。"""

    application_id: str
    incident_id: str
    report_id: str
    requested_by: str
    status: str
    decided_by: str | None
    reason: str
    created_at: str
    decided_at: str | None


@dataclass(frozen=True)
class CausalLink:
    """审计链的一个环节，用于从接口还原业务因果。"""

    sequence: int
    action: str
    resource_type: str
    resource_id: str
    occurred_at: str
    detail: dict[str, Any] = field(default_factory=dict)
