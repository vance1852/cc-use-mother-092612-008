"""实现跨专区现场事件指挥模块：报告、合并、升级、调援、交接与结案。

模块建立在基础服务的稳定边界之上：
- 每份报告独立持久化，原始报告始终可单独追查；
- 关联规则只提出合并候选，是否组成共同事件由值班指挥确认；
- 升级必须引用新的现场事实；调援核验人员资格并冻结当时的责任清单；
- 指挥权以有期限的交接转移，交接完成后原指挥不得继续作决定；
- 健康信息与联系方式只向授权角色开放，对外状态隐藏非必要细节；
- 结案前必须清空未决行动并由另一名复核者确认；
- 迟到报告只能补充证据或发起复开申请；
- 所有状态持久化在 SQLite 中，应用重启后执行中的行动不会悬空。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .audit import append_event, canonical_json
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import WriteReceipt
from .service import DomainService

COMMAND_ROLES = frozenset({"admin", "operator"})
REPORT_ROLES = frozenset({"admin", "operator", "reviewer"})
REVIEW_ROLES = frozenset({"admin", "reviewer"})
SENSITIVE_ROLES = frozenset({"admin", "operator"})
REPORT_CATEGORIES = frozenset({"person_discomfort", "lost_item", "other"})
CORRELATION_WINDOW_MINUTES = 120
CORRELATION_RULE = "same_zone_same_category_within_120m"
MIN_LEVEL = 1
MAX_LEVEL = 5
RULE_ACTOR = "correlation-rule"
SYSTEM_ACTOR = "system"
OPEN_ACTION_STATUSES = ("pending", "in_progress")
OPEN_SUPPORT_STATUSES = ("open", "acknowledged")


def _iso(moment: datetime) -> str:
    """把时刻规范为秒级精度的 UTC 文本。"""

    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, field: str) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"{field} 必须是带时区的 ISO 时间") from exc
    if moment.tzinfo is None:
        raise ValidationError(f"{field} 必须包含时区")
    return moment.astimezone(timezone.utc).replace(microsecond=0)


class IncidentService:
    """在基础服务边界之上实现跨专区事件指挥的领域规则。"""

    def __init__(self, foundation: DomainService) -> None:
        self.foundation = foundation
        self.database = foundation.database

    # ---- 通用工具 ----

    def _now(self) -> datetime:
        return self.foundation.clock.now().astimezone(timezone.utc).replace(microsecond=0)

    def _actor(self, connection, actor_id: str):
        return self.foundation._actor(connection, actor_id)

    def _require_actor(self, connection, actor_id: str):
        if not actor_id:
            raise PermissionDenied("需要操作者身份")
        return self._actor(connection, actor_id)

    def _site(self, connection, site_id: str):
        row = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if row is None:
            raise NotFoundError("场所不存在")
        return row

    def _report(self, connection, report_id: str):
        row = connection.execute(
            "SELECT * FROM incident_reports WHERE report_id=?", (report_id,)).fetchone()
        if row is None:
            raise NotFoundError("报告不存在")
        return row

    def _incident(self, connection, incident_id: str):
        row = connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFoundError("事件不存在")
        return row

    def _check_org(self, actor, organization_id: str) -> None:
        if actor.role != "admin" and actor.organization_id != organization_id:
            raise PermissionDenied("不能操作其他组织的资源")

    def _require_commander(self, actor, incident) -> None:
        if actor.actor_id != incident["commander_id"]:
            raise PermissionDenied("只有现任值班指挥可以执行该动作")

    def _require_open(self, incident) -> None:
        if incident["status"] != "open":
            raise ConflictError("事件已结案，迟到报告只能补充证据或申请复开")

    def _level(self, value: Any) -> int:
        try:
            level = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("level 必须是整数") from exc
        if not MIN_LEVEL <= level <= MAX_LEVEL:
            raise ValidationError(f"level 必须在 {MIN_LEVEL} 到 {MAX_LEVEL} 之间")
        return level

    @staticmethod
    def _within_window(left: datetime, right: datetime) -> bool:
        return abs((left - right).total_seconds()) <= CORRELATION_WINDOW_MINUTES * 60

    # ---- 关联规则（只提出候选，不作决定） ----

    def _insert_candidate(self, connection, *, site_id: str, incident_id: str, report_id: str) -> str | None:
        existing = connection.execute(
            "SELECT 1 FROM merge_candidates WHERE incident_id=? AND report_id=?",
            (incident_id, report_id)).fetchone()
        if existing:
            return None
        candidate_id = uuid.uuid4().hex
        now = _iso(self._now())
        connection.execute(
            "INSERT INTO merge_candidates(candidate_id,site_id,incident_id,report_id,rule,status,proposed_at) "
            "VALUES(?,?,?,?,?,'pending',?)",
            (candidate_id, site_id, incident_id, report_id, CORRELATION_RULE, now))
        append_event(connection, actor_id=RULE_ACTOR, action="incident.merge_proposed",
                     resource_type="incident", resource_id=incident_id,
                     detail={"candidate_id": candidate_id, "report_id": report_id, "rule": CORRELATION_RULE},
                     occurred_at=now)
        return candidate_id

    def _linked_occurrences(self, connection, incident_id: str) -> list[datetime]:
        rows = connection.execute(
            "SELECT r.occurred_at FROM incident_report_links l "
            "JOIN incident_reports r ON r.report_id=l.report_id WHERE l.incident_id=?",
            (incident_id,)).fetchall()
        return [_parse_time(row["occurred_at"], "occurred_at") for row in rows]

    def _propose_for_report(self, connection, report) -> list[str]:
        """新报告入库后，为同站点同专区同类别的未结事件提出合并候选。"""

        proposed = []
        incidents = connection.execute(
            "SELECT * FROM incidents WHERE site_id=? AND zone=? AND category=? AND status='open'",
            (report["site_id"], report["zone"], report["category"])).fetchall()
        occurred = _parse_time(report["occurred_at"], "occurred_at")
        for incident in incidents:
            anchors = self._linked_occurrences(connection, incident["incident_id"])
            if not any(self._within_window(anchor, occurred) for anchor in anchors):
                continue
            candidate_id = self._insert_candidate(
                connection, site_id=report["site_id"],
                incident_id=incident["incident_id"], report_id=report["report_id"])
            if candidate_id:
                proposed.append(candidate_id)
        return proposed

    def _propose_for_incident(self, connection, incident) -> list[str]:
        """事件开立后，为尚未关联的匹配报告补提合并候选。"""

        proposed = []
        anchors = self._linked_occurrences(connection, incident["incident_id"])
        reports = connection.execute(
            "SELECT * FROM incident_reports WHERE site_id=? AND zone=? AND category=?",
            (incident["site_id"], incident["zone"], incident["category"])).fetchall()
        for report in reports:
            linked = connection.execute(
                "SELECT 1 FROM incident_report_links WHERE report_id=?",
                (report["report_id"],)).fetchone()
            if linked:
                continue
            occurred = _parse_time(report["occurred_at"], "occurred_at")
            if not any(self._within_window(anchor, occurred) for anchor in anchors):
                continue
            candidate_id = self._insert_candidate(
                connection, site_id=incident["site_id"],
                incident_id=incident["incident_id"], report_id=report["report_id"])
            if candidate_id:
                proposed.append(candidate_id)
        return proposed

    def _auto_reject_for_report(self, connection, report_id: str, keep_incident_id: str) -> int:
        """报告关联到事件后，其余指向该报告的待决候选自动作废。"""

        cursor = connection.execute(
            "UPDATE merge_candidates SET status='rejected', decided_by=?, decided_at=? "
            "WHERE report_id=? AND status='pending' AND incident_id<>?",
            (SYSTEM_ACTOR, _iso(self._now()), report_id, keep_incident_id))
        return cursor.rowcount

    def _auto_reject_for_incident(self, connection, incident_id: str) -> int:
        """事件结案后，仍未处理的合并候选自动作废。"""

        cursor = connection.execute(
            "UPDATE merge_candidates SET status='rejected', decided_by=?, decided_at=? "
            "WHERE incident_id=? AND status='pending'",
            (SYSTEM_ACTOR, _iso(self._now()), incident_id))
        return cursor.rowcount

    # ---- 交接期限 ----

    def _expire_handovers(self, connection, incident_id: str) -> None:
        """把已过期的待处理交接标记为失效（惰性结算，重启后依然成立）。"""

        now = self._now()
        rows = connection.execute(
            "SELECT * FROM handovers WHERE incident_id=? AND status='pending'", (incident_id,)).fetchall()
        for row in rows:
            if _parse_time(row["expires_at"], "expires_at") > now:
                continue
            connection.execute(
                "UPDATE handovers SET status='expired' WHERE handover_id=?", (row["handover_id"],))
            append_event(connection, actor_id=SYSTEM_ACTOR, action="incident.handover_expired",
                         resource_type="incident", resource_id=incident_id,
                         detail={"handover_id": row["handover_id"],
                                 "from_commander_id": row["from_commander_id"],
                                 "to_commander_id": row["to_commander_id"]},
                         occurred_at=_iso(now))

    # ---- 结案清场 ----

    def _pending_items(self, connection, incident_id: str) -> dict[str, list[dict[str, Any]]]:
        actions = [dict(row) for row in connection.execute(
            "SELECT action_id,title,owner_id,status FROM incident_actions "
            "WHERE incident_id=? AND status IN ('pending','in_progress') ORDER BY created_at",
            (incident_id,))]
        supports = [dict(row) for row in connection.execute(
            "SELECT support_id,assignee_id,status FROM support_requests "
            "WHERE incident_id=? AND status IN ('open','acknowledged') ORDER BY created_at",
            (incident_id,))]
        handovers = [dict(row) for row in connection.execute(
            "SELECT handover_id,from_commander_id,to_commander_id FROM handovers "
            "WHERE incident_id=? AND status='pending'", (incident_id,))]
        return {"open_actions": actions, "open_support_requests": supports,
                "pending_handovers": handovers}

    def _ensure_clear_for_closure(self, connection, incident_id: str) -> None:
        pending = self._pending_items(connection, incident_id)
        remaining = sum(len(items) for items in pending.values())
        if remaining:
            raise ConflictError("结案前必须清空未决行动、调援与交接")

    # ---- 报告 ----

    def submit_report(self, *, request_id: str, actor_id: str, site_id: str, zone: str,
                      category: str, occurred_at: str, location: str, public_summary: str,
                      evidence_fingerprint: str, sensitive: dict[str, Any] | None = None) -> WriteReceipt:
        """把一份现场报告独立保存，随后由关联规则提出合并候选。"""

        sensitive = sensitive or {}
        if not isinstance(sensitive, dict):
            raise ValidationError("sensitive 必须是对象")
        payload = {"actor_id": actor_id, "site_id": site_id, "zone": zone, "category": category,
                   "occurred_at": occurred_at, "location": location, "public_summary": public_summary,
                   "evidence_fingerprint": evidence_fingerprint, "sensitive": sensitive}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, *REPORT_ROLES)
            site = self._site(connection, site_id)
            self._check_org(actor, site["organization_id"])
            zone = self.foundation._text(zone, "zone", 80)
            if category not in REPORT_CATEGORIES:
                raise ValidationError("category 不在允许范围内")
            occurred = _parse_time(occurred_at, "occurred_at")
            location = self.foundation._text(location, "location", 200)
            public_summary = self.foundation._text(public_summary, "public_summary", 200)
            evidence_fingerprint = self.foundation._text(evidence_fingerprint, "evidence_fingerprint", 128)

            def create() -> tuple[str, str, dict[str, Any]]:
                report_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO incident_reports(report_id,site_id,zone,category,occurred_at,location,"
                    "public_summary,evidence_fingerprint,sensitive_json,reporter_id,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (report_id, site_id, zone, category, _iso(occurred), location, public_summary,
                     evidence_fingerprint, canonical_json(sensitive), actor_id, now))
                append_event(connection, actor_id=actor_id, action="incident_report.submitted",
                             resource_type="incident_report", resource_id=report_id,
                             detail={"site_id": site_id, "zone": zone, "category": category,
                                     "occurred_at": _iso(occurred),
                                     "evidence_fingerprint": evidence_fingerprint},
                             occurred_at=now)
                report = self._report(connection, report_id)
                candidates = self._propose_for_report(connection, report)
                return "incident_report", report_id, {"report_id": report_id, "candidates": candidates}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="submit_incident_report",
                payload=payload, create=create)

    # ---- 事件开立与合并 ----

    def open_incident(self, *, request_id: str, actor_id: str, report_id: str,
                      level: int = 1, public_summary: str | None = None) -> WriteReceipt:
        """值班指挥把一份报告开立为共同事件，报告成为事件的起源记录。"""

        payload = {"actor_id": actor_id, "report_id": report_id,
                   "level": level, "public_summary": public_summary}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, *COMMAND_ROLES)
            report = self._report(connection, report_id)
            site = self._site(connection, report["site_id"])
            self._check_org(actor, site["organization_id"])
            level = self._level(level)
            if connection.execute(
                    "SELECT 1 FROM incident_report_links WHERE report_id=?", (report_id,)).fetchone():
                raise ConflictError("报告已关联到其他事件")
            summary = (self.foundation._text(public_summary, "public_summary", 200)
                       if public_summary else report["public_summary"])

            def create() -> tuple[str, str, dict[str, Any]]:
                incident_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO incidents(incident_id,site_id,zone,category,level,status,public_summary,"
                    "commander_id,opened_from_report_id,created_at) VALUES(?,?,?,?,?,'open',?,?,?,?)",
                    (incident_id, report["site_id"], report["zone"], report["category"], level,
                     summary, actor_id, report_id, now))
                connection.execute(
                    "INSERT INTO incident_report_links(incident_id,report_id,link_type,linked_by,linked_at) "
                    "VALUES(?,?,?,?,?)", (incident_id, report_id, "origin", actor_id, now))
                append_event(connection, actor_id=actor_id, action="incident.opened",
                             resource_type="incident", resource_id=incident_id,
                             detail={"report_id": report_id, "level": level, "zone": report["zone"],
                                     "category": report["category"]},
                             occurred_at=now)
                rejected = self._auto_reject_for_report(connection, report_id, incident_id)
                incident = self._incident(connection, incident_id)
                candidates = self._propose_for_incident(connection, incident)
                return "incident", incident_id, {"incident_id": incident_id, "candidates": candidates,
                                                 "auto_rejected_candidates": rejected}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="open_incident",
                payload=payload, create=create)

    def decide_merge(self, *, request_id: str, actor_id: str, candidate_id: str,
                     decision: str) -> WriteReceipt:
        """值班指挥确认或拒绝合并候选；确认后报告并入共同事件且仍可单独追查。"""

        if decision not in ("confirm", "reject"):
            raise ValidationError("decision 必须是 confirm 或 reject")
        payload = {"actor_id": actor_id, "candidate_id": candidate_id, "decision": decision}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            row = connection.execute(
                "SELECT * FROM merge_candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
            if row is None:
                raise NotFoundError("合并候选不存在")
            incident = self._incident(connection, row["incident_id"])
            self._require_commander(actor, incident)
            self._require_open(incident)
            if row["status"] != "pending":
                raise ConflictError("合并候选已处理")
            report = self._report(connection, row["report_id"])
            if connection.execute(
                    "SELECT 1 FROM incident_report_links WHERE report_id=?", (report["report_id"],)).fetchone():
                raise ConflictError("报告已关联到其他事件")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                if decision == "confirm":
                    connection.execute(
                        "INSERT INTO incident_report_links(incident_id,report_id,link_type,linked_by,linked_at) "
                        "VALUES(?,?,?,?,?)",
                        (incident["incident_id"], report["report_id"], "merged", actor_id, now))
                    status, action = "confirmed", "incident.merge_confirmed"
                else:
                    status, action = "rejected", "incident.merge_rejected"
                connection.execute(
                    "UPDATE merge_candidates SET status=?, decided_by=?, decided_at=? WHERE candidate_id=?",
                    (status, actor_id, now, candidate_id))
                rejected = 0
                if decision == "confirm":
                    rejected = self._auto_reject_for_report(
                        connection, report["report_id"], incident["incident_id"])
                append_event(connection, actor_id=actor_id, action=action,
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"candidate_id": candidate_id, "report_id": report["report_id"],
                                     "auto_rejected_candidates": rejected},
                             occurred_at=now)
                return "merge_candidate", candidate_id, {"candidate_id": candidate_id, "decision": decision}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="decide_merge",
                payload=payload, create=create)

    # ---- 升级 ----

    def escalate(self, *, request_id: str, actor_id: str, incident_id: str, to_level: int,
                 fact_refs: list[str], reason: str) -> WriteReceipt:
        """提升事件等级，必须引用尚未使用过的新现场事实。"""

        if not isinstance(fact_refs, list) or not fact_refs:
            raise ValidationError("fact_refs 必须是非空列表")
        payload = {"actor_id": actor_id, "incident_id": incident_id, "to_level": to_level,
                   "fact_refs": fact_refs, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._incident(connection, incident_id)
            self._require_commander(actor, incident)
            self._require_open(incident)
            to_level = self._level(to_level)
            if to_level <= incident["level"]:
                raise ValidationError("升级后的等级必须高于当前等级")
            reason = self.foundation._text(reason, "reason", 200)
            linked = connection.execute(
                "SELECT r.report_id, r.evidence_fingerprint FROM incident_report_links l "
                "JOIN incident_reports r ON r.report_id=l.report_id WHERE l.incident_id=?",
                (incident_id,)).fetchall()
            known = {row["report_id"] for row in linked} | {row["evidence_fingerprint"] for row in linked}
            used: set[str] = set()
            for row in connection.execute(
                    "SELECT fact_refs_json FROM escalations WHERE incident_id=?", (incident_id,)):
                used.update(json.loads(row["fact_refs_json"]))
            refs: list[str] = []
            for ref in fact_refs:
                ref = str(ref).strip()
                if ref not in known:
                    raise ValidationError("现场事实必须引用已关联报告或其证据指纹")
                if ref in used:
                    raise ConflictError("升级必须引用新的现场事实")
                if ref not in refs:
                    refs.append(ref)
            if not refs:
                raise ValidationError("fact_refs 不能为空")

            def create() -> tuple[str, str, dict[str, Any]]:
                escalation_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO escalations(escalation_id,incident_id,from_level,to_level,fact_refs_json,"
                    "reason,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (escalation_id, incident_id, incident["level"], to_level,
                     canonical_json(refs), reason, actor_id, now))
                connection.execute(
                    "UPDATE incidents SET level=? WHERE incident_id=?", (to_level, incident_id))
                append_event(connection, actor_id=actor_id, action="incident.escalated",
                             resource_type="incident", resource_id=incident_id,
                             detail={"escalation_id": escalation_id, "from_level": incident["level"],
                                     "to_level": to_level, "fact_refs": refs, "reason": reason},
                             occurred_at=now)
                return "escalation", escalation_id, {"escalation_id": escalation_id, "level": to_level}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="escalate_incident",
                payload=payload, create=create)

    # ---- 人员资格 ----

    def grant_qualification(self, *, request_id: str, actor_id: str, target_actor_id: str,
                            qualification: str) -> WriteReceipt:
        """管理员为操作者登记资格，调援时据此核验。"""

        payload = {"actor_id": actor_id, "target_actor_id": target_actor_id,
                   "qualification": qualification}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, "admin")
            self._actor(connection, target_actor_id)
            qualification = self.foundation._text(qualification, "qualification", 80)

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                connection.execute(
                    "INSERT OR IGNORE INTO actor_qualifications(actor_id,qualification,granted_by,granted_at) "
                    "VALUES(?,?,?,?)", (target_actor_id, qualification, actor_id, now))
                append_event(connection, actor_id=actor_id, action="actor.qualification_granted",
                             resource_type="actor", resource_id=target_actor_id,
                             detail={"qualification": qualification}, occurred_at=now)
                resource_id = f"{target_actor_id}:{qualification}"
                return "actor_qualification", resource_id, {"actor_id": target_actor_id,
                                                            "qualification": qualification}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="grant_qualification",
                payload=payload, create=create)

    # ---- 调援 ----

    def request_support(self, *, request_id: str, actor_id: str, incident_id: str,
                        assignee_id: str, required_qualifications: list[str],
                        note: str = "") -> WriteReceipt:
        """发起调援：核验被调援人员资格，并冻结当时的责任清单。"""

        if not isinstance(required_qualifications, list) or not required_qualifications:
            raise ValidationError("required_qualifications 必须是非空列表")
        payload = {"actor_id": actor_id, "incident_id": incident_id, "assignee_id": assignee_id,
                   "required_qualifications": required_qualifications, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._incident(connection, incident_id)
            self._require_commander(actor, incident)
            self._require_open(incident)
            assignee = self._actor(connection, assignee_id)
            site = self._site(connection, incident["site_id"])
            self._check_org(assignee, site["organization_id"])
            qualifications = sorted({self.foundation._text(item, "qualification", 80)
                                     for item in required_qualifications})
            held = {row["qualification"] for row in connection.execute(
                "SELECT qualification FROM actor_qualifications WHERE actor_id=?", (assignee_id,))}
            missing = [item for item in qualifications if item not in held]
            if missing:
                raise PermissionDenied("被调援人员缺少所需资格: " + ",".join(missing))
            note = self.foundation._text(note, "note", 200) if note else ""

            def create() -> tuple[str, str, dict[str, Any]]:
                support_id = uuid.uuid4().hex
                now = _iso(self._now())
                pending = self._pending_items(connection, incident_id)
                snapshot = {"frozen_at": now, "incident_id": incident_id,
                            "level": incident["level"], "commander_id": incident["commander_id"],
                            "open_actions": pending["open_actions"],
                            "open_support_requests": pending["open_support_requests"]}
                connection.execute(
                    "INSERT INTO support_requests(support_id,incident_id,assignee_id,"
                    "required_qualifications_json,responsibility_snapshot_json,note,status,"
                    "created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (support_id, incident_id, assignee_id, canonical_json(qualifications),
                     canonical_json(snapshot), note, "open", actor_id, now, now))
                append_event(connection, actor_id=actor_id, action="incident.support_requested",
                             resource_type="incident", resource_id=incident_id,
                             detail={"support_id": support_id, "assignee_id": assignee_id,
                                     "required_qualifications": qualifications,
                                     "responsibility_snapshot": snapshot},
                             occurred_at=now)
                return "support_request", support_id, {"support_id": support_id}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="request_support",
                payload=payload, create=create)

    def update_support(self, *, request_id: str, actor_id: str, support_id: str,
                       action: str) -> WriteReceipt:
        """推进调援状态：受理、完成或取消。"""

        if action not in ("acknowledge", "complete", "cancel"):
            raise ValidationError("action 必须是 acknowledge、complete 或 cancel")
        payload = {"actor_id": actor_id, "support_id": support_id, "action": action}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            row = connection.execute(
                "SELECT * FROM support_requests WHERE support_id=?", (support_id,)).fetchone()
            if row is None:
                raise NotFoundError("调援请求不存在")
            incident = self._incident(connection, row["incident_id"])
            is_commander = actor.actor_id == incident["commander_id"]
            is_assignee = actor.actor_id == row["assignee_id"]
            if row["status"] not in OPEN_SUPPORT_STATUSES:
                raise ConflictError("调援请求已终结")
            if action == "acknowledge":
                if not is_assignee:
                    raise PermissionDenied("只有被调援人员可以受理")
                new_status = "acknowledged"
            elif action == "complete":
                if not (is_assignee or is_commander):
                    raise PermissionDenied("只有被调援人员或值班指挥可以完成调援")
                new_status = "completed"
            else:
                if not is_commander:
                    raise PermissionDenied("只有值班指挥可以取消调援")
                new_status = "cancelled"

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                connection.execute(
                    "UPDATE support_requests SET status=?, updated_at=? WHERE support_id=?",
                    (new_status, now, support_id))
                append_event(connection, actor_id=actor_id, action="incident.support_updated",
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"support_id": support_id, "action": action, "status": new_status},
                             occurred_at=now)
                return "support_request", support_id, {"support_id": support_id, "status": new_status}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="update_support",
                payload=payload, create=create)

    # ---- 行动 ----

    def create_action(self, *, request_id: str, actor_id: str, incident_id: str,
                      title: str, owner_id: str) -> WriteReceipt:
        """登记一项行动；行动从创建起就有明确负责人。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "title": title, "owner_id": owner_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._incident(connection, incident_id)
            self._require_commander(actor, incident)
            self._require_open(incident)
            self._actor(connection, owner_id)
            title = self.foundation._text(title, "title", 200)

            def create() -> tuple[str, str, dict[str, Any]]:
                action_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO incident_actions(action_id,incident_id,title,owner_id,status,"
                    "created_by,created_at,updated_at) VALUES(?,?,?,?,'pending',?,?,?)",
                    (action_id, incident_id, title, owner_id, actor_id, now, now))
                append_event(connection, actor_id=actor_id, action="incident.action_created",
                             resource_type="incident", resource_id=incident_id,
                             detail={"action_id": action_id, "title": title, "owner_id": owner_id},
                             occurred_at=now)
                return "incident_action", action_id, {"action_id": action_id}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="create_incident_action",
                payload=payload, create=create)

    def update_action(self, *, request_id: str, actor_id: str, action_id: str,
                      status: str | None = None, new_owner_id: str | None = None,
                      note: str = "") -> WriteReceipt:
        """推进或改派行动；负责人字段任何时刻都不得为空。"""

        payload = {"actor_id": actor_id, "action_id": action_id, "status": status,
                   "new_owner_id": new_owner_id, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            row = connection.execute(
                "SELECT * FROM incident_actions WHERE action_id=?", (action_id,)).fetchone()
            if row is None:
                raise NotFoundError("行动不存在")
            incident = self._incident(connection, row["incident_id"])
            is_commander = actor.actor_id == incident["commander_id"]
            is_owner = actor.actor_id == row["owner_id"]
            if not (is_commander or is_owner):
                raise PermissionDenied("只有值班指挥或行动负责人可以更新行动")
            if row["status"] in ("done", "cancelled"):
                raise ConflictError("行动已终结")
            if status is None and new_owner_id is None:
                raise ValidationError("没有需要更新的内容")
            if status is not None:
                if status not in ("in_progress", "done", "cancelled"):
                    raise ValidationError("status 必须是 in_progress、done 或 cancelled")
                if status == "in_progress" and row["status"] != "pending":
                    raise ConflictError("只有待处理的行动可以开始执行")
            if new_owner_id is not None:
                if not is_commander:
                    raise PermissionDenied("只有值班指挥可以改派负责人")
                self._actor(connection, new_owner_id)
            note = self.foundation._text(note, "note", 200) if note else ""

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                final_status = status or row["status"]
                final_owner = new_owner_id or row["owner_id"]
                connection.execute(
                    "UPDATE incident_actions SET status=?, owner_id=?, updated_at=? WHERE action_id=?",
                    (final_status, final_owner, now, action_id))
                append_event(connection, actor_id=actor_id, action="incident.action_updated",
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"action_id": action_id, "status": final_status,
                                     "owner_id": final_owner, "note": note},
                             occurred_at=now)
                return "incident_action", action_id, {"action_id": action_id,
                                                      "status": final_status,
                                                      "owner_id": final_owner}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="update_incident_action",
                payload=payload, create=create)

    # ---- 指挥权交接 ----

    def initiate_handover(self, *, request_id: str, actor_id: str, incident_id: str,
                          to_commander_id: str, expires_at: str) -> WriteReceipt:
        """发起有期限的指挥权交接。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "to_commander_id": to_commander_id, "expires_at": expires_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._incident(connection, incident_id)
            self._require_open(incident)
            if actor.actor_id != incident["commander_id"] and actor.role != "admin":
                raise PermissionDenied("只有现任值班指挥或管理员可以发起交接")
            target = self._actor(connection, to_commander_id)
            if target.role not in COMMAND_ROLES:
                raise ValidationError("接班人必须具备指挥角色")
            if to_commander_id == incident["commander_id"]:
                raise ValidationError("不能交接给现任指挥")
            site = self._site(connection, incident["site_id"])
            self._check_org(target, site["organization_id"])
            expires = _parse_time(expires_at, "expires_at")
            if expires <= self._now():
                raise ValidationError("expires_at 必须晚于当前时间")
            self._expire_handovers(connection, incident_id)
            if connection.execute(
                    "SELECT 1 FROM handovers WHERE incident_id=? AND status='pending'",
                    (incident_id,)).fetchone():
                raise ConflictError("已有进行中的交接")

            def create() -> tuple[str, str, dict[str, Any]]:
                handover_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO handovers(handover_id,incident_id,from_commander_id,to_commander_id,"
                    "status,initiated_by,initiated_at,expires_at) VALUES(?,?,?,?,'pending',?,?,?)",
                    (handover_id, incident_id, incident["commander_id"], to_commander_id,
                     actor_id, now, _iso(expires)))
                append_event(connection, actor_id=actor_id, action="incident.handover_initiated",
                             resource_type="incident", resource_id=incident_id,
                             detail={"handover_id": handover_id,
                                     "from_commander_id": incident["commander_id"],
                                     "to_commander_id": to_commander_id,
                                     "expires_at": _iso(expires)},
                             occurred_at=now)
                return "handover", handover_id, {"handover_id": handover_id}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="initiate_handover",
                payload=payload, create=create)

    def accept_handover(self, *, request_id: str, actor_id: str, handover_id: str) -> WriteReceipt:
        """指定接班人在期限内接受交接；此后原指挥不得继续作决定。"""

        payload = {"actor_id": actor_id, "handover_id": handover_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            row = connection.execute(
                "SELECT * FROM handovers WHERE handover_id=?", (handover_id,)).fetchone()
            if row is None:
                raise NotFoundError("交接不存在")
            incident = self._incident(connection, row["incident_id"])
            self._expire_handovers(connection, incident["incident_id"])
            row = connection.execute(
                "SELECT * FROM handovers WHERE handover_id=?", (handover_id,)).fetchone()
            if row["status"] != "pending":
                raise ConflictError("交接不在待处理状态")
            if actor.actor_id != row["to_commander_id"]:
                raise PermissionDenied("只有指定接班人可以接受交接")
            self._require_open(incident)

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                reassigned = []
                for action_row in connection.execute(
                        "SELECT action_id FROM incident_actions WHERE incident_id=? AND owner_id=? "
                        "AND status IN ('pending','in_progress')",
                        (incident["incident_id"], row["from_commander_id"])).fetchall():
                    connection.execute(
                        "UPDATE incident_actions SET owner_id=?, updated_at=? WHERE action_id=?",
                        (row["to_commander_id"], now, action_row["action_id"]))
                    reassigned.append(action_row["action_id"])
                connection.execute(
                    "UPDATE handovers SET status='completed', completed_at=? WHERE handover_id=?",
                    (now, handover_id))
                connection.execute(
                    "UPDATE incidents SET commander_id=? WHERE incident_id=?",
                    (row["to_commander_id"], incident["incident_id"]))
                append_event(connection, actor_id=actor_id, action="incident.handover_completed",
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"handover_id": handover_id,
                                     "from_commander_id": row["from_commander_id"],
                                     "to_commander_id": row["to_commander_id"],
                                     "reassigned_actions": reassigned},
                             occurred_at=now)
                return "handover", handover_id, {"handover_id": handover_id,
                                                 "reassigned_actions": reassigned}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="accept_handover",
                payload=payload, create=create)

    def cancel_handover(self, *, request_id: str, actor_id: str, handover_id: str) -> WriteReceipt:
        """现任指挥或管理员取消待处理的交接。"""

        payload = {"actor_id": actor_id, "handover_id": handover_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            row = connection.execute(
                "SELECT * FROM handovers WHERE handover_id=?", (handover_id,)).fetchone()
            if row is None:
                raise NotFoundError("交接不存在")
            incident = self._incident(connection, row["incident_id"])
            self._expire_handovers(connection, incident["incident_id"])
            row = connection.execute(
                "SELECT * FROM handovers WHERE handover_id=?", (handover_id,)).fetchone()
            if row["status"] != "pending":
                raise ConflictError("交接不在待处理状态")
            if actor.actor_id != incident["commander_id"] and actor.role != "admin":
                raise PermissionDenied("只有现任值班指挥或管理员可以取消交接")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                connection.execute(
                    "UPDATE handovers SET status='cancelled' WHERE handover_id=?", (handover_id,))
                append_event(connection, actor_id=actor_id, action="incident.handover_cancelled",
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"handover_id": handover_id}, occurred_at=now)
                return "handover", handover_id, {"handover_id": handover_id, "status": "cancelled"}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="cancel_handover",
                payload=payload, create=create)

    # ---- 结案 ----

    def propose_closure(self, *, request_id: str, actor_id: str, incident_id: str) -> WriteReceipt:
        """值班指挥提出结案，前提是未决行动、调援与交接都已清空。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._incident(connection, incident_id)
            self._require_commander(actor, incident)
            self._require_open(incident)
            self._expire_handovers(connection, incident_id)
            self._ensure_clear_for_closure(connection, incident_id)
            if connection.execute(
                    "SELECT 1 FROM closures WHERE incident_id=? AND status='pending'",
                    (incident_id,)).fetchone():
                raise ConflictError("已有待确认的结案申请")

            def create() -> tuple[str, str, dict[str, Any]]:
                closure_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO closures(closure_id,incident_id,status,proposed_by,proposed_at) "
                    "VALUES(?,?,'pending',?,?)", (closure_id, incident_id, actor_id, now))
                append_event(connection, actor_id=actor_id, action="incident.closure_proposed",
                             resource_type="incident", resource_id=incident_id,
                             detail={"closure_id": closure_id}, occurred_at=now)
                return "closure", closure_id, {"closure_id": closure_id}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="propose_closure",
                payload=payload, create=create)

    def decide_closure(self, *, request_id: str, actor_id: str, closure_id: str,
                       decision: str) -> WriteReceipt:
        """另一名复核者确认或驳回结案；确认时重新核验清场条件。"""

        if decision not in ("confirm", "reject"):
            raise ValidationError("decision 必须是 confirm 或 reject")
        payload = {"actor_id": actor_id, "closure_id": closure_id, "decision": decision}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, *REVIEW_ROLES)
            row = connection.execute(
                "SELECT * FROM closures WHERE closure_id=?", (closure_id,)).fetchone()
            if row is None:
                raise NotFoundError("结案申请不存在")
            if row["status"] != "pending":
                raise ConflictError("结案申请已处理")
            if actor.actor_id == row["proposed_by"]:
                raise PermissionDenied("结案必须由另一名复核者确认")
            incident = self._incident(connection, row["incident_id"])

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                if decision == "confirm":
                    self._expire_handovers(connection, incident["incident_id"])
                    pending = self._pending_items(connection, incident["incident_id"])
                    if any(pending.values()):
                        connection.execute(
                            "UPDATE closures SET status='rejected', decided_by=?, decided_at=? "
                            "WHERE closure_id=?", (actor_id, now, closure_id))
                        append_event(connection, actor_id=actor_id,
                                     action="incident.closure_rejected",
                                     resource_type="incident", resource_id=incident["incident_id"],
                                     detail={"closure_id": closure_id,
                                             "reason": "pending_items_reappeared"},
                                     occurred_at=now)
                        return "closure", closure_id, {"closure_id": closure_id,
                                                       "decision": "rejected",
                                                       "reason": "pending_items_reappeared"}
                    rejected = self._auto_reject_for_incident(connection, incident["incident_id"])
                    connection.execute(
                        "UPDATE closures SET status='confirmed', decided_by=?, decided_at=? "
                        "WHERE closure_id=?", (actor_id, now, closure_id))
                    connection.execute(
                        "UPDATE incidents SET status='closed', closed_at=? WHERE incident_id=?",
                        (now, incident["incident_id"]))
                    append_event(connection, actor_id=actor_id, action="incident.closed",
                                 resource_type="incident", resource_id=incident["incident_id"],
                                 detail={"closure_id": closure_id,
                                         "auto_rejected_candidates": rejected},
                                 occurred_at=now)
                    return "closure", closure_id, {"closure_id": closure_id, "decision": "confirmed"}
                connection.execute(
                    "UPDATE closures SET status='rejected', decided_by=?, decided_at=? WHERE closure_id=?",
                    (actor_id, now, closure_id))
                append_event(connection, actor_id=actor_id, action="incident.closure_rejected",
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"closure_id": closure_id, "reason": "reviewer_rejected"},
                             occurred_at=now)
                return "closure", closure_id, {"closure_id": closure_id, "decision": "rejected"}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="decide_closure",
                payload=payload, create=create)

    # ---- 迟到报告：补充证据与复开 ----

    def supplement_evidence(self, *, request_id: str, actor_id: str, incident_id: str,
                            report_id: str) -> WriteReceipt:
        """把迟到报告作为补充证据挂到已结案事件，不改变事件状态。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "report_id": report_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, *REPORT_ROLES)
            incident = self._incident(connection, incident_id)
            if incident["status"] != "closed":
                raise ConflictError("事件未结案，请使用合并候选流程")
            report = self._report(connection, report_id)
            if report["site_id"] != incident["site_id"]:
                raise ValidationError("报告与事件不属于同一场所")
            if connection.execute(
                    "SELECT 1 FROM incident_report_links WHERE report_id=?", (report_id,)).fetchone():
                raise ConflictError("报告已关联到其他事件")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO incident_report_links(incident_id,report_id,link_type,linked_by,linked_at) "
                    "VALUES(?,?,?,?,?)", (incident_id, report_id, "supplementary", actor_id, now))
                self._auto_reject_for_report(connection, report_id, incident_id)
                append_event(connection, actor_id=actor_id, action="incident.evidence_supplemented",
                             resource_type="incident", resource_id=incident_id,
                             detail={"report_id": report_id,
                                     "evidence_fingerprint": report["evidence_fingerprint"]},
                             occurred_at=now)
                return "incident", incident_id, {"incident_id": incident_id, "report_id": report_id}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="supplement_evidence",
                payload=payload, create=create)

    def request_reopen(self, *, request_id: str, actor_id: str, incident_id: str,
                       report_id: str, reason: str) -> WriteReceipt:
        """基于迟到报告对已结案事件发起复开申请。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "report_id": report_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, *REPORT_ROLES)
            incident = self._incident(connection, incident_id)
            if incident["status"] != "closed":
                raise ConflictError("事件未结案，无需复开")
            report = self._report(connection, report_id)
            if report["site_id"] != incident["site_id"]:
                raise ValidationError("报告与事件不属于同一场所")
            link = connection.execute(
                "SELECT * FROM incident_report_links WHERE report_id=?", (report_id,)).fetchone()
            if link and link["incident_id"] != incident_id:
                raise ConflictError("报告已关联到其他事件")
            reason = self.foundation._text(reason, "reason", 200)
            if connection.execute(
                    "SELECT 1 FROM reopen_requests WHERE incident_id=? AND status='pending'",
                    (incident_id,)).fetchone():
                raise ConflictError("已有待处理的复开申请")

            def create() -> tuple[str, str, dict[str, Any]]:
                reopen_id = uuid.uuid4().hex
                now = _iso(self._now())
                connection.execute(
                    "INSERT INTO reopen_requests(reopen_id,incident_id,report_id,reason,status,"
                    "requested_by,requested_at) VALUES(?,?,?,?,'pending',?,?)",
                    (reopen_id, incident_id, report_id, reason, actor_id, now))
                append_event(connection, actor_id=actor_id, action="incident.reopen_requested",
                             resource_type="incident", resource_id=incident_id,
                             detail={"reopen_id": reopen_id, "report_id": report_id,
                                     "reason": reason},
                             occurred_at=now)
                return "reopen_request", reopen_id, {"reopen_id": reopen_id}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="request_reopen",
                payload=payload, create=create)

    def decide_reopen(self, *, request_id: str, actor_id: str, reopen_id: str,
                      decision: str) -> WriteReceipt:
        """复核角色批准或驳回复开申请；批准后事件回到未结状态。"""

        if decision not in ("approve", "reject"):
            raise ValidationError("decision 必须是 approve 或 reject")
        payload = {"actor_id": actor_id, "reopen_id": reopen_id, "decision": decision}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self.foundation._require(actor, *REVIEW_ROLES)
            row = connection.execute(
                "SELECT * FROM reopen_requests WHERE reopen_id=?", (reopen_id,)).fetchone()
            if row is None:
                raise NotFoundError("复开申请不存在")
            if row["status"] != "pending":
                raise ConflictError("复开申请已处理")
            incident = self._incident(connection, row["incident_id"])
            if incident["status"] != "closed":
                raise ConflictError("事件未结案")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = _iso(self._now())
                if decision == "approve":
                    connection.execute(
                        "UPDATE reopen_requests SET status='approved', decided_by=?, decided_at=? "
                        "WHERE reopen_id=?", (actor_id, now, reopen_id))
                    connection.execute(
                        "UPDATE incidents SET status='open', closed_at=NULL WHERE incident_id=?",
                        (incident["incident_id"],))
                    if not connection.execute(
                            "SELECT 1 FROM incident_report_links WHERE report_id=?",
                            (row["report_id"],)).fetchone():
                        connection.execute(
                            "INSERT INTO incident_report_links(incident_id,report_id,link_type,"
                            "linked_by,linked_at) VALUES(?,?,?,?,?)",
                            (incident["incident_id"], row["report_id"], "supplementary",
                             actor_id, now))
                    append_event(connection, actor_id=actor_id, action="incident.reopened",
                                 resource_type="incident", resource_id=incident["incident_id"],
                                 detail={"reopen_id": reopen_id, "report_id": row["report_id"]},
                                 occurred_at=now)
                    return "reopen_request", reopen_id, {"reopen_id": reopen_id,
                                                         "decision": "approved"}
                connection.execute(
                    "UPDATE reopen_requests SET status='rejected', decided_by=?, decided_at=? "
                    "WHERE reopen_id=?", (actor_id, now, reopen_id))
                append_event(connection, actor_id=actor_id, action="incident.reopen_rejected",
                             resource_type="incident", resource_id=incident["incident_id"],
                             detail={"reopen_id": reopen_id}, occurred_at=now)
                return "reopen_request", reopen_id, {"reopen_id": reopen_id,
                                                     "decision": "rejected"}

            return self.foundation._idempotent(
                connection, request_id=request_id, action="decide_reopen",
                payload=payload, create=create)

    # ---- 查询 ----

    def _report_view(self, connection, row, actor_role: str | None) -> dict[str, Any]:
        view = {"report_id": row["report_id"], "site_id": row["site_id"], "zone": row["zone"],
                "category": row["category"], "occurred_at": row["occurred_at"],
                "location": row["location"], "public_summary": row["public_summary"],
                "evidence_fingerprint": row["evidence_fingerprint"],
                "created_at": row["created_at"],
                "links": [dict(link) for link in connection.execute(
                    "SELECT incident_id,link_type,linked_by,linked_at FROM incident_report_links "
                    "WHERE report_id=? ORDER BY linked_at", (row["report_id"],))]}
        if actor_role is not None:
            view["reporter_id"] = row["reporter_id"]
            if actor_role in SENSITIVE_ROLES:
                view["sensitive"] = json.loads(row["sensitive_json"])
        return view

    def get_report(self, *, report_id: str, actor_id: str | None = None) -> dict[str, Any]:
        """读取单份报告；敏感字段只对授权角色开放，无身份时只给公开视图。"""

        connection = self.database.connection
        row = self._report(connection, report_id)
        role = self._require_actor(connection, actor_id).role if actor_id else None
        return self._report_view(connection, row, role)

    def list_reports(self, *, actor_id: str, site_id: str) -> list[dict[str, Any]]:
        connection = self.database.connection
        actor = self._require_actor(connection, actor_id)
        return [self._report_view(connection, row, actor.role)
                for row in connection.execute(
                    "SELECT * FROM incident_reports WHERE site_id=? ORDER BY occurred_at, report_id",
                    (site_id,))]

    def _incident_row_view(self, row) -> dict[str, Any]:
        return {"incident_id": row["incident_id"], "site_id": row["site_id"],
                "zone": row["zone"], "category": row["category"], "level": row["level"],
                "status": row["status"], "public_summary": row["public_summary"],
                "commander_id": row["commander_id"], "created_at": row["created_at"],
                "closed_at": row["closed_at"]}

    def list_incidents(self, *, actor_id: str, site_id: str | None = None,
                       status: str | None = None) -> list[dict[str, Any]]:
        connection = self.database.connection
        self._require_actor(connection, actor_id)
        query = "SELECT * FROM incidents WHERE 1=1"
        parameters: list[Any] = []
        if site_id:
            query += " AND site_id=?"
            parameters.append(site_id)
        if status:
            query += " AND status=?"
            parameters.append(status)
        query += " ORDER BY created_at, incident_id"
        return [self._incident_row_view(row) for row in connection.execute(query, parameters)]

    def get_incident(self, *, actor_id: str, incident_id: str) -> dict[str, Any]:
        """事件内部全貌：关联报告、行动、调援、升级、交接、结案与复开记录。"""

        connection = self.database.connection
        actor = self._require_actor(connection, actor_id)
        incident = self._incident(connection, incident_id)
        result = self._incident_row_view(incident)
        result["opened_from_report_id"] = incident["opened_from_report_id"]
        reports = []
        for link in connection.execute(
                "SELECT l.link_type, l.linked_by, l.linked_at, r.* FROM incident_report_links l "
                "JOIN incident_reports r ON r.report_id=l.report_id "
                "WHERE l.incident_id=? ORDER BY l.linked_at, l.rowid", (incident_id,)):
            view = self._report_view(connection, link, actor.role)
            view["link_type"] = link["link_type"]
            reports.append(view)
        result["reports"] = reports
        result["actions"] = [dict(row) for row in connection.execute(
            "SELECT * FROM incident_actions WHERE incident_id=? ORDER BY created_at", (incident_id,))]
        supports = []
        for row in connection.execute(
                "SELECT * FROM support_requests WHERE incident_id=? ORDER BY created_at",
                (incident_id,)):
            item = dict(row)
            item["required_qualifications"] = json.loads(item.pop("required_qualifications_json"))
            item["responsibility_snapshot"] = json.loads(
                item.pop("responsibility_snapshot_json"))
            supports.append(item)
        result["support_requests"] = supports
        escalations = []
        for row in connection.execute(
                "SELECT * FROM escalations WHERE incident_id=? ORDER BY created_at", (incident_id,)):
            item = dict(row)
            item["fact_refs"] = json.loads(item.pop("fact_refs_json"))
            escalations.append(item)
        result["escalations"] = escalations
        handovers = []
        now = self._now()
        for row in connection.execute(
                "SELECT * FROM handovers WHERE incident_id=? ORDER BY initiated_at", (incident_id,)):
            item = dict(row)
            if item["status"] == "pending" and _parse_time(item["expires_at"], "expires_at") <= now:
                item["status"] = "expired"
            handovers.append(item)
        result["handovers"] = handovers
        result["closures"] = [dict(row) for row in connection.execute(
            "SELECT * FROM closures WHERE incident_id=? ORDER BY proposed_at", (incident_id,))]
        result["reopen_requests"] = [dict(row) for row in connection.execute(
            "SELECT * FROM reopen_requests WHERE incident_id=? ORDER BY requested_at",
            (incident_id,))]
        result["merge_candidates"] = [dict(row) for row in connection.execute(
            "SELECT * FROM merge_candidates WHERE incident_id=? ORDER BY proposed_at",
            (incident_id,))]
        return result

    def public_status(self, *, incident_id: str) -> dict[str, Any]:
        """对外状态：只保留必要字段，隐藏敏感信息与内部细节。"""

        connection = self.database.connection
        incident = self._incident(connection, incident_id)
        report_count = connection.execute(
            "SELECT COUNT(*) AS count FROM incident_report_links WHERE incident_id=?",
            (incident_id,)).fetchone()["count"]
        return {"incident_id": incident["incident_id"], "site_id": incident["site_id"],
                "zone": incident["zone"], "category": incident["category"],
                "level": incident["level"], "status": incident["status"],
                "public_summary": incident["public_summary"], "report_count": report_count}

    def list_merge_candidates(self, *, actor_id: str, site_id: str | None = None,
                              incident_id: str | None = None,
                              status: str | None = None) -> list[dict[str, Any]]:
        connection = self.database.connection
        self._require_actor(connection, actor_id)
        query = "SELECT * FROM merge_candidates WHERE 1=1"
        parameters: list[Any] = []
        if site_id:
            query += " AND site_id=?"
            parameters.append(site_id)
        if incident_id:
            query += " AND incident_id=?"
            parameters.append(incident_id)
        if status:
            query += " AND status=?"
            parameters.append(status)
        query += " ORDER BY proposed_at, candidate_id"
        return [dict(row) for row in connection.execute(query, parameters)]

    def list_actions(self, *, actor_id: str, incident_id: str) -> list[dict[str, Any]]:
        connection = self.database.connection
        self._require_actor(connection, actor_id)
        self._incident(connection, incident_id)
        return [dict(row) for row in connection.execute(
            "SELECT * FROM incident_actions WHERE incident_id=? ORDER BY created_at",
            (incident_id,))]

    def incident_history(self, *, actor_id: str, incident_id: str) -> list[dict[str, Any]]:
        """按审计顺序还原合并、升级、调援、交接和结案的因果链。"""

        connection = self.database.connection
        self._require_actor(connection, actor_id)
        self._incident(connection, incident_id)
        report_ids = [row["report_id"] for row in connection.execute(
            "SELECT report_id FROM incident_report_links WHERE incident_id=?", (incident_id,))]
        clauses = ["(resource_type='incident' AND resource_id=?)"]
        parameters: list[Any] = [incident_id]
        if report_ids:
            placeholders = ",".join("?" for _ in report_ids)
            clauses.append(f"(resource_type='incident_report' AND resource_id IN ({placeholders}))")
            parameters.extend(report_ids)
        query = "SELECT * FROM audit_events WHERE " + " OR ".join(clauses) + " ORDER BY sequence"
        history = []
        for row in connection.execute(query, parameters):
            history.append({"sequence": row["sequence"], "action": row["action"],
                            "actor_id": row["actor_id"], "resource_type": row["resource_type"],
                            "resource_id": row["resource_id"],
                            "detail": json.loads(row["detail_json"]),
                            "previous_hash": row["previous_hash"],
                            "event_hash": row["event_hash"],
                            "occurred_at": row["occurred_at"]})
        return history

    def count_unowned_open_actions(self) -> int:
        """健康检查用：执行中的行动是否存在无人负责的悬空记录（应恒为 0）。"""

        row = self.database.connection.execute(
            "SELECT COUNT(*) AS count FROM incident_actions a "
            "WHERE a.status IN ('pending','in_progress') AND NOT EXISTS "
            "(SELECT 1 FROM actors WHERE actor_id=a.owner_id)").fetchone()
        return row["count"]
