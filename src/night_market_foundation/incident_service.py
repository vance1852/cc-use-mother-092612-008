"""实现跨专区事件指挥的领域服务。

在基础服务（主体、站点、权限、幂等、审计链）之上提供：
独立报告存档与关联候选、指挥确认合并、事实驱动升级、资格核验调援、
有期限指挥权交接、行动项责任不悬空、敏感信息分级可见、结案复核与复开、
以及可从接口还原因果链的审计关联。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .audit import append_event, canonical_json, digest
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .incident_domain import (
    ACTION_CANCELLED, ACTION_COMPLETED, ACTION_IN_PROGRESS, ACTION_OPEN,
    ACTION_PENDING_STATUSES, ACTION_TRANSITIONS, CANDIDATE_CONFIRMED,
    CANDIDATE_REJECTED, CLOSURE_CONFIRMED, CLOSURE_PROPOSED, CLOSURE_REJECTED,
    HANDOVER_CANCELLED, HANDOVER_COMPLETED, HANDOVER_PROPOSED, INCIDENT_CLOSED, INCIDENT_OPEN,
    INCIDENT_REOPENED, LATE_REOPEN, LATE_SUPPLEMENT, LEVEL_RANK, LEVELS,
    MAX_HANDOVER_HOURS, NEAR_DUPLICATE_WINDOW_MINUTES, REPORT_ROLES,
    REOPEN_APPROVED, REOPEN_PENDING, REOPEN_REJECTED, RULE_NEAR_DUPLICATE,
    RULE_SAME_EVIDENCE, RULE_SAME_LOCATION, SAME_LOCATION_WINDOW_MINUTES,
    SENSITIVE_ROLES, SUPPORT_CANCELLED, SUPPORT_FULFILLED,
    SUPPORT_REQUESTED,
)
from .incident_models import CausalLink
from .incident_storage import ensure_incident_schema
from .models import WriteReceipt
from .service import DomainService

_PUBLIC_STATUS_TEXT = {
    (INCIDENT_OPEN, "standard"): "常规处置中",
    (INCIDENT_OPEN, "elevated"): "升级处置中",
    (INCIDENT_OPEN, "critical"): "紧急处置中",
    (INCIDENT_REOPENED, "standard"): "复开处置中",
    (INCIDENT_REOPENED, "elevated"): "复开升级处置中",
    (INCIDENT_REOPENED, "critical"): "复开紧急处置中",
}


class IncidentService(DomainService):
    """协调事件指挥生命周期的事务、权限与审计规则。"""

    def __init__(self, database, clock=None) -> None:
        super().__init__(database, clock)
        ensure_incident_schema(self.database.connection)

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _replayed(self, connection, *, request_id: str, action: str,
                  payload: dict[str, Any]) -> Any | None:
        """在业务状态检查之前识别重放请求，返回既有回执。

        保证同一 request_id 的重试即使遇到“候选已处理、指挥已交接、事件已结案”
        等状态变化，也能得到首次执行的稳定结果，而不是状态冲突错误。
        """

        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            return None
        if row["action"] != action or row["payload_hash"] != payload_hash:
            raise ConflictError("request_id 已被不同内容使用")
        return WriteReceipt(request_id, row["resource_type"], row["resource_id"], True)

    def _parse_ts(self, value: Any, field: str) -> datetime:
        """解析带时区的 ISO8601 时间字符串并归一到 UTC。"""

        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"{field} 必须是带时区的 ISO8601 时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} 必须包含时区")
        return parsed.astimezone(timezone.utc)

    def _public_text(self, status: str, level: str) -> str:
        if status == INCIDENT_CLOSED:
            return "已结案"
        return _PUBLIC_STATUS_TEXT[(status, level)]

    def _site_row(self, connection, site_id: str):
        row = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if row is None:
            raise NotFoundError("场所不存在")
        return row

    def _report_row(self, connection, report_id: str):
        row = connection.execute("SELECT * FROM reports WHERE report_id=?", (report_id,)).fetchone()
        if row is None:
            raise NotFoundError("报告不存在")
        return row

    def _incident_row(self, connection, incident_id: str, *, for_update: bool = False):
        row = connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFoundError("事件不存在")
        return row

    def _require_commander(self, connection, incident_id: str, actor) -> Any:
        """返回事件行；仅当操作者当前持有有效指挥权时通过。

        交接完成后原指挥不再匹配 current_commander_id；超过交接期限后
        commander_until 已过期，需重新交接才能继续作决定。
        """

        row = self._incident_row(connection, incident_id)
        if row["status"] == INCIDENT_CLOSED:
            raise ConflictError("事件已结案，不能继续指挥动作")
        now = self.clock.now()
        since = self._parse_ts(row["commander_since"], "commander_since")
        if now < since:
            raise PermissionDenied("指挥权尚未生效")
        if row["commander_until"]:
            until = self._parse_ts(row["commander_until"], "commander_until")
            if now > until:
                raise PermissionDenied("指挥权已超过交接期限，需要重新交接")
        if actor.actor_id != row["current_commander_id"]:
            raise PermissionDenied("只有现任值班指挥可以执行该动作")
        return row

    def _redact_report(self, connection, row, actor) -> dict[str, Any]:
        """按角色过滤健康信息与联系方式；报告人本人始终可见自己的报告。"""

        data = {
            "report_id": row["report_id"],
            "incident_id": row["incident_id"],
            "site_id": row["site_id"],
            "occurred_at": row["occurred_at"],
            "location_text": row["location_text"],
            "public_summary": row["public_summary"],
            "evidence": json.loads(row["evidence_json"]),
            "evidence_fingerprint": row["evidence_fingerprint"],
            "reporter_id": row["reporter_id"],
            "received_at": row["received_at"],
            "is_late": bool(row["is_late"]),
            "late_kind": row["late_kind"],
        }
        allowed = actor is not None and (
            actor.actor_id == row["reporter_id"] or actor.role in SENSITIVE_ROLES
        )
        data["health_info"] = row["health_info"] if allowed else None
        data["contact_info"] = row["contact_info"] if allowed else None
        return data

    def _append_linked_event(self, connection, *, incident_id: str | None, actor_id: str, action: str,
                             resource_type: str, resource_id: str, detail: dict[str, Any]) -> None:
        """追加审计事件，并（如有事件归属）登记因果链关联。"""

        event = append_event(connection, actor_id=actor_id, action=action,
                             resource_type=resource_type, resource_id=resource_id,
                             detail=detail, occurred_at=self._now())
        if incident_id:
            sequence = connection.execute(
                "SELECT sequence FROM audit_events WHERE event_id=?", (event["event_id"],)
            ).fetchone()["sequence"]
            connection.execute(
                "INSERT OR IGNORE INTO incident_audit_links(incident_id,sequence) VALUES(?,?)",
                (incident_id, sequence),
            )

    def _link_resource(self, connection, incident_id: str, resource_type: str, resource_id: str) -> None:
        """把已存在的审计事件补关联到事件（用于合并时回溯报告存档事件）。"""

        connection.execute(
            "INSERT OR IGNORE INTO incident_audit_links(incident_id,sequence) "
            "SELECT ?, sequence FROM audit_events WHERE resource_type=? AND resource_id=?",
            (incident_id, resource_type, resource_id),
        )

    def _propose_candidates(self, connection, report_row) -> list[str]:
        """关联规则：对同一站点下的其他报告提出合并候选。

        比对范围既包括尚未归属事件的报告（可能共同组成新事件），也包括已归属
        事件的报告（新报告可并入既有事件）。规则只提候选，绝不自动合并；
        分属不同事件时由指挥通过拒绝候选处理。返回新建候选编号。
        """

        candidate_ids: list[str] = []
        others = connection.execute(
            "SELECT * FROM reports WHERE site_id=? AND report_id<>?",
            (report_row["site_id"], report_row["report_id"]),
        ).fetchall()
        new_time = self._parse_ts(report_row["occurred_at"], "occurred_at")

        def existing_candidate(a: str, b: str) -> bool:
            return connection.execute(
                "SELECT 1 FROM merge_candidates WHERE source_report_id=? AND target_report_id=?",
                (min(a, b), max(a, b)),
            ).fetchone() is not None

        for other in others:
            a, b = sorted((report_row["report_id"], other["report_id"]))
            # 已并入同一事件的两份报告不需要再次提出候选
            if report_row["incident_id"] and other["incident_id"] == report_row["incident_id"]:
                continue
            if existing_candidate(a, b):
                continue
            rule = score = None
            if report_row["evidence_fingerprint"] == other["evidence_fingerprint"]:
                rule, score = RULE_SAME_EVIDENCE, 100
            else:
                other_time = self._parse_ts(other["occurred_at"], "occurred_at")
                time_gap = abs(new_time - other_time)
                same_text = self._normalize_summary(report_row["public_summary"]) == \
                    self._normalize_summary(other["public_summary"])
                if time_gap <= timedelta(minutes=NEAR_DUPLICATE_WINDOW_MINUTES) and same_text:
                    rule, score = RULE_NEAR_DUPLICATE, 75
                elif time_gap <= timedelta(minutes=SAME_LOCATION_WINDOW_MINUTES) and \
                        self._normalize_summary(report_row["location_text"]) == \
                        self._normalize_summary(other["location_text"]):
                    rule, score = RULE_SAME_LOCATION, 50
            if rule is None:
                continue
            candidate_id = uuid.uuid4().hex
            if rule == RULE_SAME_EVIDENCE:
                rationale = "证据指纹完全一致"
            elif rule == RULE_NEAR_DUPLICATE:
                rationale = f"相似摘要且发生时间相差不超过 {NEAR_DUPLICATE_WINDOW_MINUTES} 分钟"
            else:
                rationale = (f"地点一致且发生时间相差不超过 {SAME_LOCATION_WINDOW_MINUTES} 分钟，"
                             "可能为同一事件的新事实")
            connection.execute(
                "INSERT INTO merge_candidates(candidate_id,source_report_id,target_report_id,rule_name,score,"
                "status,proposed_by,rationale,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (candidate_id, a, b, rule, score, "proposed", report_row["reporter_id"],
                 rationale, self._now()),
            )
            self._append_linked_event(
                connection, incident_id=None, actor_id="system",
                action="merge_candidate.proposed", resource_type="merge_candidate",
                resource_id=candidate_id,
                detail={"source_report_id": a, "target_report_id": b,
                        "rule_name": rule, "score": score},
            )
            candidate_ids.append(candidate_id)
        return candidate_ids

    @staticmethod
    def _normalize_summary(text: str) -> str:
        return " ".join(str(text).lower().split())

    # ------------------------------------------------------------------
    # 1. 报告独立存档
    # ------------------------------------------------------------------

    def file_report(self, *, request_id: str, actor_id: str, site_id: str, occurred_at: str,
                    location_text: str, public_summary: str, evidence: dict[str, Any],
                    health_info: str = "", contact_info: str = "",
                    is_late: bool = False, late_kind: str | None = None,
                    incident_id: str | None = None) -> Any:
        payload = {"actor_id": actor_id, "site_id": site_id, "occurred_at": occurred_at,
                   "location_text": location_text, "public_summary": public_summary,
                   "evidence": evidence, "health_info": health_info, "contact_info": contact_info,
                   "is_late": is_late, "late_kind": late_kind, "incident_id": incident_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="file_report", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, *REPORT_ROLES)
            site = self._site_row(connection, site_id)
            if actor.organization_id != site["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能向其他组织的场所提交报告")
            self._parse_ts(occurred_at, "occurred_at")
            location_text = self._text(location_text, "location_text", 200)
            public_summary = self._text(public_summary, "public_summary", 500)
            if not isinstance(evidence, dict) or not evidence:
                raise ValidationError("evidence 必须是非空对象")
            fingerprint = digest(evidence)
            linked_incident = None

            if is_late:
                # 迟到报告只能补充证据或发起复开申请，不允许进入普通待合并池
                if late_kind not in (LATE_SUPPLEMENT, LATE_REOPEN):
                    raise ValidationError("迟到报告必须声明 supplement_evidence 或 reopen_application")
                if not incident_id:
                    raise ValidationError("迟到报告必须指向所属事件")
                incident_row = self._incident_row(connection, incident_id)
                linked_incident = incident_id
                if late_kind == LATE_REOPEN and incident_row["status"] != INCIDENT_CLOSED:
                    raise ConflictError("只有已结案事件才能申请复开")
                existing = connection.execute(
                    "SELECT 1 FROM reopen_applications WHERE incident_id=? AND report_id IS NOT NULL AND status=?",
                    (incident_id, REOPEN_PENDING),
                ).fetchone()
                if late_kind == LATE_REOPEN and existing:
                    raise ConflictError("该事件已有待审批的复开申请")

            def create() -> tuple[str, str, dict[str, Any]]:
                report_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO reports(report_id,incident_id,site_id,occurred_at,location_text,public_summary,"
                    "evidence_json,evidence_fingerprint,health_info,contact_info,reporter_id,received_at,"
                    "is_late,late_kind) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (report_id, linked_incident, site_id, occurred_at, location_text, public_summary,
                     canonical_json(evidence), fingerprint, str(health_info or ""), str(contact_info or ""),
                     actor_id, self._now(), 1 if is_late else 0, late_kind),
                )
                detail = {"site_id": site_id, "occurred_at": occurred_at, "location_text": location_text,
                          "evidence_fingerprint": fingerprint, "is_late": bool(is_late)}
                candidate_ids: list[str] = []
                if is_late:
                    if late_kind == LATE_SUPPLEMENT:
                        supplement_id = uuid.uuid4().hex
                        connection.execute(
                            "INSERT INTO evidence_supplements(supplement_id,incident_id,report_id,added_by,created_at)"
                            " VALUES(?,?,?,?,?)",
                            (supplement_id, incident_id, report_id, actor_id, self._now()),
                        )
                        detail["supplement_id"] = supplement_id
                        action_name = "report.evidence_supplemented"
                    else:
                        application_id = uuid.uuid4().hex
                        connection.execute(
                            "INSERT INTO reopen_applications(application_id,incident_id,report_id,requested_by,"
                            "status,reason,created_at) VALUES(?,?,?,?,?,?,?)",
                            (application_id, incident_id, report_id, actor_id, REOPEN_PENDING,
                             "迟到报告申请复开", self._now()),
                        )
                        detail["application_id"] = application_id
                        action_name = "reopen.applied"
                else:
                    action_name = "report.filed"
                    candidate_ids = self._propose_candidates(
                        connection,
                        connection.execute("SELECT * FROM reports WHERE report_id=?", (report_id,)).fetchone(),
                    )
                    detail["merge_candidate_ids"] = candidate_ids
                self._append_linked_event(connection, incident_id=linked_incident, actor_id=actor_id,
                                          action=action_name, resource_type="report",
                                          resource_id=report_id, detail=detail)
                if is_late:
                    self._link_resource(connection, incident_id, "report", report_id)
                response = {"report_id": report_id, "evidence_fingerprint": fingerprint}
                if candidate_ids:
                    response["merge_candidate_ids"] = candidate_ids
                return "report", report_id, response

            return self._idempotent(connection, request_id=request_id, action="file_report",
                                    payload=payload, create=create)

    def get_report(self, report_id: str, actor_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            return self._redact_report(connection, self._report_row(connection, report_id), actor)

    def list_reports(self, site_id: str, actor_id: str) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._site_row(connection, site_id)
            rows = connection.execute(
                "SELECT * FROM reports WHERE site_id=? ORDER BY occurred_at, report_id", (site_id,)
            ).fetchall()
            return [self._redact_report(connection, row, actor) for row in rows]

    # ------------------------------------------------------------------
    # 2. 合并候选与指挥确认
    # ------------------------------------------------------------------

    def list_merge_candidates(self, actor_id: str, status: str = "proposed") -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "commander", "reviewer", "auditor")
            rows = connection.execute(
                "SELECT * FROM merge_candidates WHERE status=? ORDER BY score DESC, created_at", (status,)
            ).fetchall()
            return [dict(row) for row in rows]

    def _resolve_merge(self, connection, candidate_row, actor) -> str:
        """确认合并：必要时新建事件，否则把游离报告并入既有事件。返回事件编号。"""

        source = self._report_row(connection, candidate_row["source_report_id"])
        target = self._report_row(connection, candidate_row["target_report_id"])
        if source["site_id"] != target["site_id"]:
            raise ValidationError("候选报告不属于同一场所")
        site = self._site_row(connection, source["site_id"])
        if actor.organization_id != site["organization_id"]:
            raise PermissionDenied("不能指挥其他组织场所的事件")
        source_incident = source["incident_id"]
        target_incident = target["incident_id"]
        if source_incident and target_incident:
            if source_incident == target_incident:
                raise ConflictError("两份报告已属于同一事件")
            raise ConflictError("候选报告已分属不同事件，不能合并")
        incident_id = source_incident or target_incident
        if incident_id:
            self._require_commander(connection, incident_id, actor)
            loose_report = target["report_id"] if source_incident else source["report_id"]
            connection.execute("UPDATE reports SET incident_id=? WHERE report_id=?",
                               (incident_id, loose_report))
            connection.execute(
                "UPDATE incidents SET version=version+1 WHERE incident_id=?", (incident_id,)
            )
            return incident_id
        incident_id = uuid.uuid4().hex
        now = self._now()
        connection.execute(
            "INSERT INTO incidents(incident_id,site_id,level,status,public_status,current_commander_id,"
            "commander_since,commander_until,created_by,created_at,version) VALUES(?,?,?,?,?,?,?,?,?,?,1)",
            (incident_id, source["site_id"], "standard", INCIDENT_OPEN,
             self._public_text(INCIDENT_OPEN, "standard"), actor.actor_id, now, None,
             actor.actor_id, now),
        )
        connection.execute(
            "UPDATE reports SET incident_id=? WHERE report_id IN (?,?)",
            (incident_id, source["report_id"], target["report_id"]),
        )
        return incident_id

    def confirm_merge(self, *, request_id: str, actor_id: str, candidate_id: str) -> Any:
        payload = {"actor_id": actor_id, "candidate_id": candidate_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                    action="confirm_merge", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "commander")
            candidate = connection.execute(
                "SELECT * FROM merge_candidates WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            if candidate is None:
                raise NotFoundError("合并候选不存在")
            if candidate["status"] != "proposed":
                raise ConflictError("合并候选已经被处理")

            def create() -> tuple[str, str, dict[str, Any]]:
                incident_id = self._resolve_merge(connection, candidate, actor)
                connection.execute(
                    "UPDATE merge_candidates SET status=?,decided_by=?,incident_id=?,decided_at=? "
                    "WHERE candidate_id=?",
                    (CANDIDATE_CONFIRMED, actor_id, incident_id, self._now(), candidate_id),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="merge.confirmed", resource_type="merge_candidate",
                    resource_id=candidate_id,
                    detail={"incident_id": incident_id,
                            "source_report_id": candidate["source_report_id"],
                            "target_report_id": candidate["target_report_id"],
                            "rule_name": candidate["rule_name"]},
                )
                # 报告存档与候选提出这些历史事件补入事件因果链，保持原始报告可单独追查
                self._link_resource(connection, incident_id, "report", candidate["source_report_id"])
                self._link_resource(connection, incident_id, "report", candidate["target_report_id"])
                self._link_resource(connection, incident_id, "merge_candidate", candidate_id)
                return "incident", incident_id, {"incident_id": incident_id, "candidate_id": candidate_id}

            return self._idempotent(connection, request_id=request_id, action="confirm_merge",
                                    payload=payload, create=create)

    def reject_merge(self, *, request_id: str, actor_id: str, candidate_id: str, reason: str) -> Any:
        payload = {"actor_id": actor_id, "candidate_id": candidate_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                    action="reject_merge", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "commander")
            candidate = connection.execute(
                "SELECT * FROM merge_candidates WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            if candidate is None:
                raise NotFoundError("合并候选不存在")
            if candidate["status"] != "proposed":
                raise ConflictError("合并候选已经被处理")
            reason = self._text(reason, "reason")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE merge_candidates SET status=?,decided_by=?,decided_at=? WHERE candidate_id=?",
                    (CANDIDATE_REJECTED, actor_id, self._now(), candidate_id),
                )
                append_event(connection, actor_id=actor_id, action="merge.rejected",
                             resource_type="merge_candidate", resource_id=candidate_id,
                             detail={"reason": reason,
                                     "source_report_id": candidate["source_report_id"],
                                     "target_report_id": candidate["target_report_id"]},
                             occurred_at=self._now())
                return "merge_candidate", candidate_id, {"candidate_id": candidate_id, "status": "rejected"}

            return self._idempotent(connection, request_id=request_id, action="reject_merge",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------
    # 3. 升级：必须引用新的现场事实
    # ------------------------------------------------------------------

    def escalate(self, *, request_id: str, actor_id: str, incident_id: str, to_level: str,
                 reason: str, fact_report_ids: list[str] | None = None,
                 fact_action_ids: list[str] | None = None) -> Any:
        fact_report_ids = fact_report_ids or []
        fact_action_ids = fact_action_ids or []
        payload = {"actor_id": actor_id, "incident_id": incident_id, "to_level": to_level,
                   "reason": reason, "fact_report_ids": fact_report_ids,
                   "fact_action_ids": fact_action_ids}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="escalate", payload=payload)
            if replay is not None:
                return replay
            incident = self._require_commander(connection, incident_id, actor)
            if to_level not in LEVELS:
                raise ValidationError("to_level 不合法")
            if LEVEL_RANK[to_level] <= LEVEL_RANK[incident["level"]]:
                raise ConflictError("升级只能指向更高等级")
            reason = self._text(reason, "reason", 500)
            if not fact_report_ids and not fact_action_ids:
                raise ValidationError("升级必须引用至少一项新的现场事实")
            created_at = self._parse_ts(incident["created_at"], "created_at")
            for report_id in fact_report_ids:
                report = self._report_row(connection, report_id)
                if report["incident_id"] != incident_id:
                    raise ValidationError(f"事实报告 {report_id} 不属于该事件")
                if self._parse_ts(report["received_at"], "received_at") <= created_at:
                    raise ConflictError(f"报告 {report_id} 不是事件建立后到达的新事实")
            for action_id in fact_action_ids:
                action = connection.execute(
                    "SELECT * FROM action_items WHERE action_id=?", (action_id,)
                ).fetchone()
                if action is None:
                    raise NotFoundError(f"行动 {action_id} 不存在")
                if action["incident_id"] != incident_id:
                    raise ValidationError(f"行动 {action_id} 不属于该事件")
                if action["status"] != ACTION_COMPLETED or not action["result_note"]:
                    raise ConflictError(f"行动 {action_id} 尚未形成可引用的现场结果")
            for kind, fact_id in (
                [("report", r) for r in fact_report_ids] + [("action", a) for a in fact_action_ids]
            ):
                used = connection.execute(
                    "SELECT 1 FROM incident_used_facts WHERE incident_id=? AND fact_kind=? AND fact_id=?",
                    (incident_id, kind, fact_id),
                ).fetchone()
                if used:
                    raise ConflictError(f"事实 {fact_id} 已被之前的升级引用，必须引用新事实")

            def create() -> tuple[str, str, dict[str, Any]]:
                escalation_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO escalations(escalation_id,incident_id,from_level,to_level,reason,"
                    "fact_report_ids_json,fact_action_ids_json,requested_by,decided_by,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (escalation_id, incident_id, incident["level"], to_level, reason,
                     canonical_json(fact_report_ids), canonical_json(fact_action_ids),
                     actor_id, actor_id, self._now()),
                )
                for report_id in fact_report_ids:
                    connection.execute(
                        "INSERT INTO incident_used_facts(incident_id,fact_kind,fact_id,used_in)"
                        " VALUES(?,?,?,?)", (incident_id, "report", report_id, escalation_id))
                for action_id in fact_action_ids:
                    connection.execute(
                        "INSERT INTO incident_used_facts(incident_id,fact_kind,fact_id,used_in)"
                        " VALUES(?,?,?,?)", (incident_id, "action", action_id, escalation_id))
                connection.execute(
                    "UPDATE incidents SET level=?,public_status=?,version=version+1 WHERE incident_id=?",
                    (to_level, self._public_text(incident["status"], to_level), incident_id),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="incident.escalated", resource_type="escalation",
                    resource_id=escalation_id,
                    detail={"from_level": incident["level"], "to_level": to_level,
                            "fact_report_ids": fact_report_ids, "fact_action_ids": fact_action_ids},
                )
                return "escalation", escalation_id, {"escalation_id": escalation_id}

            return self._idempotent(connection, request_id=request_id, action="escalate",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------
    # 4. 行动项：责任人始终明确，重启后不悬空
    # ------------------------------------------------------------------

    def create_action(self, *, request_id: str, actor_id: str, incident_id: str,
                      title: str, owner_id: str) -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "title": title,
                   "owner_id": owner_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="create_action", payload=payload)
            if replay is not None:
                return replay
            self._require_commander(connection, incident_id, actor)
            title = self._text(title, "title", 200)
            owner = self._actor(connection, owner_id)

            def create() -> tuple[str, str, dict[str, Any]]:
                action_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO action_items(action_id,incident_id,title,status,owner_id,created_by,created_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (action_id, incident_id, title, ACTION_OPEN, owner_id, actor_id, self._now()),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="action.created", resource_type="action_item", resource_id=action_id,
                    detail={"title": title, "owner_id": owner_id},
                )
                return "action_item", action_id, {"action_id": action_id, "owner_id": owner_id}

            return self._idempotent(connection, request_id=request_id, action="create_action",
                                    payload=payload, create=create)

    def transition_action(self, *, request_id: str, actor_id: str, action_id: str,
                          to_status: str, result_note: str = "") -> Any:
        payload = {"actor_id": actor_id, "action_id": action_id, "to_status": to_status,
                   "result_note": result_note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="transition_action", payload=payload)
            if replay is not None:
                return replay
            row = connection.execute("SELECT * FROM action_items WHERE action_id=?", (action_id,)).fetchone()
            if row is None:
                raise NotFoundError("行动不存在")
            incident = self._incident_row(connection, row["incident_id"])
            if incident["status"] == INCIDENT_CLOSED:
                raise ConflictError("事件已结案，不能变更行动")
            is_commander = actor.actor_id == incident["current_commander_id"]
            if actor.actor_id != row["owner_id"] and not is_commander:
                raise PermissionDenied("只有行动责任人或现任指挥可以变更行动")
            if to_status not in ACTION_TRANSITIONS.get(row["status"], frozenset()):
                raise ConflictError(f"行动不能从 {row['status']} 迁移到 {to_status}")
            if to_status == ACTION_COMPLETED and not str(result_note or "").strip():
                raise ValidationError("完成行动必须记录现场结果")

            def create() -> tuple[str, str, dict[str, Any]]:
                closed_at = self._now() if to_status in (ACTION_COMPLETED, ACTION_CANCELLED) else None
                connection.execute(
                    "UPDATE action_items SET status=?,result_note=?,closed_at=? WHERE action_id=?",
                    (to_status, str(result_note or ""), closed_at, action_id),
                )
                self._append_linked_event(
                    connection, incident_id=row["incident_id"], actor_id=actor_id,
                    action="action.transitioned", resource_type="action_item", resource_id=action_id,
                    detail={"from_status": row["status"], "to_status": to_status},
                )
                return "action_item", action_id, {"action_id": action_id, "status": to_status}

            return self._idempotent(connection, request_id=request_id, action="transition_action",
                                    payload=payload, create=create)

    def reassign_action(self, *, request_id: str, actor_id: str, action_id: str,
                        new_owner_id: str) -> Any:
        payload = {"actor_id": actor_id, "action_id": action_id, "new_owner_id": new_owner_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="reassign_action", payload=payload)
            if replay is not None:
                return replay
            row = connection.execute("SELECT * FROM action_items WHERE action_id=?", (action_id,)).fetchone()
            if row is None:
                raise NotFoundError("行动不存在")
            self._require_commander(connection, row["incident_id"], actor)
            if row["status"] not in ACTION_PENDING_STATUSES:
                raise ConflictError("已结束的行动不必再移交")
            new_owner = self._actor(connection, new_owner_id)
            if new_owner.actor_id == row["owner_id"]:
                raise ValidationError("新责任人与当前责任人相同")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute("UPDATE action_items SET owner_id=? WHERE action_id=?",
                                   (new_owner_id, action_id))
                self._append_linked_event(
                    connection, incident_id=row["incident_id"], actor_id=actor_id,
                    action="action.reassigned", resource_type="action_item", resource_id=action_id,
                    detail={"from_owner_id": row["owner_id"], "to_owner_id": new_owner_id},
                )
                return "action_item", action_id, {"action_id": action_id, "owner_id": new_owner_id}

            return self._idempotent(connection, request_id=request_id, action="reassign_action",
                                    payload=payload, create=create)

    def list_actions(self, incident_id: str, actor_id: str, status: str | None = None) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._incident_row(connection, incident_id)
            query = "SELECT * FROM action_items WHERE incident_id=?"
            params: list[Any] = [incident_id]
            if status:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY created_at, action_id"
            return [dict(row) for row in connection.execute(query, params).fetchall()]

    def startup_recovery(self, actor_id: str | None = None) -> dict[str, Any]:
        """重启后检查执行中的行动是否仍有有效责任人。

        行动行以 NOT NULL 外键持有 owner，全部状态迁移在事务内完成，
        因此持久化层不会出现无主记录；本方法把“责任人已停用”的行动暴露出来，
        指挥需要重新指派，避免执行中的行动变成无人负责的悬空记录。
        """

        with self.database.transaction() as connection:
            if actor_id is not None:
                actor = self._actor(connection, actor_id)
                self._require(actor, "admin", "commander")
            rows = connection.execute(
                "SELECT a.action_id,a.owner_id FROM action_items a "
                "JOIN actors act ON a.owner_id=act.actor_id "
                "WHERE a.status IN ('open','in_progress') AND act.active=0"
            ).fetchall()
            return {"dangling_actions": [{"action_id": r["action_id"], "owner_id": r["owner_id"]}
                                         for r in rows]}

    # ------------------------------------------------------------------
    # 5a. 指挥官注册（commander 是事件模块新增角色，不改动基础角色表）
    # ------------------------------------------------------------------

    def register_commander(self, *, request_id: str, actor_id: str, new_actor_id: str,
                           display_name: str, organization_id: str) -> Any:
        payload = {"actor_id": actor_id, "new_actor_id": new_actor_id,
                   "display_name": display_name, "organization_id": organization_id,
                   "role": "commander"}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="register_commander", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "admin")
            new_actor_id = self._identifier(new_actor_id, "new_actor_id")
            display_name = self._text(display_name, "display_name")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                  (organization_id,)).fetchone() is None:
                raise NotFoundError("组织不存在")

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO actors(actor_id,display_name,role,organization_id,active,created_at)"
                        " VALUES(?,?,?,?,1,?)",
                        (new_actor_id, display_name, "commander", organization_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("操作者编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="commander.registered",
                             resource_type="actor", resource_id=new_actor_id,
                             detail={"display_name": display_name, "organization_id": organization_id},
                             occurred_at=self._now())
                return "actor", new_actor_id, {"actor_id": new_actor_id, "role": "commander"}

            return self._idempotent(connection, request_id=request_id, action="register_commander",
                                    payload=payload, create=create)

    def assign_commander(self, *, request_id: str, actor_id: str, incident_id: str,
                         new_commander_id: str, valid_hours: float) -> Any:
        """指挥权交接期限过期后的恢复入口：仅管理员可重新指派并授予新的期限。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "new_commander_id": new_commander_id, "valid_hours": valid_hours}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="assign_commander", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "admin")
            incident = self._incident_row(connection, incident_id)
            if incident["status"] == INCIDENT_CLOSED:
                raise ConflictError("事件已结案")
            new_commander = self._actor(connection, new_commander_id)
            if new_commander.role != "commander":
                raise ValidationError("被指派人必须具备指挥角色")
            try:
                valid_hours = float(valid_hours)
            except (TypeError, ValueError) as exc:
                raise ValidationError("valid_hours 必须是小时数") from exc
            if not 0.5 <= valid_hours <= MAX_HANDOVER_HOURS:
                raise ValidationError(f"指挥期限必须在 0.5 到 {MAX_HANDOVER_HOURS} 小时之间")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self.clock.now()
                until = now + timedelta(hours=valid_hours)
                fmt = lambda dt: dt.isoformat().replace("+00:00", "Z")
                connection.execute(
                    "UPDATE incidents SET current_commander_id=?,commander_since=?,commander_until=?,"
                    "version=version+1 WHERE incident_id=?",
                    (new_commander_id, fmt(now), fmt(until), incident_id),
                )
                connection.execute(
                    "UPDATE handovers SET status=?,completed_at=? WHERE incident_id=? AND status=?",
                    (HANDOVER_CANCELLED, fmt(now), incident_id, HANDOVER_PROPOSED),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="commander.assigned", resource_type="incident",
                    resource_id=incident_id,
                    detail={"previous_commander_id": incident["current_commander_id"],
                            "new_commander_id": new_commander_id, "commander_until": fmt(until)},
                )
                return "incident", incident_id, {"incident_id": incident_id,
                                                 "current_commander_id": new_commander_id,
                                                 "commander_until": fmt(until)}

            return self._idempotent(connection, request_id=request_id, action="assign_commander",
                                    payload=payload, create=create)


    # ------------------------------------------------------------------
    # 5. 资格与跨专区调援
    # ------------------------------------------------------------------

    def grant_qualification(self, *, request_id: str, actor_id: str, target_actor_id: str,
                            qualification_code: str, valid_until: str) -> Any:
        payload = {"actor_id": actor_id, "target_actor_id": target_actor_id,
                   "qualification_code": qualification_code, "valid_until": valid_until}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="grant_qualification", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "admin")
            target = self._actor(connection, target_actor_id)
            qualification_code = self._identifier(qualification_code, "qualification_code")
            until = self._parse_ts(valid_until, "valid_until")
            if until <= self.clock.now():
                raise ValidationError("资格有效期必须晚于当前时间")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO responder_qualifications(actor_id,qualification_code,valid_until,granted_by,"
                    "created_at) VALUES(?,?,?,?,?) ON CONFLICT(actor_id,qualification_code) DO UPDATE SET "
                    "valid_until=excluded.valid_until,granted_by=excluded.granted_by,created_at=excluded.created_at",
                    (target_actor_id, qualification_code, valid_until, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="qualification.granted",
                             resource_type="actor", resource_id=target_actor_id,
                             detail={"qualification_code": qualification_code, "valid_until": valid_until},
                             occurred_at=self._now())
                return "qualification", f"{target_actor_id}:{qualification_code}", \
                    {"actor_id": target_actor_id, "qualification_code": qualification_code}

            return self._idempotent(connection, request_id=request_id, action="grant_qualification",
                                    payload=payload, create=create)

    def request_support(self, *, request_id: str, actor_id: str, incident_id: str,
                        responder_id: str, qualification_code: str) -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "responder_id": responder_id,
                   "qualification_code": qualification_code}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="request_support", payload=payload)
            if replay is not None:
                return replay
            self._require_commander(connection, incident_id, actor)
            responder = self._actor(connection, responder_id)
            qualification_code = self._identifier(qualification_code, "qualification_code")
            qualification = connection.execute(
                "SELECT * FROM responder_qualifications WHERE actor_id=? AND qualification_code=?",
                (responder_id, qualification_code),
            ).fetchone()
            if qualification is None:
                raise PermissionDenied("被调人员不具备所要求的资格")
            if self._parse_ts(qualification["valid_until"], "valid_until") <= self.clock.now():
                raise PermissionDenied("被调人员资格已过期")

            def create() -> tuple[str, str, dict[str, Any]]:
                # 冻结当时的责任清单：事件下全部未决行动及其责任人，之后不再变化
                pending = connection.execute(
                    "SELECT action_id,title,status,owner_id FROM action_items "
                    "WHERE incident_id=? AND status IN ('open','in_progress') ORDER BY created_at,action_id",
                    (incident_id,),
                ).fetchall()
                snapshot = [dict(row) for row in pending]
                snapshot_hash = digest(snapshot)
                support_id = uuid.uuid4().hex
                frozen_at = self._now()
                connection.execute(
                    "INSERT INTO support_requests(support_id,incident_id,requesting_commander_id,responder_id,"
                    "responder_role,qualification_code,status,responsibility_snapshot_json,snapshot_hash,"
                    "frozen_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (support_id, incident_id, actor_id, responder_id, responder.role, qualification_code,
                     SUPPORT_REQUESTED, canonical_json(snapshot), snapshot_hash, frozen_at, frozen_at),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="support.requested", resource_type="support_request", resource_id=support_id,
                    detail={"responder_id": responder_id, "qualification_code": qualification_code,
                            "snapshot_hash": snapshot_hash, "snapshot_size": len(snapshot)},
                )
                return "support_request", support_id, {"support_id": support_id,
                                                       "snapshot_hash": snapshot_hash}

            return self._idempotent(connection, request_id=request_id, action="request_support",
                                    payload=payload, create=create)

    def _load_support(self, connection, support_id: str):
        row = connection.execute("SELECT * FROM support_requests WHERE support_id=?", (support_id,)).fetchone()
        if row is None:
            raise NotFoundError("调援请求不存在")
        return row

    def fulfill_support(self, *, request_id: str, actor_id: str, support_id: str) -> Any:
        payload = {"actor_id": actor_id, "support_id": support_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="fulfill_support", payload=payload)
            if replay is not None:
                return replay
            support = self._load_support(connection, support_id)
            self._require_commander(connection, support["incident_id"], actor)
            if support["status"] != SUPPORT_REQUESTED:
                raise ConflictError("调援请求不在可履约状态")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE support_requests SET status=?,fulfilled_at=? WHERE support_id=?",
                    (SUPPORT_FULFILLED, self._now(), support_id),
                )
                self._append_linked_event(
                    connection, incident_id=support["incident_id"], actor_id=actor_id,
                    action="support.fulfilled", resource_type="support_request", resource_id=support_id,
                    detail={"responder_id": support["responder_id"]},
                )
                return "support_request", support_id, {"support_id": support_id, "status": SUPPORT_FULFILLED}

            return self._idempotent(connection, request_id=request_id, action="fulfill_support",
                                    payload=payload, create=create)

    def cancel_support(self, *, request_id: str, actor_id: str, support_id: str) -> Any:
        payload = {"actor_id": actor_id, "support_id": support_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="cancel_support", payload=payload)
            if replay is not None:
                return replay
            support = self._load_support(connection, support_id)
            self._require_commander(connection, support["incident_id"], actor)
            if support["status"] != SUPPORT_REQUESTED:
                raise ConflictError("只有待履约的调援请求可以取消")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute("UPDATE support_requests SET status=? WHERE support_id=?",
                                   (SUPPORT_CANCELLED, support_id))
                self._append_linked_event(
                    connection, incident_id=support["incident_id"], actor_id=actor_id,
                    action="support.cancelled", resource_type="support_request", resource_id=support_id,
                    detail={"responder_id": support["responder_id"]},
                )
                return "support_request", support_id, {"support_id": support_id, "status": SUPPORT_CANCELLED}

            return self._idempotent(connection, request_id=request_id, action="cancel_support",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------
    # 6. 有期限的指挥权交接
    # ------------------------------------------------------------------

    def initiate_handover(self, *, request_id: str, actor_id: str, incident_id: str,
                          to_commander_id: str, valid_hours: float, reason: str) -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "to_commander_id": to_commander_id, "valid_hours": valid_hours, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="initiate_handover", payload=payload)
            if replay is not None:
                return replay
            self._require_commander(connection, incident_id, actor)
            to_actor = self._actor(connection, to_commander_id)
            if to_actor.role != "commander":
                raise ValidationError("接管人必须具备指挥角色")
            if to_actor.actor_id == actor.actor_id:
                raise ValidationError("不能把指挥权交接给自己")
            try:
                valid_hours = float(valid_hours)
            except (TypeError, ValueError) as exc:
                raise ValidationError("valid_hours 必须是小时数") from exc
            if not 0.5 <= valid_hours <= MAX_HANDOVER_HOURS:
                raise ValidationError(f"交接期限必须在 0.5 到 {MAX_HANDOVER_HOURS} 小时之间")
            reason = self._text(reason, "reason", 200)
            pending = connection.execute(
                "SELECT 1 FROM handovers WHERE incident_id=? AND status=?",
                (incident_id, HANDOVER_PROPOSED),
            ).fetchone()
            if pending:
                raise ConflictError("已有进行中的交接，需先完成或作废")

            def create() -> tuple[str, str, dict[str, Any]]:
                handover_id = uuid.uuid4().hex
                now = self.clock.now()
                valid_from = now
                valid_until = now + timedelta(hours=valid_hours)
                fmt = lambda dt: dt.isoformat().replace("+00:00", "Z")
                connection.execute(
                    "INSERT INTO handovers(handover_id,incident_id,from_commander_id,to_commander_id,status,"
                    "valid_from,valid_until,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (handover_id, incident_id, actor_id, to_commander_id, HANDOVER_PROPOSED,
                     fmt(valid_from), fmt(valid_until), reason, fmt(now)),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="handover.initiated", resource_type="handover", resource_id=handover_id,
                    detail={"from_commander_id": actor_id, "to_commander_id": to_commander_id,
                            "valid_until": fmt(valid_until)},
                )
                return "handover", handover_id, {"handover_id": handover_id,
                                                 "valid_until": fmt(valid_until)}

            return self._idempotent(connection, request_id=request_id, action="initiate_handover",
                                    payload=payload, create=create)

    def complete_handover(self, *, request_id: str, actor_id: str, handover_id: str) -> Any:
        payload = {"actor_id": actor_id, "handover_id": handover_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="complete_handover", payload=payload)
            if replay is not None:
                return replay
            handover = connection.execute(
                "SELECT * FROM handovers WHERE handover_id=?", (handover_id,)
            ).fetchone()
            if handover is None:
                raise NotFoundError("交接不存在")
            if handover["status"] != HANDOVER_PROPOSED:
                raise ConflictError("交接已经完成")
            if actor.actor_id != handover["to_commander_id"]:
                raise PermissionDenied("只有接管指挥本人可以完成交接")
            incident = self._incident_row(connection, handover["incident_id"])
            if incident["current_commander_id"] != handover["from_commander_id"]:
                raise ConflictError("交接发起后指挥权又发生变化，交接已失效")
            now = self.clock.now()
            if now < self._parse_ts(handover["valid_from"], "valid_from"):
                raise ConflictError("交接尚未到生效时间")
            if now > self._parse_ts(handover["valid_until"], "valid_until"):
                raise ConflictError("交接已超过期限，需要重新发起")

            def create() -> tuple[str, str, dict[str, Any]]:
                fmt_now = self._now()
                connection.execute(
                    "UPDATE handovers SET status=?,completed_at=? WHERE handover_id=?",
                    (HANDOVER_COMPLETED, fmt_now, handover_id),
                )
                connection.execute(
                    "UPDATE incidents SET current_commander_id=?,commander_since=?,commander_until=?,"
                    "version=version+1 WHERE incident_id=?",
                    (actor.actor_id, fmt_now, handover["valid_until"], handover["incident_id"]),
                )
                self._append_linked_event(
                    connection, incident_id=handover["incident_id"], actor_id=actor_id,
                    action="handover.completed", resource_type="handover", resource_id=handover_id,
                    detail={"from_commander_id": handover["from_commander_id"],
                            "to_commander_id": actor.actor_id,
                            "commander_until": handover["valid_until"]},
                )
                return "handover", handover_id, {"handover_id": handover_id, "status": HANDOVER_COMPLETED}

            return self._idempotent(connection, request_id=request_id, action="complete_handover",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------
    # 7. 结案：清空未决行动 + 另一名复核者
    # ------------------------------------------------------------------

    def request_closure(self, *, request_id: str, actor_id: str, incident_id: str, note: str) -> Any:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="request_closure", payload=payload)
            if replay is not None:
                return replay
            self._require_commander(connection, incident_id, actor)
            pending = connection.execute(
                "SELECT COUNT(*) AS count FROM action_items WHERE incident_id=? AND status IN ('open','in_progress')",
                (incident_id,),
            ).fetchone()["count"]
            if pending:
                raise ConflictError("仍有未决行动，必须先清空才能申请结案")
            existing = connection.execute(
                "SELECT 1 FROM closures WHERE incident_id=? AND status=?",
                (incident_id, CLOSURE_PROPOSED),
            ).fetchone()
            if existing:
                raise ConflictError("该事件已有待复核的结案申请")
            note = self._text(note, "note", 500)

            def create() -> tuple[str, str, dict[str, Any]]:
                closure_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO closures(closure_id,incident_id,requested_by,status,note,created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (closure_id, incident_id, actor_id, CLOSURE_PROPOSED, note, self._now()),
                )
                self._append_linked_event(
                    connection, incident_id=incident_id, actor_id=actor_id,
                    action="closure.requested", resource_type="closure", resource_id=closure_id,
                    detail={"note": note},
                )
                return "closure", closure_id, {"closure_id": closure_id, "status": CLOSURE_PROPOSED}

            return self._idempotent(connection, request_id=request_id, action="request_closure",
                                    payload=payload, create=create)

    def review_closure(self, *, request_id: str, actor_id: str, closure_id: str,
                       approved: bool, note: str = "") -> Any:
        payload = {"actor_id": actor_id, "closure_id": closure_id, "approved": approved, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="review_closure", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "reviewer")
            closure = connection.execute("SELECT * FROM closures WHERE closure_id=?", (closure_id,)).fetchone()
            if closure is None:
                raise NotFoundError("结案申请不存在")
            if closure["status"] != CLOSURE_PROPOSED:
                raise ConflictError("结案申请已经被复核")
            if actor.actor_id == closure["requested_by"]:
                raise PermissionDenied("必须由另一名复核者确认，不能自审")
            incident = self._incident_row(connection, closure["incident_id"])
            if actor.organization_id != self._site_row(connection, incident["site_id"])["organization_id"]:
                raise PermissionDenied("不能复核其他组织的事件")

            def create() -> tuple[str, str, dict[str, Any]]:
                status = CLOSURE_CONFIRMED if approved else CLOSURE_REJECTED
                connection.execute(
                    "UPDATE closures SET status=?,reviewed_by=?,note=?,decided_at=? WHERE closure_id=?",
                    (status, actor_id, str(note or closure["note"]), self._now(), closure_id),
                )
                detail = {"approved": bool(approved)}
                if approved:
                    # 确认时再次核验，防止申请后新增行动
                    pending = connection.execute(
                        "SELECT COUNT(*) AS count FROM action_items WHERE incident_id=? "
                        "AND status IN ('open','in_progress')",
                        (closure["incident_id"],),
                    ).fetchone()["count"]
                    if pending:
                        raise ConflictError("仍有未决行动，不能确认结案")
                    connection.execute(
                        "UPDATE incidents SET status=?,public_status=?,closed_at=?,version=version+1 "
                        "WHERE incident_id=?",
                        (INCIDENT_CLOSED, self._public_text(INCIDENT_CLOSED, incident["level"]),
                         self._now(), closure["incident_id"]),
                    )
                self._append_linked_event(
                    connection, incident_id=closure["incident_id"], actor_id=actor_id,
                    action="closure.reviewed", resource_type="closure", resource_id=closure_id,
                    detail=detail,
                )
                return "closure", closure_id, {"closure_id": closure_id, "status": status}

            return self._idempotent(connection, request_id=request_id, action="review_closure",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------
    # 8. 复开审批
    # ------------------------------------------------------------------

    def decide_reopen(self, *, request_id: str, actor_id: str, application_id: str,
                      approved: bool, note: str = "") -> Any:
        payload = {"actor_id": actor_id, "application_id": application_id,
                   "approved": approved, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replayed(connection, request_id=request_id,
                                            action="decide_reopen", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "reviewer")
            application = connection.execute(
                "SELECT * FROM reopen_applications WHERE application_id=?", (application_id,)
            ).fetchone()
            if application is None:
                raise NotFoundError("复开申请不存在")
            if application["status"] != REOPEN_PENDING:
                raise ConflictError("复开申请已经被处理")
            if actor.actor_id == application["requested_by"]:
                raise PermissionDenied("复开必须由其他复核者审批")

            def create() -> tuple[str, str, dict[str, Any]]:
                status = REOPEN_APPROVED if approved else REOPEN_REJECTED
                connection.execute(
                    "UPDATE reopen_applications SET status=?,decided_by=?,reason=?,decided_at=? "
                    "WHERE application_id=?",
                    (status, actor_id, str(note or application["reason"]), self._now(), application_id),
                )
                if approved:
                    connection.execute(
                        "UPDATE incidents SET status=?,public_status=?,closed_at=NULL,version=version+1 "
                        "WHERE incident_id=?",
                        (INCIDENT_REOPENED,
                         self._public_text(INCIDENT_REOPENED,
                                           self._incident_row(connection, application["incident_id"])["level"]),
                         application["incident_id"]),
                    )
                self._append_linked_event(
                    connection, incident_id=application["incident_id"], actor_id=actor_id,
                    action="reopen.decided", resource_type="reopen_application",
                    resource_id=application_id, detail={"approved": bool(approved),
                                                        "report_id": application["report_id"]},
                )
                return "reopen_application", application_id, \
                    {"application_id": application_id, "status": status}

            return self._idempotent(connection, request_id=request_id, action="decide_reopen",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------
    # 9. 查询：事件全貌、对外状态、因果链还原
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str, actor_id: str) -> dict[str, Any]:
        """授权视角的事件全貌，含已脱敏的报告。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            row = self._incident_row(connection, incident_id)
            result = {
                "incident_id": row["incident_id"], "site_id": row["site_id"],
                "level": row["level"], "status": row["status"],
                "public_status": row["public_status"],
                "current_commander_id": row["current_commander_id"],
                "commander_since": row["commander_since"],
                "commander_until": row["commander_until"],
                "created_at": row["created_at"], "closed_at": row["closed_at"],
                "version": row["version"],
            }
            reports = connection.execute(
                "SELECT * FROM reports WHERE incident_id=? ORDER BY occurred_at, report_id",
                (incident_id,),
            ).fetchall()
            result["reports"] = [self._redact_report(connection, r, actor) for r in reports]
            result["actions"] = [dict(r) for r in connection.execute(
                "SELECT action_id,title,status,owner_id,created_by,created_at,closed_at "
                "FROM action_items WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()]
            result["escalations"] = [dict(r) for r in connection.execute(
                "SELECT escalation_id,from_level,to_level,fact_report_ids_json,fact_action_ids_json,"
                "decided_by,created_at FROM escalations WHERE incident_id=? ORDER BY created_at",
                (incident_id,)).fetchall()]
            return result

    def public_incident_status(self, incident_id: str) -> dict[str, Any]:
        """对外状态：只暴露必要信息，隐藏等级理由、健康与联系方式。"""

        with self.database.transaction() as connection:
            row = self._incident_row(connection, incident_id)
            return {"incident_id": row["incident_id"], "status": row["public_status"]}

    def causal_chain(self, incident_id: str, actor_id: str) -> list[dict[str, Any]]:
        """按审计顺序返还原合并、升级、调援、交接、结案的因果链。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "commander", "reviewer", "auditor")
            self._incident_row(connection, incident_id)
            rows = connection.execute(
                "SELECT e.sequence,e.event_id,e.actor_id,e.action,e.resource_type,e.resource_id,"
                "e.detail_json,e.occurred_at FROM audit_events e "
                "JOIN incident_audit_links l ON l.sequence=e.sequence "
                "WHERE l.incident_id=? ORDER BY e.sequence", (incident_id,),
            ).fetchall()
            return [CausalLink(row["sequence"], row["action"], row["resource_type"], row["resource_id"],
                               row["occurred_at"], json.loads(row["detail_json"])).__dict__
                    for row in rows]
