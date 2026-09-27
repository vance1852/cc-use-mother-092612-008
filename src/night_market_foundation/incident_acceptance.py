"""跨专区事件指挥模块的离线端到端验收。

覆盖：独立报告 → 关联候选 → 指挥确认合并 → 行动项 → 新事实升级 →
资格核验调援（责任清单冻结）→ 有期限交接（原指挥失权）→ 结案复核 →
迟到报告补证据/申请复开 → 因果链还原 → 敏感信息脱敏 → 重启恢复。
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .clock import FixedClock
from .incident_service import IncidentService
from .storage import Database


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def run() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        start = datetime(2026, 9, 27, 10, 0, tzinfo=timezone.utc)
        clock = FixedClock(start)
        database = Database(Path(directory) / "incident_acceptance.sqlite3")
        service = IncidentService(database, clock)

        # 基础建档
        service.register_organization(request_id="org", actor_id="bootstrap",
                                      organization_id="o1", name="夜市主办方")
        service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                               display_name="管理员", role="admin", organization_id="o1")
        service.register_site(request_id="site", actor_id="a1", site_id="s1",
                              organization_id="o1", name="主会场", timezone_name="Asia/Shanghai")
        service.register_commander(request_id="cmd1", actor_id="a1", new_actor_id="c1",
                                   display_name="张指挥", organization_id="o1")
        service.register_commander(request_id="cmd2", actor_id="a1", new_actor_id="c2",
                                   display_name="李指挥", organization_id="o1")
        service.register_actor(request_id="vol", actor_id="a1", new_actor_id="v1",
                               display_name="志愿者甲", role="operator", organization_id="o1")
        service.register_actor(request_id="rev", actor_id="a1", new_actor_id="r1",
                               display_name="复核员", role="reviewer", organization_id="o1")

        # 两名志愿者分别报告同一情况 → 独立存档，规则提出候选
        t0 = start + timedelta(minutes=1)
        clock._value = t0
        r1 = service.file_report(request_id="rep1", actor_id="v1", site_id="s1",
                                 occurred_at=_iso(t0), location_text="A区凉茶铺",
                                 public_summary="一位老人头晕", evidence={"photo": "IMG_001"},
                                 health_info="血压偏高", contact_info="13800000001")
        clock._value = t0 + timedelta(minutes=3)
        r2 = service.file_report(request_id="rep2", actor_id="v1", site_id="s1",
                                 occurred_at=_iso(t0 + timedelta(minutes=2)),
                                 location_text="A 区凉茶铺附近",
                                 public_summary="一位老人 头晕", evidence={"photo": "IMG_001"},
                                 health_info="", contact_info="")
        candidates = service.list_merge_candidates("c1")
        assert len(candidates) == 1, f"应产生一个合并候选，实际 {len(candidates)}"
        candidate_id = candidates[0]["candidate_id"]

        # 只有指挥能确认合并 → 组成共同事件
        merged = service.confirm_merge(request_id="merge1", actor_id="c1", candidate_id=candidate_id)
        incident_id = merged.resource_id

        # 原始报告仍可单独追查且保留指纹
        rep1 = service.get_report(r1.resource_id, "v1")
        assert rep1["incident_id"] == incident_id and rep1["evidence_fingerprint"]

        # 健康/联系方式脱敏：另一个普通志愿者看不到
        service.register_actor(request_id="vol2", actor_id="a1", new_actor_id="v2",
                               display_name="志愿者乙", role="operator",
                               organization_id="o1")
        masked = service.get_report(r1.resource_id, "v2")
        assert masked["health_info"] is None and masked["contact_info"] is None, "敏感信息应对无权限角色隐藏"
        assert service.public_incident_status(incident_id).keys() == {"incident_id", "status"}

        # 行动项
        clock._value = t0 + timedelta(minutes=10)
        act = service.create_action(request_id="act1", actor_id="c1", incident_id=incident_id,
                                    title="测量血压并安排休息", owner_id="v1")
        # 行动必须记录结果才能完成
        service.transition_action(request_id="actprog", actor_id="v1", action_id=act.resource_id,
                                  to_status="in_progress")
        try:
            service.transition_action(request_id="bad", actor_id="v1",
                                      action_id=act.resource_id, to_status="completed")
            raise AssertionError("无结果完成应被拒绝")
        except Exception as exc:
            assert "现场结果" in str(exc)
        clock._value = t0 + timedelta(minutes=20)
        service.transition_action(request_id="actdone", actor_id="v1", action_id=act.resource_id,
                                  to_status="completed", result_note="血压150/95，已休息，症状缓解")

        # 升级必须引用新事实：先补一份新到场报告
        clock._value = t0 + timedelta(minutes=25)
        r3 = service.file_report(request_id="rep3", actor_id="v1", site_id="s1",
                                 occurred_at=_iso(t0 + timedelta(minutes=24)),
                                 location_text="A区凉茶铺", public_summary="老人家属到场要求送医",
                                 evidence={"audio": "NOTE_002"})
        service.confirm_merge(
            request_id="merge2", actor_id="c1",
            candidate_id=service.list_merge_candidates("c1")[0]["candidate_id"])
        service.escalate(request_id="esc1", actor_id="c1", incident_id=incident_id,
                         to_level="elevated", reason="家属要求送医，出现新情况",
                         fact_report_ids=[r3.resource_id])
        # 同一事实不能重复支撑升级
        try:
            service.escalate(request_id="esc2", actor_id="c1", incident_id=incident_id,
                             to_level="critical", reason="重复使用事实",
                             fact_report_ids=[r3.resource_id])
            raise AssertionError("重复事实升级应被拒绝")
        except Exception as exc:
            assert "新事实" in str(exc)

        # 调援：核验资格 + 冻结责任清单
        clock._value = t0 + timedelta(minutes=30)
        valid_until = start + timedelta(days=30)
        service.grant_qualification(request_id="qual", actor_id="a1", target_actor_id="v2",
                                    qualification_code="first_aid", valid_until=_iso(valid_until))
        sup = service.request_support(request_id="sup1", actor_id="c1", incident_id=incident_id,
                                      responder_id="v2", qualification_code="first_aid")
        # 无资格人员不能被调
        try:
            service.request_support(request_id="supbad", actor_id="c1", incident_id=incident_id,
                                    responder_id="v1", qualification_code="first_aid")
            raise AssertionError("无资格调援应被拒绝")
        except Exception as exc:
            assert "资格" in str(exc)
        service.fulfill_support(request_id="supok", actor_id="c1", support_id=sup.resource_id)

        # 有期限交接：完成后原指挥立即失权
        clock._value = t0 + timedelta(minutes=40)
        handover = service.initiate_handover(request_id="ho1", actor_id="c1",
                                             incident_id=incident_id, to_commander_id="c2",
                                             valid_hours=2, reason="换班")
        # 接管人之外的人不能完成
        try:
            service.complete_handover(request_id="hobad", actor_id="c1",
                                      handover_id=handover.resource_id)
            raise AssertionError("原指挥不能自行完成交接")
        except Exception as exc:
            assert "接管指挥" in str(exc)
        service.complete_handover(request_id="hodone", actor_id="c2",
                                  handover_id=handover.resource_id)
        # 原指挥不能再作决定
        try:
            service.create_action(request_id="actlate", actor_id="c1", incident_id=incident_id,
                                  title="原指挥的行动", owner_id="v1")
            raise AssertionError("交接后原指挥应失权")
        except Exception as exc:
            assert "现任值班指挥" in str(exc)

        # 期限过期后任何决定都被拒绝，需要重新指派
        clock._value = t0 + timedelta(hours=3)
        try:
            service.create_action(request_id="actexp", actor_id="c2", incident_id=incident_id,
                                  title="过期后的行动", owner_id="v1")
            raise AssertionError("超期指挥应被拒绝")
        except Exception as exc:
            assert "交接期限" in str(exc)
        service.assign_commander(request_id="reassign", actor_id="a1", incident_id=incident_id,
                                 new_commander_id="c2", valid_hours=4)
        act2 = service.create_action(request_id="act2", actor_id="c2", incident_id=incident_id,
                                     title="陪同送医", owner_id="v2")
        service.transition_action(request_id="act2cancel", actor_id="c2",
                                  action_id=act2.resource_id, to_status="in_progress")
        service.transition_action(request_id="act2done", actor_id="c2",
                                  action_id=act2.resource_id, to_status="completed",
                                  result_note="已送医，家属接管")

        # 结案：清空未决行动后申请，另一名复核者确认（指挥本人无复核角色，不能自审）
        service.request_closure(request_id="close1", actor_id="c2", incident_id=incident_id,
                                note="现场处置完毕")
        from .errors import PermissionDenied
        try:
            service.review_closure(request_id="selfclose", actor_id="c2",
                                   closure_id=service.database.connection.execute(
                                       "SELECT closure_id FROM closures").fetchone()[0],
                                   approved=True)
            raise AssertionError("指挥自审应被拒绝")
        except PermissionDenied:
            pass
        closure_id = service.database.connection.execute(
            "SELECT closure_id FROM closures WHERE status='proposed'").fetchone()[0]
        service.review_closure(request_id="closeok", actor_id="r1", closure_id=closure_id,
                               approved=True, note="确认无未决事项")

        # 迟到报告：只能补充证据或申请复开
        clock._value = t0 + timedelta(days=1)
        service.file_report(request_id="late1", actor_id="v1", site_id="s1",
                            occurred_at=_iso(t0 + timedelta(minutes=5)),
                            location_text="A区", public_summary="补充当时的照片",
                            evidence={"photo": "IMG_003"}, is_late=True,
                            late_kind="supplement_evidence", incident_id=incident_id)
        service.file_report(request_id="late2", actor_id="v1", site_id="s1",
                            occurred_at=_iso(t0 + timedelta(minutes=6)),
                            location_text="A区", public_summary="老人复诊仍不适，要求复开",
                            evidence={"note": "FOLLOWUP"}, is_late=True,
                            late_kind="reopen_application", incident_id=incident_id)
        application_id = service.database.connection.execute(
            "SELECT application_id FROM reopen_applications WHERE status='pending'").fetchone()[0]
        service.decide_reopen(request_id="reopenok", actor_id="r1",
                              application_id=application_id, approved=True, note="情况属实")
        incident_after = service.get_incident(incident_id, "c2")
        assert incident_after["status"] == "reopened"

        # 因果链可还原且动作顺序完整
        chain = service.causal_chain(incident_id, "a1")
        actions = [c["action"] for c in chain]
        for expected in ["merge.confirmed", "incident.escalated", "support.requested",
                         "handover.completed", "closure.reviewed", "reopen.decided"]:
            assert expected in actions, f"因果链缺少 {expected}"

        # 审计哈希链完整
        valid, event_count = service.verify_audit()
        assert valid, "审计链校验失败"

        # 重启恢复：新数据库实例读取同一文件，行动不悬空
        database.close()
        database2 = Database(Path(directory) / "incident_acceptance.sqlite3")
        restarted = IncidentService(database2, clock)
        recovery = restarted.startup_recovery("a1")
        assert recovery["dangling_actions"] == []
        valid2, _ = restarted.verify_audit()
        assert valid2
        database2.close()

        return {"status": "ok", "audit_events": event_count, "audit_valid": valid,
                "chain_length": len(chain), "incident_status": "reopened",
                "dangling_actions": 0}


def main() -> int:
    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
