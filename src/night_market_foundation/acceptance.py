"""运行基础服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .incidents import IncidentService
from .service import DomainService
from .storage import Database

CLOCK = FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))


def _run_incident_chain(service: DomainService, incidents: IncidentService) -> dict[str, object]:
    """走完报告、合并、升级、调援、交接、结案与迟到报告的完整链路。"""

    service.register_actor(request_id="req-reviewer", actor_id="admin-001",
                           new_actor_id="reviewer-001", display_name="复核员",
                           role="reviewer", organization_id="org-001")
    service.register_actor(request_id="req-operator2", actor_id="admin-001",
                           new_actor_id="operator-002", display_name="第二值班指挥",
                           role="operator", organization_id="org-001")
    incidents.grant_qualification(request_id="req-qual", actor_id="admin-001",
                                  target_actor_id="operator-002", qualification="medic")
    report_a = incidents.submit_report(
        request_id="req-report-a", actor_id="operator-001", site_id="site-001",
        zone="东区", category="person_discomfort", occurred_at="2026-09-25T07:50:00Z",
        location="东区义诊台", public_summary="一名游客头晕，已搀扶休息",
        evidence_fingerprint="fp-a",
        sensitive={"contact": "13800000000", "health_note": "低血糖史"})
    incidents.submit_report(
        request_id="req-report-b", actor_id="operator-002", site_id="site-001",
        zone="东区", category="person_discomfort", occurred_at="2026-09-25T07:55:00Z",
        location="东区义诊台旁", public_summary="另一志愿者报告同一起头晕事件",
        evidence_fingerprint="fp-b")
    opened = incidents.open_incident(request_id="req-incident", actor_id="operator-001",
                                     report_id=report_a.resource_id, level=1)
    incident_id = opened.resource_id
    candidates = incidents.list_merge_candidates(actor_id="operator-001",
                                                 incident_id=incident_id, status="pending")
    incidents.decide_merge(request_id="req-merge", actor_id="operator-001",
                           candidate_id=candidates[0]["candidate_id"], decision="confirm")
    incidents.escalate(request_id="req-escalation", actor_id="operator-001",
                       incident_id=incident_id, to_level=2, fact_refs=["fp-b"],
                       reason="两人报告同一不适事件，需驻点医护")
    action = incidents.create_action(request_id="req-action", actor_id="operator-001",
                                     incident_id=incident_id, title="联系驻点医护到场",
                                     owner_id="operator-002")
    support = incidents.request_support(request_id="req-support", actor_id="operator-001",
                                        incident_id=incident_id, assignee_id="operator-002",
                                        required_qualifications=["medic"],
                                        note="请医护资格人员支援")
    incidents.update_support(request_id="req-support-ack", actor_id="operator-002",
                             support_id=support.resource_id, action="acknowledge")
    incidents.update_support(request_id="req-support-done", actor_id="operator-002",
                             support_id=support.resource_id, action="complete")
    handover = incidents.initiate_handover(request_id="req-handover", actor_id="operator-001",
                                           incident_id=incident_id,
                                           to_commander_id="operator-002",
                                           expires_at="2026-09-25T09:00:00Z")
    incidents.accept_handover(request_id="req-handover-accept", actor_id="operator-002",
                              handover_id=handover.resource_id)
    incidents.update_action(request_id="req-action-done", actor_id="operator-002",
                            action_id=action.resource_id, status="done")
    closure = incidents.propose_closure(request_id="req-closure", actor_id="operator-002",
                                        incident_id=incident_id)
    incidents.decide_closure(request_id="req-closure-confirm", actor_id="reviewer-001",
                             closure_id=closure.resource_id, decision="confirm")
    late = incidents.submit_report(
        request_id="req-report-c", actor_id="operator-001", site_id="site-001",
        zone="东区", category="person_discomfort", occurred_at="2026-09-25T07:58:00Z",
        location="东区义诊台", public_summary="迟到补充：游客当时血压偏低",
        evidence_fingerprint="fp-c")
    incidents.supplement_evidence(request_id="req-supplement", actor_id="reviewer-001",
                                  incident_id=incident_id, report_id=late.resource_id)
    reopen = incidents.request_reopen(request_id="req-reopen", actor_id="operator-001",
                                      incident_id=incident_id, report_id=late.resource_id,
                                      reason="迟到报告提示需复核处置")
    incidents.decide_reopen(request_id="req-reopen-approve", actor_id="reviewer-001",
                            reopen_id=reopen.resource_id, decision="approve")
    incidents.create_action(request_id="req-action-follow", actor_id="operator-002",
                            incident_id=incident_id, title="复核迟到报告并回访",
                            owner_id="operator-002")
    history = incidents.incident_history(actor_id="reviewer-001", incident_id=incident_id)
    return {"incident_id": incident_id, "history_events": len(history)}


def run() -> dict[str, object]:
    """执行一条完整登记链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "acceptance.sqlite3"
        database = Database(path)
        service = DomainService(database, CLOCK)
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范活动机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="活动负责人", role="operator", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号活动站点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="organizer_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="organizer_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})
        incidents = IncidentService(service)
        incident_result = _run_incident_chain(service, incidents)
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        database.close()

        # 模拟应用重启：重新打开同一数据库，状态与审计链必须完好。
        restarted = Database(path)
        restarted_service = DomainService(restarted, CLOCK)
        restarted_incidents = IncidentService(restarted_service)
        restart_valid, _ = restarted_service.verify_audit()
        open_actions = [
            item for item in restarted_incidents.list_actions(
                actor_id="operator-002", incident_id=str(incident_result["incident_id"]))
            if item["status"] in ("pending", "in_progress")
        ]
        unowned = restarted_incidents.count_unowned_open_actions()
        late_replay = restarted_incidents.submit_report(
            request_id="req-report-c", actor_id="operator-001", site_id="site-001",
            zone="东区", category="person_discomfort", occurred_at="2026-09-25T07:58:00Z",
            location="东区义诊台", public_summary="迟到补充：游客当时血压偏低",
            evidence_fingerprint="fp-c")
        restarted.close()

        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed,
                  "incident_history_events": incident_result["history_events"],
                  "restart_audit_valid": restart_valid,
                  "restart_open_actions": len(open_actions),
                  "unowned_open_actions": unowned,
                  "restart_replay": late_replay.replayed}
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    ok = (result["status"] == "ok" and result["audit_valid"]
          and result["restart_audit_valid"] and result["unowned_open_actions"] == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
