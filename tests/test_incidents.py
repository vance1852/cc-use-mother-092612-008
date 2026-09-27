import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from night_market_foundation.errors import ConflictError, PermissionDenied, ValidationError
from night_market_foundation.incidents import IncidentService
from night_market_foundation.service import DomainService
from night_market_foundation.storage import Database


class MutableClock:
    def __init__(self, value):
        self._value = value

    def now(self):
        return self._value

    def advance(self, **kwargs):
        self._value = self._value + timedelta(**kwargs)


class IncidentServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = MutableClock(datetime(2026, 9, 26, 18, 0, tzinfo=timezone.utc))
        self.foundation = DomainService(self.database, self.clock)
        self.service = IncidentService(self.foundation)
        self.foundation.register_organization(request_id="org", actor_id="bootstrap",
                                              organization_id="o1", name="活动机构一")
        self.foundation.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                       display_name="管理员", role="admin", organization_id="o1")
        self.foundation.register_actor(request_id="op1", actor_id="a1", new_actor_id="op1",
                                       display_name="值班指挥一", role="operator", organization_id="o1")
        self.foundation.register_actor(request_id="op2", actor_id="a1", new_actor_id="op2",
                                       display_name="值班指挥二", role="operator", organization_id="o1")
        self.foundation.register_actor(request_id="rv1", actor_id="a1", new_actor_id="rv1",
                                       display_name="复核员", role="reviewer", organization_id="o1")
        self.foundation.register_actor(request_id="au1", actor_id="a1", new_actor_id="au1",
                                       display_name="审计员", role="auditor", organization_id="o1")
        self.foundation.register_site(request_id="site", actor_id="op1", site_id="s1",
                                      organization_id="o1", name="活动站点", timezone_name="Asia/Shanghai")

    def tearDown(self):
        self.database.close()

    # ---- 测试辅助 ----

    def submit(self, request_id, reporter="op1", zone="东区", category="person_discomfort",
               occurred_at="2026-09-26T17:30:00Z", fingerprint=None, sensitive=None):
        return self.service.submit_report(
            request_id=request_id, actor_id=reporter, site_id="s1", zone=zone,
            category=category, occurred_at=occurred_at, location=f"{zone}义诊台",
            public_summary=f"报告 {request_id}",
            evidence_fingerprint=fingerprint or f"fp-{request_id}",
            sensitive=sensitive)

    def open_incident(self, request_id="open", report_request_id="r1", commander="op1", level=1):
        report = self.submit(report_request_id)
        opened = self.service.open_incident(request_id=request_id, actor_id=commander,
                                            report_id=report.resource_id, level=level)
        return report, opened.resource_id

    def pending_candidate(self, incident_id):
        candidates = self.service.list_merge_candidates(actor_id="op1", incident_id=incident_id,
                                                        status="pending")
        self.assertEqual(1, len(candidates))
        return candidates[0]

    # ---- 报告独立保存与幂等 ----

    def test_report_stored_independently_and_replayed(self):
        first = self.submit("r1", sensitive={"contact": "138", "health_note": "低血糖"})
        replay = self.submit("r1", sensitive={"contact": "138", "health_note": "低血糖"})
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.resource_id, replay.resource_id)
        report = self.service.get_report(report_id=first.resource_id, actor_id="op1")
        self.assertEqual("东区", report["zone"])
        self.assertEqual("2026-09-26T17:30:00Z", report["occurred_at"])
        self.assertEqual("东区义诊台", report["location"])
        self.assertEqual("fp-r1", report["evidence_fingerprint"])

    def test_report_rejects_invalid_category_and_time(self):
        with self.assertRaises(ValidationError):
            self.submit("bad-category", category="unknown")
        with self.assertRaises(ValidationError):
            self.submit("bad-time", occurred_at="2026-09-26 17:30")

    def test_auditor_cannot_submit_report(self):
        with self.assertRaises(PermissionDenied):
            self.submit("auditor-report", reporter="au1")

    # ---- 关联规则与合并确认 ----

    def test_correlation_proposes_and_commander_confirms_merge(self):
        _, incident_id = self.open_incident()
        self.submit("r2", reporter="op2", occurred_at="2026-09-26T17:40:00Z")
        candidate = self.pending_candidate(incident_id)
        self.assertEqual("same_zone_same_category_within_120m", candidate["rule"])
        decided = self.service.decide_merge(request_id="merge", actor_id="op1",
                                            candidate_id=candidate["candidate_id"],
                                            decision="confirm")
        self.assertFalse(decided.replayed)
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual(2, len(incident["reports"]))
        link_types = {report["link_type"] for report in incident["reports"]}
        self.assertEqual({"origin", "merged"}, link_types)

    def test_candidate_not_proposed_outside_window_or_zone(self):
        _, incident_id = self.open_incident()
        self.submit("far-time", occurred_at="2026-09-26T21:00:00Z")
        self.submit("other-zone", zone="西区", occurred_at="2026-09-26T17:35:00Z")
        candidates = self.service.list_merge_candidates(actor_id="op1", incident_id=incident_id)
        self.assertEqual([], candidates)

    def test_merge_requires_duty_commander(self):
        _, incident_id = self.open_incident()
        self.submit("r2", occurred_at="2026-09-26T17:40:00Z")
        candidate = self.pending_candidate(incident_id)
        with self.assertRaises(PermissionDenied):
            self.service.decide_merge(request_id="merge-by-other", actor_id="op2",
                                      candidate_id=candidate["candidate_id"], decision="confirm")
        with self.assertRaises(PermissionDenied):
            self.service.decide_merge(request_id="merge-by-reviewer", actor_id="rv1",
                                      candidate_id=candidate["candidate_id"], decision="confirm")

    def test_reports_remain_traceable_after_merge(self):
        report_one, incident_id = self.open_incident()
        report_two = self.submit("r2", occurred_at="2026-09-26T17:40:00Z")
        candidate = self.pending_candidate(incident_id)
        self.service.decide_merge(request_id="merge", actor_id="op1",
                                  candidate_id=candidate["candidate_id"], decision="confirm")
        first = self.service.get_report(report_id=report_one.resource_id, actor_id="rv1")
        second = self.service.get_report(report_id=report_two.resource_id, actor_id="rv1")
        self.assertEqual(incident_id, first["links"][0]["incident_id"])
        self.assertEqual("origin", first["links"][0]["link_type"])
        self.assertEqual("merged", second["links"][0]["link_type"])
        self.assertEqual("fp-r2", second["evidence_fingerprint"])

    def test_open_incident_rejects_already_linked_report(self):
        report, _ = self.open_incident()
        with self.assertRaises(ConflictError):
            self.service.open_incident(request_id="open-again", actor_id="op1",
                                       report_id=report.resource_id)

    # ---- 升级 ----

    def test_escalation_requires_new_facts(self):
        _, incident_id = self.open_incident()
        self.submit("r2", occurred_at="2026-09-26T17:40:00Z")
        candidate = self.pending_candidate(incident_id)
        self.service.decide_merge(request_id="merge", actor_id="op1",
                                  candidate_id=candidate["candidate_id"], decision="confirm")
        escalated = self.service.escalate(request_id="esc1", actor_id="op1",
                                          incident_id=incident_id, to_level=2,
                                          fact_refs=["fp-r2"], reason="第二人报告同一事件")
        self.assertFalse(escalated.replayed)
        with self.assertRaises(ConflictError):
            self.service.escalate(request_id="esc2", actor_id="op1", incident_id=incident_id,
                                  to_level=3, fact_refs=["fp-r2"], reason="重复引用旧事实")
        with self.assertRaises(ValidationError):
            self.service.escalate(request_id="esc3", actor_id="op1", incident_id=incident_id,
                                  to_level=3, fact_refs=["fp-unknown"], reason="引用不存在的事实")
        with self.assertRaises(ValidationError):
            self.service.escalate(request_id="esc4", actor_id="op1", incident_id=incident_id,
                                  to_level=2, fact_refs=["fp-r1"], reason="等级没有提升")
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual(2, incident["level"])
        self.assertEqual(1, len(incident["escalations"]))

    # ---- 调援 ----

    def test_support_request_checks_qualification_and_freezes_responsibilities(self):
        _, incident_id = self.open_incident()
        action = self.service.create_action(request_id="act1", actor_id="op1",
                                            incident_id=incident_id,
                                            title="联系驻点医护", owner_id="op1")
        with self.assertRaises(PermissionDenied):
            self.service.request_support(request_id="sup-denied", actor_id="op1",
                                         incident_id=incident_id, assignee_id="op2",
                                         required_qualifications=["medic"])
        self.service.grant_qualification(request_id="qual", actor_id="a1",
                                         target_actor_id="op2", qualification="medic")
        with self.assertRaises(PermissionDenied):
            self.service.grant_qualification(request_id="qual-by-op", actor_id="op1",
                                             target_actor_id="op2", qualification="medic")
        support = self.service.request_support(request_id="sup1", actor_id="op1",
                                               incident_id=incident_id, assignee_id="op2",
                                               required_qualifications=["medic"],
                                               note="请医护资格人员支援")
        self.service.update_action(request_id="act1-done", actor_id="op1",
                                   action_id=action.resource_id, status="done")
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        snapshot = incident["support_requests"][0]["responsibility_snapshot"]
        self.assertEqual("op1", snapshot["commander_id"])
        self.assertEqual([action.resource_id],
                         [item["action_id"] for item in snapshot["open_actions"]])
        self.assertEqual("pending", snapshot["open_actions"][0]["status"])
        self.assertEqual("done", incident["actions"][0]["status"])
        self.service.update_support(request_id="sup1-ack", actor_id="op2",
                                    support_id=support.resource_id, action="acknowledge")
        with self.assertRaises(PermissionDenied):
            self.service.update_support(request_id="sup1-cancel", actor_id="op2",
                                        support_id=support.resource_id, action="cancel")
        done = self.service.update_support(request_id="sup1-done", actor_id="op2",
                                           support_id=support.resource_id, action="complete")
        self.assertFalse(done.replayed)

    # ---- 交接 ----

    def test_handover_transfers_command_and_blocks_former_commander(self):
        _, incident_id = self.open_incident()
        action = self.service.create_action(request_id="act1", actor_id="op1",
                                            incident_id=incident_id,
                                            title="现场值守", owner_id="op1")
        handover = self.service.initiate_handover(
            request_id="ho1", actor_id="op1", incident_id=incident_id,
            to_commander_id="op2", expires_at="2026-09-26T19:00:00Z")
        with self.assertRaises(PermissionDenied):
            self.service.accept_handover(request_id="ho1-wrong", actor_id="rv1",
                                         handover_id=handover.resource_id)
        accepted = self.service.accept_handover(request_id="ho1-accept", actor_id="op2",
                                                handover_id=handover.resource_id)
        self.assertFalse(accepted.replayed)
        incident = self.service.get_incident(actor_id="op2", incident_id=incident_id)
        self.assertEqual("op2", incident["commander_id"])
        self.assertEqual("op2", incident["actions"][0]["owner_id"])
        with self.assertRaises(PermissionDenied):
            self.service.escalate(request_id="esc-old", actor_id="op1", incident_id=incident_id,
                                  to_level=2, fact_refs=["fp-r1"], reason="原指挥越权")
        with self.assertRaises(PermissionDenied):
            self.service.create_action(request_id="act-old", actor_id="op1",
                                       incident_id=incident_id, title="原指挥派单", owner_id="op1")
        escalated = self.service.escalate(request_id="esc-new", actor_id="op2",
                                          incident_id=incident_id, to_level=2,
                                          fact_refs=["fp-r1"], reason="新指挥升级")
        self.assertFalse(escalated.replayed)

    def test_handover_expires_after_deadline(self):
        _, incident_id = self.open_incident()
        handover = self.service.initiate_handover(
            request_id="ho1", actor_id="op1", incident_id=incident_id,
            to_commander_id="op2", expires_at="2026-09-26T18:30:00Z")
        self.clock.advance(minutes=31)
        with self.assertRaises(ConflictError):
            self.service.accept_handover(request_id="ho1-late", actor_id="op2",
                                         handover_id=handover.resource_id)
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual("expired", incident["handovers"][0]["status"])
        self.assertEqual("op1", incident["commander_id"])
        follow_up = self.service.initiate_handover(
            request_id="ho2", actor_id="op1", incident_id=incident_id,
            to_commander_id="op2", expires_at="2026-09-26T19:30:00Z")
        self.assertFalse(follow_up.replayed)

    def test_handover_requires_future_deadline_and_command_role(self):
        _, incident_id = self.open_incident()
        with self.assertRaises(ValidationError):
            self.service.initiate_handover(request_id="ho-past", actor_id="op1",
                                           incident_id=incident_id, to_commander_id="op2",
                                           expires_at="2026-09-26T17:00:00Z")
        with self.assertRaises(ValidationError):
            self.service.initiate_handover(request_id="ho-reviewer", actor_id="op1",
                                           incident_id=incident_id, to_commander_id="rv1",
                                           expires_at="2026-09-26T19:00:00Z")

    # ---- 结案 ----

    def test_closure_requires_cleared_actions_and_second_reviewer(self):
        _, incident_id = self.open_incident()
        action = self.service.create_action(request_id="act1", actor_id="op1",
                                            incident_id=incident_id,
                                            title="送医跟进", owner_id="op1")
        with self.assertRaises(ConflictError):
            self.service.propose_closure(request_id="close-early", actor_id="op1",
                                         incident_id=incident_id)
        self.service.update_action(request_id="act1-done", actor_id="op1",
                                   action_id=action.resource_id, status="done")
        closure = self.service.propose_closure(request_id="close1", actor_id="op1",
                                               incident_id=incident_id)
        with self.assertRaises(PermissionDenied):
            self.service.decide_closure(request_id="close1-self", actor_id="op1",
                                        closure_id=closure.resource_id, decision="confirm")
        with self.assertRaises(PermissionDenied):
            self.service.decide_closure(request_id="close1-auditor", actor_id="au1",
                                        closure_id=closure.resource_id, decision="confirm")
        confirmed = self.service.decide_closure(request_id="close1-confirm", actor_id="rv1",
                                                closure_id=closure.resource_id, decision="confirm")
        self.assertFalse(confirmed.replayed)
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual("closed", incident["status"])
        self.assertIsNotNone(incident["closed_at"])

    def test_closure_rejected_when_pending_items_reappear(self):
        _, incident_id = self.open_incident()
        closure = self.service.propose_closure(request_id="close1", actor_id="op1",
                                               incident_id=incident_id)
        self.service.create_action(request_id="act-late", actor_id="op1",
                                   incident_id=incident_id, title="新增未决行动", owner_id="op1")
        self.service.decide_closure(request_id="close1-confirm", actor_id="rv1",
                                    closure_id=closure.resource_id, decision="confirm")
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual("open", incident["status"])
        self.assertEqual("rejected", incident["closures"][0]["status"])

    def test_self_review_is_blocked_even_for_admin_commander(self):
        report = self.submit("r1")
        opened = self.service.open_incident(request_id="open-admin", actor_id="a1",
                                            report_id=report.resource_id)
        closure = self.service.propose_closure(request_id="close-admin", actor_id="a1",
                                               incident_id=opened.resource_id)
        with self.assertRaises(PermissionDenied):
            self.service.decide_closure(request_id="close-admin-self", actor_id="a1",
                                        closure_id=closure.resource_id, decision="confirm")

    # ---- 迟到报告 ----

    def close_incident(self, incident_id, commander="op1", suffix=""):
        closure = self.service.propose_closure(request_id=f"close{suffix}", actor_id=commander,
                                               incident_id=incident_id)
        self.service.decide_closure(request_id=f"close-confirm{suffix}", actor_id="rv1",
                                    closure_id=closure.resource_id, decision="confirm")

    def test_late_report_can_only_supplement_or_reopen(self):
        _, incident_id = self.open_incident()
        self.close_incident(incident_id)
        late = self.submit("late1", occurred_at="2026-09-26T17:45:00Z")
        candidates = self.service.list_merge_candidates(actor_id="op1", incident_id=incident_id)
        self.assertEqual([], [item for item in candidates if item["status"] == "pending"])
        with self.assertRaises(ConflictError):
            self.service.create_action(request_id="act-closed", actor_id="op1",
                                       incident_id=incident_id, title="结案后派单", owner_id="op1")
        supplemented = self.service.supplement_evidence(request_id="supp1", actor_id="rv1",
                                                        incident_id=incident_id,
                                                        report_id=late.resource_id)
        self.assertFalse(supplemented.replayed)
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual("closed", incident["status"])
        self.assertEqual("supplementary", incident["reports"][-1]["link_type"])
        reopen = self.service.request_reopen(request_id="reopen1", actor_id="op1",
                                             incident_id=incident_id,
                                             report_id=late.resource_id,
                                             reason="迟到报告提示处置需复核")
        with self.assertRaises(PermissionDenied):
            self.service.decide_reopen(request_id="reopen1-op", actor_id="op1",
                                       reopen_id=reopen.resource_id, decision="approve")
        self.service.decide_reopen(request_id="reopen1-ok", actor_id="rv1",
                                   reopen_id=reopen.resource_id, decision="approve")
        incident = self.service.get_incident(actor_id="op1", incident_id=incident_id)
        self.assertEqual("open", incident["status"])
        self.assertIsNone(incident["closed_at"])

    def test_supplement_rejected_while_incident_open(self):
        _, incident_id = self.open_incident()
        extra = self.submit("extra", zone="西区")
        with self.assertRaises(ConflictError):
            self.service.supplement_evidence(request_id="supp-open", actor_id="op1",
                                             incident_id=incident_id,
                                             report_id=extra.resource_id)

    # ---- 敏感信息与对外状态 ----

    def test_sensitive_fields_only_for_authorized_roles(self):
        report = self.submit("r1", sensitive={"contact": "13800000000",
                                              "health_note": "低血糖史"})
        operator_view = self.service.get_report(report_id=report.resource_id, actor_id="op1")
        self.assertEqual("13800000000", operator_view["sensitive"]["contact"])
        reviewer_view = self.service.get_report(report_id=report.resource_id, actor_id="rv1")
        self.assertNotIn("sensitive", reviewer_view)
        self.assertEqual("op1", reviewer_view["reporter_id"])
        public_view = self.service.get_report(report_id=report.resource_id)
        self.assertNotIn("sensitive", public_view)
        self.assertNotIn("reporter_id", public_view)

    def test_public_status_hides_internal_details(self):
        _, incident_id = self.open_incident()
        status = self.service.public_status(incident_id=incident_id)
        self.assertEqual({"incident_id", "site_id", "zone", "category", "level",
                          "status", "public_summary", "report_count"}, set(status))
        self.assertEqual(1, status["report_count"])

    # ---- 因果链 ----

    def test_history_reconstructs_causal_chain(self):
        _, incident_id = self.open_incident()
        self.submit("r2", occurred_at="2026-09-26T17:40:00Z")
        candidate = self.pending_candidate(incident_id)
        self.service.decide_merge(request_id="merge", actor_id="op1",
                                  candidate_id=candidate["candidate_id"], decision="confirm")
        self.service.escalate(request_id="esc", actor_id="op1", incident_id=incident_id,
                              to_level=2, fact_refs=["fp-r2"], reason="需要医护")
        self.service.grant_qualification(request_id="qual", actor_id="a1",
                                         target_actor_id="op2", qualification="medic")
        support = self.service.request_support(request_id="sup", actor_id="op1",
                                               incident_id=incident_id, assignee_id="op2",
                                               required_qualifications=["medic"])
        self.service.update_support(request_id="sup-done", actor_id="op2",
                                    support_id=support.resource_id, action="complete")
        handover = self.service.initiate_handover(
            request_id="ho", actor_id="op1", incident_id=incident_id,
            to_commander_id="op2", expires_at="2026-09-26T19:00:00Z")
        self.service.accept_handover(request_id="ho-accept", actor_id="op2",
                                     handover_id=handover.resource_id)
        self.close_incident(incident_id, commander="op2")
        history = self.service.incident_history(actor_id="rv1", incident_id=incident_id)
        actions = [event["action"] for event in history]
        expected_order = [
            "incident_report.submitted", "incident.opened", "incident_report.submitted",
            "incident.merge_proposed", "incident.merge_confirmed", "incident.escalated",
            "incident.support_requested", "incident.support_updated",
            "incident.handover_initiated", "incident.handover_completed",
            "incident.closure_proposed", "incident.closed",
        ]
        positions = []
        for expected in expected_order:
            index = next(i for i, action in enumerate(actions)
                         if action == expected and i not in positions)
            positions.append(index)
        self.assertEqual(sorted(positions), positions)
        proposer = next(event for event in history if event["action"] == "incident.merge_proposed")
        self.assertEqual("correlation-rule", proposer["actor_id"])
        confirmer = next(event for event in history if event["action"] == "incident.merge_confirmed")
        self.assertEqual("op1", confirmer["actor_id"])
        sequences = [event["sequence"] for event in history]
        self.assertEqual(sorted(sequences), sequences)

    # ---- 重启安全 ----

    def test_restart_preserves_actions_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "incident.sqlite3")
            database = Database(path)
            clock = MutableClock(datetime(2026, 9, 26, 18, 0, tzinfo=timezone.utc))
            foundation = DomainService(database, clock)
            service = IncidentService(foundation)
            foundation.register_organization(request_id="org", actor_id="bootstrap",
                                             organization_id="o1", name="活动机构一")
            foundation.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                      display_name="管理员", role="admin", organization_id="o1")
            foundation.register_actor(request_id="op1", actor_id="a1", new_actor_id="op1",
                                      display_name="值班指挥", role="operator", organization_id="o1")
            foundation.register_site(request_id="site", actor_id="op1", site_id="s1",
                                     organization_id="o1", name="活动站点",
                                     timezone_name="Asia/Shanghai")
            report = service.submit_report(request_id="r1", actor_id="op1", site_id="s1",
                                           zone="东区", category="lost_item",
                                           occurred_at="2026-09-26T17:30:00Z",
                                           location="东区入口", public_summary="游客遗失药箱",
                                           evidence_fingerprint="fp-r1")
            opened = service.open_incident(request_id="open", actor_id="op1",
                                           report_id=report.resource_id)
            action = service.create_action(request_id="act", actor_id="op1",
                                           incident_id=opened.resource_id,
                                           title="广播寻物", owner_id="op1")
            service.update_action(request_id="act-start", actor_id="op1",
                                  action_id=action.resource_id, status="in_progress")
            database.close()

            restarted = Database(path)
            restarted_foundation = DomainService(restarted, clock)
            restarted_service = IncidentService(restarted_foundation)
            actions = restarted_service.list_actions(actor_id="op1",
                                                     incident_id=opened.resource_id)
            self.assertEqual(1, len(actions))
            self.assertEqual("in_progress", actions[0]["status"])
            self.assertEqual("op1", actions[0]["owner_id"])
            self.assertEqual(0, restarted_service.count_unowned_open_actions())
            valid, _ = restarted_foundation.verify_audit()
            self.assertTrue(valid)
            replay = restarted_service.submit_report(
                request_id="r1", actor_id="op1", site_id="s1", zone="东区",
                category="lost_item", occurred_at="2026-09-26T17:30:00Z",
                location="东区入口", public_summary="游客遗失药箱",
                evidence_fingerprint="fp-r1")
            self.assertTrue(replay.replayed)
            self.assertEqual(report.resource_id, replay.resource_id)
            restarted.close()


if __name__ == "__main__":
    unittest.main()
