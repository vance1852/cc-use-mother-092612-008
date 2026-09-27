import unittest
from datetime import datetime, timedelta, timezone

from night_market_foundation.clock import FixedClock
from night_market_foundation.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from night_market_foundation.incident_service import IncidentService
from night_market_foundation.storage import Database


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


class IncidentTestBase(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(datetime(2026, 9, 27, 10, 0, tzinfo=timezone.utc))
        self.database = Database()
        self.service = IncidentService(self.database, self.clock)
        s = self.service
        s.register_organization(request_id="org", actor_id="bootstrap",
                                organization_id="o1", name="夜市主办方")
        s.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                         display_name="管理员", role="admin", organization_id="o1")
        s.register_site(request_id="site", actor_id="a1", site_id="s1",
                        organization_id="o1", name="主会场", timezone_name="Asia/Shanghai")
        s.register_commander(request_id="c1", actor_id="a1", new_actor_id="c1",
                             display_name="值班指挥", organization_id="o1")
        s.register_commander(request_id="c2", actor_id="a1", new_actor_id="c2",
                             display_name="接班指挥", organization_id="o1")
        s.register_actor(request_id="v1", actor_id="a1", new_actor_id="v1",
                         display_name="志愿者甲", role="operator", organization_id="o1")
        s.register_actor(request_id="v2", actor_id="a1", new_actor_id="v2",
                         display_name="志愿者乙", role="operator", organization_id="o1")
        s.register_actor(request_id="r1", actor_id="a1", new_actor_id="r1",
                         display_name="复核员", role="reviewer", organization_id="o1")
        self.t0 = datetime(2026, 9, 27, 10, 5, tzinfo=timezone.utc)

    def tearDown(self):
        self.database.close()

    def file_pair(self, evidence=None):
        self.clock._value = self.t0
        r1 = self.service.file_report(
            request_id="rep1", actor_id="v1", site_id="s1", occurred_at=iso(self.t0),
            location_text="A区", public_summary="有人不适", evidence=evidence or {"p": 1},
            health_info="隐私", contact_info="电话")
        self.clock._value = self.t0 + timedelta(minutes=2)
        r2 = self.service.file_report(
            request_id="rep2", actor_id="v1", site_id="s1", occurred_at=iso(self.t0 + timedelta(minutes=1)),
            location_text="A区", public_summary="有人不适", evidence=evidence or {"p": 1})
        return r1, r2

    def merged_incident(self):
        self.file_pair()
        candidate = self.service.list_merge_candidates("c1")[0]["candidate_id"]
        return self.service.confirm_merge(request_id="merge1", actor_id="c1",
                                         candidate_id=candidate).resource_id


class ReportAndMergeTest(IncidentTestBase):
    def test_reports_independent_until_commander_confirms(self):
        r1, r2 = self.file_pair()
        candidates = self.service.list_merge_candidates("c1")
        self.assertEqual(1, len(candidates))
        self.assertEqual("proposed", candidates[0]["status"])
        self.assertIsNone(self.service.get_report(r1.resource_id, "v1")["incident_id"])
        candidate = candidates[0]["candidate_id"]
        self.service.reject_merge(request_id="rj", actor_id="c1", candidate_id=candidate,
                                  reason="判断为两件事")
        # 拒绝后两份报告仍独立可查，事件从未创建
        self.assertIsNone(self.service.get_report(r1.resource_id, "v1")["incident_id"])
        self.assertIsNone(self.service.get_report(r2.resource_id, "v1")["incident_id"])

    def test_operator_cannot_confirm_merge(self):
        self.file_pair()
        candidate = self.service.list_merge_candidates("c1")[0]["candidate_id"]
        with self.assertRaises(PermissionDenied):
            self.service.confirm_merge(request_id="deny", actor_id="v1", candidate_id=candidate)

    def test_confirmed_candidate_cannot_be_processed_again(self):
        incident_id = self.merged_incident()
        candidates = self.service.list_merge_candidates("c1", status="confirmed")
        with self.assertRaises(ConflictError):
            self.service.confirm_merge(request_id="m2", actor_id="c1",
                                       candidate_id=candidates[0]["candidate_id"])
        self.assertIn(incident_id, candidates[0]["incident_id"])

    def test_original_report_remains_traceable_after_merge(self):
        r1, _ = self.file_pair()
        incident_id = self.merged_incident()
        report = self.service.get_report(r1.resource_id, "c1")
        self.assertEqual(incident_id, report["incident_id"])
        self.assertEqual({"p": 1}, report["evidence"])
        self.assertTrue(report["evidence_fingerprint"])

    def test_late_report_must_target_closed_or_open_incident_with_mode(self):
        with self.assertRaises(ValidationError):
            self.service.file_report(
                request_id="late", actor_id="v1", site_id="s1", occurred_at=iso(self.t0),
                location_text="A区", public_summary="迟到", evidence={"x": 1},
                is_late=True)  # type: ignore[call-arg]

    def test_reopen_application_only_for_closed_incident(self):
        incident_id = self.merged_incident()
        with self.assertRaises(ConflictError):
            self.service.file_report(
                request_id="late", actor_id="v1", site_id="s1", occurred_at=iso(self.t0),
                location_text="A区", public_summary="申请复开", evidence={"x": 1},
                is_late=True, late_kind="reopen_application", incident_id=incident_id)


class PrivacyTest(IncidentTestBase):
    def test_sensitive_fields_visible_by_role(self):
        r1, _ = self.file_pair()
        self.assertEqual("隐私", self.service.get_report(r1.resource_id, "v1")["health_info"])
        self.assertEqual("隐私", self.service.get_report(r1.resource_id, "c1")["health_info"])
        self.assertEqual("隐私", self.service.get_report(r1.resource_id, "r1")["health_info"])
        self.assertIsNone(self.service.get_report(r1.resource_id, "v2")["health_info"])
        self.assertIsNone(self.service.get_report(r1.resource_id, "v2")["contact_info"])

    def test_public_status_hides_details(self):
        incident_id = self.merged_incident()
        payload = self.service.public_incident_status(incident_id)
        self.assertEqual({"incident_id", "status"}, set(payload))
        self.assertNotIn("level", payload)


class EscalationTest(IncidentTestBase):
    def _completed_action_with_result(self, incident_id):
        action = self.service.create_action(request_id="act", actor_id="c1",
                                            incident_id=incident_id, title="处置", owner_id="v1")
        self.service.transition_action(request_id="actp", actor_id="v1",
                                       action_id=action.resource_id, to_status="in_progress")
        self.service.transition_action(request_id="actd", actor_id="v1",
                                       action_id=action.resource_id, to_status="completed",
                                       result_note="现场结果：情况恶化")
        return action.resource_id

    def test_escalation_requires_new_fact(self):
        incident_id = self.merged_incident()
        with self.assertRaises(ValidationError):
            self.service.escalate(request_id="esc", actor_id="c1", incident_id=incident_id,
                                  to_level="elevated", reason="无事实")

    def test_escalation_with_completed_action_fact(self):
        incident_id = self.merged_incident()
        action_id = self._completed_action_with_result(incident_id)
        self.service.escalate(request_id="esc", actor_id="c1", incident_id=incident_id,
                              to_level="elevated", reason="情况变化",
                              fact_action_ids=[action_id])
        self.assertEqual("elevated", self.service.get_incident(incident_id, "c1")["level"])

    def test_same_fact_cannot_support_two_escalations(self):
        incident_id = self.merged_incident()
        action_id = self._completed_action_with_result(incident_id)
        self.service.escalate(request_id="esc1", actor_id="c1", incident_id=incident_id,
                              to_level="elevated", reason="第一次", fact_action_ids=[action_id])
        with self.assertRaises(ConflictError):
            self.service.escalate(request_id="esc2", actor_id="c1", incident_id=incident_id,
                                  to_level="critical", reason="复用事实",
                                  fact_action_ids=[action_id])

    def test_cannot_downgrade(self):
        incident_id = self.merged_incident()
        with self.assertRaises(ConflictError):
            self.service.escalate(request_id="esc", actor_id="c1", incident_id=incident_id,
                                  to_level="standard", reason="平级", fact_report_ids=[])


class SupportTest(IncidentTestBase):
    def test_qualification_verified_before_support(self):
        incident_id = self.merged_incident()
        with self.assertRaises(PermissionDenied):
            self.service.request_support(request_id="sup", actor_id="c1", incident_id=incident_id,
                                         responder_id="v1", qualification_code="first_aid")

    def test_expired_qualification_rejected(self):
        incident_id = self.merged_incident()
        self.service.grant_qualification(
            request_id="qual", actor_id="a1", target_actor_id="v2", qualification_code="first_aid",
            valid_until=iso(self.clock.now() + timedelta(hours=1)))
        self.clock._value = self.clock.now() + timedelta(hours=2)
        with self.assertRaises(PermissionDenied):
            self.service.request_support(request_id="sup", actor_id="c1", incident_id=incident_id,
                                         responder_id="v2", qualification_code="first_aid")

    def test_support_freezes_responsibility_snapshot(self):
        incident_id = self.merged_incident()
        self.service.create_action(request_id="a1", actor_id="c1", incident_id=incident_id,
                                   title="任务一", owner_id="v1")
        self.service.grant_qualification(
            request_id="qual", actor_id="a1", target_actor_id="v2", qualification_code="first_aid",
            valid_until=iso(self.clock.now() + timedelta(days=1)))
        receipt = self.service.request_support(request_id="sup", actor_id="c1",
                                               incident_id=incident_id, responder_id="v2",
                                               qualification_code="first_aid")
        self.assertTrue(receipt.resource_id)
        row = self.database.connection.execute(
            "SELECT * FROM support_requests WHERE support_id=?", (receipt.resource_id,)).fetchone()
        self.assertEqual(1, __import__("json").loads(row["responsibility_snapshot_json"]).__len__())
        self.assertTrue(row["snapshot_hash"])


class HandoverTest(IncidentTestBase):
    def _handover(self, incident_id):
        return self.service.initiate_handover(request_id="ho", actor_id="c1",
                                              incident_id=incident_id, to_commander_id="c2",
                                              valid_hours=2, reason="换班")

    def test_only_successor_completes_handover(self):
        incident_id = self.merged_incident()
        h = self._handover(incident_id)
        with self.assertRaises(PermissionDenied):
            self.service.complete_handover(request_id="hoc", actor_id="c1",
                                           handover_id=h.resource_id)
        self.service.complete_handover(request_id="ho2", actor_id="c2",
                                       handover_id=h.resource_id)
        with self.assertRaises(PermissionDenied):
            self.service.create_action(request_id="act", actor_id="c1", incident_id=incident_id,
                                       title="原指挥行动", owner_id="v1")

    def test_expired_commander_cannot_decide(self):
        incident_id = self.merged_incident()
        h = self._handover(incident_id)
        self.service.complete_handover(request_id="ho2", actor_id="c2",
                                       handover_id=h.resource_id)
        self.clock._value = self.clock.now() + timedelta(hours=3)
        with self.assertRaises(PermissionDenied):
            self.service.create_action(request_id="act", actor_id="c2", incident_id=incident_id,
                                       title="超期行动", owner_id="v1")
        # 管理员可重新指派恢复指挥
        self.service.assign_commander(request_id="assign", actor_id="a1", incident_id=incident_id,
                                      new_commander_id="c2", valid_hours=2)
        self.service.create_action(request_id="act2", actor_id="c2", incident_id=incident_id,
                                   title="恢复后行动", owner_id="v1")


class ClosureTest(IncidentTestBase):
    def _ready_for_closure(self, incident_id):
        action = self.service.create_action(request_id="act", actor_id="c1",
                                            incident_id=incident_id, title="收尾", owner_id="v1")
        self.service.transition_action(request_id="actp", actor_id="v1",
                                       action_id=action.resource_id, to_status="in_progress")
        self.service.transition_action(request_id="actd", actor_id="v1",
                                       action_id=action.resource_id, to_status="cancelled")

    def test_closure_blocked_with_pending_actions(self):
        incident_id = self.merged_incident()
        self.service.create_action(request_id="act", actor_id="c1", incident_id=incident_id,
                                   title="未决", owner_id="v1")
        with self.assertRaises(ConflictError):
            self.service.request_closure(request_id="closure", actor_id="c1",
                                         incident_id=incident_id, note="结案")

    def test_closure_requires_other_reviewer_and_closes(self):
        incident_id = self.merged_incident()
        self._ready_for_closure(incident_id)
        self.service.request_closure(request_id="closure", actor_id="c1", incident_id=incident_id,
                                     note="处置完毕")
        closure_id = self.database.connection.execute(
            "SELECT closure_id FROM closures WHERE status='proposed'").fetchone()[0]
        self.service.review_closure(request_id="creview", actor_id="r1", closure_id=closure_id,
                                    approved=True)
        incident = self.service.get_incident(incident_id, "r1")
        self.assertEqual("closed", incident["status"])
        self.assertEqual("已结案", incident["public_status"])
        with self.assertRaises(ConflictError):
            self.service.create_action(request_id="act", actor_id="c1", incident_id=incident_id,
                                       title="结案后", owner_id="v1")

    def test_rejected_closure_allows_continuation(self):
        incident_id = self.merged_incident()
        self._ready_for_closure(incident_id)
        self.service.request_closure(request_id="closure", actor_id="c1", incident_id=incident_id,
                                     note="申请")
        closure_id = self.database.connection.execute(
            "SELECT closure_id FROM closures WHERE status='proposed'").fetchone()[0]
        self.service.review_closure(request_id="creview", actor_id="r1", closure_id=closure_id,
                                    approved=False, note="仍有隐患")
        self.assertEqual("open", self.service.get_incident(incident_id, "c1")["status"])


class ReopenTest(IncidentTestBase):
    def _closed_incident(self):
        incident_id = self.merged_incident()
        action = self.service.create_action(request_id="act", actor_id="c1",
                                            incident_id=incident_id, title="收尾", owner_id="v1")
        self.service.transition_action(request_id="actp", actor_id="v1",
                                       action_id=action.resource_id, to_status="in_progress")
        self.service.transition_action(request_id="actd", actor_id="v1",
                                       action_id=action.resource_id, to_status="completed",
                                       result_note="完成")
        self.service.request_closure(request_id="closure", actor_id="c1", incident_id=incident_id,
                                     note="完")
        closure_id = self.database.connection.execute(
            "SELECT closure_id FROM closures WHERE status='proposed'").fetchone()[0]
        self.service.review_closure(request_id="creview", actor_id="r1", closure_id=closure_id,
                                    approved=True)
        return incident_id

    def test_late_supplement_does_not_reopen(self):
        incident_id = self._closed_incident()
        self.service.file_report(
            request_id="late", actor_id="v1", site_id="s1", occurred_at=iso(self.t0),
            location_text="A区", public_summary="补证据", evidence={"x": 9},
            is_late=True, late_kind="supplement_evidence", incident_id=incident_id)
        self.assertEqual("closed", self.service.get_incident(incident_id, "c1")["status"])

    def test_reopen_application_flow(self):
        incident_id = self._closed_incident()
        self.service.file_report(
            request_id="late", actor_id="v1", site_id="s1", occurred_at=iso(self.t0),
            location_text="A区", public_summary="复发", evidence={"x": 9},
            is_late=True, late_kind="reopen_application", incident_id=incident_id)
        application_id = self.database.connection.execute(
            "SELECT application_id FROM reopen_applications WHERE status='pending'").fetchone()[0]
        with self.assertRaises(PermissionDenied):
            self.service.decide_reopen(request_id="dec0", actor_id="v1",
                                       application_id=application_id, approved=True)
        self.service.decide_reopen(request_id="dec1", actor_id="r1",
                                   application_id=application_id, approved=True)
        self.assertEqual("reopened", self.service.get_incident(incident_id, "c1")["status"])


class CausalChainTest(IncidentTestBase):
    def test_chain_reconstructs_lifecycle_and_survives_restart(self):
        import tempfile
        from pathlib import Path
        from night_market_foundation.storage import Database as DB
        from night_market_foundation.incident_service import IncidentService as IS

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "t.sqlite3")
            database = DB(path)
            service = IS(database, self.clock)
            service.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="夜市主办方")
            service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                   display_name="管理员", role="admin", organization_id="o1")
            service.register_site(request_id="site", actor_id="a1", site_id="s1",
                                  organization_id="o1", name="主会场", timezone_name="Asia/Shanghai")
            service.register_commander(request_id="c1", actor_id="a1", new_actor_id="c1",
                                       display_name="指挥", organization_id="o1")
            service.register_actor(request_id="v1", actor_id="a1", new_actor_id="v1",
                                   display_name="志愿者", role="operator", organization_id="o1")
            r1 = service.file_report(request_id="r1", actor_id="v1", site_id="s1",
                                     occurred_at=iso(self.t0), location_text="A区",
                                     public_summary="不适", evidence={"p": 1})
            r2 = service.file_report(request_id="r2", actor_id="v1", site_id="s1",
                                     occurred_at=iso(self.t0 + timedelta(minutes=1)),
                                     location_text="A区", public_summary="不适", evidence={"p": 1})
            candidate = service.list_merge_candidates("c1")[0]["candidate_id"]
            service.confirm_merge(request_id="merge1", actor_id="c1", candidate_id=candidate)
            incident_id = service.database.connection.execute(
                "SELECT incident_id FROM incidents").fetchone()[0]
            database.close()

            database2 = DB(path)
            restarted = IS(database2, self.clock)
            chain = [c["action"] for c in restarted.causal_chain(incident_id, "a1")]
            self.assertIn("merge.confirmed", chain)
            incident = restarted.get_incident(incident_id, "c1")
            self.assertEqual(2, len(incident["reports"]))
            self.assertEqual(0, len(restarted.startup_recovery("a1")["dangling_actions"]))
            valid, _ = restarted.verify_audit()
            self.assertTrue(valid)
            database2.close()


if __name__ == "__main__":
    unittest.main()
