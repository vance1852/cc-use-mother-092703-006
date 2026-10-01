from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from env_response.clock import FrozenClock
from env_response.errors import Conflict, Forbidden, InvalidState, ValidationFailed
from env_response.service import IncidentService


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 0, 0, tzinfo=timezone.utc))
        self.service = IncidentService(self.connection, self.clock)
        for user_id, role in (
            ("duty", "duty"),
            ("field", "field"),
            ("dispatch", "dispatcher"),
            ("repair", "remediation"),
            ("review", "reviewer"),
            ("audit", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.service.create_incident("duty", {
            "incident_id": "inc-1", "title": "VOC 异常", "contaminant": "voc", "severity": "elevated",
        })

    def tearDown(self) -> None:
        self.connection.close()

    def _evidence(self, ref: str, zones: list[str], *, actor="duty", kind="monitor_alert",
                  finding="positive", note="证据说明", disputes=None, origin="站房") -> dict:
        payload = {
            "source_ref": ref, "kind": kind, "origin": origin, "finding": finding,
            "zones": zones, "reading": {"voc_mg_m3": "6.8"},
            "observed_at": "2026-09-24T08:00:00+08:00", "change_note": note,
        }
        if disputes is not None:
            payload["disputes_refs"] = disputes
        return self.service.record_evidence(actor, "inc-1", payload)

    def test_evidence_versions_expand_and_narrow_with_reasons(self) -> None:
        first = self._evidence("alert-1", ["zone-a", "zone-b"], note="初始告警覆盖 a/b")
        self.assertEqual(first["revision"], 1)
        self.assertEqual(first["added_zones"], ["zone-a", "zone-b"])
        self.assertEqual(first["removed_zones"], [])
        self.assertEqual(first["change_reason"], "初始告警覆盖 a/b")

        expanded = self._evidence("retest-1", ["zone-a", "zone-b", "zone-c"], actor="field",
                                  kind="field_retest", note="现场复测发现下风向 c 异常")
        self.assertEqual(expanded["revision"], 2)
        self.assertEqual(expanded["added_zones"], ["zone-c"])
        self.assertEqual(expanded["zones"], ["zone-a", "zone-b", "zone-c"])

        # 设备校准证明探头漂移，推翻依赖该探头的初告警与复测结论；校准仪器仅确认 c 异常。
        narrowed = self._evidence("calib-1", ["zone-c"], kind="calibration",
                                  note="校准确认 SN-07 探头漂移，原 a/b 读数作废，仅 c 维持",
                                  disputes=["alert-1", "retest-1"])
        self.assertEqual(narrowed["revision"], 3)
        self.assertEqual(narrowed["added_zones"], [])
        self.assertEqual(narrowed["removed_zones"], ["zone-a", "zone-b"])
        self.assertEqual(narrowed["zones"], ["zone-c"])

        snapshot = self.service.snapshot("audit", "inc-1")
        self.assertEqual(snapshot["zones"], ["zone-c"])
        self.assertEqual(snapshot["latest_assessment"]["change_reason"],
                         "校准确认 SN-07 探头漂移，原 a/b 读数作废，仅 c 维持")

    def test_cleared_finding_narrows_zone(self) -> None:
        self._evidence("alert-1", ["zone-a", "zone-b"], note="初始告警")
        cleared = self._evidence("thirdparty-1", ["zone-b"], actor="field", kind="third_party",
                                 finding="cleared", note="第三方实验室复测 b 达标，收窄至 a")
        self.assertEqual(cleared["removed_zones"], ["zone-b"])
        self.assertEqual(cleared["zones"], ["zone-a"])

    def test_unknown_dispute_ref_rejected(self) -> None:
        self._evidence("alert-1", ["zone-a"])
        with self.assertRaises(ValidationFailed):
            self._evidence("calib-1", [], finding="cleared", disputes=["missing-ref"], note="质疑不存在的来源")

    def test_duplicate_source_ref_conflicts(self) -> None:
        self._evidence("alert-1", ["zone-a"])
        with self.assertRaises(Conflict):
            self._evidence("alert-1", ["zone-a"], note="重复来源")

    def test_concurrent_field_records_dedup_by_source_ref(self) -> None:
        result = self.service.submit_field_records("field", "inc-1", [
            {"source_ref": "r-1", "zone_code": "zone-a", "reading": "6.1",
             "observed_at": "2026-09-24T08:00:00+08:00"},
            {"source_ref": "r-2", "zone_code": "zone-a", "reading": "6.2",
             "observed_at": "2026-09-24T08:01:00+08:00"},
        ])
        self.assertEqual(result["inserted_count"], 2)
        retried = self.service.submit_field_records("field", "inc-1", [
            {"source_ref": "r-1", "zone_code": "zone-a", "reading": "9.9",
             "observed_at": "2026-09-24T08:00:00+08:00"},
            {"source_ref": "r-3", "zone_code": "zone-b", "reading": "5.0",
             "observed_at": "2026-09-24T08:02:00+08:00"},
        ])
        self.assertEqual(retried["inserted"], ["r-3"])
        self.assertEqual(retried["deduped_count"], 1)
        self.assertEqual(retried["deduped"][0]["source_ref"], "r-1")
        self.assertEqual(retried["deduped"][0]["first_submitted_by"], "field")
        count = self.connection.execute("SELECT count(*) FROM field_records").fetchone()[0]
        self.assertEqual(count, 3)
        dupes = self.connection.execute("SELECT deduped FROM field_records WHERE source_ref='r-1'").fetchone()[0]
        self.assertEqual(dupes, 1)

    def test_concurrent_threads_dedup_at_database_level(self) -> None:
        # :memory: 无法跨连接共享，使用文件库让多个线程并发提交同一 source_ref。
        with tempfile.TemporaryDirectory() as tmp:
            from env_response.storage import connect
            path = str(Path(tmp) / "threads.sqlite3")
            setup_conn = connect(path)
            setup = IncidentService(setup_conn, self.clock)
            setup.create_user("duty", "duty", "duty")
            setup.create_user("field", "field", "field")
            setup.create_incident("duty", {"incident_id": "inc-t", "title": "t", "contaminant": "voc"})
            setup_conn.close()

            errors: list[Exception] = []

            def worker() -> None:
                conn = connect(path)
                svc = IncidentService(conn, self.clock)
                try:
                    svc.submit_field_records("field", "inc-t", [
                        {"source_ref": "same-ref", "zone_code": "zone-a", "reading": "6.1",
                         "observed_at": "2026-09-24T08:00:00+08:00"},
                    ])
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                finally:
                    conn.close()

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            check = connect(path)
            count = check.execute("SELECT count(*) FROM field_records WHERE source_ref='same-ref'").fetchone()[0]
            deduped = check.execute(
                "SELECT deduped FROM field_records WHERE source_ref='same-ref'").fetchone()[0]
            check.close()
            self.assertEqual(count, 1)
            self.assertEqual(deduped, 7)
            self.assertEqual(errors, [])

    def test_measure_must_target_known_zones(self) -> None:
        self._evidence("alert-1", ["zone-a"])
        with self.assertRaises(ValidationFailed):
            self.service.create_measure("dispatch", "inc-1", {
                "kind": "zone_isolation", "title": "封锁", "zones": ["zone-zzz"], "owner_id": "dispatch"})

    def _prepare_contained(self) -> None:
        self._evidence("alert-1", ["zone-a", "zone-b"])
        self.service.create_measure("dispatch", "inc-1", {
            "kind": "zone_isolation", "title": "封锁 a/b", "zones": ["zone-a", "zone-b"],
            "owner_id": "dispatch", "due_at": "2026-09-24T12:00:00+08:00"})
        self.service.create_task("repair", "inc-1", {
            "task_id": "task-a", "zone_code": "zone-a", "title": "处置 a", "assignee_id": "repair"})
        self.service.create_task("repair", "inc-1", {
            "task_id": "task-b", "zone_code": "zone-b", "title": "处置 b", "assignee_id": "repair"})

    def test_completing_tasks_does_not_lift_controls(self) -> None:
        self._prepare_contained()
        for task_id in ("task-a", "task-b"):
            self.service.start_task("repair", task_id)
            self.service.complete_task("repair", task_id)
        snapshot = self.service.snapshot("duty", "inc-1")
        self.assertEqual(snapshot["state"], "remediating")
        measures = self.service.measures_status("duty", "inc-1")
        self.assertTrue(all(item["state"] == "active" for item in measures["measures"]))

    def test_closure_requires_finished_tasks_per_zone(self) -> None:
        self._prepare_contained()
        self.service.start_task("repair", "task-a")
        self.service.complete_task("repair", "task-a")
        with self.assertRaises(InvalidState):
            self.service.request_closure("repair", "inc-1", "任务 b 未完成")
        self.service.start_task("repair", "task-b")
        self.service.complete_task("repair", "task-b")
        review = self.service.request_closure("repair", "inc-1", "全部完成")
        self.assertEqual(review["state"], "pending")
        # 待复核期间冻结新增证据与措施。
        with self.assertRaises(InvalidState):
            self._evidence("alert-2", ["zone-a"], note="待裁决期间禁止追加")
        with self.assertRaises(InvalidState):
            self.service.create_measure("dispatch", "inc-1", {
                "kind": "resource_dispatch", "title": "加风机", "zones": ["zone-a"],
                "owner_id": "dispatch"})

    def test_only_approved_review_lifts_and_closes(self) -> None:
        self._prepare_contained()
        for task_id in ("task-a", "task-b"):
            self.service.start_task("repair", task_id)
            self.service.complete_task("repair", task_id)
            self.service.verify_task("repair", task_id)
        first = self.service.request_closure("repair", "inc-1", "申请解除")
        rejected = self.service.decide_review("review", first["review_id"], "rejected", "材料不足")
        self.assertEqual(rejected["incident_state"], "remediating")
        self.assertEqual(rejected["lifted_measures"], [])
        self.assertTrue(all(
            item["state"] == "active"
            for item in self.service.measures_status("duty", "inc-1")["measures"]))
        second = self.service.request_closure("repair", "inc-1", "补齐材料")
        approved = self.service.decide_review("review", second["review_id"], "approved", "同意恢复")
        self.assertEqual(approved["incident_state"], "closed")
        self.assertEqual(len(approved["lifted_measures"]), 1)
        measures = self.service.measures_status("audit", "inc-1")
        self.assertTrue(all(item["state"] == "lifted" for item in measures["measures"]))

    def test_reviewer_cannot_request_closure_and_duty_cannot_approve(self) -> None:
        self._prepare_contained()
        with self.assertRaises(Forbidden):
            self.service.request_closure("review", "inc-1", "复核员不能自己申请")
        for task_id in ("task-a", "task-b"):
            self.service.start_task("repair", task_id)
            self.service.complete_task("repair", task_id)
        review = self.service.request_closure("repair", "inc-1", "申请")
        with self.assertRaises(Forbidden):
            self.service.decide_review("duty", review["review_id"], "approved", "值班不能批准")

    def test_reopen_required_to_add_evidence_after_close(self) -> None:
        self._prepare_contained()
        self.service.start_task("repair", "task-a")
        self.service.complete_task("repair", "task-a")
        self.service.start_task("repair", "task-b")
        self.service.complete_task("repair", "task-b")
        review = self.service.request_closure("repair", "inc-1", "申请")
        self.service.decide_review("review", review["review_id"], "approved", "同意")
        with self.assertRaises(InvalidState):
            self._evidence("post-1", ["zone-a"], note="关闭后不能直接加证据")
        self.service.reopen_incident("duty", "inc-1", "夜间反弹")
        self.assertEqual(self.service.snapshot("duty", "inc-1")["state"], "reopened")
        added = self._evidence("post-1", ["zone-a"], note="重开后登记反弹证据")
        self.assertEqual(added["added_zones"], ["zone-a"])

    def test_todos_report_owners_due_times_and_overdue(self) -> None:
        self._prepare_contained()
        self.clock.advance(hours=12)
        todos = self.service.todos("duty", "inc-1")
        self.assertTrue(todos["active_measures"][0]["overdue"])
        self.assertEqual(todos["active_measures"][0]["owner_id"], "dispatch")
        self.assertEqual({task["assignee_id"] for task in todos["open_tasks"]}, {"repair"})
        self.assertEqual(len(todos["open_tasks"]), 2)

    def test_history_contains_full_decision_trace(self) -> None:
        self._evidence("alert-1", ["zone-a"], note="初始")
        self._evidence("retest-1", ["zone-a", "zone-b"], actor="field", kind="field_retest", note="扩大")
        self.service.create_measure("dispatch", "inc-1", {
            "kind": "zone_isolation", "title": "封锁", "zones": ["zone-a", "zone-b"],
            "owner_id": "dispatch"})
        history = self.service.history("audit", "inc-1")
        types = [item["type"] for item in history["timeline"]]
        self.assertIn("incident.created", types)
        self.assertEqual(types.count("assessment"), 2)
        self.assertIn("measure", types)
        assessment = next(item for item in history["timeline"] if item["type"] == "assessment"
                          and item["revision"] == 2)
        self.assertEqual(assessment["added_zones"], ["zone-b"])
        self.assertEqual(assessment["change_reason"], "扩大")
        self.assertGreaterEqual(len(history["audit_log"]), 4)

    def test_optimistic_lock_on_measure_update(self) -> None:
        self._evidence("alert-1", ["zone-a"])
        measure = self.service.create_measure("dispatch", "inc-1", {
            "kind": "zone_isolation", "title": "封锁", "zones": ["zone-a"], "owner_id": "dispatch"})
        self.service.update_measure("dispatch", measure["measure_id"], owner_id="dispatch",
                                    expected_revision=1)
        with self.assertRaises(Conflict):
            self.service.update_measure("dispatch", measure["measure_id"], owner_id="dispatch",
                                        expected_revision=1)

    def test_audit_chain_valid(self) -> None:
        self._evidence("alert-1", ["zone-a"], note="初始")
        chain = self.service.audit_chain("audit")
        self.assertTrue(chain["valid"])
        self.assertGreaterEqual(chain["events"], 2)


if __name__ == "__main__":
    unittest.main()
