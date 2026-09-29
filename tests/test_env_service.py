from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from env_response.clock import FrozenClock
from env_response.errors import Conflict, Forbidden, InvalidState, ValidationFailed
from env_response.service import ResponseService
from env_response.storage import connect


def make_service() -> tuple[sqlite3.Connection, ResponseService, FrozenClock]:
    connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 9, 29, 2, 0, tzinfo=timezone.utc))
    service = ResponseService(connection, clock)
    for user_id, role in (
        ("duty", "duty"),
        ("cmd", "commander"),
        ("rev", "reviewer"),
        ("aud", "auditor"),
    ):
        service.create_user(user_id, user_id, role)
    return connection, service, clock


def seed_world(service: ResponseService) -> None:
    for zone_id, name in (
        ("z-a", "甲车间"),
        ("z-b", "乙车间"),
        ("z-c", "下游泵房"),
    ):
        service.register_zone("cmd", zone_id, name, "workshop", "受管业务")
    service.create_incident("duty", "inc-1", "排口异常", "monitor-1", {"v": 1})


class EvidenceAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service, self.clock = make_service()
        seed_world(self.service)

    def tearDown(self) -> None:
        self.connection.close()

    def _first(self) -> dict:
        return self.service.add_evidence(
            "duty", "inc-1", "SRC-1", "field_retest", "现场复测",
            ["z-a", "z-b"], "major", {"cod": 400},
        )

    def test_first_evidence_forms_initial_assessment(self) -> None:
        result = self._first()
        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["direction"], "initial")
        self.assertEqual(result["affected_zone_ids"], ["z-a", "z-b"])
        self.assertEqual(result["change_reason"], "首份证据形成初始判断")
        status = self.service.incident_status("inc-1")
        self.assertEqual(status["current_assessment"]["severity"], "major")

    def test_expand_and_narrow_must_record_reason_and_diff(self) -> None:
        self._first()
        with self.assertRaises(ValidationFailed):
            self.service.add_evidence(
                "cmd", "inc-1", "SRC-2", "third_party", "扩散分析",
                ["z-a", "z-b", "z-c"], "critical", {"model": "x"},
            )
        expanded = self.service.add_evidence(
            "cmd", "inc-1", "SRC-2", "third_party", "扩散分析",
            ["z-a", "z-b", "z-c"], "critical", {"model": "x"},
            change_note="污染团扩散至下游泵房",
        )
        self.assertEqual(expanded["direction"], "expanded")
        self.assertEqual(expanded["added_zone_ids"], ["z-c"])
        self.assertEqual(expanded["removed_zone_ids"], [])

        narrowed = self.service.add_evidence(
            "cmd", "inc-1", "SRC-3", "calibration", "校准报告",
            [], "minor", {"drift": 80},
            change_note="零点漂移导致泵房读数误报",
            cleared_zone_ids=["z-c"],
        )
        self.assertEqual(narrowed["direction"], "narrowed")
        self.assertEqual(narrowed["added_zone_ids"], [])
        self.assertEqual(narrowed["removed_zone_ids"], ["z-c"])
        self.assertEqual(narrowed["affected_zone_ids"], ["z-a", "z-b"])

        revisions = self.service.assessments("inc-1")
        self.assertEqual([item["revision"] for item in revisions], [1, 2, 3])
        self.assertTrue(all(item["evidence_set_sha256"] for item in revisions))
        self.assertEqual(revisions[2]["basis_evidence_ids"], [1, 2, 3])

    def test_evidence_can_both_add_and_clear_zones(self) -> None:
        self._first()
        result = self.service.add_evidence(
            "cmd", "inc-1", "SRC-2", "third_party", "重新测绘",
            ["z-c"], "minor", {},
            change_note="排除乙车间、新发现泵房",
            cleared_zone_ids=["z-b"],
        )
        self.assertEqual(result["affected_zone_ids"], ["z-a", "z-c"])
        self.assertEqual(result["added_zone_ids"], ["z-c"])
        self.assertEqual(result["removed_zone_ids"], ["z-b"])

    def test_duplicate_source_id_is_deduplicated_and_conflicting_content_rejected(self) -> None:
        first = self._first()
        replay = self._first()
        self.assertTrue(replay["duplicate"])
        self.assertEqual(replay["evidence_id"], first["evidence_id"])
        with self.assertRaises(Conflict):
            self.service.add_evidence(
                "duty", "inc-1", "SRC-1", "field_retest", "现场复测",
                ["z-a", "z-b"], "major", {"cod": 999},
            )
        count = self.connection.execute("SELECT count(*) FROM evidence").fetchone()[0]
        self.assertEqual(count, 1)
        revisions = self.connection.execute("SELECT count(*) FROM assessments").fetchone()[0]
        self.assertEqual(revisions, 1)

    def test_concurrent_same_source_submissions_deduplicate(self) -> None:
        # 真实部署是多连接打同一个数据库文件：每个线程独立连接，由
        # UNIQUE(incident_id, source_id) 与 BEGIN IMMEDIATE 串行化保证只落一条。
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "concurrent.sqlite3"
            admin = ResponseService(connect(database))
            for user_id, role in (("duty", "duty"), ("cmd", "commander")):
                admin.create_user(user_id, user_id, role)
            admin.register_zone("cmd", "z-a", "甲车间", "workshop", "业务")
            admin.create_incident("duty", "inc-1", "排口异常", "monitor-1", {"v": 1})

            barrier = threading.Barrier(4)
            results: list[dict | Exception] = []

            def submit() -> None:
                service = ResponseService(connect(database), self.clock)
                barrier.wait()
                try:
                    results.append(service.add_evidence(
                        "duty", "inc-1", "SRC-CONC", "field_retest", "并发记录",
                        ["z-a"], "minor", {"cod": 320},
                    ))
                except Exception as exc:  # noqa: BLE001 - 测试需要收集任意结果
                    results.append(exc)

            threads = [threading.Thread(target=submit) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            evidence_rows = admin.connection.execute(
                "SELECT count(*) FROM evidence WHERE source_id='SRC-CONC'"
            ).fetchone()[0]
            self.assertEqual(evidence_rows, 1)
            inserted = [item for item in results if isinstance(item, dict) and not item.get("duplicate")]
            duplicates = [item for item in results if isinstance(item, dict) and item.get("duplicate")]
            self.assertEqual(len(inserted), 1)
            self.assertEqual(len(duplicates), 3)
            self.assertTrue(all(not isinstance(item, Conflict) for item in results))

    def test_evidence_after_release_is_rejected(self) -> None:
        self._first()
        self.service.order_isolation("cmd", "inc-1", "隔离", ["z-a"], "cmd")
        self.service.request_release("cmd", "inc-1", "申请")
        review = self.connection.execute(
            "SELECT review_id FROM release_reviews"
        ).fetchone()[0]
        self.service.review_release("rev", review, True, "通过")
        with self.assertRaises(InvalidState):
            self.service.add_evidence(
                "duty", "inc-1", "SRC-9", "field_retest", "迟到证据",
                ["z-a"], "minor", {},
            )


class MeasureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service, self.clock = make_service()
        seed_world(self.service)
        self.service.add_evidence(
            "duty", "inc-1", "SRC-1", "field_retest", "现场复测",
            ["z-a", "z-b"], "major", {},
        )

    def tearDown(self) -> None:
        self.connection.close()

    def test_isolation_cannot_exceed_current_assessment(self) -> None:
        with self.assertRaises(InvalidState):
            self.service.order_isolation("cmd", "inc-1", "越界隔离", ["z-c"], "cmd")

    def test_isolation_tracks_assessment_expansion_and_narrowing(self) -> None:
        isolation = self.service.order_isolation("cmd", "inc-1", "封控", ["z-a"], "cmd")
        self.service.add_evidence(
            "cmd", "inc-1", "SRC-2", "third_party", "扩散",
            ["z-a", "z-b", "z-c"], "critical", {},
            change_note="扩散到乙车间和泵房",
        )
        self.assertEqual(
            self.service.measure(isolation["measure_id"])["zone_ids"],
            ["z-a", "z-b", "z-c"],
        )
        self.service.add_evidence(
            "cmd", "inc-1", "SRC-3", "calibration", "校准",
            [], "minor", {},
            change_note="乙、泵房误报", cleared_zone_ids=["z-b", "z-c"],
        )
        self.assertEqual(self.service.measure(isolation["measure_id"])["zone_ids"], ["z-a"])
        self.assertGreater(self.service.measure(isolation["measure_id"])["revision"], 1)

    def test_repair_completion_does_not_release_control(self) -> None:
        isolation = self.service.order_isolation("cmd", "inc-1", "封控", ["z-a"], "cmd")
        repair = self.service.assign_repair(
            "cmd", "inc-1", "修复加药泵", ["z-a"], "duty",
            due_at="2026-09-29T12:00:00Z",
        )
        self.service.update_measure("cmd", repair["measure_id"], "completed", "修复完毕")
        status = self.service.incident_status("inc-1")
        self.assertEqual(status["state"], "recovering")
        self.assertEqual(self.service.measure(isolation["measure_id"])["status"], "pending")
        with self.assertRaises(InvalidState):
            self.service.close_incident("cmd", "inc-1")

    def test_finished_measure_is_immutable(self) -> None:
        repair = self.service.assign_repair("cmd", "inc-1", "修复", ["z-a"], "duty")
        self.service.update_measure("cmd", repair["measure_id"], "completed", "done")
        with self.assertRaises(InvalidState):
            self.service.update_measure("cmd", repair["measure_id"], "cancelled", "撤销")

    def test_overdue_flag_and_duty_board(self) -> None:
        self.service.assign_repair(
            "cmd", "inc-1", "紧急修复", ["z-a"], "duty", due_at="2026-09-29T03:00:00Z"
        )
        board = self.service.duty_board("duty")
        self.assertEqual(board["incidents"][0]["overdue_count"], 0)
        self.clock.advance(hours=2)
        board = self.service.duty_board("duty")
        self.assertEqual(board["incidents"][0]["overdue_count"], 1)
        measure = board["incidents"][0]["open_measures"][0]
        self.assertTrue(measure["overdue"])
        self.assertEqual(measure["responsible_id"], "duty")

    def test_measures_filter_by_responsible_and_status(self) -> None:
        first = self.service.assign_repair("cmd", "inc-1", "修复一", ["z-a"], "duty")
        self.service.assign_repair("cmd", "inc-1", "修复二", ["z-b"], "cmd")
        self.service.update_measure("cmd", first["measure_id"], "completed", "ok")
        pending = self.service.list_measures("cmd", responsible_id="duty", status="pending")
        self.assertEqual(pending, [])
        mine = self.service.list_measures("cmd", responsible_id="duty")
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["status"], "completed")


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service, self.clock = make_service()
        seed_world(self.service)
        self.service.add_evidence(
            "duty", "inc-1", "SRC-1", "field_retest", "现场复测",
            ["z-a"], "major", {},
        )
        self.isolation = self.service.order_isolation("cmd", "inc-1", "封控", ["z-a"], "cmd")
        self.repair = self.service.assign_repair("cmd", "inc-1", "修复", ["z-a"], "duty")

    def tearDown(self) -> None:
        self.connection.close()

    def test_release_requires_open_review_and_independent_reviewer(self) -> None:
        request = self.service.request_release("cmd", "inc-1", "申请恢复")
        with self.assertRaises(Conflict):
            self.service.request_release("cmd", "inc-1", "重复申请")
        with self.assertRaises(Forbidden):
            self.service.review_release("cmd", request["review_id"], True, "自我批准")

    def test_release_blocked_while_tasks_unfinished(self) -> None:
        request = self.service.request_release("cmd", "inc-1", "申请恢复")
        with self.assertRaises(InvalidState):
            self.service.review_release("rev", request["review_id"], True, "提前通过")
        review_row = self.connection.execute(
            "SELECT status FROM release_reviews WHERE review_id=?", (request["review_id"],)
        ).fetchone()
        self.assertEqual(review_row["status"], "pending")

    def test_rejection_keeps_control_then_approval_resumes_business(self) -> None:
        first = self.service.request_release("cmd", "inc-1", "申请")
        rejected = self.service.review_release("rev", first["review_id"], False, "数据不达标")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["incident_state"], "controlling")
        self.assertEqual(self.service.measure(self.isolation["measure_id"])["status"], "pending")

        self.service.update_measure("cmd", self.repair["measure_id"], "completed", "ok")
        second = self.service.request_release("cmd", "inc-1", "整改后申请")
        approved = self.service.review_release("rev", second["review_id"], True, "复核通过")
        self.assertEqual(approved["incident_state"], "released")
        self.assertEqual(approved["resumed_zone_ids"], ["z-a"])
        self.assertEqual(self.service.measure(self.isolation["measure_id"])["status"], "completed")
        self.service.close_incident("cmd", "inc-1")
        self.assertEqual(self.service.incident_status("inc-1")["state"], "closed")


class HistoryAndRoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.service, self.clock = make_service()
        seed_world(self.service)

    def tearDown(self) -> None:
        self.connection.close()

    def test_history_contains_full_decision_lineage(self) -> None:
        self.service.add_evidence(
            "duty", "inc-1", "SRC-1", "field_retest", "现场", ["z-a"], "major", {},
        )
        isolation = self.service.order_isolation("cmd", "inc-1", "封控", ["z-a"], "cmd")
        repair = self.service.assign_repair("cmd", "inc-1", "修复", ["z-a"], "duty")
        self.service.update_measure("cmd", repair["measure_id"], "completed", "ok")
        request = self.service.request_release("cmd", "inc-1", "申请")
        self.service.review_release("rev", request["review_id"], True, "通过")

        history = self.service.history("aud", "inc-1")
        event_types = [event["event_type"] for event in history["events"]]
        self.assertIn("incident.created", event_types)
        self.assertIn("evidence.submitted", event_types)
        self.assertIn("assessment.versioned", event_types)
        self.assertIn("isolation.ordered", event_types)
        self.assertIn("repair.assigned", event_types)
        self.assertIn("release.requested", event_types)
        self.assertIn("release.approved", event_types)
        self.assertEqual(history["incident"]["state"], "released")
        self.assertEqual(len(history["assessments"]), 1)
        self.assertEqual(len(history["release_reviews"]), 1)
        self.assertEqual(history["measures"][0]["zone_ids"], ["z-a"])
        self.assertEqual(isolation["measure_id"], history["measures"][0]["measure_id"])
        self.assertTrue(self.service.audit_chain("aud")["valid"])

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.register_zone("duty", "z-x", "x", "workshop", "b")
        with self.assertRaises(Forbidden):
            self.service.order_isolation("duty", "inc-1", "封控", ["z-a"], "cmd")
        with self.assertRaises(Forbidden):
            self.service.review_release("cmd", 1, True, "指挥不能自批")
        with self.assertRaises(Forbidden):
            self.service.audit_chain("duty")


if __name__ == "__main__":
    unittest.main()
