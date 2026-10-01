"""贯通监测异常、证据版本、隔离调度、修复与授权解除的离线验收。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .service import IncidentService


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
    service = IncidentService(connection, clock)
    for user_id, role in (
        ("duty", "duty"),
        ("field", "field"),
        ("dispatch", "dispatcher"),
        ("repair", "remediation"),
        ("review", "reviewer"),
        ("audit", "auditor"),
    ):
        service.create_user(user_id, user_id, role)

    service.create_incident("duty", {
        "incident_id": "inc-20260924-01",
        "title": "北区废气监测 VOC 异常",
        "contaminant": "voc",
        "severity": "elevated",
    })

    # 三份材料：监测告警 -> 现场复测（扩大）-> 第三方分析（收窄）-> 设备校准（推翻告警）。
    alert = service.record_evidence("duty", "inc-20260924-01", {
        "source_ref": "monitor-0924-0800",
        "kind": "monitor_alert",
        "origin": "园区大气站 SN-07",
        "finding": "positive",
        "zones": ["zone-a", "zone-b"],
        "reading": {"voc_mg_m3": "6.8", "threshold": "4.0"},
        "observed_at": "2026-09-24T08:00:00+08:00",
        "change_note": "自动监测超阈值，初判影响 zone-a、zone-b",
    })
    retest = service.record_evidence("field", "inc-20260924-01", {
        "source_ref": "retest-0924-0930",
        "kind": "field_retest",
        "origin": "值班组现场复测",
        "finding": "positive",
        "zones": ["zone-a", "zone-b", "zone-c"],
        "reading": {"voc_mg_m3": "7.4"},
        "observed_at": "2026-09-24T09:30:00+08:00",
        "change_note": "下风向 zone-c 也检出，扩大隔离范围",
    })
    third_party = service.record_evidence("duty", "inc-20260924-01", {
        "source_ref": "thirdparty-lab-1188",
        "kind": "third_party",
        "origin": "华测环境实验室",
        "finding": "positive",
        "zones": ["zone-a", "zone-b", "zone-c"],
        "reading": {"voc_mg_m3": "6.1", "confidence": "0.92"},
        "observed_at": "2026-09-24T12:00:00+08:00",
        "change_note": "实验室确认三区域污染，维持当前范围",
    })

    # 并发现场记录：来源编号去重。
    first_batch = service.submit_field_records("field", "inc-20260924-01", [
        {"source_ref": "rec-a-01", "zone_code": "zone-a", "reading": "voc 5.9",
         "observed_at": "2026-09-24T10:05:00+08:00"},
        {"source_ref": "rec-b-01", "zone_code": "zone-b", "reading": "voc 6.3",
         "observed_at": "2026-09-24T10:08:00+08:00"},
    ])
    concurrent = service.submit_field_records("field", "inc-20260924-01", [
        {"source_ref": "rec-a-01", "zone_code": "zone-a", "reading": "voc 5.9(重传)",
         "observed_at": "2026-09-24T10:05:00+08:00"},
        {"source_ref": "rec-c-01", "zone_code": "zone-c", "reading": "voc 4.7",
         "observed_at": "2026-09-24T10:12:00+08:00"},
    ])

    # 区域隔离与资源调度。
    isolation = service.create_measure("dispatch", "inc-20260924-01", {
        "kind": "zone_isolation",
        "title": "封锁 zone-a/b/c 与下风向通道",
        "zones": ["zone-a", "zone-b", "zone-c"],
        "owner_id": "dispatch",
        "due_at": "2026-09-24T18:00:00+08:00",
        "detail": {"barriers": 6, "notify_tenants": True},
    })
    fans = service.create_measure("dispatch", "inc-20260924-01", {
        "kind": "resource_dispatch",
        "title": "调度活性炭排风机组两组",
        "zones": ["zone-a"],
        "owner_id": "dispatch",
        "due_at": "2026-09-24T14:00:00+08:00",
        "detail": {"units": 2, "asset_refs": ["fan-12", "fan-13"]},
    })

    # 修复任务。
    service.create_task("repair", "inc-20260924-01", {
        "task_id": "task-a-flush", "zone_code": "zone-a", "title": "zone-a 排风置换",
        "assignee_id": "repair", "due_at": "2026-09-24T20:00:00+08:00"})
    service.create_task("repair", "inc-20260924-01", {
        "task_id": "task-b-source", "zone_code": "zone-b", "title": "排查 zone-b 泄漏点",
        "assignee_id": "repair", "due_at": "2026-09-24T19:00:00+08:00"})
    service.create_task("repair", "inc-20260924-01", {
        "task_id": "task-c-monitor", "zone_code": "zone-c", "title": "zone-c 持续监测",
        "assignee_id": "repair", "due_at": "2026-09-24T21:00:00+08:00"})
    service.start_task("repair", "task-a-flush")
    service.complete_task("repair", "task-a-flush")
    service.verify_task("repair", "task-a-flush")

    # 任务未全部完成时，解除申请必须被拒绝受理。
    blocked = None
    try:
        service.request_closure("repair", "inc-20260924-01", "申请解除")
    except Exception as exc:  # noqa: BLE001 - 验收需要断言错误信息
        blocked = str(exc)

    service.start_task("repair", "task-b-source")
    service.complete_task("repair", "task-b-source")
    service.verify_task("repair", "task-b-source")
    service.start_task("repair", "task-c-monitor")
    service.complete_task("repair", "task-c-monitor")
    service.verify_task("repair", "task-c-monitor")

    # 完成修复不等于自动解除：措施仍 active、事件仍 remediating。
    after_tasks = service.snapshot("duty", "inc-20260924-01")
    measures_before_review = service.measures_status("duty", "inc-20260924-01")

    # 授权复核：第一次驳回，补齐材料后通过，通过才解除措施、恢复业务。
    request_a = service.request_closure("repair", "inc-20260924-01", "修复完成，申请恢复")
    rejected = service.decide_review("review", request_a["review_id"], "rejected",
                                    "缺少 zone-c 复测确认，继续隔离")
    service.record_evidence("field", "inc-20260924-01", {
        "source_ref": "retest-0924-1700",
        "kind": "field_retest",
        "origin": "值班组收班复测",
        "finding": "positive",
        "zones": ["zone-a", "zone-b", "zone-c"],
        "reading": {"voc_mg_m3": "3.2"},
        "observed_at": "2026-09-24T17:00:00+08:00",
        "change_note": "浓度已低于阈值但本轮仍按阳性记录，维持范围等待复核",
    })
    request_b = service.request_closure("repair", "inc-20260924-01", "补充复测达标，再次申请")
    approved = service.decide_review("review", request_b["review_id"], "approved",
                                    "复测连续达标，同意解除隔离、恢复受影响业务",
                                    expected_revision=4)

    clock.advance(hours=1)
    todos = service.todos("duty", "inc-20260924-01")
    history = service.history("audit", "inc-20260924-01")
    audit = service.audit_chain("audit")
    closed = service.snapshot("duty", "inc-20260924-01")

    result = {
        "status": "ok",
        "workspace": workspace.name,
        "assessments": {"alert": alert, "retest": retest, "third_party": third_party},
        "field_records": {"first": first_batch, "concurrent": concurrent},
        "measures": {"isolation": isolation, "fans": fans},
        "closure_blocked_reason": blocked,
        "state_after_tasks": after_tasks["state"],
        "active_measures_before_review": len(measures_before_review["measures"]),
        "first_review": rejected,
        "final_review": approved,
        "closed_state": closed["state"],
        "remaining_todos": len(todos["active_measures"]) + len(todos["open_tasks"]),
        "timeline_events": len(history["timeline"]),
        "audit": audit,
    }
    connection.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行环境事件响应服务离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
