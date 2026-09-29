"""贯通异常信号、三份证据版本判断、措施联动与授权解除的离线验收。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .service import ResponseService
from .storage import inspect_schema


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 9, 29, 2, 0, tzinfo=timezone.utc))
    service = ResponseService(connection, clock)
    for user_id, role in (
        ("duty1", "duty"),
        ("cmd1", "commander"),
        ("rev1", "reviewer"),
        ("aud1", "auditor"),
    ):
        service.create_user(user_id, user_id, role)

    # 园区受影响候选区域：A 片区（排放源车间）与 B 片区（下游）。
    zones = {
        "zone-a1": ("一号涂装车间", "workshop", "涂装一线"),
        "zone-a2": ("二号涂装车间", "workshop", "涂装二线"),
        "zone-b1": ("下游仓库", "warehouse", "成品仓储"),
        "zone-b2": ("下游泵房", "utility", "循环水泵房"),
    }
    for zone_id, (name, zone_type, business) in zones.items():
        service.register_zone("cmd1", zone_id, name, zone_type, business)

    service.create_incident(
        "duty1", "inc-2026-0929", "废水排口 COD 浓度异常",
        "online-monitor-COD-07",
        {"reading_mg_l": 480, "limit_mg_l": 300, "observed_at": "2026-09-29T01:40:00Z"},
    )

    # 材料一：现场复测，判断先落在 A 片区两个车间。
    first = service.add_evidence(
        "duty1", "inc-2026-0929", "FR-20260929-01", "field_retest",
        "现场快速复测记录", ["zone-a1", "zone-a2"], "major",
        {"cod_mg_l": 455, "sampled_at": "2026-09-29T02:10:00Z"},
    )
    assert first["revision"] == 1 and first["direction"] == "initial"

    # 并发提交的同一来源编号记录必须去重：重复提交原样返回，改内容则冲突。
    replay = service.add_evidence(
        "duty1", "inc-2026-0929", "FR-20260929-01", "field_retest",
        "现场快速复测记录", ["zone-a1", "zone-a2"], "major",
        {"cod_mg_l": 455, "sampled_at": "2026-09-29T02:10:00Z"},
    )
    assert replay["duplicate"] is True and replay["evidence_id"] == first["evidence_id"]

    isolation = service.order_isolation(
        "cmd1", "inc-2026-0929", "对 A 片区实施临时管控", ["zone-a1", "zone-a2"],
        "cmd1", due_at="2026-09-29T06:00:00Z", detail={"level": "limit_access"},
    )
    service.update_measure("cmd1", isolation["measure_id"], "in_progress", "现场开始封控")
    dispatch = service.dispatch_resource(
        "cmd1", "inc-2026-0929", "调运活性炭吸附装置与应急罐车", ["zone-a1", "zone-a2"],
        "duty1", due_at="2026-09-29T05:00:00Z", detail={"units": 2},
    )
    repair = service.assign_repair(
        "cmd1", "inc-2026-0929", "检修废水预处理加药系统", ["zone-a1"],
        "duty1", due_at="2026-09-29T12:00:00Z", detail={"fault": "加药泵气蚀"},
    )

    # 材料二：第三方扩散分析，影响范围扩大到下游 B 片区，必须给出变化理由。
    clock.advance(hours=2)
    second = service.add_evidence(
        "cmd1", "inc-2026-0929", "TP-HYDRO-07", "third_party",
        "第三方水力扩散分析报告", ["zone-a1", "zone-a2", "zone-b1", "zone-b2"], "critical",
        {"plume_model": "hydro-2d", "confidence": 0.86},
        change_note="第三方扩散模型显示污染团沿管网到达下游 B 片区，扩大隔离范围",
    )
    assert second["direction"] == "expanded"
    assert second["added_zone_ids"] == ["zone-b1", "zone-b2"]
    assert second["removed_zone_ids"] == []
    # 现行隔离措施应随判断自动扩大。
    assert service.measure(isolation["measure_id"])["zone_ids"] == [
        "zone-a1", "zone-a2", "zone-b1", "zone-b2",
    ]
    extra_dispatch = service.dispatch_resource(
        "cmd1", "inc-2026-0929", "向下游泵房增派围油栏与吸附棉", ["zone-b1", "zone-b2"],
        "duty1", due_at="2026-09-29T08:00:00Z",
    )

    # 材料三：设备校准报告证明零点漂移，B 片区读数为误报，范围收窄并说明理由。
    clock.advance(hours=3)
    third = service.add_evidence(
        "cmd1", "inc-2026-0929", "CAL-COD07-0929", "calibration",
        "在线 COD 分析仪校准报告", [], "minor",
        {"zero_drift_mg_l": 120, "calibrated_at": "2026-09-29T06:30:00Z"},
        change_note="校准确认 COD-07 存在零点漂移，B 片区异常读数系误报，收窄至 A 片区",
        cleared_zone_ids=["zone-b1", "zone-b2"],
    )
    assert third["direction"] == "narrowed"
    assert third["added_zone_ids"] == []
    assert third["removed_zone_ids"] == ["zone-b1", "zone-b2"]
    assert third["affected_zone_ids"] == ["zone-a1", "zone-a2"]
    # 隔离措施随判断自动收窄。
    assert service.measure(isolation["measure_id"])["zone_ids"] == ["zone-a1", "zone-a2"]

    # 调度与修复逐项完成，但管控不得自动解除。
    for measure_id in (dispatch["measure_id"], extra_dispatch["measure_id"], repair["measure_id"]):
        service.update_measure("cmd1", measure_id, "completed", "现场处置完成")
    status_after_repair = service.incident_status("inc-2026-0929")
    assert status_after_repair["state"] == "recovering"
    assert service.measure(isolation["measure_id"])["status"] == "in_progress"

    # 复核未完成前不能解除：先申请，再由独立授权复核人驳回一次，整改后通过。
    request = service.request_release("cmd1", "inc-2026-0929", "修复与调度均已完成，申请恢复")
    rejected = service.review_release("rev1", request["review_id"], False, "复测数据尚未连续达标")
    assert rejected["incident_state"] == "controlling"

    service.update_measure("cmd1", isolation["measure_id"], "in_progress", "等待连续复测达标")
    clock.advance(hours=24)
    service.add_evidence(
        "duty1", "inc-2026-0929", "FR-20260930-02", "field_retest",
        "连续 24 小时复测达标记录", ["zone-a1", "zone-a2"], "watch",
        {"cod_mg_l": 210, "samples": 24},
        change_note="连续复测达标，但 A 片区仍列为观察区",
    )
    request_two = service.request_release("cmd1", "inc-2026-0929", "连续复测达标，再次申请恢复")
    approved = service.review_release("rev1", request_two["review_id"], True, "复核通过，恢复 A 片区业务")
    assert approved["status"] == "approved"
    final_status = service.incident_status("inc-2026-0929")
    assert final_status["state"] == "released"
    assert service.measure(isolation["measure_id"])["status"] == "completed"

    service.close_incident("cmd1", "inc-2026-0929")
    history = service.history("aud1", "inc-2026-0929")
    chain = service.audit_chain("aud1")
    schema = inspect_schema(connection)
    connection.close()

    directions = [item["change_direction"] for item in history["assessments"]]
    assert directions == ["initial", "expanded", "narrowed", "unchanged"]
    assert chain["valid"]
    return {
        "status": "ok",
        "incident_id": "inc-2026-0929",
        "final_state": "closed",
        "evidence_count": len(history["evidence"]),
        "assessment_revisions": len(history["assessments"]),
        "directions": directions,
        "measure_count": len(history["measures"]),
        "release_reviews": len(history["release_reviews"]),
        "resumed_zone_ids": approved["resumed_zone_ids"],
        "event_count": len(history["events"]),
        "audit": chain,
        "schema": schema,
        "workspace": workspace.name,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行产业园环境事件响应服务离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
