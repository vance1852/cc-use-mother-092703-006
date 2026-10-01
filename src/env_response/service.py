"""环境事件响应的事务用例：证据版本判断、管控措施、修复与解除复核。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Mapping

from . import contracts
from .clock import SystemClock, parse_utc, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "duty": {"incident.create", "evidence.write", "review.request", "incident.reopen", "read"},
    "field": {"evidence.write", "read"},
    "dispatcher": {"measure.write", "read"},
    "remediation": {"task.write", "review.request", "read"},
    "reviewer": {"review.decide", "read"},
    "auditor": {"read", "audit.read"},
}

GENESIS_HASH = "0" * 64


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value: str) -> Any:
    return json.loads(value)


class IncidentService:
    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ------------------------------------------------------------------ 基础

    def _now(self) -> str:
        return utc_text(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM env_users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound("用户不存在")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _incident(self, incident_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFound("事件不存在")
        return row

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM env_audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = GENESIS_HASH if previous is None else previous["event_hash"]
        incident_id = entity_id if entity_type == "incident" else payload.get("incident_id")
        body = {
            "incident_id": incident_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO env_audit_events(incident_id,entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                incident_id,
                entity_type,
                entity_id,
                event_type,
                actor_id,
                canonical_json(payload),
                previous_hash,
                event_hash,
                body["created_at"],
            ),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed("未知角色")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO env_users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id.strip(), "role": role}

    # ------------------------------------------------------------------ 事件

    def create_incident(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "incident.create")
        incident_id = contracts.identifier(raw.get("incident_id"), "incident_id")
        title = contracts.required_text(raw.get("title"), "title")
        contaminant = contracts.choice(raw.get("contaminant"), "contaminant", contracts.CONTAMINANTS)
        severity = contracts.choice(raw.get("severity", "watch"), "severity", {"watch", "elevated", "serious"})
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO incidents(incident_id,title,contaminant,severity,state,created_by,created_at) "
                    "VALUES(?,?,?,?, 'open',?,?)",
                    (incident_id, title, contaminant, severity, actor_id, self._now()),
                )
                self._audit("incident", incident_id, "incident.created", actor_id,
                            {"title": title, "contaminant": contaminant, "severity": severity})
        except sqlite3.IntegrityError as exc:
            raise Conflict("事件编号已经存在") from exc
        return {"incident_id": incident_id, "state": "open", "revision": 0, "zones": []}

    # ------------------------------------------------------------------ 证据

    def _effective_zones(self, incident_id: str) -> tuple[list[str], dict[str, Any]]:
        """根据全部证据重算影响区域。

        规则（保守但允许新证据收窄）：
        - 被后续证据质疑（disputes_refs）的证据整体作废，例如设备校准证明探头漂移；
        - 对每个区域，以时间上最新一份、未被作废且提到该区域的证据结论为准——
          最新结论为 cleared 即移出影响范围（第三方复测澄清），阳性则保留；
          没有被更新结论覆盖的阳性区域继续保留，避免遗漏风险。
        """
        rows = self.connection.execute(
            "SELECT evidence_id,source_ref,kind,finding,observed_zones_json,disputes_json "
            "FROM evidence WHERE incident_id=? AND archived=0 ORDER BY evidence_id",
            (incident_id,),
        ).fetchall()
        disputed: set[str] = set()
        for row in rows:
            disputed.update(_loads(row["disputes_json"]))
        latest_word: dict[str, tuple[int, str]] = {}
        contributing: list[str] = []
        clearing: list[str] = []
        for row in rows:
            if row["source_ref"] in disputed:
                continue
            finding = row["finding"]
            if finding == "positive" and _loads(row["observed_zones_json"]):
                contributing.append(row["source_ref"])
            if finding == "cleared" and _loads(row["observed_zones_json"]):
                clearing.append(row["source_ref"])
            for zone in _loads(row["observed_zones_json"]):
                previous = latest_word.get(zone)
                if previous is None or row["evidence_id"] > previous[0]:
                    latest_word[zone] = (row["evidence_id"], finding)
        zones = sorted(zone for zone, (_, finding) in latest_word.items() if finding == "positive")
        basis = {
            "contributing_evidence": contributing,
            "clearing_evidence": clearing,
            "disputed_refs": sorted(disputed),
            "evidence_count": len(rows),
        }
        return zones, basis

    def record_evidence(self, actor_id: str, incident_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "evidence.write")
        incident = self._incident(incident_id)
        if incident["state"] == "closed":
            raise InvalidState("事件已关闭，需先重开才能追加证据")
        if incident["state"] == "review_pending":
            raise InvalidState("解除复核尚未得出结论，不能追加证据")
        source_ref = contracts.identifier(raw.get("source_ref"), "source_ref")
        kind = contracts.choice(raw.get("kind"), "kind", contracts.EVIDENCE_KINDS)
        origin = contracts.required_text(raw.get("origin"), "origin")
        finding = contracts.choice(raw.get("finding", "positive"), "finding", {"positive", "cleared"})
        allow_empty = finding == "cleared"
        zones = contracts.zone_codes(raw.get("zones", []), allow_empty=allow_empty)
        change_note = contracts.required_text(raw.get("change_note"), "change_note")
        note = contracts.optional_text(raw.get("note"), "note") or ""
        disputes_refs = raw.get("disputes_refs", [])
        if not isinstance(disputes_refs, list) or any(not isinstance(item, str) for item in disputes_refs):
            raise ValidationFailed("disputes_refs 必须是字符串数组")
        disputes_refs = [item.strip() for item in disputes_refs if item.strip()]
        if source_ref in disputes_refs:
            raise ValidationFailed("证据不能质疑自身")
        reading = raw.get("reading", {})
        if not isinstance(reading, Mapping):
            raise ValidationFailed("reading 必须是对象")
        observed_at = contracts.required_text(raw.get("observed_at"), "observed_at", 40)
        try:
            parse_utc(observed_at, "observed_at")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        content = {
            "source_ref": source_ref,
            "kind": kind,
            "origin": origin,
            "finding": finding,
            "zones": zones,
            "reading": reading,
            "observed_at": observed_at,
            "disputes_refs": sorted(disputes_refs),
            "note": note,
        }
        content_sha256 = hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()
        with transaction(self.connection, immediate=True):
            prior = self.connection.execute(
                "SELECT evidence_id FROM evidence WHERE incident_id=? AND source_ref=?",
                (incident_id, source_ref),
            ).fetchone()
            if prior is not None:
                raise Conflict("同一来源编号的证据已经登记")
            for ref in disputes_refs:
                exists = self.connection.execute(
                    "SELECT 1 FROM evidence WHERE incident_id=? AND source_ref=?",
                    (incident_id, ref),
                ).fetchone()
                if exists is None:
                    raise ValidationFailed(f"disputes_refs 中 {ref} 不存在")
            cursor = self.connection.execute(
                "INSERT INTO evidence(incident_id,source_ref,kind,origin,reading_json,observed_zones_json,"
                "finding,disputes_json,note,content_sha256,recorded_by,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    incident_id,
                    source_ref,
                    kind,
                    origin,
                    canonical_json(reading),
                    canonical_json(zones),
                    finding,
                    canonical_json(sorted(disputes_refs)),
                    note,
                    content_sha256,
                    actor_id,
                    self._now(),
                ),
            )
            evidence_id = int(cursor.lastrowid)
            previous_zones = set(_loads(incident["current_zones_json"]))
            new_zones, basis = self._effective_zones(incident_id)
            added = sorted(set(new_zones) - previous_zones)
            removed = sorted(previous_zones - set(new_zones))
            revision = incident["current_revision"] + 1
            if revision == 1 and not new_zones:
                result = "dismissed"
            elif not new_zones and previous_zones:
                result = "downgraded"
            else:
                result = "confirmed"
            self.connection.execute(
                "INSERT INTO assessments(incident_id,revision,evidence_id,result,zones_json,added_zones_json,"
                "removed_zones_json,change_reason,basis_json,decided_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    incident_id,
                    revision,
                    evidence_id,
                    result,
                    canonical_json(new_zones),
                    canonical_json(added),
                    canonical_json(removed),
                    change_note,
                    canonical_json(basis),
                    actor_id,
                    self._now(),
                ),
            )
            self.connection.execute(
                "UPDATE incidents SET current_zones_json=?,current_revision=?,latest_assessment_id=? "
                "WHERE incident_id=?",
                (canonical_json(new_zones), revision, evidence_id, incident_id),
            )
            self._audit("incident", incident_id, "evidence.recorded", actor_id,
                        {"evidence_id": evidence_id, "source_ref": source_ref, "revision": revision,
                         "added_zones": added, "removed_zones": removed, "result": result})
        return {
            "incident_id": incident_id,
            "evidence_id": evidence_id,
            "revision": revision,
            "result": result,
            "zones": new_zones,
            "added_zones": added,
            "removed_zones": removed,
            "change_reason": change_note,
        }

    # ------------------------------------------------------------- 现场记录

    def submit_field_records(
        self, actor_id: str, incident_id: str, raw_records: list[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """并发提交现场记录：按 (事件, source_ref) 去重，重复来源只保留首次提交。"""
        self._require(actor_id, "evidence.write")
        self._incident(incident_id)
        records = contracts.record_fields(raw_records)
        inserted: list[str] = []
        deduped: list[dict[str, Any]] = []
        with transaction(self.connection, immediate=True):
            for record in records:
                try:
                    cursor = self.connection.execute(
                        "INSERT INTO field_records(incident_id,source_ref,zone_code,reading,observed_at,note,"
                        "submitted_by,submitted_at) VALUES(?,?,?,?,?,?,?,?)",
                        (
                            incident_id,
                            record["source_ref"],
                            record["zone_code"],
                            record["reading_text"],
                            record["observed_at"],
                            record["note"],
                            actor_id,
                            self._now(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    existing = self.connection.execute(
                        "SELECT source_ref,submitted_by,submitted_at FROM field_records "
                        "WHERE incident_id=? AND source_ref=?",
                        (incident_id, record["source_ref"]),
                    ).fetchone()
                    self.connection.execute(
                        "UPDATE field_records SET deduped=deduped+1 WHERE incident_id=? AND source_ref=?",
                        (incident_id, record["source_ref"]),
                    )
                    deduped.append({
                        "source_ref": existing["source_ref"],
                        "first_submitted_by": existing["submitted_by"],
                        "first_submitted_at": existing["submitted_at"],
                    })
                else:
                    inserted.append(record["source_ref"])
                    record_id = int(cursor.lastrowid)
                    self._audit("field_record", str(record_id), "field_record.submitted", actor_id,
                                {"incident_id": incident_id, "source_ref": record["source_ref"],
                                 "zone_code": record["zone_code"]})
        return {"incident_id": incident_id, "inserted": inserted, "inserted_count": len(inserted),
                "deduped": deduped, "deduped_count": len(deduped)}

    # ------------------------------------------------------------------ 措施

    def create_measure(self, actor_id: str, incident_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "measure.write")
        incident = self._incident(incident_id)
        if incident["state"] in {"closed", "review_pending"}:
            raise InvalidState("当前事件状态不能新增管控措施")
        kind = contracts.choice(raw.get("kind"), "kind", {"zone_isolation", "resource_dispatch"})
        title = contracts.required_text(raw.get("title"), "title")
        zones = contracts.zone_codes(raw.get("zones", []))
        current_zones = set(_loads(incident["current_zones_json"]))
        unknown = sorted(set(zones) - current_zones)
        if unknown:
            raise ValidationFailed(f"区域 {unknown} 不在当前影响范围内，不能据此布置措施")
        owner_id = contracts.identifier(raw.get("owner_id"), "owner_id")
        self._user(owner_id)
        due_at = contracts.optional_text(raw.get("due_at"), "due_at", 40)
        if due_at is not None:
            try:
                due_at = utc_text(parse_utc(due_at, "due_at"))
            except ValueError as exc:
                raise ValidationFailed(str(exc)) from exc
        detail = raw.get("detail", {})
        if not isinstance(detail, Mapping):
            raise ValidationFailed("detail 必须是对象")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO measures(incident_id,kind,title,detail_json,zones_json,owner_id,due_at,"
                "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (incident_id, kind, title, canonical_json(detail), canonical_json(zones),
                 owner_id, due_at, actor_id, self._now()),
            )
            measure_id = int(cursor.lastrowid)
            if incident["state"] in {"open", "reopened"}:
                self.connection.execute(
                    "UPDATE incidents SET state='contained' WHERE incident_id=? AND state IN ('open','reopened')",
                    (incident_id,),
                )
            self._audit("measure", str(measure_id), "measure.created", actor_id,
                        {"incident_id": incident_id, "kind": kind, "zones": zones, "owner_id": owner_id})
        return self.measure(measure_id)

    def measure(self, measure_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM measures WHERE measure_id=?", (measure_id,)).fetchone()
        if row is None:
            raise NotFound("管控措施不存在")
        return self._measure_dict(row)

    @staticmethod
    def _measure_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "measure_id": row["measure_id"],
            "incident_id": row["incident_id"],
            "kind": row["kind"],
            "title": row["title"],
            "detail": _loads(row["detail_json"]),
            "zones": _loads(row["zones_json"]),
            "state": row["state"],
            "revision": row["revision"],
            "owner_id": row["owner_id"],
            "due_at": row["due_at"],
            "lifted_at": row["lifted_at"],
            "created_at": row["created_at"],
        }

    def update_measure(
        self,
        actor_id: str,
        measure_id: int,
        owner_id: str | None = None,
        due_at: object = ...,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "measure.write")
        row = self.connection.execute("SELECT * FROM measures WHERE measure_id=?", (measure_id,)).fetchone()
        if row is None:
            raise NotFound("管控措施不存在")
        if row["state"] != "active":
            raise InvalidState("只有生效中的措施可以调整")
        if expected_revision is not None and row["revision"] != expected_revision:
            raise Conflict("措施已被其他人修改，请基于最新版本调整")
        updates: dict[str, Any] = {}
        if owner_id is not None:
            owner_id = contracts.identifier(owner_id, "owner_id")
            self._user(owner_id)
            updates["owner_id"] = owner_id
        if due_at is not ...:
            if due_at is None:
                updates["due_at"] = None
            else:
                text = contracts.required_text(due_at, "due_at", 40)
                try:
                    updates["due_at"] = utc_text(parse_utc(text, "due_at"))
                except ValueError as exc:
                    raise ValidationFailed(str(exc)) from exc
        if not updates:
            return self._measure_dict(row)
        with transaction(self.connection, immediate=True):
            assignments = ", ".join(f"{key}=?" for key in updates)
            values = list(updates.values())
            self.connection.execute(
                f"UPDATE measures SET {assignments}, revision=revision+1 WHERE measure_id=? AND state='active'",
                (*values, measure_id),
            )
            self._audit("measure", str(measure_id), "measure.updated", actor_id,
                        {"incident_id": row["incident_id"], "changes": updates})
        return self.measure(measure_id)

    def cancel_measure(self, actor_id: str, measure_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "measure.write")
        reason = contracts.required_text(reason, "reason")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE measures SET state='cancelled',revision=revision+1 "
                "WHERE measure_id=? AND state='active'",
                (measure_id,),
            )
            if cursor.rowcount != 1:
                raise InvalidState("措施不存在或已不在生效中")
            row = self.connection.execute(
                "SELECT incident_id FROM measures WHERE measure_id=?", (measure_id,)
            ).fetchone()
            self._audit("measure", str(measure_id), "measure.cancelled", actor_id,
                        {"incident_id": row["incident_id"], "reason": reason})
        return self.measure(measure_id)

    def measures_status(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "read")
        incident = self._incident(incident_id)
        rows = self.connection.execute(
            "SELECT * FROM measures WHERE incident_id=? ORDER BY measure_id", (incident_id,)
        ).fetchall()
        measures = [self._measure_dict(row) for row in rows]
        current_zones = set(_loads(incident["current_zones_json"]))
        covered = {zone for item in measures if item["state"] == "active" for zone in item["zones"]}
        return {
            "incident_id": incident_id,
            "state": incident["state"],
            "zones": sorted(current_zones),
            "measures": measures,
            "uncovered_active_zones": sorted(current_zones - covered),
        }

    # ------------------------------------------------------------------ 修复

    def create_task(self, actor_id: str, incident_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "task.write")
        incident = self._incident(incident_id)
        if incident["state"] in {"closed", "review_pending"}:
            raise InvalidState("当前事件状态不能新增修复任务")
        task_id = contracts.identifier(raw.get("task_id"), "task_id")
        title = contracts.required_text(raw.get("title"), "title")
        zone_code = contracts.identifier(raw.get("zone_code"), "zone_code")
        current_zones = set(_loads(incident["current_zones_json"]))
        if zone_code not in current_zones:
            raise ValidationFailed("任务区域不在当前影响范围内")
        assignee_id = contracts.identifier(raw.get("assignee_id"), "assignee_id")
        self._user(assignee_id)
        due_at = contracts.optional_text(raw.get("due_at"), "due_at", 40)
        if due_at is not None:
            try:
                due_at = utc_text(parse_utc(due_at, "due_at"))
            except ValueError as exc:
                raise ValidationFailed(str(exc)) from exc
        detail = contracts.optional_text(raw.get("detail"), "detail") or ""
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO remediation_tasks(task_id,incident_id,zone_code,title,detail,assignee_id,"
                    "due_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (task_id, incident_id, zone_code, title, detail, assignee_id, due_at,
                     actor_id, self._now()),
                )
                if incident["state"] in {"open", "contained", "reopened"}:
                    self.connection.execute(
                        "UPDATE incidents SET state='remediating' WHERE incident_id=? "
                        "AND state IN ('open','contained','reopened')",
                        (incident_id,),
                    )
                self._audit("task", task_id, "task.created", actor_id,
                            {"incident_id": incident_id, "zone_code": zone_code, "assignee_id": assignee_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("修复任务编号已经存在") from exc
        return self.task(task_id)

    def task(self, task_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM remediation_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise NotFound("修复任务不存在")
        return dict(row)

    def _advance_task(self, actor_id: str, task_id: str, event: str, from_states: set[str],
                      to_state: str, *, complete: bool = False) -> dict[str, Any]:
        self._require(actor_id, "task.write")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM remediation_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None:
                raise NotFound("修复任务不存在")
            if row["state"] not in from_states:
                raise InvalidState(f"任务当前状态 {row['state']} 不能{event}")
            if complete:
                self.connection.execute(
                    "UPDATE remediation_tasks SET state=?,completed_at=?,completed_by=?,revision=revision+1 "
                    "WHERE task_id=?",
                    (to_state, self._now(), actor_id, task_id),
                )
            else:
                self.connection.execute(
                    "UPDATE remediation_tasks SET state=?,revision=revision+1 WHERE task_id=?",
                    (to_state, task_id),
                )
            self._audit("task", task_id, f"task.{event}", actor_id,
                        {"incident_id": row["incident_id"], "state": to_state})
        return self.task(task_id)

    def start_task(self, actor_id: str, task_id: str) -> dict[str, Any]:
        return self._advance_task(actor_id, task_id, "started", {"open"}, "in_progress")

    def complete_task(self, actor_id: str, task_id: str) -> dict[str, Any]:
        # 完成修复任务不会改变事件状态、不会解除任何管控措施。
        return self._advance_task(actor_id, task_id, "completed", {"open", "in_progress"}, "done", complete=True)

    def verify_task(self, actor_id: str, task_id: str) -> dict[str, Any]:
        return self._advance_task(actor_id, task_id, "verified", {"done"}, "verified")

    # ------------------------------------------------------------- 解除复核

    def request_closure(self, actor_id: str, incident_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "review.request")
        note = contracts.required_text(note, "note")
        incident = self._incident(incident_id)
        if incident["state"] not in {"open", "contained", "remediating", "reopened"}:
            raise InvalidState("当前事件状态不能申请解除管控")
        zones = set(_loads(incident["current_zones_json"]))
        if zones:
            unfinished = [
                row["task_id"] for row in self.connection.execute(
                    "SELECT task_id FROM remediation_tasks WHERE incident_id=? AND state IN ('open','in_progress')",
                    (incident_id,),
                ).fetchall()
            ]
            if unfinished:
                raise InvalidState(f"修复任务尚未完成: {unfinished}")
            handled_zones = {
                row["zone_code"] for row in self.connection.execute(
                    "SELECT DISTINCT zone_code FROM remediation_tasks "
                    "WHERE incident_id=? AND state IN ('done','verified')",
                    (incident_id,),
                ).fetchall()
            }
            unhandled = sorted(zones - handled_zones)
            if unhandled:
                raise InvalidState(f"影响区域尚无完成的修复任务: {unhandled}")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT 1 FROM closure_reviews WHERE incident_id=? AND state='pending'", (incident_id,)
            ).fetchone()
            if pending is not None:
                raise Conflict("已有待裁决的解除申请")
            cursor = self.connection.execute(
                "INSERT INTO closure_reviews(incident_id,request_note,requested_by,requested_at,revision) "
                "VALUES(?,?,?,?,?)",
                (incident_id, note, actor_id, self._now(), incident["current_revision"]),
            )
            review_id = int(cursor.lastrowid)
            self.connection.execute(
                "UPDATE incidents SET state='review_pending' WHERE incident_id=?", (incident_id,)
            )
            self._audit("incident", incident_id, "closure.requested", actor_id,
                        {"review_id": review_id, "note": note})
        return {"review_id": review_id, "incident_id": incident_id, "state": "pending"}

    def decide_review(
        self, actor_id: str, review_id: int, verdict: str, note: str, expected_revision: int | None = None
    ) -> dict[str, Any]:
        self._require(actor_id, "review.decide")
        verdict = contracts.choice(verdict, "verdict", contracts.REVIEW_VERDICTS)
        note = contracts.required_text(note, "note")
        with transaction(self.connection, immediate=True):
            review = self.connection.execute(
                "SELECT * FROM closure_reviews WHERE review_id=?", (review_id,)
            ).fetchone()
            if review is None:
                raise NotFound("解除申请不存在")
            if review["state"] != "pending":
                raise InvalidState("解除申请已经裁决")
            incident = self._incident(review["incident_id"])
            if incident["state"] != "review_pending":
                raise InvalidState("事件不处于待复核状态")
            if expected_revision is not None and incident["current_revision"] != expected_revision:
                raise Conflict("事件判断已经产生新版本，请基于最新版本复核")
            self.connection.execute(
                "UPDATE closure_reviews SET verdict=?,review_note=?,reviewer_id=?,reviewed_at=?,state=? "
                "WHERE review_id=?",
                (verdict, note, actor_id, self._now(), verdict, review_id),
            )
            lifted_measures: list[int] = []
            if verdict == "approved":
                measure_rows = self.connection.execute(
                    "SELECT measure_id FROM measures WHERE incident_id=? AND state='active'",
                    (incident["incident_id"],),
                ).fetchall()
                lifted_measures = [row["measure_id"] for row in measure_rows]
                for measure_id in lifted_measures:
                    self.connection.execute(
                        "UPDATE measures SET state='lifted',lifted_at=?,revision=revision+1 WHERE measure_id=?",
                        (self._now(), measure_id),
                    )
                self.connection.execute(
                    "UPDATE incidents SET state='closed',closed_at=? WHERE incident_id=?",
                    (self._now(), incident["incident_id"]),
                )
                new_state = "closed"
            else:
                task_exists = self.connection.execute(
                    "SELECT 1 FROM remediation_tasks WHERE incident_id=?", (incident["incident_id"],)
                ).fetchone()
                measure_exists = self.connection.execute(
                    "SELECT 1 FROM measures WHERE incident_id=? AND state='active'",
                    (incident["incident_id"],),
                ).fetchone()
                new_state = "remediating" if task_exists else ("contained" if measure_exists else "open")
                self.connection.execute(
                    "UPDATE incidents SET state=? WHERE incident_id=?",
                    (new_state, incident["incident_id"]),
                )
            self._audit("incident", incident["incident_id"], "closure.reviewed", actor_id,
                        {"review_id": review_id, "verdict": verdict, "lifted_measures": lifted_measures,
                         "incident_state": new_state})
        return {"review_id": review_id, "incident_id": incident["incident_id"], "verdict": verdict,
                "incident_state": self._incident(incident["incident_id"])["state"],
                "lifted_measures": lifted_measures}

    def reopen_incident(self, actor_id: str, incident_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "incident.reopen")
        note = contracts.required_text(note, "note")
        with transaction(self.connection, immediate=True):
            incident = self._incident(incident_id)
            if incident["state"] != "closed":
                raise InvalidState("事件未关闭，无需重开")
            # 归档关闭前的证据周期：历史版本保留可查，但不再参与当前影响区域计算，
            # 使新一轮证据的区域变化（新增/移除）能够被清楚呈现。
            self.connection.execute(
                "UPDATE evidence SET archived=1 WHERE incident_id=? AND archived=0", (incident_id,)
            )
            self.connection.execute(
                "UPDATE incidents SET state='reopened',closed_at=NULL,current_zones_json='[]' "
                "WHERE incident_id=?",
                (incident_id,),
            )
            self._audit("incident", incident_id, "incident.reopened", actor_id,
                        {"note": note, "archived_revision": incident["current_revision"]})
        return {"incident_id": incident_id, "state": "reopened"}

    # ------------------------------------------------------------------ 查询

    def snapshot(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "read")
        incident = self._incident(incident_id)
        latest = None
        if incident["latest_assessment_id"] is not None:
            row = self.connection.execute(
                "SELECT a.revision,a.result,a.zones_json,a.added_zones_json,a.removed_zones_json,"
                "a.change_reason,a.created_at,e.source_ref,e.kind,e.origin "
                "FROM assessments a JOIN evidence e ON e.evidence_id=a.evidence_id "
                "WHERE a.assessment_id=(SELECT max(assessment_id) FROM assessments WHERE incident_id=?)",
                (incident_id,),
            ).fetchone()
            if row is not None:
                latest = {
                    "revision": row["revision"],
                    "result": row["result"],
                    "source_ref": row["source_ref"],
                    "kind": row["kind"],
                    "origin": row["origin"],
                    "zones": _loads(row["zones_json"]),
                    "added_zones": _loads(row["added_zones_json"]),
                    "removed_zones": _loads(row["removed_zones_json"]),
                    "change_reason": row["change_reason"],
                    "created_at": row["created_at"],
                }
        return {
            "incident_id": incident["incident_id"],
            "title": incident["title"],
            "contaminant": incident["contaminant"],
            "severity": incident["severity"],
            "state": incident["state"],
            "revision": incident["current_revision"],
            "zones": _loads(incident["current_zones_json"]),
            "latest_assessment": latest,
            "closed_at": incident["closed_at"],
        }

    @staticmethod
    def _overdue(due_at: str | None, now_text: str) -> bool:
        return bool(due_at) and due_at <= now_text

    def todos(self, actor_id: str, incident_id: str | None = None) -> dict[str, Any]:
        """当前措施、责任人、待办时限，供值班人员一屏查询。"""
        self._require(actor_id, "read")
        now_text = self._now()
        if incident_id is not None:
            self._incident(incident_id)
        params: list[Any] = []
        if incident_id is not None:
            params.append(incident_id)
        measures = []
        for row in self.connection.execute(
            "SELECT * FROM measures WHERE state='active'" +
            (" AND incident_id=?" if incident_id is not None else "") +
            " ORDER BY due_at IS NULL,due_at,measure_id",
            params,
        ).fetchall():
            item = self._measure_dict(row)
            item["overdue"] = self._overdue(item["due_at"], now_text)
            measures.append(item)
        tasks = []
        for row in self.connection.execute(
            "SELECT * FROM remediation_tasks WHERE state IN ('open','in_progress')" +
            (" AND incident_id=?" if incident_id is not None else "") + " ORDER BY due_at IS NULL,due_at,task_id",
            params,
        ).fetchall():
            item = dict(row)
            item["overdue"] = self._overdue(item["due_at"], now_text)
            tasks.append(item)
        return {"as_of": now_text, "active_measures": measures, "open_tasks": tasks}

    def history(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        """整条决策沿革：证据版本、区域变化理由、措施、修复、复核裁决按时间排列。"""
        self._require(actor_id, "read")
        incident = self._incident(incident_id)
        timeline: list[dict[str, Any]] = [{
            "type": "incident.created",
            "at": incident["created_at"],
            "by": incident["created_by"],
            "state": "open",
        }]
        for row in self.connection.execute(
            "SELECT a.assessment_id,a.revision,a.result,a.zones_json,a.added_zones_json,a.removed_zones_json,"
            "a.change_reason,a.basis_json,a.created_at,a.decided_by,e.source_ref,e.kind,e.origin,e.reading_json "
            "FROM assessments a JOIN evidence e ON e.evidence_id=a.evidence_id "
            "WHERE a.incident_id=? ORDER BY a.revision",
            (incident_id,),
        ).fetchall():
            timeline.append({
                "type": "assessment",
                "at": row["created_at"],
                "by": row["decided_by"],
                "revision": row["revision"],
                "result": row["result"],
                "evidence": {"source_ref": row["source_ref"], "kind": row["kind"], "origin": row["origin"],
                             "reading": _loads(row["reading_json"])},
                "zones": _loads(row["zones_json"]),
                "added_zones": _loads(row["added_zones_json"]),
                "removed_zones": _loads(row["removed_zones_json"]),
                "change_reason": row["change_reason"],
                "basis": _loads(row["basis_json"]),
            })
        for row in self.connection.execute(
            "SELECT * FROM measures WHERE incident_id=? ORDER BY measure_id", (incident_id,)
        ).fetchall():
            timeline.append({
                "type": "measure",
                "at": row["created_at"],
                "measure_id": row["measure_id"],
                "kind": row["kind"],
                "title": row["title"],
                "zones": _loads(row["zones_json"]),
                "state": row["state"],
                "owner_id": row["owner_id"],
                "due_at": row["due_at"],
                "lifted_at": row["lifted_at"],
            })
        for row in self.connection.execute(
            "SELECT * FROM remediation_tasks WHERE incident_id=? ORDER BY created_at,task_id", (incident_id,)
        ).fetchall():
            timeline.append({
                "type": "task",
                "at": row["created_at"],
                "task_id": row["task_id"],
                "zone_code": row["zone_code"],
                "title": row["title"],
                "state": row["state"],
                "assignee_id": row["assignee_id"],
                "due_at": row["due_at"],
                "completed_at": row["completed_at"],
            })
        for row in self.connection.execute(
            "SELECT * FROM closure_reviews WHERE incident_id=? ORDER BY review_id", (incident_id,)
        ).fetchall():
            timeline.append({
                "type": "closure_request",
                "at": row["requested_at"],
                "review_id": row["review_id"],
                "state": row["state"],
                "request_note": row["request_note"],
                "requested_by": row["requested_by"],
            })
            if row["reviewed_at"]:
                timeline.append({
                    "type": "closure_decision",
                    "at": row["reviewed_at"],
                    "review_id": row["review_id"],
                    "state": row["state"],
                    "verdict": row["verdict"],
                    "review_note": row["review_note"],
                    "reviewer_id": row["reviewer_id"],
                })
        audit_rows = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM env_audit_events "
            "WHERE incident_id=? ORDER BY event_id",
            (incident_id,),
        ).fetchall()
        audit = [{"event_type": row["event_type"], "actor_id": row["actor_id"],
                  "payload": _loads(row["payload_json"]), "created_at": row["created_at"]} for row in audit_rows]
        timeline.sort(key=lambda item: (item["at"], item["type"]))
        return {"incident_id": incident_id, "state": incident["state"],
                "revision": incident["current_revision"], "timeline": timeline, "audit_log": audit}

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM env_audit_events ORDER BY event_id").fetchall()
        previous_hash = GENESIS_HASH
        valid = True
        for row in rows:
            body = {
                "incident_id": row["incident_id"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": _loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
