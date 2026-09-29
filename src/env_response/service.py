"""环境事件响应的领域用例：证据版本判断、区域措施与授权解除。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Mapping, Sequence

from .clock import SystemClock, parse_utc, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


SEVERITY_ORDER = {"watch": 1, "minor": 2, "major": 3, "critical": 4}
EVIDENCE_KINDS = {"field_retest", "third_party", "calibration", "other"}
MEASURE_TYPES = {"isolation", "dispatch", "repair"}
MEASURE_STATES = {"pending", "in_progress", "completed", "cancelled"}
FINISHED_STATES = {"completed", "cancelled"}

ROLE_PERMISSIONS = {
    "duty": {"incident.create", "evidence.submit", "board.read", "report.read"},
    "commander": {
        "zone.write", "incident.create", "evidence.submit", "measure.write",
        "release.request", "incident.close", "board.read", "report.read", "audit.read",
    },
    "reviewer": {"release.review", "board.read", "report.read", "audit.read"},
    "auditor": {"report.read", "audit.read"},
}


class ResponseService:
    """在单个 SQLite 连接上提供全部环境事件响应操作。"""

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
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

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
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": dict(payload),
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO env_audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
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

    # -------------------------------------------------------------- 输入校验

    @staticmethod
    def _text(value: object, field: str, maximum: int = 256) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationFailed(f"{field} 不能为空")
        result = value.strip()
        if len(result) > maximum:
            raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
        return result

    @staticmethod
    def _detail(value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValidationFailed("detail 必须是 JSON 对象")
        return value

    def _zone_ids(self, value: object, field: str, *, allow_empty: bool = False) -> list[str]:
        if not isinstance(value, (list, tuple)) or (not value and not allow_empty):
            raise ValidationFailed(f"{field} 必须是{'数组' if allow_empty else '非空数组'}")
        result: list[str] = []
        for item in value:
            zone_id = self._text(item, f"{field} 元素", 64)
            if zone_id in result:
                raise ValidationFailed(f"{field} 含重复区域 {zone_id}")
            result.append(zone_id)
        return result

    def _require_zones_exist(self, zone_ids: Sequence[str]) -> None:
        for zone_id in zone_ids:
            row = self.connection.execute(
                "SELECT active FROM zones WHERE zone_id=?", (zone_id,)
            ).fetchone()
            if row is None:
                raise ValidationFailed(f"区域不存在: {zone_id}")
            if not row["active"]:
                raise ValidationFailed(f"区域已停用: {zone_id}")

    def _due_at(self, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValidationFailed("due_at 必须是 ISO 8601 时间")
        try:
            return utc_text(parse_utc(value, "due_at"))
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc

    def _incident_row(self, incident_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFound("事件不存在")
        return row

    def _measure_row(self, measure_id: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM measures WHERE measure_id=?", (measure_id,)
        ).fetchone()
        if row is None:
            raise NotFound("措施不存在")
        return row

    # ------------------------------------------------------------- 用户与区域

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed("未知角色")
        user_id = self._text(user_id, "user_id", 64)
        display_name = self._text(display_name, "display_name", 128)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO env_users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id, display_name, role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id, "role": role}

    def register_zone(
        self, actor_id: str, zone_id: str, name: str, zone_type: str, business: str
    ) -> dict[str, Any]:
        self._require(actor_id, "zone.write")
        zone_id = self._text(zone_id, "zone_id", 64)
        name = self._text(name, "name", 128)
        zone_type = self._text(zone_type, "zone_type", 64)
        business = self._text(business, "business", 128)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO zones(zone_id,name,zone_type,business,created_at) VALUES(?,?,?,?,?)",
                    (zone_id, name, zone_type, business, self._now()),
                )
                self._audit("zone", zone_id, "zone.registered", actor_id, {"name": name, "business": business})
        except sqlite3.IntegrityError as exc:
            raise Conflict("区域编号已经存在") from exc
        return {"zone_id": zone_id, "name": name, "zone_type": zone_type, "business": business}

    def zone(self, zone_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM zones WHERE zone_id=?", (zone_id,)).fetchone()
        if row is None:
            raise NotFound("区域不存在")
        return dict(row)

    # ------------------------------------------------------------------ 事件

    def create_incident(
        self,
        actor_id: str,
        incident_id: str,
        title: str,
        signal_source: str,
        signal_detail: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._require(actor_id, "incident.create")
        incident_id = self._text(incident_id, "incident_id", 64)
        title = self._text(title, "title", 200)
        signal_source = self._text(signal_source, "signal_source", 128)
        signal_detail = self._detail(signal_detail)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO incidents(incident_id,title,signal_source,signal_detail_json,state,"
                    "created_by,created_at) VALUES(?,?,?,?, 'monitoring', ?,?)",
                    (incident_id, title, signal_source, canonical_json(signal_detail), actor_id, self._now()),
                )
                self._audit(
                    "incident",
                    incident_id,
                    "incident.created",
                    actor_id,
                    {"title": title, "signal_source": signal_source, "signal_detail": signal_detail},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("事件编号已经存在") from exc
        return {"incident_id": incident_id, "state": "monitoring", "revision": 0}

    def _latest_assessment(self, incident_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM assessments WHERE incident_id=? ORDER BY revision DESC LIMIT 1",
            (incident_id,),
        ).fetchone()

    def _effective_zones(self, incident_id: str) -> tuple[list[str], list[str]]:
        """按全部证据汇总：指认区域并集减去证据排除区域并集。"""

        rows = self.connection.execute(
            "SELECT affected_zone_ids_json,cleared_zone_ids_json FROM evidence "
            "WHERE incident_id=? ORDER BY evidence_id",
            (incident_id,),
        ).fetchall()
        implicated: set[str] = set()
        cleared: set[str] = set()
        for row in rows:
            implicated.update(json.loads(row["affected_zone_ids_json"]))
            cleared.update(json.loads(row["cleared_zone_ids_json"]))
        affected = implicated - cleared
        return sorted(affected), sorted(cleared)

    def add_evidence(
        self,
        actor_id: str,
        incident_id: str,
        source_id: str,
        evidence_kind: str,
        title: str,
        affected_zone_ids: Sequence[str],
        severity: str,
        detail: Mapping[str, Any],
        change_note: str | None = None,
        cleared_zone_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """追加一份证据并形成新版本的事件判断。

        同一事件下 source_id 全局唯一：并发提交的相同来源记录只保留一条，
        完全重复的提交原样返回，不同内容则报冲突。
        """

        self._require(actor_id, "evidence.submit")
        source_id = self._text(source_id, "source_id", 128)
        title = self._text(title, "title", 200)
        if evidence_kind not in EVIDENCE_KINDS:
            raise ValidationFailed("未知证据类型")
        if severity not in SEVERITY_ORDER:
            raise ValidationFailed("未知严重级别")
        detail = self._detail(detail)
        affected = self._zone_ids(affected_zone_ids, "affected_zone_ids", allow_empty=True)
        cleared = self._zone_ids(cleared_zone_ids or [], "cleared_zone_ids") if cleared_zone_ids else []
        overlap = sorted(set(affected) & set(cleared))
        if overlap:
            raise ValidationFailed(f"同一证据不能同时指认并排除区域: {overlap}")
        if not affected and not cleared:
            raise ValidationFailed("证据必须指认或排除至少一个区域")
        self._require_zones_exist(affected + cleared)
        incident = self._incident_row(incident_id)
        if incident["state"] in {"released", "closed"}:
            raise InvalidState("事件已解除或关闭，不能再追加证据")

        body_digest = content_digest({
            "evidence_kind": evidence_kind,
            "title": title,
            "affected_zone_ids": affected,
            "cleared_zone_ids": cleared,
            "severity": severity,
            "detail": detail,
        })
        duplicate = self.connection.execute(
            "SELECT evidence_id,content_sha256 FROM evidence WHERE incident_id=? AND source_id=?",
            (incident_id, source_id),
        ).fetchone()
        if duplicate is not None:
            if duplicate["content_sha256"] != body_digest:
                raise Conflict("同一来源编号已提交过不同内容的现场记录")
            existing = self.connection.execute(
                "SELECT * FROM evidence WHERE evidence_id=?", (duplicate["evidence_id"],)
            ).fetchone()
            return {"evidence_id": existing["evidence_id"], "duplicate": True, "state": "deduplicated"}

        previous = self._latest_assessment(incident_id)
        note = self._text(change_note or "", "change_note", 500) if previous is not None else (change_note or "").strip()

        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO evidence(incident_id,source_id,evidence_kind,title,affected_zone_ids_json,"
                    "cleared_zone_ids_json,severity,detail_json,content_sha256,submitted_by,submitted_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        incident_id, source_id, evidence_kind, title, canonical_json(affected),
                        canonical_json(cleared), severity, canonical_json(detail), body_digest, actor_id, now,
                    ),
                )
                evidence_id = int(cursor.lastrowid)

                evidence_rows = self.connection.execute(
                    "SELECT evidence_id,source_id,content_sha256,severity FROM evidence "
                    "WHERE incident_id=? ORDER BY evidence_id",
                    (incident_id,),
                ).fetchall()
                effective, all_cleared = self._effective_zones(incident_id)
                prior_zones: set[str] = set()
                prior_revision = 0
                if previous is not None:
                    prior_zones = set(json.loads(previous["affected_zone_ids_json"]))
                    prior_revision = previous["revision"]
                revision = prior_revision + 1
                added = sorted(set(effective) - prior_zones)
                removed = sorted(prior_zones - set(effective))
                if revision == 1:
                    direction = "initial"
                elif added and not removed:
                    direction = "expanded"
                elif removed and not added:
                    direction = "narrowed"
                elif not added and not removed:
                    direction = "unchanged"
                else:
                    direction = "expanded" if len(effective) >= len(prior_zones) else "narrowed"
                reason = note if revision > 1 else "首份证据形成初始判断"
                worst = max(
                    (row["severity"] for row in evidence_rows),
                    key=lambda value: SEVERITY_ORDER[value],
                )
                isolated = self._isolated_zone_ids(incident_id)
                if not isolated:
                    containment = "none"
                elif set(effective) <= set(isolated):
                    containment = "full"
                else:
                    containment = "partial"
                set_digest = content_digest([
                    [row["evidence_id"], row["source_id"], row["content_sha256"]] for row in evidence_rows
                ])
                assessment_cursor = self.connection.execute(
                    "INSERT INTO assessments(incident_id,revision,basis_evidence_ids_json,affected_zone_ids_json,"
                    "severity,containment_level,change_direction,change_reason,change_added_json,"
                    "change_removed_json,evidence_set_sha256,decided_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        incident_id, revision,
                        canonical_json([row["evidence_id"] for row in evidence_rows]),
                        canonical_json(effective), worst, containment, direction, reason,
                        canonical_json(added), canonical_json(removed), set_digest, actor_id, now,
                    ),
                )
                assessment_id = int(assessment_cursor.lastrowid)
                self.connection.execute(
                    "UPDATE incidents SET revision=?, current_assessment_id=? WHERE incident_id=?",
                    (revision, assessment_id, incident_id),
                )
                isolation_change = self._sync_isolation(incident_id, effective, actor_id, evidence_id)
                self._audit(
                    "incident",
                    incident_id,
                    "evidence.submitted",
                    actor_id,
                    {
                        "evidence_id": evidence_id,
                        "source_id": source_id,
                        "evidence_kind": evidence_kind,
                        "severity": severity,
                        "affected_zone_ids": affected,
                        "cleared_zone_ids": cleared,
                    },
                )
                self._audit(
                    "incident",
                    incident_id,
                    "assessment.versioned",
                    actor_id,
                    {
                        "assessment_id": assessment_id,
                        "revision": revision,
                        "direction": direction,
                        "added": added,
                        "removed": removed,
                        "reason": reason,
                        "driven_by_evidence": evidence_id,
                        "affected_zone_ids": effective,
                    },
                )
        except sqlite3.IntegrityError as exc:
            winner = self.connection.execute(
                "SELECT evidence_id,content_sha256 FROM evidence WHERE incident_id=? AND source_id=?",
                (incident_id, source_id),
            ).fetchone()
            if winner is not None and winner["content_sha256"] == body_digest:
                return {"evidence_id": winner["evidence_id"], "duplicate": True, "state": "deduplicated"}
            raise Conflict("证据来源编号或判断版本并发冲突，请重试") from exc
        return {
            "evidence_id": evidence_id,
            "assessment_id": assessment_id,
            "revision": revision,
            "duplicate": False,
            "direction": direction,
            "affected_zone_ids": effective,
            "added_zone_ids": added,
            "removed_zone_ids": removed,
            "change_reason": reason,
            "severity": worst,
            "isolation_change": isolation_change,
        }

    # ------------------------------------------------------------- 隔离与措施

    def _isolated_zone_ids(self, incident_id: str) -> list[str]:
        rows = self.connection.execute(
            "SELECT l.zone_id FROM measure_zone_links l "
            "JOIN measures m ON m.measure_id=l.measure_id "
            "WHERE m.incident_id=? AND m.measure_type='isolation' AND m.status NOT IN ('completed','cancelled')",
            (incident_id,),
        ).fetchall()
        return sorted(row["zone_id"] for row in rows)

    def _sync_isolation(
        self, incident_id: str, effective_zones: Sequence[str], actor_id: str, evidence_id: int
    ) -> dict[str, Any] | None:
        """让生效中的隔离措施与最新判断区域保持一致，返回变更说明。"""

        row = self.connection.execute(
            "SELECT measure_id FROM measures WHERE incident_id=? AND measure_type='isolation' "
            "AND status NOT IN ('completed','cancelled') ORDER BY measure_id LIMIT 1",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        measure_id = row["measure_id"]
        current = set(self._isolated_zone_ids(incident_id))
        target = set(effective_zones)
        added = sorted(target - current)
        removed = sorted(current - target)
        if not added and not removed:
            return None
        for zone_id in added:
            self.connection.execute(
                "INSERT INTO measure_zone_links(measure_id,zone_id) VALUES(?,?)",
                (measure_id, zone_id),
            )
        if removed:
            placeholders = ",".join("?" for _ in removed)
            self.connection.execute(
                f"DELETE FROM measure_zone_links WHERE measure_id=? AND zone_id IN ({placeholders})",
                [measure_id, *removed],
            )
        self.connection.execute(
            "UPDATE measures SET revision=revision+1 WHERE measure_id=?", (measure_id,)
        )
        self._audit(
            "measure",
            str(measure_id),
            "isolation.adjusted",
            actor_id,
            {"evidence_id": evidence_id, "added": added, "removed": removed},
        )
        return {"measure_id": measure_id, "added": added, "removed": removed}

    def _create_measure(
        self,
        actor_id: str,
        incident_id: str,
        measure_type: str,
        title: str,
        responsible_id: str,
        zone_ids: Sequence[str],
        due_at: str | None,
        detail: Mapping[str, Any],
        event_type: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "measure.write")
        incident = self._incident_row(incident_id)
        if incident["state"] in {"released", "closed"}:
            raise InvalidState("事件已解除或关闭，不能再安排措施")
        title = self._text(title, "title", 200)
        self._text(responsible_id, "responsible_id", 64)
        self._user(responsible_id)
        zones = self._zone_ids(zone_ids, "zone_ids")
        self._require_zones_exist(zones)
        due_text = self._due_at(due_at)
        detail = self._detail(detail)
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO measures(incident_id,measure_type,title,detail_json,status,responsible_id,"
                "due_at,created_by,created_at) VALUES(?,?,?,?,'pending',?,?,?,?)",
                (incident_id, measure_type, title, canonical_json(detail), responsible_id, due_text, actor_id, now),
            )
            measure_id = int(cursor.lastrowid)
            for zone_id in zones:
                self.connection.execute(
                    "INSERT INTO measure_zone_links(measure_id,zone_id) VALUES(?,?)",
                    (measure_id, zone_id),
                )
            if measure_type == "isolation":
                self.connection.execute(
                    "UPDATE incidents SET state='controlling' WHERE incident_id=? AND state='monitoring'",
                    (incident_id,),
                )
            self._audit(
                "measure",
                str(measure_id),
                event_type,
                actor_id,
                {
                    "incident_id": incident_id,
                    "title": title,
                    "zone_ids": zones,
                    "responsible_id": responsible_id,
                    "due_at": due_text,
                },
            )
        return self.measure(measure_id)

    def order_isolation(
        self,
        actor_id: str,
        incident_id: str,
        title: str,
        zone_ids: Sequence[str],
        responsible_id: str,
        due_at: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "measure.write")
        assessment = self._latest_assessment(incident_id)
        if assessment is None:
            raise InvalidState("事件尚未形成证据判断，不能隔离")
        affected = set(json.loads(assessment["affected_zone_ids_json"]))
        outside = sorted(set(zone_ids) - affected)
        if outside:
            raise InvalidState(f"隔离区域超出当前判断影响范围: {outside}")
        return self._create_measure(
            actor_id, incident_id, "isolation", title, responsible_id, zone_ids, due_at,
            detail or {}, "isolation.ordered",
        )

    def dispatch_resource(
        self,
        actor_id: str,
        incident_id: str,
        title: str,
        zone_ids: Sequence[str],
        responsible_id: str,
        due_at: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._create_measure(
            actor_id, incident_id, "dispatch", title, responsible_id, zone_ids, due_at,
            detail or {}, "resource.dispatched",
        )

    def assign_repair(
        self,
        actor_id: str,
        incident_id: str,
        title: str,
        zone_ids: Sequence[str],
        responsible_id: str,
        due_at: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._create_measure(
            actor_id, incident_id, "repair", title, responsible_id, zone_ids, due_at,
            detail or {}, "repair.assigned",
        )

    def update_measure(
        self, actor_id: str, measure_id: int, status: str, note: str | None = None
    ) -> dict[str, Any]:
        self._require(actor_id, "measure.write")
        if status not in MEASURE_STATES:
            raise ValidationFailed("未知措施状态")
        note = (note or "").strip()
        row = self._measure_row(measure_id)
        if row["status"] in FINISHED_STATES:
            raise InvalidState("措施已经结束，不能再变更")
        if status == row["status"] and not note:
            raise InvalidState("措施状态未变化")
        now = self._now()
        with transaction(self.connection, immediate=True):
            completed_at = now if status == "completed" else None
            self.connection.execute(
                "UPDATE measures SET status=?, completed_at=?, result_note=?, revision=revision+1 "
                "WHERE measure_id=? AND status NOT IN ('completed','cancelled')",
                (status, completed_at, note or None, measure_id),
            )
            # 修复推进只代表处置进展，管控状态保持 controlling，绝不自动解除。
            if row["measure_type"] == "repair" and status == "completed":
                self.connection.execute(
                    "UPDATE incidents SET state='recovering' WHERE incident_id=? AND state='controlling'",
                    (row["incident_id"],),
                )
            self._audit(
                "measure",
                str(measure_id),
                "measure.updated",
                actor_id,
                {
                    "incident_id": row["incident_id"],
                    "measure_type": row["measure_type"],
                    "status": status,
                    "note": note,
                    "auto_released": False,
                },
            )
        return self.measure(measure_id)

    def measure(self, measure_id: int) -> dict[str, Any]:
        row = self._measure_row(measure_id)
        return self._measure_dict(row)

    def _measure_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        zones = [
            item["zone_id"]
            for item in self.connection.execute(
                "SELECT zone_id FROM measure_zone_links WHERE measure_id=? ORDER BY zone_id",
                (row["measure_id"],),
            ).fetchall()
        ]
        result = dict(row)
        result["detail"] = json.loads(result.pop("detail_json"))
        result["zone_ids"] = zones
        overdue = False
        if row["due_at"] and row["status"] not in FINISHED_STATES:
            overdue = parse_utc(row["due_at"], "due_at") < self.clock.now()
        result["overdue"] = overdue
        return result

    def list_measures(
        self,
        actor_id: str,
        incident_id: str | None = None,
        status: str | None = None,
        responsible_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self._require(actor_id, "board.read")
        sql = "SELECT * FROM measures WHERE 1=1"
        params: list[Any] = []
        if incident_id is not None:
            sql += " AND incident_id=?"
            params.append(incident_id)
        if status is not None:
            if status not in MEASURE_STATES:
                raise ValidationFailed("未知措施状态")
            sql += " AND status=?"
            params.append(status)
        if responsible_id is not None:
            sql += " AND responsible_id=?"
            params.append(responsible_id)
        sql += " ORDER BY measure_id"
        rows = self.connection.execute(sql, params).fetchall()
        return [self._measure_dict(row) for row in rows]

    # ------------------------------------------------------------- 解除与复核

    def request_release(self, actor_id: str, incident_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "release.request")
        note = self._text(note, "note", 500)
        incident = self._incident_row(incident_id)
        if incident["state"] not in {"controlling", "recovering"}:
            raise InvalidState("只有管控或修复中的事件可以申请解除")
        pending = self.connection.execute(
            "SELECT review_id FROM release_reviews WHERE incident_id=? AND status='pending'",
            (incident_id,),
        ).fetchone()
        if pending is not None:
            raise Conflict("已有待处理的解除复核")
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO release_reviews(incident_id,incident_revision,status,note,requested_by,requested_at) "
                "VALUES(?,?,'pending',?,?,?)",
                (incident_id, incident["revision"], note, actor_id, now),
            )
            review_id = int(cursor.lastrowid)
            self._audit(
                "review",
                str(review_id),
                "release.requested",
                actor_id,
                {"incident_id": incident_id, "incident_revision": incident["revision"], "note": note},
            )
        return {"review_id": review_id, "status": "pending", "incident_revision": incident["revision"]}

    def review_release(self, actor_id: str, review_id: int, approve: bool, note: str) -> dict[str, Any]:
        self._require(actor_id, "release.review")
        note = self._text(note, "note", 500)
        row = self.connection.execute(
            "SELECT * FROM release_reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFound("解除复核不存在")
        if row["status"] != "pending":
            raise InvalidState("解除复核已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能授权自己的解除申请")
        incident_id = row["incident_id"]
        now = self._now()
        with transaction(self.connection, immediate=True):
            if approve:
                unfinished = self.connection.execute(
                    "SELECT measure_id,title FROM measures WHERE incident_id=? "
                    "AND measure_type!='isolation' AND status NOT IN ('completed','cancelled')",
                    (incident_id,),
                ).fetchall()
                if unfinished:
                    raise InvalidState(
                        "仍有调度或修复任务未完成: " + ",".join(item["title"] for item in unfinished)
                    )
                isolation_rows = self.connection.execute(
                    "SELECT measure_id FROM measures WHERE incident_id=? AND measure_type='isolation' "
                    "AND status NOT IN ('completed','cancelled')",
                    (incident_id,),
                ).fetchall()
                self.connection.execute(
                    "UPDATE measures SET status='completed', completed_at=?, result_note=?, revision=revision+1 "
                    "WHERE incident_id=? AND measure_type='isolation' AND status NOT IN ('completed','cancelled')",
                    (now, "授权复核通过，解除隔离", incident_id),
                )
                resumed_zones = sorted({
                    item["zone_id"]
                    for measure in isolation_rows
                    for item in self.connection.execute(
                        "SELECT zone_id FROM measure_zone_links WHERE measure_id=?", (measure["measure_id"],)
                    ).fetchall()
                })
                self.connection.execute(
                    "UPDATE incidents SET state='released' WHERE incident_id=?", (incident_id,)
                )
                event_type = "release.approved"
                payload: dict[str, Any] = {"note": note, "resumed_zone_ids": resumed_zones}
            else:
                self.connection.execute(
                    "UPDATE incidents SET state='controlling' WHERE incident_id=? AND state='recovering'",
                    (incident_id,),
                )
                event_type = "release.rejected"
                payload = {"note": note}
            self.connection.execute(
                "UPDATE release_reviews SET status=?, reviewed_by=?, reviewed_at=?, review_note=? "
                "WHERE review_id=? AND status='pending'",
                ("approved" if approve else "rejected", actor_id, now, note, review_id),
            )
            self._audit("review", str(review_id), event_type, actor_id, payload)
            self._audit(
                "incident",
                incident_id,
                event_type,
                actor_id,
                {"review_id": review_id, **payload},
            )
        return {
            "review_id": review_id,
            "status": "approved" if approve else "rejected",
            "incident_state": self.incident_status(incident_id)["state"],
            **payload,
        }

    def close_incident(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "incident.close")
        incident = self._incident_row(incident_id)
        if incident["state"] != "released":
            raise InvalidState("只有已解除的事件可以归档关闭")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE incidents SET state='closed' WHERE incident_id=? AND state='released'",
                (incident_id,),
            )
            self._audit("incident", incident_id, "incident.closed", actor_id, {})
        return {"incident_id": incident_id, "state": "closed"}

    # ------------------------------------------------------------------ 查询

    def incident_status(self, incident_id: str) -> dict[str, Any]:
        incident = self._incident_row(incident_id)
        result = dict(incident)
        result["signal_detail"] = json.loads(result.pop("signal_detail_json"))
        assessment = self._latest_assessment(incident_id)
        result["current_assessment"] = None if assessment is None else self._assessment_dict(assessment)
        result["isolated_zone_ids"] = self._isolated_zone_ids(incident_id)
        result["active_measures"] = [
            self._measure_dict(row)
            for row in self.connection.execute(
                "SELECT * FROM measures WHERE incident_id=? AND status NOT IN ('completed','cancelled') "
                "ORDER BY measure_id",
                (incident_id,),
            ).fetchall()
        ]
        review = self.connection.execute(
            "SELECT * FROM release_reviews WHERE incident_id=? ORDER BY review_id DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
        result["latest_review"] = None if review is None else dict(review)
        return result

    def _assessment_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "assessment_id": row["assessment_id"],
            "revision": row["revision"],
            "basis_evidence_ids": json.loads(row["basis_evidence_ids_json"]),
            "affected_zone_ids": json.loads(row["affected_zone_ids_json"]),
            "severity": row["severity"],
            "containment_level": row["containment_level"],
            "change_direction": row["change_direction"],
            "change_reason": row["change_reason"],
            "added_zone_ids": json.loads(row["change_added_json"]),
            "removed_zone_ids": json.loads(row["change_removed_json"]),
            "evidence_set_sha256": row["evidence_set_sha256"],
            "decided_by": row["decided_by"],
            "created_at": row["created_at"],
        }

    def assessments(self, incident_id: str) -> list[dict[str, Any]]:
        self._incident_row(incident_id)
        rows = self.connection.execute(
            "SELECT * FROM assessments WHERE incident_id=? ORDER BY revision", (incident_id,)
        ).fetchall()
        return [self._assessment_dict(row) for row in rows]

    def evidence_list(self, incident_id: str) -> list[dict[str, Any]]:
        self._incident_row(incident_id)
        rows = self.connection.execute(
            "SELECT * FROM evidence WHERE incident_id=? ORDER BY evidence_id", (incident_id,)
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["affected_zone_ids"] = json.loads(item.pop("affected_zone_ids_json"))
            item["cleared_zone_ids"] = json.loads(item.pop("cleared_zone_ids_json"))
            item["detail"] = json.loads(item.pop("detail_json"))
            items.append(item)
        return items

    def duty_board(self, actor_id: str) -> dict[str, Any]:
        """值班视图：当前状态、措施、责任人与待办时限。"""

        self._require(actor_id, "board.read")
        now = self.clock.now()
        incidents = self.connection.execute(
            "SELECT * FROM incidents WHERE state!='closed' ORDER BY incident_id"
        ).fetchall()
        board: list[dict[str, Any]] = []
        for incident in incidents:
            measures = [
                self._measure_dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM measures WHERE incident_id=? AND status NOT IN ('completed','cancelled') "
                    "ORDER BY due_at IS NULL, due_at, measure_id",
                    (incident["incident_id"],),
                ).fetchall()
            ]
            assessment = self._latest_assessment(incident["incident_id"])
            board.append({
                "incident_id": incident["incident_id"],
                "title": incident["title"],
                "state": incident["state"],
                "revision": incident["revision"],
                "severity": None if assessment is None else assessment["severity"],
                "affected_zone_ids": []
                if assessment is None else json.loads(assessment["affected_zone_ids_json"]),
                "open_measures": measures,
                "overdue_count": sum(
                    1 for item in measures
                    if item["due_at"] and parse_utc(item["due_at"], "due_at") < now
                ),
            })
        return {"as_of": self._now(), "incidents": board}

    def history(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        """整条决策沿革：事件、证据、判断版本、措施、复核与审计链。"""

        self._require(actor_id, "report.read")
        incident = self.incident_status(incident_id)
        measures = [
            self._measure_dict(row)
            for row in self.connection.execute(
                "SELECT * FROM measures WHERE incident_id=? ORDER BY measure_id", (incident_id,)
            ).fetchall()
        ]
        reviews = [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM release_reviews WHERE incident_id=? ORDER BY review_id", (incident_id,)
            ).fetchall()
        ]
        events = self._incident_events(incident_id)
        return {
            "incident": incident,
            "evidence": self.evidence_list(incident_id),
            "assessments": self.assessments(incident_id),
            "measures": measures,
            "release_reviews": reviews,
            "events": events,
        }

    def _incident_events(self, incident_id: str) -> list[dict[str, Any]]:
        """汇总事件本身及其全部措施、复核单的审计事件，按发生顺序排列。"""

        review_ids = [row["review_id"] for row in self.connection.execute(
            "SELECT review_id FROM release_reviews WHERE incident_id=? ORDER BY review_id",
            (incident_id,),
        ).fetchall()]
        clauses = ["entity_id=?"]
        params: list[Any] = [incident_id]
        measure_ids = [row[0] for row in self.connection.execute(
            "SELECT measure_id FROM measures WHERE incident_id=?", (incident_id,)
        ).fetchall()]
        if measure_ids:
            clauses.append(
                "(entity_type='measure' AND entity_id IN ("
                + ",".join("?" * len(measure_ids)) + "))"
            )
            params.extend(str(measure_id) for measure_id in measure_ids)
        if review_ids:
            clauses.append(
                "(entity_type='review' AND entity_id IN ("
                + ",".join("?" * len(review_ids)) + "))"
            )
            params.extend(str(review_id) for review_id in review_ids)
        where = " OR ".join(clauses)
        rows = self.connection.execute(
            f"SELECT * FROM env_audit_events WHERE {where} ORDER BY event_id", params
        ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM env_audit_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
