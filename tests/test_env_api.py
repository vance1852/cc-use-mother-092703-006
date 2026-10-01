from __future__ import annotations

import json
import sqlite3
import unittest

from env_response.api import JsonApplication
from env_response.service import IncidentService


def _json(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(IncidentService(self.connection))
        for actor, role in (
            ("duty", "duty"), ("field", "field"), ("dispatch", "dispatcher"),
            ("repair", "remediation"), ("review", "reviewer"), ("audit", "auditor"),
        ):
            self.app.handle("POST", "/users", body=_json(
                {"user_id": actor, "display_name": actor, "role": role}))

    def tearDown(self) -> None:
        self.connection.close()

    def _headers(self, actor: str) -> dict[str, str]:
        return {"X-Actor-Id": actor, "Content-Type": "application/json"}

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_requires_actor(self) -> None:
        response = self.app.handle("GET", "/incidents/inc-1")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_full_flow_via_http(self) -> None:
        response = self.app.handle("POST", "/incidents", self._headers("duty"), _json({
            "incident_id": "inc-1", "title": "VOC", "contaminant": "voc"}))
        self.assertEqual(response.status, 201)

        response = self.app.handle("POST", "/incidents/inc-1/evidence", self._headers("duty"), _json({
            "source_ref": "alert-1", "kind": "monitor_alert", "origin": "站房",
            "zones": ["zone-a"], "observed_at": "2026-09-24T08:00:00+08:00",
            "change_note": "初判"}))
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["zones"], ["zone-a"])

        response = self.app.handle("POST", "/incidents/inc-1/measures", self._headers("dispatch"), _json({
            "kind": "zone_isolation", "title": "封锁", "zones": ["zone-a"], "owner_id": "dispatch"}))
        self.assertEqual(response.status, 201)

        response = self.app.handle("POST", "/incidents/inc-1/tasks", self._headers("repair"), _json({
            "task_id": "t-1", "zone_code": "zone-a", "title": "处置", "assignee_id": "repair"}))
        self.assertEqual(response.status, 201)

        response = self.app.handle("POST", "/tasks/t-1/start", self._headers("repair"))
        self.assertEqual(response.status, 200)
        response = self.app.handle("POST", "/tasks/t-1/complete", self._headers("repair"))
        self.assertEqual(response.status, 200)

        # 完成任务后不能直接关闭，必须走复核。
        response = self.app.handle("GET", "/incidents/inc-1", self._headers("audit"))
        self.assertEqual(response.body["state"], "remediating")

        response = self.app.handle("POST", "/incidents/inc-1/closure-requests",
                                   self._headers("repair"), _json({"note": "申请"}))
        review_id = response.body["review_id"]
        response = self.app.handle("POST", f"/closure-reviews/{review_id}/decision",
                                   self._headers("review"),
                                   _json({"verdict": "approved", "note": "同意"}))
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["incident_state"], "closed")

        response = self.app.handle("GET", "/incidents/inc-1/history", self._headers("audit"))
        self.assertEqual(response.status, 200)
        self.assertGreaterEqual(len(response.body["timeline"]), 6)

        response = self.app.handle("GET", "/todos?incident_id=inc-1", self._headers("duty"))
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["active_measures"], [])

    def test_dedup_endpoint(self) -> None:
        self.app.handle("POST", "/incidents", self._headers("duty"),
                        _json({"incident_id": "inc-2", "title": "噪声", "contaminant": "noise"}))
        record = {"source_ref": "r-1", "zone_code": "zone-a", "reading": "55dB",
                  "observed_at": "2026-09-24T08:00:00+08:00"}
        first = self.app.handle("POST", "/incidents/inc-2/field-records", self._headers("field"),
                                _json({"records": [record]}))
        second = self.app.handle("POST", "/incidents/inc-2/field-records", self._headers("field"),
                                 _json({"records": [record]}))
        self.assertEqual(first.body["inserted_count"], 1)
        self.assertEqual(second.body["deduped_count"], 1)

    def test_unknown_route(self) -> None:
        response = self.app.handle("GET", "/nope", self._headers("audit"))
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
