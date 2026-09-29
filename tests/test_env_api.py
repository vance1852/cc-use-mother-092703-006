from __future__ import annotations

import json
import sqlite3
import unittest

from env_response.api import JsonApplication
from env_response.service import ResponseService


class EnvApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(ResponseService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path: str, payload: dict, actor: str = "cmd") -> tuple[int, dict]:
        response = self.app.handle(
            "POST", path, {"x-actor-id": actor},
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )
        return response.status, response.body

    def _get(self, path: str, actor: str = "cmd") -> tuple[int, dict]:
        response = self.app.handle("GET", path, {"x-actor-id": actor})
        return response.status, response.body

    def _seed(self) -> None:
        for user_id, role in (("duty", "duty"), ("cmd", "commander"), ("rev", "reviewer")):
            status, body = self._post("/users", {"user_id": user_id, "display_name": user_id, "role": role})
            self.assertEqual(status, 201, body)
        self.assertEqual(self._post("/zones", {
            "zone_id": "z-a", "name": "甲车间", "zone_type": "workshop", "business": "涂装",
        })[0], 201)
        self.assertEqual(self._post("/incidents", {
            "incident_id": "inc-1", "title": "排口异常",
            "signal_source": "monitor-1", "signal_detail": {"cod": 420},
        }, actor="duty")[0], 201)

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_full_flow_over_http(self) -> None:
        self._seed()
        status, evidence = self._post("/incidents/inc-1/evidence", {
            "source_id": "SRC-1", "evidence_kind": "field_retest", "title": "现场复测",
            "affected_zone_ids": ["z-a"], "severity": "major", "detail": {"cod": 400},
        }, actor="duty")
        self.assertEqual(status, 201, evidence)
        self.assertEqual(evidence["revision"], 1)

        status, isolation = self._post("/incidents/inc-1/isolation", {
            "title": "封控甲车间", "zone_ids": ["z-a"],
            "responsible_id": "cmd", "due_at": "2026-09-29T06:00:00Z",
        })
        self.assertEqual(status, 201, isolation)
        status, repair = self._post("/incidents/inc-1/repairs", {
            "title": "修复加药泵", "zone_ids": ["z-a"], "responsible_id": "duty",
        })
        self.assertEqual(status, 201, repair)

        status, body = self._post(
            f"/measures/{repair['measure_id']}/updates", {"status": "completed", "note": "done"}
        )
        self.assertEqual(status, 200, body)

        status, request = self._post("/incidents/inc-1/release-requests", {"note": "申请恢复"})
        self.assertEqual(status, 201, request)
        status, decision = self._post(
            f"/release-reviews/{request['review_id']}/decision",
            {"approve": True, "note": "复核通过"}, actor="rev",
        )
        self.assertEqual(status, 200, decision)
        self.assertEqual(decision["incident_state"], "released")

        status, board = self._get("/board", actor="duty")
        self.assertEqual(status, 200)
        self.assertEqual(board["incidents"][0]["state"], "released")

        status, history = self._get("/incidents/inc-1/history", actor="rev")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(history["events"]), 8)

    def test_missing_actor_is_422(self) -> None:
        response = self.app.handle("GET", "/board")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_unknown_route_is_404(self) -> None:
        response = self.app.handle("GET", "/nope", {"x-actor-id": "cmd"})
        self.assertEqual(response.status, 404)

    def test_duplicate_evidence_source_is_conflict_or_dedup(self) -> None:
        self._seed()
        payload = {
            "source_id": "SRC-1", "evidence_kind": "field_retest", "title": "现场复测",
            "affected_zone_ids": ["z-a"], "severity": "major", "detail": {},
        }
        self.assertEqual(self._post("/incidents/inc-1/evidence", payload, actor="duty")[0], 201)
        status, replay = self._post("/incidents/inc-1/evidence", payload, actor="duty")
        self.assertEqual(status, 201)
        self.assertTrue(replay["duplicate"])
        changed = dict(payload)
        changed["detail"] = {"cod": 1}
        status, body = self._post("/incidents/inc-1/evidence", changed, actor="duty")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "conflict")


if __name__ == "__main__":
    unittest.main()
