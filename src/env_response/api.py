"""无第三方依赖的环境事件响应 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import ResponseError, ValidationFailed
from .service import ResponseService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Any


class JsonApplication:
    """将 HTTP 路由映射到领域服务，便于无网络单元测试。"""

    def __init__(self, service: ResponseService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    @staticmethod
    def _zones(payload: dict[str, Any], key: str = "zone_ids") -> list[str]:
        value = payload.get(key, [])
        if not isinstance(value, list):
            raise ValidationFailed(f"{key} 必须是数组")
        return value

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            actor = self._actor(normalized)
            service = self.service

            if method == "POST" and path == "/users":
                return Response(201, service.create_user(
                    payload["user_id"], payload["display_name"], payload["role"]
                ))
            if method == "POST" and path == "/zones":
                return Response(201, service.register_zone(
                    actor, payload["zone_id"], payload["name"],
                    payload["zone_type"], payload["business"],
                ))
            if method == "GET" and len(parts) == 2 and parts[0] == "zones":
                return Response(200, service.zone(parts[1]))
            if method == "POST" and path == "/incidents":
                return Response(201, service.create_incident(
                    actor, payload["incident_id"], payload["title"],
                    payload["signal_source"], payload.get("signal_detail", {}),
                ))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "evidence":
                return Response(201, service.add_evidence(
                    actor, parts[1], payload["source_id"], payload["evidence_kind"],
                    payload["title"], payload["affected_zone_ids"], payload["severity"],
                    payload.get("detail", {}), payload.get("change_note"),
                    payload.get("cleared_zone_ids"),
                ))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "assessments":
                return Response(200, {"incident_id": parts[1], "assessments": service.assessments(parts[1])})
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "evidence":
                return Response(200, {"incident_id": parts[1], "evidence": service.evidence_list(parts[1])})
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "history":
                return Response(200, service.history(actor, parts[1]))
            if method == "GET" and len(parts) == 2 and parts[0] == "incidents":
                return Response(200, service.incident_status(parts[1]))

            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "isolation":
                return Response(201, service.order_isolation(
                    actor, parts[1], payload["title"], self._zones(payload),
                    payload["responsible_id"], payload.get("due_at"), payload.get("detail"),
                ))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "dispatches":
                return Response(201, service.dispatch_resource(
                    actor, parts[1], payload["title"], self._zones(payload),
                    payload["responsible_id"], payload.get("due_at"), payload.get("detail"),
                ))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "repairs":
                return Response(201, service.assign_repair(
                    actor, parts[1], payload["title"], self._zones(payload),
                    payload["responsible_id"], payload.get("due_at"), payload.get("detail"),
                ))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "release-requests":
                return Response(201, service.request_release(actor, parts[1], payload["note"]))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "close":
                return Response(200, service.close_incident(actor, parts[1]))

            if method == "GET" and path == "/measures":
                return Response(200, {"measures": service.list_measures(
                    actor,
                    query.get("incident_id", [None])[0],
                    query.get("status", [None])[0],
                    query.get("responsible_id", [None])[0],
                )})
            if method == "POST" and len(parts) == 3 and parts[0] == "measures" and parts[2] == "updates":
                return Response(200, service.update_measure(
                    actor, int(parts[1]), payload["status"], payload.get("note")
                ))
            if method == "GET" and len(parts) == 2 and parts[0] == "measures":
                return Response(200, service.measure(int(parts[1])))

            if method == "POST" and len(parts) == 3 and parts[0] == "release-reviews" and parts[2] == "decision":
                return Response(200, service.review_release(
                    actor, int(parts[1]), bool(payload["approve"]), payload["note"]
                ))

            if method == "GET" and path == "/board":
                return Response(200, service.duty_board(actor))
            if method == "GET" and path == "/audit/chain":
                return Response(200, service.audit_chain(actor))
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except ResponseError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "EnvResponse/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动产业园环境事件响应服务")
    parser.add_argument("--database", type=Path, default=Path("env_response.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(JsonApplication(ResponseService(connection))))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
