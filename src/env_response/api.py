"""无第三方依赖的环境事件响应 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import EnvironmentalError, ValidationFailed
from .service import IncidentService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    def __init__(self, service: IncidentService) -> None:
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

    def handle(self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b"") -> Response:
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            if method == "POST" and path == "/users":
                return Response(201, self.service.create_user(payload["user_id"], payload["display_name"], payload["role"]))
            actor = self._actor(normalized)
            if method == "POST" and path == "/incidents":
                return Response(201, self.service.create_incident(actor, payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "evidence":
                return Response(201, self.service.record_evidence(actor, parts[1], payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "field-records":
                return Response(201, self.service.submit_field_records(actor, parts[1], payload.get("records", [])))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "measures":
                return Response(201, self.service.create_measure(actor, parts[1], payload))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "measures":
                return Response(200, self.service.measures_status(actor, parts[1]))
            if method == "POST" and path == "/measures/cancel":
                return Response(200, self.service.cancel_measure(actor, int(payload["measure_id"]), payload["reason"]))
            if method == "POST" and len(parts) == 2 and parts[0] == "measures":
                return Response(200, self.service.update_measure(
                    actor, int(parts[1]), payload.get("owner_id"),
                    payload.get("due_at", ...), payload.get("expected_revision")))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "tasks":
                return Response(201, self.service.create_task(actor, parts[1], payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "tasks" and parts[2] == "start":
                return Response(200, self.service.start_task(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "tasks" and parts[2] == "complete":
                return Response(200, self.service.complete_task(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "tasks" and parts[2] == "verify":
                return Response(200, self.service.verify_task(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "closure-requests":
                return Response(201, self.service.request_closure(actor, parts[1], payload["note"]))
            if method == "POST" and len(parts) == 3 and parts[0] == "closure-reviews" and parts[2] == "decision":
                return Response(200, self.service.decide_review(
                    actor, int(parts[1]), payload["verdict"], payload["note"], payload.get("expected_revision")))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "reopen":
                return Response(200, self.service.reopen_incident(actor, parts[1], payload["note"]))
            if method == "GET" and len(parts) == 2 and parts[0] == "incidents":
                return Response(200, self.service.snapshot(actor, parts[1]))
            if method == "GET" and path == "/todos":
                incident_id = query.get("incident_id", [None])[0]
                return Response(200, self.service.todos(actor, incident_id))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "history":
                return Response(200, self.service.history(actor, parts[1]))
            if method == "GET" and path == "/audit/chain":
                return Response(200, self.service.audit_chain(actor))
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except EnvironmentalError as exc:
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
    server = ThreadingHTTPServer((args.host, args.port), make_handler(JsonApplication(IncidentService(connection))))
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
