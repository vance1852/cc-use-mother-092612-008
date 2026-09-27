"""跨专区事件指挥模块的 HTTP/JSON 边界。

事件接口与基础接口共用同一个 IncidentService（它是基础 DomainService 的子类），
未命中事件路径的请求回落到基础路由，因此基础模块的既有接口保持不变。
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import api as base_api
from .errors import DomainError, ValidationError
from .incident_service import IncidentService
from .storage import Database


def _receipt_status(receipt) -> tuple[int, dict[str, Any]]:
    return 200 if receipt.replayed else 201, receipt.__dict__


def route(service: IncidentService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    """把事件相关 HTTP 请求分派到 IncidentService，其余回落到基础路由。"""

    headers = headers or {}
    body = dict(body or {})
    parsed = urlparse(path)
    segments = [s for s in parsed.path.split("/") if s]
    query = parse_qs(parsed.query)
    actor_id = headers.get("X-Actor-Id", "")

    def q(name: str, default: str | None = None) -> str | None:
        return query.get(name, [default])[0]

    try:
        # ---- 报告 ----
        if method == "POST" and parsed.path == "/reports":
            return _receipt_status(service.file_report(actor_id=actor_id, **body))
        if method == "GET" and parsed.path == "/reports":
            site_id = q("site_id")
            if not site_id:
                raise ValidationError("site_id 不能为空")
            return 200, {"items": service.list_reports(site_id, actor_id)}
        if method == "GET" and len(segments) == 2 and segments[0] == "reports":
            return 200, service.get_report(segments[1], actor_id)

        # ---- 合并候选 ----
        if method == "GET" and parsed.path == "/merge-candidates":
            return 200, {"items": service.list_merge_candidates(actor_id, q("status", "proposed"))}
        if method == "POST" and parsed.path == "/merges/confirm":
            return _receipt_status(service.confirm_merge(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/merges/reject":
            return _receipt_status(service.reject_merge(actor_id=actor_id, **body))

        # ---- 资格 ----
        if method == "POST" and parsed.path == "/qualifications":
            return _receipt_status(service.grant_qualification(actor_id=actor_id, **body))

        # ---- 指挥官 ----
        if method == "POST" and parsed.path == "/commanders":
            return _receipt_status(service.register_commander(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/recovery/startup":
            return 200, service.startup_recovery(actor_id or None)

        # ---- /incidents/{id}/... ----
        if len(segments) >= 2 and segments[0] == "incidents":
            incident_id = segments[1]
            if method == "GET" and len(segments) == 2:
                return 200, service.get_incident(incident_id, actor_id)
            if method == "GET" and len(segments) == 3 and segments[2] == "public":
                # 对外状态不要求操作者身份，只返回最小公开信息
                return 200, service.public_incident_status(incident_id)
            if method == "GET" and len(segments) == 3 and segments[2] == "causal-chain":
                return 200, {"items": service.causal_chain(incident_id, actor_id)}
            if method == "GET" and len(segments) == 3 and segments[2] == "actions":
                return 200, {"items": service.list_actions(incident_id, actor_id, q("status"))}
            if method == "POST" and len(segments) == 3 and segments[2] == "escalate":
                body["incident_id"] = incident_id
                return _receipt_status(service.escalate(actor_id=actor_id, **body))
            if method == "POST" and len(segments) == 3 and segments[2] == "actions":
                body["incident_id"] = incident_id
                return _receipt_status(service.create_action(actor_id=actor_id, **body))
            if method == "POST" and len(segments) == 3 and segments[2] == "support":
                body["incident_id"] = incident_id
                return _receipt_status(service.request_support(actor_id=actor_id, **body))
            if method == "POST" and len(segments) == 3 and segments[2] == "handovers":
                body["incident_id"] = incident_id
                return _receipt_status(service.initiate_handover(actor_id=actor_id, **body))
            if method == "POST" and len(segments) == 3 and segments[2] == "closures":
                body["incident_id"] = incident_id
                return _receipt_status(service.request_closure(actor_id=actor_id, **body))
            if method == "POST" and len(segments) == 3 and segments[2] == "commander-assignment":
                body["incident_id"] = incident_id
                return _receipt_status(service.assign_commander(actor_id=actor_id, **body))

        # ---- 行动 / 调援 / 交接 / 结案 / 复开的子资源操作 ----
        if method == "POST" and len(segments) == 3 and segments[0] == "actions" \
                and segments[2] == "transition":
            body["action_id"] = segments[1]
            return _receipt_status(service.transition_action(actor_id=actor_id, **body))
        if method == "POST" and len(segments) == 3 and segments[0] == "actions" \
                and segments[2] == "reassign":
            body["action_id"] = segments[1]
            return _receipt_status(service.reassign_action(actor_id=actor_id, **body))
        if method == "POST" and len(segments) == 3 and segments[0] == "support" \
                and segments[2] == "fulfill":
            body["support_id"] = segments[1]
            return _receipt_status(service.fulfill_support(actor_id=actor_id, **body))
        if method == "POST" and len(segments) == 3 and segments[0] == "support" \
                and segments[2] == "cancel":
            body["support_id"] = segments[1]
            return _receipt_status(service.cancel_support(actor_id=actor_id, **body))
        if method == "POST" and len(segments) == 3 and segments[0] == "handovers" \
                and segments[2] == "complete":
            body["handover_id"] = segments[1]
            return _receipt_status(service.complete_handover(actor_id=actor_id, **body))
        if method == "POST" and len(segments) == 3 and segments[0] == "closures" \
                and segments[2] == "review":
            body["closure_id"] = segments[1]
            return _receipt_status(service.review_closure(actor_id=actor_id, **body))
        if method == "POST" and len(segments) == 3 and segments[0] == "reopen-applications" \
                and segments[2] == "decision":
            body["application_id"] = segments[1]
            return _receipt_status(service.decide_reopen(actor_id=actor_id, **body))

        return base_api.route(service, method, path, body, headers)
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


class IncidentHandler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为事件路由调用。"""

    service: IncidentService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")})
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动包含事件指挥能力的 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动夜市跨专区事件指挥服务")
    parser.add_argument("--database", default="incident.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    IncidentHandler.service = IncidentService(database)
    server = ThreadingHTTPServer((args.host, args.port), IncidentHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
