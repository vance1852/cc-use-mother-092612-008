"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .incidents import IncidentService
from .service import DomainService
from .storage import Database


def _query_value(query: dict[str, list[str]], name: str, required: bool = False) -> str | None:
    value = query.get(name, [None])[0]
    if required and not value:
        raise ValidationError(f"{name} 不能为空")
    return value


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None,
          incidents: IncidentService | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    actor_id = headers.get("X-Actor-Id", "")
    incident_service = incidents or IncidentService(service)
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count,
                         "open_actions_without_owner": incident_service.count_unowned_open_actions()}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            query = parse_qs(parsed.query)
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            query = parse_qs(parsed.query)
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}
        # ---- 跨专区事件指挥模块 ----
        if method == "POST" and parsed.path == "/incident-reports":
            receipt = incident_service.submit_report(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/incident-reports":
            query = parse_qs(parsed.query)
            site_id = _query_value(query, "site_id", required=True)
            return 200, {"items": incident_service.list_reports(actor_id=actor_id, site_id=site_id)}
        if method == "GET" and parsed.path == "/incident-report":
            query = parse_qs(parsed.query)
            report_id = _query_value(query, "report_id", required=True)
            return 200, incident_service.get_report(report_id=report_id, actor_id=actor_id or None)
        if method == "POST" and parsed.path == "/incidents":
            receipt = incident_service.open_incident(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/incidents":
            query = parse_qs(parsed.query)
            items = incident_service.list_incidents(
                actor_id=actor_id, site_id=_query_value(query, "site_id"),
                status=_query_value(query, "status"))
            return 200, {"items": items}
        if method == "GET" and parsed.path == "/incident":
            query = parse_qs(parsed.query)
            incident_id = _query_value(query, "incident_id", required=True)
            return 200, incident_service.get_incident(actor_id=actor_id, incident_id=incident_id)
        if method == "GET" and parsed.path == "/incident-status":
            query = parse_qs(parsed.query)
            incident_id = _query_value(query, "incident_id", required=True)
            return 200, incident_service.public_status(incident_id=incident_id)
        if method == "GET" and parsed.path == "/merge-candidates":
            query = parse_qs(parsed.query)
            items = incident_service.list_merge_candidates(
                actor_id=actor_id, site_id=_query_value(query, "site_id"),
                incident_id=_query_value(query, "incident_id"),
                status=_query_value(query, "status"))
            return 200, {"items": items}
        if method == "POST" and parsed.path == "/merge-decisions":
            receipt = incident_service.decide_merge(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/escalations":
            receipt = incident_service.escalate(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/qualifications":
            receipt = incident_service.grant_qualification(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/support-requests":
            receipt = incident_service.request_support(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/support-request-updates":
            receipt = incident_service.update_support(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/incident-actions":
            receipt = incident_service.create_action(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/incident-actions":
            query = parse_qs(parsed.query)
            incident_id = _query_value(query, "incident_id", required=True)
            return 200, {"items": incident_service.list_actions(actor_id=actor_id,
                                                                incident_id=incident_id)}
        if method == "POST" and parsed.path == "/incident-action-updates":
            receipt = incident_service.update_action(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/handovers":
            receipt = incident_service.initiate_handover(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/handover-acceptances":
            receipt = incident_service.accept_handover(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/handover-cancellations":
            receipt = incident_service.cancel_handover(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/closure-requests":
            receipt = incident_service.propose_closure(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/closure-decisions":
            receipt = incident_service.decide_closure(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/evidence-supplements":
            receipt = incident_service.supplement_evidence(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/reopen-requests":
            receipt = incident_service.request_reopen(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/reopen-decisions":
            receipt = incident_service.decide_reopen(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/incident-history":
            query = parse_qs(parsed.query)
            incident_id = _query_value(query, "incident_id", required=True)
            return 200, {"items": incident_service.incident_history(actor_id=actor_id,
                                                                    incident_id=incident_id)}
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService

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
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动技能赛训协作基础服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service = DomainService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
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
