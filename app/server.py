"""HTTP service: browser UI + recovery API + health probe.

Endpoints
---------
GET  /                      browser UI
GET  /static/*              static assets
GET  /healthz               health response (JSON)
POST /api/recover           submit pages + WAL; returns a frozen verdict or a
                            stable rejection (HTTP 422).  A rejection for an
                            audit id removes any previously frozen success.
GET  /api/audit?auditId=..  read the frozen verdict / rejection
GET  /api/sample            a ready-to-use demo payload

Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recovery import RecoveryError, recover  # noqa: E402
from storage import AuditStore  # noqa: E402

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 8 * 1024 * 1024  # 8 MiB cap on a single submission

SAMPLE: dict[str, Any] = {
    "auditId": "AOC-AUDIT-DEMO-0001",
    "pages": [
        {"page": 7, "pageLSN": 30, "data": ("11" * 16) + ("00" * (4096 - 16))},
        {"page": 9, "pageLSN": 20, "data": ("ab" * 8) + ("00" * (4096 - 8))},
    ],
    "wal": [
        {"lsn": 10, "type": "begin", "xid": "T1"},
        {"lsn": 20, "type": "update", "xid": "T1", "prevLSN": 10, "page": 9,
         "offset": 0, "before": "0000000000000000", "after": "abababababababab"},
        {"lsn": 30, "type": "update", "xid": "T1", "prevLSN": 20, "page": 7,
         "offset": 0, "before": "00" * 16, "after": "11" * 16},
        {"lsn": 35, "type": "begin", "xid": "T2"},
        {
            "lsn": 40, "type": "checkpoint",
            "transactions": {"T1": 30, "T2": 35},
            "dirtyPages": {"7": 30},
        },
        {"lsn": 60, "type": "update", "xid": "T2", "prevLSN": 35, "page": 7,
         "offset": 16, "before": "00000000", "after": "22222222"},
        {"lsn": 70, "type": "commit", "xid": "T1", "prevLSN": 30},
        {"lsn": 80, "type": "end", "xid": "T1", "prevLSN": 70},
        # T2 never commits -> loser; its LSN-60 update is redone then undone.
    ],
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AriesAudit/1.0"
    store: Optional[AuditStore] = None

    # ---- helpers ---------------------------------------------------------
    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, rel_path: str, content_type: str) -> None:
        safe = os.path.normpath(os.path.join(STATIC_DIR, rel_path))
        if not safe.startswith(STATIC_DIR + os.sep) or not os.path.isfile(safe):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        with open(safe, "rb") as fh:
            body = fh.read()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[http] %s - %s\n" % (self.address_string(), fmt % args))

    def _send_accepted_replay(self, audit_id: str) -> bool:
        if not audit_id:
            return False
        cached = self.store.get_accepted_replay(audit_id)
        if cached is None:
            return False
        self._send_json(
            HTTPStatus.OK,
            {
                "status": "accepted",
                "replayed": True,
                "verdict": cached["verdict"],
            },
        )
        return True

    # ---- routing ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok", "service": "aries-recovery-audit"})
            return
        if path == "/api/sample":
            self._send_json(HTTPStatus.OK, SAMPLE)
            return
        if path == "/api/audit":
            qs = parse_qs(parsed.query)
            audit_id = (qs.get("auditId") or [""])[0].strip()
            if not audit_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "缺少 auditId 查询参数"})
                return
            row = self.store.get(audit_id)
            if row is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"无审计标识 {audit_id} 的冻结裁决"})
            else:
                self._send_json(HTTPStatus.OK, row)
            return
        if path == "/" or path == "/index.html":
            self._send_file("index.html", "text/html; charset=utf-8")
            return
        if path.startswith("/static/"):
            name = path[len("/static/"):]
            ctype = "application/javascript; charset=utf-8" if name.endswith(".js") else \
                "text/css; charset=utf-8" if name.endswith(".css") else \
                "application/octet-stream"
            self._send_file(name, ctype)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/recover":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "空请求体"})
            return
        if length > MAX_BODY:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "请求体超过 8 MiB 上限"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"请求体不是合法 JSON：{exc}"})
            return

        audit_id = payload.get("auditId") if isinstance(payload, dict) else None
        audit_id = audit_id.strip() if isinstance(audit_id, str) else ""

        if self._send_accepted_replay(audit_id):
            return

        try:
            verdict = recover(payload)
        except RecoveryError as exc:
            # Stable rejection: persist and clear any prior success evidence.
            if audit_id:
                try:
                    self.store.save_rejected(audit_id, payload, str(exc))
                except Exception:  # pragma: no cover - storage failure must not mask verdict
                    traceback.print_exc()
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"status": "rejected", "auditId": audit_id or None, "error": str(exc)},
            )
            return
        except Exception as exc:  # internal error must never look like a verdict
            traceback.print_exc()
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"服务内部错误：{exc}"})
            return

        self.store.save_accepted(verdict["auditId"], payload, verdict)
        self._send_json(HTTPStatus.OK, {"status": "accepted", "verdict": verdict})


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("AUDIT_DB", "/data/audit.db")
    Handler.store = AuditStore(db_path)
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[http] recovery audit listening on {host}:{port} (db={db_path})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        Handler.store.close()


if __name__ == "__main__":
    main()
