"""HTTP service: browser UI + recovery API + health probe.

Endpoints
---------
GET  /                      browser UI
GET  /static/*              static assets
GET  /healthz               health response (JSON)
POST /api/recover           submit pages + WAL.  Every request is fully
                            validated by the recovery engine first; the store
                            then atomically decides the outcome:
                              200 frozen   — first success for the auditId
                              200 replayed — semantically identical retransmit
                              409 conflict — different valid history, the first
                                             frozen evidence is kept
                              422 rejected — validation failed; any earlier
                                             success evidence is cleared
GET  /api/audit?auditId=..  read the frozen verdict / rejection / conflict
GET  /api/sample            a ready-to-use demo payload

Standard library only.
"""

from __future__ import annotations

import hashlib
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
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "请求体超过 8 MiB 上限"}
            )
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"请求体不是合法 JSON：{exc}"})
            return

        audit_id = payload.get("auditId") if isinstance(payload, dict) else None
        audit_id = audit_id.strip() if isinstance(audit_id, str) else ""

        # Every submission — including repeat submissions of a frozen id —
        # must actually go through recovery validation.  Nothing is replayed
        # before the engine has spoken.
        try:
            verdict = recover(payload)
        except RecoveryError as exc:
            return self._handle_invalid(audit_id, payload, exc)
        except Exception as exc:  # internal error must never look like a verdict
            traceback.print_exc()
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"服务内部错误：{exc}"}
            )
            return

        audit_id = verdict["auditId"]
        fingerprint = verdict["inputFingerprint"]
        try:
            outcome, frozen_verdict, frozen_error = self.store.submit(
                audit_id, payload, verdict, fingerprint
            )
        except Exception as exc:  # pragma: no cover
            traceback.print_exc()
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"存储失败：{exc}"}
            )
            return

        if outcome == "frozen":
            self._send_json(
                HTTPStatus.OK,
                {"status": "accepted", "outcome": "frozen", "verdict": verdict},
            )
            return
        if outcome == "replayed":
            # Semantically identical retransmission (field order / hex case
            # may differ): replay the originally frozen verdict.
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "accepted",
                    "outcome": "replayed",
                    "replayed": True,
                    "verdict": frozen_verdict,
                },
            )
            return

        # The identifier is already bound to a different frozen history.
        if frozen_verdict is not None:
            body = {
                "status": "conflict",
                "outcome": "conflict",
                "auditId": audit_id,
                "error": (
                    f"审计标识 {audit_id} 已冻结另一份恢复输入（指纹 "
                    f"{frozen_verdict.get('inputFingerprint', '')[:16]}…）；"
                    "本次为业务内容不同的合法恢复历史，判定为标识冲突，"
                    "最先冻结的审计证据保持不变。"
                ),
                "frozenFingerprint": frozen_verdict.get("inputFingerprint"),
                "submittedFingerprint": fingerprint,
                "verdict": frozen_verdict,
            }
        else:
            # The id was frozen with a stable rejection of a different input.
            body = {
                "status": "conflict",
                "outcome": "conflict",
                "auditId": audit_id,
                "error": (
                    f"审计标识 {audit_id} 已冻结另一份（被稳定拒绝的）恢复历史；"
                    f"本次合法恢复历史判为标识冲突，冻结记录保持不变。"
                    f"既有拒绝原因：{frozen_error}"
                ),
                "submittedFingerprint": fingerprint,
            }
        self._send_json(HTTPStatus.CONFLICT, body)

    def _handle_invalid(self, audit_id: str, payload: Any,
                        exc: RecoveryError) -> None:
        """Persist and answer a request that failed recovery validation."""
        fingerprint = getattr(exc, "fingerprint", None)
        if fingerprint is None:
            # Input failed structural parsing (so the engine could not build
            # its semantic fingerprint): fall back to a canonical hash of the
            # raw JSON, so an identical malformed retransmission still
            # replays stably instead of looking like a new conflict.
            try:
                fingerprint = hashlib.sha256(
                    json.dumps(payload, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8")
                ).hexdigest()
            except (TypeError, ValueError):
                fingerprint = None
        if not audit_id:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"status": "rejected", "outcome": "rejected",
                 "auditId": None, "error": str(exc)},
            )
            return
        try:
            outcome, frozen_verdict, stored_error = self.store.submit_rejected(
                audit_id, payload, str(exc), fingerprint
            )
        except Exception:  # pragma: no cover - storage must not mask the verdict
            traceback.print_exc()
            outcome, frozen_verdict, stored_error = "rejected", None, str(exc)

        if outcome == "replayed":
            if frozen_verdict is not None:
                # The frozen input rejected on a later pass: keep history.
                self._send_json(
                    HTTPStatus.OK,
                    {"status": "accepted", "outcome": "replayed",
                     "replayed": True, "verdict": frozen_verdict},
                )
                return
            # Identical retransmission of a frozen rejection: same 422.
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"status": "rejected", "outcome": "replayed",
                 "auditId": audit_id, "error": stored_error},
            )
            return

        if outcome == "conflict":
            self._send_json(
                HTTPStatus.CONFLICT,
                {"status": "conflict", "outcome": "conflict",
                 "auditId": audit_id,
                 "error": (
                     f"审计标识 {audit_id} 已冻结另一份被稳定拒绝的恢复历史；"
                     "本次输入不同，判为标识冲突，冻结记录保持不变。"
                     f"既有拒绝原因：{stored_error}"
                 )},
            )
            return

        # rejected (first record) or rejection_recorded (a former success was
        # cleared in the same transaction and replaced by this rejection).
        self._send_json(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            {"status": "rejected", "outcome": outcome,
             "auditId": audit_id, "error": str(exc)},
        )


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
