"""End-to-end HTTP/API smoke test against a real running server.

Spawns app/server.py on an ephemeral port with a temporary AUDIT_DB and
exercises: health probe, browser UI, committed-transaction redo, loser
rollback, frozen-verdict retrieval, and the "rejection clears old success
evidence" guarantee.

Exits 0 on success, non-zero on failure (used by the verify container).
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "app")

Z = "00" * 4096


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_ready(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.25)
    raise RuntimeError(f"server not ready: {last}")


def request(method: str, url: str, body=None, expect=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
        ctype = e.headers.get("Content-Type", "")
    if "application/json" in ctype:
        payload = json.loads(raw.decode()) if raw else None
    else:
        payload = raw.decode(errors="replace")
    if expect is not None and status != expect:
        raise AssertionError(f"{method} {url} -> {status}, expected {expect}: {payload}")
    return status, payload


def main() -> int:
    base_url = os.environ.get("SMOKE_BASE_URL")
    if base_url:
        # Target an already-running server (e.g. the compose `web` service).
        return run_checks(base_url, managed_proc=None, managed_tmp=None)

    port = free_port()
    tmp = tempfile.TemporaryDirectory()
    db = os.path.join(tmp.name, "audit.db")
    env = dict(os.environ, PORT=str(port), HOST="127.0.0.1", AUDIT_DB=db,
               PYTHONPATH=APP)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(APP, "server.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        wait_ready(port)
        return run_checks(f"http://127.0.0.1:{port}", proc, tmp)
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        tmp.cleanup()


def run_checks(base: str, managed_proc, managed_tmp) -> int:
    failures = []
    out = ""
    try:

        def check(name, cond, detail=""):
            print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail and not cond else ''}")
            if not cond:
                failures.append(name)

        # 1. health
        status, payload = request("GET", f"{base}/healthz")
        check("GET /healthz 200 ok", status == 200 and payload.get("status") == "ok")

        # 2. browser UI
        status, _ = request("GET", f"{base}/")
        check("GET / serves browser UI", status == 200)
        status, _ = request("GET", f"{base}/static/app.js")
        check("GET /static/app.js reachable", status == 200)

        # 3. sample available
        status, sample = request("GET", f"{base}/api/sample")
        check("GET /api/sample", status == 200 and "wal" in sample)

        # 4. committed transaction: missing update is redone and kept
        committed = {
            "auditId": "SMOKE-COMMIT",
            "pages": [{"page": 1, "pageLSN": 10, "data": Z}],
            "wal": [
                {"lsn": 10, "type": "begin", "xid": "T1"},
                {"lsn": 20, "type": "update", "xid": "T1", "prevLSN": 10,
                 "page": 1, "offset": 0, "before": "00000000", "after": "aaaaaaaa"},
                {"lsn": 30, "type": "commit", "xid": "T1", "prevLSN": 20},
                {"lsn": 40, "type": "end", "xid": "T1", "prevLSN": 30},
            ],
        }
        status, payload = request("POST", f"{base}/api/recover", committed, expect=200)
        v = payload["verdict"]
        check("committed redo accepted", payload["status"] == "accepted")
        check("committed update redone", v["redone"] == 1 and v["undone"] == 0)
        check("committed bytes survive", v["pages"][0]["data"].startswith("aaaaaaaa"))
        check("final sha256 present", len(v["pages"][0]["sha256After"]) == 64)

        # 5. frozen verdict readable afterwards
        status, payload = request("GET", f"{base}/api/audit?auditId=SMOKE-COMMIT")
        check("frozen verdict readable", status == 200 and payload["status"] == "accepted")

        # 6. loser rollback via the sample scenario (T2 loses)
        sample["auditId"] = "SMOKE-LOSER"
        status, payload = request("POST", f"{base}/api/recover", sample, expect=200)
        v = payload["verdict"]
        check("loser scenario accepted", payload["status"] == "accepted")
        check("loser T2 identified", v["loserTransactions"] == ["T2"])
        check("loser update redone then undone", v["redone"] == 1 and v["undone"] == 1)
        p7 = next(p for p in v["pages"] if p["page"] == 7)
        check("loser bytes rolled back", p7["data"][32:40] == "00" * 4)
        check("committed T1 bytes remain", p7["data"].startswith("11" * 16))

        # 7. corrupted predecessor chain -> stable rejection
        corrupted = json.loads(json.dumps(committed))
        corrupted["auditId"] = "SMOKE-REJECT"
        corrupted["wal"][1]["prevLSN"] = 999
        status, payload = request("POST", f"{base}/api/recover", corrupted, expect=422)
        check("broken chain rejected 422", status == 422 and "断链" in payload["error"])
        status, payload = request("GET", f"{base}/api/audit?auditId=SMOKE-REJECT")
        check("rejection frozen as rejected", payload["status"] == "rejected")

        # 8. rejection of same audit id CLEARS earlier success evidence
        status, payload = request("POST", f"{base}/api/recover", committed, expect=200)
        check("baseline success stored", payload["status"] == "accepted")
        corrupted2 = json.loads(json.dumps(committed))
        corrupted2["wal"][1]["before"] = "bbbbbbbb"  # wrong before-image on redo
        # page zeros != before and != after(missing) -> redo error 前像不匹配
        status, payload = request("POST", f"{base}/api/recover", corrupted2, expect=422)
        check("wrong before-image rejected 422", status == 422 and "前像" in payload["error"])
        status, payload = request("GET", f"{base}/api/audit?auditId=SMOKE-COMMIT")
        check("old success evidence replaced by rejection",
              payload["status"] == "rejected" and "verdict" not in payload)

        # 9. unknown audit id
        status, _ = request("GET", f"{base}/api/audit?auditId=NOPE", expect=404)
        check("unknown auditId -> 404", status == 404)

    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append(f"exception: {exc}")
    finally:
        if managed_proc is not None:
            managed_proc.terminate()
            try:
                out, _ = managed_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                managed_proc.kill()
                out, _ = managed_proc.communicate()
        if managed_tmp is not None:
            managed_tmp.cleanup()

    if failures:
        print(f"\nSMOKE FAILED ({len(failures)}): {failures}")
        print("--- server output ---")
        print(out[-2000:])
        return 1
    print("\nALL HTTP/API SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
