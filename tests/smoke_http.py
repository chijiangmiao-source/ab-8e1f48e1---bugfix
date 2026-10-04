"""End-to-end HTTP/API acceptance test against a real running server.

Covers the stable-identifier freeze protocol:

  * first valid submission freezes a verdict (HTTP 200);
  * a semantically identical retransmit (reordered JSON keys, upper-case
    hex, 0x prefix) replays the first verdict (HTTP 200, replayed=true);
  * a different but itself valid recovery history is an identifier
    conflict (HTTP 409) and never overwrites the first freeze;
  * after a success, a formally complete but broken WAL (corrupted
    predecessor chain / reference to an ended transaction) still goes
    through recovery validation and is stably rejected (HTTP 422); the old
    success evidence is cleared and GET no longer returns a verdict;
  * two concurrent different valid first submissions: exactly one freezes;
  * after a server restart against the same database, replay / conflict /
    rejection behaviour is unchanged;
  * health probe and the browser page stay available.

Exits 0 on success, non-zero on failure (used by the verify container).
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "app")

Z = "00" * 4096

# Unique per process so re-running acceptance against a persistent database
# volume never collides with identifiers frozen by an earlier run.
RUN_ID = uuid.uuid4().hex[:12]


def newid(name: str) -> str:
    return f"{name}-{RUN_ID}"


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
            time.sleep(0.2)
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


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def committed_payload(audit_id, after="aaaaaaaa"):
    """A valid committed transaction whose update is missing from the page."""
    return {
        "auditId": audit_id,
        "pages": [{"page": 1, "pageLSN": 10, "data": Z}],
        "wal": [
            {"lsn": 10, "type": "begin", "xid": "T1"},
            {"lsn": 20, "type": "update", "xid": "T1", "prevLSN": 10,
             "page": 1, "offset": 0, "before": "00000000", "after": after},
            {"lsn": 30, "type": "commit", "xid": "T1", "prevLSN": 20},
            {"lsn": 40, "type": "end", "xid": "T1", "prevLSN": 30},
        ],
    }


def reordered_hex_variant(payload):
    """Same business input, different surface form: reordered keys,
    upper-case hex, 0x prefix and whitespace."""
    return {
        "auditId": payload["auditId"],
        "pages": [{"data": "0X" + Z.upper(), "pageLSN": 10, "page": 1}],
        "wal": [
            {"type": "begin", "xid": "T1", "lsn": 10},
            {"type": "update", "xid": "T1", "lsn": 20, "prevLSN": 10,
             "page": 1, "offset": 0,
             "before": "00000000",
             "after": payload["wal"][1]["after"].upper()},
            {"type": "commit", "xid": "T1", "prevLSN": 20, "lsn": 30},
            {"type": "end", "xid": "T1", "prevLSN": 30, "lsn": 40},
        ],
    }


def with_broken_chain(payload):
    p = json.loads(json.dumps(payload))
    p["wal"][1]["prevLSN"] = 999  # predecessor LSN absent from the WAL
    return p


def with_ended_transaction_reference(payload):
    p = json.loads(json.dumps(payload))
    p["wal"].append(
        {"lsn": 50, "type": "update", "xid": "T1", "prevLSN": 40,
         "page": 1, "offset": 8, "before": "0000", "after": "cccc"}
    )  # T1 already has an end record at LSN 40
    return p


def verdict_sig(v):
    return [(p["page"], p["sha256After"], p["pageLSNAfter"]) for p in v["pages"]]


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def spawn_server(port, db):
    env = dict(os.environ, PORT=str(port), HOST="127.0.0.1", AUDIT_DB=db,
               PYTHONPATH=APP)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(APP, "server.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    wait_ready(port)
    return proc


def stop_proc(proc):
    if proc is None:
        return ""
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out or ""


# ---------------------------------------------------------------------------
# Acceptance suites
# ---------------------------------------------------------------------------

def run_freeze_protocol(base, failures, prefix):
    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(f"{prefix}: {name}{(' — ' + detail) if detail else ''}")

    # 1. first valid submission freezes ------------------------------------
    pid = newid(f"{prefix}-FREEZE")
    p1 = committed_payload(pid, "aaaaaaaa")
    status, payload = request("POST", f"{base}/api/recover", p1, expect=200)
    check("first valid submission 200 accepted",
          status == 200 and payload.get("status") == "accepted"
          and payload.get("replayed") is False)
    frozen_sig = verdict_sig(payload["verdict"])
    check("committed update redone and kept",
          payload["verdict"]["redone"] == 1
          and payload["verdict"]["pages"][0]["data"].startswith("aaaaaaaa"))

    # 2. semantically identical retransmit replays the first verdict -------
    status, payload = request(
        "POST", f"{base}/api/recover", reordered_hex_variant(p1), expect=200
    )
    check("identical retransmit 200 replayed",
          status == 200 and payload.get("replayed") is True)
    check("replayed verdict is the frozen one",
          verdict_sig(payload["verdict"]) == frozen_sig)

    # 3. different but valid recovery history -> 409 conflict --------------
    p2 = committed_payload(pid, "bbbbbbbb")
    status, payload = request("POST", f"{base}/api/recover", p2, expect=409)
    check("different valid history -> 409 conflict",
          status == 409 and payload.get("status") == "conflict")
    status, got = request("GET", f"{base}/api/audit?auditId={pid}", expect=200)
    check("frozen record unchanged after conflict",
          got["status"] == "accepted"
          and got["verdict"]["pages"][0]["data"].startswith("aaaaaaaa")
          and not got["verdict"]["pages"][0]["data"].startswith("bbbbbbbb"))

    # The original input must still replay after the conflict attempt.
    status, payload = request("POST", f"{base}/api/recover", p1, expect=200)
    check("original input still replays after conflict",
          payload.get("replayed") is True
          and verdict_sig(payload["verdict"]) == frozen_sig)

    # 4. broken WAL after a success -> 422, evidence cleared ---------------
    status, payload = request(
        "POST", f"{base}/api/recover", with_broken_chain(p1), expect=422
    )
    check("broken predecessor chain 422", status == 422 and "断链" in payload["error"])
    status, got = request("GET", f"{base}/api/audit?auditId={pid}", expect=200)
    check("broken chain clears verdict from frozen record",
          got["status"] == "rejected" and "verdict" not in got
          and "断链" in got["error"])

    # 5. reference to an already-ended transaction on a fresh id -----------
    eid = newid(f"{prefix}-ENDED")
    pe = committed_payload(eid, "aaaaaaaa")
    request("POST", f"{base}/api/recover", pe, expect=200)
    status, payload = request(
        "POST", f"{base}/api/recover", with_ended_transaction_reference(pe),
        expect=422,
    )
    check("reference to ended transaction 422",
          status == 422 and "已结束事务" in payload["error"])
    status, got = request("GET", f"{base}/api/audit?auditId={eid}", expect=200)
    check("ended-txn rejection clears prior success",
          got["status"] == "rejected" and "verdict" not in got)

    # 6. concurrent different valid first submissions: one freeze only -----
    race_id = newid(f"{prefix}-RACE")
    ra = committed_payload(race_id, "aaaaaaaa")
    rb = committed_payload(race_id, "bbbbbbbb")
    results = []
    barrier = threading.Barrier(2)

    def worker(payload):
        barrier.wait()
        try:
            status, resp = request("POST", f"{base}/api/recover", payload)
        except Exception as exc:  # noqa: BLE001
            results.append(("error", str(exc)))
            return
        head = None
        if status == 200:
            head = resp["verdict"]["pages"][0]["data"][:8]
        results.append((status, head))

    t1 = threading.Thread(target=worker, args=(ra,))
    t2 = threading.Thread(target=worker, args=(rb,))
    t1.start(); t2.start(); t1.join(); t2.join()
    statuses = sorted(r[0] for r in results)
    check("concurrent first submissions -> one 200 + one 409",
          statuses == [200, 409], detail=str(results))
    status, got = request("GET", f"{base}/api/audit?auditId={race_id}", expect=200)
    winner = [r[1] for r in results if r[0] == 200][0]
    check("frozen record matches the single race winner",
          got["status"] == "accepted"
          and got["verdict"]["pages"][0]["data"][:8] == winner
          and winner in {"aaaaaaaa", "bbbbbbbb"})

    # 7. persistent ids for the post-restart suite -------------------------
    keep_id = newid(f"{prefix}-KEEP")
    cf_id = newid(f"{prefix}-CF")
    return {
        "ok": (keep_id, committed_payload(keep_id, "dddddddd")),
        "conflict": (cf_id, committed_payload(cf_id, "eeeeeeee")),
        "rejected": (pid, p1),
    }


def run_restart_protocol(base, failures, prefix, seeds):
    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(f"{prefix}: {name}{(' — ' + detail) if detail else ''}")

    ok_id, ok_payload = seeds["ok"]
    cf_id, cf_payload = seeds["conflict"]
    rej_id, rej_payload = seeds["rejected"]

    # accepted evidence survives restart and is byte-identical
    status, before = request("POST", f"{base}/api/recover", ok_payload, expect=200)
    before_sig = verdict_sig(before["verdict"])
    status, cf = request("POST", f"{base}/api/recover", cf_payload, expect=200)
    cf_sig = verdict_sig(cf["verdict"])
    request("POST", f"{base}/api/recover", with_broken_chain(rej_payload), expect=422)

    return {
        "ok_id": ok_id, "ok_payload": ok_payload, "ok_sig": before_sig,
        "cf_id": cf_id, "cf_sig": cf_sig,
        "cf_other": committed_payload(cf_id, "99999999"),
        "rej_id": rej_id, "rej_broken": with_broken_chain(rej_payload),
    }


def verify_after_restart(base, failures, prefix, state):
    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(f"{prefix}: {name}{(' — ' + detail) if detail else ''}")

    # accepted record still present, unchanged
    status, got = request("GET", f"{base}/api/audit?auditId={state['ok_id']}", expect=200)
    check("accepted verdict survives restart",
          got["status"] == "accepted"
          and verdict_sig(got["verdict"]) == state["ok_sig"])
    # identical input still replays
    status, payload = request(
        "POST", f"{base}/api/recover",
        reordered_hex_variant(state["ok_payload"]), expect=200)
    check("identical retransmit replays after restart",
          payload.get("replayed") is True
          and verdict_sig(payload["verdict"]) == state["ok_sig"])
    # different valid input still conflicts
    status, payload = request(
        "POST", f"{base}/api/recover", state["cf_other"], expect=409)
    check("different valid history conflicts after restart",
          status == 409 and payload.get("status") == "conflict")
    status, got = request("GET", f"{base}/api/audit?auditId={state['cf_id']}", expect=200)
    check("first conflict-side freeze survives restart",
          got["status"] == "accepted" and verdict_sig(got["verdict"]) == state["cf_sig"])
    # rejection record survives; no verdict is ever returned
    status, got = request("GET", f"{base}/api/audit?auditId={state['rej_id']}", expect=200)
    check("rejected record survives restart without verdict",
          got["status"] == "rejected" and "verdict" not in got)
    status, payload = request(
        "POST", f"{base}/api/recover", state["rej_broken"], expect=422)
    check("broken chain still rejected after restart", status == 422)


def run_basic_checks(base, failures):
    def check(name, cond):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(f"basic: {name}")

    status, payload = request("GET", f"{base}/healthz")
    check("GET /healthz 200 ok", status == 200 and payload.get("status") == "ok")
    status, page = request("GET", f"{base}/")
    check("GET / serves browser page", status == 200 and "恢复审计" in page)
    status, _ = request("GET", f"{base}/static/app.js")
    check("GET /static/app.js reachable", status == 200)
    status, sample = request("GET", f"{base}/api/sample")
    check("GET /api/sample", status == 200 and "wal" in sample)

    # loser rollback scenario stays valid
    sample["auditId"] = newid("SMOKE-LOSER")
    status, payload = request("POST", f"{base}/api/recover", sample, expect=200)
    v = payload["verdict"]
    check("loser scenario accepted",
          payload["status"] == "accepted" and v["loserTransactions"] == ["T2"]
          and v["redone"] == 1 and v["undone"] == 1)
    p7 = next(p for p in v["pages"] if p["page"] == 7)
    check("loser bytes rolled back, committed bytes kept",
          p7["data"][32:40] == "00" * 4 and p7["data"].startswith("11" * 16))

    status, _ = request("GET", f"{base}/api/audit?auditId=NOPE", expect=404)
    check("unknown auditId -> 404", status == 404)


def main() -> int:
    external = os.environ.get("SMOKE_BASE_URL")
    failures = []

    if external:
        # Basic + freeze/concurrency suite against the compose `web` service.
        print(f"== online suite against {external} ==")
        run_basic_checks(external, failures)
        run_freeze_protocol(external, failures, "WEB")

    # A fully self-managed instance additionally exercises the *restart*
    # guarantee (the external container cannot be restarted from inside the
    # verify container).  Running it here as well means the one-shot verify
    # container covers every scenario end to end.
    print("== self-managed suite (incl. restart) ==")
    port = free_port()
    tmp = tempfile.TemporaryDirectory()
    db = os.path.join(tmp.name, "audit.db")
    out = ""
    proc = None
    try:
        proc = spawn_server(port, db)
        base = f"http://127.0.0.1:{port}"
        run_basic_checks(base, failures)
        seeds = run_freeze_protocol(base, failures, "LOCAL")
        state = run_restart_protocol(base, failures, "LOCAL", seeds)

        # restart the service against the SAME database
        out += stop_proc(proc)
        proc = None
        port2 = free_port()
        proc = spawn_server(port2, db)
        base2 = f"http://127.0.0.1:{port2}"
        verify_after_restart(base2, failures, "LOCAL-RESTART", state)
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append(f"exception: {exc}")
    finally:
        out += stop_proc(proc)
        tmp.cleanup()

    if failures:
        print(f"\nSMOKE FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        print("--- server output (tail) ---")
        print(out[-2000:])
        return 1
    print("\nALL HTTP/API ACCEPTANCE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
