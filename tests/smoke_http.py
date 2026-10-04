"""End-to-end HTTP/API acceptance tests against a real running server.

Covers the stable-identifier contract over HTTP:

  1. health probe + browser UI stay available;
  2. a successful recovery (with committed-transaction redo) freezes the
     verdict on first submission (HTTP 200, outcome=frozen);
  3. a semantically identical retransmission — JSON field order, hex-letter
     case, 0x prefix and page-image order changed — replays the original
     verdict unchanged (HTTP 200, outcome=replayed);
  4. a *different but valid* recovery history under the same auditId is
     judged an identifier conflict (HTTP 409); the first frozen evidence is
     kept and is what GET /api/audit returns;
  5. a well-formed WAL that references an already-ended transaction or has a
     broken predecessor chain actually goes through recovery validation and
     is stably rejected (HTTP 422); after a prior success the old success
     evidence is cleared, so reading the id returns no verdict;
  6. after a server restart (same database file) replay / conflict /
     rejection behaviour is unchanged;
  7. two concurrent different valid first submissions for one fresh id:
     exactly one freezes (200 frozen), the other gets 409 conflict and the
     frozen record stays singular and consistent.

Self-spawns app/server.py on an ephemeral port with a temporary AUDIT_DB by
default (the restart scenario then really restarts the process).  When
SMOKE_BASE_URL points at an already-running server (the compose `web`
service) the cross-process restart scenario is skipped — restart persistence
is covered there by the store's reopen unit test in stage 2 — and every run
uses unique audit ids so the suite is repeatable against a persistent volume.

Exits 0 on success, non-zero on failure (used by the verify container).
"""

import copy
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
sys.path.insert(0, APP)

from recovery import recover  # noqa: E402

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
            time.sleep(0.2)
    raise RuntimeError(f"server not ready: {last}")


def request(method: str, url: str, body=None, expect=None, raw_body=None,
            timeout=15):
    data = None
    headers = {}
    if raw_body is not None:
        data = raw_body
        headers["Content-Type"] = "application/json"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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


def spawn_server(port: int, db: str):
    env = dict(os.environ, PORT=str(port), HOST="127.0.0.1", AUDIT_DB=db,
               PYTHONPATH=APP)
    return subprocess.Popen(
        [sys.executable, os.path.join(APP, "server.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def committed_payload(audit_id, after="aaaaaaaa", at_offset=0):
    """Valid history: T1 begins, updates one page, commits, ends.  The crashed
    image predates the update, so recovery redoes the committed change."""
    before = (b"\x00" * (len(after) // 2)).hex()
    return {
        "auditId": audit_id,
        "pages": [{"page": 1, "pageLSN": 10, "data": Z}],
        "wal": [
            {"lsn": 10, "type": "begin", "xid": "T1"},
            {"lsn": 20, "type": "update", "xid": "T1", "prevLSN": 10,
             "page": 1, "offset": at_offset, "before": before, "after": after},
            {"lsn": 30, "type": "commit", "xid": "T1", "prevLSN": 20},
            {"lsn": 40, "type": "end", "xid": "T1", "prevLSN": 30},
        ],
    }


def equivalent_retransmission(payload):
    """The SAME business content with cosmetically different serialization:
    reordered top-level keys, upper-case hex with a 0x prefix on the page
    image and the after-image, and reordered keys inside WAL records."""
    upper_page = "0x" + payload["pages"][0]["data"].upper()
    return {
        "wal": [
            {"xid": "T1", "lsn": 10, "type": "begin"},
            {"after": payload["wal"][1]["after"].upper(),
             "before": payload["wal"][1]["before"].upper(),
             "offset": payload["wal"][1]["offset"],
             "page": 1, "prevLSN": 10, "xid": "T1",
             "type": "update", "lsn": 20},
            {"prevLSN": 20, "lsn": 30, "type": "commit", "xid": "T1"},
            {"type": "end", "xid": "T1", "prevLSN": 30, "lsn": 40},
        ],
        "auditId": payload["auditId"],
        "pages": [{"data": upper_page, "page": 1, "pageLSN": 10}],
    }


def broken_chain_payload(audit_id):
    """Well-formed shape, but the update's prevLSN points nowhere."""
    p = committed_payload(audit_id)
    p["wal"][1]["prevLSN"] = 999
    return p


def ended_txn_payload(audit_id):
    """Well-formed shape, but the last update references an already-ended T1."""
    p = committed_payload(audit_id)
    p["wal"].append(
        {"lsn": 50, "type": "update", "xid": "T1", "prevLSN": 40,
         "page": 1, "offset": 8, "before": "00000000", "after": "bbbbbbbb"}
    )
    return p


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

def run_checks(base: str, restart, log) -> int:
    failures = []

    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{(' — ' + detail) if detail and not cond else ''}")
        if not cond:
            failures.append(name)

    run_id = uuid.uuid4().hex[:8]
    def rid(tag):
        return f"SMOKE-{run_id}-{tag}"

    # The restart sub-scenario needs its own base when the primary target is
    # an external server the suite cannot restart.
    restart_base = restart.base if restart is not None else None

    try:
        # ---- 1. health + UI ----------------------------------------------
        status, payload = request("GET", f"{base}/healthz")
        check("GET /healthz 200 ok", status == 200 and payload.get("status") == "ok")
        status, html = request("GET", f"{base}/")
        check("GET / serves browser page", status == 200 and "恢复审计" in html)
        status, _ = request("GET", f"{base}/static/app.js")
        check("GET /static/app.js reachable", status == 200)
        status, sample = request("GET", f"{base}/api/sample")
        check("GET /api/sample", status == 200 and "wal" in sample)

        # ---- 2. first successful recovery freezes ------------------------
        id_freeze = rid("FREEZE")
        good = committed_payload(id_freeze)
        status, payload = request("POST", f"{base}/api/recover", good, expect=200)
        v1 = payload["verdict"]
        check("first valid submit 200 frozen",
              status == 200 and payload.get("outcome") == "frozen")
        check("committed update redone and kept",
              v1["redone"] == 1 and v1["pages"][0]["data"].startswith("aaaaaaaa"))
        fp1 = v1["inputFingerprint"]
        check("verdict carries input fingerprint", isinstance(fp1, str) and len(fp1) == 64)

        status, got = request("GET", f"{base}/api/audit?auditId={id_freeze}")
        check("frozen verdict readable", status == 200 and got["status"] == "accepted"
              and got["verdict"]["inputFingerprint"] == fp1)

        # ---- 3. semantically identical retransmission replays ------------
        id_reply = rid("REPLAY")
        good_r = committed_payload(id_reply)
        status, first = request("POST", f"{base}/api/recover", good_r, expect=200)
        check("replay scenario froze first", first.get("outcome") == "frozen")
        first_v = first["verdict"]

        echo = equivalent_retransmission(good_r)
        status, payload = request("POST", f"{base}/api/recover", echo, expect=200)
        check("identical retransmit 200 replayed",
              payload.get("outcome") == "replayed" and payload.get("replayed") is True)
        check("replayed verdict is the ORIGINAL verdict",
              payload["verdict"] == first_v)
        check("replayed fingerprint identical",
              payload["verdict"]["inputFingerprint"] == first_v["inputFingerprint"])
        status, got = request("GET", f"{base}/api/audit?auditId={id_reply}")
        check("GET still serves the same frozen verdict",
              status == 200 and got["verdict"] == first_v)

        # ---- 4. different valid history -> 409 conflict ------------------
        id_conflict = rid("CONFLICT")
        hist_a = committed_payload(id_conflict, after="aaaaaaaa")
        hist_b = committed_payload(id_conflict, after="cccccccc")
        self_fp = {
            "a": None, "b": None,
        }
        status, pa = request("POST", f"{base}/api/recover", hist_a, expect=200)
        self_fp["a"] = pa["verdict"]["inputFingerprint"]
        check("conflict scenario: history A freezes", pa.get("outcome") == "frozen")
        # The challenger itself is perfectly valid: prove that in isolation
        # (fresh id) it succeeds — i.e. the 409 is purely an id conflict.
        status, probe = request("POST", f"{base}/api/recover",
                                committed_payload(rid("CONFLICT-PROBE"), after="cccccccc"),
                                expect=200)
        check("challenger history is valid on its own", probe.get("outcome") == "frozen")
        self_fp["b"] = probe["verdict"]["inputFingerprint"]
        check("histories really differ", self_fp["a"] != self_fp["b"])

        status, payload = request("POST", f"{base}/api/recover", hist_b, expect=409)
        check("different valid history -> 409 conflict",
              status == 409 and payload.get("status") == "conflict")
        check("409 names both fingerprints",
              payload.get("frozenFingerprint") == self_fp["a"]
              and payload.get("submittedFingerprint") == self_fp["b"])
        check("409 returns the FIRST verdict, not the challenger",
              payload["verdict"]["inputFingerprint"] == self_fp["a"]
              and payload["verdict"]["pages"][0]["data"].startswith("aaaaaaaa"))
        status, got = request("GET", f"{base}/api/audit?auditId={id_conflict}")
        check("GET keeps first frozen evidence",
              status == 200 and got["status"] == "accepted"
              and got["verdict"]["inputFingerprint"] == self_fp["a"]
              and got["verdict"]["pages"][0]["data"].startswith("aaaaaaaa"))
        # Re-submitting A now replays; B keeps conflicting.
        status, payload = request("POST", f"{base}/api/recover", hist_a, expect=200)
        check("history A replayed afterwards", payload.get("outcome") == "replayed")
        status, _ = request("POST", f"{base}/api/recover", hist_b, expect=409)
        check("history B still conflicts afterwards", status == 409)

        # ---- 5. dangerous boundary: corrupt WAL after a success ----------
        for tag, corrupt, kw in (
            ("CHAIN", broken_chain_payload, "断链"),
            ("ENDED", ended_txn_payload, "已结束事务"),
        ):
            cid = rid(tag)
            base_good = committed_payload(cid)
            status, payload = request("POST", f"{base}/api/recover", base_good, expect=200)
            check(f"{tag}: baseline success frozen", payload.get("outcome") == "frozen")

            bad = corrupt(cid)
            status, payload = request("POST", f"{base}/api/recover", bad, expect=422)
            check(f"{tag}: corrupt WAL actually validated -> 422",
                  status == 422 and payload.get("status") == "rejected"
                  and kw in payload["error"],
                  detail=str(payload))
            status, got = request("GET", f"{base}/api/audit?auditId={cid}")
            check(f"{tag}: old success evidence cleared, no verdict",
                  status == 200 and got["status"] == "rejected"
                  and "verdict" not in got and kw in got["error"])
            # The identical corrupt retransmission stably replays the 422.
            status2, payload2 = request("POST", f"{base}/api/recover", bad, expect=422)
            check(f"{tag}: identical corrupt retransmit stays 422",
                  payload2.get("outcome") == "replayed")
            # A valid history cannot resurrect the id (terminal rejection).
            status2, payload2 = request("POST", f"{base}/api/recover", base_good, expect=409)
            check(f"{tag}: later valid history cannot overwrite rejection",
                  payload2.get("status") == "conflict")

        # A corrupt request on a fresh id is rejected there too — proving the
        # 422 above came from validation, not from the frozen record.
        status, payload = request("POST", f"{base}/api/recover",
                                  broken_chain_payload(rid("FRESH-BAD")), expect=422)
        check("broken chain rejected even with no prior record",
              payload.get("outcome") == "rejected")

        # ---- 6. restart persistence --------------------------------------
        if restart is not None:
            print("  -- restart-persistence: freeze evidence, then restart "
                  "the server with the same database --")
            rbase = restart_base
            r_freeze = rid("RESTART-FREEZE")
            r_conflict = rid("RESTART-CONFLICT")
            r_reject = rid("RESTART-REJECT")

            r_good = committed_payload(r_freeze)
            status, r_first = request("POST", f"{rbase}/api/recover", r_good, expect=200)
            check("restart setup: freeze", r_first.get("outcome") == "frozen")
            r_first_v = r_first["verdict"]

            ca = committed_payload(r_conflict, after="aaaaaaaa")
            cb = committed_payload(r_conflict, after="cccccccc")
            request("POST", f"{rbase}/api/recover", ca, expect=200)
            request("POST", f"{rbase}/api/recover", cb, expect=409)

            r_bad = broken_chain_payload(r_reject)
            request("POST", f"{rbase}/api/recover",
                    committed_payload(r_reject), expect=200)
            request("POST", f"{rbase}/api/recover", r_bad, expect=422)

            restart()
            wait_ready(restart.port)

            status, payload = request("POST", f"{rbase}/api/recover",
                                      equivalent_retransmission(r_good), expect=200)
            check("after restart: identical input replays 200",
                  payload.get("outcome") == "replayed"
                  and payload["verdict"] == r_first_v)
            status, _ = request("POST", f"{rbase}/api/recover", cb, expect=409)
            check("after restart: conflict input stays 409", status == 409)
            status, got = request("GET", f"{rbase}/api/audit?auditId={r_conflict}")
            check("after restart: first conflict evidence still served",
                  got["status"] == "accepted"
                  and got["verdict"]["pages"][0]["data"].startswith("aaaaaaaa"))
            status, got = request("GET", f"{rbase}/api/audit?auditId={r_reject}")
            check("after restart: rejection record survives, no verdict",
                  got["status"] == "rejected" and "verdict" not in got
                  and "断链" in got["error"])
            status, payload = request("POST", f"{rbase}/api/recover", r_bad, expect=422)
            check("after restart: identical corrupt retransmit stably rejected",
                  payload.get("outcome") == "replayed")
            status, got = request("GET", f"{rbase}/api/audit?auditId={r_freeze}")
            check("after restart: plain frozen verdict still served",
                  got["status"] == "accepted"
                  and got["verdict"]["inputFingerprint"] == r_first_v["inputFingerprint"])
        else:
            print("  [skip] process restart (no restartable target provided)")

        # ---- 7. concurrent different valid first submissions -------------
        for round_no in range(5):
            cid = rid(f"RACE{round_no}")
            a = committed_payload(cid, after="aaaaaaaa")
            b = committed_payload(cid, after="dddddddd")
            results = []
            barrier = threading.Barrier(2)

            def worker(payload):
                barrier.wait()
                try:
                    results.append(request("POST", f"{base}/api/recover", payload))
                except Exception as exc:  # noqa: BLE001
                    results.append(("error", {"error": str(exc)}))

            t1 = threading.Thread(target=worker, args=(a,))
            t2 = threading.Thread(target=worker, args=(b,))
            t1.start(); t2.start(); t1.join(); t2.join()
            statuses = sorted(s for s, _ in results)
            outcomes = sorted(p.get("outcome") for _, p in results)
            check(f"race{round_no}: exactly one 200 + one 409",
                  statuses == [200, 409] and outcomes == ["conflict", "frozen"],
                  detail=str(results))
            status, got = request("GET", f"{base}/api/audit?auditId={cid}")
            winner = next(p for s, p in results if s == 200)
            check(f"race{round_no}: singular frozen record matches the winner",
                  status == 200 and got["status"] == "accepted"
                  and got["verdict"]["inputFingerprint"]
                  == winner["verdict"]["inputFingerprint"])

        # ---- unknown id ---------------------------------------------------
        status, _ = request("GET", f"{base}/api/audit?auditId=NO-SUCH-ID", expect=404)
        check("unknown auditId -> 404", status == 404)

    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append(f"exception: {exc}")

    if failures:
        print(f"\nSMOKE FAILED ({len(failures)}): {failures}")
        return 1
    print("\nALL HTTP/API ACCEPTANCE CHECKS PASSED")
    return 0


class Restarter:
    """A self-spawned server whose process can be cycled against the same
    database file.  Used for the restart-persistence scenario even when the
    primary acceptance target is an external (compose) server."""

    def __init__(self, port, db):
        self.port = port
        self.db = db
        self.base = f"http://127.0.0.1:{port}"
        self.proc = None

    def start(self):
        self.proc = spawn_server(self.port, self.db)
        wait_ready(self.port)

    def __call__(self):
        self.proc.terminate()
        try:
            self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.communicate()
        self.start()

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.communicate()


def main() -> int:
    base_url = os.environ.get("SMOKE_BASE_URL")

    tmp = tempfile.TemporaryDirectory()
    if base_url:
        # Primary target is an external server the suite must not restart;
        # spawn a private ephemeral instance solely for restart persistence.
        restart = Restarter(free_port(), os.path.join(tmp.name, "restart.db"))
        restart.start()
    else:
        port = free_port()
        db = os.path.join(tmp.name, "audit.db")
        restart = Restarter(port, db)
        restart.start()
        base_url = restart.base
    try:
        return run_checks(base_url, restart=restart, log=None)
    finally:
        restart.stop()
        tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
