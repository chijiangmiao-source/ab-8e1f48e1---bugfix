"""Rule tests for the ARIES recovery engine and the audit store.

Run: python -m unittest -v tests.test_recovery
(no third-party dependencies)
"""

import copy
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

from recovery import RecoveryError, input_fingerprint, recover  # noqa: E402
from storage import (  # noqa: E402
    AuditStore,
    CONFLICT,
    FROZEN,
    REJECTED,
    REJECTION_RECORDED,
    REPLAYED,
    TERMINAL_REJECTION,
)

ZEROS = "00" * 4096


def zeros_with(offset, hexbytes):
    """A 4096-byte page hex string with *hexbytes* written at *offset*."""
    raw = bytearray(4096)
    patch = bytes.fromhex(hexbytes)
    raw[offset : offset + len(patch)] = patch
    return bytes(raw).hex()


def page(pno, data=ZEROS, page_lsn=None):
    p = {"page": pno, "data": data}
    if page_lsn is not None:
        p["pageLSN"] = page_lsn
    return p


def begin(lsn, xid):
    return {"lsn": lsn, "type": "begin", "xid": xid}


def upd(lsn, xid, prev, pno, offset, before, after):
    return {
        "lsn": lsn, "type": "update", "xid": xid, "prevLSN": prev,
        "page": pno, "offset": offset, "before": before, "after": after,
    }


def commit(lsn, xid, prev):
    return {"lsn": lsn, "type": "commit", "xid": xid, "prevLSN": prev}


def abort(lsn, xid, prev):
    return {"lsn": lsn, "type": "abort", "xid": xid, "prevLSN": prev}


def end(lsn, xid, prev):
    return {"lsn": lsn, "type": "end", "xid": xid, "prevLSN": prev}


def run(audit_id="A", pages=None, wal=None):
    return recover({"auditId": audit_id, "pages": pages or [], "wal": wal or []})


class CommittedRedoTests(unittest.TestCase):
    def test_committed_missing_update_is_redone_and_kept(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "00000000", "aaaaaaaa"),
            commit(30, "T1", 20),
            end(40, "T1", 30),
        ]
        v = run("commit-redo", [page(1, ZEROS, page_lsn=10)], wal)

        self.assertEqual(v["committedTransactions"], ["T1"])
        self.assertEqual(v["loserTransactions"], [])
        self.assertEqual(v["redone"], 1)
        self.assertEqual(v["undone"], 0)
        summary = v["pages"][0]
        self.assertTrue(summary["changed"])
        self.assertEqual(summary["pageLSNBefore"], 10)
        self.assertEqual(summary["pageLSNAfter"], 20)
        self.assertTrue(summary["data"].startswith("aaaaaaaa"))
        self.assertEqual(len(summary["sha256After"]), 64)

    def test_already_flushed_update_is_skipped(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "00000000", "aaaaaaaa"),
            commit(30, "T1", 20),
            end(40, "T1", 30),
        ]
        # Crashed image already carries the update (pageLSN 20 + after bytes).
        v = run("already-disk", [page(1, zeros_with(0, "aaaaaaaa"), page_lsn=20)], wal)
        self.assertEqual(v["redone"], 0)
        self.assertFalse(v["pages"][0]["changed"])
        redo_rows = [t for t in v["trace"] if t["phase"] == "redo" and t["type"] == "update"]
        self.assertIn("跳过", redo_rows[0]["decision"])


class LoserUndoTests(unittest.TestCase):
    def sample_loser_payload(self, page7_lsn=30):
        # Mirrors /api/sample: T1 commits; T2 (loser) update LSN60 is
        # missing from the crashed page image and must be redone then undone.
        pages = [
            page(7, zeros_with(0, "11" * 16), page_lsn=page7_lsn),
            page(9, zeros_with(0, "ab" * 8), page_lsn=20),
        ]
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 9, 0, "00" * 8, "ab" * 8),
            upd(30, "T1", 20, 7, 0, "00" * 16, "11" * 16),
            begin(35, "T2"),
            {"lsn": 40, "type": "checkpoint",
             "transactions": {"T1": 30, "T2": 35},
             "dirtyPages": {"7": 30}},
            upd(60, "T2", 35, 7, 16, "00000000", "22222222"),
            commit(70, "T1", 30),
            end(80, "T1", 70),
        ]
        return pages, wal

    def test_loser_update_redone_then_undone(self):
        pages, wal = self.sample_loser_payload()
        v = run("loser-rollback", pages, wal)

        self.assertEqual(v["committedTransactions"], ["T1"])
        self.assertEqual(v["loserTransactions"], ["T2"])
        self.assertEqual(v["redone"], 1)   # only LSN60; LSN30 already on page
        self.assertEqual(v["undone"], 1)

        p7 = next(p for p in v["pages"] if p["page"] == 7)
        # T1 committed bytes remain; T2 bytes are rolled back to before-image.
        self.assertTrue(p7["data"].startswith("11" * 16))
        self.assertTrue(p7["data"][32:40] == "00" * 4)
        # Undo rolled pageLSN from 60 back along T2's prevLSN chain (35).
        self.assertEqual(p7["pageLSNBefore"], 30)
        self.assertEqual(p7["pageLSNAfter"], 35)

        p9 = next(p for p in v["pages"] if p["page"] == 9)
        self.assertFalse(p9["changed"])  # LSN20 was already on the image

    def test_undo_requires_page_lsn_condition(self):
        # Crashed image *already contains* T2's after bytes but with an
        # older pageLSN: redo is idempotently skipped, so at undo time
        # pageLSN != 60 -> the page-LSN guard must reject the rewrite.
        pages, wal = self.sample_loser_payload(page7_lsn=30)
        raw = bytearray.fromhex(pages[0]["data"])
        raw[16:20] = bytes.fromhex("22222222")
        pages[0]["data"] = bytes(raw).hex()
        # pageLSN still 30 while bytes equal after: redo skips (idempotent),
        # undo finds pageLSN 30 != 60 -> stable rejection.
        with self.assertRaises(RecoveryError) as ctx:
            run("undo-guard", pages, wal)
        self.assertIn("页 LSN 条件不满足", str(ctx.exception))

    def test_aborted_without_end_is_also_rolled_back(self):
        wal = [
            begin(10, "T9"),
            upd(20, "T9", 10, 3, 0, "0000", "cccc"),
            abort(30, "T9", 20),
            # no end record before crash
        ]
        v = run("aborted-no-end", [page(3, ZEROS, page_lsn=10)], wal)
        self.assertEqual(v["abortedTransactions"], ["T9"])
        self.assertEqual(v["loserTransactions"], ["T9"])
        self.assertEqual(v["undone"], 1)
        self.assertTrue(v["pages"][0]["data"].startswith("0000"))


class AnalysisTests(unittest.TestCase):
    def test_checkpoint_seeds_tables_and_redo_starts_at_min_reclsn(self):
        wal = [
            begin(10, "T0"),
            upd(15, "T0", 10, 2, 0, "0000", "dddd"),
            begin(20, "T1"),
            upd(25, "T1", 20, 1, 0, "0000", "eeee"),
            {"lsn": 30, "type": "checkpoint",
             "transactions": {"T0": 15, "T1": 25},
             "dirtyPages": {"1": 25}},   # page 2 flushed before checkpoint
            upd(35, "T1", 25, 1, 2, "0000", "ffff"),
        ]
        # Page 2 was flushed before the checkpoint: its crashed image
        # already carries LSN15 (and must not be redone/undone).
        v = run("cp-analysis",
                [page(1, ZEROS, page_lsn=None),
                 page(2, zeros_with(0, "dddd"), page_lsn=15)], wal)
        # Redo starts at 25 (min DPT recLSN); LSN15 on flushed page 2 is
        # not revisited.
        self.assertEqual(v["redoStartLSN"], 25)
        redo_lsns = [t["lsn"] for t in v["trace"]
                     if t["phase"] == "redo" and t["type"] == "update"]
        self.assertEqual(redo_lsns, [25, 35])
        # Both T0 and T1 are losers; undo walks both chains in reverse LSN,
        # including flushed page 2 (a committed-disk update of a loser is
        # still rolled back).
        self.assertEqual(sorted(v["loserTransactions"]), ["T0", "T1"])
        undo_lsns = [t["lsn"] for t in v["trace"]
                     if t["phase"] == "undo" and t["type"] == "update"]
        self.assertEqual(undo_lsns, [35, 25, 15])

    def test_no_checkpoint_analyzes_whole_wal(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "0000", "aaaa"),
        ]
        v = run("no-cp", [page(1, ZEROS)], wal)
        # Analysis of the full WAL still builds the DPT; redo starts at the
        # only recLSN, loser T1 is then rolled back to the zero image.
        self.assertEqual(v["redoStartLSN"], 20)
        self.assertEqual(v["loserTransactions"], ["T1"])
        self.assertEqual(v["redone"], 1)
        self.assertEqual(v["undone"], 1)
        self.assertFalse(v["pages"][0]["changed"])


class FingerprintTests(unittest.TestCase):
    def _payload(self):
        return {
            "auditId": "FP-1",
            "pages": [page(1, ZEROS, page_lsn=10)],
            "wal": [
                begin(10, "T1"),
                upd(20, "T1", 10, 1, 0, "00000000", "aaaaaaaa"),
                commit(30, "T1", 20),
                end(40, "T1", 30),
            ],
        }

    def test_verdict_carries_stable_fingerprint(self):
        v = recover(copy.deepcopy(self._payload()))
        self.assertEqual(len(v["inputFingerprint"]), 64)

    def test_field_reorder_hex_case_and_page_order_keep_fingerprint(self):
        base = self._payload()
        reordered = {
            "wal": list(reversed(base["wal"])),  # ascending LSN regardless of key order
            "auditId": "FP-1",
            "pages": [
                # reordered keys, upper-case hex, 0x prefix
                {"data": "0x" + ("00" * 4096).upper(), "page": 1, "pageLSN": 10},
                page(2, ZEROS),
            ],
        }
        base2 = copy.deepcopy(base)
        base2["pages"].append(page(2, ZEROS))
        # page 2 listed before page 1 in this variant
        reordered["pages"] = [reordered["pages"][1], reordered["pages"][0]]
        # records with reordered object keys
        reordered["wal"] = [
            {"xid": "T1", "type": "begin", "lsn": 10},
            {"after": "AAAAAAAA", "before": "00000000", "offset": 0, "page": 1,
             "prevLSN": 10, "xid": "T1", "type": "update", "lsn": 20},
            {"prevLSN": 20, "xid": "T1", "type": "commit", "lsn": 30},
            {"lsn": 40, "prevLSN": 30, "xid": "T1", "type": "end"},
        ]
        va = recover(base2)
        vb = recover(reordered)
        self.assertEqual(va["inputFingerprint"], vb["inputFingerprint"])

    def test_different_business_content_changes_fingerprint(self):
        a = self._payload()
        b = copy.deepcopy(a)
        b["wal"][1]["after"] = "bbbbbbbb"  # different business content
        self.assertNotEqual(
            recover(a)["inputFingerprint"], recover(b)["inputFingerprint"]
        )

    def test_input_fingerprint_helper_stable(self):
        # Key ordering is irrelevant; the values themselves are taken as-is
        # (hex-case normalization happens in the recovery canonicalization).
        canon = {"b": 2, "a": [{"y": 1, "x": "AB"}]}
        self.assertEqual(input_fingerprint(canon),
                         input_fingerprint({"a": [{"x": "AB", "y": 1}], "b": 2}))


class StableRejectionTests(unittest.TestCase):
    def _base(self):
        return [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "0000", "aaaa"),
            commit(30, "T1", 20),
            end(40, "T1", 30),
        ], [page(1, ZEROS, page_lsn=10)]

    def test_broken_prevlsn_chain(self):
        wal, pages = self._base()
        wal[1]["prevLSN"] = 999  # does not exist
        with self.assertRaises(RecoveryError) as ctx:
            run("broken-chain", pages, wal)
        self.assertIn("断链", str(ctx.exception))

    def test_prevlsn_points_into_other_transaction(self):
        wal, pages = self._base()
        wal.append(begin(50, "T2"))
        wal.append(upd(60, "T2", 20, 1, 4, "0000", "bbbb"))  # T1's LSN!
        with self.assertRaises(RecoveryError) as ctx:
            run("cross-txn-chain", pages, wal)
        self.assertIn("属于事务", str(ctx.exception))

    def _wal_with_second_committed_txn(self):
        return [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "0000", "aaaa"),
            begin(50, "T2"),
            upd(60, "T2", 50, 1, 8, "0000", "bbbb"),
        ]

    def test_chain_out_of_order_predecessor(self):
        # T2 update points at begin 10 (T1) -> cross txn; instead build a
        # genuine out-of-order chain: two T2 updates whose middle link is
        # skipped.
        wal = [
            begin(10, "T2"),
            upd(20, "T2", 10, 1, 0, "0000", "aaaa"),
            upd(30, "T2", 20, 1, 4, "0000", "bbbb"),
            upd(40, "T2", 20, 1, 8, "0000", "cccc"),  # skips LSN30
        ]
        with self.assertRaises(RecoveryError) as ctx:
            run("chain-order", [page(1, ZEROS)], wal)
        self.assertIn("前驱链失序", str(ctx.exception))

    def test_duplicate_lsn(self):
        wal, pages = self._base()
        wal.append({"lsn": 20, "type": "begin", "xid": "T2"})
        with self.assertRaises(RecoveryError) as ctx:
            run("dup-lsn", pages, wal)
        self.assertIn("重复 LSN", str(ctx.exception))

    def test_wal_must_be_sorted(self):
        wal, pages = self._base()
        wal[1]["lsn"] = 50
        wal[2]["lsn"] = 25
        # rebuild ordering-independent fields consistently
        with self.assertRaises(RecoveryError) as ctx:
            run("unsorted", pages, wal)
        self.assertIn("升序", str(ctx.exception))

    def test_wrong_before_image_during_redo(self):
        wal, _ = self._base()
        # Page carries garbage where the before-image is expected.
        bad = [page(1, zeros_with(0, "ffff"), page_lsn=10)]
        with self.assertRaises(RecoveryError) as ctx:
            run("bad-before", bad, wal)
        self.assertIn("错误前像", str(ctx.exception))

    def test_out_of_range_interval(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 4095, "0000", "aaaa"),  # [4095,4097) > 4096
        ]
        with self.assertRaises(RecoveryError) as ctx:
            run("oob", [page(1)], wal)
        self.assertIn("越界", str(ctx.exception))

    def test_interval_ending_exactly_at_page_boundary_is_valid(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 4094, "0000", "aaaa"),  # [4094,4096) half-open
            commit(30, "T1", 20),
            end(40, "T1", 30),
        ]
        v = run("edge-ok", [page(1, ZEROS, page_lsn=10)], wal)
        self.assertEqual(v["redone"], 1)

    def test_unequal_before_after_length(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "0000", "aa"),
        ]
        with self.assertRaises(RecoveryError) as ctx:
            run("unequal", [page(1)], wal)
        self.assertIn("等长", str(ctx.exception))

    def test_reference_to_ended_transaction(self):
        wal, pages = self._base()
        wal.append(upd(50, "T1", 40, 1, 4, "0000", "bbbb"))  # T1 already ended
        with self.assertRaises(RecoveryError) as ctx:
            run("ended-ref", pages, wal)
        self.assertIn("已结束事务", str(ctx.exception))

    def test_end_must_follow_terminator(self):
        wal = [begin(10, "T1"), upd(20, "T1", 10, 1, 0, "0000", "aaaa"),
               end(30, "T1", 20)]
        with self.assertRaises(RecoveryError) as ctx:
            run("bad-end", [page(1, ZEROS)], wal)
        self.assertIn("end 必须紧跟", str(ctx.exception))

    def test_record_after_commit_rejected(self):
        wal = [
            begin(10, "T1"),
            upd(20, "T1", 10, 1, 0, "0000", "aaaa"),
            commit(30, "T1", 20),
            upd(40, "T1", 30, 1, 4, "0000", "bbbb"),
        ]
        with self.assertRaises(RecoveryError):
            run("after-commit", [page(1, ZEROS)], wal)

    def test_checkpoint_dangling_dirty_reclsn_rejected(self):
        wal = [
            begin(10, "T1"),
            {"lsn": 20, "type": "checkpoint",
             "transactions": {}, "dirtyPages": {"1": 999}},
        ]
        with self.assertRaises(RecoveryError) as ctx:
            run("cp-dangle", [page(1, ZEROS)], wal)
        self.assertIn("断链", str(ctx.exception))

    def test_checkpoint_null_lastlsn_with_unverifiable_chain_rejected(self):
        # T3 is active at checkpoint with a null chain tail while its
        # predecessor (LSN 5) is absent from the WAL window: the chain
        # cannot be verified and recovery is stably rejected.
        wal = [
            begin(10, "T1"),
            upd(15, "T3", 5, 1, 0, "0000", "aaaa"),   # begin(5) outside window
            {"lsn": 20, "type": "checkpoint",
             "transactions": {"T3": None}, "dirtyPages": {}},
            upd(30, "T3", 15, 1, 4, "0000", "bbbb"),
        ]
        with self.assertRaises(RecoveryError):
            run("cp-null-lastlsn", [page(1, ZEROS)], wal)

    def test_checkpoint_reference_after_checkpoint_lsn_rejected(self):
        wal = [
            begin(10, "T1"),
            {"lsn": 20, "type": "checkpoint",
             "transactions": {"T1": 30}, "dirtyPages": {}},
            upd(30, "T1", 10, 1, 0, "0000", "aaaa"),
        ]
        with self.assertRaises(RecoveryError) as ctx:
            run("cp-future-lastlsn", [page(1, ZEROS)], wal)
        self.assertIn("不能晚于检查点", str(ctx.exception))

    def test_limits_enforced(self):
        pages = [page(i) for i in range(49)]
        with self.assertRaises(RecoveryError) as ctx:
            run("too-many-pages", pages, [])
        self.assertIn("48", str(ctx.exception))

        wal = [begin(i + 1, f"T{i}") for i in range(129)]
        with self.assertRaises(RecoveryError) as ctx:
            run("too-many-wal", [page(0)], wal)
        self.assertIn("128", str(ctx.exception))

    def test_missing_audit_id_rejected(self):
        with self.assertRaises(RecoveryError):
            recover({"pages": [page(0)], "wal": []})


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "audit.db")
        self.store = AuditStore(self.db)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _good(self, audit="stable-id", after="aaaa"):
        verdict = run(audit, [page(1, ZEROS, 10)],
                      [begin(10, "T1"), upd(20, "T1", 10, 1, 0, "0000", after),
                       commit(30, "T1", 20), end(40, "T1", 30)])
        request = {"auditId": audit, "pages": [page(1, ZEROS, 10)],
                   "wal": [begin(10, "T1"), upd(20, "T1", 10, 1, 0, "0000", after),
                           commit(30, "T1", 20), end(40, "T1", 30)]}
        return request, verdict, verdict["inputFingerprint"]

    def test_first_success_freezes(self):
        request, verdict, fp = self._good()
        outcome, frozen, err = self.store.submit("stable-id", request, verdict, fp)
        self.assertEqual(outcome, FROZEN)
        self.assertIsNone(err)
        row = self.store.get("stable-id")
        self.assertEqual(row["status"], "accepted")
        self.assertEqual(row["inputFingerprint"], fp)

    def test_identical_retransmission_replays(self):
        request, verdict, fp = self._good()
        self.store.submit("stable-id", request, verdict, fp)
        outcome, frozen, _ = self.store.submit("stable-id", request, verdict, fp)
        self.assertEqual(outcome, REPLAYED)
        self.assertEqual(frozen["inputFingerprint"], fp)
        # Nothing changed: still one accepted row with the original verdict.
        self.assertEqual(self.store.get("stable-id")["status"], "accepted")

    def test_different_valid_history_conflicts_and_first_is_kept(self):
        request1, verdict1, fp1 = self._good(after="aaaa")
        request2, verdict2, fp2 = self._good(after="bbbb")
        self.assertNotEqual(fp1, fp2)
        self.store.submit("stable-id", request1, verdict1, fp1)
        outcome, frozen, _ = self.store.submit("stable-id", request2, verdict2, fp2)
        self.assertEqual(outcome, CONFLICT)
        # The returned evidence is the FIRST verdict, not the challenger.
        self.assertEqual(frozen["inputFingerprint"], fp1)
        row = self.store.get("stable-id")
        self.assertEqual(row["status"], "accepted")
        self.assertEqual(row["verdict"]["inputFingerprint"], fp1)

    def test_broken_chain_after_success_clears_success_evidence(self):
        request, verdict, fp = self._good()
        self.store.submit("stable-id", request, verdict, fp)

        bad_request = {"auditId": "stable-id", "pages": [page(1, ZEROS, 10)],
                       "wal": [begin(10, "T1"),
                               upd(20, "T1", 999, 1, 0, "0000", "aaaa")]}
        bad_fp = None  # structural fingerprint attached by the engine in real flow
        # Simulate the engine having produced a fingerprint for the bad input.
        try:
            recover(copy.deepcopy(bad_request))
        except RecoveryError as exc:
            bad_fp = exc.fingerprint
        self.assertIsNotNone(bad_fp)
        self.assertNotEqual(bad_fp, fp)

        outcome, returned_verdict, err = self.store.submit_rejected(
            "stable-id", bad_request, "LSN 20 的 prevLSN 999 不存在（断链）", bad_fp)
        self.assertEqual(outcome, REJECTION_RECORDED)
        self.assertIsNone(returned_verdict)

        after = self.store.get("stable-id")
        self.assertEqual(after["status"], "rejected")
        self.assertNotIn("verdict", after)
        self.assertIn("断链", after["error"])
        self.assertEqual(after["inputFingerprint"], bad_fp)

    def test_rejection_is_terminal_and_identical_rejection_replays(self):
        bad_request = {"auditId": "r", "pages": [page(1, ZEROS, 10)],
                       "wal": [begin(10, "T1"),
                               upd(20, "T1", 999, 1, 0, "0000", "aaaa")]}
        try:
            recover(copy.deepcopy(bad_request))
        except RecoveryError as exc:
            bad_fp = exc.fingerprint
        outcome, _, err = self.store.submit_rejected(
            "r", bad_request, "断链", bad_fp)
        self.assertEqual(outcome, REJECTED)
        self.assertIn("断链", err)

        # Same invalid input retransmitted: stable replay of the rejection.
        outcome, _, err = self.store.submit_rejected(
            "r", bad_request, "a different error wording must not win", bad_fp)
        self.assertEqual(outcome, REPLAYED)
        self.assertEqual(err, "断链")

        # A later *different* valid history cannot overwrite the rejection.
        request, verdict, fp = self._good(audit="r")
        outcome, returned, err = self.store.submit("r", request, verdict, fp)
        self.assertEqual(outcome, TERMINAL_REJECTION)
        self.assertIsNone(returned)
        self.assertIn("断链", err)
        self.assertEqual(self.store.get("r")["status"], "rejected")

    def test_different_rejection_after_rejection_conflicts(self):
        b1 = {"auditId": "r", "pages": [page(1, ZEROS, 10)],
              "wal": [begin(10, "T1"), upd(20, "T1", 999, 1, 0, "0000", "aaaa")]}
        b2 = {"auditId": "r", "pages": [page(1, ZEROS, 10)],
              "wal": [begin(10, "T1"), upd(20, "T1", 999, 1, 0, "0000", "cccc")]}
        fp1 = rejection_fp(b1)
        fp2 = rejection_fp(b2)
        self.assertNotEqual(fp1, fp2)
        self.store.submit_rejected("r", b1, "first rejection", fp1)
        outcome, _, err = self.store.submit_rejected("r", b2, "second rejection", fp2)
        self.assertEqual(outcome, CONFLICT)
        self.assertEqual(err, "first rejection")  # first frozen evidence kept

    def test_unrelated_audit_survives_other_rejection(self):
        request, verdict, fp = self._good(audit="keep")
        self.store.submit("keep", request, verdict, fp)
        self.store.submit_rejected("drop", {}, "bad", "fp-bad")
        self.assertEqual(self.store.get("keep")["status"], "accepted")
        self.assertEqual(self.store.get("drop")["status"], "rejected")

    def test_concurrent_different_first_submissions_only_one_freezes(self):
        request1, verdict1, fp1 = self._good(audit="race", after="aaaa")
        request2, verdict2, fp2 = self._good(audit="race", after="bbbb")
        outcomes = []

        barrier = threading.Barrier(2)

        def worker(req, ver, fp):
            barrier.wait()
            outcome, _, _ = self.store.submit("race", req, ver, fp)
            outcomes.append(outcome)

        t1 = threading.Thread(target=worker, args=(request1, verdict1, fp1))
        t2 = threading.Thread(target=worker, args=(request2, verdict2, fp2))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(sorted(outcomes), [CONFLICT, FROZEN])
        row = self.store.get("race")
        self.assertEqual(row["status"], "accepted")
        # Exactly one fingerprint won and is now immutable.
        self.assertIn(row["inputFingerprint"], {fp1, fp2})

    def test_persistence_survives_reopen(self):
        request, verdict, fp = self._good()
        self.store.submit("stable-id", request, verdict, fp)
        self.store.close()
        reopened = AuditStore(self.db)
        try:
            outcome, frozen, _ = reopened.submit(
                "stable-id", request, verdict, fp)
            self.assertEqual(outcome, REPLAYED)
            self.assertEqual(frozen["inputFingerprint"], fp)
        finally:
            reopened.close()


def rejection_fp(payload):
    """Run the engine purely to obtain the structural fingerprint of an
    input that is expected to be rejected."""
    try:
        recover(copy.deepcopy(payload))
    except RecoveryError as exc:
        return exc.fingerprint
    raise AssertionError("payload was expected to fail validation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
