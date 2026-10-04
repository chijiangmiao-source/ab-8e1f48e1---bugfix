"""Rule tests for the ARIES recovery engine and the audit store.

Run: python -m unittest -v tests.test_recovery
(no third-party dependencies)
"""

import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

from recovery import RecoveryError, recover, semantic_fingerprint  # noqa: E402
from storage import (  # noqa: E402
    AuditStore,
    CONFLICT,
    FIRST_ACCEPTED,
    REJECTED_FIRST,
    REJECTED_REPLACED,
    REJECTED_SAME,
    REPLAYED,
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


class FingerprintTests(unittest.TestCase):
    def _payload(self, after="aaaaaaaa"):
        return {
            "auditId": "fp-id",
            "pages": [page(1, ZEROS, page_lsn=10)],
            "wal": [
                begin(10, "T1"),
                upd(20, "T1", 10, 1, 0, "00000000", after),
                commit(30, "T1", 20),
                end(40, "T1", 30),
            ],
        }

    def test_field_order_hex_case_and_prefix_do_not_change_fingerprint(self):
        base = self._payload()
        reordered = {
            "pages": [{"data": "0x" + ZEROS.upper(), "page": 1, "pageLSN": 10}],
            "auditId": "fp-id",
            "wal": [
                {"xid": "T1", "lsn": 10, "type": "begin"},
                {"after": "AAAAAAAA", "before": "00000000", "offset": 0,
                 "page": 1, "prevLSN": 10, "xid": "T1", "lsn": 20, "type": "update"},
                {"lsn": 30, "type": "commit", "xid": "T1", "prevLSN": 20},
                {"lsn": 40, "type": "end", "xid": "T1", "prevLSN": 30},
            ],
        }
        # Whitespace inside the hex string is also semantically irrelevant.
        reordered["pages"][0]["data"] = "  " + " ".join(
            ZEROS[i:i + 2] for i in range(0, len(ZEROS), 2)
        ) + " "
        self.assertEqual(semantic_fingerprint(base), semantic_fingerprint(reordered))

    def test_audit_id_is_not_part_of_fingerprint(self):
        a = self._payload()
        b = json.loads(json.dumps(a))
        b["auditId"] = "a-different-routing-key"
        self.assertEqual(semantic_fingerprint(a), semantic_fingerprint(b))

    def test_business_change_changes_fingerprint(self):
        self.assertNotEqual(
            semantic_fingerprint(self._payload("aaaaaaaa")),
            semantic_fingerprint(self._payload("bbbbbbbb")),
        )


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "audit.db")
        self.store = AuditStore(self.db)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _valid(self, audit_id="stable-id", after="aaaaaaaa"):
        payload = {
            "auditId": audit_id,
            "pages": [page(1, ZEROS, page_lsn=10)],
            "wal": [
                begin(10, "T1"),
                upd(20, "T1", 10, 1, 0, "00000000", after),
                commit(30, "T1", 20),
                end(40, "T1", 30),
            ],
        }
        verdict = recover(payload)
        return payload, semantic_fingerprint(payload), verdict

    def _broken_chain(self, audit_id="stable-id"):
        payload = {
            "auditId": audit_id,
            "pages": [page(1, ZEROS, page_lsn=10)],
            "wal": [begin(10, "T1"),
                    upd(20, "T1", 999, 1, 0, "00000000", "aaaaaaaa")],
        }
        return payload, semantic_fingerprint(payload), "LSN 20 的 prevLSN 999 不存在（断链）"

    def _ended_ref(self, payload):
        # Formally shaped, but references a transaction that already ended.
        p = json.loads(json.dumps(payload))
        p["wal"].append(upd(50, "T1", 40, 1, 4, "0000", "cccc"))
        return p, semantic_fingerprint(p)

    # ---- lifecycle -------------------------------------------------------
    def test_first_valid_input_freezes(self):
        payload, fp, verdict = self._valid()
        code, row = self.store.resolve("stable-id", payload, fp, verdict, None)
        self.assertEqual(code, FIRST_ACCEPTED)
        self.assertEqual(row["status"], "accepted")
        self.assertEqual(row["fingerprint"], fp)

    def test_semantic_retransmit_replays_first_verdict(self):
        payload, fp, verdict = self._valid()
        self.store.resolve("stable-id", payload, fp, verdict, None)

        # Re-send with reordered keys / uppercase hex / 0x prefix.
        again = {
            "auditId": "stable-id",
            "pages": [{"data": "0X" + ZEROS.upper(), "pageLSN": 10, "page": 1}],
            "wal": [
                {"type": "begin", "xid": "T1", "lsn": 10},
                {"type": "update", "xid": "T1", "lsn": 20, "prevLSN": 10,
                 "page": 1, "offset": 0, "before": "00000000", "after": "AAAAAAAA"},
                {"type": "commit", "xid": "T1", "prevLSN": 20, "lsn": 30},
                {"type": "end", "xid": "T1", "prevLSN": 30, "lsn": 40},
            ],
        }
        fp2 = semantic_fingerprint(again)
        self.assertEqual(fp, fp2)
        code, row = self.store.resolve(
            "stable-id", again, fp2, recover(again), None
        )
        self.assertEqual(code, REPLAYED)
        # The replayed verdict is exactly the first frozen one.
        self.assertEqual(row["verdict"], verdict)

    def test_different_valid_input_is_conflict_and_keeps_first_freeze(self):
        p1, f1, v1 = self._valid(after="aaaaaaaa")
        self.store.resolve("stable-id", p1, f1, v1, None)
        p2, f2, v2 = self._valid(after="bbbbbbbb")
        self.assertNotEqual(f1, f2)

        code, row = self.store.resolve("stable-id", p2, f2, v2, None)
        self.assertEqual(code, CONFLICT)
        # First evidence is untouched: frozen bytes are still those of input 1.
        frozen = self.store.get("stable-id")
        self.assertEqual(frozen["status"], "accepted")
        self.assertTrue(frozen["verdict"]["pages"][0]["data"].startswith("aaaaaaaa"))
        self.assertFalse(frozen["verdict"]["pages"][0]["data"].startswith("bbbbbbbb"))

    def test_rejection_of_different_input_clears_prior_success(self):
        p1, f1, v1 = self._valid()
        self.store.resolve("stable-id", p1, f1, v1, None)

        bad, fbad, err = self._broken_chain()
        self.assertNotEqual(f1, fbad)
        code, row = self.store.resolve("stable-id", bad, fbad, None, err)
        self.assertEqual(code, REJECTED_REPLACED)
        self.assertEqual(row["status"], "rejected")
        self.assertNotIn("verdict", row)

        after = self.store.get("stable-id")
        self.assertEqual(after["status"], "rejected")
        self.assertNotIn("verdict", after)
        self.assertIn("断链", after["error"])

    def test_ended_transaction_reference_is_rejected_and_clears_evidence(self):
        p1, f1, v1 = self._valid()
        self.store.resolve("stable-id", p1, f1, v1, None)

        ended, fended = self._ended_ref(p1)
        with self.assertRaises(RecoveryError) as ctx:
            recover(ended)
        self.assertIn("已结束事务", str(ctx.exception))
        code, row = self.store.resolve(
            "stable-id", ended, fended, None, str(ctx.exception)
        )
        self.assertEqual(code, REJECTED_REPLACED)
        self.assertEqual(row["status"], "rejected")
        self.assertNotIn("verdict", self.store.get("stable-id"))

    def test_repeated_identical_rejection_is_stable(self):
        bad, fbad, err = self._broken_chain()
        code, _ = self.store.resolve("stable-id", bad, fbad, None, err)
        self.assertEqual(code, REJECTED_FIRST)
        code, row = self.store.resolve("stable-id", bad, fbad, None, err)
        self.assertEqual(code, REJECTED_SAME)
        self.assertEqual(row["status"], "rejected")

    def test_valid_after_rejection_freezes_fresh(self):
        bad, fbad, err = self._broken_chain()
        self.store.resolve("stable-id", bad, fbad, None, err)
        p1, f1, v1 = self._valid()
        code, row = self.store.resolve("stable-id", p1, f1, v1, None)
        self.assertEqual(code, FIRST_ACCEPTED)
        self.assertEqual(row["status"], "accepted")

    def test_unrelated_audit_survives_other_rejection(self):
        pk, fk, vk = self._valid("keep")
        self.store.resolve("keep", pk, fk, vk, None)
        bd, fb, err = self._broken_chain("drop")
        self.store.resolve("drop", bd, fb, None, err)
        self.assertEqual(self.store.get("keep")["status"], "accepted")
        self.assertEqual(self.store.get("drop")["status"], "rejected")

    # ---- persistence across reopen --------------------------------------
    def test_decisions_survive_store_reopen(self):
        p1, f1, v1 = self._valid("persist")
        self.store.resolve("persist", p1, f1, v1, None)
        bad, fbad, err = self._broken_chain("rejected-id")
        self.store.resolve("rejected-id", bad, fbad, None, err)
        self.store.close()

        reopened = AuditStore(self.db)
        try:
            # Same input still replays; different valid input still conflicts.
            code, row = reopened.resolve("persist", p1, f1, v1, None)
            self.assertEqual(code, REPLAYED)
            other, fother, vother = self._valid("persist", after="cccccccc")
            code, _ = reopened.resolve("persist", other, fother, vother, None)
            self.assertEqual(code, CONFLICT)
            self.assertEqual(reopened.get("persist")["status"], "accepted")
            # The rejection record is still present.
            self.assertEqual(reopened.get("rejected-id")["status"], "rejected")
        finally:
            reopened.close()

    # ---- concurrency -----------------------------------------------------
    def test_concurrent_different_valid_first_submissions_only_one_freezes(self):
        p1, f1, v1 = self._valid("race", after="aaaaaaaa")
        p2, f2, v2 = self._valid("race", after="bbbbbbbb")
        outcomes = []

        def worker(payload, fp, verdict):
            # A fresh connection per thread, mirroring two HTTP workers that
            # share the same database file.
            store = AuditStore(self.db)
            try:
                barrier.wait()
                code, _ = store.resolve("race", payload, fp, verdict, None)
                outcomes.append(code)
            finally:
                store.close()

        barrier = threading.Barrier(2)
        t1 = threading.Thread(target=worker, args=(p1, f1, v1))
        t2 = threading.Thread(target=worker, args=(p2, f2, v2))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(sorted(outcomes), sorted([FIRST_ACCEPTED, CONFLICT]))
        frozen = self.store.get("race")
        self.assertEqual(frozen["status"], "accepted")
        # Exactly one of the two business contents is frozen, never a mix.
        head = frozen["verdict"]["pages"][0]["data"][:8]
        self.assertIn(head, {"aaaaaaaa", "bbbbbbbb"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
