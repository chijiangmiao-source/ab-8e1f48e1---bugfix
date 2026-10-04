"""Persistent storage for frozen recovery verdicts.

Freeze semantics
----------------
A stable audit identifier maps to **exactly one** frozen piece of recovery
evidence:

* The first successful verdict for an audit id freezes it.  A later
  *different but valid* history under the same id is an **identifier
  conflict**: the original evidence stays untouched.
* A semantically identical retransmission (same pages + WAL, regardless of
  JSON field order or hex-letter case) replays the frozen verdict.
* A later request that fails recovery validation is a stable rejection; it
  actually goes through validation.  When such a rejection arrives after a
  previously frozen success, the stale success evidence is **cleared within
  the same transaction** and replaced by the rejection, so the id can never
  again be read as that old verdict.

All compare-and-freeze decisions happen in a single SQLite transaction, so
two concurrent first-time submissions cannot both freeze.

Only the Python standard library (sqlite3) is used.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Optional

DEFAULT_DB_PATH = os.environ.get("AUDIT_DB", "/data/audit.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id      TEXT PRIMARY KEY,
    status        TEXT NOT NULL CHECK (status IN ('accepted', 'rejected')),
    fingerprint   TEXT,
    error         TEXT,
    request       TEXT NOT NULL,
    verdict       TEXT,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);
"""

# Outcomes of submit() / submit_rejected().
FROZEN = "frozen"              # a new success verdict was frozen
REPLAYED = "replayed"          # identical retransmission: old verdict replayed
CONFLICT = "conflict"          # different valid input: id was already frozen
TERMINAL_REJECTION = "terminal_rejection"  # id is frozen as a rejection
REJECTED = "rejected"          # invalid input: rejection row stored
REJECTION_RECORDED = "rejection_recorded"  # invalid input replaced old success


class AuditStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(_SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(audits)")}
        if "fingerprint" not in cols:
            self._conn.execute("ALTER TABLE audits ADD COLUMN fingerprint TEXT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    @staticmethod
    def _dump(value: Any) -> str:
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            return json.dumps({"_unserializable": str(value)[:1000]})

    def submit(self, audit_id: str, request: dict[str, Any],
               verdict: dict[str, Any], fingerprint: str) -> tuple[str, Optional[dict[str, Any]], Optional[str]]:
        """Atomically decide the fate of a *validated-valid* submission.

        Returns ``(outcome, frozen_verdict, error)``:

        * ``(FROZEN, verdict, None)`` when this is the first evidence;
        * ``(REPLAYED, stored_verdict, None)`` for a semantically identical
          retransmission of the frozen input;
        * ``(CONFLICT, stored_verdict, None)`` when the id is already frozen
          (by a different success); the stored evidence is returned unchanged;
        * ``(TERMINAL_REJECTION, None, stored_error)`` when the id is already
          frozen as a stable rejection.

        A previously stored *rejection* is also frozen evidence: the id is
        already bound to that definitive rejection, so a later valid
        submission is reported as a conflict and never freezes.
        """
        now = time.time()
        request_text = self._dump(request)
        verdict_text = self._dump(verdict)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT status, fingerprint, verdict, error FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()

            if row is not None and row["status"] == "accepted":
                stored = json.loads(row["verdict"])
                if row["fingerprint"] == fingerprint:
                    return REPLAYED, stored, None
                return CONFLICT, stored, None

            if row is not None:  # frozen rejection already on record
                return TERMINAL_REJECTION, None, row["error"]

            # First evidence for this id: freeze the success verdict.  If a
            # concurrent process won the race between the SELECT above and
            # this INSERT (the in-process lock only covers one process),
            # classify against the winner instead of surfacing a 500.
            self._conn.execute("SAVEPOINT submit_freeze")
            try:
                self._conn.execute(
                    "INSERT INTO audits(audit_id, status, fingerprint, error, request, "
                    "verdict, created_at, updated_at) "
                    "VALUES (?, 'accepted', ?, NULL, ?, ?, ?, ?)",
                    (audit_id, fingerprint, request_text, verdict_text, now, now),
                )
            except sqlite3.IntegrityError:
                self._conn.execute("ROLLBACK TO SAVEPOINT submit_freeze")
                winner = self._conn.execute(
                    "SELECT status, fingerprint, verdict, error FROM audits "
                    "WHERE audit_id = ?",
                    (audit_id,),
                ).fetchone()
                if winner is not None and winner["status"] == "accepted":
                    stored = json.loads(winner["verdict"])
                    if winner["fingerprint"] == fingerprint:
                        return REPLAYED, stored, None
                    return CONFLICT, stored, None
                if winner is not None:
                    return TERMINAL_REJECTION, None, winner["error"]
                raise
            self._conn.execute("RELEASE SAVEPOINT submit_freeze")
            return FROZEN, verdict, None

    def submit_rejected(self, audit_id: str, request: Any, error: str,
                        fingerprint: Optional[str]) -> tuple[str, Optional[dict[str, Any]], Optional[str]]:
        """Record the outcome for an input that failed recovery validation.

        Every rejection is itself a frozen, terminal verdict for the
        identifier:

        * no prior record                → store the rejection (REJECTED);
        * identical input retransmitted  → replay the recorded outcome
          (REPLAYED, with the stored error text);
        * a different input when a prior rejection is on record → identifier
          conflict (CONFLICT), the first rejection is preserved;
        * a different invalid input when a prior *success* is frozen → the
          success evidence is cleared in the same transaction and replaced by
          the rejection (REJECTION_RECORDED); re-reading the id then returns
          no verdict at all.
        """
        now = time.time()
        request_text = self._dump(request)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT status, fingerprint, verdict, error FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()

            if row is not None:
                same = row["fingerprint"] is not None and row["fingerprint"] == fingerprint
                if same:
                    if row["status"] == "accepted":
                        # The frozen input rejected on a later pass: replay
                        # the historical verdict instead of rewriting it.
                        return REPLAYED, json.loads(row["verdict"]), None
                    return REPLAYED, None, row["error"]
                if row["status"] == "rejected":
                    # Id already frozen with another (rejected) history.
                    return CONFLICT, None, row["error"]
                # accepted + different fingerprint: clear the stale success.
                outcome = REJECTION_RECORDED
            else:
                outcome = REJECTED

            self._conn.execute("SAVEPOINT submit_reject")
            try:
                self._conn.execute("DELETE FROM audits WHERE audit_id = ?", (audit_id,))
                self._conn.execute(
                    "INSERT INTO audits(audit_id, status, fingerprint, error, request, "
                    "verdict, created_at, updated_at) "
                    "VALUES (?, 'rejected', ?, ?, ?, NULL, ?, ?)",
                    (audit_id, fingerprint, error, request_text, now, now),
                )
            except sqlite3.IntegrityError:
                # A concurrent process inserted the row in between.
                self._conn.execute("ROLLBACK TO SAVEPOINT submit_reject")
                winner = self._conn.execute(
                    "SELECT status, fingerprint, verdict, error FROM audits "
                    "WHERE audit_id = ?",
                    (audit_id,),
                ).fetchone()
                if winner is not None:
                    same = winner["fingerprint"] is not None and winner["fingerprint"] == fingerprint
                    if same and winner["status"] == "accepted":
                        return REPLAYED, json.loads(winner["verdict"]), None
                    if same:
                        return REPLAYED, None, winner["error"]
                    if winner["status"] == "rejected":
                        return CONFLICT, None, winner["error"]
                    return CONFLICT, json.loads(winner["verdict"]), None
                raise
            self._conn.execute("RELEASE SAVEPOINT submit_reject")
            return outcome, None, error

    def get(self, audit_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT audit_id, status, fingerprint, error, verdict, updated_at "
                "FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
        if row is None:
            return None
        result: dict[str, Any] = {
            "auditId": row["audit_id"],
            "status": row["status"],
            "updatedAt": row["updated_at"],
        }
        if row["fingerprint"]:
            result["inputFingerprint"] = row["fingerprint"]
        if row["status"] == "accepted":
            result["verdict"] = json.loads(row["verdict"])
        else:
            result["error"] = row["error"]
        return result
