"""Persistent storage for frozen recovery verdicts.

Invariant: a stable audit identifier maps to **exactly one definite recovery
input**.  Once a valid recovery input has been frozen for an id, that
evidence is immutable:

* re-submitting the *same* input (semantically — JSON field order and hex
  casing do not matter) replays the original verdict;
* a *different but itself valid* recovery history under the same id is an
  identifier **conflict** (HTTP 409) and never overwrites the first freeze;
* a malformed request (broken WAL, reference to an ended transaction, …)
  still goes through full recovery validation and is stably rejected
  (HTTP 422); such a rejection atomically clears any earlier success
  evidence for the id.

The decision for every submission is taken inside a single ``BEGIN
IMMEDIATE`` SQLite transaction, so two concurrent, different, valid first
submissions cannot both freeze: exactly one wins and the other is reported
as a conflict.

Uses only the Python standard library (sqlite3).
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
    audit_id    TEXT PRIMARY KEY,
    status      TEXT NOT NULL CHECK (status IN ('accepted', 'rejected')),
    fingerprint TEXT,
    error       TEXT,
    request     TEXT NOT NULL,
    verdict     TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
"""

# Return codes for AuditStore.resolve.
FIRST_ACCEPTED = "first-accepted"        # no prior row: this valid input freezes
REPLAYED = "replayed"                    # same valid input as the frozen one
CONFLICT = "conflict"                    # different valid input vs frozen evidence
REJECTED_FIRST = "rejected-first"        # no prior row: invalid input recorded
REJECTED_REPLACED = "rejected-replaced"  # invalid input replaced an older row
REJECTED_SAME = "rejected-same"          # same invalid input already recorded


def _ensure_fingerprint_column(conn: sqlite3.Connection) -> None:
    """Upgrade an older schema (created without ``fingerprint``) in place."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audits)")}
    if "fingerprint" not in cols:
        conn.execute("ALTER TABLE audits ADD COLUMN fingerprint TEXT")


class AuditStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Wait rather than fail immediately if the write lock is briefly held
        # by another process (e.g. an overlapping restart on the same DB).
        self._conn.execute("PRAGMA busy_timeout = 5000")
        with self._conn:
            self._conn.executescript(_SCHEMA)
            _ensure_fingerprint_column(self._conn)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Atomic decision point
    # ------------------------------------------------------------------
    def resolve(
        self,
        audit_id: str,
        request: dict[str, Any],
        fingerprint: str,
        verdict: Optional[dict[str, Any]],
        error: Optional[str],
    ) -> tuple[str, dict[str, Any]]:
        """Atomically decide the fate of one submission for ``audit_id``.

        Exactly one of ``verdict`` (valid input) / ``error`` (invalid input)
        is given.  Returns ``(code, row)`` where ``row`` is the stored state
        after the decision: ``{status, fingerprint, error, verdict,
        updatedAt}``.

        The whole check runs under ``BEGIN IMMEDIATE``: it takes a writer
        lock for the duration, which is what makes concurrent first
        submissions serialize (exactly one freeze wins).
        """
        now = time.time()
        request_text = json.dumps(request, sort_keys=True)
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT status, fingerprint, error, request, verdict, updated_at "
                "FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()

            if verdict is not None:
                # ---- valid recovery input -------------------------------
                if row is None:
                    code = FIRST_ACCEPTED
                    self._conn.execute(
                        "INSERT INTO audits(audit_id, status, fingerprint, error, "
                        "request, verdict, created_at, updated_at) "
                        "VALUES (?, 'accepted', ?, NULL, ?, ?, ?, ?)",
                        (audit_id, fingerprint, request_text,
                         json.dumps(verdict, sort_keys=True), now, now),
                    )
                elif row["status"] == "accepted":
                    if row["fingerprint"] == fingerprint:
                        # Semantically identical retransmit: keep the first
                        # frozen evidence and replay its verdict untouched.
                        code = REPLAYED
                    else:
                        # A different, itself valid recovery history: do NOT
                        # validate-less replay, do NOT overwrite.  Keep the
                        # first freeze and report an identifier conflict.
                        code = CONFLICT
                else:
                    # Prior row was a rejection: a now-valid input replaces
                    # it (the identifier had no success evidence to protect).
                    code = FIRST_ACCEPTED
                    self._conn.execute(
                        "UPDATE audits SET status='accepted', fingerprint=?, "
                        "error=NULL, request=?, verdict=?, updated_at=?",
                        (fingerprint, request_text,
                         json.dumps(verdict, sort_keys=True), now),
                    )
            else:
                # ---- invalid recovery input: always validate-and-reject --
                if row is None:
                    code = REJECTED_FIRST
                elif row["fingerprint"] == fingerprint:
                    code = REJECTED_SAME
                else:
                    # Different invalid input: any earlier *success* evidence
                    # must be cleared; a prior rejection is replaced too.
                    code = REJECTED_REPLACED
                self._conn.execute(
                    "INSERT INTO audits(audit_id, status, fingerprint, error, "
                    "request, verdict, created_at, updated_at) "
                    "VALUES (?, 'rejected', ?, ?, ?, NULL, ?, ?) "
                    "ON CONFLICT(audit_id) DO UPDATE SET status='rejected', "
                    "fingerprint=excluded.fingerprint, error=excluded.error, "
                    "request=excluded.request, verdict=NULL, "
                    "updated_at=excluded.updated_at",
                    (audit_id, fingerprint, error or "", request_text, now, now),
                )

            saved = self._conn.execute(
                "SELECT status, fingerprint, error, verdict, updated_at "
                "FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()

        return code, self._row_to_dict(saved)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": row["status"],
            "fingerprint": row["fingerprint"],
            "updatedAt": row["updated_at"],
        }
        if row["status"] == "accepted":
            result["verdict"] = json.loads(row["verdict"])
        else:
            result["error"] = row["error"]
        return result

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
        if row["status"] == "accepted":
            result["verdict"] = json.loads(row["verdict"])
        else:
            result["error"] = row["error"]
        return result
