"""Persistent storage for frozen recovery verdicts.

A stable audit identifier maps to at most one frozen result.  Re-submitting
the same identifier atomically replaces the previous row — so a rejected
request *clears any earlier success evidence* instead of leaving a stale
"committed" verdict behind.

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
    error       TEXT,
    request     TEXT NOT NULL,
    verdict     TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
"""


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

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def save_accepted(self, audit_id: str, request: dict[str, Any], verdict: dict[str, Any]) -> None:
        """Freeze a successful verdict, replacing any prior row (including a
        previous success for the same audit id)."""
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM audits WHERE audit_id = ?", (audit_id,))
            self._conn.execute(
                "INSERT INTO audits(audit_id, status, error, request, verdict, "
                "created_at, updated_at) VALUES (?, 'accepted', NULL, ?, ?, ?, ?)",
                (audit_id, json.dumps(request, sort_keys=True),
                 json.dumps(verdict, sort_keys=True), now, now),
            )

    def save_rejected(self, audit_id: str, request: Any, error: str) -> None:
        """Stable rejection.  Any previous success evidence for the same audit
        id is deleted within the same transaction and replaced by a rejected
        row — nothing stale can remain 'accepted'."""
        now = time.time()
        try:
            request_text = json.dumps(request, sort_keys=True)
        except (TypeError, ValueError):
            request_text = json.dumps({"_unserializable": str(request)[:1000]})
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM audits WHERE audit_id = ?", (audit_id,))
            self._conn.execute(
                "INSERT INTO audits(audit_id, status, error, request, verdict, "
                "created_at, updated_at) VALUES (?, 'rejected', ?, ?, NULL, ?, ?)",
                (audit_id, error, request_text, now, now),
            )

    def get_accepted_replay(self, audit_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT audit_id, verdict, updated_at FROM audits "
                "WHERE audit_id = ? AND status = 'accepted'",
                (audit_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "auditId": row["audit_id"],
            "verdict": json.loads(row["verdict"]),
            "updatedAt": row["updated_at"],
        }

    def get(self, audit_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT audit_id, status, error, verdict, updated_at "
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
