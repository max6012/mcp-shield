"""Audit logging for MCP Shield.

Records every tool call through the gateway to a SQLite database.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from mcp_shield.scanner import Match


# ------------------------------------------------------------------
# Database setup
# ------------------------------------------------------------------

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    server      TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    direction   TEXT    NOT NULL,  -- 'request' or 'response'
    action      TEXT    NOT NULL,  -- 'pass', 'log', 'redact', 'block'
    matches     TEXT,              -- JSON array of match summaries
    payload     TEXT,              -- full payload (if configured)
    PRIMARY KEY (id)
);
"""

# Fix: PRIMARY KEY already set via AUTOINCREMENT, remove duplicate
_SCHEMA = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    server      TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    direction   TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    matches     TEXT,
    payload     TEXT
);
"""


class AuditLog:
    """SQLite-backed audit log."""

    def __init__(
        self,
        db_path: str = "mcp-shield-audit.db",
        log_matched_text: bool = False,
        log_full_payload: bool = False,
    ):
        self.db_path = db_path
        self.log_matched_text = log_matched_text
        self.log_full_payload = log_full_payload
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    def record(
        self,
        server: str,
        tool: str,
        direction: str,
        action: str,
        matches: list[Match] | None = None,
        payload: Any = None,
    ) -> None:
        """Write one audit record."""
        match_summaries = None
        if matches:
            match_summaries = json.dumps([
                {
                    "pattern": m.pattern_name,
                    "severity": m.severity,
                    "category": m.category,
                    "matched_text": m.matched_text if self.log_matched_text
                                    else sha256(m.matched_text.encode()).hexdigest()[:12],
                }
                for m in matches
            ])

        payload_json = None
        if self.log_full_payload and payload is not None:
            payload_json = json.dumps(payload, default=str)

        self._conn.execute(
            "INSERT INTO audit_log (timestamp, server, tool, direction, action, matches, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), server, tool, direction, action, match_summaries, payload_json),
        )
        self._conn.commit()

    def query(
        self,
        last: int = 50,
        severity: str | None = None,
        tool: str | None = None,
    ) -> list[dict]:
        """Query audit records."""
        sql = "SELECT id, timestamp, server, tool, direction, action, matches, payload FROM audit_log"
        conditions = []
        params: list[Any] = []

        if tool:
            conditions.append("tool = ?")
            params.append(tool)

        if severity:
            # Filter by severity in the JSON matches field
            conditions.append("matches LIKE ?")
            params.append(f'%"severity": "{severity}"%')

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += " ORDER BY id DESC LIMIT ?"
        params.append(last)

        rows = self._conn.execute(sql, params).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "server": r[2],
                "tool": r[3],
                "direction": r[4],
                "action": r[5],
                "matches": json.loads(r[6]) if r[6] else None,
                "payload": json.loads(r[7]) if r[7] else None,
            }
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()


# ------------------------------------------------------------------
# CLI query function
# ------------------------------------------------------------------

def query_audit_log(
    last: int = 50,
    severity: str | None = None,
    tool: str | None = None,
    db_path: str = "mcp-shield-audit.db",
) -> None:
    """Query and print audit log entries."""
    if not Path(db_path).exists():
        print(f"No audit database found at {db_path}")
        return

    audit = AuditLog(db_path=db_path)
    rows = audit.query(last=last, severity=severity, tool=tool)
    audit.close()

    if not rows:
        print("No matching records.")
        return

    for row in reversed(rows):  # oldest first
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["timestamp"]))
        matches_str = ""
        if row["matches"]:
            patterns = [m["pattern"] for m in row["matches"]]
            matches_str = f" matches=[{', '.join(patterns)}]"
        print(f"[{ts}] {row['direction']:8s} {row['server']}.{row['tool']} "
              f"action={row['action']}{matches_str}")
