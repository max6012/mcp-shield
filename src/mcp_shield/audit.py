"""Audit logging for MCP Shield.

Records every tool call through the gateway to a SQLite database.
"""

from __future__ import annotations

import asyncio
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
    direction   TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    max_severity TEXT,
    matches     TEXT,
    payload     TEXT
);
"""


class AuditLog:
    """SQLite-backed audit log.

    Uses a per-write connection to avoid sharing state across concurrent
    async callers. An asyncio.Lock serialises writes so concurrent proxy
    calls don't race on the same file even in the same event loop.
    """

    def __init__(
        self,
        db_path: str = "mcp-shield-audit.db",
        log_matched_text: bool = False,
        log_full_payload: bool = False,
    ):
        self.db_path = db_path
        self.log_matched_text = log_matched_text
        self.log_full_payload = log_full_payload
        self._lock = asyncio.Lock()
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    async def record(
        self,
        server: str,
        tool: str,
        direction: str,
        action: str,
        matches: list[Match] | None = None,
        payload: Any = None,
    ) -> None:
        """Write one audit record. Safe to call concurrently."""
        match_summaries = None
        max_severity = None
        if matches:
            _RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            max_severity = max(matches, key=lambda m: _RANK.get(m.severity, 0)).severity
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

        loop = asyncio.get_event_loop()
        async with self._lock:
            await loop.run_in_executor(
                None,
                self._write,
                time.time(), server, tool, direction, action,
                max_severity, match_summaries, payload_json,
            )

    def _write(
        self,
        timestamp: float,
        server: str,
        tool: str,
        direction: str,
        action: str,
        max_severity: str | None,
        match_summaries: str | None,
        payload_json: str | None,
    ) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "INSERT INTO audit_log "
                "(timestamp, server, tool, direction, action, max_severity, matches, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp, server, tool, direction, action,
                 max_severity, match_summaries, payload_json),
            )
            conn.commit()
        finally:
            conn.close()

    def query(
        self,
        last: int = 50,
        severity: str | None = None,
        tool: str | None = None,
    ) -> list[dict]:
        """Query audit records."""
        sql = ("SELECT id, timestamp, server, tool, direction, action, "
               "max_severity, matches, payload FROM audit_log")
        conditions = []
        params: list[Any] = []

        if tool:
            conditions.append("tool = ?")
            params.append(tool)

        if severity:
            conditions.append("max_severity = ?")
            params.append(severity)

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += " ORDER BY id DESC LIMIT ?"
        params.append(last)

        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()

        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "server": r[2],
                "tool": r[3],
                "direction": r[4],
                "action": r[5],
                "max_severity": r[6],
                "matches": json.loads(r[7]) if r[7] else None,
                "payload": json.loads(r[8]) if r[8] else None,
            }
            for r in rows
        ]

    def close(self) -> None:
        pass  # connections are closed after each write; nothing to do here


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

    if not rows:
        print("No matching records.")
        return

    for row in reversed(rows):  # oldest first
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["timestamp"]))
        matches_str = ""
        if row["matches"]:
            patterns = [m["pattern"] for m in row["matches"]]
            matches_str = f" matches=[{', '.join(patterns)}]"
        sev_str = f" max_severity={row['max_severity']}" if row["max_severity"] else ""
        print(f"[{ts}] {row['direction']:8s} {row['server']}.{row['tool']} "
              f"action={row['action']}{sev_str}{matches_str}")
