"""Tests for the audit logging module."""

from __future__ import annotations

import asyncio
import sqlite3

import pytest

from mcp_shield.audit import AuditLog
from mcp_shield.scanner import Match


@pytest.fixture
def audit_log(tmp_path):
    db = tmp_path / "test-audit.db"
    return AuditLog(db_path=str(db))


class TestAuditLog:

    def test_creates_database(self, audit_log):
        conn = sqlite3.connect(audit_log.db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t[0] for t in tables]
        assert "audit_log" in table_names
        conn.close()

    def test_schema_has_max_severity_column(self, audit_log):
        conn = sqlite3.connect(audit_log.db_path)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()]
        conn.close()
        assert "max_severity" in cols

    @pytest.mark.anyio
    async def test_record_and_query(self, audit_log):
        await audit_log.record("myserver", "mytool", "request", "pass")
        rows = audit_log.query(last=10)
        assert len(rows) == 1
        assert rows[0]["server"] == "myserver"
        assert rows[0]["tool"] == "mytool"
        assert rows[0]["direction"] == "request"
        assert rows[0]["action"] == "pass"
        assert rows[0]["matches"] is None

    @pytest.mark.anyio
    async def test_record_with_matches_hashes_text(self, audit_log):
        matches = [
            Match(
                pattern_name="aws_access_key_id",
                matched_text="AKIAIOSFODNN7EXAMPLE",
                start=0, end=20,
                severity="critical",
                category="credentials",
            ),
        ]
        await audit_log.record("srv", "tool", "request", "block", matches=matches)
        rows = audit_log.query(last=1)
        assert len(rows) == 1
        m = rows[0]["matches"][0]
        assert m["pattern"] == "aws_access_key_id"
        assert m["severity"] == "critical"
        assert m["matched_text"] != "AKIAIOSFODNN7EXAMPLE"
        assert len(m["matched_text"]) == 12  # sha256 truncated

    @pytest.mark.anyio
    async def test_record_with_log_matched_text(self, tmp_path):
        db = tmp_path / "clear.db"
        audit = AuditLog(db_path=str(db), log_matched_text=True)
        matches = [Match("ssn", "123-45-6789", 0, 11, "high", "pii")]
        await audit.record("srv", "tool", "request", "log", matches=matches)
        rows = audit.query(last=1)
        assert rows[0]["matches"][0]["matched_text"] == "123-45-6789"

    @pytest.mark.anyio
    async def test_query_filter_by_tool(self, audit_log):
        await audit_log.record("srv", "tool_a", "request", "pass")
        await audit_log.record("srv", "tool_b", "request", "pass")
        await audit_log.record("srv", "tool_a", "response", "pass")

        rows = audit_log.query(tool="tool_a")
        assert len(rows) == 2
        assert all(r["tool"] == "tool_a" for r in rows)

    @pytest.mark.anyio
    async def test_query_filter_by_severity_uses_column(self, audit_log):
        await audit_log.record(
            "srv", "tool", "request", "block",
            matches=[Match("key", "x", 0, 1, "critical", "cred")],
        )
        await audit_log.record(
            "srv", "tool", "request", "log",
            matches=[Match("ssn", "x", 0, 1, "high", "pii")],
        )

        rows = audit_log.query(severity="critical")
        assert len(rows) == 1
        assert rows[0]["action"] == "block"
        assert rows[0]["max_severity"] == "critical"

    @pytest.mark.anyio
    async def test_max_severity_is_highest_match(self, audit_log):
        await audit_log.record(
            "srv", "tool", "request", "log",
            matches=[
                Match("low_pat", "x", 0, 1, "low", "pii"),
                Match("crit_pat", "y", 1, 2, "critical", "cred"),
                Match("high_pat", "z", 2, 3, "high", "pii"),
            ],
        )
        rows = audit_log.query(last=1)
        assert rows[0]["max_severity"] == "critical"

    @pytest.mark.anyio
    async def test_query_last_limit(self, audit_log):
        for i in range(10):
            await audit_log.record("srv", f"tool_{i}", "request", "pass")

        rows = audit_log.query(last=3)
        assert len(rows) == 3

    @pytest.mark.anyio
    async def test_payload_not_logged_by_default(self, audit_log):
        await audit_log.record("srv", "tool", "request", "pass", payload={"key": "val"})
        rows = audit_log.query(last=1)
        assert rows[0]["payload"] is None

    @pytest.mark.anyio
    async def test_payload_logged_when_configured(self, tmp_path):
        db = tmp_path / "payload.db"
        audit = AuditLog(db_path=str(db), log_full_payload=True)
        await audit.record("srv", "tool", "request", "pass", payload={"key": "val"})
        rows = audit.query(last=1)
        assert rows[0]["payload"] == {"key": "val"}

    @pytest.mark.anyio
    async def test_concurrent_writes_do_not_raise(self, audit_log):
        """Multiple concurrent record() calls must not raise or corrupt the db."""
        async def write_one(i: int) -> None:
            await audit_log.record("srv", f"tool_{i}", "request", "pass")

        await asyncio.gather(*(write_one(i) for i in range(20)))

        rows = audit_log.query(last=30)
        assert len(rows) == 20

    @pytest.mark.anyio
    async def test_pass_record_has_no_max_severity(self, audit_log):
        await audit_log.record("srv", "tool", "request", "pass")
        rows = audit_log.query(last=1)
        assert rows[0]["max_severity"] is None

    @pytest.mark.anyio
    async def test_schema_no_duplicate_primary_key(self, audit_log):
        """Verify the schema was created without a 'duplicate PRIMARY KEY' error."""
        conn = sqlite3.connect(audit_log.db_path)
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchone()[0]
        conn.close()
        # Should have exactly one PRIMARY KEY declaration
        assert ddl.upper().count("PRIMARY KEY") == 1
