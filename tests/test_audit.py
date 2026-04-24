"""Tests for the audit logging module."""

from __future__ import annotations

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

    def test_record_and_query(self, audit_log):
        audit_log.record("myserver", "mytool", "request", "pass")
        rows = audit_log.query(last=10)
        assert len(rows) == 1
        assert rows[0]["server"] == "myserver"
        assert rows[0]["tool"] == "mytool"
        assert rows[0]["direction"] == "request"
        assert rows[0]["action"] == "pass"
        assert rows[0]["matches"] is None

    def test_record_with_matches_hashes_text(self, audit_log):
        matches = [
            Match(
                pattern_name="aws_access_key_id",
                matched_text="AKIAIOSFODNN7EXAMPLE",
                start=0, end=20,
                severity="critical",
                category="credentials",
            ),
        ]
        audit_log.record("srv", "tool", "request", "block", matches=matches)
        rows = audit_log.query(last=1)
        assert len(rows) == 1
        m = rows[0]["matches"][0]
        assert m["pattern"] == "aws_access_key_id"
        assert m["severity"] == "critical"
        # By default, matched_text is hashed, not stored in clear
        assert m["matched_text"] != "AKIAIOSFODNN7EXAMPLE"
        assert len(m["matched_text"]) == 12  # sha256 truncated

    def test_record_with_log_matched_text(self, tmp_path):
        db = tmp_path / "clear.db"
        audit = AuditLog(db_path=str(db), log_matched_text=True)
        matches = [
            Match("ssn", "123-45-6789", 0, 11, "high", "pii"),
        ]
        audit.record("srv", "tool", "request", "log", matches=matches)
        rows = audit.query(last=1)
        assert rows[0]["matches"][0]["matched_text"] == "123-45-6789"

    def test_query_filter_by_tool(self, audit_log):
        audit_log.record("srv", "tool_a", "request", "pass")
        audit_log.record("srv", "tool_b", "request", "pass")
        audit_log.record("srv", "tool_a", "response", "pass")

        rows = audit_log.query(tool="tool_a")
        assert len(rows) == 2
        assert all(r["tool"] == "tool_a" for r in rows)

    def test_query_filter_by_severity(self, audit_log):
        audit_log.record(
            "srv", "tool", "request", "block",
            matches=[Match("key", "x", 0, 1, "critical", "cred")],
        )
        audit_log.record(
            "srv", "tool", "request", "log",
            matches=[Match("ssn", "x", 0, 1, "high", "pii")],
        )

        rows = audit_log.query(severity="critical")
        assert len(rows) == 1
        assert rows[0]["action"] == "block"

    def test_query_last_limit(self, audit_log):
        for i in range(10):
            audit_log.record("srv", f"tool_{i}", "request", "pass")

        rows = audit_log.query(last=3)
        assert len(rows) == 3

    def test_payload_not_logged_by_default(self, audit_log):
        audit_log.record("srv", "tool", "request", "pass", payload={"key": "val"})
        rows = audit_log.query(last=1)
        assert rows[0]["payload"] is None

    def test_payload_logged_when_configured(self, tmp_path):
        db = tmp_path / "payload.db"
        audit = AuditLog(db_path=str(db), log_full_payload=True)
        audit.record("srv", "tool", "request", "pass", payload={"key": "val"})
        rows = audit.query(last=1)
        assert rows[0]["payload"] == {"key": "val"}
