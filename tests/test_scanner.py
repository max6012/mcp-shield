"""Tests for the mcp_shield.scanner module."""

from __future__ import annotations

import textwrap
import tempfile
from pathlib import Path

import pytest

from mcp_shield.scanner import Scanner, Match


SAMPLE_PATTERNS_YAML = textwrap.dedent("""\
    - name: aws-access-key
      description: AWS Access Key ID
      regex: "AKIA[0-9A-Z]{16}"
      severity: critical
      category: credentials

    - name: ssn
      description: US Social Security Number
      regex: "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
      severity: high
      category: pii
""")


@pytest.fixture()
def patterns_file(tmp_path: Path) -> Path:
    p = tmp_path / "patterns.yaml"
    p.write_text(SAMPLE_PATTERNS_YAML)
    return p


class TestScanner:
    def test_scan_finds_aws_key(self, patterns_file: Path) -> None:
        scanner = Scanner(patterns_file)
        matches = scanner.scan("my key is AKIAIOSFODNN7EXAMPLE")
        assert len(matches) == 1
        m = matches[0]
        assert m.pattern_name == "aws-access-key"
        assert m.matched_text == "AKIAIOSFODNN7EXAMPLE"
        assert m.severity == "critical"
        assert m.category == "credentials"

    def test_scan_returns_empty_for_clean_text(self, patterns_file: Path) -> None:
        scanner = Scanner(patterns_file)
        matches = scanner.scan("no secrets here")
        assert matches == []

    def test_scan_finds_ssn(self, patterns_file: Path) -> None:
        scanner = Scanner(patterns_file)
        matches = scanner.scan("SSN: 123-45-6789")
        assert len(matches) == 1
        assert matches[0].pattern_name == "ssn"
        assert matches[0].matched_text == "123-45-6789"

    def test_scan_json_walks_nested_structure(self, patterns_file: Path) -> None:
        scanner = Scanner(patterns_file)
        data = {
            "args": {
                "query": "show AKIAIOSFODNN7EXAMPLE",
            },
            "safe": "nothing here",
        }
        matches = scanner.scan_json(data)
        assert len(matches) == 1
        assert "args.query" in matches[0].pattern_name

    def test_scan_json_walks_lists(self, patterns_file: Path) -> None:
        scanner = Scanner(patterns_file)
        data = ["clean", "SSN is 123-45-6789"]
        matches = scanner.scan_json(data)
        assert len(matches) == 1
        assert "[1]" in matches[0].pattern_name
