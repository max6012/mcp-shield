"""Tests against the default_patterns.yaml — true positives and false positives."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_shield.scanner import Scanner


@pytest.fixture(scope="module")
def scanner() -> Scanner:
    patterns_path = Path(__file__).parent.parent / "src" / "mcp_shield" / "patterns" / "default_patterns.yaml"
    return Scanner(patterns_path)


def _names(matches) -> set[str]:
    return {m.pattern_name for m in matches}


# ------------------------------------------------------------------
# True positive: each new pattern fires on a known example
# ------------------------------------------------------------------

class TestNewPatternsTruePositives:

    def test_openai_api_key_detected(self, scanner):
        text = "OPENAI_API_KEY=sk-proj-abc123DEF456ghi789JKL012mno345PQR678stu901"
        assert any(m.pattern_name == "openai_api_key" for m in scanner.scan(text))

    def test_anthropic_api_key_detected(self, scanner):
        text = "key = sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDE"
        assert any(m.pattern_name == "anthropic_api_key" for m in scanner.scan(text))

    def test_twilio_auth_token_detected(self, scanner):
        text = "account_sid = ACdeadbeefdeadbeefdeadbeefdeadbeef"
        assert any(m.pattern_name == "twilio_auth_token" for m in scanner.scan(text))

    def test_npm_token_detected(self, scanner):
        text = "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert any(m.pattern_name == "npm_token" for m in scanner.scan(text))


# ------------------------------------------------------------------
# True positive: tightened patterns still fire on real examples
# ------------------------------------------------------------------

class TestTightenedPatternsTruePositives:

    def test_aws_secret_with_context_detected(self, scanner):
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert any(m.pattern_name == "aws_secret_access_key" for m in scanner.scan(text))

    def test_bearer_in_auth_header_detected(self, scanner):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
        assert any(m.pattern_name == "bearer_token" for m in scanner.scan(text))

    def test_connection_string_with_password_detected(self, scanner):
        text = "amqp://admin:s3cret@rabbitmq.internal:5672/vhost"
        assert any(m.pattern_name == "generic_connection_string_with_password" for m in scanner.scan(text))

    def test_database_url_detected(self, scanner):
        text = "postgresql://user:pass@localhost:5432/mydb"
        assert any(m.pattern_name == "database_connection_string" for m in scanner.scan(text))


# ------------------------------------------------------------------
# False positive: previously noisy patterns must NOT fire on benign text
# ------------------------------------------------------------------

class TestFalsePositiveReduction:

    def test_aws_secret_no_context_does_not_fire(self, scanner):
        """A bare 40-char base64 string without AWS context should not match aws_secret_access_key."""
        text = "checksum = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        names = _names(scanner.scan(text))
        assert "aws_secret_access_key" not in names

    def test_bearer_without_auth_header_does_not_fire(self, scanner):
        """'Bearer' in prose without an Authorization: header should not match."""
        text = "The service uses Bearer tokens for authentication."
        names = _names(scanner.scan(text))
        assert "bearer_token" not in names

    def test_ssh_git_url_does_not_fire_as_connection_string(self, scanner):
        """git@github.com:org/repo should NOT match generic_connection_string_with_password."""
        text = "remote = git@github.com:my-org/my-repo.git"
        names = _names(scanner.scan(text))
        assert "generic_connection_string_with_password" not in names

    def test_github_https_without_password_does_not_fire(self, scanner):
        """https://github.com/org/repo (no password) should not fire."""
        text = "clone https://github.com/anthropics/mcp-shield.git"
        names = _names(scanner.scan(text))
        assert "generic_connection_string_with_password" not in names

    def test_phone_number_severity_is_medium(self, scanner):
        """US phone numbers are severity=medium after downgrade."""
        matches = [m for m in scanner.scan("call (555) 123-4567") if m.pattern_name == "us_phone_number"]
        assert matches
        assert matches[0].severity == "medium"

    def test_aws_access_key_id_still_fires(self, scanner):
        """Ensure the AKIA pattern wasn't accidentally broken."""
        matches = scanner.scan("key=AKIAIOSFODNN7EXAMPLE")
        assert any(m.pattern_name == "aws_access_key_id" for m in matches)

    def test_port_number_sequence_not_phone(self, scanner):
        """A version string like '1.2.3-456' should not be a phone number."""
        text = "version: 1.2.3-4567"
        matches = [m for m in scanner.scan(text) if m.pattern_name == "us_phone_number"]
        assert not matches

    def test_10_digit_model_number_not_phone(self, scanner):
        """Random 10-digit string without phone formatting should not fire."""
        text = "part number: 1234567890"
        matches = [m for m in scanner.scan(text) if m.pattern_name == "us_phone_number"]
        assert not matches
