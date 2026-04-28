"""Tests for the MCP Shield gateway proxy layer and scanning integration."""

from __future__ import annotations

import json
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.types import CallToolResult, TextContent, Tool

from mcp_shield.gateway import ShieldGateway, _resolve_patterns_path, create_server
from mcp_shield.policy import GatewayConfig, LocalConfig, Policy, PolicyRule
from mcp_shield.scanner import Scanner


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

MINI_PATTERNS_YAML = """\
- name: aws_access_key_id
  description: AWS Access Key ID
  regex: 'AKIA[0-9A-Za-z]{16}'
  severity: critical
  category: credentials

- name: ssn
  description: US Social Security Number
  regex: '(?<!\\d)\\d{3}-\\d{2}-\\d{4}(?!\\d)'
  severity: high
  category: pii
"""


@pytest.fixture
def scanner(tmp_path):
    p = tmp_path / "patterns.yaml"
    p.write_text(MINI_PATTERNS_YAML)
    return Scanner(p)


def _make_config(
    global_policy: PolicyRule | None = None,
    server_policies: dict | None = None,
    tool_policies: dict | None = None,
) -> GatewayConfig:
    return GatewayConfig(
        local=LocalConfig(downstream_servers={}),
        policy=Policy(
            global_rule=global_policy or PolicyRule(action="log"),
            server_rules=server_policies or {},
            tool_rules=tool_policies or {},
        ),
    )


def _make_gateway_with_fake_downstream(
    config: GatewayConfig,
    scanner: Scanner | None = None,
    response_text: str = "ok",
) -> ShieldGateway:
    """Create a gateway with a mocked downstream server."""
    gw = ShieldGateway(config, scanner=scanner)

    # Fake a downstream server entry
    mock_session = AsyncMock()
    mock_session.call_tool.return_value = CallToolResult(
        content=[TextContent(type="text", text=response_text)],
        isError=False,
    )

    fake_ds = MagicMock()
    fake_ds.name = "testserver"
    fake_ds.session = mock_session
    fake_ds.tools = [
        Tool(name="echo", description="echo tool", inputSchema={"type": "object"}),
    ]

    gw.downstream["testserver"] = fake_ds
    gw._tool_map["testserver__echo"] = ("testserver", "echo")

    return gw


# ------------------------------------------------------------------
# Basic gateway tests
# ------------------------------------------------------------------

class TestShieldGateway:

    def test_creates_with_config(self):
        gw = ShieldGateway(_make_config())
        assert gw.downstream == {}
        assert gw._tool_map == {}

    def test_get_aggregated_tools_empty_before_start(self):
        gw = ShieldGateway(_make_config())
        assert gw.get_aggregated_tools() == []

    def test_server_has_correct_name(self):
        gw = ShieldGateway(_make_config())
        server = create_server(gw)
        assert server.name == "mcp-shield"

    @pytest.mark.anyio
    async def test_proxy_unknown_tool_returns_error(self):
        gw = ShieldGateway(_make_config())
        result = await gw.proxy_call("nonexistent__tool", {})
        assert result.isError is True
        assert "Unknown tool" in result.content[0].text


# ------------------------------------------------------------------
# Scanning integration: LOG action
# ------------------------------------------------------------------

class TestScanningLog:

    @pytest.mark.anyio
    async def test_log_action_passes_through_with_matches(self, scanner):
        """With action=log, matched requests still get forwarded."""
        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )
        assert result.isError is False
        assert result.content[0].text == "ok"
        # Verify the call was forwarded
        gw.downstream["testserver"].session.call_tool.assert_awaited_once()

    @pytest.mark.anyio
    async def test_log_action_passes_through_response_with_matches(self, scanner):
        """With action=log, matched responses still get returned."""
        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(
            config, scanner=scanner,
            response_text="your key is AKIAIOSFODNN7EXAMPLE",
        )

        result = await gw.proxy_call("testserver__echo", {"query": "hello"})
        assert result.isError is False
        assert "AKIAIOSFODNN7EXAMPLE" in result.content[0].text


# ------------------------------------------------------------------
# Scanning integration: BLOCK action
# ------------------------------------------------------------------

class TestScanningBlock:

    @pytest.mark.anyio
    async def test_block_on_request_match(self, scanner):
        """With action=block, requests with sensitive data are blocked."""
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )
        assert result.isError is True
        assert "Blocked" in result.content[0].text
        assert "aws_access_key_id" in result.content[0].text
        # Call should NOT have been forwarded
        gw.downstream["testserver"].session.call_tool.assert_not_awaited()

    @pytest.mark.anyio
    async def test_block_on_response_match(self, scanner):
        """With action=block, responses with sensitive data are blocked."""
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(
            config, scanner=scanner,
            response_text="secret: AKIAIOSFODNN7EXAMPLE",
        )

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "get my credentials"},
        )
        assert result.isError is True
        assert "Blocked" in result.content[0].text

    @pytest.mark.anyio
    async def test_block_does_not_trigger_below_threshold(self, scanner):
        """Matches below the severity threshold should not trigger block."""
        config = _make_config(
            global_policy=PolicyRule(action="block", severity_threshold="critical")
        )
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        # SSN is severity=high, threshold is critical → should pass through
        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "ssn is 123-45-6789"},
        )
        assert result.isError is False

    @pytest.mark.anyio
    async def test_clean_request_passes_through(self, scanner):
        """Requests with no sensitive data pass through regardless of action."""
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "hello world"},
        )
        assert result.isError is False
        assert result.content[0].text == "ok"


# ------------------------------------------------------------------
# Scanning integration: REDACT action
# ------------------------------------------------------------------

class TestScanningRedact:

    @pytest.mark.anyio
    async def test_redact_request_replaces_matched_text(self, scanner):
        """With action=redact, sensitive data in request args is replaced."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )

        # Check what was actually forwarded
        call_args = gw.downstream["testserver"].session.call_tool.call_args
        forwarded_args = call_args[0][1]  # second positional arg
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(forwarded_args)
        assert "[REDACTED:credentials]" in json.dumps(forwarded_args)

    @pytest.mark.anyio
    async def test_redact_response_replaces_matched_text(self, scanner):
        """With action=redact, sensitive data in responses is replaced."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(
            config, scanner=scanner,
            response_text="here is the key: AKIAIOSFODNN7EXAMPLE",
        )

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "get key"},
        )
        assert result.isError is False
        assert "AKIAIOSFODNN7EXAMPLE" not in result.content[0].text
        assert "[REDACTED:credentials]" in result.content[0].text


# ------------------------------------------------------------------
# Policy inheritance in scanning
# ------------------------------------------------------------------

class TestPolicyInheritance:

    @pytest.mark.anyio
    async def test_tool_policy_overrides_global(self, scanner):
        """A tool-specific policy overrides the global default."""
        config = _make_config(
            global_policy=PolicyRule(action="log"),
            tool_policies={
                "testserver.echo": PolicyRule(action="block"),
            },
        )
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )
        # Tool policy says block, so it should be blocked
        assert result.isError is True
        assert "Blocked" in result.content[0].text

    @pytest.mark.anyio
    async def test_server_policy_overrides_global(self, scanner):
        """A server-specific policy overrides the global default."""
        config = _make_config(
            global_policy=PolicyRule(action="log"),
            server_policies={
                "testserver": PolicyRule(action="block"),
            },
        )
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )
        assert result.isError is True

    @pytest.mark.anyio
    async def test_category_filter_excludes_non_matching(self, scanner):
        """When enabled_categories is set, only those categories are enforced."""
        config = _make_config(
            global_policy=PolicyRule(
                action="block",
                enabled_categories=["pii"],  # only PII, not credentials
            ),
        )
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        # AWS key is category=credentials → should pass through
        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )
        assert result.isError is False

        # SSN is category=pii → should be blocked
        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "ssn is 123-45-6789"},
        )
        assert result.isError is True


# ------------------------------------------------------------------
# No scanner (disabled)
# ------------------------------------------------------------------

class TestNoScanner:

    @pytest.mark.anyio
    async def test_no_scanner_passes_through(self):
        """Without a scanner, everything passes through unscanned."""
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(config, scanner=None)

        result = await gw.proxy_call(
            "testserver__echo",
            {"query": "key is AKIAIOSFODNN7EXAMPLE"},
        )
        assert result.isError is False


# ------------------------------------------------------------------
# _resolve_patterns_path
# ------------------------------------------------------------------

class TestResolvePatternsPath:

    def test_returns_default_when_no_custom_file(self) -> None:
        config = _make_config()
        path = _resolve_patterns_path(config)
        assert path.name == "default_patterns.yaml"
        assert path.exists()

    def test_returns_custom_path_when_set(self, tmp_path) -> None:
        custom = tmp_path / "my_patterns.yaml"
        custom.touch()
        config = GatewayConfig(
            local=LocalConfig(downstream_servers={}),
            policy=Policy(
                global_rule=PolicyRule(action="log", custom_patterns_file=str(custom)),
            ),
        )
        assert _resolve_patterns_path(config) == custom
