"""Tests for the MCP Shield gateway proxy layer and scanning integration."""

from __future__ import annotations

import asyncio
import json
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.types import CallToolResult, EmbeddedResource, TextContent, TextResourceContents, Tool

from mcp_shield.gateway import DownstreamServer, ShieldGateway, _resolve_patterns_path, create_server
from mcp_shield.policy import FALLBACK_POLICY, GatewayConfig, LocalConfig, Policy, PolicyRule
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

    @pytest.mark.anyio
    async def test_call_tool_exception_returns_is_error(self, scanner):
        """Exceptions from the downstream call_tool are caught and returned as isError=True."""
        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.downstream["testserver"].session.call_tool.side_effect = RuntimeError("connection lost")

        result = await gw.proxy_call("testserver__echo", {"query": "hello"})
        assert result.isError is True
        assert "connection lost" in result.content[0].text


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
# Namespace separator validation
# ------------------------------------------------------------------

class TestNamespaceSeparatorValidation:

    def _make_config_with_server(self, server_name: str) -> GatewayConfig:
        return GatewayConfig(
            local=LocalConfig(downstream_servers={server_name: {"command": "echo"}}),
            policy=Policy(global_rule=PolicyRule(action="log")),
        )

    @pytest.mark.anyio
    async def test_server_name_with_double_underscore_raises(self):
        """start() must raise ValueError if a server name contains '__'."""
        gw = ShieldGateway(self._make_config_with_server("bad__name"))
        with pytest.raises(ValueError, match="bad__name"):
            await gw.start()

    @pytest.mark.anyio
    async def test_tool_name_with_double_underscore_raises(self):
        """start() must raise ValueError if a discovered tool name contains '__'."""
        from unittest.mock import patch

        gw = ShieldGateway(self._make_config_with_server("goodserver"))
        bad_tool = Tool(name="bad__tool", description="", inputSchema={"type": "object"})

        async def fake_connect(self_ds, stack):
            self_ds.tools = [bad_tool]

        with patch.object(DownstreamServer, "connect", fake_connect):
            with pytest.raises(ValueError, match="bad__tool"):
                await gw.start()

    @pytest.mark.anyio
    async def test_clean_server_and_tools_proceed(self):
        """start() proceeds past validation for servers and tools without '__'."""
        from unittest.mock import patch

        gw = ShieldGateway(self._make_config_with_server("goodserver"))
        good_tool = Tool(name="echo", description="", inputSchema={"type": "object"})

        async def fake_connect(self_ds, stack):
            self_ds.tools = [good_tool]

        with patch.object(DownstreamServer, "connect", fake_connect):
            await gw.start()  # should not raise

        assert "goodserver__echo" in gw._tool_map


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


# ------------------------------------------------------------------
# run_gateway: policy_source wiring
# ------------------------------------------------------------------

class TestRunGatewayPolicySource:

    def test_policy_source_file_overrides_inline_policy(self, tmp_path) -> None:
        """run_gateway respects policy_source when set to a local file."""
        from mcp_shield.gateway import run_gateway
        from mcp_shield.policy import load_config
        import textwrap

        # Create a remote policy file with action=block
        policy_file = tmp_path / "live_policy.yaml"
        policy_file.write_text("default_action: block\n")

        # Create a config with inline action=log but policy_source pointing to the file
        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent(f"""\
            downstream_servers: {{}}
            policy_source: {policy_file}
            policy:
              default_action: log
        """))

        # Load config and simulate what run_gateway does with policy_source
        import asyncio
        from mcp_shield.policy import load_config
        from mcp_shield.providers import make_policy_provider

        config = load_config(config_file)
        assert config.policy.global_rule.action == "log"  # inline policy

        provider = make_policy_provider(str(config.local.policy_source))
        live_policy = asyncio.run(provider.fetch())

        # The live policy from the file should be block, not log
        assert live_policy.global_rule.action == "block"


# ------------------------------------------------------------------
# Redact tree-walk edge cases
# ------------------------------------------------------------------

class TestRedactEdgeCases:

    @pytest.mark.anyio
    async def test_redact_nested_object(self, scanner):
        """Sensitive data inside a nested dict is redacted, not just top-level."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        await gw.proxy_call(
            "testserver__echo",
            {"outer": {"inner": "key is AKIAIOSFODNN7EXAMPLE"}},
        )

        call_args = gw.downstream["testserver"].session.call_tool.call_args
        forwarded = call_args[0][1]
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(forwarded)
        assert "[REDACTED:credentials]" in json.dumps(forwarded)

    @pytest.mark.anyio
    async def test_redact_does_not_alter_keys(self, scanner):
        """Dict keys that happen to contain sensitive text are NOT redacted — only values."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        # The key "AKIAIOSFODNN7EXAMPLE" itself — values are empty strings
        await gw.proxy_call(
            "testserver__echo",
            {"AKIAIOSFODNN7EXAMPLE": "safe_value"},
        )

        call_args = gw.downstream["testserver"].session.call_tool.call_args
        forwarded = call_args[0][1]
        # Key should remain untouched
        assert "AKIAIOSFODNN7EXAMPLE" in forwarded

    @pytest.mark.anyio
    async def test_redact_string_with_json_special_chars(self, scanner):
        """A secret inside a string that also contains JSON-special chars is safely redacted."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        # The value contains a backslash and quotes alongside the secret
        await gw.proxy_call(
            "testserver__echo",
            {"query": 'got "key": AKIAIOSFODNN7EXAMPLE and \\path'},
        )

        call_args = gw.downstream["testserver"].session.call_tool.call_args
        forwarded = call_args[0][1]
        assert "AKIAIOSFODNN7EXAMPLE" not in forwarded["query"]
        assert "[REDACTED:credentials]" in forwarded["query"]
        # The surrounding text should still be intact
        assert "\\path" in forwarded["query"]

    @pytest.mark.anyio
    async def test_redact_list_items(self, scanner):
        """Sensitive data inside a list element is redacted."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        await gw.proxy_call(
            "testserver__echo",
            {"items": ["safe", "key is AKIAIOSFODNN7EXAMPLE", "also safe"]},
        )

        call_args = gw.downstream["testserver"].session.call_tool.call_args
        forwarded = call_args[0][1]
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(forwarded)
        assert "[REDACTED:credentials]" in json.dumps(forwarded)


# ------------------------------------------------------------------
# EmbeddedResource scanning
# ------------------------------------------------------------------

class TestPayloadSizeCap:

    @pytest.mark.anyio
    async def test_oversized_response_is_scanned_after_truncation(self, scanner):
        """A response larger than 1 MB is truncated before scanning — not skipped entirely."""
        from mcp_shield.gateway import _SCAN_SIZE_LIMIT
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        # Prepend a known secret just before a huge padding block
        huge_text = "AKIAIOSFODNN7EXAMPLE" + "x" * (_SCAN_SIZE_LIMIT + 1)
        gw.downstream["testserver"].session.call_tool.return_value = CallToolResult(
            content=[TextContent(type="text", text=huge_text)],
            isError=False,
        )
        result = await gw.proxy_call("testserver__echo", {"query": "big"})
        # Secret is at the start — survives truncation — should be blocked
        assert result.isError is True
        assert "Blocked" in result.content[0].text

    @pytest.mark.anyio
    async def test_small_response_passes_through_unchanged(self, scanner):
        """Responses under the size cap are scanned normally."""
        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner, response_text="hello")
        result = await gw.proxy_call("testserver__echo", {})
        assert result.isError is False
        assert result.content[0].text == "hello"


class TestEmbeddedResourceScanning:

    def _make_embedded_response(self, text: str) -> CallToolResult:
        resource = TextResourceContents(
            uri="file:///secret.txt",
            mimeType="text/plain",
            text=text,
        )
        return CallToolResult(
            content=[EmbeddedResource(type="resource", resource=resource)],
            isError=False,
        )

    @pytest.mark.anyio
    async def test_embedded_resource_text_is_scanned(self, scanner):
        """Credentials inside an EmbeddedResource text blob are detected."""
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.downstream["testserver"].session.call_tool.return_value = (
            self._make_embedded_response("AWS key: AKIAIOSFODNN7EXAMPLE")
        )

        result = await gw.proxy_call("testserver__echo", {"query": "get file"})
        assert result.isError is True
        assert "Blocked" in result.content[0].text

    @pytest.mark.anyio
    async def test_embedded_resource_text_is_redacted(self, scanner):
        """With redact action, credentials in EmbeddedResource text are replaced."""
        config = _make_config(global_policy=PolicyRule(action="redact"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.downstream["testserver"].session.call_tool.return_value = (
            self._make_embedded_response("AWS key: AKIAIOSFODNN7EXAMPLE")
        )

        result = await gw.proxy_call("testserver__echo", {"query": "get file"})
        assert result.isError is False
        resource = result.content[0].resource
        assert "AKIAIOSFODNN7EXAMPLE" not in resource.text
        assert "[REDACTED:credentials]" in resource.text

    @pytest.mark.anyio
    async def test_image_content_passes_through_unscanned(self, scanner):
        """ImageContent (non-text) content is not scanned and passes through."""
        from mcp.types import ImageContent
        config = _make_config(global_policy=PolicyRule(action="block"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.downstream["testserver"].session.call_tool.return_value = CallToolResult(
            content=[ImageContent(type="image", data="base64data", mimeType="image/png")],
            isError=False,
        )

        result = await gw.proxy_call("testserver__echo", {"query": "screenshot"})
        assert result.isError is False


# ------------------------------------------------------------------
# Periodic policy refresh
# ------------------------------------------------------------------

class TestPolicyRefresh:

    async def _run_refresh_until(self, gw, done_event: asyncio.Event) -> None:
        """Run the refresh loop (interval=0) until done_event is set, then cancel."""
        task = asyncio.create_task(gw._refresh_loop(interval=0))
        await asyncio.wait_for(done_event.wait(), timeout=1.0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.anyio
    async def test_refresh_picks_up_changed_policy(self, scanner) -> None:
        """Refresh loop updates gateway.config when provider returns a new policy."""
        from mcp_shield.policy import Policy, PolicyRule

        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        new_policy = Policy(global_rule=PolicyRule(action="block"))
        fetched = asyncio.Event()

        async def fake_fetch():
            fetched.set()
            return new_policy

        gw._provider = MagicMock()
        gw._provider.fetch = fake_fetch

        await self._run_refresh_until(gw, fetched)
        assert gw.config.policy.global_rule.action == "block"

    @pytest.mark.anyio
    async def test_refresh_failure_keeps_current_policy(self, scanner) -> None:
        """Refresh loop keeps current policy when fetch fails."""
        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)

        attempted = asyncio.Event()

        async def failing_fetch():
            attempted.set()
            raise Exception("timeout")

        gw._provider = MagicMock()
        gw._provider.fetch = failing_fetch

        await self._run_refresh_until(gw, attempted)
        assert gw.config.policy.global_rule.action == "log"

    @pytest.mark.anyio
    async def test_refresh_clears_fallback_flag(self, scanner) -> None:
        """A successful refresh clears is_fallback even if gateway started in fallback mode."""
        from mcp_shield.policy import Policy, PolicyRule

        config = _make_config(global_policy=PolicyRule(action="log"))
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.is_fallback = True

        new_policy = Policy(global_rule=PolicyRule(action="log"))
        fetched = asyncio.Event()

        async def fake_fetch():
            fetched.set()
            return new_policy

        gw._provider = MagicMock()
        gw._provider.fetch = fake_fetch

        await self._run_refresh_until(gw, fetched)
        assert gw.is_fallback is False

    @pytest.mark.anyio
    async def test_refresh_zero_interval_disables_polling(self, scanner) -> None:
        """policy_refresh_seconds=0 means no refresh task is created."""
        from mcp_shield.policy import LocalConfig, GatewayConfig, Policy, PolicyRule

        local = LocalConfig(downstream_servers={}, policy_refresh_seconds=0)
        config = GatewayConfig(local=local, policy=Policy(global_rule=PolicyRule(action="log")))
        gw = ShieldGateway(config, scanner=scanner)
        assert gw._refresh_task is None

        # After start() with no downstream servers, no refresh task either
        await gw.start()
        assert gw._refresh_task is None
        await gw.shutdown()

    def test_policy_refresh_seconds_default(self) -> None:
        from mcp_shield.policy import LocalConfig
        local = LocalConfig(downstream_servers={})
        assert local.policy_refresh_seconds == 14400

    def test_policy_refresh_seconds_parsed_from_config(self, tmp_path) -> None:
        import textwrap
        from mcp_shield.policy import load_config
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            downstream_servers:
              s1:
                command: echo
            policy_refresh_seconds: 3600
            policy:
              default_action: log
        """))
        cfg = load_config(p)
        assert cfg.local.policy_refresh_seconds == 3600


# ------------------------------------------------------------------
# Fail-open / fail-closed fallback
# ------------------------------------------------------------------

class TestFallbackPolicy:

    @pytest.mark.anyio
    async def test_fail_open_allows_tool_calls(self, scanner) -> None:
        """fail-open fallback: tool calls proceed, result returned."""
        config = _make_config()
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.is_fallback = True
        # fallback_mode defaults to "fail-open" in LocalConfig
        result = await gw.proxy_call("testserver__echo", {"msg": "hello"})
        assert result.isError is False

    @pytest.mark.anyio
    async def test_fail_open_logs_warning_per_call(self, scanner, caplog) -> None:
        """fail-open fallback: a warning is logged for every proxied call."""
        import logging
        config = _make_config()
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.is_fallback = True

        with caplog.at_level(logging.WARNING, logger="mcp-shield"):
            await gw.proxy_call("testserver__echo", {"msg": "hello"})

        assert any("FALLBACK" in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_fail_closed_refuses_all_tool_calls(self, scanner) -> None:
        """fail-closed fallback: every tool call returns an error immediately."""
        from mcp_shield.policy import FALLBACK_POLICY
        local = LocalConfig(downstream_servers={}, fallback_mode="fail-closed")
        config = GatewayConfig(local=local, policy=FALLBACK_POLICY)
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.is_fallback = True

        result = await gw.proxy_call("testserver__echo", {"msg": "hello"})
        assert result.isError is True
        assert "fail-closed" in result.content[0].text

    @pytest.mark.anyio
    async def test_fail_closed_does_not_call_downstream(self, scanner) -> None:
        """fail-closed: downstream session.call_tool is never invoked."""
        from mcp_shield.policy import FALLBACK_POLICY
        local = LocalConfig(downstream_servers={}, fallback_mode="fail-closed")
        config = GatewayConfig(local=local, policy=FALLBACK_POLICY)
        gw = _make_gateway_with_fake_downstream(config, scanner=scanner)
        gw.is_fallback = True

        await gw.proxy_call("testserver__echo", {})
        gw.downstream["testserver"].session.call_tool.assert_not_called()

    @pytest.mark.anyio
    async def test_is_fallback_false_by_default(self, scanner) -> None:
        """Normal gateway (no fetch failure) has is_fallback=False."""
        config = _make_config()
        gw = ShieldGateway(config, scanner=scanner)
        assert gw.is_fallback is False

    def test_run_gateway_fail_closed_raises_on_fetch_failure(self, tmp_path) -> None:
        """run_gateway with fail-closed refuses to start if policy fetch fails."""
        import textwrap
        from unittest.mock import patch
        from mcp_shield.gateway import run_gateway

        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent("""\
            downstream_servers: {}
            policy_source: https://unreachable.example.com/policy.json
            fallback_mode: fail-closed
            policy:
              default_action: log
        """))

        # Patch asyncio.run: first call is the policy fetch (make it fail)
        original_asyncio_run = __import__("asyncio").run
        call_count = [0]
        def patched_run(coro):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("simulated fetch failure")
            return original_asyncio_run(coro)

        with patch("mcp_shield.gateway.asyncio.run", side_effect=patched_run):
            with pytest.raises(RuntimeError, match="fail-closed"):
                run_gateway(str(config_file))

    def test_run_gateway_fail_open_starts_with_fallback_policy(self, tmp_path) -> None:
        """run_gateway with fail-open uses FALLBACK_POLICY when fetch fails."""
        import textwrap
        from unittest.mock import patch
        from mcp_shield.gateway import run_gateway
        from mcp_shield.policy import FALLBACK_POLICY

        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent("""\
            downstream_servers: {}
            policy_source: https://unreachable.example.com/policy.json
            fallback_mode: fail-open
            policy:
              default_action: block
        """))

        gateways_created = []

        class CapturingGateway(ShieldGateway):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                gateways_created.append(self)

        call_count = [0]
        def patched_run(coro):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("simulated fetch failure")
            # Second call is main() — stop before it runs
            raise SystemExit(0)

        with patch("mcp_shield.gateway.asyncio.run", side_effect=patched_run), \
             patch("mcp_shield.gateway.ShieldGateway", CapturingGateway):
            try:
                run_gateway(str(config_file))
            except SystemExit:
                pass

        assert len(gateways_created) == 1
        assert gateways_created[0].is_fallback is True
        assert gateways_created[0].config.policy.global_rule.action == "log"
