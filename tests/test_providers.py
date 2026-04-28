"""Tests for mcp_shield.providers."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_shield.providers import (
    FilePolicyProvider,
    PolicyProvider,
    RemotePolicyError,
    RemotePolicyProvider,
    make_policy_provider,
)


POLICY_YAML = textwrap.dedent("""\
    default_action: redact
    severity_threshold: medium
    servers:
      github:
        default_action: block
        severity_threshold: high
    tools:
      github.create_issue:
        default_action: block
        severity_threshold: critical
""")

POLICY_DICT = {
    "default_action": "redact",
    "severity_threshold": "medium",
    "servers": {
        "github": {"default_action": "block", "severity_threshold": "high"},
    },
    "tools": {
        "github.create_issue": {"default_action": "block", "severity_threshold": "critical"},
    },
}


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY_YAML)
    return p


def _mock_http_client(status: int, body: dict | None = None, etag: str | None = None):
    """Return a patched httpx.AsyncClient context manager yielding a mock response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.json = MagicMock(return_value=body or {})
    mock_resp.headers = {"ETag": etag} if etag else {}

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    return patch("mcp_shield.providers.httpx.AsyncClient", return_value=mock_client), mock_client


# ------------------------------------------------------------------
# FilePolicyProvider
# ------------------------------------------------------------------

class TestFilePolicyProvider:

    @pytest.mark.anyio
    async def test_fetch_returns_policy(self, policy_file: Path) -> None:
        provider = FilePolicyProvider(policy_file)
        policy = await provider.fetch()
        assert policy.global_rule.action == "redact"
        assert policy.global_rule.severity_threshold == "medium"

    @pytest.mark.anyio
    async def test_fetch_loads_server_rules(self, policy_file: Path) -> None:
        provider = FilePolicyProvider(policy_file)
        policy = await provider.fetch()
        assert "github" in policy.server_rules
        assert policy.server_rules["github"].action == "block"

    @pytest.mark.anyio
    async def test_fetch_loads_tool_rules(self, policy_file: Path) -> None:
        provider = FilePolicyProvider(policy_file)
        policy = await provider.fetch()
        assert policy.tool_rules["github.create_issue"].severity_threshold == "critical"

    @pytest.mark.anyio
    async def test_missing_file_raises(self, tmp_path: Path) -> None:
        provider = FilePolicyProvider(tmp_path / "nonexistent.yaml")
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            await provider.fetch()

    @pytest.mark.anyio
    async def test_non_mapping_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("- item1\n- item2\n")
        with pytest.raises(ValueError, match="must be a YAML mapping"):
            await provider.fetch() if False else await FilePolicyProvider(bad).fetch()

    @pytest.mark.anyio
    async def test_minimal_policy_file(self, tmp_path: Path) -> None:
        p = tmp_path / "minimal.yaml"
        p.write_text("default_action: log\n")
        policy = await FilePolicyProvider(p).fetch()
        assert policy.global_rule.action == "log"
        assert policy.server_rules == {}
        assert policy.tool_rules == {}


# ------------------------------------------------------------------
# RemotePolicyProvider — happy path
# ------------------------------------------------------------------

class TestRemotePolicyProviderSuccess:

    @pytest.mark.anyio
    async def test_200_returns_policy(self) -> None:
        patcher, _ = _mock_http_client(200, POLICY_DICT)
        with patcher:
            policy = await RemotePolicyProvider("https://example.com/p").fetch()
        assert policy.global_rule.action == "redact"

    @pytest.mark.anyio
    async def test_200_stores_etag(self) -> None:
        patcher, _ = _mock_http_client(200, POLICY_DICT, etag='"v1"')
        with patcher:
            provider = RemotePolicyProvider("https://example.com/p")
            await provider.fetch()
        assert provider._etag == '"v1"'

    @pytest.mark.anyio
    async def test_304_returns_cached_policy(self) -> None:
        provider = RemotePolicyProvider("https://example.com/p")

        # First fetch: 200 + ETag
        patcher200, _ = _mock_http_client(200, POLICY_DICT, etag='"v1"')
        with patcher200:
            policy1 = await provider.fetch()

        # Second fetch: 304
        patcher304, _ = _mock_http_client(304)
        with patcher304:
            policy2 = await provider.fetch()

        assert policy2 is policy1

    @pytest.mark.anyio
    async def test_second_request_sends_if_none_match(self) -> None:
        provider = RemotePolicyProvider("https://example.com/p")

        patcher200, client200 = _mock_http_client(200, POLICY_DICT, etag='"v1"')
        with patcher200:
            await provider.fetch()

        patcher304, client304 = _mock_http_client(304)
        with patcher304:
            await provider.fetch()

        _, kwargs = client304.get.call_args
        sent_headers = kwargs.get("headers", {})
        assert sent_headers.get("If-None-Match") == '"v1"'

    @pytest.mark.anyio
    async def test_api_key_sent_in_header(self) -> None:
        patcher, mock_client = _mock_http_client(200, POLICY_DICT)
        with patcher:
            await RemotePolicyProvider("https://example.com/p", api_key="sk-test").fetch()

        _, kwargs = mock_client.get.call_args
        assert kwargs["headers"]["X-API-Key"] == "sk-test"

    @pytest.mark.anyio
    async def test_no_api_key_omits_header(self) -> None:
        patcher, mock_client = _mock_http_client(200, POLICY_DICT)
        with patcher:
            await RemotePolicyProvider("https://example.com/p", api_key=None).fetch()

        _, kwargs = mock_client.get.call_args
        assert "X-API-Key" not in kwargs["headers"]

    @pytest.mark.anyio
    async def test_no_etag_in_response_leaves_etag_none(self) -> None:
        patcher, _ = _mock_http_client(200, POLICY_DICT, etag=None)
        with patcher:
            provider = RemotePolicyProvider("https://example.com/p")
            await provider.fetch()
        assert provider._etag is None


# ------------------------------------------------------------------
# RemotePolicyProvider — error handling and retry
# ------------------------------------------------------------------

class TestRemotePolicyProviderErrors:

    @pytest.mark.anyio
    async def test_4xx_raises_without_retry(self) -> None:
        patcher, mock_client = _mock_http_client(401, {})
        with patcher:
            with pytest.raises(RemotePolicyError, match="HTTP 401"):
                await RemotePolicyProvider("https://example.com/p").fetch()
        assert mock_client.get.call_count == 1

    @pytest.mark.anyio
    async def test_5xx_retries_three_times(self) -> None:
        patcher, mock_client = _mock_http_client(503, {})
        with patcher:
            with patch("mcp_shield.providers.asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(RemotePolicyError):
                    await RemotePolicyProvider("https://example.com/p").fetch()
        assert mock_client.get.call_count == 3

    @pytest.mark.anyio
    async def test_5xx_sleeps_between_retries(self) -> None:
        patcher, _ = _mock_http_client(503, {})
        with patcher:
            with patch("mcp_shield.providers.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                with pytest.raises(RemotePolicyError):
                    await RemotePolicyProvider("https://example.com/p").fetch()
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    @pytest.mark.anyio
    async def test_connect_error_retries(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_shield.providers.httpx.AsyncClient", return_value=mock_client):
            with patch("mcp_shield.providers.asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(RemotePolicyError, match="failed after"):
                    await RemotePolicyProvider("https://example.com/p").fetch()

        assert mock_client.get.call_count == 3

    @pytest.mark.anyio
    async def test_timeout_error_retries(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_shield.providers.httpx.AsyncClient", return_value=mock_client):
            with patch("mcp_shield.providers.asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(RemotePolicyError, match="failed after"):
                    await RemotePolicyProvider("https://example.com/p").fetch()

    @pytest.mark.anyio
    async def test_5xx_then_200_succeeds(self) -> None:
        bad_resp = MagicMock(status_code=503, headers={})
        good_resp = MagicMock(status_code=200, headers={"ETag": '"v1"'})
        good_resp.json = MagicMock(return_value={"default_action": "log"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[bad_resp, good_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_shield.providers.httpx.AsyncClient", return_value=mock_client):
            with patch("mcp_shield.providers.asyncio.sleep", new_callable=AsyncMock):
                policy = await RemotePolicyProvider("https://example.com/p").fetch()

        assert policy.global_rule.action == "log"


# ------------------------------------------------------------------
# make_policy_provider factory
# ------------------------------------------------------------------

class TestMakePolicyProvider:

    def test_https_returns_remote(self) -> None:
        p = make_policy_provider("https://policy.example.com/policy.json")
        assert isinstance(p, RemotePolicyProvider)
        assert p.url == "https://policy.example.com/policy.json"

    def test_http_returns_remote(self) -> None:
        assert isinstance(
            make_policy_provider("http://internal.example.com/policy.json"),
            RemotePolicyProvider,
        )

    def test_path_returns_file_provider(self) -> None:
        assert isinstance(make_policy_provider("/etc/mcp-shield/policy.yaml"), FilePolicyProvider)

    def test_relative_path_returns_file_provider(self) -> None:
        assert isinstance(make_policy_provider("policy.yaml"), FilePolicyProvider)

    def test_reads_api_key_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("MCP_SHIELD_API_KEY", "sk-test")
        p = make_policy_provider("https://example.com/p")
        assert isinstance(p, RemotePolicyProvider)
        assert p.api_key == "sk-test"

    def test_api_key_none_when_env_unset(self, monkeypatch) -> None:
        monkeypatch.delenv("MCP_SHIELD_API_KEY", raising=False)
        p = make_policy_provider("https://example.com/p")
        assert isinstance(p, RemotePolicyProvider)
        assert p.api_key is None


# ------------------------------------------------------------------
# Protocol conformance
# ------------------------------------------------------------------

class TestPolicyProviderProtocol:

    def test_file_provider_satisfies_protocol(self, policy_file: Path) -> None:
        assert isinstance(FilePolicyProvider(policy_file), PolicyProvider)

    def test_remote_provider_satisfies_protocol(self) -> None:
        assert isinstance(RemotePolicyProvider("https://example.com/p"), PolicyProvider)
