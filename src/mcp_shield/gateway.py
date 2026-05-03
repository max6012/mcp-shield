"""MCP Shield gateway — proxy MCP server with security inspection.

Starts a low-level MCP Server that connects to downstream MCP servers as
clients, aggregates their tools (namespaced as "server__tool"), and proxies
all tool calls. The scanner/policy integration happens in the call_tool path.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, EmbeddedResource, TextContent, TextResourceContents, Tool

from mcp_shield.audit import AuditLog
from mcp_shield.policy import FALLBACK_POLICY, GatewayConfig, PolicyRule, _SEVERITY_RANK, load_config
from mcp_shield.scanner import Match, Scanner

log = logging.getLogger("mcp-shield")


# ------------------------------------------------------------------
# Downstream server management
# ------------------------------------------------------------------

class DownstreamServer:
    """A connection to a single downstream MCP server."""

    def __init__(self, name: str, params: StdioServerParameters):
        self.name = name
        self.params = params
        self.session: ClientSession | None = None
        self.tools: list[Tool] = []

    async def connect(self, stack: AsyncExitStack) -> None:
        """Connect to the downstream server and discover its tools."""
        transport = await stack.enter_async_context(stdio_client(self.params))
        read_stream, write_stream = transport
        self.session = await stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await self.session.initialize()
        result = await self.session.list_tools()
        self.tools = result.tools
        log.info(
            "Connected to %s: %d tools discovered",
            self.name,
            len(self.tools),
        )


# ------------------------------------------------------------------
# Gateway
# ------------------------------------------------------------------

class ShieldGateway:
    """The MCP Shield gateway — aggregates and proxies downstream MCP servers."""

    def __init__(
        self,
        config: GatewayConfig,
        scanner: Scanner | None = None,
        audit: AuditLog | None = None,
        is_fallback: bool = False,
        provider=None,
    ):
        self.config = config
        self.scanner = scanner
        self.audit = audit
        self.is_fallback = is_fallback
        self._provider = provider  # PolicyProvider | None — used by refresh loop
        self.downstream: dict[str, DownstreamServer] = {}
        self._stack = AsyncExitStack()
        # Maps namespaced tool name → (server_name, original_tool_name)
        self._tool_map: dict[str, tuple[str, str]] = {}
        self._refresh_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Connect to all downstream servers and build the tool map."""
        for srv_name, srv_conf in self.config.downstream_servers.items():
            if "__" in srv_name:
                raise ValueError(
                    f"Server name {srv_name!r} contains '__', which is reserved as the "
                    "namespace separator. Rename the server in your config."
                )
            params = StdioServerParameters(
                command=srv_conf["command"],
                args=srv_conf.get("args", []),
                env=srv_conf.get("env"),
            )
            ds = DownstreamServer(srv_name, params)
            await ds.connect(self._stack)
            self.downstream[srv_name] = ds

            for tool in ds.tools:
                if "__" in tool.name:
                    raise ValueError(
                        f"Tool name {tool.name!r} from server {srv_name!r} contains '__', "
                        "which is reserved as the namespace separator."
                    )
                namespaced = f"{srv_name}__{tool.name}"
                self._tool_map[namespaced] = (srv_name, tool.name)

        total = sum(len(ds.tools) for ds in self.downstream.values())
        log.info("Gateway ready: %d servers, %d tools", len(self.downstream), total)

    def get_aggregated_tools(self) -> list[Tool]:
        """Return all downstream tools with namespaced names."""
        tools: list[Tool] = []
        for srv_name, ds in self.downstream.items():
            for tool in ds.tools:
                namespaced = f"{srv_name}__{tool.name}"
                tools.append(
                    Tool(
                        name=namespaced,
                        description=f"[{srv_name}] {tool.description or ''}",
                        inputSchema=tool.inputSchema,
                        outputSchema=tool.outputSchema,
                        annotations=tool.annotations,
                    )
                )
        return tools

    async def proxy_call(
        self, namespaced_name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        """Forward a tool call to the correct downstream server, with scanning."""
        if self.is_fallback and self.config.local.fallback_mode == "fail-closed":
            return CallToolResult(
                content=[TextContent(
                    type="text",
                    text="MCP Shield: no valid policy (endpoint unreachable, no cache, fail-closed configured)",
                )],
                isError=True,
            )

        if self.is_fallback:
            log.warning(
                "MCP SHIELD FALLBACK: processing %s without enforced policy (fail-open)",
                namespaced_name,
            )

        if namespaced_name not in self._tool_map:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {namespaced_name}")],
                isError=True,
            )

        srv_name, original_name = self._tool_map[namespaced_name]
        ds = self.downstream[srv_name]
        if ds.session is None:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Server {srv_name!r} not connected")],
                isError=True,
            )

        policy = self.config.resolve_policy(srv_name, original_name)

        # --- Scan request arguments ---
        if self.scanner:
            req_matches = self._filter_matches(
                self.scanner.scan_json(arguments), policy
            )
            if req_matches:
                action = policy.action
                log.warning(
                    "SCAN REQUEST %s.%s: %d match(es), action=%s",
                    srv_name, original_name, len(req_matches), action,
                )
                for m in req_matches:
                    log.warning("  → %s [%s/%s]", m.pattern_name, m.severity, m.category)

                if action == "block":
                    if self.audit:
                        await self.audit.record(srv_name, original_name, "request", "block",
                                                matches=req_matches, payload=arguments)
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=f"Blocked by MCP Shield: sensitive data detected in request ({req_matches[0].pattern_name})",
                        )],
                        isError=True,
                    )
                if action == "redact":
                    if self.audit:
                        await self.audit.record(srv_name, original_name, "request", "redact",
                                                matches=req_matches, payload=arguments)
                    arguments = self._redact_json(arguments, req_matches)
                else:
                    # action == "log"
                    if self.audit:
                        await self.audit.record(srv_name, original_name, "request", "log",
                                                matches=req_matches, payload=arguments)
            elif self.audit:
                await self.audit.record(srv_name, original_name, "request", "pass")

        # --- Forward to downstream ---
        try:
            result = await ds.session.call_tool(original_name, arguments)
        except Exception as exc:
            log.warning("call_tool %s.%s raised: %s", srv_name, original_name, exc)
            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool call failed: {exc}")],
                isError=True,
            )

        # --- Scan response ---
        if self.scanner and result.content:
            resp_text = _extract_text(result)
            if resp_text:
                resp_matches = self._filter_matches(
                    self.scanner.scan(resp_text), policy
                )
                if resp_matches:
                    log.warning(
                        "SCAN RESPONSE %s.%s: %d match(es), action=%s",
                        srv_name, original_name, len(resp_matches), policy.action,
                    )
                    for m in resp_matches:
                        log.warning("  → %s [%s/%s]", m.pattern_name, m.severity, m.category)

                    if policy.action == "block":
                        if self.audit:
                            await self.audit.record(srv_name, original_name, "response", "block",
                                                    matches=resp_matches)
                        return CallToolResult(
                            content=[TextContent(
                                type="text",
                                text=f"Blocked by MCP Shield: sensitive data detected in response ({resp_matches[0].pattern_name})",
                            )],
                            isError=True,
                        )
                    if policy.action == "redact":
                        if self.audit:
                            await self.audit.record(srv_name, original_name, "response", "redact",
                                                    matches=resp_matches)
                        result = self._redact_response(result, resp_matches)
                    else:
                        if self.audit:
                            await self.audit.record(srv_name, original_name, "response", "log",
                                                    matches=resp_matches)
                elif self.audit:
                    await self.audit.record(srv_name, original_name, "response", "pass")

        return result

    def _filter_matches(self, matches: list[Match], policy: PolicyRule) -> list[Match]:
        """Filter matches by policy severity threshold and enabled categories."""
        threshold = _SEVERITY_RANK.get(policy.severity_threshold, 0)
        filtered = []
        for m in matches:
            if _SEVERITY_RANK.get(m.severity, 0) < threshold:
                continue
            if policy.enabled_categories and m.category not in policy.enabled_categories:
                continue
            filtered.append(m)
        return filtered

    def _redact_json(self, data: Any, matches: list[Match]) -> Any:
        """Redact matched text in a JSON-like structure by walking leaf strings."""
        if isinstance(data, str):
            return _redact_string(data, matches)
        if isinstance(data, dict):
            return {k: self._redact_json(v, matches) for k, v in data.items()}
        if isinstance(data, list):
            return [self._redact_json(item, matches) for item in data]
        return data

    def _redact_response(self, result: CallToolResult, matches: list[Match]) -> CallToolResult:
        """Return a new CallToolResult with matched text redacted."""
        new_content = []
        for content in result.content:
            if isinstance(content, TextContent):
                new_content.append(
                    TextContent(type="text", text=_redact_string(content.text, matches))
                )
            elif isinstance(content, EmbeddedResource):
                resource = content.resource
                if isinstance(resource, TextResourceContents) and resource.text:
                    resource = resource.model_copy(
                        update={"text": _redact_string(resource.text, matches)}
                    )
                    new_content.append(EmbeddedResource(type="resource", resource=resource))
                else:
                    new_content.append(content)
            else:
                new_content.append(content)
        return CallToolResult(content=new_content, isError=result.isError)

    async def _refresh_loop(self, interval: int) -> None:
        """Background task: re-fetch policy every interval seconds."""
        while True:
            await asyncio.sleep(interval)
            if self._provider is None:
                return
            try:
                new_policy = await self._provider.fetch()
            except Exception as exc:
                log.warning("Policy refresh failed (keeping current policy): %s", exc)
                continue

            old_action = self.config.policy.global_rule.action
            new_action = new_policy.global_rule.action
            if new_action != old_action:
                log.info(
                    "Policy refreshed: global action %s → %s",
                    old_action, new_action,
                )
            else:
                log.debug("Policy refreshed (no change to global action: %s)", old_action)

            self.config = GatewayConfig(local=self.config.local, policy=new_policy)
            self.is_fallback = False  # successful fetch clears fallback flag

    async def shutdown(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        await self._stack.aclose()


def _redact_string(text: str, matches: list[Match]) -> str:
    """Replace each match's exact text with a [REDACTED:category] placeholder.

    Applies replacements longest-first to avoid a shorter match clobbering
    part of a longer one before the longer one gets a chance to replace.
    Operates on the raw string value, never on serialized JSON, so JSON
    delimiters and escape sequences in the surrounding payload are safe.
    """
    for m in sorted(matches, key=lambda x: -len(x.matched_text)):
        text = text.replace(m.matched_text, f"[REDACTED:{m.category}]")
    return text


_SCAN_SIZE_LIMIT = 1_048_576  # 1 MB — responses larger than this are truncated before scanning


def _extract_text(result: CallToolResult) -> str:
    """Extract all scannable text content from a CallToolResult.

    Caps output at _SCAN_SIZE_LIMIT bytes to prevent large responses from
    blocking the asyncio event loop during regex scanning.
    """
    parts = []
    for content in result.content:
        if isinstance(content, TextContent):
            parts.append(content.text)
        elif isinstance(content, EmbeddedResource):
            resource = content.resource
            if isinstance(resource, TextResourceContents) and resource.text:
                parts.append(resource.text)
    text = "\n".join(parts)
    if len(text.encode()) > _SCAN_SIZE_LIMIT:
        log.warning(
            "Response payload exceeds scan limit (%d bytes > %d); truncating before scan",
            len(text.encode()), _SCAN_SIZE_LIMIT,
        )
        text = text.encode()[:_SCAN_SIZE_LIMIT].decode(errors="ignore")
    return text


# ------------------------------------------------------------------
# Wire up the MCP server
# ------------------------------------------------------------------

def create_server(gateway: ShieldGateway) -> Server:
    """Create the low-level MCP Server wired to the gateway."""

    @asynccontextmanager
    async def lifespan(server: Server):
        await gateway.start()
        if gateway.is_fallback:
            log.warning(
                "MCP SHIELD: operating without enforced policy (fail-open fallback). "
                "Scanner still detects and logs, but nothing is blocked or redacted. "
                "Fix the policy endpoint or provide a local cache."
            )
            if gateway.audit:
                await gateway.audit.record("*", "*", "startup", "fallback")

        refresh_secs = gateway.config.local.policy_refresh_seconds
        if gateway._provider is not None and refresh_secs > 0:
            gateway._refresh_task = asyncio.create_task(
                gateway._refresh_loop(refresh_secs)
            )
            log.info("Policy refresh scheduled every %ds", refresh_secs)

        try:
            yield {}
        finally:
            await gateway.shutdown()

    server = Server(name="mcp-shield", lifespan=lifespan)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return gateway.get_aggregated_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        return await gateway.proxy_call(name, arguments)

    return server


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def _resolve_patterns_path(config: GatewayConfig) -> Path:
    """Find the patterns file — custom from global policy, or the built-in default."""
    if config.policy.global_rule.custom_patterns_file:
        return Path(config.policy.global_rule.custom_patterns_file)
    return Path(__file__).parent / "patterns" / "default_patterns.yaml"


def run_gateway(config_path: str) -> None:
    """Load config, start the gateway, and run as stdio MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    config = load_config(config_path)

    # If a policy_source is configured, fetch the live policy and replace the
    # inline bootstrap policy from the config file.
    is_fallback = False
    provider = None
    if config.local.policy_source:
        from mcp_shield.providers import PolicyCache, RemotePolicyError, make_policy_provider

        provider = make_policy_provider(
            config.local.policy_source,
            cache=PolicyCache(),
        )
        log.info("Fetching policy from %s", config.local.policy_source)

        async def _fetch_policy():
            return await provider.fetch()

        try:
            live_policy = asyncio.run(_fetch_policy())
            config = GatewayConfig(local=config.local, policy=live_policy)
            log.info("Live policy loaded (global action: %s)", live_policy.global_rule.action)
        except Exception as exc:
            if config.local.fallback_mode == "fail-closed":
                raise RuntimeError(
                    f"MCP Shield: policy fetch failed and fallback_mode=fail-closed — refusing to start. "
                    f"Error: {exc}"
                ) from exc
            log.warning(
                "MCP SHIELD: policy fetch failed (%s). "
                "Falling back to fail-open default (log-only). "
                "Fix the policy endpoint or provide a local cache.",
                exc,
            )
            config = GatewayConfig(local=config.local, policy=FALLBACK_POLICY)
            is_fallback = True

    # Build the final server inventory: discovered servers + explicit servers.
    # Explicit entries (from config file) win on name conflict.
    if config.local.discovery_source:
        from mcp_shield.discovery import DiscoveryLoader

        discovered: dict = {}
        for name, srv_config in DiscoveryLoader(config.local.discovery_source).load():
            discovered[name] = srv_config

        merged = {**discovered, **config.local.downstream_servers}
        if not merged:
            log.warning(
                "MCP Shield has no downstream servers to proxy (discovery source empty "
                "and no explicit servers configured); it will appear as an empty MCP server."
            )
        elif discovered:
            log.info(
                "Server inventory: %d discovered + %d explicit = %d total",
                len(discovered), len(config.local.downstream_servers), len(merged),
            )
        from mcp_shield.policy import GatewayConfig as _GC, LocalConfig as _LC
        merged_local = _LC(
            downstream_servers=merged,
            audit=config.local.audit,
            policy_source=config.local.policy_source,
            fallback_mode=config.local.fallback_mode,
            policy_refresh_seconds=config.local.policy_refresh_seconds,
            discovery_source=config.local.discovery_source,
        )
        config = _GC(local=merged_local, policy=config.policy)

    elif not config.local.downstream_servers:
        log.warning(
            "MCP Shield has no downstream servers to proxy; "
            "it will appear as an empty MCP server to clients."
        )

    patterns_path = _resolve_patterns_path(config)
    scanner = Scanner(patterns_path)
    log.info("Loaded %d patterns from %s", len(scanner.patterns), patterns_path)

    audit = AuditLog(
        db_path=config.audit.get("db_path", "mcp-shield-audit.db"),
        log_matched_text=config.audit.get("log_matched_text", False),
        log_full_payload=config.audit.get("log_full_payload", False),
    )
    log.info("Audit log: %s", audit.db_path)

    gateway = ShieldGateway(config, scanner=scanner, audit=audit, is_fallback=is_fallback, provider=provider)
    server = create_server(gateway)

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(main())
