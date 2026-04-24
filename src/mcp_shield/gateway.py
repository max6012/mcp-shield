"""MCP Shield gateway — proxy MCP server with security inspection.

Starts a low-level MCP Server that connects to downstream MCP servers as
clients, aggregates their tools (namespaced as "server__tool"), and proxies
all tool calls. The scanner/policy integration happens in the call_tool path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from mcp_shield.audit import AuditLog
from mcp_shield.policy import GatewayConfig, PolicyRule, _SEVERITY_RANK, load_config
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
    ):
        self.config = config
        self.scanner = scanner
        self.audit = audit
        self.downstream: dict[str, DownstreamServer] = {}
        self._stack = AsyncExitStack()
        # Maps namespaced tool name → (server_name, original_tool_name)
        self._tool_map: dict[str, tuple[str, str]] = {}

    async def start(self) -> None:
        """Connect to all downstream servers and build the tool map."""
        for srv_name, srv_conf in self.config.downstream_servers.items():
            params = StdioServerParameters(
                command=srv_conf["command"],
                args=srv_conf.get("args", []),
                env=srv_conf.get("env"),
            )
            ds = DownstreamServer(srv_name, params)
            await ds.connect(self._stack)
            self.downstream[srv_name] = ds

            for tool in ds.tools:
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
                        self.audit.record(srv_name, original_name, "request", "block",
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
                        self.audit.record(srv_name, original_name, "request", "redact",
                                          matches=req_matches, payload=arguments)
                    arguments = self._redact_json(arguments, req_matches)
                else:
                    # action == "log"
                    if self.audit:
                        self.audit.record(srv_name, original_name, "request", "log",
                                          matches=req_matches, payload=arguments)

        # --- Forward to downstream ---
        result = await ds.session.call_tool(original_name, arguments)

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
                            self.audit.record(srv_name, original_name, "response", "block",
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
                            self.audit.record(srv_name, original_name, "response", "redact",
                                              matches=resp_matches)
                        result = self._redact_response(result, resp_matches)
                    else:
                        if self.audit:
                            self.audit.record(srv_name, original_name, "response", "log",
                                              matches=resp_matches)

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
        """Redact matched text in a JSON-like structure by replacing with placeholders."""
        text = json.dumps(data)
        for m in sorted(matches, key=lambda x: -len(x.matched_text)):
            text = text.replace(m.matched_text, f"[REDACTED:{m.category}]")
        return json.loads(text)

    def _redact_response(self, result: CallToolResult, matches: list[Match]) -> CallToolResult:
        """Return a new CallToolResult with matched text redacted."""
        new_content = []
        for content in result.content:
            if isinstance(content, TextContent):
                text = content.text
                for m in sorted(matches, key=lambda x: -len(x.matched_text)):
                    text = text.replace(m.matched_text, f"[REDACTED:{m.category}]")
                new_content.append(TextContent(type="text", text=text))
            else:
                new_content.append(content)
        return CallToolResult(content=new_content, isError=result.isError)

    async def shutdown(self) -> None:
        await self._stack.aclose()


def _extract_text(result: CallToolResult) -> str:
    """Extract all text content from a CallToolResult."""
    parts = []
    for content in result.content:
        if isinstance(content, TextContent):
            parts.append(content.text)
    return "\n".join(parts)


# ------------------------------------------------------------------
# Wire up the MCP server
# ------------------------------------------------------------------

def create_server(gateway: ShieldGateway) -> Server:
    """Create the low-level MCP Server wired to the gateway."""

    @asynccontextmanager
    async def lifespan(server: Server):
        await gateway.start()
        try:
            yield {}
        finally:
            await gateway.shutdown()

    server = Server(name="mcp-shield", lifespan=lifespan)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return gateway.get_aggregated_tools()

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        return await gateway.proxy_call(name, arguments)

    return server


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def _resolve_patterns_path(config: GatewayConfig) -> Path:
    """Find the patterns file — custom from global policy, or the built-in default."""
    if config.global_policy.custom_patterns_file:
        return Path(config.global_policy.custom_patterns_file)
    return Path(__file__).parent / "patterns" / "default_patterns.yaml"


def run_gateway(config_path: str) -> None:
    """Load config, start the gateway, and run as stdio MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    config = load_config(config_path)
    patterns_path = _resolve_patterns_path(config)
    scanner = Scanner(patterns_path)
    log.info("Loaded %d patterns from %s", len(scanner.patterns), patterns_path)

    audit = AuditLog(
        db_path=config.audit.get("db_path", "mcp-shield-audit.db"),
        log_matched_text=config.audit.get("log_matched_text", False),
        log_full_payload=config.audit.get("log_full_payload", False),
    )
    log.info("Audit log: %s", audit.db_path)

    gateway = ShieldGateway(config, scanner=scanner, audit=audit)
    server = create_server(gateway)

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(main())
