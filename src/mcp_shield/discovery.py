"""Discovery source loader for MCP Shield.

Reads downstream MCP server definitions from a JSON file in the universal
Claude MCP schema:

  {"mcpServers": {"server_name": {"command": "...", "args": [...], "env": {...}}}}

This is the format used by Claude Desktop, Claude Code, Cursor, Windsurf,
and most MCP clients, making it easy to reuse an existing client config.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator

log = logging.getLogger("mcp-shield.discovery")


class DiscoverySourceError(Exception):
    """Raised when a discovery source file is malformed."""


_SHIELD_COMMAND_MARKERS = ("mcp_shield", "mcp-shield")
_SHIELD_ARG_MARKERS = ("-m", "mcp_shield")


def _is_shield_entry(name: str, config: dict) -> bool:
    """Return True if this server entry looks like mcp-shield itself.

    Filters on:
      1. Command path contains 'mcp_shield' or 'mcp-shield'.
      2. Args contain the shield module path ('-m' followed by 'mcp_shield' or 'mcp_shield.cli').
      3. Explicit opt-out via 'shield_skip: true' key.
    """
    if config.get("shield_skip"):
        return True
    command = config.get("command", "")
    if any(marker in command for marker in _SHIELD_COMMAND_MARKERS):
        return True
    args = config.get("args", [])
    for i, arg in enumerate(args):
        if arg == "-m" and i + 1 < len(args) and args[i + 1].startswith("mcp_shield"):
            return True
        if isinstance(arg, str) and any(marker in arg for marker in _SHIELD_COMMAND_MARKERS):
            return True
    return False


class DiscoveryLoader:
    """Load MCP server definitions from a Claude-format JSON file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> Iterator[tuple[str, dict]]:
        """Yield (server_name, server_config) pairs from the discovery file.

        On missing file: logs ERROR and yields nothing.
        On malformed JSON or wrong structure: raises DiscoverySourceError.
        """
        if not self.path.exists():
            log.error(
                "Discovery source not found: %s — no servers will be discovered",
                self.path,
            )
            return

        try:
            raw = json.loads(self.path.read_text())
        except json.JSONDecodeError as exc:
            raise DiscoverySourceError(
                f"Discovery source is not valid JSON: {self.path}: {exc}"
            ) from exc

        if not isinstance(raw, dict) or "mcpServers" not in raw:
            raise DiscoverySourceError(
                f"Discovery source must be a JSON object with a top-level "
                f"'mcpServers' key: {self.path}"
            )

        servers = raw["mcpServers"]
        if not isinstance(servers, dict):
            raise DiscoverySourceError(
                f"'mcpServers' must be a JSON object: {self.path}"
            )

        for name, config in servers.items():
            if not isinstance(config, dict):
                log.warning(
                    "Skipping discovery entry %r: config must be an object, got %s",
                    name, type(config).__name__,
                )
                continue
            if _is_shield_entry(name, config):
                log.info("Skipping self-referential discovery entry %r (shield self-filter)", name)
                continue
            log.debug("Discovered server %r from %s", name, self.path)
            yield name, config
