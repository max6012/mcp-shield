"""Policy configuration engine for MCP Shield.

Loads a YAML config describing downstream servers, security policies, and
audit settings.  Policies are resolved with three-level inheritance:
tool_policies > server_policies > global_policy.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ------------------------------------------------------------------
# Constants & helpers
# ------------------------------------------------------------------

class PolicyAction(enum.Enum):
    """Actions that the gateway can take when a pattern matches."""

    BLOCK = "block"
    REDACT = "redact"
    LOG = "log"


_VALID_ACTIONS = {a.value for a in PolicyAction}
_SEVERITY_LEVELS = ("low", "medium", "high", "critical")
_SEVERITY_RANK = {level: idx for idx, level in enumerate(_SEVERITY_LEVELS)}


def _validate_action(value: str) -> str:
    if value not in _VALID_ACTIONS:
        raise ValueError(
            f"Invalid action {value!r}; must be one of {sorted(_VALID_ACTIONS)}"
        )
    return value


def _validate_severity(value: str) -> str:
    if value not in _SEVERITY_RANK:
        raise ValueError(
            f"Invalid severity {value!r}; must be one of {list(_SEVERITY_LEVELS)}"
        )
    return value


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyRule:
    """A single policy rule that maps matches to an action."""

    action: str
    severity_threshold: str = "low"
    enabled_categories: list[str] | None = None
    custom_patterns_file: str | None = None

    def __post_init__(self) -> None:
        _validate_action(self.action)
        _validate_severity(self.severity_threshold)


@dataclass
class GatewayConfig:
    """Top-level gateway configuration."""

    downstream_servers: dict[str, dict[str, Any]]
    global_policy: PolicyRule
    server_policies: dict[str, PolicyRule] = field(default_factory=dict)
    tool_policies: dict[str, PolicyRule] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=lambda: {
        "db_path": "mcp-shield-audit.db",
        "log_matched_text": False,
        "log_full_payload": False,
    })

    # ------------------------------------------------------------------
    # Policy resolution
    # ------------------------------------------------------------------

    def resolve_policy(self, server_name: str, tool_name: str) -> PolicyRule:
        """Return the effective policy for *server_name* / *tool_name*.

        Resolution order (most specific wins):
          1. tool_policies  (key = "server.tool")
          2. server_policies
          3. global_policy
        """
        fq_tool = f"{server_name}.{tool_name}"
        if fq_tool in self.tool_policies:
            return self.tool_policies[fq_tool]
        if server_name in self.server_policies:
            return self.server_policies[server_name]
        return self.global_policy


# ------------------------------------------------------------------
# YAML loading
# ------------------------------------------------------------------

def _parse_policy_rule(raw: dict[str, Any]) -> PolicyRule:
    """Build a PolicyRule from a raw YAML dict."""
    return PolicyRule(
        action=raw.get("default_action", "log"),
        severity_threshold=raw.get("severity_threshold", "low"),
        enabled_categories=raw.get("enabled_categories"),
        custom_patterns_file=raw.get("custom_patterns_file"),
    )


def load_config(path: str | Path) -> GatewayConfig:
    """Read a YAML configuration file and return a ``GatewayConfig``."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("Config YAML must be a mapping at the top level")

    # --- downstream servers ---
    if "downstream_servers" not in raw:
        raise ValueError("Config must contain a 'downstream_servers' section")
    downstream_servers: dict[str, dict[str, Any]] = raw["downstream_servers"]

    # --- policy ---
    policy_raw = raw.get("policy", {})
    if not isinstance(policy_raw, dict):
        raise ValueError("'policy' section must be a mapping")

    global_policy = _parse_policy_rule(policy_raw)

    server_policies: dict[str, PolicyRule] = {}
    for name, srv_raw in policy_raw.get("servers", {}).items():
        server_policies[name] = _parse_policy_rule(srv_raw)

    tool_policies: dict[str, PolicyRule] = {}
    for name, tool_raw in policy_raw.get("tools", {}).items():
        tool_policies[name] = _parse_policy_rule(tool_raw)

    # --- audit ---
    audit_raw = raw.get("audit", {})
    audit = {
        "db_path": audit_raw.get("db_path", "mcp-shield-audit.db"),
        "log_matched_text": audit_raw.get("log_matched_text", False),
        "log_full_payload": audit_raw.get("log_full_payload", False),
    }

    return GatewayConfig(
        downstream_servers=downstream_servers,
        global_policy=global_policy,
        server_policies=server_policies,
        tool_policies=tool_policies,
        audit=audit,
    )
