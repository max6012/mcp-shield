"""Policy configuration engine for MCP Shield.

Three concerns, separated:
- LocalConfig: bootstrap config on disk (servers, audit, where to get policy)
- Policy: security rules (global, per-server, per-tool) — loadable from disk or remote
- GatewayConfig: assembled runtime config (LocalConfig + Policy)
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
    """Actions the gateway can take when a pattern matches."""

    BLOCK = "block"
    REDACT = "redact"
    LOG = "log"


_VALID_ACTIONS = {a.value for a in PolicyAction}
_SEVERITY_LEVELS = ("low", "medium", "high", "critical")
_SEVERITY_RANK = {level: idx for idx, level in enumerate(_SEVERITY_LEVELS)}
_VALID_FALLBACK_MODES = ("fail-open", "fail-closed")


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
# PolicyRule
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


# ------------------------------------------------------------------
# Policy — security rules, independently loadable / remotely fetchable
# ------------------------------------------------------------------

@dataclass
class Policy:
    """Security rules for the gateway. Decoupled from deployment config so it
    can be loaded from a local file or fetched from a remote endpoint."""

    global_rule: PolicyRule
    server_rules: dict[str, PolicyRule] = field(default_factory=dict)
    tool_rules: dict[str, PolicyRule] = field(default_factory=dict)

    def resolve(self, server_name: str, tool_name: str) -> PolicyRule:
        """Return the effective rule for server_name / tool_name.

        Resolution order (most specific wins):
          1. tool_rules   (key = "server.tool")
          2. server_rules
          3. global_rule
        """
        fq_tool = f"{server_name}.{tool_name}"
        if fq_tool in self.tool_rules:
            return self.tool_rules[fq_tool]
        if server_name in self.server_rules:
            return self.server_rules[server_name]
        return self.global_rule


# Safe default used when remote policy is unreachable and no cache exists.
# Detects and logs everything; never blocks or redacts — operator must fix the endpoint.
FALLBACK_POLICY = Policy(
    global_rule=PolicyRule(action="log", severity_threshold="low"),
)


# ------------------------------------------------------------------
# LocalConfig — bootstrap config, lives on disk, user-editable
# ------------------------------------------------------------------

@dataclass
class LocalConfig:
    """Bootstrap configuration: which servers to connect to, where to write
    audit records, and optionally where to fetch policy from."""

    downstream_servers: dict[str, dict[str, Any]]
    audit: dict[str, Any] = field(default_factory=lambda: {
        "db_path": "mcp-shield-audit.db",
        "log_matched_text": False,
        "log_full_payload": False,
    })
    policy_source: str | None = None  # URL or path; None = use inline policy from YAML
    fallback_mode: str = "fail-open"  # "fail-open" | "fail-closed"
    policy_refresh_seconds: int = 14400  # 0 = disable polling; default 4 h
    discovery_source: str | None = None  # path to Claude-format mcpServers JSON


# ------------------------------------------------------------------
# GatewayConfig — assembled runtime config
# ------------------------------------------------------------------

@dataclass
class GatewayConfig:
    """Runtime gateway config: LocalConfig + Policy combined."""

    local: LocalConfig
    policy: Policy

    @property
    def downstream_servers(self) -> dict[str, dict[str, Any]]:
        return self.local.downstream_servers

    @property
    def audit(self) -> dict[str, Any]:
        return self.local.audit

    def resolve_policy(self, server_name: str, tool_name: str) -> PolicyRule:
        return self.policy.resolve(server_name, tool_name)


# ------------------------------------------------------------------
# YAML loading
# ------------------------------------------------------------------

def _parse_policy_rule(raw: dict[str, Any]) -> PolicyRule:
    # custom_patterns_file is intentionally excluded here — it references a local
    # filesystem path and must only be set via load_config (which reads the trusted
    # local config file). Allowing it through load_policy_from_dict would let a
    # remote policy endpoint trigger an arbitrary file read.
    return PolicyRule(
        action=raw.get("default_action", "log"),
        severity_threshold=raw.get("severity_threshold", "low"),
        enabled_categories=raw.get("enabled_categories"),
    )


def load_policy_from_dict(raw: dict[str, Any]) -> Policy:
    """Build a Policy from a raw dict (YAML section or remote fetch response).

    Note: custom_patterns_file is stripped from all rules here. Only load_config
    (which reads a trusted local file) may set it.
    """
    return Policy(
        global_rule=_parse_policy_rule(raw),
        server_rules={
            name: _parse_policy_rule(srv)
            for name, srv in raw.get("servers", {}).items()
        },
        tool_rules={
            name: _parse_policy_rule(tool)
            for name, tool in raw.get("tools", {}).items()
        },
    )


def load_config(path: str | Path) -> GatewayConfig:
    """Read a YAML configuration file and return a GatewayConfig."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("Config YAML must be a mapping at the top level")

    if "downstream_servers" not in raw:
        raise ValueError("Config must contain a 'downstream_servers' section")

    fallback_mode = raw.get("fallback_mode", "fail-open")
    if fallback_mode not in _VALID_FALLBACK_MODES:
        raise ValueError(
            f"Invalid fallback_mode {fallback_mode!r}; must be one of {list(_VALID_FALLBACK_MODES)}"
        )

    audit_raw = raw.get("audit", {})
    local = LocalConfig(
        downstream_servers=raw["downstream_servers"],
        audit={
            "db_path": audit_raw.get("db_path", "mcp-shield-audit.db"),
            "log_matched_text": audit_raw.get("log_matched_text", False),
            "log_full_payload": audit_raw.get("log_full_payload", False),
        },
        policy_source=raw.get("policy_source"),
        fallback_mode=fallback_mode,
        policy_refresh_seconds=int(raw.get("policy_refresh_seconds", 14400)),
        discovery_source=raw.get("discovery_source"),
    )

    policy_raw = raw.get("policy", {})
    if not isinstance(policy_raw, dict):
        raise ValueError("'policy' section must be a mapping")

    policy = load_policy_from_dict(policy_raw)

    # custom_patterns_file is a local filesystem path — only honour it when reading
    # from the trusted local config file, never from a remote policy fetch.
    custom_patterns_file = policy_raw.get("custom_patterns_file")
    if custom_patterns_file:
        policy = Policy(
            global_rule=PolicyRule(
                action=policy.global_rule.action,
                severity_threshold=policy.global_rule.severity_threshold,
                enabled_categories=policy.global_rule.enabled_categories,
                custom_patterns_file=custom_patterns_file,
            ),
            server_rules=policy.server_rules,
            tool_rules=policy.tool_rules,
        )

    return GatewayConfig(local=local, policy=policy)
