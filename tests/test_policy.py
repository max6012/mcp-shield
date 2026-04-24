"""Tests for the mcp_shield.policy module."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_shield.policy import (
    GatewayConfig,
    PolicyAction,
    PolicyRule,
    load_config,
)


SAMPLE_CONFIG_YAML = textwrap.dedent("""\
    downstream_servers:
      filesystem:
        command: npx
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
      github:
        command: npx
        args: ["-y", "@modelcontextprotocol/server-github"]
        env:
          GITHUB_TOKEN: "tok-xxx"

    policy:
      default_action: log
      severity_threshold: low
      enabled_categories: null  # all

      servers:
        filesystem:
          default_action: redact
          severity_threshold: medium

      tools:
        github.create_issue:
          default_action: block
          severity_threshold: high

    audit:
      db_path: mcp-shield-audit.db
      log_matched_text: false
      log_full_payload: false
""")


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(SAMPLE_CONFIG_YAML)
    return p


class TestPolicyAction:
    def test_enum_values(self) -> None:
        assert PolicyAction.BLOCK.value == "block"
        assert PolicyAction.REDACT.value == "redact"
        assert PolicyAction.LOG.value == "log"


class TestPolicyRule:
    def test_valid_rule(self) -> None:
        rule = PolicyRule(action="block", severity_threshold="high")
        assert rule.action == "block"
        assert rule.severity_threshold == "high"

    def test_invalid_action_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid action"):
            PolicyRule(action="explode")

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid severity"):
            PolicyRule(action="log", severity_threshold="extreme")


class TestLoadConfig:
    def test_loads_downstream_servers(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert "filesystem" in cfg.downstream_servers
        assert "github" in cfg.downstream_servers
        assert cfg.downstream_servers["filesystem"]["command"] == "npx"

    def test_loads_global_policy(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert cfg.global_policy.action == "log"
        assert cfg.global_policy.severity_threshold == "low"
        assert cfg.global_policy.enabled_categories is None

    def test_loads_server_policy(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert "filesystem" in cfg.server_policies
        fs_policy = cfg.server_policies["filesystem"]
        assert fs_policy.action == "redact"
        assert fs_policy.severity_threshold == "medium"

    def test_loads_tool_policy(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert "github.create_issue" in cfg.tool_policies
        tool_policy = cfg.tool_policies["github.create_issue"]
        assert tool_policy.action == "block"
        assert tool_policy.severity_threshold == "high"

    def test_loads_audit_settings(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert cfg.audit["db_path"] == "mcp-shield-audit.db"
        assert cfg.audit["log_matched_text"] is False
        assert cfg.audit["log_full_payload"] is False

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            load_config(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_structure_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("- just\n- a\n- list\n")
        with pytest.raises(ValueError, match="must be a mapping"):
            load_config(bad)

    def test_missing_downstream_servers_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("policy:\n  default_action: log\n")
        with pytest.raises(ValueError, match="downstream_servers"):
            load_config(bad)

    def test_invalid_action_in_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(textwrap.dedent("""\
            downstream_servers:
              s1:
                command: echo
            policy:
              default_action: nuke
        """))
        with pytest.raises(ValueError, match="Invalid action"):
            load_config(bad)


class TestResolvePolicy:
    def test_global_default_when_no_override(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        # "github" server, "list_repos" tool — no overrides exist
        policy = cfg.resolve_policy("github", "list_repos")
        assert policy.action == "log"
        assert policy.severity_threshold == "low"

    def test_server_override_takes_precedence(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        # "filesystem" has a server-level override; "read_file" has no tool override
        policy = cfg.resolve_policy("filesystem", "read_file")
        assert policy.action == "redact"
        assert policy.severity_threshold == "medium"

    def test_tool_override_takes_precedence(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        # "github.create_issue" has a tool-level override
        policy = cfg.resolve_policy("github", "create_issue")
        assert policy.action == "block"
        assert policy.severity_threshold == "high"

    def test_tool_override_beats_server_override(self) -> None:
        """Tool policy wins even when a server policy also exists."""
        cfg = GatewayConfig(
            downstream_servers={"s": {"command": "echo"}},
            global_policy=PolicyRule(action="log"),
            server_policies={"s": PolicyRule(action="redact")},
            tool_policies={"s.t": PolicyRule(action="block", severity_threshold="critical")},
        )
        policy = cfg.resolve_policy("s", "t")
        assert policy.action == "block"
        assert policy.severity_threshold == "critical"
