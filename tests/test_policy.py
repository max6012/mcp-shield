"""Tests for the mcp_shield.policy module."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_shield.policy import (
    GatewayConfig,
    LocalConfig,
    Policy,
    PolicyAction,
    PolicyRule,
    load_config,
    load_policy_from_dict,
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
        assert cfg.policy.global_rule.action == "log"
        assert cfg.policy.global_rule.severity_threshold == "low"
        assert cfg.policy.global_rule.enabled_categories is None

    def test_loads_server_policy(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert "filesystem" in cfg.policy.server_rules
        fs_rule = cfg.policy.server_rules["filesystem"]
        assert fs_rule.action == "redact"
        assert fs_rule.severity_threshold == "medium"

    def test_loads_tool_policy(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert "github.create_issue" in cfg.policy.tool_rules
        tool_rule = cfg.policy.tool_rules["github.create_issue"]
        assert tool_rule.action == "block"
        assert tool_rule.severity_threshold == "high"

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

    def test_policy_source_loaded(self, tmp_path: Path) -> None:
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent("""\
            downstream_servers:
              s1:
                command: echo
            policy_source: https://policy.example.com/policy.json
            policy:
              default_action: log
        """))
        cfg = load_config(p)
        assert cfg.local.policy_source == "https://policy.example.com/policy.json"

    def test_policy_source_defaults_to_none(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        assert cfg.local.policy_source is None


class TestPolicy:
    def test_load_policy_from_dict(self) -> None:
        raw = {
            "default_action": "redact",
            "severity_threshold": "medium",
            "servers": {
                "s1": {"default_action": "block", "severity_threshold": "high"},
            },
            "tools": {
                "s1.t1": {"default_action": "log"},
            },
        }
        policy = load_policy_from_dict(raw)
        assert policy.global_rule.action == "redact"
        assert policy.server_rules["s1"].action == "block"
        assert policy.tool_rules["s1.t1"].action == "log"

    def test_load_policy_from_dict_strips_custom_patterns_file(self) -> None:
        """custom_patterns_file in a remote/dict policy is ignored — path traversal guard."""
        raw = {
            "default_action": "block",
            "custom_patterns_file": "/etc/ssh/ssh_host_rsa_key",
        }
        policy = load_policy_from_dict(raw)
        assert policy.global_rule.custom_patterns_file is None

    def test_load_config_honours_custom_patterns_file(self, tmp_path: Path) -> None:
        """custom_patterns_file in the local config file IS honoured."""
        patterns = tmp_path / "my_patterns.yaml"
        patterns.touch()
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent(f"""\
            downstream_servers:
              s1:
                command: echo
            policy:
              default_action: log
              custom_patterns_file: {patterns}
        """))
        cfg = load_config(cfg_file)
        assert cfg.policy.global_rule.custom_patterns_file == str(patterns)

    def test_remote_policy_cannot_set_custom_patterns_file(self, tmp_path: Path) -> None:
        """Simulates a remote policy response with custom_patterns_file — must be stripped."""
        # This is what an attacker-controlled policy endpoint would return
        remote_policy_response = {
            "default_action": "log",
            "custom_patterns_file": "/etc/passwd",
        }
        policy = load_policy_from_dict(remote_policy_response)
        assert policy.global_rule.custom_patterns_file is None


class TestResolvePolicy:
    def test_global_default_when_no_override(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        policy = cfg.resolve_policy("github", "list_repos")
        assert policy.action == "log"
        assert policy.severity_threshold == "low"

    def test_server_override_takes_precedence(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        policy = cfg.resolve_policy("filesystem", "read_file")
        assert policy.action == "redact"
        assert policy.severity_threshold == "medium"

    def test_tool_override_takes_precedence(self, config_file: Path) -> None:
        cfg = load_config(config_file)
        policy = cfg.resolve_policy("github", "create_issue")
        assert policy.action == "block"
        assert policy.severity_threshold == "high"

    def test_tool_override_beats_server_override(self) -> None:
        cfg = GatewayConfig(
            local=LocalConfig(downstream_servers={"s": {"command": "echo"}}),
            policy=Policy(
                global_rule=PolicyRule(action="log"),
                server_rules={"s": PolicyRule(action="redact")},
                tool_rules={"s.t": PolicyRule(action="block", severity_threshold="critical")},
            ),
        )
        policy = cfg.resolve_policy("s", "t")
        assert policy.action == "block"
        assert policy.severity_threshold == "critical"
