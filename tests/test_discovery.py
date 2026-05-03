"""Tests for mcp_shield.discovery — DiscoveryLoader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_shield.discovery import DiscoveryLoader, DiscoverySourceError, _is_shield_entry


VALID_CONFIG = {
    "mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"TOKEN": "x"}},
    }
}


@pytest.fixture
def discovery_file(tmp_path: Path) -> Path:
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(VALID_CONFIG))
    return p


class TestDiscoveryLoaderSuccess:

    def test_yields_all_servers(self, discovery_file: Path) -> None:
        pairs = list(DiscoveryLoader(discovery_file).load())
        names = {name for name, _ in pairs}
        assert names == {"filesystem", "github"}

    def test_yields_correct_config(self, discovery_file: Path) -> None:
        pairs = dict(DiscoveryLoader(discovery_file).load())
        assert pairs["filesystem"]["command"] == "npx"
        assert pairs["github"]["env"] == {"TOKEN": "x"}

    def test_env_key_preserved(self, discovery_file: Path) -> None:
        pairs = dict(DiscoveryLoader(discovery_file).load())
        assert "env" in pairs["github"]

    def test_minimal_server_entry(self, tmp_path: Path) -> None:
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({"mcpServers": {"s1": {"command": "echo"}}}))
        pairs = dict(DiscoveryLoader(p).load())
        assert "s1" in pairs
        assert pairs["s1"]["command"] == "echo"

    def test_empty_mcpservers(self, tmp_path: Path) -> None:
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({"mcpServers": {}}))
        pairs = list(DiscoveryLoader(p).load())
        assert pairs == []

    def test_real_claude_desktop_format(self, tmp_path: Path) -> None:
        """Parses a realistic Claude Desktop config file successfully."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"],
                },
                "brave-search": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-brave-search"],
                    "env": {"BRAVE_API_KEY": "BSAx..."},
                },
            }
        }
        p = tmp_path / ".mcp.json"
        p.write_text(json.dumps(config))
        pairs = dict(DiscoveryLoader(p).load())
        assert set(pairs) == {"filesystem", "brave-search"}


class TestDiscoveryLoaderMissingFile:

    def test_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        pairs = list(DiscoveryLoader(tmp_path / "nonexistent.json").load())
        assert pairs == []

    def test_missing_file_logs_error(self, tmp_path: Path, caplog) -> None:
        import logging
        with caplog.at_level(logging.ERROR, logger="mcp-shield.discovery"):
            list(DiscoveryLoader(tmp_path / "nonexistent.json").load())
        assert any("Discovery source not found" in r.message for r in caplog.records)


class TestDiscoveryLoaderErrors:

    def test_malformed_json_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "mcp.json"
        p.write_text("{not valid json")
        with pytest.raises(DiscoverySourceError, match="not valid JSON"):
            list(DiscoveryLoader(p).load())

    def test_missing_mcpservers_key_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({"servers": {}}))
        with pytest.raises(DiscoverySourceError, match="mcpServers"):
            list(DiscoveryLoader(p).load())

    def test_top_level_list_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps([{"command": "echo"}]))
        with pytest.raises(DiscoverySourceError, match="mcpServers"):
            list(DiscoveryLoader(p).load())

    def test_mcpservers_is_list_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({"mcpServers": [{"command": "echo"}]}))
        with pytest.raises(DiscoverySourceError, match="mcpServers.*object"):
            list(DiscoveryLoader(p).load())

    def test_non_dict_server_entry_skipped(self, tmp_path: Path) -> None:
        """Malformed individual entries are skipped with a warning, not a hard error."""
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({
            "mcpServers": {
                "good": {"command": "echo"},
                "bad": "not-a-dict",
            }
        }))
        pairs = dict(DiscoveryLoader(p).load())
        assert "good" in pairs
        assert "bad" not in pairs


class TestSelfFilter:

    def test_command_with_mcp_shield_filtered(self) -> None:
        assert _is_shield_entry("shield", {"command": "mcp_shield"})

    def test_command_with_mcp_hyphen_shield_filtered(self) -> None:
        assert _is_shield_entry("shield", {"command": "/usr/local/bin/mcp-shield"})

    def test_args_with_module_flag_filtered(self) -> None:
        assert _is_shield_entry("s", {"command": "python", "args": ["-m", "mcp_shield.cli"]})

    def test_args_with_module_package_filtered(self) -> None:
        assert _is_shield_entry("s", {"command": "python3", "args": ["-m", "mcp_shield"]})

    def test_explicit_shield_skip_flag_filtered(self) -> None:
        assert _is_shield_entry("s", {"command": "npx", "shield_skip": True})

    def test_unrelated_server_not_filtered(self) -> None:
        assert not _is_shield_entry("github", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]})

    def test_unrelated_command_not_filtered(self) -> None:
        assert not _is_shield_entry("fs", {"command": "node", "args": ["server.js"]})

    def test_loader_skips_shield_entries(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "mcp-shield": {"command": "mcp_shield", "args": ["config.yaml"]},
                "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config))
        pairs = dict(DiscoveryLoader(p).load())
        assert "github" in pairs
        assert "mcp-shield" not in pairs

    def test_loader_logs_info_for_filtered_entries(self, tmp_path: Path, caplog) -> None:
        import logging
        config = {
            "mcpServers": {
                "shield": {"command": "mcp_shield", "args": ["config.yaml"]},
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config))
        with caplog.at_level(logging.INFO, logger="mcp-shield.discovery"):
            list(DiscoveryLoader(p).load())
        assert any("self-filter" in r.message for r in caplog.records)

    def test_non_shield_entries_still_yielded_after_filter(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "self": {"command": "mcp-shield"},
                "fs": {"command": "npx", "args": ["server-filesystem"]},
                "gh": {"command": "npx", "args": ["server-github"]},
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config))
        pairs = dict(DiscoveryLoader(p).load())
        assert set(pairs) == {"fs", "gh"}


class TestDiscoveryMerge:
    """Integration: discovered + explicit server merge via run_gateway logic."""

    def _make_discovery_file(self, tmp_path: Path, servers: dict) -> Path:
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({"mcpServers": servers}))
        return p

    def _make_config_file(self, tmp_path: Path, explicit: dict, discovery_path: str | None = None) -> Path:
        import textwrap, yaml  # yaml already a dep
        lines = ["downstream_servers:"]
        for name, cfg in explicit.items():
            lines.append(f"  {name}:")
            lines.append(f"    command: {cfg['command']}")
        if discovery_path:
            lines.append(f"discovery_source: {discovery_path}")
        lines.append("policy:")
        lines.append("  default_action: log")
        p = tmp_path / "config.yaml"
        p.write_text("\n".join(lines) + "\n")
        return p

    def test_explicit_wins_over_discovered_on_conflict(self, tmp_path: Path) -> None:
        from mcp_shield.policy import load_config
        disc = self._make_discovery_file(tmp_path, {"s1": {"command": "discovered-cmd"}})
        cfg_file = self._make_config_file(tmp_path, {"s1": {"command": "explicit-cmd"}}, str(disc))
        cfg = load_config(cfg_file)
        # The merge happens in run_gateway, not load_config — test loader directly
        from mcp_shield.discovery import DiscoveryLoader
        discovered = dict(DiscoveryLoader(disc).load())
        explicit = cfg.local.downstream_servers
        merged = {**discovered, **explicit}
        assert merged["s1"]["command"] == "explicit-cmd"

    def test_discovered_alone_works(self, tmp_path: Path) -> None:
        disc = self._make_discovery_file(tmp_path, {
            "server_a": {"command": "cmd-a"},
            "server_b": {"command": "cmd-b"},
        })
        from mcp_shield.discovery import DiscoveryLoader
        pairs = dict(DiscoveryLoader(disc).load())
        assert set(pairs) == {"server_a", "server_b"}

    def test_explicit_alone_works(self, tmp_path: Path) -> None:
        from mcp_shield.policy import load_config
        cfg_file = self._make_config_file(tmp_path, {"only": {"command": "cmd"}})
        cfg = load_config(cfg_file)
        assert "only" in cfg.local.downstream_servers

    def test_both_empty_allowed(self, tmp_path: Path) -> None:
        disc = self._make_discovery_file(tmp_path, {})
        from mcp_shield.discovery import DiscoveryLoader
        pairs = list(DiscoveryLoader(disc).load())
        assert pairs == []

    def test_explicit_plus_discovered_combines_all(self, tmp_path: Path) -> None:
        disc = self._make_discovery_file(tmp_path, {
            "disc1": {"command": "d1"},
            "disc2": {"command": "d2"},
        })
        from mcp_shield.discovery import DiscoveryLoader
        from mcp_shield.policy import load_config
        cfg_file = self._make_config_file(tmp_path, {"exp1": {"command": "e1"}}, str(disc))
        cfg = load_config(cfg_file)
        discovered = dict(DiscoveryLoader(disc).load())
        merged = {**discovered, **cfg.local.downstream_servers}
        assert set(merged) == {"disc1", "disc2", "exp1"}


class TestDiscoverySourceInLocalConfig:

    def test_discovery_source_parsed_from_config(self, tmp_path: Path) -> None:
        import textwrap
        from mcp_shield.policy import load_config

        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            downstream_servers: {}
            discovery_source: /etc/mcp-shield/servers.json
            policy:
              default_action: log
        """))
        cfg = load_config(cfg_file)
        assert cfg.local.discovery_source == "/etc/mcp-shield/servers.json"

    def test_discovery_source_defaults_to_none(self, tmp_path: Path) -> None:
        import textwrap
        from mcp_shield.policy import load_config

        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            downstream_servers: {}
            policy:
              default_action: log
        """))
        cfg = load_config(cfg_file)
        assert cfg.local.discovery_source is None
