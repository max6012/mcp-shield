# MCP Shield — Deployment Guide

## How it actually works (and what it can't do)

MCP Shield intercepts stdio transport between an AI client (Claude Desktop, Claude Code, Cursor, etc.) and its downstream MCP servers. It sits in the `.mcp.json` (or equivalent) config as the entry point, and lists the real servers it should proxy.

**The tamper-resistance reality:** the shield is only as strong as who controls the `.mcp.json` file. An end user with write access to that file can remove MCP Shield from the proxy chain entirely. For meaningful enforcement, you need to lock the file via MDM (Jamf, Intune, etc.). This is the same threat model as any endpoint-deployed security tool — without MDM-locked config, it's a best-effort, not a hard control.

**Scope boundary** — fill this in for each deployment:

| Dimension | Scope |
|-----------|-------|
| Read scope | Tool responses from all proxied MCP servers |
| Write scope | Tool arguments sent by the AI client |
| Execution scope | stdio subprocess only — no network-listening component |
| Network scope | HTTPS to the policy endpoint (if using remote policy) |
| Credential scope | All credentials visible in MCP traffic; none stored by the gateway itself |

**Worst-case impact if MCP Shield is compromised:** the gateway has visibility into all MCP traffic including any credentials that appear in tool calls or responses. MCP Shield's own supply chain (the `mcp-shield` package and its transitive dependencies) is therefore a Tier 2 supply-chain attack surface. Treat it with the same rigor as any privileged process. Pin dependencies to cryptographic hashes; monitor for `.pth` file creation in Python site-packages as a detection signal for supply-chain compromise.


## Directory layout for IT/MDM deployments

```
/etc/mcp-shield/
├── local.yaml          # Gateway config (MDM-locked, points to policy endpoint)
└── servers.json        # Discovery source (may be user-editable or MDM-locked)

~/.mcp.json             # Claude client config (MDM-locked to point at mcp-shield)
~/mcp-shield-audit.db   # SQLite audit log (or configure db_path in local.yaml)
```

A MDM-locked `.mcp.json` (or `claude_desktop_config.json`) looks like:

```json
{
  "mcpServers": {
    "mcp-shield": {
      "command": "python",
      "args": ["-m", "mcp_shield.cli", "/etc/mcp-shield/local.yaml"]
    }
  }
}
```

The real downstream servers are listed in `/etc/mcp-shield/servers.json` (discovery source) or directly in `local.yaml`. MCP Shield discovers and self-filters — if its own entry appears in the discovery file it is automatically skipped.


## Setting up a remote policy endpoint

Remote policy is the recommended pattern for enterprise deployments — it lets you update enforcement rules without touching endpoints.

### Policy JSON schema

```json
{
  "default_action": "log",
  "severity_threshold": "low",
  "servers": {
    "filesystem": {
      "default_action": "redact",
      "severity_threshold": "medium"
    }
  },
  "tools": {
    "github.create_issue": {
      "default_action": "block",
      "severity_threshold": "high"
    }
  }
}
```

Fields:
- `default_action`: `log` | `redact` | `block` (required)
- `severity_threshold`: `low` | `medium` | `high` | `critical` (optional, default `low`)
- `servers`: per-server overrides (optional)
- `tools`: per-tool overrides using `server.tool` key format (optional)

**Note:** `custom_patterns_file` is intentionally ignored in remotely-fetched policy as a path-traversal protection. Custom pattern files must be specified in the local gateway config only.

### Auth

Pass `X-API-Key: <key>` in the request header. Set `MCP_SHIELD_API_KEY` in the environment where MCP Shield runs. The gateway always requests over HTTPS.

### ETag caching

Return an `ETag` header and the gateway will send `If-None-Match` on subsequent requests. A `304 Not Modified` response skips re-parsing the policy. This keeps refresh traffic minimal.

### Minimal Flask policy server

See `examples/policy_server.py` for a complete minimal example. In production, replace the hardcoded policy dict with a lookup against your policy store (Git, database, secrets manager, etc.).

### Gateway config with remote policy

```yaml
downstream_servers: {}   # empty — servers come from discovery_source

discovery_source: /etc/mcp-shield/servers.json

policy_source: https://policy.internal.example.com/mcp-shield/policy.json
fallback_mode: fail-open       # or fail-closed — see below
policy_refresh_seconds: 14400  # refresh every 4h (0 = disable)

policy:
  default_action: log    # bootstrap policy used before first remote fetch

audit:
  db_path: /var/log/mcp-shield-audit.db
  log_matched_text: false
  log_full_payload: false
```


## Fail-open vs fail-closed

`fallback_mode: fail-open` (default): if the policy endpoint is unreachable at startup and there is no cached policy on disk, MCP Shield starts with a built-in safe default (log everything, block and redact nothing). A loud warning is logged and an audit record with `action=fallback` is written. The gateway continues serving tool calls.

`fallback_mode: fail-closed`: if the policy endpoint is unreachable and there is no cache, the gateway refuses to start. Tool calls are refused until the endpoint is reachable again.

Choose based on your tolerance for availability vs security: fail-open keeps the AI client working but may miss policy-required blocks; fail-closed prioritizes enforcement over availability.

After startup, the disk cache (`~/.mcp-shield/cache/policy.json`) is updated on every successful remote fetch, including the ETag. On the next restart the cache pre-seeds the provider, so a transient endpoint outage at startup won't trigger the fallback if a recent policy was previously fetched.


## Auto-discovery of downstream servers

Set `discovery_source` to a path containing a standard Claude MCP servers JSON file:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

This is the same format used by Claude Desktop (`claude_desktop_config.json`), Claude Code (`.mcp.json`), Cursor, and Windsurf — you can point MCP Shield at the same config file your client already uses.

MCP Shield automatically filters itself out of the discovery results, so it is safe to point at the full client config even if it contains the MCP Shield entry.

Explicit `downstream_servers` in `local.yaml` win on name conflict with discovered entries.


## What MCP Shield does NOT defend against

- **Motivated insider with local admin.** Someone who can modify `.mcp.json` or kill the gateway process can bypass it completely. MDM-locked config is the only mitigation.
- **Credentials pasted into prompts.** If a user pastes a secret into the prompt itself (rather than a tool argument), it flows through the AI's context window, not through a tool call. MCP Shield never sees it. This is a prompt-level DLP problem.
- **Model outputs that paraphrase sensitive data.** If the AI rephrases a credential in natural language ("the key starts with AKIA..."), regex matching may fail. Semantic analysis is outside scope.
- **Compromised policy endpoint.** An attacker controlling the remote policy endpoint can silently weaken enforcement to `log`. Cryptographic signing of policy responses is in the backlog (see `t-policy-signing-v2`). Until then, treat the policy endpoint as a high-value target — lock it down with the same care as the secrets it protects.
- **ImageContent blobs.** Screenshots and rendered pages returned as `ImageContent` pass through unscanned.
- **Credentials outside MCP traffic.** Secrets injected at the OS or container level, or passed through side channels, are invisible to the gateway.

MCP Shield is a transport-layer DLP filter. It is most useful as one layer in a defense-in-depth stack, not as a standalone security control.
