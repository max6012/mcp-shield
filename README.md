# MCP Shield

A security gateway for Model Context Protocol (MCP) servers. MCP Shield sits between AI clients (Claude Desktop, Claude Code, Cursor, etc.) and the MCP servers they use, proxying tool calls and responses while inspecting traffic for sensitive data — secrets, credentials, PII — via regex pattern matching. No LLM inference in the inspection path.

## Current state

Working MVP. Handles stdio-transport MCP servers end-to-end.

- Proxy gateway aggregates and namespaces tools from multiple downstream MCP servers
- 24 built-in patterns across 5 categories: cloud credentials, API tokens, cryptographic material, structured PII, infrastructure
- Policy engine with three-level inheritance (tool > server > global), severity thresholds, category filters
- `block` / `redact` / `log` actions applied to both requests and responses
- SQLite audit log with configurable payload and plaintext capture
- 47 tests passing

## Roadmap

### v0.2 — Centralized policy and deployment

- Separate local bootstrap config from centrally-managed policy
- Remote policy fetch over HTTPS with API-key auth, local cache, configurable fail-open / fail-closed fallback
- Periodic refresh with ETag support (4 hour default)
- Auto-discovery of downstream MCP servers from the universal `mcpServers` config schema
- Deployment guide covering MDM integration and the threat model boundaries

### Backlog

- Cryptographic signing of policy responses (defense against user-controlled MITM)

## License

MIT. See [LICENSE](LICENSE).
