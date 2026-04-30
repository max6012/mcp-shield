# MCP Shield

A regex-based DLP proxy for the MCP stdio transport. MCP Shield sits between an AI client (Claude Desktop, Claude Code, Cursor, etc.) and its MCP servers, intercepting tool calls and responses to scan for known credential formats and PII. Matches are blocked, redacted, or logged according to a policy you control.

**What this is:** a transport-layer DLP filter. It catches secrets and PII that appear in tool arguments or tool responses — known formats that your patterns cover.

**What this is not:** a defense against prompt injection, malicious MCP servers, or credential formats you haven't written patterns for. See [Threat model](#threat-model) for the full scope.

## Current state

Working MVP. Handles stdio-transport MCP servers end-to-end.

- Proxy gateway aggregates and namespaces tools from multiple downstream MCP servers
- 24 built-in patterns across 5 categories: cloud credentials, API tokens, cryptographic material, structured PII, infrastructure
- Policy engine with three-level inheritance (tool > server > global), severity thresholds, category filters
- `block` / `redact` / `log` actions applied to both requests and responses
- SQLite audit log with configurable payload and plaintext capture
- `PolicyProvider` abstraction separates local bootstrap config from security policy — policy is independently loadable from a local file or a remote HTTPS endpoint
- Remote policy fetch with X-API-Key auth, ETag caching, and retry/backoff
- 86 tests passing

## Threat model

### What MCP Shield stops

- **Credential exfiltration through tool responses.** A filesystem MCP server returns a `.env` file; a database server echoes a connection string back in an error message. MCP Shield intercepts the response before it reaches the AI client and redacts or blocks it.
- **Credentials sent into tool calls.** A user pastes an API key into a prompt; the AI client forwards it as a tool argument. MCP Shield scans outbound arguments and can block or redact before the downstream server sees them.
- **PII flowing through MCP traffic.** SSNs, credit card numbers, and phone numbers in either direction.
- **Policy-driven enforcement without per-server configuration.** A centrally managed policy applies uniformly across all downstream servers — no per-tool opt-in required.

### What MCP Shield does not stop

- **Supply chain attacks against MCP Shield itself.** If the `mcp-shield` package or any of its dependencies (`mcp`, `httpx`, `pyyaml`) is compromised, the gateway becomes the attacker's foothold with access to every credential that flows through it. Pin dependencies to cryptographic hashes in production. (See the [LiteLLM supply chain compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html) for the exact attack class.)
- **Unknown or encoded credential formats.** Patterns match what they are written for. A base64-encoded secret, a custom token format, or a credential split across multiple fields will not be caught.
- **Prompt injection.** MCP Shield is a regex scanner, not a semantic analyzer. It cannot detect instructions embedded in tool output designed to manipulate the AI client's subsequent behavior.
- **A malicious downstream MCP server.** MCP Shield trusts the servers listed in its config. If a downstream server is itself compromised or adversarial, MCP Shield will proxy its calls faithfully, subject only to pattern matches on the traffic content.
- **Policy endpoint compromise.** If the remote policy source is tampered with, an attacker can silently weaken enforcement (e.g., flip all rules to `log`). Cryptographic signing of policy responses is in the backlog; until then, treat the policy endpoint as a high-value target.
- **Credentials that never appear in tool call text.** Secrets injected at the OS or container level, or passed through side channels outside the MCP protocol, are invisible to the gateway.
- **Non-text MCP content.** `ImageContent` blobs (screenshots, rendered pages) are passed through unscanned — regex cannot read pixels. `EmbeddedResource` text blobs are scanned; binary resources are not.

### Trust boundaries

MCP Shield trusts its own process and config. Everything in tool call traffic — arguments, responses, server names — is untrusted input. The policy source (local file or remote endpoint) is trusted by configuration; securing it is the operator's responsibility.

## Roadmap

### v0.2 — Centralized policy and deployment

- ~~Separate local bootstrap config from centrally-managed policy~~ ✓
- ~~Remote policy fetch over HTTPS with API-key auth, ETag support, retry/backoff~~ ✓
- Local policy cache (survives process restarts), configurable fail-open / fail-closed fallback
- Periodic background refresh (4 hour default)
- Auto-discovery of downstream MCP servers from the universal `mcpServers` config schema
- Deployment guide covering MDM integration and the threat model boundaries

### Backlog

- Cryptographic signing of policy responses (defense against user-controlled MITM)
- SIEM forwarding for audit events
- Behavioral hard-stops beyond payload matching (rate limits, repeated blocked calls)
- Usage report / policy tuning mode

## License

MIT. See [LICENSE](LICENSE).
