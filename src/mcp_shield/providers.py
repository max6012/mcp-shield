"""PolicyProvider protocol and implementations.

FilePolicyProvider   — loads Policy from a local YAML file.
RemotePolicyProvider — fetches Policy over HTTPS with ETag caching and retry/backoff.
PolicyCache          — persists fetched policy to disk so ETag survives restarts.
make_policy_provider — factory: https?:// URL → Remote, anything else → File.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx
import yaml

from mcp_shield.policy import Policy, load_policy_from_dict

log = logging.getLogger("mcp-shield.providers")

_MAX_ATTEMPTS = 3
_RETRY_DELAYS = (1.0, 2.0)   # seconds before attempt 2 and 3
_REQUEST_TIMEOUT = 10.0


class RemotePolicyError(Exception):
    """Raised when a remote policy fetch fails unrecoverably."""


# ------------------------------------------------------------------
# URL safety validation
# ------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local (AWS IMDS, etc.)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


def _validate_policy_url(url: str) -> None:
    """Raise ValueError if url targets a non-public or non-http(s) destination.

    Blocks: non-http(s) schemes, RFC1918, loopback, link-local addresses.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"policy_source URL must use http or https scheme, got {parsed.scheme!r}"
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"policy_source URL has no hostname: {url!r}")
    try:
        addr = ipaddress.ip_address(hostname)
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                raise ValueError(
                    f"policy_source URL resolves to a private/internal address "
                    f"({addr} is in {network}) — SSRF protection"
                )
    except ValueError as exc:
        if "SSRF protection" in str(exc):
            raise
        # hostname is a domain name, not a bare IP — DNS resolution is not checked
        # here (that would require async), but the scheme and IP-literal checks above
        # catch the most common SSRF vectors (169.254.x.x, 127.x.x.x, etc.).
        pass


# ------------------------------------------------------------------
# PolicyCache
# ------------------------------------------------------------------

_DEFAULT_CACHE_DIR = Path.home() / ".mcp-shield" / "cache"


class PolicyCache:
    """Persists a fetched policy to disk so ETag and policy survive process restarts.

    Cache format (JSON):
      {
        "source_url": "https://...",
        "fetched_at": "2026-04-27T12:00:00Z",
        "etag": "\"v1\"",
        "policy": { ... raw policy dict ... }
      }
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._path = (cache_dir or _DEFAULT_CACHE_DIR) / "policy.json"

    def save(self, source_url: str, raw_dict: dict, etag: str | None) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "source_url": source_url,
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "etag": etag,
            "policy": raw_dict,
        }
        self._path.write_text(json.dumps(data, indent=2))
        log.debug("Policy cached to %s", self._path)

    def load(self) -> tuple[Policy, str | None] | None:
        if not self._path.exists():
            return None
        try:
            data = json.loads(self._path.read_text())
            policy = load_policy_from_dict(data["policy"])
            etag = data.get("etag")
            log.debug("Loaded policy from cache (etag=%s, path=%s)", etag, self._path)
            return policy, etag
        except Exception as exc:
            log.warning("Policy cache corrupt or unreadable (%s): %s", self._path, exc)
            return None


@runtime_checkable
class PolicyProvider(Protocol):
    """Async protocol for fetching a Policy from any source."""

    async def fetch(self) -> Policy:
        ...


# ------------------------------------------------------------------
# FilePolicyProvider
# ------------------------------------------------------------------

class FilePolicyProvider:
    """Loads Policy from a standalone YAML file (just the policy dict, no nesting)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    async def fetch(self) -> Policy:
        if not self.path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.path}")
        raw = yaml.safe_load(self.path.read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"Policy file must be a YAML mapping: {self.path}")
        return load_policy_from_dict(raw)


# ------------------------------------------------------------------
# RemotePolicyProvider
# ------------------------------------------------------------------

class RemotePolicyProvider:
    """Fetches Policy from a remote HTTPS endpoint.

    - X-API-Key auth header when api_key is set
    - ETag / If-None-Match for conditional GETs (avoids re-parsing unchanged policy)
    - Up to 3 attempts with 1s / 2s backoff on transient errors (connect, timeout, 5xx)
    - Raises RemotePolicyError on unrecoverable failure (4xx, exhausted retries)
    """

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        cache: PolicyCache | None = None,
    ) -> None:
        _validate_policy_url(url)
        self.url = url
        self.api_key = api_key
        self._etag: str | None = None
        self._cached_policy: Policy | None = None
        self._cache = cache
        if cache is not None:
            cached = cache.load()
            if cached is not None:
                self._cached_policy, self._etag = cached
                log.debug("Pre-seeded policy from disk cache (etag=%s)", self._etag)

    async def fetch(self) -> Policy:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if self._etag and self._cached_policy is not None:
            headers["If-None-Match"] = self._etag

        last_exc: Exception | None = None

        for attempt in range(_MAX_ATTEMPTS):
            if attempt > 0:
                delay = _RETRY_DELAYS[attempt - 1]
                log.info(
                    "Policy fetch retry %d/%d in %.0fs",
                    attempt + 1, _MAX_ATTEMPTS, delay,
                )
                await asyncio.sleep(delay)

            try:
                async with httpx.AsyncClient(follow_redirects=False) as client:
                    resp = await client.get(
                        self.url, headers=headers, timeout=_REQUEST_TIMEOUT
                    )
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                log.warning("Policy fetch attempt %d failed: %s", attempt + 1, exc)
                last_exc = exc
                continue

            if resp.status_code == 304:
                if self._cached_policy is None:
                    raise RemotePolicyError("Received 304 Not Modified but no cached policy exists")
                log.debug("Policy unchanged (304 Not Modified), using cached policy")
                return self._cached_policy

            if resp.status_code == 200:
                etag = resp.headers.get("ETag")
                if etag:
                    self._etag = etag
                raw = resp.json()
                self._cached_policy = load_policy_from_dict(raw)
                if self._cache is not None:
                    self._cache.save(self.url, raw, etag)
                log.info(
                    "Policy fetched from %s (etag=%s)",
                    self.url, etag or "none",
                )
                return self._cached_policy

            if resp.status_code >= 500:
                log.warning(
                    "Policy fetch attempt %d: HTTP %d from %s",
                    attempt + 1, resp.status_code, self.url,
                )
                last_exc = RemotePolicyError(f"HTTP {resp.status_code}")
                continue

            # 4xx — auth error, not found, etc. — don't retry
            raise RemotePolicyError(
                f"Policy fetch failed: HTTP {resp.status_code} from {self.url}"
            )

        raise RemotePolicyError(
            f"Policy fetch failed after {_MAX_ATTEMPTS} attempts: {last_exc}"
        ) from last_exc


# ------------------------------------------------------------------
# Factory
# ------------------------------------------------------------------

def make_policy_provider(
    source: str,
    cache: PolicyCache | None = None,
) -> PolicyProvider:
    """Return the appropriate PolicyProvider for source.

    https?:// URL → RemotePolicyProvider (reads MCP_SHIELD_API_KEY from env).
    Anything else → FilePolicyProvider (treated as a local path).
    """
    if source.startswith("https://") or source.startswith("http://"):
        return RemotePolicyProvider(
            url=source,
            api_key=os.environ.get("MCP_SHIELD_API_KEY"),
            cache=cache,
        )
    return FilePolicyProvider(path=source)
