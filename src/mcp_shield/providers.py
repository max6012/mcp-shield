"""PolicyProvider protocol and implementations.

FilePolicyProvider   — loads Policy from a local YAML file.
RemotePolicyProvider — fetches Policy over HTTPS with ETag caching and retry/backoff.
make_policy_provider — factory: https?:// URL → Remote, anything else → File.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

import httpx
import yaml

from mcp_shield.policy import Policy, load_policy_from_dict

log = logging.getLogger("mcp-shield.providers")

_MAX_ATTEMPTS = 3
_RETRY_DELAYS = (1.0, 2.0)   # seconds before attempt 2 and 3
_REQUEST_TIMEOUT = 10.0


class RemotePolicyError(Exception):
    """Raised when a remote policy fetch fails unrecoverably."""


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

    def __init__(self, url: str, api_key: str | None = None) -> None:
        self.url = url
        self.api_key = api_key
        self._etag: str | None = None
        self._cached_policy: Policy | None = None

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
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        self.url, headers=headers, timeout=_REQUEST_TIMEOUT
                    )
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                log.warning("Policy fetch attempt %d failed: %s", attempt + 1, exc)
                last_exc = exc
                continue

            if resp.status_code == 304:
                log.debug("Policy unchanged (304 Not Modified), using cached policy")
                return self._cached_policy  # type: ignore[return-value]  # guaranteed by If-None-Match guard above

            if resp.status_code == 200:
                etag = resp.headers.get("ETag")
                if etag:
                    self._etag = etag
                self._cached_policy = load_policy_from_dict(resp.json())
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

def make_policy_provider(source: str) -> PolicyProvider:
    """Return the appropriate PolicyProvider for source.

    https?:// URL → RemotePolicyProvider (reads MCP_SHIELD_API_KEY from env).
    Anything else → FilePolicyProvider (treated as a local path).
    """
    if source.startswith("https://") or source.startswith("http://"):
        return RemotePolicyProvider(
            url=source,
            api_key=os.environ.get("MCP_SHIELD_API_KEY"),
        )
    return FilePolicyProvider(path=source)
