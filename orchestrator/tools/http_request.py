"""GET-only HTTP probe against an allowlisted host.

Mutating methods and request bodies are rejected. This is labeled
reconnaissance against the current scenario target, not a general HTTP client.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from orchestrator.allowlist import AllowlistEntry, is_target_allowed
from orchestrator.interfaces import ActionResult

_MAX_BODY_BYTES = 65_536
_MAX_PATH_LEN = 256
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/=?&%+\-]*$")
_ALLOWED_SCHEMES = {"http", "https"}


class HttpProbeError(ValueError):
    """Raised when an HTTP probe argument fails a safety check."""


def sanitize_path(path: str) -> str:
    """Return a relative URL path that is safe to append to an allowlisted origin."""
    cleaned = (path or "/").strip() or "/"
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if ".." in cleaned or "\\" in cleaned or "\n" in cleaned or "\r" in cleaned:
        raise HttpProbeError("path must be a single relative URL path")
    if len(cleaned) > _MAX_PATH_LEN:
        raise HttpProbeError(f"path exceeds {_MAX_PATH_LEN} characters")
    if not _PATH_RE.match(cleaned):
        raise HttpProbeError("path contains unsupported characters")
    return cleaned


def resolve_probe_url(
    arguments: dict[str, Any],
    default_target: str,
    default_port: int,
    allowlist: list[AllowlistEntry],
) -> tuple[str, str, int, str]:
    """Resolve and allowlist-check the probe URL.

    Returns (url, host, port, path).
    """
    method = str(arguments.get("method") or "GET").upper()
    if method != "GET":
        raise HttpProbeError("http-request is GET-only")
    if arguments.get("body"):
        raise HttpProbeError("http-request does not send a request body")

    raw_url = arguments.get("url")
    if raw_url:
        parsed = urlparse(str(raw_url))
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise HttpProbeError("url must use http or https")
        if parsed.username or parsed.password:
            raise HttpProbeError("url must not include credentials")
        host = parsed.hostname
        if not host:
            raise HttpProbeError("url is missing a host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = sanitize_path(parsed.path or "/")
        if parsed.query:
            path = f"{path}?{parsed.query}"
            if len(path) > _MAX_PATH_LEN:
                raise HttpProbeError(f"path exceeds {_MAX_PATH_LEN} characters")
        url = f"{parsed.scheme}://{host}:{port}{path}"
    else:
        host = str(arguments.get("target") or default_target)
        port = int(arguments.get("port") or default_port)
        path = sanitize_path(str(arguments.get("path") or "/"))
        url = f"http://{host}:{port}{path}"

    if not is_target_allowed(host, port, allowlist):
        raise HttpProbeError(f"target not in allowlist: {host}:{port}")
    return url, host, port, path


async def run(
    arguments: dict[str, Any],
    *,
    default_target: str,
    default_port: int,
    allowlist: list[AllowlistEntry],
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> ActionResult:
    """GET an allowlisted URL and return a truncated response snapshot."""
    try:
        url, host, port, path = resolve_probe_url(
            arguments, default_target, default_port, allowlist
        )
    except HttpProbeError as exc:
        return ActionResult(
            success=False,
            output={
                "tool_id": "http-request",
                "status": "rejected",
                "reason": str(exc),
            },
            error=str(exc),
            terminal=False,
        )

    request_headers = dict(headers or {})
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(url, headers=request_headers)
    except httpx.HTTPError as exc:
        return ActionResult(
            success=False,
            output={
                "tool_id": "http-request",
                "status": "error",
                "url": url,
                "host": host,
                "port": port,
                "path": path,
            },
            error=str(exc),
            terminal=False,
        )

    body = response.content[:_MAX_BODY_BYTES]
    try:
        text = body.decode(response.encoding or "utf-8", errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")

    return ActionResult(
        success=response.is_success,
        output={
            "tool_id": "http-request",
            "status": "executed",
            "url": url,
            "host": host,
            "port": port,
            "path": path,
            "method": "GET",
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "body": text,
            "truncated": len(response.content) > _MAX_BODY_BYTES,
        },
        error=None if response.is_success else f"HTTP {response.status_code}",
        terminal=False,
    )
