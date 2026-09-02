"""Gated POST probe for lab auth endpoints (Night Quire login, etc.).

Only POST is allowed. Paths must match a fixed allowlist; bodies are JSON-only
with a size cap. Targets must pass the network allowlist.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from orchestrator.allowlist import AllowlistEntry, is_target_allowed
from orchestrator.interfaces import ActionResult
from orchestrator.tools.http_request import HttpProbeError, sanitize_path

_MAX_BODY_BYTES = 2048
_MAX_PATH_LEN = 256
_ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PATHS = (
    "/api/v1/auth/login",
    "/api/v1/auth/register",
)

_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/=?&%+\-]*$")


def _allowed_paths() -> frozenset[str]:
    raw = os.environ.get("ATHENA_POST_PROBE_PATHS", "")
    if raw.strip():
        return frozenset(p.strip() for p in raw.split(",") if p.strip())
    return frozenset(_DEFAULT_PATHS)


def resolve_post_url(
    arguments: dict[str, Any],
    default_target: str,
    default_port: int,
    allowlist: list[AllowlistEntry],
) -> tuple[str, str, int, str, dict[str, Any]]:
    """Resolve POST URL and JSON body after safety checks."""
    method = str(arguments.get("method") or "POST").upper()
    if method != "POST":
        raise HttpProbeError("http-post-probe is POST-only")

    body_raw = arguments.get("body")
    if body_raw is None:
        raise HttpProbeError("http-post-probe requires a JSON body")
    if isinstance(body_raw, str):
        if len(body_raw.encode("utf-8")) > _MAX_BODY_BYTES:
            raise HttpProbeError(f"body exceeds {_MAX_BODY_BYTES} bytes")
        try:
            body = json.loads(body_raw)
        except json.JSONDecodeError as exc:
            raise HttpProbeError(f"body must be valid JSON: {exc}") from exc
    elif isinstance(body_raw, dict):
        body = body_raw
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_BODY_BYTES:
            raise HttpProbeError(f"body exceeds {_MAX_BODY_BYTES} bytes")
    else:
        raise HttpProbeError("body must be a JSON object or string")

    raw_url = arguments.get("url")
    if raw_url:
        parsed = urlparse(str(raw_url))
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise HttpProbeError("url must use http or https")
        host = parsed.hostname
        if not host:
            raise HttpProbeError("url is missing a host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = sanitize_path(parsed.path or "/")
        url = f"{parsed.scheme}://{host}:{port}{path}"
    else:
        host = str(arguments.get("target") or default_target)
        port = int(arguments.get("port") or default_port)
        path = sanitize_path(str(arguments.get("path") or "/"))
        url = f"http://{host}:{port}{path}"

    path_only = path.split("?", 1)[0]
    if path_only not in _allowed_paths():
        raise HttpProbeError(f"path not in POST probe allowlist: {path_only}")

    if not is_target_allowed(host, port, allowlist):
        raise HttpProbeError(f"target not in allowlist: {host}:{port}")
    return url, host, port, path, body


async def run(
    arguments: dict[str, Any],
    *,
    default_target: str,
    default_port: int,
    allowlist: list[AllowlistEntry],
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> ActionResult:
    """POST JSON to an allowlisted auth path on an allowlisted target."""
    try:
        url, host, port, path, body = resolve_post_url(
            arguments, default_target, default_port, allowlist
        )
    except HttpProbeError as exc:
        return ActionResult(
            success=False,
            output={
                "tool_id": "http-post-probe",
                "status": "rejected",
                "reason": str(exc),
            },
            error=str(exc),
            terminal=False,
        )

    request_headers = {"Content-Type": "application/json", **dict(headers or {})}
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(url, headers=request_headers, json=body)
    except httpx.HTTPError as exc:
        return ActionResult(
            success=False,
            output={
                "tool_id": "http-post-probe",
                "status": "error",
                "url": url,
                "host": host,
                "port": port,
                "path": path,
            },
            error=str(exc),
            terminal=False,
        )

    text = response.text[:65_536]
    return ActionResult(
        success=response.is_success,
        output={
            "tool_id": "http-post-probe",
            "status": "executed",
            "url": url,
            "host": host,
            "port": port,
            "path": path,
            "method": "POST",
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "body": text,
        },
        error=None if response.is_success else f"HTTP {response.status_code}",
        terminal=False,
    )
