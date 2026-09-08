"""Directory brute-force against an allowlisted HTTP origin.

Gobuster/ffuf-style path discovery implemented in-process so every request
carries Athena traffic labels and stays under rate/wordlist clamps. Does not
shell out to gobuster/ffuf (no free-form flags).
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import httpx

from orchestrator.allowlist import AllowlistEntry, is_target_allowed
from orchestrator.interfaces import ActionResult
from orchestrator.tools.http_request import HttpProbeError, sanitize_path

_TOOL_ID = "dir-bruteforce"
_MAX_WORDLIST = 64
_MAX_CONCURRENCY = 8
_DEFAULT_CONCURRENCY = 4
_DEFAULT_TIMEOUT_S = 5.0
_INTERESTING_STATUSES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403})
_WORD_RE = re.compile(r"^[A-Za-z0-9._~\-]{1,64}$")

# Tiny lab wordlist (Juice Shop / Night Quire style). Prefer file override for larger lists.
_BUILTIN_WORDS = (
    "admin",
    "api",
    "assets",
    "backup",
    "config",
    "console",
    "ftp",
    "hidden",
    "login",
    "metrics",
    "rest",
    "robots.txt",
    "sitemap.xml",
    "vendor",
    "upload",
    "uploads",
    "swagger",
    "graphql",
    "health",
    "status",
    ".git",
    ".env",
    "wp-admin",
)


class DirBruteError(HttpProbeError):
    """Raised when dir-bruteforce arguments fail a safety check."""


def _normalize_word(raw: str) -> str | None:
    word = raw.strip().lstrip("/")
    if not word or word.startswith("#"):
        return None
    if ".." in word or "/" in word or "\\" in word:
        return None
    if not _WORD_RE.match(word):
        return None
    return word


def load_wordlist(
    wordlist_path: str | None,
    *,
    max_entries: int = _MAX_WORDLIST,
    extra_words: list[str] | None = None,
) -> list[str]:
    """Load and clamp a path wordlist (file, explicit words, or built-in).

    Priority: file → explicit ``extra_words`` only → built-in. File + extras
    merges (file first). Explicit words without a file replace the built-in list.
    """
    words: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        word = _normalize_word(raw)
        if word is None or word in seen:
            return
        seen.add(word)
        words.append(word)

    if wordlist_path:
        path = Path(wordlist_path)
        if not path.is_file():
            raise DirBruteError(f"wordlist not found: {wordlist_path}")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            add(line)
            if len(words) >= max_entries:
                break
        for raw in extra_words or []:
            add(str(raw))
            if len(words) >= max_entries:
                break
    elif extra_words:
        for raw in extra_words:
            add(str(raw))
            if len(words) >= max_entries:
                break
    else:
        for built_in in _BUILTIN_WORDS:
            add(built_in)
            if len(words) >= max_entries:
                break

    if not words:
        raise DirBruteError("wordlist is empty after sanitization")
    return words[:max_entries]


def resolve_origin(
    arguments: dict[str, Any],
    default_target: str,
    default_port: int,
    allowlist: list[AllowlistEntry],
) -> tuple[str, str, int]:
    """Resolve allowlisted http://host:port origin (no path)."""
    host = str(arguments.get("target") or default_target)
    port = int(arguments.get("port") or default_port)
    if not is_target_allowed(host, port, allowlist):
        raise DirBruteError(f"target not in allowlist: {host}:{port}")
    return f"http://{host}:{port}", host, port


async def run(
    arguments: dict[str, Any],
    *,
    default_target: str,
    default_port: int,
    allowlist: list[AllowlistEntry],
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> ActionResult:
    """GET wordlist paths under an allowlisted origin; return interesting hits."""
    try:
        origin, host, port = resolve_origin(
            arguments, default_target, default_port, allowlist
        )
        max_entries = int(arguments.get("max_entries") or _MAX_WORDLIST)
        max_entries = max(1, min(max_entries, _MAX_WORDLIST))
        concurrency = int(arguments.get("concurrency") or _DEFAULT_CONCURRENCY)
        concurrency = max(1, min(concurrency, _MAX_CONCURRENCY))
        wordlist_path = arguments.get("wordlist")
        extra = arguments.get("words")
        extra_words = list(extra) if isinstance(extra, list) else None
        words = load_wordlist(
            str(wordlist_path) if wordlist_path else None,
            max_entries=max_entries,
            extra_words=extra_words,
        )
        # Validate each path via shared sanitizer
        paths = [sanitize_path(f"/{w}") for w in words]
    except (DirBruteError, HttpProbeError, TypeError, ValueError) as exc:
        return ActionResult(
            success=False,
            output={
                "tool_id": _TOOL_ID,
                "status": "rejected",
                "reason": str(exc),
            },
            error=str(exc),
            terminal=False,
        )

    request_headers = dict(headers or {})
    request_headers.setdefault("User-Agent", "athena-agents/dir-bruteforce")
    sem = asyncio.Semaphore(concurrency)
    hits: list[dict[str, Any]] = []
    errors = 0

    async def probe_one(client: httpx.AsyncClient, path: str) -> None:
        nonlocal errors
        url = f"{origin}{path}"
        async with sem:
            try:
                response = await client.get(url, headers=request_headers)
            except httpx.HTTPError:
                errors += 1
                return
        if response.status_code in _INTERESTING_STATUSES:
            hits.append(
                {
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": response.headers.get("content-type", ""),
                }
            )

    try:
        async with httpx.AsyncClient(
            timeout=min(timeout, _DEFAULT_TIMEOUT_S),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            await asyncio.gather(*(probe_one(client, path) for path in paths))
    except httpx.HTTPError as exc:
        return ActionResult(
            success=False,
            output={
                "tool_id": _TOOL_ID,
                "status": "error",
                "host": host,
                "port": port,
                "origin": origin,
            },
            error=str(exc),
            terminal=False,
        )

    hits.sort(key=lambda row: row["path"])
    return ActionResult(
        success=True,
        output={
            "tool_id": _TOOL_ID,
            "status": "executed",
            "host": host,
            "port": port,
            "origin": origin,
            "probed": len(paths),
            "hits": hits,
            "hit_count": len(hits),
            "errors": errors,
            "concurrency": concurrency,
            "mode": "dir",
            "wrapper": "in-process-gobuster-style",
        },
        error=None,
        terminal=False,
    )
