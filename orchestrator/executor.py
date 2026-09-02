"""Execute registered tools from the Act phase.

Subprocess tools receive ``--arg-name value`` flags. HTTP probes are handled
in-process and are GET-only. nmap is constrained to a connect scan of
allowlisted ports.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from orchestrator.allowlist import AllowlistEntry, is_target_allowed
from orchestrator.interfaces import ActionResult
from orchestrator.tool_registry import ToolEntry
from orchestrator.tools import http_request

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 30.0
_NMAP_ALLOWED_FLAGS = frozenset({"-sT", "-Pn"})


class ExecutionError(Exception):
    """Raised when a tool cannot be invoked."""


def build_argv(tool: ToolEntry, arguments: dict[str, Any]) -> list[str]:
    """Build a subprocess argv from a tool entry and validated arguments."""
    if not tool.executable:
        raise ExecutionError("tool has no executable")
    argv = [tool.executable]
    for name, value in arguments.items():
        if value is None:
            continue
        argv.append("--" + name.replace("_", "-"))
        if isinstance(value, (dict, list)):
            argv.append(json.dumps(value))
        else:
            argv.append(str(value))
    return argv


def clamp_port_range(
    start: int,
    end: int,
    allowlist: list[AllowlistEntry],
    host: str,
) -> tuple[int, int]:
    """Intersect a requested port range with the allowlist entry for host."""
    for entry in allowlist:
        if entry.host != host:
            continue
        lo, hi = entry.port_range
        clamped_start = max(start, lo)
        clamped_end = min(end, hi)
        if clamped_start <= clamped_end:
            return clamped_start, clamped_end
        return lo, lo
    raise ExecutionError(f"target not in allowlist: {host}")


def constrain_nmap_flags(raw_flags: str | None) -> list[str]:
    """Return the nmap flag list, dropping anything outside the allowlist."""
    tokens = (raw_flags or "-sT").split()
    kept = [token for token in tokens if token in _NMAP_ALLOWED_FLAGS]
    if "-sT" not in kept:
        kept.insert(0, "-sT")
    if "-Pn" not in kept:
        kept.append("-Pn")
    return kept


def build_nmap_argv(
    executable: str,
    host: str,
    port_start: int,
    port_end: int,
    raw_flags: str | None,
) -> list[str]:
    """Build a constrained nmap argv for an allowlisted host and port range."""
    if port_start == port_end:
        port_spec = str(port_start)
    else:
        port_spec = f"{port_start}-{port_end}"
    return [executable, *constrain_nmap_flags(raw_flags), "-p", port_spec, host]


def _decode_output(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


async def run_subprocess(
    argv: list[str],
    env: dict[str, str],
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> ActionResult:
    """Run a tool subprocess and capture stdout/stderr."""
    executable = argv[0]
    resolved = shutil.which(executable) if os.path.basename(executable) == executable else executable
    if resolved is None or not Path(resolved).exists():
        return ActionResult(
            success=False,
            output={"status": "error", "reason": "executable_not_found", "executable": executable},
            error=f"executable not found: {executable}",
            terminal=False,
        )
    argv = [resolved, *argv[1:]]

    merged_env = os.environ.copy()
    merged_env.update(env)
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=merged_env,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        return ActionResult(
            success=False,
            output={"status": "error", "reason": "timeout", "argv": argv},
            error=f"tool timed out after {timeout:.0f}s",
            terminal=False,
        )
    except OSError as exc:
        return ActionResult(
            success=False,
            output={"status": "error", "reason": "spawn_failed", "argv": argv},
            error=str(exc),
            terminal=False,
        )

    success = process.returncode == 0
    return ActionResult(
        success=success,
        output={
            "status": "executed",
            "argv": argv,
            "returncode": process.returncode,
            "stdout": _decode_output(stdout),
            "stderr": _decode_output(stderr),
        },
        error=None if success else (stderr.decode("utf-8", errors="replace").strip() or f"exit {process.returncode}"),
        terminal=False,
    )


async def execute_tool(
    tool_id: str,
    tool: ToolEntry,
    arguments: dict[str, Any],
    *,
    allowlist: list[AllowlistEntry],
    default_target: str,
    default_port: int,
    env: dict[str, str],
    headers: dict[str, str],
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> ActionResult:
    """Dispatch a validated action to the matching invocation path."""
    host = str(arguments.get("target") or default_target)
    if "target" in arguments or tool_id in {"nmap-scan", "http-request", "http-post-probe", "port-scanner"}:
        if not any(entry.host == host for entry in allowlist):
            return ActionResult(
                success=False,
                output={"tool_id": tool_id, "status": "rejected", "reason": "target_not_allowlisted"},
                error=f"target not in allowlist: {host}",
                terminal=False,
            )

    if tool_id == "http-request":
        result = await http_request.run(
            arguments,
            default_target=default_target,
            default_port=default_port,
            allowlist=allowlist,
            headers=headers,
            timeout=min(timeout, 10.0),
        )
        return result

    if tool_id == "http-post-probe":
        from orchestrator.tools import http_post_probe

        result = await http_post_probe.run(
            arguments,
            default_target=default_target,
            default_port=default_port,
            allowlist=allowlist,
            headers=headers,
            timeout=min(timeout, 10.0),
        )
        return result

    if tool_id == "nmap-scan":
        port_start = int(arguments.get("start_port") or default_port)
        port_end = int(arguments.get("end_port") or default_port)
        port_start, port_end = clamp_port_range(port_start, port_end, allowlist, host)
        if not is_target_allowed(host, port_start, allowlist):
            return ActionResult(
                success=False,
                output={"tool_id": tool_id, "status": "rejected", "reason": "port_not_allowlisted"},
                error=f"port not in allowlist: {host}:{port_start}",
                terminal=False,
            )
        executable = tool.executable or "nmap"
        argv = build_nmap_argv(
            executable,
            host,
            port_start,
            port_end,
            arguments.get("flags") if isinstance(arguments.get("flags"), str) else None,
        )
        result = await run_subprocess(argv, env, timeout=timeout)
        result.output["tool_id"] = tool_id
        return result

    if tool.invocation == "subprocess":
        start = arguments.get("start_port")
        end = arguments.get("end_port")
        if isinstance(start, int) and isinstance(end, int):
            arguments = dict(arguments)
            arguments["start_port"], arguments["end_port"] = clamp_port_range(
                start, end, allowlist, host
            )
        argv = build_argv(tool, arguments)
        result = await run_subprocess(argv, env, timeout=timeout)
        result.output["tool_id"] = tool_id
        return result

    return ActionResult(
        success=False,
        output={"tool_id": tool_id, "status": "unsupported", "invocation": tool.invocation},
        error=f"in-process tool '{tool_id}' is not wired",
        terminal=False,
    )
