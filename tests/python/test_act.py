"""Tests for the Act-phase executor and GET-only HTTP probe."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from orchestrator.agent import AgentOrchestrator
from orchestrator.allowlist import AllowlistEntry
from orchestrator.executor import (
    build_argv,
    build_nmap_argv,
    clamp_port_range,
    constrain_nmap_flags,
    execute_tool,
)
from orchestrator.ground_truth import GroundTruthEmitter
from orchestrator.interfaces import ActionSpec
from orchestrator.rate_limiter import RateLimiter
from orchestrator.tool_registry import ToolArg, ToolEntry, ToolRegistry
from orchestrator.tools.http_request import HttpProbeError, resolve_probe_url, sanitize_path


def _allowlist() -> list[AllowlistEntry]:
    return [
        AllowlistEntry(host="127.0.0.1", port_range=(3010, 3010), protocol="http", label="grimoire"),
    ]


def _http_tool() -> ToolEntry:
    return ToolEntry(
        module="orchestrator.tools.http_request",
        invocation="in-process",
        required_capabilities=[],
        description="GET probe",
        args={
            "target": ToolArg(type="string", required=True),
            "port": ToolArg(type="integer", required=True, min=1, max=65535),
            "path": ToolArg(type="string", required=False, default="/"),
            "url": ToolArg(type="string", required=False),
        },
    )


class TestArgvAndNmapConstraints:
    def test_build_argv_uses_long_flags(self) -> None:
        tool = ToolEntry(executable="/usr/bin/true", invocation="subprocess", args={})
        assert build_argv(tool, {"start_port": 3010, "target": "127.0.0.1"}) == [
            "/usr/bin/true",
            "--start-port",
            "3010",
            "--target",
            "127.0.0.1",
        ]

    def test_nmap_flags_drop_unknown_tokens(self) -> None:
        assert constrain_nmap_flags("-sS --script vuln -sT") == ["-sT", "-Pn"]

    def test_nmap_argv_uses_allowlisted_port(self) -> None:
        argv = build_nmap_argv("nmap", "127.0.0.1", 3010, 3010, "-sS")
        assert argv == ["nmap", "-sT", "-Pn", "-p", "3010", "127.0.0.1"]

    def test_port_range_clamps_to_allowlist(self) -> None:
        start, end = clamp_port_range(1, 65535, _allowlist(), "127.0.0.1")
        assert (start, end) == (3010, 3010)


class TestHttpProbeSafety:
    def test_sanitize_path_rejects_traversal(self) -> None:
        with pytest.raises(HttpProbeError):
            sanitize_path("/../../etc/passwd")

    def test_resolve_rejects_post(self) -> None:
        with pytest.raises(HttpProbeError, match="GET-only"):
            resolve_probe_url(
                {"method": "POST", "url": "http://127.0.0.1:3010/api/health"},
                "127.0.0.1",
                3010,
                _allowlist(),
            )

    def test_resolve_rejects_body(self) -> None:
        with pytest.raises(HttpProbeError, match="request body"):
            resolve_probe_url(
                {"url": "http://127.0.0.1:3010/api/health", "body": "{}"},
                "127.0.0.1",
                3010,
                _allowlist(),
            )

    def test_resolve_rejects_off_allowlist_host(self) -> None:
        with pytest.raises(HttpProbeError, match="not in allowlist"):
            resolve_probe_url(
                {"url": "http://example.com/"},
                "127.0.0.1",
                3010,
                _allowlist(),
            )

    def test_resolve_builds_url_from_target_port_path(self) -> None:
        url, host, port, path = resolve_probe_url(
            {"target": "127.0.0.1", "port": 3010, "path": "/api/health"},
            "127.0.0.1",
            3010,
            _allowlist(),
        )
        assert url == "http://127.0.0.1:3010/api/health"
        assert (host, port, path) == ("127.0.0.1", 3010, "/api/health")


class TestExecuteTool:
    async def test_http_request_executes_get(self) -> None:
        request = httpx.Request("GET", "http://127.0.0.1:3010/api/health")
        response = httpx.Response(200, text="ok", request=request)

        with patch("orchestrator.tools.http_request.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.get = AsyncMock(return_value=response)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=None)
            client_cls.return_value = client

            result = await execute_tool(
                "http-request",
                _http_tool(),
                {"target": "127.0.0.1", "port": 3010, "path": "/api/health"},
                allowlist=_allowlist(),
                default_target="127.0.0.1",
                default_port=3010,
                env={},
                headers={"X-Athena-Scenario-Id": "test"},
            )

        assert result.success is True
        assert result.output["status"] == "executed"
        assert result.output["status_code"] == 200
        assert result.output["body"] == "ok"
        client.get.assert_awaited()
        called_headers = client.get.await_args.kwargs["headers"]
        assert called_headers["X-Athena-Scenario-Id"] == "test"

    async def test_http_request_rejects_post(self) -> None:
        result = await execute_tool(
            "http-request",
            _http_tool(),
            {"url": "http://127.0.0.1:3010/api/health", "method": "POST"},
            allowlist=_allowlist(),
            default_target="127.0.0.1",
            default_port=3010,
            env={},
            headers={},
        )
        assert result.success is False
        assert result.output["status"] == "rejected"

    async def test_unknown_in_process_tool_is_not_invoked(self) -> None:
        tool = ToolEntry(
            module="orchestrator.tools.missing",
            invocation="in-process",
            args={},
        )
        result = await execute_tool(
            "scapy-craft",
            tool,
            {},
            allowlist=_allowlist(),
            default_target="127.0.0.1",
            default_port=3010,
            env={},
            headers={},
        )
        assert result.success is False
        assert result.output["status"] == "unsupported"

    async def test_subprocess_true_executes(self) -> None:
        tool = ToolEntry(executable="/usr/bin/true", invocation="subprocess", args={})
        result = await execute_tool(
            "test-scanner",
            tool,
            {},
            allowlist=_allowlist(),
            default_target="127.0.0.1",
            default_port=3010,
            env={},
            headers={},
        )
        assert result.success is True
        assert result.output["status"] == "executed"
        assert result.output["returncode"] == 0


def _create_allowlist_file(tmp_path: Path) -> tuple[Path, str]:
    data = [{"host": "127.0.0.1", "port_range": [3010, 3010], "protocol": "http", "label": "grimoire"}]
    path = tmp_path / "allowlist.json"
    content = json.dumps(data).encode()
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


class TestOrchestratorAct:
    def _orchestrator(self, tmp_path: Path) -> AgentOrchestrator:
        allowlist_path, allowlist_hash = _create_allowlist_file(tmp_path)
        registry = ToolRegistry({
            "http-request": _http_tool(),
            "test-scanner": ToolEntry(
                executable="/usr/bin/true",
                invocation="subprocess",
                args={},
            ),
        })
        backend = MagicMock()
        backend.generate = AsyncMock(return_value="stub response")
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(tmp_path / "gt.jsonl")}):
            emitter = GroundTruthEmitter()
        orch = AgentOrchestrator(
            tool_registry=registry,
            llm_backend=backend,
            ground_truth_emitter=emitter,
            allowlist_path=allowlist_path,
            allowlist_hash=allowlist_hash,
            rate_limiter=RateLimiter(actions_per_minute=60),
        )
        orch.verify_allowlist_integrity()
        orch._current_scenario_id = "s1"
        orch._current_run_id = "r1"
        orch._current_target = "127.0.0.1"
        return orch

    async def test_unknown_tool_is_rejected(self, tmp_path: Path) -> None:
        orch = self._orchestrator(tmp_path)
        result = await orch.act(ActionSpec(tool_id="login-user", arguments={}, technique=None, rationale="no"))
        assert result.success is False
        assert result.output["status"] == "rejected"
        assert result.output["reason"] == "unknown_tool"

    async def test_missing_required_args_are_rejected(self, tmp_path: Path) -> None:
        orch = self._orchestrator(tmp_path)
        registry = ToolRegistry({
            "port-scanner": ToolEntry(
                executable="/usr/bin/true",
                invocation="subprocess",
                args={
                    "target": ToolArg(type="string", required=True),
                    "start_port": ToolArg(type="integer", required=True, min=1, max=65535),
                    "end_port": ToolArg(type="integer", required=True, min=1, max=65535),
                    "seed": ToolArg(type="integer", required=True, min=0),
                },
            )
        })
        orch.tool_registry = registry
        result = await orch.act(
            ActionSpec(tool_id="port-scanner", arguments={}, technique=None, rationale="incomplete")
        )
        assert result.success is False
        assert result.output["reason"] == "invalid_arguments"

    async def test_act_fills_target_and_port_for_http(self, tmp_path: Path) -> None:
        orch = self._orchestrator(tmp_path)
        request = httpx.Request("GET", "http://127.0.0.1:3010/")
        response = httpx.Response(200, text="ok", request=request)

        with patch("orchestrator.tools.http_request.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.get = AsyncMock(return_value=response)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=None)
            client_cls.return_value = client
            result = await orch.act(
                ActionSpec(tool_id="http-request", arguments={}, technique=None, rationale="probe")
            )

        assert result.success is True
        assert result.output["status"] == "executed"
        assert result.output["url"] == "http://127.0.0.1:3010/"
        assert "stub_executed" not in result.output.values()


def _dir_brute_tool() -> ToolEntry:
    return ToolEntry(
        module="orchestrator.tools.dir_bruteforce",
        invocation="in-process",
        required_capabilities=[],
        description="dir brute",
        args={
            "target": ToolArg(type="string", required=True),
            "port": ToolArg(type="integer", required=True, min=1, max=65535),
            "wordlist": ToolArg(type="string", required=False),
            "concurrency": ToolArg(type="integer", required=False, default=4, min=1, max=8),
            "max_entries": ToolArg(type="integer", required=False, default=64, min=1, max=64),
        },
    )


class TestDirBruteforce:
    def test_load_wordlist_builtin_clamped(self) -> None:
        from orchestrator.tools.dir_bruteforce import load_wordlist

        words = load_wordlist(None, max_entries=5)
        assert len(words) == 5
        assert "admin" in words

    def test_load_wordlist_rejects_traversal_tokens(self, tmp_path: Path) -> None:
        from orchestrator.tools.dir_bruteforce import load_wordlist

        wl = tmp_path / "words.txt"
        wl.write_text("../etc\nadmin\nbad/path\napi\n", encoding="utf-8")
        words = load_wordlist(str(wl), max_entries=64)
        assert words == ["admin", "api"]

    def test_load_wordlist_missing_file(self) -> None:
        from orchestrator.tools.dir_bruteforce import DirBruteError, load_wordlist

        with pytest.raises(DirBruteError, match="not found"):
            load_wordlist("/no/such/wordlist.txt")

    async def test_execute_probes_and_reports_hits(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/admin":
                return httpx.Response(200, text="ok", request=request)
            if request.url.path == "/hidden":
                return httpx.Response(403, text="no", request=request)
            return httpx.Response(404, text="missing", request=request)

        transport = httpx.MockTransport(handler)
        real_client = httpx.AsyncClient(transport=transport, follow_redirects=False)

        with patch("orchestrator.tools.dir_bruteforce.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.get = real_client.get
            client.__aenter__ = AsyncMock(return_value=real_client)
            client.__aexit__ = AsyncMock(return_value=None)
            client_cls.return_value = client

            result = await execute_tool(
                "dir-bruteforce",
                _dir_brute_tool(),
                {
                    "target": "127.0.0.1",
                    "port": 3010,
                    "words": ["admin", "hidden", "missing"],
                    "max_entries": 8,
                    "concurrency": 2,
                },
                allowlist=_allowlist(),
                default_target="127.0.0.1",
                default_port=3010,
                env={},
                headers={"X-Athena-Scenario": "day23"},
            )
            await real_client.aclose()

        assert result.success is True
        assert result.output["status"] == "executed"
        assert result.output["probed"] == 3
        paths = {hit["path"] for hit in result.output["hits"]}
        assert paths == {"/admin", "/hidden"}

    async def test_rejects_off_allowlist(self) -> None:
        result = await execute_tool(
            "dir-bruteforce",
            _dir_brute_tool(),
            {"target": "8.8.8.8", "port": 80},
            allowlist=_allowlist(),
            default_target="127.0.0.1",
            default_port=3010,
            env={},
            headers={},
        )
        assert result.success is False
        assert result.output["status"] == "rejected"
