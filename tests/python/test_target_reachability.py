"""Tests for target reachability verification in AgentOrchestrator.

Validates:
- verify_target_reachable succeeds for a reachable target (Req 12.2)
- verify_target_reachable raises TargetUnreachableError for unreachable target (Req 12.3)
- run_scenario refuses and returns error result if target unreachable (Req 12.3)
- Configurable timeout parameter is respected (Req 12.2)
- A needs_review ground-truth record is emitted on unreachable target (Req 4.8)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestrator.agent import (
    AgentOrchestrator,
    ScenarioConfig,
    TargetUnreachableError,
)
from orchestrator.ground_truth import GroundTruthEmitter
from orchestrator.interfaces import GroundTruthLabel
from orchestrator.rate_limiter import RateLimiter
from orchestrator.tool_registry import ToolEntry, ToolRegistry


# --- Fixtures ---


def _create_allowlist_file(tmp_path: Path, host: str = "127.0.0.1", port_start: int = 1, port_end: int = 65535) -> tuple[Path, str]:
    """Create a valid allowlist file and return its path and hash."""
    allowlist_data = [
        {
            "host": host,
            "port_range": [port_start, port_end],
            "protocol": "tcp",
            "label": "test-target",
        }
    ]
    allowlist_path = tmp_path / "allowlist.json"
    content = json.dumps(allowlist_data).encode()
    allowlist_path.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()
    return allowlist_path, expected_hash


def _create_tool_registry() -> ToolRegistry:
    """Create a minimal ToolRegistry for testing."""
    tool_entry = ToolEntry(
        executable="/usr/bin/true",
        invocation="subprocess",
        required_capabilities=[],
        description="Test scanner",
        args={},
    )
    return ToolRegistry({"test-scanner": tool_entry})


def _create_mock_llm_backend() -> MagicMock:
    """Create a mock LLM backend."""
    backend = MagicMock()
    backend.generate = AsyncMock(return_value="stub response")
    backend.health_check = AsyncMock(return_value=True)
    backend.backend_id = "mock:test@localhost"
    return backend


@pytest.fixture
def reachability_deps(tmp_path: Path):
    """Provide dependencies for reachability tests using localhost."""
    allowlist_path, allowlist_hash = _create_allowlist_file(tmp_path, host="127.0.0.1")
    gt_output = tmp_path / "gt_output.jsonl"

    with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
        emitter = GroundTruthEmitter()

    return {
        "tool_registry": _create_tool_registry(),
        "llm_backend": _create_mock_llm_backend(),
        "ground_truth_emitter": emitter,
        "allowlist_path": allowlist_path,
        "allowlist_hash": allowlist_hash,
        "rate_limiter": RateLimiter(actions_per_minute=60),
        "gt_output_path": gt_output,
    }


# --- Tests: verify_target_reachable succeeds for reachable target ---


class TestTargetReachableSuccess:
    """Verify that verify_target_reachable succeeds for a reachable target."""

    async def test_reachable_target_returns_true(self, reachability_deps, tmp_path: Path) -> None:
        """verify_target_reachable returns True when a local TCP server is listening."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=5.0,
        )

        # Start a local TCP server
        server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]

        try:
            result = await orchestrator.verify_target_reachable("127.0.0.1", port)
            assert result is True
        finally:
            server.close()
            await server.wait_closed()

    async def test_reachable_with_custom_timeout(self, reachability_deps) -> None:
        """verify_target_reachable works with a custom timeout value."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=10.0,
        )

        # Start a local TCP server
        server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]

        try:
            result = await orchestrator.verify_target_reachable("127.0.0.1", port)
            assert result is True
            assert orchestrator.target_timeout == 10.0
        finally:
            server.close()
            await server.wait_closed()


# --- Tests: verify_target_reachable raises for unreachable target ---


class TestTargetUnreachable:
    """Verify that verify_target_reachable raises for unreachable targets."""

    async def test_unreachable_port_raises_error(self, reachability_deps) -> None:
        """verify_target_reachable raises TargetUnreachableError for a closed port."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=2.0,
        )

        # Use a port that is almost certainly not listening
        # Bind then immediately close to get a known-closed port
        temp_server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        closed_port = temp_server.sockets[0].getsockname()[1]
        temp_server.close()
        await temp_server.wait_closed()

        with pytest.raises(TargetUnreachableError) as exc_info:
            await orchestrator.verify_target_reachable("127.0.0.1", closed_port)

        assert exc_info.value.target == "127.0.0.1"
        assert exc_info.value.port == closed_port
        assert exc_info.value.timeout == 2.0

    async def test_unreachable_host_raises_error(self, reachability_deps) -> None:
        """verify_target_reachable raises TargetUnreachableError for unresolvable host."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=2.0,
        )

        with pytest.raises(TargetUnreachableError) as exc_info:
            await orchestrator.verify_target_reachable(
                "nonexistent-host-that-does-not-resolve.invalid", 80
            )

        assert exc_info.value.target == "nonexistent-host-that-does-not-resolve.invalid"
        assert exc_info.value.port == 80
        assert exc_info.value.timeout == 2.0
        assert exc_info.value.reason != ""

    async def test_timeout_raises_error(self, reachability_deps) -> None:
        """verify_target_reachable raises TargetUnreachableError on timeout.

        Uses a very short timeout against a non-routable address to trigger timeout.
        """
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=0.001,  # Very short timeout
        )

        # Use a non-routable IP to ensure timeout (RFC 5737 TEST-NET-1)
        with pytest.raises(TargetUnreachableError) as exc_info:
            await orchestrator.verify_target_reachable("192.0.2.1", 80)

        assert exc_info.value.timeout == 0.001
        assert "timed out" in exc_info.value.reason.lower() or exc_info.value.reason != ""

    async def test_error_contains_target_and_timeout_info(self, reachability_deps) -> None:
        """TargetUnreachableError message contains target, port, and timeout."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=3.0,
        )

        # Bind then close to get a known-closed port
        temp_server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        closed_port = temp_server.sockets[0].getsockname()[1]
        temp_server.close()
        await temp_server.wait_closed()

        with pytest.raises(TargetUnreachableError) as exc_info:
            await orchestrator.verify_target_reachable("127.0.0.1", closed_port)

        error_str = str(exc_info.value)
        assert "127.0.0.1" in error_str
        assert str(closed_port) in error_str
        assert "3.0" in error_str


# --- Tests: run_scenario refuses when target unreachable ---


class TestRunScenarioTargetUnreachable:
    """Verify run_scenario refuses and returns error if target is unreachable."""

    async def test_run_scenario_returns_error_on_unreachable(
        self, reachability_deps, tmp_path: Path
    ) -> None:
        """run_scenario returns an error ScenarioResult when target is unreachable."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=2.0,
        )

        # Get a port that is definitely closed
        temp_server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        closed_port = temp_server.sockets[0].getsockname()[1]
        temp_server.close()
        await temp_server.wait_closed()

        # Override allowlist to use the closed port
        allowlist_data = [
            {
                "host": "127.0.0.1",
                "port_range": [closed_port, closed_port],
                "protocol": "tcp",
                "label": "closed-port-target",
            }
        ]
        allowlist_path = tmp_path / "allowlist_closed.json"
        content = json.dumps(allowlist_data).encode()
        allowlist_path.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()
        orchestrator.allowlist_path = allowlist_path
        orchestrator.allowlist_hash = expected_hash

        scenario = ScenarioConfig(
            target="127.0.0.1",
            max_actions=5,
            scenario_id="test-unreachable-scenario",
            run_id="test-unreachable-run",
        )

        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        assert result.total_actions == 0
        assert "unreachable" in result.error_detail.lower() or "Target unreachable" in result.error_detail

    async def test_run_scenario_emits_needs_review_on_unreachable(
        self, reachability_deps, tmp_path: Path
    ) -> None:
        """run_scenario emits a needs_review GT record when target is unreachable."""
        gt_output = tmp_path / "gt_unreachable.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=2.0,
        )

        # Get a port that is definitely closed
        temp_server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        closed_port = temp_server.sockets[0].getsockname()[1]
        temp_server.close()
        await temp_server.wait_closed()

        # Override allowlist to use the closed port
        allowlist_data = [
            {
                "host": "127.0.0.1",
                "port_range": [closed_port, closed_port],
                "protocol": "tcp",
                "label": "closed-port-target",
            }
        ]
        allowlist_path = tmp_path / "allowlist_closed2.json"
        content = json.dumps(allowlist_data).encode()
        allowlist_path.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()
        orchestrator.allowlist_path = allowlist_path
        orchestrator.allowlist_hash = expected_hash

        scenario = ScenarioConfig(
            target="127.0.0.1",
            max_actions=5,
            scenario_id="test-gt-unreachable",
            run_id="test-gt-unreachable-run",
        )

        await orchestrator.run_scenario(scenario)

        lines = gt_output.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["label"] == "needs_review"
        assert record["scenario_id"] == "test-gt-unreachable"
        assert record["target"] == "127.0.0.1"

    async def test_run_scenario_no_actions_executed_on_unreachable(
        self, reachability_deps, tmp_path: Path
    ) -> None:
        """run_scenario does not execute the OPAR loop if target is unreachable."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=2.0,
        )

        # Get a port that is definitely closed
        temp_server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        closed_port = temp_server.sockets[0].getsockname()[1]
        temp_server.close()
        await temp_server.wait_closed()

        # Override allowlist to use the closed port
        allowlist_data = [
            {
                "host": "127.0.0.1",
                "port_range": [closed_port, closed_port],
                "protocol": "tcp",
                "label": "closed-port-target",
            }
        ]
        allowlist_path = tmp_path / "allowlist_closed3.json"
        content = json.dumps(allowlist_data).encode()
        allowlist_path.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()
        orchestrator.allowlist_path = allowlist_path
        orchestrator.allowlist_hash = expected_hash

        scenario = ScenarioConfig(
            target="127.0.0.1",
            max_actions=5,
            scenario_id="test-no-opar",
            run_id="test-no-opar-run",
        )

        result = await orchestrator.run_scenario(scenario)

        # Action history should be empty — no OPAR loop executed
        assert result.action_history == []
        assert result.total_actions == 0

    async def test_run_scenario_succeeds_with_reachable_target(
        self, reachability_deps, tmp_path: Path
    ) -> None:
        """run_scenario proceeds normally when target is reachable."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=5.0,
        )

        # Start a local TCP server on a dynamic port
        server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]

        # Override allowlist to use our live port
        allowlist_data = [
            {
                "host": "127.0.0.1",
                "port_range": [port, port],
                "protocol": "tcp",
                "label": "live-target",
            }
        ]
        allowlist_path = tmp_path / "allowlist_live.json"
        content = json.dumps(allowlist_data).encode()
        allowlist_path.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()
        orchestrator.allowlist_path = allowlist_path
        orchestrator.allowlist_hash = expected_hash

        scenario = ScenarioConfig(
            target="127.0.0.1",
            max_actions=2,
            scenario_id="test-reachable-scenario",
            run_id="test-reachable-run",
        )

        try:
            result = await orchestrator.run_scenario(scenario)
            # Should proceed with the OPAR loop
            assert result.total_actions == 2
            assert result.termination_reason == "limit-reached"
        finally:
            server.close()
            await server.wait_closed()


# --- Tests: default timeout value ---


class TestTargetTimeoutDefault:
    """Verify the target_timeout parameter defaults and configuration."""

    def test_default_timeout_is_five_seconds(self, reachability_deps) -> None:
        """Default target_timeout is 5.0 seconds."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
        )
        assert orchestrator.target_timeout == 5.0

    def test_custom_timeout_is_stored(self, reachability_deps) -> None:
        """Custom target_timeout value is stored correctly."""
        orchestrator = AgentOrchestrator(
            tool_registry=reachability_deps["tool_registry"],
            llm_backend=reachability_deps["llm_backend"],
            ground_truth_emitter=reachability_deps["ground_truth_emitter"],
            allowlist_path=reachability_deps["allowlist_path"],
            allowlist_hash=reachability_deps["allowlist_hash"],
            rate_limiter=reachability_deps["rate_limiter"],
            target_timeout=15.0,
        )
        assert orchestrator.target_timeout == 15.0
