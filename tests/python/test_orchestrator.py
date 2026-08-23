"""Tests for the AgentOrchestrator observe/plan/act/reflect loop.

Validates:
- Scenario runs the correct number of iterations when max_actions reached (Req 4.6)
- Action history grows with each iteration (Req 4.7)
- Ground-truth records are emitted (Req 4.5)
- Terminal result stops the loop early (Req 4.1)
- Rate limit rejection halts gracefully (Req 11.3, 11.4)
- Max actions outside 1-1000 raises ValueError (Req 4.6)
- Failure in act/plan/observe halts with needs_review (Req 4.8)
- Capability mismatch skips tool invocation (Req 6.4, 6.6, 6.7)
- Boundary violation detection halts immediately (Req 11.5)
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestrator.agent import AgentOrchestrator, ScenarioConfig, ScenarioResult
from orchestrator.ground_truth import GroundTruthEmitter
from orchestrator.interfaces import (
    ActionResult,
    ActionSpec,
    GroundTruthLabel,
    ReflectSummary,
)
from orchestrator.rate_limiter import RateLimiter
from orchestrator.tool_registry import ToolEntry, ToolRegistry


# --- Fixtures ---


@pytest.fixture(autouse=True)
def _mock_target_reachability():
    """Patch verify_target_reachable for all tests in this module.

    These tests don't test target reachability (see test_target_reachability.py).
    The target 'juice-shop.lab.local' doesn't resolve in the test environment.
    """
    with patch(
        "orchestrator.agent.AgentOrchestrator.verify_target_reachable",
        new_callable=AsyncMock,
        return_value=True,
    ):
        yield


def _create_allowlist_file(tmp_path: Path) -> tuple[Path, str]:
    """Create a valid allowlist file and return its path and hash."""
    allowlist_data = [
        {
            "host": "juice-shop.lab.local",
            "port_range": [1, 65535],
            "protocol": "http",
            "label": "juice-shop-lab",
        }
    ]
    allowlist_path = tmp_path / "allowlist.json"
    content = json.dumps(allowlist_data).encode()
    allowlist_path.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()
    return allowlist_path, expected_hash


def _create_mock_llm_backend() -> MagicMock:
    """Create a mock LLM backend satisfying the LLMBackend protocol."""
    backend = MagicMock()
    backend.generate = AsyncMock(return_value="stub response")
    backend.health_check = AsyncMock(return_value=True)
    backend.backend_id = "mock:test@localhost"
    return backend


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


def _create_tool_registry_with_capabilities() -> ToolRegistry:
    """Create a ToolRegistry with tools that require capabilities."""
    scanner = ToolEntry(
        executable="/usr/bin/true",
        invocation="subprocess",
        required_capabilities=[],
        description="Test scanner (no caps needed)",
        args={},
    )
    crafter = ToolEntry(
        executable="/usr/bin/true",
        invocation="subprocess",
        required_capabilities=["NET_RAW"],
        description="Packet crafter (needs NET_RAW)",
        args={},
    )
    exploit_tool = ToolEntry(
        executable="/usr/bin/true",
        invocation="subprocess",
        required_capabilities=["NET_RAW", "SYS_PTRACE"],
        description="Capability-gated test tool (needs NET_RAW + SYS_PTRACE)",
        args={},
    )
    return ToolRegistry({
        "test-scanner": scanner,
        "packet-crafter": crafter,
        "exploit-runner": exploit_tool,
    })


@pytest.fixture
def orchestrator_deps(tmp_path: Path):
    """Provide all dependencies needed to construct an AgentOrchestrator."""
    allowlist_path, allowlist_hash = _create_allowlist_file(tmp_path)
    gt_output = tmp_path / "gt_output.jsonl"

    # Patch env so GroundTruthEmitter writes to our temp file
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


@pytest.fixture
def orchestrator(orchestrator_deps) -> AgentOrchestrator:
    """Create an AgentOrchestrator instance with all dependencies wired."""
    return AgentOrchestrator(
        tool_registry=orchestrator_deps["tool_registry"],
        llm_backend=orchestrator_deps["llm_backend"],
        ground_truth_emitter=orchestrator_deps["ground_truth_emitter"],
        allowlist_path=orchestrator_deps["allowlist_path"],
        allowlist_hash=orchestrator_deps["allowlist_hash"],
        rate_limiter=orchestrator_deps["rate_limiter"],
    )


@pytest.fixture
def scenario() -> ScenarioConfig:
    """Create a basic ScenarioConfig targeting an allowed host."""
    return ScenarioConfig(
        target="juice-shop.lab.local",
        max_actions=5,
        scenario_id="test-scenario-001",
        run_id="test-run-001",
    )


# --- Tests: Iteration count ---


class TestScenarioIterationCount:
    """Verify the loop executes the correct number of iterations."""

    async def test_runs_max_actions_iterations(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Loop executes exactly max_actions iterations when no terminal result."""
        scenario.max_actions = 3
        result = await orchestrator.run_scenario(scenario)

        assert result.total_actions == 3
        assert result.termination_reason == "limit-reached"

    async def test_single_action_scenario(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Loop executes exactly 1 iteration when max_actions is 1."""
        scenario.max_actions = 1
        result = await orchestrator.run_scenario(scenario)

        assert result.total_actions == 1
        assert result.termination_reason == "limit-reached"

    async def test_scenario_result_contains_ids(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """ScenarioResult carries the correct scenario_id and run_id."""
        result = await orchestrator.run_scenario(scenario)

        assert result.scenario_id == "test-scenario-001"
        assert result.run_id == "test-run-001"


# --- Tests: Action history growth ---


class TestActionHistoryGrowth:
    """Verify action_history grows with each iteration."""

    async def test_history_grows_each_iteration(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Action history has one entry per iteration at completion."""
        scenario.max_actions = 4
        result = await orchestrator.run_scenario(scenario)

        assert len(result.action_history) == 4

    async def test_history_contains_reflect_summaries(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Each action history entry is a ReflectSummary."""
        scenario.max_actions = 2
        result = await orchestrator.run_scenario(scenario)

        for entry in result.action_history:
            assert isinstance(entry, ReflectSummary)
            assert entry.action_spec is not None
            assert entry.result is not None
            assert entry.evaluation != ""

    async def test_history_accessible_during_reflect(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """The orchestrator's action_history list is the same as in the result."""
        scenario.max_actions = 3
        result = await orchestrator.run_scenario(scenario)

        # The result's action_history is a copy of the in-memory history
        assert len(orchestrator.action_history) == 3
        assert orchestrator.action_history == result.action_history

    async def test_history_resets_between_scenarios(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Action history is reset at the start of each new scenario."""
        scenario.max_actions = 2
        await orchestrator.run_scenario(scenario)

        # Run again - history should be fresh
        scenario.max_actions = 3
        result = await orchestrator.run_scenario(scenario)

        assert len(result.action_history) == 3


# --- Tests: Ground-truth emission ---


class TestGroundTruthEmission:
    """Verify ground-truth records are emitted for each action."""

    async def test_emits_record_per_action(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """One ground-truth record is emitted per action iteration."""
        scenario.max_actions = 3
        await orchestrator.run_scenario(scenario)

        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        assert len(lines) == 3

    async def test_emitted_records_are_valid_json(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """Each emitted ground-truth record is valid parseable JSON."""
        scenario.max_actions = 2
        await orchestrator.run_scenario(scenario)

        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        for line in lines:
            record = json.loads(line)
            assert record["scenario_id"] == "test-scenario-001"
            assert record["run_id"] == "test-run-001"
            assert record["target"] == "juice-shop.lab.local"
            assert "label" in record
            assert "timestamp" in record

    async def test_emitted_records_have_correct_label(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """Non-terminal successful actions are labeled 'malicious'."""
        scenario.max_actions = 1
        await orchestrator.run_scenario(scenario)

        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        record = json.loads(lines[0])
        # Successful non-terminal act() is labeled 'malicious'
        assert record["label"] == "malicious"


# --- Tests: Terminal early stop ---


class TestTerminalEarlyStop:
    """Verify the loop stops early when a terminal result is produced."""

    async def test_terminal_result_stops_loop(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Loop terminates before max_actions when result.terminal is True."""
        scenario.max_actions = 10
        call_count = 0

        original_act = orchestrator.act

        async def terminal_on_third(action_spec: ActionSpec) -> ActionResult:
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                return ActionResult(
                    success=True,
                    output={"status": "terminal"},
                    error=None,
                    terminal=True,
                )
            return await original_act(action_spec)

        orchestrator.act = terminal_on_third  # type: ignore[assignment]

        result = await orchestrator.run_scenario(scenario)

        assert result.total_actions == 3
        assert result.termination_reason == "completed"

    async def test_terminal_on_first_action(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Loop stops after a single action if it's terminal."""
        scenario.max_actions = 10

        async def always_terminal(action_spec: ActionSpec) -> ActionResult:
            return ActionResult(
                success=True,
                output={"status": "terminal"},
                error=None,
                terminal=True,
            )

        orchestrator.act = always_terminal  # type: ignore[assignment]

        result = await orchestrator.run_scenario(scenario)

        assert result.total_actions == 1
        assert result.termination_reason == "completed"
        assert len(result.action_history) == 1

    async def test_terminal_emits_ground_truth(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """Ground-truth record is emitted even for a terminal action."""
        scenario.max_actions = 10

        async def always_terminal(action_spec: ActionSpec) -> ActionResult:
            return ActionResult(
                success=True,
                output={"status": "terminal"},
                error=None,
                terminal=True,
            )

        orchestrator.act = always_terminal  # type: ignore[assignment]

        await orchestrator.run_scenario(scenario)

        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        # Terminal + success = successful_simulation
        assert record["label"] == "successful_simulation"


# --- Tests: ScenarioConfig and ScenarioResult dataclasses ---


class TestDataclasses:
    """Verify ScenarioConfig and ScenarioResult dataclass behavior."""

    def test_scenario_config_defaults(self) -> None:
        """ScenarioConfig has sensible defaults."""
        config = ScenarioConfig(target="test-host")
        assert config.target == "test-host"
        assert config.max_actions == 100
        assert config.scenario_id != ""
        assert config.run_id != ""

    def test_scenario_config_custom_values(self) -> None:
        """ScenarioConfig accepts custom values."""
        config = ScenarioConfig(
            target="custom-target",
            max_actions=50,
            scenario_id="custom-scenario",
            run_id="custom-run",
        )
        assert config.target == "custom-target"
        assert config.max_actions == 50
        assert config.scenario_id == "custom-scenario"
        assert config.run_id == "custom-run"

    def test_scenario_result_fields(self) -> None:
        """ScenarioResult carries all expected fields."""
        result = ScenarioResult(
            scenario_id="s1",
            run_id="r1",
            total_actions=5,
            termination_reason="completed",
            action_history=[],
        )
        assert result.scenario_id == "s1"
        assert result.run_id == "r1"
        assert result.total_actions == 5
        assert result.termination_reason == "completed"
        assert result.action_history == []
        assert result.error_detail is None

    def test_scenario_result_with_error_detail(self) -> None:
        """ScenarioResult carries error_detail when set."""
        result = ScenarioResult(
            scenario_id="s1",
            run_id="r1",
            total_actions=2,
            termination_reason="error",
            action_history=[],
            error_detail="RuntimeError in act: connection refused",
        )
        assert result.termination_reason == "error"
        assert result.error_detail == "RuntimeError in act: connection refused"


# --- Tests: Rate limiter integration (Req 11.3, 11.4) ---


class TestRateLimiterIntegration:
    """Verify rate limiter halts the scenario gracefully."""

    async def test_rate_limit_rejection_halts_gracefully(
        self, orchestrator_deps, scenario: ScenarioConfig, tmp_path: Path
    ) -> None:
        """When rate limiter rejects, scenario halts with rate-limited reason."""
        # Create a rate limiter that's already exhausted
        exhausted_limiter = RateLimiter(actions_per_minute=1)
        # Consume the single token
        exhausted_limiter.acquire()

        gt_output = tmp_path / "gt_rate.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        orchestrator = AgentOrchestrator(
            tool_registry=orchestrator_deps["tool_registry"],
            llm_backend=orchestrator_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=orchestrator_deps["allowlist_path"],
            allowlist_hash=orchestrator_deps["allowlist_hash"],
            rate_limiter=exhausted_limiter,
        )

        scenario.max_actions = 5
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "rate-limited"
        assert result.total_actions == 0
        assert result.error_detail is not None
        assert "Rate limit" in result.error_detail

    async def test_rate_limit_halts_mid_scenario(
        self, orchestrator_deps, scenario: ScenarioConfig, tmp_path: Path
    ) -> None:
        """Rate limiter exhaustion after some actions halts the loop."""
        # Create a rate limiter with 2 tokens
        limited_limiter = RateLimiter(actions_per_minute=2)

        gt_output = tmp_path / "gt_rate2.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        orchestrator = AgentOrchestrator(
            tool_registry=orchestrator_deps["tool_registry"],
            llm_backend=orchestrator_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=orchestrator_deps["allowlist_path"],
            allowlist_hash=orchestrator_deps["allowlist_hash"],
            rate_limiter=limited_limiter,
        )

        scenario.max_actions = 10
        result = await orchestrator.run_scenario(scenario)

        # Should have executed 2 actions then been rate limited on the 3rd
        assert result.termination_reason == "rate-limited"
        assert result.total_actions == 2


# --- Tests: Max actions validation (Req 4.6) ---


class TestMaxActionsValidation:
    """Verify max_actions outside 1-1000 raises ValueError."""

    async def test_max_actions_zero_raises_value_error(
        self, orchestrator: AgentOrchestrator
    ) -> None:
        """max_actions=0 raises ValueError."""
        scenario = ScenarioConfig(
            target="juice-shop.lab.local",
            max_actions=0,
            scenario_id="test-s",
            run_id="test-r",
        )
        with pytest.raises(ValueError, match="max_actions must be between 1 and 1000"):
            await orchestrator.run_scenario(scenario)

    async def test_max_actions_negative_raises_value_error(
        self, orchestrator: AgentOrchestrator
    ) -> None:
        """Negative max_actions raises ValueError."""
        scenario = ScenarioConfig(
            target="juice-shop.lab.local",
            max_actions=-5,
            scenario_id="test-s",
            run_id="test-r",
        )
        with pytest.raises(ValueError, match="max_actions must be between 1 and 1000"):
            await orchestrator.run_scenario(scenario)

    async def test_max_actions_1001_raises_value_error(
        self, orchestrator: AgentOrchestrator
    ) -> None:
        """max_actions=1001 raises ValueError."""
        scenario = ScenarioConfig(
            target="juice-shop.lab.local",
            max_actions=1001,
            scenario_id="test-s",
            run_id="test-r",
        )
        with pytest.raises(ValueError, match="max_actions must be between 1 and 1000"):
            await orchestrator.run_scenario(scenario)

    async def test_max_actions_boundary_1_is_valid(
        self, orchestrator: AgentOrchestrator
    ) -> None:
        """max_actions=1 is accepted (lower boundary)."""
        scenario = ScenarioConfig(
            target="juice-shop.lab.local",
            max_actions=1,
            scenario_id="test-s",
            run_id="test-r",
        )
        result = await orchestrator.run_scenario(scenario)
        assert result.total_actions == 1

    async def test_max_actions_boundary_1000_is_valid(
        self, orchestrator_deps, tmp_path: Path
    ) -> None:
        """max_actions=1000 is accepted (upper boundary)."""
        gt_output = tmp_path / "gt_1000.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        # Use a mock rate limiter that always allows (we're testing max_actions
        # validation, not rate limiting here)
        mock_limiter = MagicMock(spec=RateLimiter)
        mock_limiter.acquire = MagicMock(return_value=True)

        orchestrator = AgentOrchestrator(
            tool_registry=orchestrator_deps["tool_registry"],
            llm_backend=orchestrator_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=orchestrator_deps["allowlist_path"],
            allowlist_hash=orchestrator_deps["allowlist_hash"],
            rate_limiter=mock_limiter,
        )

        scenario = ScenarioConfig(
            target="juice-shop.lab.local",
            max_actions=1000,
            scenario_id="test-s",
            run_id="test-r",
        )
        result = await orchestrator.run_scenario(scenario)
        assert result.total_actions == 1000
        assert result.termination_reason == "limit-reached"


# --- Tests: Failure handling (Req 4.8) ---


class TestFailureHandling:
    """Verify failures halt with needs_review and error termination."""

    async def test_runtime_error_in_act_halts_with_needs_review(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """RuntimeError in act phase halts scenario and emits needs_review."""

        async def failing_act(action_spec: ActionSpec) -> ActionResult:
            raise RuntimeError("LLM timeout: backend unresponsive")

        orchestrator.act = failing_act  # type: ignore[assignment]

        scenario.max_actions = 5
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        assert "RuntimeError" in result.error_detail
        assert "LLM timeout" in result.error_detail

        # Check needs_review GT record was emitted
        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        assert len(lines) >= 1
        record = json.loads(lines[-1])
        assert record["label"] == "needs_review"

    async def test_connection_error_in_observe_halts(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """ConnectionError in observe phase halts with needs_review."""

        async def failing_observe(target: str):
            raise ConnectionError("Target unreachable: juice-shop.lab.local")

        orchestrator.observe = failing_observe  # type: ignore[assignment]

        scenario.max_actions = 5
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        assert "ConnectionError" in result.error_detail
        assert result.total_actions == 0

        # Check needs_review record was emitted
        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        record = json.loads(lines[-1])
        assert record["label"] == "needs_review"

    async def test_timeout_error_in_plan_halts(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """TimeoutError in plan phase halts with needs_review."""

        async def failing_plan(state, history):
            raise TimeoutError("LLM backend timed out after 10s")

        orchestrator.plan = failing_plan  # type: ignore[assignment]

        scenario.max_actions = 5
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        assert "TimeoutError" in result.error_detail

    async def test_os_error_in_act_halts(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """OSError (tool execution error) in act halts with error."""

        async def failing_act(action_spec: ActionSpec) -> ActionResult:
            raise OSError("Tool binary not found: /usr/local/bin/athena-scanner")

        orchestrator.act = failing_act  # type: ignore[assignment]

        scenario.max_actions = 5
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        assert "OSError" in result.error_detail

    async def test_failure_after_successful_actions(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """Failure after some successful actions preserves action history."""
        call_count = 0
        original_act = orchestrator.act

        async def fail_on_third(action_spec: ActionSpec) -> ActionResult:
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                raise RuntimeError("Transient tool failure")
            return await original_act(action_spec)

        orchestrator.act = fail_on_third  # type: ignore[assignment]

        scenario.max_actions = 10
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        # Two successful actions before the failure
        assert result.total_actions == 2

        # GT records: 2 successful + 1 needs_review
        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        assert len(lines) == 3
        assert json.loads(lines[-1])["label"] == "needs_review"


# --- Tests: Capability checking (Req 6.4, 6.6, 6.7) ---


class TestCapabilityChecking:
    """Verify capability mismatch skips tool invocation."""

    async def test_capability_mismatch_skips_tool(
        self, orchestrator_deps, scenario: ScenarioConfig, tmp_path: Path
    ) -> None:
        """Tool with required capabilities not in active profile is skipped."""
        registry = _create_tool_registry_with_capabilities()

        gt_output = tmp_path / "gt_cap.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        # Active capabilities: empty — so NET_RAW tools should be skipped
        orchestrator = AgentOrchestrator(
            tool_registry=registry,
            llm_backend=orchestrator_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=orchestrator_deps["allowlist_path"],
            allowlist_hash=orchestrator_deps["allowlist_hash"],
            rate_limiter=RateLimiter(actions_per_minute=60),
            active_capabilities=[],
        )

        # Override plan to request the packet-crafter (requires NET_RAW)
        async def plan_crafter(state, history):
            return ActionSpec(
                tool_id="packet-crafter",
                arguments={},
                technique=None,
                rationale="Test crafter",
            )

        orchestrator.plan = plan_crafter  # type: ignore[assignment]

        scenario.max_actions = 3
        result = await orchestrator.run_scenario(scenario)

        # All actions should be skipped (capability mismatch)
        assert result.total_actions == 3
        for entry in result.action_history:
            assert "skipped" in entry.evaluation
            assert "capability mismatch" in entry.evaluation

    async def test_capability_match_allows_execution(
        self, orchestrator_deps, scenario: ScenarioConfig, tmp_path: Path
    ) -> None:
        """Tool executes normally when active capabilities satisfy requirements."""
        registry = _create_tool_registry_with_capabilities()

        gt_output = tmp_path / "gt_cap2.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        # Active capabilities include NET_RAW — crafter should be allowed
        orchestrator = AgentOrchestrator(
            tool_registry=registry,
            llm_backend=orchestrator_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=orchestrator_deps["allowlist_path"],
            allowlist_hash=orchestrator_deps["allowlist_hash"],
            rate_limiter=RateLimiter(actions_per_minute=60),
            active_capabilities=["NET_RAW"],
        )

        # Override plan to request the packet-crafter (requires NET_RAW)
        async def plan_crafter(state, history):
            return ActionSpec(
                tool_id="packet-crafter",
                arguments={},
                technique=None,
                rationale="Test crafter",
            )

        orchestrator.plan = plan_crafter  # type: ignore[assignment]

        scenario.max_actions = 2
        result = await orchestrator.run_scenario(scenario)

        # Actions should execute normally (not skipped)
        assert result.total_actions == 2
        assert result.termination_reason == "limit-reached"
        for entry in result.action_history:
            assert "skipped" not in entry.evaluation

    async def test_partial_capability_mismatch_skips(
        self, orchestrator_deps, scenario: ScenarioConfig, tmp_path: Path
    ) -> None:
        """Tool requiring multiple caps is skipped if only some are active."""
        registry = _create_tool_registry_with_capabilities()

        gt_output = tmp_path / "gt_cap3.jsonl"
        with patch.dict("os.environ", {"ATHENA_GT_OUTPUT": str(gt_output)}):
            emitter = GroundTruthEmitter()

        # Only NET_RAW active, but exploit-runner needs NET_RAW + SYS_PTRACE
        orchestrator = AgentOrchestrator(
            tool_registry=registry,
            llm_backend=orchestrator_deps["llm_backend"],
            ground_truth_emitter=emitter,
            allowlist_path=orchestrator_deps["allowlist_path"],
            allowlist_hash=orchestrator_deps["allowlist_hash"],
            rate_limiter=RateLimiter(actions_per_minute=60),
            active_capabilities=["NET_RAW"],
        )

        async def plan_exploit(state, history):
            return ActionSpec(
                tool_id="exploit-runner",
                arguments={},
                technique=None,
                rationale="Test exploit",
            )

        orchestrator.plan = plan_exploit  # type: ignore[assignment]

        scenario.max_actions = 1
        result = await orchestrator.run_scenario(scenario)

        assert result.total_actions == 1
        assert "skipped" in result.action_history[0].evaluation
        assert "capability mismatch" in result.action_history[0].evaluation

    async def test_no_capabilities_required_always_passes(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig
    ) -> None:
        """Tools with no required capabilities always pass the check."""
        # Default orchestrator has active_capabilities=[] but test-scanner
        # requires no capabilities, so it should pass
        scenario.max_actions = 2
        result = await orchestrator.run_scenario(scenario)

        assert result.total_actions == 2
        assert result.termination_reason == "limit-reached"
        for entry in result.action_history:
            assert "skipped" not in entry.evaluation


# --- Tests: Boundary violation detection (Req 11.5) ---


class TestBoundaryViolationDetection:
    """Verify boundary violation halts immediately."""

    async def test_boundary_violation_halts_immediately(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """Boundary violation in act result halts the scenario."""

        async def violation_act(action_spec: ActionSpec) -> ActionResult:
            return ActionResult(
                success=True,
                output={
                    "tool_id": action_spec.tool_id,
                    "status": "executed",
                    "boundary_violation": True,
                },
                error=None,
                terminal=False,
            )

        orchestrator.act = violation_act  # type: ignore[assignment]

        scenario.max_actions = 10
        result = await orchestrator.run_scenario(scenario)

        assert result.termination_reason == "error"
        assert "Boundary violation" in result.error_detail
        # Should have halted after first action
        assert result.total_actions == 0  # no actions completed before halt

    async def test_boundary_violation_emits_needs_review(
        self, orchestrator: AgentOrchestrator, scenario: ScenarioConfig, orchestrator_deps
    ) -> None:
        """Boundary violation emits a needs_review ground-truth record."""

        async def violation_act(action_spec: ActionSpec) -> ActionResult:
            return ActionResult(
                success=True,
                output={
                    "tool_id": action_spec.tool_id,
                    "boundary_violation": True,
                },
                error=None,
                terminal=False,
            )

        orchestrator.act = violation_act  # type: ignore[assignment]

        scenario.max_actions = 5
        await orchestrator.run_scenario(scenario)

        gt_output_path: Path = orchestrator_deps["gt_output_path"]
        lines = gt_output_path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["label"] == "needs_review"
