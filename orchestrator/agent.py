"""Agent Orchestrator with observe/plan/act/reflect execution cycle.

Implements the core OPAR loop for autonomous offensive security testing.
The orchestrator coordinates target observation, LLM-driven planning, tool
execution, ground-truth telemetry emission, and reflective evaluation.

Includes safety controls:
- Allowlist verification before each execution cycle (Req 4.2, 4.3, 11.1)
- Rate limiter integration in act phase (Req 11.3, 11.4)
- Max actions validation and enforcement (Req 4.6)
- Failure handling with needs_review emission (Req 4.8)
- Capability checking against active profile (Req 6.4, 6.6, 6.7)
- Boundary violation detection stub (Req 11.5)

Requirements: 4.1, 4.2, 4.3, 4.5, 4.6, 4.7, 4.8, 6.4, 6.6, 6.7, 11.1, 11.5, 12.2, 12.3
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.allowlist import AllowlistEntry, AllowlistError, verify_allowlist
from orchestrator.ground_truth import GroundTruthEmitter
from orchestrator.interfaces import (
    ActionResult,
    ActionSpec,
    GroundTruthLabel,
    GroundTruthRecord,
    ReflectSummary,
    TargetState,
)
from orchestrator.llm.interface import LLMBackend
from orchestrator.rate_limiter import RateLimiter
from orchestrator.tool_registry import ToolRegistry
from orchestrator.traffic_labeling import TrafficLabeler

logger = logging.getLogger(__name__)

# Configurable max actions range
_MIN_MAX_ACTIONS = 1
_MAX_MAX_ACTIONS = 1000


class TargetUnreachableError(Exception):
    """Raised when a target fails the TCP reachability check.

    Attributes:
        target: The host that could not be reached.
        port: The port that was attempted.
        timeout: The timeout duration in seconds.
        reason: Human-readable description of the failure.
    """

    def __init__(self, target: str, port: int, timeout: float, reason: str) -> None:
        self.target = target
        self.port = port
        self.timeout = timeout
        self.reason = reason
        super().__init__(
            f"Target unreachable: {target}:{port} (timeout={timeout}s) - {reason}"
        )


@dataclass
class ScenarioConfig:
    """Configuration for a single agent scenario execution.

    Attributes:
        target: Target host identifier (must be in the approved allowlist).
        max_actions: Maximum number of actions before the loop halts (1-1000).
        scenario_id: UUID identifying this scenario definition.
        run_id: UUID identifying this particular execution run.
    """

    target: str
    max_actions: int = 100
    scenario_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ScenarioResult:
    """Result of a completed scenario execution.

    Attributes:
        scenario_id: UUID of the scenario that was executed.
        run_id: UUID of this execution run.
        total_actions: Number of actions executed before termination.
        termination_reason: Why the loop stopped ("completed", "limit-reached",
            "error", or "rate-limited").
        action_history: Full list of reflect summaries from the execution.
        error_detail: Optional error information if termination_reason is "error".
    """

    scenario_id: str
    run_id: str
    total_actions: int
    termination_reason: str
    action_history: list[ReflectSummary]
    error_detail: str | None = None


class AgentOrchestrator:
    """Core observe/plan/act/reflect execution cycle.

    Coordinates the four-phase loop that drives autonomous offensive testing:
    1. Observe: produce a structured target-state snapshot
    2. Plan: select a technique and tool via LLM + Tool_Registry
    3. Act: execute the action, emit ground-truth record
    4. Reflect: evaluate result, append summary to action history

    Safety controls are integrated throughout:
    - Allowlist verification before each execution cycle
    - Rate limiter checks before each act phase
    - Capability matching before tool invocation
    - Failure handling with needs_review emission
    - Boundary violation detection after act phase

    Parameters
    ----------
    tool_registry : ToolRegistry
        Configuration-driven catalog of available offensive tools.
    llm_backend : LLMBackend
        LLM inference backend for planning decisions.
    ground_truth_emitter : GroundTruthEmitter
        Emitter for ground-truth telemetry records.
    allowlist_path : Path
        Path to the approved target allowlist JSON file.
    allowlist_hash : str
        Expected SHA-256 hash for allowlist integrity verification.
    rate_limiter : RateLimiter
        Token-bucket rate limiter controlling action throughput.
    active_capabilities : list[str]
        List of capabilities available in the active runtime profile.
        Tools requiring capabilities not in this list will be skipped.
    target_timeout : float
        Timeout in seconds for TCP target reachability checks (default 5.0).
    traffic_labeler : TrafficLabeler | None
        Optional TrafficLabeler instance for producing HTTP headers and
        environment variables that label attack traffic for SOC filtering.
        If None, a default TrafficLabeler is created.
    scenario_label : str
        Descriptive label for the scenario (e.g., "sqli-juice-shop").
        Passed to tool invocations via ATHENA_SCENARIO_LABEL env var.
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        llm_backend: LLMBackend,
        ground_truth_emitter: GroundTruthEmitter,
        allowlist_path: Path,
        allowlist_hash: str,
        rate_limiter: RateLimiter,
        active_capabilities: list[str] | None = None,
        target_timeout: float = 5.0,
        traffic_labeler: TrafficLabeler | None = None,
        scenario_label: str = "",
    ) -> None:
        self.tool_registry = tool_registry
        self.llm_backend = llm_backend
        self.ground_truth_emitter = ground_truth_emitter
        self.allowlist_path = allowlist_path
        self.allowlist_hash = allowlist_hash
        self.rate_limiter = rate_limiter
        self.active_capabilities: list[str] = active_capabilities or []
        self.target_timeout = target_timeout
        self.traffic_labeler = traffic_labeler or TrafficLabeler()
        self.scenario_label = scenario_label
        self.action_history: list[ReflectSummary] = []
        self._allowlist: list[AllowlistEntry] = []

    def verify_allowlist_integrity(self) -> None:
        """Verify the allowlist file integrity via SHA-256 hash comparison.

        Raises
        ------
        AllowlistError
            If the allowlist is missing, unreadable, or fails hash verification.
        """
        self._allowlist = verify_allowlist(self.allowlist_path, self.allowlist_hash)
        logger.info(
            "Allowlist verified: %d entries loaded from %s",
            len(self._allowlist),
            self.allowlist_path,
        )

    def validate_target(self, target: str) -> None:
        """Validate that the target is present in the verified allowlist.

        Args:
            target: The target host identifier to validate.

        Raises:
            AllowlistError: If the target is not in the allowlist.
        """
        for entry in self._allowlist:
            if entry.host == target:
                return
        raise AllowlistError(f"Target not in allowlist: {target}")

    def _get_target_port(self, target: str) -> int:
        """Get the first port from the allowlist entry for the target.

        Finds the matching allowlist entry and returns the start of the
        port range as the default connection port. This is used for
        reachability verification.

        Args:
            target: The target host identifier.

        Returns:
            The start port from the target's allowlist entry.

        Raises:
            AllowlistError: If the target is not in the allowlist.
        """
        for entry in self._allowlist:
            if entry.host == target:
                return entry.port_range[0]
        raise AllowlistError(f"Target not in allowlist: {target}")

    async def verify_target_reachable(self, host: str, port: int) -> bool:
        """Verify that the target is reachable via TCP connection.

        Attempts a TCP connection to the specified host and port within
        the configured timeout. This is called before starting a scenario
        to ensure the target is available.

        Args:
            host: The target hostname or IP address.
            port: The target port number.

        Returns:
            True if the target is reachable.

        Raises:
            TargetUnreachableError: If the connection fails due to timeout,
                connection refused, DNS failure, or other network errors.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.target_timeout,
            )
            writer.close()
            await writer.wait_closed()
            logger.info(
                "Target reachable: %s:%d (timeout=%.1fs)",
                host,
                port,
                self.target_timeout,
            )
            return True
        except asyncio.TimeoutError:
            reason = "Connection timed out"
            logger.error(
                "Target unreachable: %s:%d (timeout=%.1fs) - %s",
                host,
                port,
                self.target_timeout,
                reason,
            )
            raise TargetUnreachableError(host, port, self.target_timeout, reason)
        except OSError as exc:
            reason = str(exc)
            logger.error(
                "Target unreachable: %s:%d (timeout=%.1fs) - %s",
                host,
                port,
                self.target_timeout,
                reason,
            )
            raise TargetUnreachableError(host, port, self.target_timeout, reason)

    def _validate_max_actions(self, max_actions: int) -> None:
        """Validate that max_actions is within allowed range [1, 1000].

        Args:
            max_actions: The configured maximum actions per scenario.

        Raises:
            ValueError: If max_actions is outside the allowed range.
        """
        if max_actions < _MIN_MAX_ACTIONS or max_actions > _MAX_MAX_ACTIONS:
            raise ValueError(
                f"max_actions must be between {_MIN_MAX_ACTIONS} and "
                f"{_MAX_MAX_ACTIONS}, got {max_actions}"
            )

    def _check_capabilities(self, action_spec: ActionSpec) -> bool:
        """Check if the tool's required capabilities are satisfied.

        Compares the tool's required_capabilities against the active
        runtime profile capabilities. If any required capability is
        missing, the tool invocation should be skipped.

        Args:
            action_spec: The action specification containing the tool_id.

        Returns:
            True if all required capabilities are met, False otherwise.
        """
        tool_entry = self.tool_registry.get_tool(action_spec.tool_id)
        if tool_entry is None:
            # Tool not in registry — will be handled by act phase
            logger.warning(
                "Tool '%s' not found in registry during capability check",
                action_spec.tool_id,
            )
            return True  # Let act handle the missing tool case

        required = tool_entry.required_capabilities
        if not required:
            return True  # No capabilities required

        missing = [cap for cap in required if cap not in self.active_capabilities]
        if missing:
            logger.warning(
                "Capability mismatch for tool '%s': required %s, active %s, missing %s",
                action_spec.tool_id,
                required,
                self.active_capabilities,
                missing,
            )
            return False
        return True

    def _check_boundary_violation(self, result: ActionResult) -> bool:
        """Check if the action result indicates a boundary violation.

        Detects if a response appears to originate from an unexpected
        source not in the verified allowlist. This is a stub for future
        full implementation that will inspect response metadata.

        Args:
            result: The action result to inspect.

        Returns:
            True if a boundary violation is detected, False otherwise.
        """
        # Stub: check if the result output contains a boundary_violation flag
        # In production, this will inspect IP addresses, hostnames, etc.
        if result.output.get("boundary_violation"):
            logger.critical(
                "Boundary violation detected: response from unexpected source"
            )
            return True
        return False

    async def observe(self, target: str) -> TargetState:
        """Produce a structured target-state snapshot.

        For now, returns a minimal stub with the target and empty services.
        Future implementations will perform actual reconnaissance.

        Args:
            target: The target host to observe.

        Returns:
            A TargetState snapshot of the target.
        """
        return TargetState(
            target=target,
            open_ports=[],
            services=[],
            timestamp=datetime.now(timezone.utc),
        )

    async def plan(self, state: TargetState, history: list[ReflectSummary]) -> ActionSpec:
        """Select a technique and tool via LLM and Tool_Registry.

        For now, returns a stub ActionSpec. Future implementations will
        use the LLM backend to reason about available tools and decide
        the next action based on target state and action history.

        Args:
            state: Current target state from the observe phase.
            history: Action history from previous reflect phases.

        Returns:
            An ActionSpec describing the planned action.
        """
        # Stub: in production, this will call the LLM to select a tool
        # and construct arguments based on the current state and history.
        available_tools = self.tool_registry.list_tools()
        tool_id = available_tools[0] if available_tools else "noop"

        return ActionSpec(
            tool_id=tool_id,
            arguments={},
            technique=None,
            rationale="Stub plan - LLM integration pending",
        )

    async def act(self, action_spec: ActionSpec) -> ActionResult:
        """Execute the planned action using the tool from the registry.

        Before invoking the tool, the traffic labeler produces HTTP headers
        and environment variables that label this action's traffic for SOC
        dashboard filtering. For HTTP-based tools, the X-Athena-Scenario-Id
        header is included in requests. For all tools, ATHENA_SCENARIO_ID
        and ATHENA_SCENARIO_LABEL environment variables are set.

        Args:
            action_spec: The action specification from the plan phase.

        Returns:
            An ActionResult describing the execution outcome.
        """
        # Prepare traffic labeling metadata (Req 10.2, 10.4)
        scenario_id = self._current_scenario_id
        label = self.scenario_label or f"scenario-{scenario_id}"

        http_headers = self.traffic_labeler.get_http_headers(scenario_id)
        env_vars = self.traffic_labeler.get_env_vars(scenario_id, label)

        # Store for use by tool invocation infrastructure when fully wired
        self._current_http_headers = http_headers
        self._current_env_vars = env_vars

        # Stub: in production, this will invoke the tool and capture output,
        # passing http_headers for HTTP-based tools and env_vars for all tools.
        return ActionResult(
            success=True,
            output={"tool_id": action_spec.tool_id, "status": "stub_executed"},
            error=None,
            terminal=False,
        )

    async def reflect(self, action_spec: ActionSpec, result: ActionResult) -> ReflectSummary:
        """Evaluate the action result and produce a reflect summary.

        For now, produces a basic summary. Future implementations will use
        the LLM to evaluate the result in context.

        Args:
            action_spec: The action that was executed.
            result: The result of the execution.

        Returns:
            A ReflectSummary for the action history.
        """
        evaluation = (
            f"Action '{action_spec.tool_id}' "
            f"{'succeeded' if result.success else 'failed'}"
        )
        return ReflectSummary(
            action_spec=action_spec,
            result=result,
            evaluation=evaluation,
            next_recommendation="Continue with next available technique",
        )

    def emit_ground_truth(
        self,
        action_spec: ActionSpec,
        result: ActionResult,
        label_override: GroundTruthLabel | None = None,
    ) -> None:
        """Create and emit a ground-truth telemetry record.

        Constructs a GroundTruthRecord from the action spec and result,
        then writes it via the configured emitter.

        Args:
            action_spec: The action that was executed.
            result: The result of the execution.
            label_override: Optional override for the label (e.g., needs_review).
        """
        label = label_override if label_override is not None else self._determine_label(result)
        record = GroundTruthRecord(
            scenario_id=self._current_scenario_id,
            run_id=self._current_run_id,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            target=self._current_target,
            payload_family="generic",
            technique=action_spec.technique,
            expected_result=action_spec.rationale,
            safety_boundary="lab-network-only",
            label=label,
            artifact_reference="",
        )
        self.ground_truth_emitter.emit(record)

    def _determine_label(self, result: ActionResult) -> GroundTruthLabel:
        """Determine the ground-truth label based on action result.

        Args:
            result: The action execution result.

        Returns:
            The appropriate GroundTruthLabel.
        """
        if not result.success:
            return GroundTruthLabel.FAILED_ATTACK
        if result.terminal:
            return GroundTruthLabel.SUCCESSFUL_SIMULATION
        return GroundTruthLabel.MALICIOUS

    def finalize_scenario(self, reason: str, error_detail: str | None = None) -> ScenarioResult:
        """Produce the final ScenarioResult after loop termination.

        Args:
            reason: The termination reason ("completed", "limit-reached",
                "error", or "rate-limited").
            error_detail: Optional error information for error terminations.

        Returns:
            A ScenarioResult summarizing the execution.
        """
        return ScenarioResult(
            scenario_id=self._current_scenario_id,
            run_id=self._current_run_id,
            total_actions=len(self.action_history),
            termination_reason=reason,
            action_history=list(self.action_history),
            error_detail=error_detail,
        )

    async def run_scenario(self, scenario: ScenarioConfig) -> ScenarioResult:
        """Execute the full observe/plan/act/reflect loop for a scenario.

        This is the main entry point for running a scenario. It validates
        max_actions, verifies the allowlist, validates the target, verifies
        target reachability via TCP, then iterates through the OPAR cycle
        with integrated safety controls:
        - Target reachability check before loop start
        - Rate limiter checked before each act phase
        - Capability matching before tool invocation
        - Failure handling with needs_review emission
        - Boundary violation detection after act phase

        Args:
            scenario: Configuration for the scenario to execute.

        Returns:
            A ScenarioResult summarizing the full execution.

        Raises:
            AllowlistError: If the allowlist fails verification or the
                target is not approved.
            ValueError: If max_actions is outside the allowed range [1, 1000].
        """
        # Validate max_actions range (Req 4.6)
        self._validate_max_actions(scenario.max_actions)

        # Store scenario context for use in emit_ground_truth
        self._current_scenario_id = scenario.scenario_id
        self._current_run_id = scenario.run_id
        self._current_target = scenario.target

        # Reset action history for this scenario
        self.action_history = []

        # Pre-execution checks (Req 4.2, 4.3, 11.1)
        self.verify_allowlist_integrity()
        self.validate_target(scenario.target)

        # Target reachability check (Req 12.2, 12.3)
        target_port = self._get_target_port(scenario.target)
        try:
            await self.verify_target_reachable(scenario.target, target_port)
        except TargetUnreachableError as exc:
            logger.error(
                "Scenario '%s' refused: target '%s' unreachable on port %d "
                "(timeout=%.1fs) - %s",
                scenario.scenario_id,
                scenario.target,
                exc.port,
                exc.timeout,
                exc.reason,
            )
            # Emit a needs_review ground-truth record for unreachable target
            unreachable_spec = ActionSpec(
                tool_id="target-reachability-check",
                arguments={"host": scenario.target, "port": target_port},
                technique=None,
                rationale=f"Pre-scenario reachability check failed: {exc.reason}",
            )
            unreachable_result = ActionResult(
                success=False,
                output={
                    "error": "target_unreachable",
                    "host": scenario.target,
                    "port": target_port,
                    "timeout": self.target_timeout,
                    "reason": exc.reason,
                },
                error=str(exc),
                terminal=True,
            )
            self.emit_ground_truth(
                unreachable_spec,
                unreachable_result,
                label_override=GroundTruthLabel.NEEDS_REVIEW,
            )
            return self.finalize_scenario(
                reason="error",
                error_detail=str(exc),
            )

        action_count = 0
        action_spec: ActionSpec | None = None

        while action_count < scenario.max_actions:
            try:
                # Phase 1: Observe
                state = await self.observe(scenario.target)

                # Phase 2: Plan
                action_spec = await self.plan(state, self.action_history)

                # Capability check before act (Req 6.4, 6.6, 6.7)
                if not self._check_capabilities(action_spec):
                    # Skip tool — record the skip in action history
                    skip_result = ActionResult(
                        success=False,
                        output={
                            "tool_id": action_spec.tool_id,
                            "status": "skipped",
                            "reason": "capability_mismatch",
                        },
                        error="Capability mismatch: tool requires capabilities not in active profile",
                        terminal=False,
                    )
                    skip_summary = ReflectSummary(
                        action_spec=action_spec,
                        result=skip_result,
                        evaluation=(
                            f"Tool '{action_spec.tool_id}' skipped: "
                            f"capability mismatch with active profile"
                        ),
                        next_recommendation="Select a tool with matching capabilities",
                    )
                    self.action_history.append(skip_summary)
                    action_count += 1
                    continue

                # Rate limiter check before act (Req 11.3, 11.4)
                if not self.rate_limiter.acquire():
                    logger.warning(
                        "Rate limit exceeded during scenario '%s' at action %d",
                        scenario.scenario_id,
                        action_count,
                    )
                    return self.finalize_scenario(
                        reason="rate-limited",
                        error_detail="Rate limit exceeded; scenario halted",
                    )

                # Phase 3: Act
                result = await self.act(action_spec)

                # Boundary violation detection (Req 11.5)
                if self._check_boundary_violation(result):
                    logger.critical(
                        "Boundary violation in scenario '%s': halting immediately",
                        scenario.scenario_id,
                    )
                    # Emit needs_review record for the boundary violation
                    self.emit_ground_truth(
                        action_spec, result, label_override=GroundTruthLabel.NEEDS_REVIEW
                    )
                    return self.finalize_scenario(
                        reason="error",
                        error_detail="Boundary violation detected: response from unexpected source",
                    )

                self.emit_ground_truth(action_spec, result)
                action_count += 1

                # Phase 4: Reflect
                summary = await self.reflect(action_spec, result)
                self.action_history.append(summary)

                if result.terminal:
                    break

            except (RuntimeError, ConnectionError, TimeoutError, OSError) as exc:
                # Failure handling (Req 4.8): halt, log, emit needs_review
                phase = self._determine_failure_phase(action_spec)
                error_msg = f"{type(exc).__name__} in {phase}: {exc}"
                logger.error(
                    "Scenario '%s' failed at action %d (%s): %s",
                    scenario.scenario_id,
                    action_count,
                    phase,
                    exc,
                )

                # Emit needs_review ground-truth record
                failure_spec = (
                    action_spec
                    if action_spec is not None
                    else ActionSpec(
                        tool_id="unknown",
                        arguments={},
                        technique=None,
                        rationale=f"Failed during {phase}",
                    )
                )
                failure_result = ActionResult(
                    success=False,
                    output={"error": str(exc), "phase": phase},
                    error=str(exc),
                    terminal=True,
                )
                self.emit_ground_truth(
                    failure_spec,
                    failure_result,
                    label_override=GroundTruthLabel.NEEDS_REVIEW,
                )

                return self.finalize_scenario(
                    reason="error",
                    error_detail=error_msg,
                )

        return self.finalize_scenario(
            reason="limit-reached" if action_count >= scenario.max_actions else "completed"
        )

    @staticmethod
    def _determine_failure_phase(action_spec: ActionSpec | None) -> str:
        """Determine which phase likely failed based on available context.

        Args:
            action_spec: The current action spec, if planning completed.

        Returns:
            A string identifying the failure phase.
        """
        if action_spec is None:
            return "observe/plan"
        return "act"
