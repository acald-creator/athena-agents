"""Orchestrator interfaces and data models.

Defines the core dataclasses and enums used across the agent orchestrator:
- OPAR loop interfaces (TargetState, ActionSpec, ActionResult, ReflectSummary)
- Ground-truth telemetry schema (GroundTruthRecord, GroundTruthLabel)
- Supporting types (ServiceInfo)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


@dataclass
class ServiceInfo:
    """Describes a network service discovered on a target."""

    port: int
    name: str
    version: str | None = None


@dataclass
class TargetState:
    """Structured snapshot from the observe phase."""

    target: str
    open_ports: list[int]
    services: list[ServiceInfo]
    timestamp: datetime


@dataclass
class ActionSpec:
    """Output from the plan phase."""

    tool_id: str
    arguments: dict[str, Any]
    technique: str | None  # MITRE ATT&CK ID
    rationale: str


@dataclass
class ActionResult:
    """Output from the act phase."""

    success: bool
    output: dict[str, Any]
    error: str | None
    terminal: bool


@dataclass
class ReflectSummary:
    """Output from the reflect phase, appended to action history."""

    action_spec: ActionSpec
    result: ActionResult
    evaluation: str
    next_recommendation: str


class GroundTruthLabel(str, Enum):
    """Enumerated labels for ground-truth telemetry records."""

    MALICIOUS = "malicious"
    BENIGN_CONTROL = "benign_control"
    FAILED_ATTACK = "failed_attack"
    SUCCESSFUL_SIMULATION = "successful_simulation"
    NEEDS_REVIEW = "needs_review"


@dataclass
class GroundTruthRecord:
    """Structured ground-truth telemetry record.

    Each record captures labeled information about an offensive action
    executed by the agent orchestrator, enabling the eval harness to
    reconcile predictions against known-true attack labels.
    """

    scenario_id: str  # UUID identifying the scenario
    run_id: str  # UUID identifying this execution run
    timestamp: str  # ISO 8601 UTC (e.g., "2024-01-15T10:30:00.000Z")
    target: str  # Target identifier
    payload_family: str  # Category of payload (e.g., "sqli", "xss")
    technique: str | None  # MITRE ATT&CK ID or null
    expected_result: str  # What the attack should achieve
    safety_boundary: str  # Lab isolation context
    label: GroundTruthLabel  # Enum value
    artifact_reference: str  # Path or URI to related artifacts
