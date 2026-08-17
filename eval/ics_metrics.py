"""ICS-specific evaluation metrics for the Athena eval harness.

Measures protocol coverage, register/ID coverage, and safety boundary
compliance for Modbus TCP and CAN Bus engagements.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BoundaryViolation:
    """A safety boundary violation recorded during an ICS engagement."""

    register_address: int
    attempted_value: int
    safe_min: int
    safe_max: int
    timestamp: str


@dataclass
class IcsCoverageReport:
    """ICS engagement coverage metrics."""

    function_codes_tested: set[int] = field(default_factory=set)
    function_code_coverage_pct: float = 0.0
    registers_accessed: set[int] = field(default_factory=set)
    register_coverage_pct: float = 0.0
    can_ids_exercised: set[int] = field(default_factory=set)
    can_id_coverage_pct: float = 0.0
    safety_boundary_compliance: float = 1.0  # 1.0 = 100% compliant
    boundary_violations: list[BoundaryViolation] = field(default_factory=list)


def compute_function_code_coverage(tested_codes: set[int], total_codes: int = 127) -> float:
    """Percentage of Modbus function codes that were tested."""
    if total_codes == 0:
        return 0.0
    return len(tested_codes) / total_codes


def compute_register_coverage(accessed_registers: set[int], address_space_size: int) -> float:
    """Percentage of target register address space that was explored."""
    if address_space_size == 0:
        return 0.0
    return len(accessed_registers) / address_space_size


def compute_can_id_coverage(exercised_ids: set[int], id_range: tuple[int, int]) -> float:
    """Percentage of CAN arbitration ID range that was exercised."""
    range_size = id_range[1] - id_range[0] + 1
    if range_size <= 0:
        return 0.0
    return len(exercised_ids) / range_size


def compute_safety_compliance(total_writes: int, violations: int) -> float:
    """Ratio of safe writes to total writes. 1.0 = no violations."""
    if total_writes == 0:
        return 1.0  # No writes = 100% compliant
    return (total_writes - violations) / total_writes


def generate_ics_report(
    function_codes_tested: set[int],
    registers_accessed: set[int],
    register_space_size: int,
    can_ids_exercised: set[int],
    can_id_range: tuple[int, int],
    total_writes: int,
    boundary_violations: list[BoundaryViolation],
) -> IcsCoverageReport:
    """Generate a complete ICS coverage report."""
    return IcsCoverageReport(
        function_codes_tested=function_codes_tested,
        function_code_coverage_pct=compute_function_code_coverage(function_codes_tested),
        registers_accessed=registers_accessed,
        register_coverage_pct=compute_register_coverage(registers_accessed, register_space_size),
        can_ids_exercised=can_ids_exercised,
        can_id_coverage_pct=compute_can_id_coverage(can_ids_exercised, can_id_range),
        safety_boundary_compliance=compute_safety_compliance(
            total_writes, len(boundary_violations)
        ),
        boundary_violations=boundary_violations,
    )
