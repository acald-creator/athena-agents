"""Tests for eval/ics_metrics.py — ICS coverage and safety metrics."""

from eval.ics_metrics import (
    BoundaryViolation,
    IcsCoverageReport,
    compute_can_id_coverage,
    compute_function_code_coverage,
    compute_register_coverage,
    compute_safety_compliance,
    generate_ics_report,
)


class TestComputeFunctionCodeCoverage:
    """Tests for compute_function_code_coverage."""

    def test_known_data(self):
        """10 of 127 function codes = ~0.0787."""
        tested = set(range(1, 11))  # 10 codes
        result = compute_function_code_coverage(tested, total_codes=127)
        assert abs(result - 10 / 127) < 1e-9

    def test_full_coverage(self):
        """All 127 codes tested = 1.0."""
        tested = set(range(1, 128))
        result = compute_function_code_coverage(tested, total_codes=127)
        assert abs(result - 1.0) < 1e-9

    def test_zero_total_codes(self):
        """Zero total codes → 0.0 (no division by zero)."""
        result = compute_function_code_coverage({1, 2, 3}, total_codes=0)
        assert result == 0.0

    def test_empty_tested_set(self):
        """No codes tested → 0.0."""
        result = compute_function_code_coverage(set(), total_codes=127)
        assert result == 0.0


class TestComputeRegisterCoverage:
    """Tests for compute_register_coverage."""

    def test_known_data(self):
        """5 of 100 registers = 0.05."""
        accessed = {0, 10, 20, 30, 40}
        result = compute_register_coverage(accessed, address_space_size=100)
        assert abs(result - 0.05) < 1e-9

    def test_zero_address_space(self):
        """Zero space → 0.0 (no division by zero)."""
        result = compute_register_coverage({1, 2, 3}, address_space_size=0)
        assert result == 0.0

    def test_empty_accessed_set(self):
        """No registers accessed → 0.0."""
        result = compute_register_coverage(set(), address_space_size=1000)
        assert result == 0.0


class TestComputeCanIdCoverage:
    """Tests for compute_can_id_coverage."""

    def test_known_data(self):
        """100 IDs exercised in a range of 2048 (0–2047)."""
        exercised = set(range(100))
        result = compute_can_id_coverage(exercised, id_range=(0, 2047))
        assert abs(result - 100 / 2048) < 1e-9

    def test_full_coverage(self):
        """All IDs in range exercised = 1.0."""
        exercised = set(range(0, 2048))
        result = compute_can_id_coverage(exercised, id_range=(0, 2047))
        assert abs(result - 1.0) < 1e-9

    def test_inverted_range(self):
        """Inverted range (start > end) → 0.0."""
        result = compute_can_id_coverage({1, 2}, id_range=(100, 50))
        assert result == 0.0

    def test_zero_range(self):
        """Range of size 0 (end < start by 1) → 0.0."""
        result = compute_can_id_coverage({1}, id_range=(5, 3))
        assert result == 0.0


class TestComputeSafetyCompliance:
    """Tests for compute_safety_compliance."""

    def test_no_violations(self):
        """0 violations of 10 writes = 1.0."""
        result = compute_safety_compliance(total_writes=10, violations=0)
        assert result == 1.0

    def test_some_violations(self):
        """5 violations of 10 writes = 0.5."""
        result = compute_safety_compliance(total_writes=10, violations=5)
        assert abs(result - 0.5) < 1e-9

    def test_all_violations(self):
        """10 violations of 10 writes = 0.0."""
        result = compute_safety_compliance(total_writes=10, violations=10)
        assert result == 0.0

    def test_zero_writes(self):
        """0 total writes → 1.0 (100% compliant by default)."""
        result = compute_safety_compliance(total_writes=0, violations=0)
        assert result == 1.0


class TestGenerateIcsReport:
    """Tests for generate_ics_report end-to-end."""

    def test_produces_correct_values(self):
        """Integration: generate_ics_report computes all metrics correctly."""
        function_codes = {1, 3, 6, 16}
        registers = {0, 1, 2, 3, 4}
        can_ids = set(range(50))
        violations = [
            BoundaryViolation(
                register_address=100,
                attempted_value=9999,
                safe_min=0,
                safe_max=1000,
                timestamp="2024-01-15T10:00:00Z",
            ),
        ]

        report = generate_ics_report(
            function_codes_tested=function_codes,
            registers_accessed=registers,
            register_space_size=200,
            can_ids_exercised=can_ids,
            can_id_range=(0, 2047),
            total_writes=20,
            boundary_violations=violations,
        )

        assert isinstance(report, IcsCoverageReport)
        assert report.function_codes_tested == function_codes
        assert abs(report.function_code_coverage_pct - 4 / 127) < 1e-9
        assert report.registers_accessed == registers
        assert abs(report.register_coverage_pct - 5 / 200) < 1e-9
        assert report.can_ids_exercised == can_ids
        assert abs(report.can_id_coverage_pct - 50 / 2048) < 1e-9
        assert abs(report.safety_boundary_compliance - 19 / 20) < 1e-9
        assert len(report.boundary_violations) == 1
        assert report.boundary_violations[0].register_address == 100

    def test_empty_engagement(self):
        """Report with no activity produces defaults."""
        report = generate_ics_report(
            function_codes_tested=set(),
            registers_accessed=set(),
            register_space_size=100,
            can_ids_exercised=set(),
            can_id_range=(0, 2047),
            total_writes=0,
            boundary_violations=[],
        )

        assert report.function_code_coverage_pct == 0.0
        assert report.register_coverage_pct == 0.0
        assert report.can_id_coverage_pct == 0.0
        assert report.safety_boundary_compliance == 1.0
        assert report.boundary_violations == []
