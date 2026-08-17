"""Unit tests for orchestrator/ics_safety.py."""

import tempfile
from pathlib import Path

import pytest

from orchestrator.ics_safety import (
    IcsConfigError,
    IcsTargetConfig,
    SafeRange,
    load_ics_target_config,
    validate_write_against_safe_range,
)


# ---------------------------------------------------------------------------
# validate_write_against_safe_range tests
# ---------------------------------------------------------------------------


class TestValidateWriteAgainstSafeRange:
    """Tests for validate_write_against_safe_range."""

    def test_value_within_range_allowed(self):
        ranges = [SafeRange(register_address=100, min_value=0, max_value=1000)]
        allowed, err = validate_write_against_safe_range(100, 500, ranges)
        assert allowed is True
        assert err is None

    def test_value_at_min_boundary_allowed(self):
        ranges = [SafeRange(register_address=100, min_value=10, max_value=500)]
        allowed, err = validate_write_against_safe_range(100, 10, ranges)
        assert allowed is True
        assert err is None

    def test_value_at_max_boundary_allowed(self):
        ranges = [SafeRange(register_address=100, min_value=10, max_value=500)]
        allowed, err = validate_write_against_safe_range(100, 500, ranges)
        assert allowed is True
        assert err is None

    def test_value_below_min_rejected(self):
        ranges = [SafeRange(register_address=100, min_value=10, max_value=500)]
        allowed, err = validate_write_against_safe_range(100, 9, ranges)
        assert allowed is False
        assert err is not None
        assert "safety boundary violation" in err
        assert "9" in err
        assert "100" in err

    def test_value_above_max_rejected(self):
        ranges = [SafeRange(register_address=100, min_value=10, max_value=500)]
        allowed, err = validate_write_against_safe_range(100, 501, ranges)
        assert allowed is False
        assert err is not None
        assert "501" in err

    def test_no_range_for_address_allows_any_value(self):
        ranges = [SafeRange(register_address=100, min_value=0, max_value=1000)]
        allowed, err = validate_write_against_safe_range(200, 65535, ranges)
        assert allowed is True
        assert err is None

    def test_empty_ranges_allows_any_value(self):
        allowed, err = validate_write_against_safe_range(100, 65535, [])
        assert allowed is True
        assert err is None

    def test_multiple_ranges_correct_range_applied(self):
        ranges = [
            SafeRange(register_address=100, min_value=0, max_value=1000),
            SafeRange(register_address=101, min_value=0, max_value=500),
            SafeRange(register_address=200, min_value=100, max_value=200),
        ]
        # Address 101: 500 should pass
        allowed, _ = validate_write_against_safe_range(101, 500, ranges)
        assert allowed is True

        # Address 101: 501 should fail
        allowed, err = validate_write_against_safe_range(101, 501, ranges)
        assert allowed is False
        assert err is not None

        # Address 200: 150 should pass
        allowed, _ = validate_write_against_safe_range(200, 150, ranges)
        assert allowed is True

        # Address 200: 99 should fail
        allowed, err = validate_write_against_safe_range(200, 99, ranges)
        assert allowed is False


# ---------------------------------------------------------------------------
# load_ics_target_config tests
# ---------------------------------------------------------------------------


class TestLoadIcsTargetConfig:
    """Tests for load_ics_target_config."""

    def _write_toml(self, content: str) -> Path:
        """Write a temporary TOML file and return its path."""
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        f.write(content)
        f.close()
        return Path(f.name)

    def test_load_valid_modbus_config(self):
        content = """\
[target]
id = "openplc"
host = "openplc.lab.local"
port = 502
protocol = "modbus-tcp"
ics_rate_limit = 10

[target.safe_ranges]
100 = [0, 1000]
101 = [0, 500]
"""
        path = self._write_toml(content)
        try:
            config = load_ics_target_config(path)
            assert config.target_id == "openplc"
            assert config.host == "openplc.lab.local"
            assert config.port == 502
            assert config.protocol == "modbus-tcp"
            assert config.ics_rate_limit == 10
            assert len(config.safe_ranges) == 2

            # Find the range for address 100
            r100 = next(r for r in config.safe_ranges if r.register_address == 100)
            assert r100.min_value == 0
            assert r100.max_value == 1000
        finally:
            path.unlink()

    def test_load_valid_canbus_config(self):
        content = """\
[target]
id = "vcan-lab"
host = ""
port = 0
protocol = "canbus"
ics_rate_limit = 10
"""
        path = self._write_toml(content)
        try:
            config = load_ics_target_config(path)
            assert config.target_id == "vcan-lab"
            assert config.protocol == "canbus"
            assert "CAN_INJECT" in config.capabilities_required
        finally:
            path.unlink()

    def test_load_missing_file_raises_error(self):
        path = Path("/nonexistent/path/target.toml")
        with pytest.raises(IcsConfigError, match="not found"):
            load_ics_target_config(path)

    def test_load_missing_target_section_raises_error(self):
        content = """\
[other]
key = "value"
"""
        path = self._write_toml(content)
        try:
            with pytest.raises(IcsConfigError, match="missing \\[target\\] section"):
                load_ics_target_config(path)
        finally:
            path.unlink()

    def test_load_missing_required_field_raises_error(self):
        content = """\
[target]
id = "test"
host = "localhost"
# missing port and protocol
"""
        path = self._write_toml(content)
        try:
            with pytest.raises(IcsConfigError, match="missing required field"):
                load_ics_target_config(path)
        finally:
            path.unlink()

    def test_load_invalid_protocol_raises_error(self):
        content = """\
[target]
id = "test"
host = "localhost"
port = 502
protocol = "invalid-protocol"
"""
        path = self._write_toml(content)
        try:
            with pytest.raises(IcsConfigError, match="invalid protocol"):
                load_ics_target_config(path)
        finally:
            path.unlink()

    def test_load_invalid_toml_raises_error(self):
        content = "this is not valid toml {{{"
        path = self._write_toml(content)
        try:
            with pytest.raises(IcsConfigError, match="failed to parse"):
                load_ics_target_config(path)
        finally:
            path.unlink()

    def test_default_rate_limit_when_not_specified(self):
        content = """\
[target]
id = "test"
host = "localhost"
port = 502
protocol = "modbus-tcp"
"""
        path = self._write_toml(content)
        try:
            config = load_ics_target_config(path)
            assert config.ics_rate_limit == 10
        finally:
            path.unlink()

    def test_no_safe_ranges_returns_empty_list(self):
        content = """\
[target]
id = "test"
host = "localhost"
port = 502
protocol = "modbus-tcp"
"""
        path = self._write_toml(content)
        try:
            config = load_ics_target_config(path)
            assert config.safe_ranges == []
        finally:
            path.unlink()
