"""Tests for orchestrator.allowlist module.

Verifies allowlist loading, hash verification, JSON parsing, and target matching.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from orchestrator.allowlist import (
    AllowlistEntry,
    AllowlistError,
    is_target_allowed,
    verify_allowlist,
)


# --- Fixtures ---


SAMPLE_ALLOWLIST = [
    {
        "host": "juice-shop.lab.local",
        "port_range": [3000, 3000],
        "protocol": "http",
        "label": "juice-shop-lab",
    },
    {
        "host": "dvwa.lab.local",
        "port_range": [80, 443],
        "protocol": "http",
        "label": "dvwa-lab",
    },
]


@pytest.fixture
def allowlist_file(tmp_path: Path) -> tuple[Path, str]:
    """Create a valid allowlist file and return (path, expected_hash)."""
    content = json.dumps(SAMPLE_ALLOWLIST).encode()
    file_path = tmp_path / "allowlist.json"
    file_path.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()
    return file_path, expected_hash


# --- verify_allowlist tests ---


class TestVerifyAllowlist:
    """Tests for verify_allowlist function."""

    def test_successful_load_and_verify(self, allowlist_file: tuple[Path, str]) -> None:
        """Valid file with correct hash should return parsed entries."""
        path, expected_hash = allowlist_file
        entries = verify_allowlist(path, expected_hash)

        assert len(entries) == 2
        assert entries[0].host == "juice-shop.lab.local"
        assert entries[0].port_range == (3000, 3000)
        assert entries[0].protocol == "http"
        assert entries[0].label == "juice-shop-lab"
        assert entries[1].host == "dvwa.lab.local"
        assert entries[1].port_range == (80, 443)
        assert entries[1].protocol == "http"
        assert entries[1].label == "dvwa-lab"

    def test_hash_mismatch_raises_error(self, allowlist_file: tuple[Path, str]) -> None:
        """Incorrect expected hash should raise AllowlistError."""
        path, _ = allowlist_file
        wrong_hash = "0" * 64

        with pytest.raises(AllowlistError) as exc_info:
            verify_allowlist(path, wrong_hash)

        assert "integrity check failed" in exc_info.value.reason
        assert wrong_hash in exc_info.value.reason

    def test_file_not_found_raises_error(self, tmp_path: Path) -> None:
        """Missing file should raise AllowlistError."""
        missing = tmp_path / "nonexistent.json"

        with pytest.raises(AllowlistError) as exc_info:
            verify_allowlist(missing, "abc123")

        assert "not found" in exc_info.value.reason

    def test_invalid_json_raises_error(self, tmp_path: Path) -> None:
        """File with invalid JSON should raise AllowlistError."""
        file_path = tmp_path / "bad.json"
        content = b"not valid json {{"
        file_path.write_bytes(content)
        file_hash = hashlib.sha256(content).hexdigest()

        with pytest.raises(AllowlistError) as exc_info:
            verify_allowlist(file_path, file_hash)

        assert "Invalid JSON" in exc_info.value.reason

    def test_non_array_json_raises_error(self, tmp_path: Path) -> None:
        """JSON that isn't an array should raise AllowlistError."""
        file_path = tmp_path / "object.json"
        content = json.dumps({"not": "an array"}).encode()
        file_path.write_bytes(content)
        file_hash = hashlib.sha256(content).hexdigest()

        with pytest.raises(AllowlistError) as exc_info:
            verify_allowlist(file_path, file_hash)

        assert "must be a JSON array" in exc_info.value.reason

    def test_missing_fields_raises_error(self, tmp_path: Path) -> None:
        """Entry with missing required fields should raise AllowlistError."""
        file_path = tmp_path / "incomplete.json"
        content = json.dumps([{"host": "example.com"}]).encode()
        file_path.write_bytes(content)
        file_hash = hashlib.sha256(content).hexdigest()

        with pytest.raises(AllowlistError) as exc_info:
            verify_allowlist(file_path, file_hash)

        assert "invalid or missing fields" in exc_info.value.reason

    def test_empty_array_returns_empty_list(self, tmp_path: Path) -> None:
        """An empty JSON array is valid and returns an empty list."""
        file_path = tmp_path / "empty.json"
        content = json.dumps([]).encode()
        file_path.write_bytes(content)
        file_hash = hashlib.sha256(content).hexdigest()

        entries = verify_allowlist(file_path, file_hash)
        assert entries == []


# --- is_target_allowed tests ---


class TestIsTargetAllowed:
    """Tests for is_target_allowed function."""

    @pytest.fixture
    def sample_entries(self) -> list[AllowlistEntry]:
        return [
            AllowlistEntry(
                host="juice-shop.lab.local",
                port_range=(3000, 3000),
                protocol="http",
                label="juice-shop-lab",
            ),
            AllowlistEntry(
                host="dvwa.lab.local",
                port_range=(80, 443),
                protocol="http",
                label="dvwa-lab",
            ),
        ]

    def test_exact_match(self, sample_entries: list[AllowlistEntry]) -> None:
        """Target:port matching an entry exactly should return True."""
        assert is_target_allowed("juice-shop.lab.local", 3000, sample_entries) is True

    def test_port_in_range(self, sample_entries: list[AllowlistEntry]) -> None:
        """Port within the allowed range should return True."""
        assert is_target_allowed("dvwa.lab.local", 80, sample_entries) is True
        assert is_target_allowed("dvwa.lab.local", 200, sample_entries) is True
        assert is_target_allowed("dvwa.lab.local", 443, sample_entries) is True

    def test_port_outside_range(self, sample_entries: list[AllowlistEntry]) -> None:
        """Port outside the allowed range should return False."""
        assert is_target_allowed("dvwa.lab.local", 8080, sample_entries) is False
        assert is_target_allowed("juice-shop.lab.local", 3001, sample_entries) is False

    def test_unknown_host(self, sample_entries: list[AllowlistEntry]) -> None:
        """Unknown host should return False."""
        assert is_target_allowed("evil.attacker.com", 80, sample_entries) is False

    def test_empty_allowlist(self) -> None:
        """Empty allowlist should reject all targets."""
        assert is_target_allowed("juice-shop.lab.local", 3000, []) is False


# --- AllowlistError tests ---


class TestAllowlistError:
    """Tests for AllowlistError exception."""

    def test_reason_attribute(self) -> None:
        """Error should store the reason string."""
        err = AllowlistError("test failure reason")
        assert err.reason == "test failure reason"
        assert str(err) == "test failure reason"
