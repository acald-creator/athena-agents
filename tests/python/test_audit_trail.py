"""Tests for orchestrator/audit_trail.py.

Validates:
- Entries are written as valid JSON Lines
- Each entry has all required fields
- Append-only behavior (new entries don't overwrite old)
- ISO-8601 timestamp format
- Status is "success" or "failure"

Requirements: 11.8
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

from orchestrator.audit_trail import AuditTrail, AuditTrailEntry


# --- AuditTrailEntry tests ---


class TestAuditTrailEntry:
    """Tests for AuditTrailEntry dataclass."""

    def test_valid_success_entry(self) -> None:
        """Entry with status='success' is valid."""
        entry = AuditTrailEntry(
            timestamp="2024-06-15T10:30:00.000Z",
            target="juice-shop.lab.local",
            action_type="scan",
            tool_id="port-scanner",
            status="success",
        )
        assert entry.status == "success"
        assert entry.detail is None

    def test_valid_failure_entry(self) -> None:
        """Entry with status='failure' is valid."""
        entry = AuditTrailEntry(
            timestamp="2024-06-15T10:30:00.000Z",
            target="dvwa.lab.local",
            action_type="fuzz",
            tool_id="protocol-fuzzer",
            status="failure",
            detail="Connection refused",
        )
        assert entry.status == "failure"
        assert entry.detail == "Connection refused"

    def test_invalid_status_raises(self) -> None:
        """Entry with invalid status raises ValueError."""
        with pytest.raises(ValueError, match="status must be 'success' or 'failure'"):
            AuditTrailEntry(
                timestamp="2024-06-15T10:30:00.000Z",
                target="target",
                action_type="scan",
                tool_id="tool",
                status="unknown",
            )

    def test_invalid_status_empty_string(self) -> None:
        """Empty string status raises ValueError."""
        with pytest.raises(ValueError):
            AuditTrailEntry(
                timestamp="2024-06-15T10:30:00.000Z",
                target="target",
                action_type="scan",
                tool_id="tool",
                status="",
            )


# --- AuditTrail tests ---


class TestAuditTrail:
    """Tests for AuditTrail class."""

    def test_entries_written_as_valid_json_lines(self, tmp_path: Path) -> None:
        """Each line in the audit trail is a valid JSON object."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="juice-shop", tool_id="port-scanner",
                action_type="scan", success=True,
            )
            trail.log_action(
                target="dvwa", tool_id="protocol-fuzzer",
                action_type="fuzz", success=False, detail="timeout",
            )

        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            record = json.loads(line)
            assert isinstance(record, dict)

    def test_each_entry_has_required_fields(self, tmp_path: Path) -> None:
        """Each entry contains timestamp, target, action_type, tool_id, status."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="target-host", tool_id="nmap-scan",
                action_type="recon", success=True,
            )

        lines = audit_file.read_text().strip().split("\n")
        record = json.loads(lines[0])
        required_fields = {"timestamp", "target", "action_type", "tool_id", "status"}
        assert required_fields.issubset(record.keys())

    def test_append_only_behavior(self, tmp_path: Path) -> None:
        """New entries don't overwrite existing entries."""
        audit_file = tmp_path / "audit.jsonl"

        # First write session
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="target-1", tool_id="tool-a",
                action_type="scan", success=True,
            )

        # Second write session (should append, not overwrite)
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="target-2", tool_id="tool-b",
                action_type="fuzz", success=False,
            )

        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 2
        first_record = json.loads(lines[0])
        second_record = json.loads(lines[1])
        assert first_record["target"] == "target-1"
        assert second_record["target"] == "target-2"

    def test_iso8601_timestamp_format(self, tmp_path: Path) -> None:
        """Timestamps are in ISO-8601 UTC format."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="host", tool_id="scanner",
                action_type="scan", success=True,
            )

        lines = audit_file.read_text().strip().split("\n")
        record = json.loads(lines[0])
        timestamp = record["timestamp"]
        # ISO 8601 with milliseconds and Z suffix
        iso_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
        assert re.match(iso_pattern, timestamp), f"Timestamp not ISO-8601: {timestamp}"

    def test_status_is_success_or_failure(self, tmp_path: Path) -> None:
        """Status field is constrained to 'success' or 'failure'."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="host", tool_id="tool",
                action_type="scan", success=True,
            )
            trail.log_action(
                target="host", tool_id="tool",
                action_type="scan", success=False,
            )

        lines = audit_file.read_text().strip().split("\n")
        for line in lines:
            record = json.loads(line)
            assert record["status"] in ("success", "failure")

    def test_detail_included_when_provided(self, tmp_path: Path) -> None:
        """Detail field appears when provided."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="host", tool_id="fuzzer",
                action_type="fuzz", success=False,
                detail="Connection refused to port 8080",
            )

        lines = audit_file.read_text().strip().split("\n")
        record = json.loads(lines[0])
        assert record["detail"] == "Connection refused to port 8080"

    def test_detail_omitted_when_none(self, tmp_path: Path) -> None:
        """Detail field is omitted from JSON when None."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="host", tool_id="scanner",
                action_type="scan", success=True,
            )

        lines = audit_file.read_text().strip().split("\n")
        record = json.loads(lines[0])
        assert "detail" not in record

    def test_log_method_with_entry_object(self, tmp_path: Path) -> None:
        """Direct log() method works with an AuditTrailEntry."""
        audit_file = tmp_path / "audit.jsonl"
        entry = AuditTrailEntry(
            timestamp="2024-06-15T10:30:00.000Z",
            target="custom-target",
            action_type="craft",
            tool_id="packet-crafter",
            status="success",
        )
        with AuditTrail(path=audit_file) as trail:
            trail.log(entry)

        lines = audit_file.read_text().strip().split("\n")
        record = json.loads(lines[0])
        assert record["timestamp"] == "2024-06-15T10:30:00.000Z"
        assert record["target"] == "custom-target"
        assert record["tool_id"] == "packet-crafter"
        assert record["status"] == "success"

    def test_env_var_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """AuditTrail uses ATHENA_AUDIT_PATH env var when no path provided."""
        audit_file = tmp_path / "env_audit.jsonl"
        monkeypatch.setenv("ATHENA_AUDIT_PATH", str(audit_file))

        with AuditTrail() as trail:
            trail.log_action(
                target="env-target", tool_id="tool",
                action_type="test", success=True,
            )

        assert audit_file.exists()
        lines = audit_file.read_text().strip().split("\n")
        record = json.loads(lines[0])
        assert record["target"] == "env-target"

    def test_stdout_fallback(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
        """AuditTrail writes to stdout when no path and no env var configured."""
        monkeypatch.delenv("ATHENA_AUDIT_PATH", raising=False)

        with AuditTrail() as trail:
            trail.log_action(
                target="stdout-target", tool_id="tool",
                action_type="test", success=True,
            )

        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["target"] == "stdout-target"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """AuditTrail creates parent directories if they don't exist."""
        audit_file = tmp_path / "nested" / "deep" / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            trail.log_action(
                target="host", tool_id="tool",
                action_type="scan", success=True,
            )

        assert audit_file.exists()

    def test_multiple_entries_independently_parseable(self, tmp_path: Path) -> None:
        """Each line in the trail can be parsed independently."""
        audit_file = tmp_path / "audit.jsonl"
        with AuditTrail(path=audit_file) as trail:
            for i in range(5):
                trail.log_action(
                    target=f"target-{i}", tool_id=f"tool-{i}",
                    action_type="scan", success=(i % 2 == 0),
                )

        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 5
        for i, line in enumerate(lines):
            record = json.loads(line)
            assert record["target"] == f"target-{i}"
            assert record["tool_id"] == f"tool-{i}"
