"""Tests for ground-truth telemetry emitter.

Validates:
- Serialization/deserialization round-trip (Requirement 7.5)
- JSON Lines format: one object per line (Requirement 7.6)
- ATHENA_GT_OUTPUT env var behavior (Requirement 7.3)
- Each record independently parseable (Requirement 7.6)
- None technique serializes as JSON null (Requirement 7.4)
"""

from __future__ import annotations

import json
import os
import tempfile

from orchestrator.ground_truth import (
    GroundTruthEmitter,
    deserialize_record,
    serialize_record,
)
from orchestrator.interfaces import GroundTruthLabel, GroundTruthRecord


def _make_record(
    technique: str | None = "T1190",
    label: GroundTruthLabel = GroundTruthLabel.MALICIOUS,
) -> GroundTruthRecord:
    """Create a sample GroundTruthRecord for testing."""
    return GroundTruthRecord(
        scenario_id="550e8400-e29b-41d4-a716-446655440000",
        run_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        timestamp="2024-01-15T10:30:00.000Z",
        target="juice-shop.lab.local:3000",
        payload_family="sqli",
        technique=technique,
        expected_result="SQL injection bypasses authentication",
        safety_boundary="lab-network-only",
        label=label,
        artifact_reference="/artifacts/run-6ba7b810/action-001.json",
    )


class TestSerializeRecord:
    """Tests for serialize_record function."""

    def test_produces_valid_json(self) -> None:
        record = _make_record()
        result = serialize_record(record)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_single_line_no_newlines(self) -> None:
        record = _make_record()
        result = serialize_record(record)
        assert "\n" not in result
        assert "\r" not in result

    def test_enum_serialized_as_string_value(self) -> None:
        record = _make_record(label=GroundTruthLabel.BENIGN_CONTROL)
        result = serialize_record(record)
        parsed = json.loads(result)
        assert parsed["label"] == "benign_control"

    def test_none_technique_serialized_as_null(self) -> None:
        record = _make_record(technique=None)
        result = serialize_record(record)
        parsed = json.loads(result)
        assert parsed["technique"] is None

    def test_technique_present_serialized_as_string(self) -> None:
        record = _make_record(technique="T1190")
        result = serialize_record(record)
        parsed = json.loads(result)
        assert parsed["technique"] == "T1190"

    def test_all_fields_present(self) -> None:
        record = _make_record()
        result = serialize_record(record)
        parsed = json.loads(result)
        expected_fields = {
            "scenario_id",
            "run_id",
            "timestamp",
            "target",
            "payload_family",
            "technique",
            "expected_result",
            "safety_boundary",
            "label",
            "artifact_reference",
        }
        assert set(parsed.keys()) == expected_fields

    def test_all_label_values(self) -> None:
        for label in GroundTruthLabel:
            record = _make_record(label=label)
            result = serialize_record(record)
            parsed = json.loads(result)
            assert parsed["label"] == label.value


class TestDeserializeRecord:
    """Tests for deserialize_record function."""

    def test_round_trip_with_technique(self) -> None:
        original = _make_record(technique="T1190")
        json_str = serialize_record(original)
        restored = deserialize_record(json_str)
        assert restored == original

    def test_round_trip_with_none_technique(self) -> None:
        original = _make_record(technique=None)
        json_str = serialize_record(original)
        restored = deserialize_record(json_str)
        assert restored == original

    def test_round_trip_all_labels(self) -> None:
        for label in GroundTruthLabel:
            original = _make_record(label=label)
            json_str = serialize_record(original)
            restored = deserialize_record(json_str)
            assert restored == original

    def test_field_by_field_equivalence(self) -> None:
        original = _make_record()
        json_str = serialize_record(original)
        restored = deserialize_record(json_str)
        assert restored.scenario_id == original.scenario_id
        assert restored.run_id == original.run_id
        assert restored.timestamp == original.timestamp
        assert restored.target == original.target
        assert restored.payload_family == original.payload_family
        assert restored.technique == original.technique
        assert restored.expected_result == original.expected_result
        assert restored.safety_boundary == original.safety_boundary
        assert restored.label == original.label
        assert restored.artifact_reference == original.artifact_reference


class TestGroundTruthEmitter:
    """Tests for GroundTruthEmitter class."""

    def test_writes_to_file_via_env_var(self, monkeypatch: object, tmp_path) -> None:
        output_file = tmp_path / "gt_output.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))  # type: ignore[attr-defined]

        record = _make_record()
        with GroundTruthEmitter() as emitter:
            emitter.emit(record)

        content = output_file.read_text()
        assert content.strip() != ""
        parsed = json.loads(content.strip())
        assert parsed["scenario_id"] == record.scenario_id

    def test_writes_to_stdout_when_no_env_var(self, monkeypatch, capsys) -> None:
        monkeypatch.delenv("ATHENA_GT_OUTPUT", raising=False)

        record = _make_record()
        with GroundTruthEmitter() as emitter:
            emitter.emit(record)

        captured = capsys.readouterr()
        assert captured.out.strip() != ""
        parsed = json.loads(captured.out.strip())
        assert parsed["scenario_id"] == record.scenario_id

    def test_json_lines_format_multiple_records(self, monkeypatch, tmp_path) -> None:
        output_file = tmp_path / "gt_multi.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))

        records = [
            _make_record(label=GroundTruthLabel.MALICIOUS),
            _make_record(label=GroundTruthLabel.BENIGN_CONTROL),
            _make_record(label=GroundTruthLabel.FAILED_ATTACK),
        ]

        with GroundTruthEmitter() as emitter:
            for record in records:
                emitter.emit(record)

        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_each_record_independently_parseable(self, monkeypatch, tmp_path) -> None:
        output_file = tmp_path / "gt_independent.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))

        records = [
            _make_record(technique="T1190"),
            _make_record(technique=None),
            _make_record(label=GroundTruthLabel.NEEDS_REVIEW),
        ]

        with GroundTruthEmitter() as emitter:
            for record in records:
                emitter.emit(record)

        lines = output_file.read_text().strip().split("\n")
        for line in lines:
            # Each line must independently parse as valid JSON
            parsed = json.loads(line)
            assert isinstance(parsed, dict)
            assert "scenario_id" in parsed
            assert "label" in parsed

    def test_appends_to_existing_file(self, monkeypatch, tmp_path) -> None:
        output_file = tmp_path / "gt_append.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))

        # First write
        with GroundTruthEmitter() as emitter:
            emitter.emit(_make_record(label=GroundTruthLabel.MALICIOUS))

        # Second write (should append)
        with GroundTruthEmitter() as emitter:
            emitter.emit(_make_record(label=GroundTruthLabel.BENIGN_CONTROL))

        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["label"] == "malicious"
        assert json.loads(lines[1])["label"] == "benign_control"

    def test_context_manager_closes_file(self, monkeypatch, tmp_path) -> None:
        output_file = tmp_path / "gt_close.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))

        emitter = GroundTruthEmitter()
        emitter.emit(_make_record())
        emitter.close()

        # Verify file is readable after close
        content = output_file.read_text()
        assert content.strip() != ""

    def test_close_is_idempotent(self, monkeypatch, tmp_path) -> None:
        output_file = tmp_path / "gt_idem.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))

        emitter = GroundTruthEmitter()
        emitter.emit(_make_record())
        emitter.close()
        # Calling close again should not raise
        emitter.close()

    def test_deserialized_records_match_emitted(self, monkeypatch, tmp_path) -> None:
        output_file = tmp_path / "gt_roundtrip.jsonl"
        monkeypatch.setenv("ATHENA_GT_OUTPUT", str(output_file))

        original_records = [
            _make_record(technique="T1190", label=GroundTruthLabel.MALICIOUS),
            _make_record(technique=None, label=GroundTruthLabel.FAILED_ATTACK),
            _make_record(technique="T1059", label=GroundTruthLabel.SUCCESSFUL_SIMULATION),
        ]

        with GroundTruthEmitter() as emitter:
            for record in original_records:
                emitter.emit(record)

        lines = output_file.read_text().strip().split("\n")
        for i, line in enumerate(lines):
            restored = deserialize_record(line)
            assert restored == original_records[i]
