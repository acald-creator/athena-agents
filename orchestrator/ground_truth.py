"""Ground-truth telemetry emitter.

Provides JSON Lines serialization and output for GroundTruthRecord instances.
Records are written one per line, each independently parseable as a JSON object.

Output destination is configurable via the ATHENA_GT_OUTPUT environment variable:
- If set, records are appended to the specified file path.
- If unset, records are written to stdout.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import IO

from orchestrator.interfaces import GroundTruthLabel, GroundTruthRecord


def serialize_record(record: GroundTruthRecord) -> str:
    """Serialize a GroundTruthRecord to a single-line JSON string.

    Handles GroundTruthLabel enum values by extracting the string value,
    and serializes None technique as JSON null.

    Args:
        record: The ground-truth record to serialize.

    Returns:
        A single-line JSON string (no trailing newline).
    """
    data = asdict(record)
    # Convert the GroundTruthLabel enum to its string value
    data["label"] = record.label.value
    return json.dumps(data, separators=(",", ":"))


def deserialize_record(json_str: str) -> GroundTruthRecord:
    """Deserialize a single JSON line back into a GroundTruthRecord.

    Proves round-trip fidelity: serialize then deserialize yields
    a field-by-field equivalent object.

    Args:
        json_str: A JSON string representing a single ground-truth record.

    Returns:
        A reconstructed GroundTruthRecord instance.

    Raises:
        json.JSONDecodeError: If the string is not valid JSON.
        KeyError: If required fields are missing.
        ValueError: If the label value is not a valid GroundTruthLabel.
    """
    data = json.loads(json_str)
    data["label"] = GroundTruthLabel(data["label"])
    return GroundTruthRecord(**data)


class GroundTruthEmitter:
    """Emits GroundTruthRecord instances as JSON Lines.

    Supports configurable output via ATHENA_GT_OUTPUT environment variable.
    Can be used as a context manager for automatic resource cleanup.

    Usage:
        # Write to file:
        os.environ["ATHENA_GT_OUTPUT"] = "/tmp/gt.jsonl"
        with GroundTruthEmitter() as emitter:
            emitter.emit(record)

        # Write to stdout (default):
        with GroundTruthEmitter() as emitter:
            emitter.emit(record)
    """

    def __init__(self) -> None:
        """Initialize the emitter based on ATHENA_GT_OUTPUT env var."""
        output_path = os.environ.get("ATHENA_GT_OUTPUT")
        self._owns_handle = False
        self._handle: IO[str]

        if output_path:
            self._handle = open(output_path, "a")  # noqa: SIM115
            self._owns_handle = True
        else:
            self._handle = sys.stdout
            self._owns_handle = False

    def emit(self, record: GroundTruthRecord) -> None:
        """Serialize and write a single record as one JSON line.

        Args:
            record: The ground-truth record to emit.
        """
        line = serialize_record(record)
        self._handle.write(line + "\n")
        self._handle.flush()

    def close(self) -> None:
        """Flush and close the output handle if owned by this emitter."""
        if self._owns_handle and self._handle and not self._handle.closed:
            self._handle.flush()
            self._handle.close()

    def __enter__(self) -> GroundTruthEmitter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.close()
