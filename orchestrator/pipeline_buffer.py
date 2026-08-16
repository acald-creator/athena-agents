"""Pipeline buffer for SOC pipeline resilience.

Provides local buffering of ground-truth records when the SOC pipeline is
unavailable, and recovery-based forwarding when connectivity is restored.

Behavior:
- If the SOC pipeline doesn't acknowledge within 30 seconds, the orchestrator
  continues execution and stores GT records locally (JSON Lines append-only file).
- On pipeline recovery, locally stored records are forwarded within 5 minutes.

Buffer directory is configurable via the ATHENA_BUFFER_DIR environment variable.
Defaults to ./buffer/ if the variable is not set.

Requirements: 10.5, 10.6
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx

from orchestrator.interfaces import GroundTruthLabel, GroundTruthRecord

logger = logging.getLogger(__name__)

# Default acknowledgment timeout in seconds
DEFAULT_ACK_TIMEOUT = 30.0

# Default forward window in seconds (how soon after recovery to forward records)
DEFAULT_FORWARD_WINDOW = 300.0  # 5 minutes

# Buffer filename
BUFFER_FILENAME = "gt_buffer.jsonl"


def _serialize_record(record: GroundTruthRecord) -> str:
    """Serialize a GroundTruthRecord to a single-line JSON string for buffering.

    Args:
        record: The ground-truth record to serialize.

    Returns:
        A single-line JSON string.
    """
    data = asdict(record)
    # Convert the GroundTruthLabel enum to its string value
    data["label"] = record.label.value
    return json.dumps(data, separators=(",", ":"))


def _deserialize_record(json_str: str) -> GroundTruthRecord:
    """Deserialize a JSON line back into a GroundTruthRecord.

    Args:
        json_str: A JSON string representing a single ground-truth record.

    Returns:
        A reconstructed GroundTruthRecord instance.
    """
    data = json.loads(json_str)
    data["label"] = GroundTruthLabel(data["label"])
    return GroundTruthRecord(**data)


class PipelineBuffer:
    """Buffers ground-truth records locally when the SOC pipeline is unavailable.

    Stores records in a JSON Lines file in a configurable buffer directory.
    The buffer is append-only and persists across PipelineBuffer instances.
    When the pipeline recovers, buffered records can be flushed (forwarded)
    to the pipeline endpoint.

    Parameters
    ----------
    buffer_dir : Path | None
        Directory for the buffer file. Defaults to ATHENA_BUFFER_DIR env var
        or ./buffer/ if not set.
    ack_timeout : float
        Timeout in seconds for pipeline acknowledgment (default 30.0).
    forward_window : float
        Maximum time in seconds after recovery to forward buffered records
        (default 300.0 = 5 minutes).
    """

    def __init__(
        self,
        buffer_dir: Path | None = None,
        ack_timeout: float = DEFAULT_ACK_TIMEOUT,
        forward_window: float = DEFAULT_FORWARD_WINDOW,
    ) -> None:
        if buffer_dir is not None:
            self._buffer_dir = buffer_dir
        else:
            env_dir = os.environ.get("ATHENA_BUFFER_DIR")
            self._buffer_dir = Path(env_dir) if env_dir else Path("./buffer")

        self._ack_timeout = ack_timeout
        self._forward_window = forward_window

        # Track pipeline connectivity status
        self._pipeline_available: bool | None = None
        self._last_recovery_time: float | None = None

        # Ensure buffer directory exists
        self._buffer_dir.mkdir(parents=True, exist_ok=True)

    @property
    def buffer_file(self) -> Path:
        """Path to the buffer file."""
        return self._buffer_dir / BUFFER_FILENAME

    @property
    def ack_timeout(self) -> float:
        """Acknowledgment timeout in seconds."""
        return self._ack_timeout

    @property
    def forward_window(self) -> float:
        """Forward window in seconds."""
        return self._forward_window

    @property
    def pipeline_available(self) -> bool | None:
        """Current pipeline connectivity status (None if unchecked)."""
        return self._pipeline_available

    def buffer_record(self, record: GroundTruthRecord) -> None:
        """Store a ground-truth record locally in the buffer.

        Appends the record as a single JSON line to the buffer file.
        The buffer is append-only and persists across instances.

        Args:
            record: The ground-truth record to buffer.
        """
        line = _serialize_record(record)
        with open(self.buffer_file, "a") as f:
            f.write(line + "\n")

        logger.info(
            "Buffered GT record for scenario '%s' (buffered count: %d)",
            record.scenario_id,
            self.get_buffered_count(),
        )

    def get_buffered_count(self) -> int:
        """Return the number of locally stored records awaiting forward.

        Counts non-empty lines in the buffer file.

        Returns:
            Number of buffered records, or 0 if no buffer file exists.
        """
        if not self.buffer_file.exists():
            return 0

        count = 0
        with open(self.buffer_file, "r") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def get_buffered_records(self) -> list[GroundTruthRecord]:
        """Read all buffered records from the buffer file.

        Returns:
            List of GroundTruthRecord instances from the buffer.
        """
        if not self.buffer_file.exists():
            return []

        records: list[GroundTruthRecord] = []
        with open(self.buffer_file, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    try:
                        records.append(_deserialize_record(stripped))
                    except (json.JSONDecodeError, KeyError, ValueError) as exc:
                        logger.warning("Skipping malformed buffer line: %s", exc)
        return records

    def is_pipeline_available(self, endpoint: str, timeout: float | None = None) -> bool:
        """Check if the SOC pipeline acknowledges within the configured timeout.

        Sends a GET request to the pipeline endpoint and waits for a
        successful response (HTTP 2xx). If the pipeline does not respond
        within the timeout, it is considered unavailable.

        Args:
            endpoint: The pipeline endpoint URL to check.
            timeout: Override for the acknowledgment timeout (defaults to
                self.ack_timeout).

        Returns:
            True if the pipeline responds with 2xx within timeout,
            False otherwise.
        """
        check_timeout = timeout if timeout is not None else self._ack_timeout

        try:
            response = httpx.get(endpoint, timeout=check_timeout)
            available = response.status_code >= 200 and response.status_code < 300
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
            available = False

        # Update internal state
        was_unavailable = self._pipeline_available is False
        self._pipeline_available = available

        if available and was_unavailable:
            # Pipeline just recovered
            self._last_recovery_time = time.time()
            logger.info("SOC pipeline recovered at %s", endpoint)

        if not available:
            logger.warning(
                "SOC pipeline unavailable at %s (timeout=%.1fs)",
                endpoint,
                check_timeout,
            )

        return available

    def flush_buffer(self, pipeline_endpoint: str) -> bool:
        """Attempt to forward buffered records to the SOC pipeline.

        Reads all buffered records and POSTs them to the pipeline endpoint.
        On successful forward (HTTP 2xx), the buffer file is cleared.
        If forwarding fails, the buffer remains intact for the next attempt.

        The forwarding must complete within the configured forward_window
        after pipeline recovery.

        Args:
            pipeline_endpoint: The pipeline endpoint URL to forward records to.

        Returns:
            True if all records were successfully forwarded and the buffer
            was cleared. False if forwarding failed (buffer remains intact).
        """
        buffered_count = self.get_buffered_count()
        if buffered_count == 0:
            logger.info("No buffered records to forward")
            return True

        # Check if we're within the forward window
        if self._last_recovery_time is not None:
            elapsed = time.time() - self._last_recovery_time
            if elapsed > self._forward_window:
                logger.warning(
                    "Forward window expired (%.1fs > %.1fs since recovery). "
                    "Attempting forward anyway.",
                    elapsed,
                    self._forward_window,
                )

        # Read buffered records
        records = self.get_buffered_records()
        if not records:
            return True

        # Serialize records for forwarding
        payload = [json.loads(_serialize_record(r)) for r in records]

        try:
            response = httpx.post(
                pipeline_endpoint,
                json=payload,
                timeout=self._ack_timeout,
            )
            if 200 <= response.status_code < 300:
                # Successfully forwarded — clear the buffer
                self._clear_buffer()
                logger.info(
                    "Forwarded %d buffered records to %s",
                    len(records),
                    pipeline_endpoint,
                )
                return True
            else:
                logger.warning(
                    "Pipeline rejected forwarded records (HTTP %d): %s",
                    response.status_code,
                    response.text[:200],
                )
                return False
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as exc:
            logger.warning(
                "Failed to forward buffered records to %s: %s",
                pipeline_endpoint,
                exc,
            )
            return False

    def _clear_buffer(self) -> None:
        """Remove the buffer file, clearing all stored records."""
        if self.buffer_file.exists():
            self.buffer_file.unlink()
            logger.debug("Buffer file cleared: %s", self.buffer_file)
