"""Tests for orchestrator.pipeline_buffer module.

Validates:
- Records are buffered locally when pipeline unavailable
- flush_buffer clears local records after successful forward
- get_buffered_count returns correct count
- Buffer persists across PipelineBuffer instances (append-only file)

Requirements: 10.5, 10.6
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from orchestrator.interfaces import GroundTruthLabel, GroundTruthRecord
from orchestrator.pipeline_buffer import (
    DEFAULT_ACK_TIMEOUT,
    DEFAULT_FORWARD_WINDOW,
    PipelineBuffer,
    _deserialize_record,
    _serialize_record,
)


@pytest.fixture
def buffer_dir(tmp_path: Path) -> Path:
    """Provide a temporary buffer directory for tests."""
    d = tmp_path / "buffer"
    d.mkdir()
    return d


@pytest.fixture
def sample_record() -> GroundTruthRecord:
    """Provide a sample ground-truth record for testing."""
    return GroundTruthRecord(
        scenario_id="550e8400-e29b-41d4-a716-446655440000",
        run_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        timestamp="2024-01-15T10:30:00.000Z",
        target="juice-shop.lab.local",
        payload_family="sqli",
        technique="T1190",
        expected_result="SQL injection in login form",
        safety_boundary="lab-network-only",
        label=GroundTruthLabel.MALICIOUS,
        artifact_reference="/artifacts/scenario-001/payload.json",
    )


@pytest.fixture
def sample_record_2() -> GroundTruthRecord:
    """Provide a second sample record for multi-record tests."""
    return GroundTruthRecord(
        scenario_id="660e8400-e29b-41d4-a716-446655440001",
        run_id="7ba7b810-9dad-11d1-80b4-00c04fd430c9",
        timestamp="2024-01-15T10:31:00.000Z",
        target="dvwa.lab.local",
        payload_family="xss",
        technique="T1059",
        expected_result="Reflected XSS in search field",
        safety_boundary="lab-network-only",
        label=GroundTruthLabel.SUCCESSFUL_SIMULATION,
        artifact_reference="/artifacts/scenario-002/payload.json",
    )


@pytest.fixture
def pipeline_buffer(buffer_dir: Path) -> PipelineBuffer:
    """Provide a PipelineBuffer with a temporary buffer directory."""
    return PipelineBuffer(buffer_dir=buffer_dir)


class TestPipelineBufferInit:
    """Tests for PipelineBuffer initialization."""

    def test_default_timeout(self, buffer_dir: Path) -> None:
        """Default ack_timeout should be 30 seconds."""
        buf = PipelineBuffer(buffer_dir=buffer_dir)
        assert buf.ack_timeout == DEFAULT_ACK_TIMEOUT
        assert buf.ack_timeout == 30.0

    def test_default_forward_window(self, buffer_dir: Path) -> None:
        """Default forward_window should be 5 minutes (300 seconds)."""
        buf = PipelineBuffer(buffer_dir=buffer_dir)
        assert buf.forward_window == DEFAULT_FORWARD_WINDOW
        assert buf.forward_window == 300.0

    def test_custom_timeout(self, buffer_dir: Path) -> None:
        """Custom ack_timeout should be respected."""
        buf = PipelineBuffer(buffer_dir=buffer_dir, ack_timeout=10.0)
        assert buf.ack_timeout == 10.0

    def test_custom_forward_window(self, buffer_dir: Path) -> None:
        """Custom forward_window should be respected."""
        buf = PipelineBuffer(buffer_dir=buffer_dir, forward_window=120.0)
        assert buf.forward_window == 120.0

    def test_buffer_dir_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Buffer directory should come from ATHENA_BUFFER_DIR env var."""
        env_dir = tmp_path / "env_buffer"
        monkeypatch.setenv("ATHENA_BUFFER_DIR", str(env_dir))
        buf = PipelineBuffer()
        assert buf.buffer_file.parent == env_dir
        assert env_dir.exists()

    def test_buffer_dir_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Without env var, buffer dir should default to ./buffer/."""
        monkeypatch.delenv("ATHENA_BUFFER_DIR", raising=False)
        monkeypatch.chdir(tmp_path)
        buf = PipelineBuffer()
        assert buf.buffer_file.parent == Path("./buffer")

    def test_pipeline_available_initially_none(self, buffer_dir: Path) -> None:
        """Pipeline availability should be None before first check."""
        buf = PipelineBuffer(buffer_dir=buffer_dir)
        assert buf.pipeline_available is None

    def test_creates_buffer_dir_if_missing(self, tmp_path: Path) -> None:
        """Should create buffer directory if it doesn't exist."""
        new_dir = tmp_path / "new" / "nested" / "buffer"
        buf = PipelineBuffer(buffer_dir=new_dir)
        assert new_dir.exists()
        assert buf.buffer_file.parent == new_dir


class TestBufferRecord:
    """Tests for buffering records locally."""

    def test_buffer_single_record(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """A single record should be buffered and retrievable."""
        pipeline_buffer.buffer_record(sample_record)
        assert pipeline_buffer.get_buffered_count() == 1

    def test_buffer_multiple_records(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
        sample_record_2: GroundTruthRecord,
    ) -> None:
        """Multiple records should all be buffered."""
        pipeline_buffer.buffer_record(sample_record)
        pipeline_buffer.buffer_record(sample_record_2)
        assert pipeline_buffer.get_buffered_count() == 2

    def test_buffered_record_content(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Buffered record should deserialize back to equivalent object."""
        pipeline_buffer.buffer_record(sample_record)
        records = pipeline_buffer.get_buffered_records()
        assert len(records) == 1
        retrieved = records[0]
        assert retrieved.scenario_id == sample_record.scenario_id
        assert retrieved.run_id == sample_record.run_id
        assert retrieved.timestamp == sample_record.timestamp
        assert retrieved.target == sample_record.target
        assert retrieved.payload_family == sample_record.payload_family
        assert retrieved.technique == sample_record.technique
        assert retrieved.expected_result == sample_record.expected_result
        assert retrieved.safety_boundary == sample_record.safety_boundary
        assert retrieved.label == sample_record.label
        assert retrieved.artifact_reference == sample_record.artifact_reference

    def test_buffer_with_null_technique(
        self,
        pipeline_buffer: PipelineBuffer,
    ) -> None:
        """Records with null technique should round-trip correctly."""
        record = GroundTruthRecord(
            scenario_id="test-id",
            run_id="run-id",
            timestamp="2024-01-15T10:30:00.000Z",
            target="target.local",
            payload_family="recon",
            technique=None,
            expected_result="Port discovery",
            safety_boundary="lab-only",
            label=GroundTruthLabel.BENIGN_CONTROL,
            artifact_reference="",
        )
        pipeline_buffer.buffer_record(record)
        records = pipeline_buffer.get_buffered_records()
        assert records[0].technique is None


class TestBufferPersistence:
    """Tests for buffer persistence across instances."""

    def test_buffer_persists_across_instances(
        self,
        buffer_dir: Path,
        sample_record: GroundTruthRecord,
        sample_record_2: GroundTruthRecord,
    ) -> None:
        """Records buffered by one instance should be readable by another."""
        # First instance buffers a record
        buf1 = PipelineBuffer(buffer_dir=buffer_dir)
        buf1.buffer_record(sample_record)

        # Second instance should see the buffered record
        buf2 = PipelineBuffer(buffer_dir=buffer_dir)
        assert buf2.get_buffered_count() == 1

        # Second instance adds another record
        buf2.buffer_record(sample_record_2)

        # Third instance should see both
        buf3 = PipelineBuffer(buffer_dir=buffer_dir)
        assert buf3.get_buffered_count() == 2
        records = buf3.get_buffered_records()
        assert records[0].scenario_id == sample_record.scenario_id
        assert records[1].scenario_id == sample_record_2.scenario_id

    def test_append_only_file(
        self,
        buffer_dir: Path,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Buffer file should be append-only (not overwritten on new instance)."""
        buf1 = PipelineBuffer(buffer_dir=buffer_dir)
        buf1.buffer_record(sample_record)

        # Creating a new instance should NOT clear existing buffer
        buf2 = PipelineBuffer(buffer_dir=buffer_dir)
        assert buf2.get_buffered_count() == 1


class TestGetBufferedCount:
    """Tests for get_buffered_count method."""

    def test_empty_buffer(self, pipeline_buffer: PipelineBuffer) -> None:
        """Empty buffer should return 0."""
        assert pipeline_buffer.get_buffered_count() == 0

    def test_no_buffer_file(self, tmp_path: Path) -> None:
        """Non-existent buffer file should return 0."""
        buf = PipelineBuffer(buffer_dir=tmp_path / "nonexistent_sub")
        # The dir is created by __init__ but no file exists yet
        assert buf.get_buffered_count() == 0

    def test_accurate_count_after_multiple_writes(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Count should increment with each buffered record."""
        assert pipeline_buffer.get_buffered_count() == 0
        pipeline_buffer.buffer_record(sample_record)
        assert pipeline_buffer.get_buffered_count() == 1
        pipeline_buffer.buffer_record(sample_record)
        assert pipeline_buffer.get_buffered_count() == 2
        pipeline_buffer.buffer_record(sample_record)
        assert pipeline_buffer.get_buffered_count() == 3


class TestIsPipelineAvailable:
    """Tests for is_pipeline_available method."""

    def test_available_pipeline(self, pipeline_buffer: PipelineBuffer) -> None:
        """Should return True when pipeline responds with 200."""
        mock_response = httpx.Response(200)
        with patch("orchestrator.pipeline_buffer.httpx.get", return_value=mock_response):
            assert pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health") is True
            assert pipeline_buffer.pipeline_available is True

    def test_unavailable_pipeline_timeout(self, pipeline_buffer: PipelineBuffer) -> None:
        """Should return False when pipeline times out."""
        with patch(
            "orchestrator.pipeline_buffer.httpx.get",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            assert pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health") is False
            assert pipeline_buffer.pipeline_available is False

    def test_unavailable_pipeline_connection_error(
        self, pipeline_buffer: PipelineBuffer
    ) -> None:
        """Should return False when pipeline connection is refused."""
        with patch(
            "orchestrator.pipeline_buffer.httpx.get",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            assert pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health") is False
            assert pipeline_buffer.pipeline_available is False

    def test_unavailable_pipeline_server_error(self, pipeline_buffer: PipelineBuffer) -> None:
        """Should return False when pipeline returns 5xx."""
        mock_response = httpx.Response(503)
        with patch("orchestrator.pipeline_buffer.httpx.get", return_value=mock_response):
            assert pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health") is False
            assert pipeline_buffer.pipeline_available is False

    def test_custom_timeout(self, buffer_dir: Path) -> None:
        """Custom timeout should be passed to the HTTP call."""
        buf = PipelineBuffer(buffer_dir=buffer_dir, ack_timeout=15.0)
        mock_response = httpx.Response(200)
        with patch("orchestrator.pipeline_buffer.httpx.get", return_value=mock_response) as mock_get:
            buf.is_pipeline_available("http://soc-pipeline:8080/health")
            mock_get.assert_called_once_with("http://soc-pipeline:8080/health", timeout=15.0)

    def test_override_timeout(self, pipeline_buffer: PipelineBuffer) -> None:
        """Explicitly passed timeout should override default."""
        mock_response = httpx.Response(200)
        with patch("orchestrator.pipeline_buffer.httpx.get", return_value=mock_response) as mock_get:
            pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health", timeout=5.0)
            mock_get.assert_called_once_with("http://soc-pipeline:8080/health", timeout=5.0)

    def test_recovery_detection(self, pipeline_buffer: PipelineBuffer) -> None:
        """Should detect pipeline recovery from unavailable to available."""
        # First: mark unavailable
        with patch(
            "orchestrator.pipeline_buffer.httpx.get",
            side_effect=httpx.TimeoutException("timeout"),
        ):
            pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health")

        assert pipeline_buffer.pipeline_available is False

        # Second: pipeline recovers
        mock_response = httpx.Response(200)
        with patch("orchestrator.pipeline_buffer.httpx.get", return_value=mock_response):
            result = pipeline_buffer.is_pipeline_available("http://soc-pipeline:8080/health")

        assert result is True
        assert pipeline_buffer.pipeline_available is True
        assert pipeline_buffer._last_recovery_time is not None


class TestFlushBuffer:
    """Tests for flush_buffer method."""

    def test_flush_empty_buffer(self, pipeline_buffer: PipelineBuffer) -> None:
        """Flushing an empty buffer should succeed with no network call."""
        result = pipeline_buffer.flush_buffer("http://soc-pipeline:8080/ingest")
        assert result is True

    def test_flush_success_clears_buffer(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
        sample_record_2: GroundTruthRecord,
    ) -> None:
        """Successful flush should clear local buffer records."""
        pipeline_buffer.buffer_record(sample_record)
        pipeline_buffer.buffer_record(sample_record_2)
        assert pipeline_buffer.get_buffered_count() == 2

        mock_response = httpx.Response(200)
        with patch("orchestrator.pipeline_buffer.httpx.post", return_value=mock_response):
            result = pipeline_buffer.flush_buffer("http://soc-pipeline:8080/ingest")

        assert result is True
        assert pipeline_buffer.get_buffered_count() == 0

    def test_flush_failure_preserves_buffer(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Failed flush should preserve buffer contents for retry."""
        pipeline_buffer.buffer_record(sample_record)
        assert pipeline_buffer.get_buffered_count() == 1

        with patch(
            "orchestrator.pipeline_buffer.httpx.post",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            result = pipeline_buffer.flush_buffer("http://soc-pipeline:8080/ingest")

        assert result is False
        assert pipeline_buffer.get_buffered_count() == 1

    def test_flush_server_error_preserves_buffer(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Server error (5xx) during flush should preserve buffer."""
        pipeline_buffer.buffer_record(sample_record)

        mock_response = httpx.Response(500, text="Internal Server Error")
        with patch("orchestrator.pipeline_buffer.httpx.post", return_value=mock_response):
            result = pipeline_buffer.flush_buffer("http://soc-pipeline:8080/ingest")

        assert result is False
        assert pipeline_buffer.get_buffered_count() == 1

    def test_flush_timeout_preserves_buffer(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Timeout during flush should preserve buffer."""
        pipeline_buffer.buffer_record(sample_record)

        with patch(
            "orchestrator.pipeline_buffer.httpx.post",
            side_effect=httpx.TimeoutException("Request timed out"),
        ):
            result = pipeline_buffer.flush_buffer("http://soc-pipeline:8080/ingest")

        assert result is False
        assert pipeline_buffer.get_buffered_count() == 1

    def test_flush_sends_correct_payload(
        self,
        pipeline_buffer: PipelineBuffer,
        sample_record: GroundTruthRecord,
    ) -> None:
        """Flush should POST all buffered records as JSON array."""
        pipeline_buffer.buffer_record(sample_record)

        mock_response = httpx.Response(200)
        with patch("orchestrator.pipeline_buffer.httpx.post", return_value=mock_response) as mock_post:
            pipeline_buffer.flush_buffer("http://soc-pipeline:8080/ingest")

            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args[1]
            assert call_kwargs["json"] is not None
            payload = call_kwargs["json"]
            assert isinstance(payload, list)
            assert len(payload) == 1
            assert payload[0]["scenario_id"] == sample_record.scenario_id
            assert payload[0]["label"] == "malicious"


class TestSerializationHelpers:
    """Tests for internal serialization/deserialization functions."""

    def test_round_trip(self, sample_record: GroundTruthRecord) -> None:
        """Serialize then deserialize should produce equivalent record."""
        json_str = _serialize_record(sample_record)
        restored = _deserialize_record(json_str)
        assert restored.scenario_id == sample_record.scenario_id
        assert restored.run_id == sample_record.run_id
        assert restored.timestamp == sample_record.timestamp
        assert restored.target == sample_record.target
        assert restored.payload_family == sample_record.payload_family
        assert restored.technique == sample_record.technique
        assert restored.expected_result == sample_record.expected_result
        assert restored.safety_boundary == sample_record.safety_boundary
        assert restored.label == sample_record.label
        assert restored.artifact_reference == sample_record.artifact_reference

    def test_serialize_produces_single_line(self, sample_record: GroundTruthRecord) -> None:
        """Serialized output should be a single line (no newlines)."""
        json_str = _serialize_record(sample_record)
        assert "\n" not in json_str

    def test_serialize_is_valid_json(self, sample_record: GroundTruthRecord) -> None:
        """Serialized output should be valid JSON."""
        json_str = _serialize_record(sample_record)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)
