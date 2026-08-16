"""Tests for orchestrator.llm.config module.

Verifies LLM backend configuration loading, type validation, backend creation,
and startup health check validation.

Requirements: 9.4, 9.5, 9.7
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from orchestrator.llm import (
    LlamaCppBackend,
    LLMConfig,
    LLMConfigError,
    OllamaBackend,
    VLLMBackend,
    create_backend,
    load_llm_config,
    validate_backend_startup,
)


# --- Config Loading ---


class TestLoadLLMConfig:
    """Tests for load_llm_config function."""

    def test_valid_config_loads_correctly(self, tmp_path: Path) -> None:
        """A well-formed llm.toml should load into an LLMConfig instance."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "ollama"\n'
            'url = "http://localhost:11434"\n'
            'model = "llama3:8b"\n'
            'timeout_seconds = 10\n'
        )
        config = load_llm_config(config_file)

        assert config.type == "ollama"
        assert config.url == "http://localhost:11434"
        assert config.model == "llama3:8b"
        assert config.timeout_seconds == 10.0

    def test_valid_vllm_config(self, tmp_path: Path) -> None:
        """vLLM configuration should load correctly."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "vllm"\n'
            'url = "http://gpu-server:8000"\n'
            'model = "mistral-7b"\n'
            'timeout_seconds = 30\n'
        )
        config = load_llm_config(config_file)

        assert config.type == "vllm"
        assert config.url == "http://gpu-server:8000"
        assert config.model == "mistral-7b"
        assert config.timeout_seconds == 30.0

    def test_valid_llamacpp_config_model_optional(self, tmp_path: Path) -> None:
        """llamacpp config should work without a model field."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "llamacpp"\n'
            'url = "http://localhost:8080"\n'
        )
        config = load_llm_config(config_file)

        assert config.type == "llamacpp"
        assert config.url == "http://localhost:8080"
        assert config.model == ""
        assert config.timeout_seconds == 10.0

    def test_invalid_type_raises_llm_config_error(self, tmp_path: Path) -> None:
        """An unsupported backend type should raise LLMConfigError."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "gpt4"\n'
            'url = "http://localhost:8080"\n'
        )
        with pytest.raises(LLMConfigError, match="Invalid LLM backend configuration"):
            load_llm_config(config_file)

    def test_missing_file_raises_error(self, tmp_path: Path) -> None:
        """A missing config file should raise LLMConfigError."""
        config_file = tmp_path / "nonexistent.toml"
        with pytest.raises(LLMConfigError, match="not found"):
            load_llm_config(config_file)

    def test_missing_backend_section_raises_error(self, tmp_path: Path) -> None:
        """A TOML file without [backend] section should raise LLMConfigError."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text('[other]\nkey = "value"\n')
        with pytest.raises(LLMConfigError, match="missing \\[backend\\] section"):
            load_llm_config(config_file)

    def test_invalid_toml_raises_error(self, tmp_path: Path) -> None:
        """Malformed TOML should raise LLMConfigError."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text("this is not valid toml [[[")
        with pytest.raises(LLMConfigError, match="Invalid TOML"):
            load_llm_config(config_file)

    def test_missing_url_raises_error(self, tmp_path: Path) -> None:
        """Missing required 'url' field should raise LLMConfigError."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "ollama"\n'
            'model = "llama3:8b"\n'
        )
        with pytest.raises(LLMConfigError, match="Invalid LLM backend configuration"):
            load_llm_config(config_file)

    def test_default_timeout_seconds(self, tmp_path: Path) -> None:
        """timeout_seconds should default to 10.0 if not specified."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "ollama"\n'
            'url = "http://localhost:11434"\n'
            'model = "llama3:8b"\n'
        )
        config = load_llm_config(config_file)
        assert config.timeout_seconds == 10.0


# --- LLMConfig Validation ---


class TestLLMConfigModel:
    """Tests for the LLMConfig Pydantic model directly."""

    def test_valid_ollama_config(self) -> None:
        config = LLMConfig(type="ollama", url="http://localhost:11434", model="llama3:8b")
        assert config.type == "ollama"

    def test_valid_vllm_config(self) -> None:
        config = LLMConfig(type="vllm", url="http://localhost:8000", model="mistral")
        assert config.type == "vllm"

    def test_valid_llamacpp_config(self) -> None:
        config = LLMConfig(type="llamacpp", url="http://localhost:8080")
        assert config.type == "llamacpp"

    def test_invalid_type_rejected(self) -> None:
        """Unsupported type should be rejected at Pydantic validation."""
        with pytest.raises(Exception, match="Unsupported backend type"):
            LLMConfig(type="openai", url="http://localhost:8080")


# --- Backend Creation ---


class TestCreateBackend:
    """Tests for create_backend function."""

    def test_creates_ollama_backend(self) -> None:
        config = LLMConfig(
            type="ollama", url="http://localhost:11434", model="llama3:8b", timeout_seconds=15.0
        )
        backend = create_backend(config)
        assert isinstance(backend, OllamaBackend)
        assert backend.backend_id == "ollama:llama3:8b@http://localhost:11434"

    def test_creates_vllm_backend(self) -> None:
        config = LLMConfig(
            type="vllm", url="http://gpu-server:8000", model="mistral-7b", timeout_seconds=20.0
        )
        backend = create_backend(config)
        assert isinstance(backend, VLLMBackend)
        assert backend.backend_id == "vllm:mistral-7b@http://gpu-server:8000"

    def test_creates_llamacpp_backend(self) -> None:
        config = LLMConfig(
            type="llamacpp", url="http://localhost:8080", timeout_seconds=5.0
        )
        backend = create_backend(config)
        assert isinstance(backend, LlamaCppBackend)
        assert backend.backend_id == "llamacpp@http://localhost:8080"

    def test_each_type_returns_correct_class(self) -> None:
        """Verify each config type maps to its expected backend class."""
        type_to_class = {
            "ollama": OllamaBackend,
            "vllm": VLLMBackend,
            "llamacpp": LlamaCppBackend,
        }
        for backend_type, expected_class in type_to_class.items():
            config = LLMConfig(type=backend_type, url="http://localhost:8080", model="test")
            backend = create_backend(config)
            assert isinstance(backend, expected_class), (
                f"Expected {expected_class.__name__} for type '{backend_type}'"
            )


# --- Startup Validation ---


class TestValidateBackendStartup:
    """Tests for validate_backend_startup function."""

    @pytest.mark.asyncio
    async def test_succeeds_when_health_check_returns_true(self) -> None:
        """Startup validation should succeed when health_check returns True."""
        backend = AsyncMock()
        backend.backend_id = "ollama:llama3:8b@http://localhost:11434"
        backend.health_check = AsyncMock(return_value=True)

        # Should not raise
        await validate_backend_startup(backend, timeout=10.0)

    @pytest.mark.asyncio
    async def test_raises_when_health_check_returns_false(self) -> None:
        """Startup validation should raise when health_check returns False."""
        backend = AsyncMock()
        backend.backend_id = "ollama:llama3:8b@http://localhost:11434"
        backend.health_check = AsyncMock(return_value=False)

        with pytest.raises(LLMConfigError, match="health check returned unhealthy"):
            await validate_backend_startup(backend, timeout=10.0)

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self) -> None:
        """Startup validation should raise when health check exceeds timeout."""

        async def slow_health_check() -> bool:
            await asyncio.sleep(5.0)
            return True

        backend = AsyncMock()
        backend.backend_id = "vllm:model@http://localhost:8000"
        backend.health_check = slow_health_check

        with pytest.raises(LLMConfigError, match="timed out"):
            await validate_backend_startup(backend, timeout=0.1)

    @pytest.mark.asyncio
    async def test_raises_on_connection_error(self) -> None:
        """Startup validation should raise when health check throws an exception."""
        backend = AsyncMock()
        backend.backend_id = "llamacpp@http://localhost:8080"
        backend.health_check = AsyncMock(
            side_effect=ConnectionError("Connection refused")
        )

        with pytest.raises(LLMConfigError, match="startup validation failed"):
            await validate_backend_startup(backend, timeout=10.0)

    @pytest.mark.asyncio
    async def test_error_message_includes_backend_id(self) -> None:
        """Error message should include the backend_id for diagnostics."""
        backend = AsyncMock()
        backend.backend_id = "vllm:mistral@http://gpu-box:8000"
        backend.health_check = AsyncMock(return_value=False)

        with pytest.raises(LLMConfigError) as exc_info:
            await validate_backend_startup(backend, timeout=10.0)

        assert "vllm:mistral@http://gpu-box:8000" in str(exc_info.value)


# --- Integration: Load + Create + Validate ---


class TestEndToEndConfigFlow:
    """Integration tests for the full config → backend → validate flow."""

    def test_load_and_create_ollama(self, tmp_path: Path) -> None:
        """Full flow: load config, create Ollama backend."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "ollama"\n'
            'url = "http://localhost:11434"\n'
            'model = "llama3:8b"\n'
            'timeout_seconds = 15\n'
        )
        config = load_llm_config(config_file)
        backend = create_backend(config)

        assert isinstance(backend, OllamaBackend)
        assert backend.backend_id == "ollama:llama3:8b@http://localhost:11434"

    @pytest.mark.asyncio
    async def test_load_create_validate_success(self, tmp_path: Path) -> None:
        """Full flow with successful validation."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "vllm"\n'
            'url = "http://localhost:8000"\n'
            'model = "codellama"\n'
            'timeout_seconds = 5\n'
        )
        config = load_llm_config(config_file)
        backend = create_backend(config)

        # Mock the health_check on the real backend instance
        backend.health_check = AsyncMock(return_value=True)
        await validate_backend_startup(backend, timeout=config.timeout_seconds)

    @pytest.mark.asyncio
    async def test_load_create_validate_failure_exits_scenario(self, tmp_path: Path) -> None:
        """Full flow where validation fails should raise LLMConfigError."""
        config_file = tmp_path / "llm.toml"
        config_file.write_text(
            '[backend]\n'
            'type = "llamacpp"\n'
            'url = "http://localhost:8080"\n'
            'timeout_seconds = 5\n'
        )
        config = load_llm_config(config_file)
        backend = create_backend(config)

        # Mock an unhealthy backend
        backend.health_check = AsyncMock(return_value=False)

        with pytest.raises(LLMConfigError, match="unhealthy"):
            await validate_backend_startup(backend, timeout=config.timeout_seconds)
