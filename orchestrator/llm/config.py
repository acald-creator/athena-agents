"""LLM backend configuration and startup validation.

Loads backend configuration from config/llm.toml, validates the backend type,
instantiates the appropriate backend class, and performs startup health checks.

Requirements: 9.4, 9.5, 9.7
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from orchestrator.llm.interface import LLMBackend
from orchestrator.llm.llamacpp import LlamaCppBackend
from orchestrator.llm.ollama import OllamaBackend
from orchestrator.llm.vllm import VLLMBackend

logger = logging.getLogger(__name__)

SUPPORTED_BACKENDS = ("ollama", "vllm", "llamacpp")


class LLMConfigError(Exception):
    """Raised when LLM backend configuration is invalid or startup validation fails."""


class LLMConfig(BaseModel):
    """Configuration model for the LLM backend.

    Fields:
        type: Backend type — must be one of 'ollama', 'vllm', or 'llamacpp'.
        url: Base URL of the backend server.
        model: Model identifier (optional for llamacpp).
        timeout_seconds: HTTP request timeout and health check timeout.
    """

    type: Literal["ollama", "vllm", "llamacpp"]
    url: str
    model: str = ""
    timeout_seconds: float = 10.0

    @field_validator("type", mode="before")
    @classmethod
    def validate_backend_type(cls, v: str) -> str:
        """Reject unsupported backend types with a descriptive error."""
        if v not in SUPPORTED_BACKENDS:
            raise ValueError(
                f"Unsupported backend type '{v}'. "
                f"Must be one of: {', '.join(SUPPORTED_BACKENDS)}"
            )
        return v


def load_llm_config(path: Path) -> LLMConfig:
    """Load and validate LLM backend configuration from a TOML file.

    Args:
        path: Path to the llm.toml configuration file.

    Returns:
        A validated LLMConfig instance.

    Raises:
        LLMConfigError: If the file is missing, unreadable, or contains
            invalid configuration.
    """
    if not path.exists():
        raise LLMConfigError(f"LLM config file not found: {path}")

    try:
        content = path.read_bytes()
    except OSError as e:
        raise LLMConfigError(f"Cannot read LLM config file: {path}: {e}") from e

    try:
        data = tomllib.loads(content.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise LLMConfigError(f"Invalid TOML in LLM config: {path}: {e}") from e

    backend_section = data.get("backend")
    if backend_section is None:
        raise LLMConfigError(f"LLM config missing [backend] section: {path}")

    if not isinstance(backend_section, dict):
        raise LLMConfigError(f"LLM config [backend] section must be a table: {path}")

    try:
        return LLMConfig.model_validate(backend_section)
    except Exception as e:
        raise LLMConfigError(f"Invalid LLM backend configuration in {path}: {e}") from e


def create_backend(config: LLMConfig) -> LLMBackend:
    """Instantiate the appropriate LLM backend class from configuration.

    Args:
        config: Validated LLMConfig instance.

    Returns:
        An LLMBackend implementation matching the configured type.

    Raises:
        LLMConfigError: If the backend type is not recognized (should not occur
            after config validation).
    """
    if config.type == "ollama":
        return OllamaBackend(
            base_url=config.url,
            model=config.model,
            timeout=config.timeout_seconds,
        )
    elif config.type == "vllm":
        return VLLMBackend(
            base_url=config.url,
            model=config.model,
            timeout=config.timeout_seconds,
        )
    elif config.type == "llamacpp":
        return LlamaCppBackend(
            base_url=config.url,
            timeout=config.timeout_seconds,
        )
    else:
        raise LLMConfigError(
            f"Unrecognized backend type '{config.type}'. "
            f"Supported: {', '.join(SUPPORTED_BACKENDS)}"
        )


async def validate_backend_startup(backend: LLMBackend, timeout: float = 10.0) -> None:
    """Validate backend connectivity at startup by calling health_check.

    Calls the backend's health_check() method with a timeout. If the backend
    is unreachable or unhealthy, raises LLMConfigError with the URL and
    failure reason.

    Args:
        backend: An LLMBackend instance to validate.
        timeout: Maximum seconds to wait for the health check response.

    Raises:
        LLMConfigError: If the backend is unreachable, returns unhealthy,
            or the health check times out.
    """
    backend_id = backend.backend_id
    logger.info("Validating LLM backend connectivity: %s", backend_id)

    try:
        healthy = await asyncio.wait_for(backend.health_check(), timeout=timeout)
    except asyncio.TimeoutError:
        msg = (
            f"LLM backend startup validation failed: health check timed out "
            f"after {timeout}s (backend={backend_id})"
        )
        logger.error(msg)
        raise LLMConfigError(msg)
    except Exception as exc:
        msg = (
            f"LLM backend startup validation failed: {exc} "
            f"(backend={backend_id})"
        )
        logger.error(msg)
        raise LLMConfigError(msg) from exc

    if not healthy:
        msg = (
            f"LLM backend startup validation failed: health check returned unhealthy "
            f"(backend={backend_id})"
        )
        logger.error(msg)
        raise LLMConfigError(msg)

    logger.info("LLM backend validated successfully: %s", backend_id)


def log_mid_scenario_failure(backend: LLMBackend, error: Exception) -> None:
    """Log a mid-scenario backend failure with backend_id and timestamp.

    This function is called when the LLM backend becomes unreachable during
    scenario execution. It logs the failure details for diagnostics.

    Args:
        backend: The backend that failed.
        error: The exception that caused the failure.
    """
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).isoformat()
    logger.error(
        "LLM backend failure during scenario execution: backend=%s, "
        "timestamp=%s, error=%s",
        backend.backend_id,
        timestamp,
        str(error),
    )
