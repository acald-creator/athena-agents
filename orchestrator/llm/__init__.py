"""LLM backend abstraction layer.

Provides a common interface (LLMBackend protocol) and implementations
for multiple inference backends:
- OllamaBackend: Ollama REST API (Apple Silicon, cross-platform)
- VLLMBackend: vLLM OpenAI-compatible API (NVIDIA GPU / CUDA)
- LlamaCppBackend: llama.cpp server API (CPU-only, Apple Silicon MLX)

Configuration and startup validation:
- LLMConfig: Pydantic model for backend configuration
- load_llm_config: Load and validate config/llm.toml
- create_backend: Instantiate the appropriate backend from config
- validate_backend_startup: Health check with timeout at startup
"""

from orchestrator.llm.config import (
    LLMConfig,
    LLMConfigError,
    create_backend,
    load_llm_config,
    log_mid_scenario_failure,
    validate_backend_startup,
)
from orchestrator.llm.interface import LLMBackend
from orchestrator.llm.llamacpp import LlamaCppBackend
from orchestrator.llm.ollama import OllamaBackend
from orchestrator.llm.vllm import VLLMBackend

__all__ = [
    "LLMBackend",
    "LLMConfig",
    "LLMConfigError",
    "LlamaCppBackend",
    "OllamaBackend",
    "VLLMBackend",
    "create_backend",
    "load_llm_config",
    "log_mid_scenario_failure",
    "validate_backend_startup",
]
