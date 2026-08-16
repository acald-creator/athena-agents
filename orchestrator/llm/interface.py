"""LLM Backend protocol definition.

Defines the common interface that all LLM inference backends must implement,
enabling the agent orchestrator to switch backends via configuration only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for LLM inference backends.

    All backends must implement async generate and health_check methods,
    plus expose a backend_id property for logging and diagnostics.
    """

    async def generate(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate a completion from the given prompt.

        Args:
            prompt: The input prompt text.
            max_tokens: Maximum number of tokens to generate.

        Returns:
            The generated text response.

        Raises:
            RuntimeError: If the backend is unreachable or returns an error.
        """
        ...

    async def health_check(self) -> bool:
        """Check if the backend is reachable and healthy.

        Returns:
            True if the backend responds successfully, False otherwise.
        """
        ...

    @property
    def backend_id(self) -> str:
        """Unique identifier for this backend instance.

        Format varies by backend type:
        - Ollama: "ollama:{model}@{base_url}"
        - vLLM: "vllm:{model}@{base_url}"
        - llama.cpp: "llamacpp@{base_url}"
        """
        ...
