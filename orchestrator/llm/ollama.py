"""Ollama LLM backend implementation.

Provides an async HTTP client for the Ollama REST API, suitable for
Apple Silicon and cross-platform local inference.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class OllamaBackend:
    """HTTP client for Ollama REST API.

    Endpoints used:
    - POST /api/generate — text generation
    - GET /api/tags — health check (returns 200 if Ollama is running)
    """

    def __init__(self, base_url: str, model: str, timeout: float = 10.0) -> None:
        """Initialize OllamaBackend.

        Args:
            base_url: Base URL of the Ollama server (e.g., "http://localhost:11434").
            model: Model name to use for generation (e.g., "llama3:8b").
            timeout: HTTP request timeout in seconds.
        """
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    @property
    def backend_id(self) -> str:
        """Unique identifier for this Ollama backend instance."""
        return f"ollama:{self._model}@{self._base_url}"

    async def generate(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate a completion using Ollama's /api/generate endpoint.

        Args:
            prompt: The input prompt text.
            max_tokens: Maximum number of tokens to generate.

        Returns:
            The generated text response.

        Raises:
            RuntimeError: If the request fails or returns an error status.
        """
        url = f"{self._base_url}/api/generate"
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
            },
        }
        try:
            response = await self._client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except httpx.HTTPStatusError as exc:
            msg = (
                f"Ollama generate failed: HTTP {exc.response.status_code} "
                f"from {self.backend_id}"
            )
            logger.error(msg)
            raise RuntimeError(msg) from exc
        except httpx.RequestError as exc:
            msg = f"Ollama generate connection error: {exc} ({self.backend_id})"
            logger.error(msg)
            raise RuntimeError(msg) from exc

    async def health_check(self) -> bool:
        """Check Ollama availability via GET /api/tags.

        Returns:
            True if Ollama responds with HTTP 200, False otherwise.
        """
        url = f"{self._base_url}/api/tags"
        try:
            response = await self._client.get(url)
            return response.status_code == 200
        except httpx.RequestError as exc:
            logger.warning("Ollama health check failed: %s (%s)", exc, self.backend_id)
            return False
