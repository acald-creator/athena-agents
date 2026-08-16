"""llama.cpp LLM backend implementation.

Provides an async HTTP client for the llama.cpp server API,
suitable for CPU-only and Apple Silicon MLX inference.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class LlamaCppBackend:
    """HTTP client for llama.cpp server API.

    Endpoints used:
    - POST /completion — text generation
    - GET /health — health check
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        """Initialize LlamaCppBackend.

        Args:
            base_url: Base URL of the llama.cpp server (e.g., "http://localhost:8080").
            timeout: HTTP request timeout in seconds.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    @property
    def backend_id(self) -> str:
        """Unique identifier for this llama.cpp backend instance."""
        return f"llamacpp@{self._base_url}"

    async def generate(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate a completion using llama.cpp's /completion endpoint.

        Args:
            prompt: The input prompt text.
            max_tokens: Maximum number of tokens to generate (mapped to n_predict).

        Returns:
            The generated text response.

        Raises:
            RuntimeError: If the request fails or returns an error status.
        """
        url = f"{self._base_url}/completion"
        payload = {
            "prompt": prompt,
            "n_predict": max_tokens,
        }
        try:
            response = await self._client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("content", "")
        except httpx.HTTPStatusError as exc:
            msg = (
                f"llama.cpp generate failed: HTTP {exc.response.status_code} "
                f"from {self.backend_id}"
            )
            logger.error(msg)
            raise RuntimeError(msg) from exc
        except httpx.RequestError as exc:
            msg = f"llama.cpp generate connection error: {exc} ({self.backend_id})"
            logger.error(msg)
            raise RuntimeError(msg) from exc

    async def health_check(self) -> bool:
        """Check llama.cpp availability via GET /health.

        Returns:
            True if llama.cpp responds with HTTP 200, False otherwise.
        """
        url = f"{self._base_url}/health"
        try:
            response = await self._client.get(url)
            return response.status_code == 200
        except httpx.RequestError as exc:
            logger.warning(
                "llama.cpp health check failed: %s (%s)", exc, self.backend_id
            )
            return False
