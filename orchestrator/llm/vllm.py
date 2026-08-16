"""vLLM LLM backend implementation.

Provides an async HTTP client for the vLLM OpenAI-compatible API,
optimized for NVIDIA GPU inference with CUDA acceleration.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class VLLMBackend:
    """HTTP client for vLLM's OpenAI-compatible API.

    Endpoints used:
    - POST /v1/completions — text generation
    - GET /health or GET /v1/models — health check
    """

    def __init__(self, base_url: str, model: str, timeout: float = 10.0) -> None:
        """Initialize VLLMBackend.

        Args:
            base_url: Base URL of the vLLM server (e.g., "http://localhost:8000").
            model: Model name to use for generation.
            timeout: HTTP request timeout in seconds.
        """
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    @property
    def backend_id(self) -> str:
        """Unique identifier for this vLLM backend instance."""
        return f"vllm:{self._model}@{self._base_url}"

    async def generate(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate a completion using vLLM's /v1/completions endpoint.

        Args:
            prompt: The input prompt text.
            max_tokens: Maximum number of tokens to generate.

        Returns:
            The generated text response.

        Raises:
            RuntimeError: If the request fails or returns an error status.
        """
        url = f"{self._base_url}/v1/completions"
        payload = {
            "model": self._model,
            "prompt": prompt,
            "max_tokens": max_tokens,
        }
        try:
            response = await self._client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            # OpenAI-compatible format: choices[0].text
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("text", "")
            return ""
        except httpx.HTTPStatusError as exc:
            msg = (
                f"vLLM generate failed: HTTP {exc.response.status_code} "
                f"from {self.backend_id}"
            )
            logger.error(msg)
            raise RuntimeError(msg) from exc
        except httpx.RequestError as exc:
            msg = f"vLLM generate connection error: {exc} ({self.backend_id})"
            logger.error(msg)
            raise RuntimeError(msg) from exc

    async def health_check(self) -> bool:
        """Check vLLM availability via GET /health, falling back to /v1/models.

        Returns:
            True if vLLM responds with HTTP 200, False otherwise.
        """
        # Try /health first (vLLM native)
        try:
            response = await self._client.get(f"{self._base_url}/health")
            if response.status_code == 200:
                return True
        except httpx.RequestError:
            pass

        # Fallback to /v1/models (OpenAI-compatible)
        try:
            response = await self._client.get(f"{self._base_url}/v1/models")
            return response.status_code == 200
        except httpx.RequestError as exc:
            logger.warning("vLLM health check failed: %s (%s)", exc, self.backend_id)
            return False
