"""Tests for orchestrator.llm module.

Verifies the LLMBackend protocol compliance, backend_id formatting,
generate/health_check behavior, and error handling for all three backends.
Uses httpx mock transport to avoid real HTTP calls.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from orchestrator.llm import LLMBackend, LlamaCppBackend, OllamaBackend, VLLMBackend


# --- Mock Transport ---


class MockTransport(httpx.AsyncBaseTransport):
    """Configurable mock transport for httpx.AsyncClient."""

    def __init__(self, handler: Any = None) -> None:
        self._handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._handler:
            return self._handler(request)
        return httpx.Response(status_code=200, json={})


def make_json_response(data: dict, status_code: int = 200) -> httpx.Response:
    """Create an httpx.Response with JSON content."""
    return httpx.Response(
        status_code=status_code,
        json=data,
    )


def make_error_response(status_code: int = 500) -> httpx.Response:
    """Create an httpx.Response indicating server error."""
    return httpx.Response(
        status_code=status_code,
        json={"error": "internal server error"},
    )


# --- Protocol Compliance ---


class TestLLMBackendProtocol:
    """Verify all backends satisfy the LLMBackend protocol."""

    def test_ollama_is_llm_backend(self) -> None:
        """OllamaBackend should be recognized as implementing LLMBackend."""
        backend = OllamaBackend(base_url="http://localhost:11434", model="llama3:8b")
        assert isinstance(backend, LLMBackend)

    def test_vllm_is_llm_backend(self) -> None:
        """VLLMBackend should be recognized as implementing LLMBackend."""
        backend = VLLMBackend(base_url="http://localhost:8000", model="mistral-7b")
        assert isinstance(backend, LLMBackend)

    def test_llamacpp_is_llm_backend(self) -> None:
        """LlamaCppBackend should be recognized as implementing LLMBackend."""
        backend = LlamaCppBackend(base_url="http://localhost:8080")
        assert isinstance(backend, LLMBackend)


# --- Backend ID ---


class TestBackendId:
    """Verify backend_id property format for all backends."""

    def test_ollama_backend_id(self) -> None:
        backend = OllamaBackend(base_url="http://localhost:11434", model="llama3:8b")
        assert backend.backend_id == "ollama:llama3:8b@http://localhost:11434"

    def test_ollama_backend_id_strips_trailing_slash(self) -> None:
        backend = OllamaBackend(base_url="http://localhost:11434/", model="phi3")
        assert backend.backend_id == "ollama:phi3@http://localhost:11434"

    def test_vllm_backend_id(self) -> None:
        backend = VLLMBackend(base_url="http://gpu-server:8000", model="mistral-7b")
        assert backend.backend_id == "vllm:mistral-7b@http://gpu-server:8000"

    def test_vllm_backend_id_strips_trailing_slash(self) -> None:
        backend = VLLMBackend(base_url="http://localhost:8000/", model="codellama")
        assert backend.backend_id == "vllm:codellama@http://localhost:8000"

    def test_llamacpp_backend_id(self) -> None:
        backend = LlamaCppBackend(base_url="http://localhost:8080")
        assert backend.backend_id == "llamacpp@http://localhost:8080"

    def test_llamacpp_backend_id_strips_trailing_slash(self) -> None:
        backend = LlamaCppBackend(base_url="http://localhost:8080/")
        assert backend.backend_id == "llamacpp@http://localhost:8080"


# --- OllamaBackend ---


class TestOllamaBackend:
    """Tests for OllamaBackend generate and health_check."""

    @pytest.fixture
    def backend_with_transport(self):
        """Create an OllamaBackend with a mock transport injected."""

        def _make(handler):
            backend = OllamaBackend(
                base_url="http://localhost:11434", model="llama3:8b"
            )
            backend._client = httpx.AsyncClient(transport=MockTransport(handler))
            return backend

        return _make

    @pytest.mark.asyncio
    async def test_generate_success(self, backend_with_transport) -> None:
        """Successful generate should return the response text."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert "/api/generate" in str(request.url)
            body = json.loads(request.content)
            assert body["model"] == "llama3:8b"
            assert body["prompt"] == "Hello"
            assert body["options"]["num_predict"] == 512
            return make_json_response({"response": "Hi there!"})

        backend = backend_with_transport(handler)
        result = await backend.generate("Hello", max_tokens=512)
        assert result == "Hi there!"

    @pytest.mark.asyncio
    async def test_generate_http_error_raises(self, backend_with_transport) -> None:
        """HTTP error from Ollama should raise RuntimeError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return make_error_response(500)

        backend = backend_with_transport(handler)
        with pytest.raises(RuntimeError, match="Ollama generate failed"):
            await backend.generate("test prompt")

    @pytest.mark.asyncio
    async def test_generate_connection_error_raises(self) -> None:
        """Connection failure should raise RuntimeError."""
        backend = OllamaBackend(
            base_url="http://unreachable:11434", model="llama3:8b", timeout=0.1
        )
        # Replace client with one that raises on request
        backend._client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
            )
        )
        with pytest.raises(RuntimeError, match="connection error"):
            await backend.generate("test")

    @pytest.mark.asyncio
    async def test_health_check_success(self, backend_with_transport) -> None:
        """Health check should return True on HTTP 200."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert "/api/tags" in str(request.url)
            return make_json_response({"models": []})

        backend = backend_with_transport(handler)
        assert await backend.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_non_200(self, backend_with_transport) -> None:
        """Health check should return False on non-200 status."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=503)

        backend = backend_with_transport(handler)
        assert await backend.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self) -> None:
        """Health check should return False on connection error."""
        backend = OllamaBackend(
            base_url="http://unreachable:11434", model="llama3:8b", timeout=0.1
        )
        backend._client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
            )
        )
        assert await backend.health_check() is False


# --- VLLMBackend ---


class TestVLLMBackend:
    """Tests for VLLMBackend generate and health_check."""

    @pytest.fixture
    def backend_with_transport(self):
        """Create a VLLMBackend with a mock transport injected."""

        def _make(handler):
            backend = VLLMBackend(
                base_url="http://localhost:8000", model="mistral-7b"
            )
            backend._client = httpx.AsyncClient(transport=MockTransport(handler))
            return backend

        return _make

    @pytest.mark.asyncio
    async def test_generate_success(self, backend_with_transport) -> None:
        """Successful generate should return choices[0].text."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert "/v1/completions" in str(request.url)
            body = json.loads(request.content)
            assert body["model"] == "mistral-7b"
            assert body["prompt"] == "Analyze this"
            assert body["max_tokens"] == 256
            return make_json_response(
                {"choices": [{"text": "Analysis result", "index": 0}]}
            )

        backend = backend_with_transport(handler)
        result = await backend.generate("Analyze this", max_tokens=256)
        assert result == "Analysis result"

    @pytest.mark.asyncio
    async def test_generate_empty_choices(self, backend_with_transport) -> None:
        """Empty choices array should return empty string."""

        def handler(request: httpx.Request) -> httpx.Response:
            return make_json_response({"choices": []})

        backend = backend_with_transport(handler)
        result = await backend.generate("test")
        assert result == ""

    @pytest.mark.asyncio
    async def test_generate_http_error_raises(self, backend_with_transport) -> None:
        """HTTP error from vLLM should raise RuntimeError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return make_error_response(422)

        backend = backend_with_transport(handler)
        with pytest.raises(RuntimeError, match="vLLM generate failed"):
            await backend.generate("test")

    @pytest.mark.asyncio
    async def test_generate_connection_error_raises(self) -> None:
        """Connection failure should raise RuntimeError."""
        backend = VLLMBackend(
            base_url="http://unreachable:8000", model="mistral-7b", timeout=0.1
        )
        backend._client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
            )
        )
        with pytest.raises(RuntimeError, match="connection error"):
            await backend.generate("test")

    @pytest.mark.asyncio
    async def test_health_check_via_health_endpoint(
        self, backend_with_transport
    ) -> None:
        """Health check should succeed via /health endpoint."""

        def handler(request: httpx.Request) -> httpx.Response:
            if "/health" in str(request.url) and "/v1" not in str(request.url):
                return httpx.Response(status_code=200)
            return httpx.Response(status_code=404)

        backend = backend_with_transport(handler)
        assert await backend.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_fallback_to_v1_models(
        self, backend_with_transport
    ) -> None:
        """Health check should fall back to /v1/models if /health fails."""

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/health"):
                return httpx.Response(status_code=404)
            if "/v1/models" in url:
                return make_json_response({"data": [{"id": "mistral-7b"}]})
            return httpx.Response(status_code=404)

        backend = backend_with_transport(handler)
        assert await backend.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_all_fail(self) -> None:
        """Health check should return False if both endpoints fail."""
        backend = VLLMBackend(
            base_url="http://unreachable:8000", model="mistral-7b", timeout=0.1
        )
        backend._client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
            )
        )
        assert await backend.health_check() is False


# --- LlamaCppBackend ---


class TestLlamaCppBackend:
    """Tests for LlamaCppBackend generate and health_check."""

    @pytest.fixture
    def backend_with_transport(self):
        """Create a LlamaCppBackend with a mock transport injected."""

        def _make(handler):
            backend = LlamaCppBackend(base_url="http://localhost:8080")
            backend._client = httpx.AsyncClient(transport=MockTransport(handler))
            return backend

        return _make

    @pytest.mark.asyncio
    async def test_generate_success(self, backend_with_transport) -> None:
        """Successful generate should return the content field."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert "/completion" in str(request.url)
            body = json.loads(request.content)
            assert body["prompt"] == "Scan target"
            assert body["n_predict"] == 2048
            return make_json_response({"content": "Scanning complete."})

        backend = backend_with_transport(handler)
        result = await backend.generate("Scan target", max_tokens=2048)
        assert result == "Scanning complete."

    @pytest.mark.asyncio
    async def test_generate_missing_content_field(
        self, backend_with_transport
    ) -> None:
        """Missing 'content' field should return empty string."""

        def handler(request: httpx.Request) -> httpx.Response:
            return make_json_response({"stop": True})

        backend = backend_with_transport(handler)
        result = await backend.generate("test")
        assert result == ""

    @pytest.mark.asyncio
    async def test_generate_http_error_raises(self, backend_with_transport) -> None:
        """HTTP error from llama.cpp should raise RuntimeError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return make_error_response(503)

        backend = backend_with_transport(handler)
        with pytest.raises(RuntimeError, match="llama.cpp generate failed"):
            await backend.generate("test")

    @pytest.mark.asyncio
    async def test_generate_connection_error_raises(self) -> None:
        """Connection failure should raise RuntimeError."""
        backend = LlamaCppBackend(base_url="http://unreachable:8080", timeout=0.1)
        backend._client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
            )
        )
        with pytest.raises(RuntimeError, match="connection error"):
            await backend.generate("test")

    @pytest.mark.asyncio
    async def test_health_check_success(self, backend_with_transport) -> None:
        """Health check should return True on HTTP 200."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert "/health" in str(request.url)
            return httpx.Response(status_code=200, json={"status": "ok"})

        backend = backend_with_transport(handler)
        assert await backend.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_non_200(self, backend_with_transport) -> None:
        """Health check should return False on non-200 status."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=503)

        backend = backend_with_transport(handler)
        assert await backend.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self) -> None:
        """Health check should return False on connection error."""
        backend = LlamaCppBackend(base_url="http://unreachable:8080", timeout=0.1)
        backend._client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
            )
        )
        assert await backend.health_check() is False


# --- Default parameter tests ---


class TestDefaultParameters:
    """Verify default parameter values."""

    def test_ollama_default_timeout(self) -> None:
        backend = OllamaBackend(base_url="http://localhost:11434", model="test")
        assert backend._timeout == 10.0

    def test_vllm_default_timeout(self) -> None:
        backend = VLLMBackend(base_url="http://localhost:8000", model="test")
        assert backend._timeout == 10.0

    def test_llamacpp_default_timeout(self) -> None:
        backend = LlamaCppBackend(base_url="http://localhost:8080")
        assert backend._timeout == 10.0
