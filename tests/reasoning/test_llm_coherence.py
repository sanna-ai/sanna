import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

httpx = pytest.importorskip("httpx")


@pytest.fixture(autouse=True)
def _set_api_key(monkeypatch):
    """Ensure ANTHROPIC_API_KEY is set for all tests."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")


def _make_mock_response(text: str) -> MagicMock:
    """Build a mock httpx response returning the given text.

    Uses MagicMock (not AsyncMock) because httpx response methods
    like .json() and .raise_for_status() are synchronous.
    """
    resp = MagicMock()
    resp.json.return_value = {"content": [{"text": text}]}
    resp.raise_for_status.return_value = None
    return resp


def _patch_post(mock_client_cls, response):
    """Wire up mock_client_cls so `async with AsyncClient() as c: await c.post(...)` works."""
    mock_instance = AsyncMock()
    mock_instance.post.return_value = response
    mock_client_cls.return_value.__aenter__.return_value = mock_instance
    return mock_instance


def _patch_post_error(mock_client_cls, exception):
    """Wire up mock_client_cls so `await c.post(...)` raises."""
    mock_instance = AsyncMock()
    mock_instance.post.side_effect = exception
    mock_client_cls.return_value.__aenter__.return_value = mock_instance
    return mock_instance


@pytest.mark.asyncio
class TestLLMCoherenceCheck:
    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_high_score_passes(self, mock_client_cls):
        """LLM returns 0.9 -> check passes."""
        _patch_post(mock_client_cls, _make_mock_response("0.9"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({"score_threshold": 0.6, "timeout_ms": 2000})
        result = await check.execute(
            "Cleanup per retention policy",
            {"tool_name": "delete_db", "args": {"id": 123}},
        )

        assert result.passed is True
        assert result.score == 0.9
        assert result.latency_ms >= 0
        assert result.check_id == "glc_005_llm_coherence"
        assert result.method == "llm_coherence"

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_low_score_fails(self, mock_client_cls):
        """LLM returns 0.3 -> check fails."""
        _patch_post(mock_client_cls, _make_mock_response("0.3"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({"score_threshold": 0.6})
        result = await check.execute(
            "because you asked",
            {"tool_name": "delete_db", "args": {}},
        )

        assert result.passed is False
        assert result.score == 0.3
        assert result.details["score"] == 0.3
        assert result.details["threshold"] == 0.6

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_exact_threshold_passes(self, mock_client_cls):
        """Score exactly at threshold passes."""
        _patch_post(mock_client_cls, _make_mock_response("0.6"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({"score_threshold": 0.6})
        result = await check.execute(
            "Reasonable justification",
            {"tool_name": "read_file", "args": {"path": "/tmp/x"}},
        )

        assert result.passed is True
        assert result.score == 0.6

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_timeout_partial_assurance(self, mock_client_cls):
        """LLM timeout -> score 0.5, partial assurance."""
        _patch_post_error(mock_client_cls, httpx.TimeoutException("timeout"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({"timeout_ms": 1000})
        result = await check.execute(
            "test justification",
            {"tool_name": "test", "args": {}},
        )

        assert result.score == 0.5
        assert result.details["error"] == "timeout"
        assert result.details["timeout_ms"] == 1000

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_api_error_partial_assurance(self, mock_client_cls):
        """LLM API error -> score 0.5."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        _patch_post_error(
            mock_client_cls,
            httpx.HTTPStatusError("error", request=MagicMock(), response=mock_resp),
        )

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck()
        result = await check.execute(
            "test justification",
            {"tool_name": "test", "args": {}},
        )

        assert result.score == 0.5
        assert result.details["error"] == "api_error"
        assert result.details["status_code"] == 500

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_invalid_score_range_returns_partial(self, mock_client_cls):
        """LLM returns score > 1.0 -> fallback to 0.5."""
        _patch_post(mock_client_cls, _make_mock_response("1.5"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck()
        result = await check.execute(
            "test justification",
            {"tool_name": "test", "args": {}},
        )

        assert result.score == 0.5
        assert result.details["error"] == "invalid_score_range"

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_parse_error_partial_assurance(self, mock_client_cls):
        """LLM returns unparseable response -> score 0.5."""
        _patch_post(mock_client_cls, _make_mock_response("I cannot provide a score"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck()
        result = await check.execute(
            "test justification",
            {"tool_name": "test", "args": {}},
        )

        assert result.score == 0.5
        assert result.details["error"] == "parse_error"

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_score_with_prefix_text(self, mock_client_cls):
        """LLM returns 'Score: 0.8' -> extracts 0.8."""
        _patch_post(mock_client_cls, _make_mock_response("Score: 0.8"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({"score_threshold": 0.6})
        result = await check.execute(
            "Cleanup per retention policy",
            {"tool_name": "delete_db", "args": {"id": 123}},
        )

        assert result.passed is True
        assert result.score == 0.8

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_custom_threshold(self, mock_client_cls):
        """Custom score_threshold is respected."""
        _patch_post(mock_client_cls, _make_mock_response("0.7"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({"score_threshold": 0.8})
        result = await check.execute(
            "Some justification",
            {"tool_name": "test", "args": {}},
        )

        assert result.passed is False
        assert result.score == 0.7

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_missing_context_defaults(self, mock_client_cls):
        """Missing tool_name/args in context use defaults."""
        _patch_post(mock_client_cls, _make_mock_response("0.9"))

        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck()
        result = await check.execute("Some justification", {})

        assert result.passed is True
        assert result.score == 0.9


class TestLLMClientFactory:
    def test_unsupported_provider_raises(self):
        from sanna.reasoning.llm_client import create_llm_client

        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            create_llm_client("openai", "key-123")

    def test_anthropic_provider_creates_client(self):
        from sanna.reasoning.llm_client import AnthropicClient, create_llm_client

        client = create_llm_client("anthropic", "key-123")
        assert isinstance(client, AnthropicClient)

    def test_model_priority_explicit_param(self, monkeypatch):
        """Explicit model param takes precedence over env var."""
        monkeypatch.setenv("SANNA_LLM_MODEL", "env-model")

        from sanna.reasoning.llm_client import AnthropicClient

        client = AnthropicClient("key", model="explicit-model")
        assert client.model == "explicit-model"

    def test_model_priority_env_var(self, monkeypatch):
        """Env var used when no explicit param."""
        monkeypatch.setenv("SANNA_LLM_MODEL", "env-model")

        from sanna.reasoning.llm_client import AnthropicClient

        client = AnthropicClient("key")
        assert client.model == "env-model"

    def test_model_priority_default(self, monkeypatch):
        """Default model used when no param and no env var."""
        monkeypatch.delenv("SANNA_LLM_MODEL", raising=False)

        from sanna.reasoning.llm_client import AnthropicClient

        client = AnthropicClient("key")
        assert client.model == "claude-sonnet-4-20250514"


class TestLLMCoherenceCheckInit:
    def test_missing_api_key_raises(self, monkeypatch):
        """Missing ANTHROPIC_API_KEY raises ValueError."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        from sanna.reasoning.checks import LLMCoherenceCheck

        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            LLMCoherenceCheck()

    def test_default_config_values(self):
        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck()
        assert check.timeout_ms == 2000
        assert check.score_threshold == 0.6

    def test_custom_config_values(self):
        from sanna.reasoning.checks import LLMCoherenceCheck

        check = LLMCoherenceCheck({
            "timeout_ms": 5000,
            "score_threshold": 0.8,
        })
        assert check.timeout_ms == 5000
        assert check.score_threshold == 0.8
