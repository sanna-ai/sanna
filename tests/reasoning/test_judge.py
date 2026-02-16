"""Tests for BaseJudge interface, HeuristicJudge, and LLM judge implementations."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sanna.reasoning.judge import BaseJudge, JudgeResult, JudgeVerdict
from sanna.reasoning.heuristic_judge import HeuristicJudge

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# ---------------------------------------------------------------------------
# Heuristic judge
# ---------------------------------------------------------------------------


class TestHeuristicJudge:
    @pytest.mark.asyncio
    async def test_heuristic_judge_basic_pass(self):
        """Justification with tool reference scores > 0.5."""
        judge = HeuristicJudge()
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="We need to delete_db because the retention policy requires removal of old records after 90 days",
            invariant_id="glc_005_coherence",
        )

        assert result.score > 0.5
        assert result.verdict in (JudgeVerdict.PASS, JudgeVerdict.HEURISTIC)
        assert result.method == "heuristic"
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_heuristic_judge_empty_justification(self):
        """Empty justification → score 0.0."""
        judge = HeuristicJudge()
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="",
            invariant_id="glc_005_coherence",
        )

        assert result.score == 0.0
        assert result.verdict == JudgeVerdict.FAIL
        assert "missing or empty" in result.explanation

    @pytest.mark.asyncio
    async def test_heuristic_judge_parroting(self):
        """Blocklist match → low score."""
        judge = HeuristicJudge()
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="because you asked me to remove this record from the system",
            invariant_id="glc_005_coherence",
        )

        # "because you asked" is in the default blocklist
        assert result.score < 0.5
        assert "blocklist" in result.explanation.lower()

    @pytest.mark.asyncio
    async def test_heuristic_judge_short_justification(self):
        """Short justification → low score."""
        judge = HeuristicJudge()
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="ok",
            invariant_id="glc_005_coherence",
        )

        assert result.score < 0.5
        assert "too short" in result.explanation

    @pytest.mark.asyncio
    async def test_heuristic_provider_name(self):
        """provider_name() returns 'heuristic'."""
        judge = HeuristicJudge()
        assert judge.provider_name() == "heuristic"

    @pytest.mark.asyncio
    async def test_heuristic_judge_no_tool_reference(self):
        """Missing tool name reference → partial credit (0.5 for that sub-check)."""
        judge = HeuristicJudge()
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="The retention policy requires removal of old records after 90 days for compliance",
            invariant_id="glc_005_coherence",
        )

        # Passes presence, substance, no-parroting, but not tool reference (0.5)
        # min([1.0, 1.0, 1.0, 0.5]) = 0.5
        assert result.score == 0.5
        assert result.verdict == JudgeVerdict.HEURISTIC

    @pytest.mark.asyncio
    async def test_heuristic_judge_custom_blocklist(self):
        """Custom blocklist is used."""
        judge = HeuristicJudge(blocklist=["forbidden phrase"])
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="This is a forbidden phrase that should be caught by the custom blocklist check",
            invariant_id="test",
        )

        assert "blocklist" in result.explanation.lower()
        assert result.score < 0.5

    @pytest.mark.asyncio
    async def test_heuristic_judge_custom_min_length(self):
        """Custom min_length is respected."""
        judge = HeuristicJudge(min_length=5)
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="Short test justification here",
            invariant_id="test",
        )

        # 30 chars > 5 min_length → passes substance
        assert result.score >= 0.5


# ---------------------------------------------------------------------------
# LLM judge implementations
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
class TestAnthropicJudge:
    @pytest.fixture(autouse=True)
    def _set_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

    def _mock_response(self, text: str) -> MagicMock:
        resp = MagicMock()
        resp.json.return_value = {"content": [{"text": text}]}
        resp.raise_for_status.return_value = None
        return resp

    def _patch_post(self, mock_cls, response):
        mock_instance = AsyncMock()
        mock_instance.post.return_value = response
        mock_cls.return_value.__aenter__.return_value = mock_instance
        return mock_instance

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_anthropic_judge_pass(self, mock_cls):
        from sanna.reasoning.llm_client import AnthropicJudge

        self._patch_post(mock_cls, self._mock_response("0.9"))

        judge = AnthropicJudge(api_key="test-key")
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="Cleanup per retention policy",
            invariant_id="glc_005",
        )

        assert result.score == 0.9
        assert result.verdict == JudgeVerdict.PASS
        assert result.method == "anthropic_llm"
        assert result.error_detail is None

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_error_policy_block(self, mock_cls):
        """API error + block policy → score 0.0, verdict ERROR."""
        from sanna.reasoning.llm_client import AnthropicJudge

        mock_instance = AsyncMock()
        mock_instance.post.side_effect = httpx.TimeoutException("timeout")
        mock_cls.return_value.__aenter__.return_value = mock_instance

        judge = AnthropicJudge(api_key="test-key", error_policy="block")
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="test",
            invariant_id="glc_005",
        )

        assert result.score == 0.0
        assert result.verdict == JudgeVerdict.ERROR
        assert result.error_detail is not None
        assert "TimeoutException" in result.error_detail

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_error_policy_allow(self, mock_cls):
        """API error + allow policy → score 1.0, verdict ERROR."""
        from sanna.reasoning.llm_client import AnthropicJudge

        mock_instance = AsyncMock()
        mock_instance.post.side_effect = httpx.TimeoutException("timeout")
        mock_cls.return_value.__aenter__.return_value = mock_instance

        judge = AnthropicJudge(api_key="test-key", error_policy="allow")
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="test",
            invariant_id="glc_005",
        )

        assert result.score == 1.0
        assert result.verdict == JudgeVerdict.ERROR
        assert result.error_detail is not None

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_error_policy_score_zero(self, mock_cls):
        """API error + score_zero policy → score 0.0, verdict ERROR."""
        from sanna.reasoning.llm_client import AnthropicJudge

        mock_instance = AsyncMock()
        mock_instance.post.side_effect = Exception("connection failed")
        mock_cls.return_value.__aenter__.return_value = mock_instance

        judge = AnthropicJudge(api_key="test-key", error_policy="score_zero")
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="test",
            invariant_id="glc_005",
        )

        assert result.score == 0.0
        assert result.verdict == JudgeVerdict.ERROR
        assert result.error_detail is not None

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_error_result_includes_detail(self, mock_cls):
        """Error results always have error_detail populated."""
        from sanna.reasoning.llm_client import AnthropicJudge

        mock_instance = AsyncMock()
        mock_instance.post.side_effect = ConnectionError("refused")
        mock_cls.return_value.__aenter__.return_value = mock_instance

        judge = AnthropicJudge(api_key="test-key", error_policy="block")
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="test",
            invariant_id="glc_005",
        )

        assert result.verdict == JudgeVerdict.ERROR
        assert result.error_detail is not None
        assert len(result.error_detail) > 0
        assert "ConnectionError" in result.error_detail

    def test_anthropic_judge_provider_name(self):
        from sanna.reasoning.llm_client import AnthropicJudge

        judge = AnthropicJudge(api_key="test-key")
        assert judge.provider_name() == "anthropic"


@pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
class TestOpenAIJudge:
    def _mock_openai_response(self, text: str) -> MagicMock:
        resp = MagicMock()
        resp.json.return_value = {
            "choices": [{"message": {"content": text}}]
        }
        resp.raise_for_status.return_value = None
        return resp

    def _patch_post(self, mock_cls, response):
        mock_instance = AsyncMock()
        mock_instance.post.return_value = response
        mock_cls.return_value.__aenter__.return_value = mock_instance
        return mock_instance

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_openai_judge_pass(self, mock_cls):
        from sanna.reasoning.llm_client import OpenAIJudge

        self._patch_post(mock_cls, self._mock_openai_response("0.85"))

        judge = OpenAIJudge(api_key="test-key")
        result = await judge.evaluate(
            tool_name="delete_db",
            arguments={"id": 123},
            justification="Cleanup per retention policy",
            invariant_id="glc_005",
        )

        assert result.score == 0.85
        assert result.verdict == JudgeVerdict.PASS
        assert result.method == "openai_llm"

    def test_openai_judge_provider_name(self):
        from sanna.reasoning.llm_client import OpenAIJudge

        judge = OpenAIJudge(api_key="test-key")
        assert judge.provider_name() == "openai"

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_openai_error_policy_block(self, mock_cls):
        from sanna.reasoning.llm_client import OpenAIJudge

        mock_instance = AsyncMock()
        mock_instance.post.side_effect = httpx.TimeoutException("timeout")
        mock_cls.return_value.__aenter__.return_value = mock_instance

        judge = OpenAIJudge(api_key="test-key", error_policy="block")
        result = await judge.evaluate(
            tool_name="test",
            arguments={},
            justification="test",
            invariant_id="glc_005",
        )

        assert result.score == 0.0
        assert result.verdict == JudgeVerdict.ERROR


# ---------------------------------------------------------------------------
# Sanitize args helper
# ---------------------------------------------------------------------------


class TestSanitizeArgs:
    def test_sanitize_args_strips_justification(self):
        """_justification key removed from displayed args."""
        from sanna.reasoning.llm_client import _sanitize_args

        result = _sanitize_args({
            "id": 123,
            "_justification": "secret reasoning",
            "name": "test",
        })

        assert "_justification" not in result
        assert "123" in result
        assert "test" in result

    def test_sanitize_args_truncation(self):
        """Oversized args truncated to 2000 chars."""
        from sanna.reasoning.llm_client import _sanitize_args

        big_args = {"data": "x" * 5000}
        result = _sanitize_args(big_args)

        assert len(result) <= 2000
