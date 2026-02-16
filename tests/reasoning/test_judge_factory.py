"""Tests for JudgeFactory — provider detection, fallback, and configuration."""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from sanna.reasoning.judge import BaseJudge
from sanna.reasoning.heuristic_judge import HeuristicJudge
from sanna.reasoning.judge_factory import JudgeFactory, NoProviderAvailableError

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


class TestJudgeFactory:
    def test_judge_factory_no_key_fallback(self, monkeypatch, caplog):
        """No API keys → HeuristicJudge with WARNING log."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("SANNA_JUDGE_PROVIDER", raising=False)

        with caplog.at_level(logging.WARNING, logger="sanna.reasoning.judge_factory"):
            judge = JudgeFactory.create()

        assert isinstance(judge, HeuristicJudge)
        assert any("No LLM API key found" in msg for msg in caplog.messages)

    @pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
    def test_judge_factory_anthropic_env(self, monkeypatch):
        """With ANTHROPIC_API_KEY set, returns AnthropicJudge."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("SANNA_JUDGE_PROVIDER", raising=False)

        from sanna.reasoning.llm_client import AnthropicJudge

        judge = JudgeFactory.create()
        assert isinstance(judge, AnthropicJudge)

    @pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
    def test_judge_factory_openai_env(self, monkeypatch):
        """With OPENAI_API_KEY set (no Anthropic), returns OpenAIJudge."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-456")
        monkeypatch.delenv("SANNA_JUDGE_PROVIDER", raising=False)

        from sanna.reasoning.llm_client import OpenAIJudge

        judge = JudgeFactory.create()
        assert isinstance(judge, OpenAIJudge)

    @pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
    def test_judge_factory_anthropic_takes_precedence(self, monkeypatch):
        """When both keys present, Anthropic takes precedence."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-456")
        monkeypatch.delenv("SANNA_JUDGE_PROVIDER", raising=False)

        from sanna.reasoning.llm_client import AnthropicJudge

        judge = JudgeFactory.create()
        assert isinstance(judge, AnthropicJudge)

    @pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
    def test_judge_factory_explicit_provider(self, monkeypatch):
        """Explicit provider overrides env detection."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-456")

        from sanna.reasoning.llm_client import OpenAIJudge

        judge = JudgeFactory.create(provider="openai")
        assert isinstance(judge, OpenAIJudge)

    def test_judge_factory_explicit_heuristic(self, monkeypatch):
        """Explicit provider='heuristic' returns HeuristicJudge."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

        judge = JudgeFactory.create(provider="heuristic")
        assert isinstance(judge, HeuristicJudge)

    @pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
    def test_judge_factory_env_var_provider(self, monkeypatch):
        """SANNA_JUDGE_PROVIDER env var selects provider."""
        monkeypatch.setenv("SANNA_JUDGE_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-456")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        from sanna.reasoning.llm_client import OpenAIJudge

        judge = JudgeFactory.create()
        assert isinstance(judge, OpenAIJudge)

    def test_judge_factory_env_var_heuristic(self, monkeypatch):
        """SANNA_JUDGE_PROVIDER=heuristic forces heuristic."""
        monkeypatch.setenv("SANNA_JUDGE_PROVIDER", "heuristic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

        judge = JudgeFactory.create()
        assert isinstance(judge, HeuristicJudge)

    def test_judge_factory_explicit_provider_no_key_raises(self, monkeypatch):
        """Provider specified but no key → raises ValueError."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("SANNA_JUDGE_PROVIDER", raising=False)

        with pytest.raises(ValueError, match="Explicit provider"):
            JudgeFactory.create(provider="anthropic")


# ---------------------------------------------------------------------------
# Error policy passthrough
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
class TestErrorPolicyPassthrough:
    def test_error_policy_passed_to_anthropic(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        from sanna.reasoning.llm_client import AnthropicJudge

        judge = JudgeFactory.create(error_policy="allow")
        assert isinstance(judge, AnthropicJudge)
        assert judge._error_policy == "allow"

    def test_error_policy_passed_to_openai(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        from sanna.reasoning.llm_client import OpenAIJudge

        judge = JudgeFactory.create(error_policy="score_zero")
        assert isinstance(judge, OpenAIJudge)
        assert judge._error_policy == "score_zero"


# ---------------------------------------------------------------------------
# NoProviderAvailableError
# ---------------------------------------------------------------------------


class TestNoProviderError:
    def test_detect_provider_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        from sanna.reasoning.judge_factory import _detect_provider

        with pytest.raises(NoProviderAvailableError):
            _detect_provider()


# ---------------------------------------------------------------------------
# Constitution on_api_error field
# ---------------------------------------------------------------------------


class TestConstitutionOnApiError:
    def test_constitution_on_api_error_field(self):
        """Parsing constitution with on_api_error field."""
        from sanna.constitution import parse_constitution

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "dev@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"}
            ],
            "reasoning": {
                "require_justification_for": ["must_escalate"],
                "on_api_error": "allow",
                "checks": {},
            },
        }

        constitution = parse_constitution(data)
        assert constitution.reasoning is not None
        assert constitution.reasoning.on_api_error == "allow"

    def test_constitution_on_api_error_default(self):
        """Missing on_api_error field defaults to 'block'."""
        from sanna.constitution import parse_constitution

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "dev@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"}
            ],
            "reasoning": {
                "require_justification_for": ["must_escalate"],
                "checks": {},
            },
        }

        constitution = parse_constitution(data)
        assert constitution.reasoning is not None
        assert constitution.reasoning.on_api_error == "block"


# ---------------------------------------------------------------------------
# Pipeline uses judge interface
# ---------------------------------------------------------------------------


class TestPipelineUsesJudge:
    @pytest.mark.asyncio
    async def test_pipeline_uses_judge_interface(self, monkeypatch):
        """Pipeline calls judge.evaluate(), not llm_client directly."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        from sanna.constitution import parse_constitution
        from sanna.reasoning.judge import JudgeResult, JudgeVerdict
        from sanna.reasoning.pipeline import ReasoningPipeline

        # Create a mock judge
        class MockJudge(BaseJudge):
            def __init__(self):
                self.called = False
                self.call_args = None

            def provider_name(self) -> str:
                return "mock"

            async def evaluate(self, tool_name, arguments, justification, invariant_id, constitution_context=None):
                self.called = True
                self.call_args = {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "justification": justification,
                    "invariant_id": invariant_id,
                }
                return JudgeResult(
                    score=0.95,
                    verdict=JudgeVerdict.PASS,
                    method="mock_llm",
                    explanation="Mock judge passed",
                    latency_ms=1.0,
                )

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "dev@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"}
            ],
            "reasoning": {
                "require_justification_for": ["must_escalate"],
                "on_check_error": "allow",
                "checks": {
                    "glc_005_llm_coherence": {
                        "enabled": True,
                        "enabled_for": ["must_escalate"],
                        "score_threshold": 0.6,
                    },
                },
            },
        }

        constitution = parse_constitution(data)
        mock_judge = MockJudge()
        pipeline = ReasoningPipeline(constitution, judge=mock_judge)

        result = await pipeline.evaluate(
            tool_name="delete_db",
            args={
                "id": 123,
                "_justification": "Cleanup per retention policy for compliance reasons",
            },
            enforcement_level="must_escalate",
        )

        # Judge was called
        assert mock_judge.called
        assert mock_judge.call_args["tool_name"] == "delete_db"
        assert mock_judge.call_args["invariant_id"] == "glc_005_llm_coherence"

        # Result includes LLM check
        llm_checks = [c for c in result.checks if c.check_id == "glc_005_llm_coherence"]
        assert len(llm_checks) == 1
        assert llm_checks[0].method == "mock_llm"
        assert llm_checks[0].passed is True
        assert llm_checks[0].score == 0.95
