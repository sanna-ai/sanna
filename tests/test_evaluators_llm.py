"""Tests for LLM-as-Judge semantic evaluators.

All tests mock urllib.request.urlopen to avoid real API calls.
"""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch, MagicMock

import pytest

from sanna.evaluators import clear_evaluators, get_evaluator, list_evaluators
from sanna.evaluators.llm import (
    LLMJudge,
    register_llm_evaluators,
    enable_llm_checks,
    _CHECK_ALIASES,
    _CHECK_PROMPTS,
)
from sanna.receipt import CheckResult


@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear evaluator registry before and after each test."""
    clear_evaluators()
    yield
    clear_evaluators()


def _mock_api_response(content_text: str, status_code: int = 200):
    """Create a mock response from urlopen."""
    body = json.dumps({
        "content": [{"type": "text", "text": content_text}],
        "model": "claude-sonnet-4-5-20250929",
        "role": "assistant",
    }).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestLLMJudgeInit:
    """LLMJudge initialization."""

    def test_requires_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="api_key is required"):
                LLMJudge(api_key="")

    def test_accepts_explicit_api_key(self):
        judge = LLMJudge(api_key="sk-ant-test")
        assert judge.api_key == "sk-ant-test"

    def test_reads_env_var(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-env"}):
            judge = LLMJudge()
            assert judge.api_key == "sk-env"

    def test_custom_model_and_url(self):
        judge = LLMJudge(
            api_key="sk-ant-test",
            model="claude-haiku-4-5-20251001",
            base_url="https://custom.api.example.com/",
        )
        assert judge.model == "claude-haiku-4-5-20251001"
        assert judge.base_url == "https://custom.api.example.com"


class TestLLMJudgeEvaluate:
    """LLMJudge.evaluate() with mocked API."""

    def test_successful_pass(self):
        judge = LLMJudge(api_key="sk-test")
        response = _mock_api_response(json.dumps({
            "pass": True,
            "confidence": 0.95,
            "evidence": "No fabrication detected",
        }))
        with patch("urllib.request.urlopen", return_value=response):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert isinstance(result, CheckResult)
        assert result.passed is True
        assert result.check_id == "INV_NO_FABRICATION"
        assert "confidence=0.95" in result.details

    def test_successful_fail(self):
        judge = LLMJudge(api_key="sk-test")
        response = _mock_api_response(json.dumps({
            "pass": False,
            "confidence": 0.88,
            "evidence": "Output contains unsupported claim",
        }))
        with patch("urllib.request.urlopen", return_value=response):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert result.passed is False
        assert result.severity == "critical"
        assert "unsupported claim" in result.details

    def test_malformed_json_returns_errored(self):
        judge = LLMJudge(api_key="sk-test")
        response = _mock_api_response("not json at all")
        with patch("urllib.request.urlopen", return_value=response):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert result.passed is False
        assert "ERRORED" in result.details

    def test_non_boolean_pass_returns_errored(self):
        judge = LLMJudge(api_key="sk-test")
        response = _mock_api_response(json.dumps({
            "pass": "yes",
            "confidence": 0.9,
            "evidence": "ok",
        }))
        with patch("urllib.request.urlopen", return_value=response):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert result.passed is False
        assert "ERRORED" in result.details
        assert "'pass' field must be boolean" in result.details

    def test_timeout_returns_errored(self):
        judge = LLMJudge(api_key="sk-test", timeout=1)
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert result.passed is False
        assert "ERRORED" in result.details

    def test_http_500_returns_errored(self):
        judge = LLMJudge(api_key="sk-test")
        import urllib.error
        error = urllib.error.HTTPError(
            "https://api.anthropic.com/v1/messages",
            500,
            "Internal Server Error",
            {},
            BytesIO(b"error"),
        )
        with patch("urllib.request.urlopen", side_effect=error):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert result.passed is False
        assert "ERRORED" in result.details

    def test_empty_api_response_returns_errored(self):
        judge = LLMJudge(api_key="sk-test")
        body = json.dumps({"content": []}).encode("utf-8")
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=resp):
            result = judge.evaluate("INV_NO_FABRICATION", "ctx", "out", "const")
        assert result.passed is False
        assert "ERRORED" in result.details

    def test_unknown_check_id(self):
        judge = LLMJudge(api_key="sk-test")
        result = judge.evaluate("INV_UNKNOWN_CHECK", "ctx", "out", "const")
        assert result.passed is False
        assert "No prompt template" in result.details


class TestPromptConstruction:
    """Verify prompts are constructed correctly per check type."""

    def test_all_five_checks_have_prompts(self):
        assert set(_CHECK_PROMPTS.keys()) == {"C1", "C2", "C3", "C4", "C5"}

    def test_prompt_includes_context_and_output(self):
        judge = LLMJudge(api_key="sk-test")
        response = _mock_api_response(json.dumps({
            "pass": True, "confidence": 0.9, "evidence": "ok",
        }))
        with patch("urllib.request.urlopen", return_value=response) as mock_urlopen:
            judge.evaluate("INV_NO_FABRICATION", "my context", "my output", "my constitution")
        # Extract the prompt from the request
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        prompt = body["messages"][0]["content"]
        assert "my context" in prompt
        assert "my output" in prompt
        assert "my constitution" in prompt

    def test_each_check_uses_correct_template(self):
        judge = LLMJudge(api_key="sk-test")
        response = _mock_api_response(json.dumps({
            "pass": True, "confidence": 0.9, "evidence": "ok",
        }))

        for alias, inv_id in _CHECK_ALIASES.items():
            with patch("urllib.request.urlopen", return_value=response) as mock_urlopen:
                judge.evaluate(inv_id, "ctx", "out", "const")
            req = mock_urlopen.call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            prompt = body["messages"][0]["content"]
            # Each check's prompt should contain its distinctive keyword
            if alias == "C1":
                assert "fabricat" in prompt.lower()
            elif alias == "C2":
                assert "unmarked" in prompt.lower()
            elif alias == "C3":
                assert "goal drift" in prompt.lower()
            elif alias == "C4":
                assert "contradict" in prompt.lower()
            elif alias == "C5":
                assert "hidden state" in prompt.lower()


class TestRegistration:
    """register_llm_evaluators and enable_llm_checks."""

    def test_register_all_five(self):
        judge = LLMJudge(api_key="sk-test")
        registered = register_llm_evaluators(judge)
        assert len(registered) == 5
        for inv_id in _CHECK_ALIASES.values():
            assert inv_id in registered
            assert get_evaluator(inv_id) is not None

    def test_register_subset(self):
        judge = LLMJudge(api_key="sk-test")
        registered = register_llm_evaluators(judge, checks=["C1", "C3"])
        assert len(registered) == 2
        assert "INV_NO_FABRICATION" in registered
        assert "INV_NO_GOAL_DRIFT" in registered
        # C2 should NOT be registered
        assert get_evaluator("INV_NO_UNMARKED_INFERENCE") is None

    def test_enable_llm_checks_convenience(self):
        registered = enable_llm_checks(api_key="sk-test", checks=["C1"])
        assert registered == ["INV_NO_FABRICATION"]
        assert get_evaluator("INV_NO_FABRICATION") is not None

    def test_enable_llm_checks_all(self):
        registered = enable_llm_checks(api_key="sk-test")
        assert len(registered) == 5

    def test_registered_evaluator_calls_judge(self):
        judge = LLMJudge(api_key="sk-test")
        register_llm_evaluators(judge, checks=["C1"])
        evaluator = get_evaluator("INV_NO_FABRICATION")

        response = _mock_api_response(json.dumps({
            "pass": True, "confidence": 0.95, "evidence": "clean",
        }))
        with patch("urllib.request.urlopen", return_value=response):
            result = evaluator("my context", "my output", {"doc": "constitution"}, {})
        assert isinstance(result, CheckResult)
        assert result.passed is True

    def test_unknown_check_raises(self):
        judge = LLMJudge(api_key="sk-test")
        with pytest.raises(ValueError, match="Unknown check"):
            register_llm_evaluators(judge, checks=["C99"])


class TestExistingEvaluatorsUnaffected:
    """Importing llm module does not affect existing evaluators."""

    def test_deterministic_checks_unaffected(self):
        """Importing llm does not auto-register anything."""
        # Just importing should not register evaluators
        import sanna.evaluators.llm  # noqa: F401
        assert list_evaluators() == []
