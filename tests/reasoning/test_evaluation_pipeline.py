from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sanna.constitution import parse_constitution
from sanna.reasoning.evaluator import ReasoningEvaluator
from sanna.reasoning.pipeline import ReasoningPipeline

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_constitution(reasoning_data=None, version="1.1"):
    """Build a minimal Constitution via parse_constitution."""
    data = {
        "sanna_constitution": "0.1.0",
        "identity": {"agent_name": "test-agent", "domain": "testing"},
        "provenance": {
            "authored_by": "dev@test.com",
            "approved_by": ["approver@test.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Test boundary",
                "category": "scope",
                "severity": "high",
            },
        ],
        "version": version,
    }
    if reasoning_data is not None:
        data["reasoning"] = reasoning_data
    return parse_constitution(data)


def _reasoning_config(**overrides):
    """Build a reasoning config dict (deterministic checks only)."""
    config = {
        "require_justification_for": ["must_escalate"],
        "on_missing_justification": "block",
        "on_check_error": "block",
        "checks": {
            "glc_minimum_substance": {"enabled": True, "min_length": 20},
            "glc_no_parroting": {"enabled": True},
        },
    }
    config.update(overrides)
    return config


def _reasoning_with_llm(enabled_for=None):
    """Build a reasoning config dict including LLM coherence check."""
    if enabled_for is None:
        enabled_for = ["must_escalate"]
    return {
        "require_justification_for": ["must_escalate"],
        "on_missing_justification": "block",
        "on_check_error": "block",
        "checks": {
            "glc_minimum_substance": {"enabled": True, "min_length": 20},
            "glc_no_parroting": {"enabled": True},
            "glc_llm_coherence": {
                "enabled": True,
                "enabled_for": enabled_for,
                "score_threshold": 0.6,
            },
        },
    }


# LLM mock helpers (same pattern as test_llm_coherence.py)

def _make_mock_response(text: str) -> MagicMock:
    """Build a mock httpx response returning the given text."""
    resp = MagicMock()
    resp.json.return_value = {"content": [{"text": text}]}
    resp.raise_for_status.return_value = None
    return resp


def _patch_post(mock_client_cls, response):
    """Wire up mock_client_cls so async context manager + post() works."""
    mock_instance = AsyncMock()
    mock_instance.post.return_value = response
    mock_client_cls.return_value.__aenter__.return_value = mock_instance
    return mock_instance


# ---------------------------------------------------------------------------
# Deterministic pipeline tests
# ---------------------------------------------------------------------------


class TestReasoningPipeline:
    @pytest.mark.asyncio
    async def test_all_checks_pass_full_assurance(self):
        """All deterministic checks pass -> assurance=full."""
        constitution = _make_constitution(_reasoning_config())
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="delete_db",
            args={"id": 123, "_justification": "Cleanup per retention policy"},
            enforcement_level="must_escalate",
        )

        assert result.assurance == "full"
        assert result.passed is True
        assert result.overall_score > 0.0
        assert len(result.checks) == 3  # glc_001, glc_002, glc_003

    @pytest.mark.asyncio
    async def test_deterministic_failure_partial_assurance(self):
        """Deterministic check fails -> assurance=partial."""
        constitution = _make_constitution(_reasoning_config())
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="delete_db",
            args={"id": 123, "_justification": "ok"},  # Too short
            enforcement_level="must_escalate",
        )

        assert result.assurance == "partial"
        assert result.passed is False
        assert result.overall_score == 0.0

    @pytest.mark.asyncio
    async def test_missing_justification_none_assurance(self):
        """Missing required justification -> assurance=none."""
        constitution = _make_constitution(_reasoning_config())
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="delete_db",
            args={"id": 123},  # No _justification
            enforcement_level="must_escalate",
        )

        assert result.assurance == "none"
        assert result.passed is False
        assert result.failure_reason == "missing_required_justification"

    def test_strip_justification(self):
        """_justification removed from args."""
        args = {"id": 123, "_justification": "test"}
        stripped = ReasoningEvaluator.strip_justification(args)

        assert "_justification" not in stripped
        assert stripped["id"] == 123

    @pytest.mark.asyncio
    async def test_overall_score_minimum(self):
        """overall_score = min(all check scores)."""
        constitution = _make_constitution(_reasoning_config())
        evaluator = ReasoningEvaluator(constitution)

        # glc_001 passes (non-empty), glc_002 passes (>20 chars),
        # glc_003 fails (contains "because you asked") -> score 0.0
        result = await evaluator.evaluate(
            tool_name="delete_db",
            args={
                "id": 123,
                "_justification": "because you asked me to delete this data",
            },
            enforcement_level="must_escalate",
        )

        assert result.overall_score == 0.0

    @pytest.mark.asyncio
    async def test_reasoning_disabled(self):
        """Constitution without reasoning -> reasoning disabled."""
        constitution = _make_constitution()  # No reasoning config
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="test",
            args={"_justification": "test"},
            enforcement_level="must_escalate",
        )

        assert result.passed is True
        assert result.failure_reason == "reasoning_disabled"

    @pytest.mark.asyncio
    async def test_justification_not_required_passes(self):
        """Justification not required for can_execute -> passes."""
        constitution = _make_constitution(_reasoning_config())
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="read_db",
            args={"id": 123},  # No justification
            enforcement_level="can_execute",  # Not in require_justification_for
        )

        assert result.passed is True
        assert result.failure_reason == "justification_not_required"

    @pytest.mark.asyncio
    async def test_on_check_error_block_early_termination(self):
        """on_check_error='block' terminates pipeline on first failure."""
        constitution = _make_constitution(_reasoning_config(on_check_error="block"))
        evaluator = ReasoningEvaluator(constitution)

        # "short" passes glc_001 (non-empty) but fails glc_002 (< 20 chars)
        result = await evaluator.evaluate(
            tool_name="test",
            args={"_justification": "short"},
            enforcement_level="must_escalate",
        )

        assert result.passed is False
        assert result.assurance == "partial"
        assert len(result.checks) == 2  # glc_001 (pass) + glc_002 (fail)
        assert result.checks[0].passed is True
        assert result.checks[1].passed is False

    @pytest.mark.asyncio
    async def test_on_check_error_allow_continues(self):
        """on_check_error='allow' continues pipeline after failure."""
        constitution = _make_constitution(_reasoning_config(on_check_error="allow"))
        evaluator = ReasoningEvaluator(constitution)

        # "short" fails glc_002, but pipeline continues to glc_003
        result = await evaluator.evaluate(
            tool_name="test",
            args={"_justification": "short"},
            enforcement_level="must_escalate",
        )

        assert len(result.checks) == 3  # All 3 checks ran
        assert result.passed is False
        assert result.assurance == "partial"

    @pytest.mark.asyncio
    async def test_empty_justification_fails_presence(self):
        """Empty string justification fails glc_001."""
        constitution = _make_constitution(_reasoning_config())
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="test",
            args={"_justification": ""},
            enforcement_level="must_escalate",
        )

        # Empty string → missing_required_justification (not even checked)
        assert result.passed is False
        assert result.failure_reason == "missing_required_justification"

    @pytest.mark.asyncio
    async def test_pipeline_direct_usage(self):
        """ReasoningPipeline can be used directly."""
        constitution = _make_constitution(_reasoning_config())
        pipeline = ReasoningPipeline(constitution)

        assert pipeline.enabled is True

        result = await pipeline.evaluate(
            tool_name="read_file",
            args={"path": "/tmp/x", "_justification": "Reading config for deployment"},
            enforcement_level="must_escalate",
        )

        assert result.assurance == "full"
        assert result.passed is True


# ---------------------------------------------------------------------------
# LLM integration tests (require httpx)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_HTTPX, reason="httpx not installed")
@pytest.mark.asyncio
class TestLLMIntegration:
    @pytest.fixture(autouse=True)
    def _set_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_llm_runs_for_must_escalate(self, mock_client_cls):
        """LLM check runs when enforcement_level matches enabled_for."""
        _patch_post(mock_client_cls, _make_mock_response("0.9"))

        constitution = _make_constitution(_reasoning_with_llm(["must_escalate"]))
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="delete_db",
            args={"id": 123, "_justification": "Cleanup per retention policy"},
            enforcement_level="must_escalate",
        )

        assert result.assurance == "full"
        assert result.passed is True
        assert len(result.checks) == 4  # glc_001, 002, 003, 005

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_llm_skipped_for_can_execute(self, mock_client_cls):
        """LLM check doesn't run when enforcement_level not in enabled_for."""
        _patch_post(mock_client_cls, _make_mock_response("0.9"))

        constitution = _make_constitution(_reasoning_with_llm(["must_escalate"]))
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="read_db",
            args={"id": 123, "_justification": "Need to check data for report"},
            enforcement_level="can_execute",
        )

        # Should only have deterministic checks (no LLM)
        assert len(result.checks) == 3
        assert result.passed is True

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_llm_failure_partial_assurance(self, mock_client_cls):
        """LLM returns low score -> assurance=partial."""
        _patch_post(mock_client_cls, _make_mock_response("0.3"))

        constitution = _make_constitution(_reasoning_with_llm(["must_escalate"]))
        evaluator = ReasoningEvaluator(constitution)

        result = await evaluator.evaluate(
            tool_name="delete_db",
            args={"id": 123, "_justification": "Cleanup per retention policy"},
            enforcement_level="must_escalate",
        )

        assert result.assurance == "partial"
        assert result.passed is False
        assert result.overall_score == 0.3
        assert len(result.checks) == 4

    @patch("sanna.reasoning.llm_client.httpx.AsyncClient")
    async def test_llm_not_run_when_deterministic_fails(self, mock_client_cls):
        """LLM check skipped when deterministic checks fail."""
        _patch_post(mock_client_cls, _make_mock_response("0.9"))

        config = _reasoning_with_llm(["must_escalate"])
        config["on_check_error"] = "allow"  # Don't block, but still skip LLM
        constitution = _make_constitution(config)
        evaluator = ReasoningEvaluator(constitution)

        # "short" fails glc_002 → LLM should not run
        result = await evaluator.evaluate(
            tool_name="test",
            args={"_justification": "short"},
            enforcement_level="must_escalate",
        )

        # Only deterministic checks (LLM skipped because not all passed)
        assert len(result.checks) == 3
        assert result.passed is False
