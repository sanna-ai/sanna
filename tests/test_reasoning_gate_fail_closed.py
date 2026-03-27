"""SAN-64: Reasoning gate must fail closed in enforce mode.

When a reasoning evaluation throws an exception:
- on_check_error="block" (enforce/default) → action BLOCKED
- on_check_error="allow" (monitor) → action proceeds (logged)
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
import yaml

from sanna.constitution import load_constitution, sign_constitution, save_constitution
from sanna.crypto import generate_keypair
from sanna.middleware import (
    _run_reasoning_gate,
    _run_reasoning_gate_async,
    sanna_observe,
    SannaHaltError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_signed_constitution(tmp_path, *, on_check_error="block"):
    """Create a signed constitution with reasoning config."""
    priv_path, pub_path = generate_keypair(str(tmp_path))

    data = {
        "sanna_constitution": "1.1",
        "identity": {"agent_name": "test-agent", "domain": "testing"},
        "provenance": {
            "authored_by": "test@dev.com",
            "approved_by": ["approver@dev.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {"id": "B001", "description": "Test", "category": "scope", "severity": "high"},
        ],
        "invariants": [],
        "reasoning": {
            "require_justification_for": ["must_escalate", "cannot_execute"],
            "on_missing_justification": "block",
            "on_check_error": on_check_error,
            "auto_deny_on_reasoning_failure": True,
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
            },
        },
    }

    const_path = str(tmp_path / "constitution.yaml")
    with open(const_path, "w") as f:
        yaml.safe_dump(data, f)
    constitution = load_constitution(const_path)
    signed = sign_constitution(constitution, priv_path)
    save_constitution(signed, const_path)
    return const_path, load_constitution(const_path)


# ---------------------------------------------------------------------------
# Unit tests: _run_reasoning_gate
# ---------------------------------------------------------------------------

class TestRunReasoningGateFailClosed:
    """Unit tests for _run_reasoning_gate error handling."""

    def test_enforce_mode_error_returns_failed_result(self, tmp_path):
        """on_check_error='block' + exception → returns failed dict (not None)."""
        _, constitution = _make_signed_constitution(tmp_path, on_check_error="block")

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("LLM API timeout"),
        ):
            result = _run_reasoning_gate(
                constitution, "some justification text here", {},
                func_name="my_tool",
                on_check_error="block",
            )

        assert result is not None
        assert result["passed"] is False
        assert "fail-closed" in result["failure_reason"]
        assert "LLM API timeout" in result["failure_reason"]
        assert result["overall_score"] == 0.0
        assert result["assurance"] == "none"

    def test_allow_mode_error_returns_none(self, tmp_path):
        """on_check_error='allow' + exception → returns None (proceed)."""
        _, constitution = _make_signed_constitution(tmp_path, on_check_error="allow")

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("LLM API timeout"),
        ):
            result = _run_reasoning_gate(
                constitution, "some justification text here", {},
                func_name="my_tool",
                on_check_error="allow",
            )

        assert result is None

    def test_default_on_check_error_is_block(self, tmp_path):
        """Default on_check_error parameter is 'block' (fail-closed by default)."""
        _, constitution = _make_signed_constitution(tmp_path)

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("unexpected error"),
        ):
            # Call without explicit on_check_error — should default to "block"
            result = _run_reasoning_gate(
                constitution, "some justification text here", {},
                func_name="my_tool",
            )

        assert result is not None
        assert result["passed"] is False


# ---------------------------------------------------------------------------
# Unit tests: _run_reasoning_gate_async
# ---------------------------------------------------------------------------

class TestRunReasoningGateAsyncFailClosed:
    """Unit tests for _run_reasoning_gate_async error handling."""

    @pytest.mark.asyncio
    async def test_enforce_mode_error_returns_failed_result(self, tmp_path):
        """on_check_error='block' + exception → returns failed dict (not None)."""
        _, constitution = _make_signed_constitution(tmp_path, on_check_error="block")

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("LLM API timeout"),
        ):
            result = await _run_reasoning_gate_async(
                constitution, "some justification text here", {},
                func_name="my_tool",
                on_check_error="block",
            )

        assert result is not None
        assert result["passed"] is False
        assert "fail-closed" in result["failure_reason"]
        assert result["overall_score"] == 0.0
        assert result["assurance"] == "none"

    @pytest.mark.asyncio
    async def test_allow_mode_error_returns_none(self, tmp_path):
        """on_check_error='allow' + exception → returns None (proceed)."""
        _, constitution = _make_signed_constitution(tmp_path, on_check_error="allow")

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("LLM API timeout"),
        ):
            result = await _run_reasoning_gate_async(
                constitution, "some justification text here", {},
                func_name="my_tool",
                on_check_error="allow",
            )

        assert result is None


# ---------------------------------------------------------------------------
# Integration tests: @sanna_observe end-to-end
# ---------------------------------------------------------------------------

class TestSannaObserveFailClosed:
    """End-to-end tests through @sanna_observe decorator."""

    def test_enforce_mode_error_blocks_execution(self, tmp_path):
        """on_check_error='block' + pipeline exception → SannaHaltError, func NOT called."""
        const_path, _ = _make_signed_constitution(tmp_path, on_check_error="block")

        func_called = False

        @sanna_observe(
            require_constitution_sig=False,
            constitution_path=const_path,
            strict=False,
        )
        def my_agent(query, context, _justification=""):
            nonlocal func_called
            func_called = True
            return "result"

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("LLM provider down"),
        ):
            with pytest.raises(SannaHaltError) as exc_info:
                my_agent(
                    query="test",
                    context="test context",
                    _justification="This is a sufficiently long justification for the test",
                )

        assert not func_called
        assert "fail-closed" in str(exc_info.value).lower() or "Reasoning" in str(exc_info.value)

    def test_allow_mode_error_permits_execution(self, tmp_path):
        """on_check_error='allow' + pipeline exception → func IS called."""
        const_path, _ = _make_signed_constitution(tmp_path, on_check_error="allow")

        func_called = False

        @sanna_observe(
            require_constitution_sig=False,
            constitution_path=const_path,
            strict=False,
        )
        def my_agent(query, context, _justification=""):
            nonlocal func_called
            func_called = True
            return "result"

        with patch(
            "sanna.reasoning.pipeline.ReasoningPipeline",
            side_effect=RuntimeError("LLM provider down"),
        ):
            result = my_agent(
                query="test",
                context="test context",
                _justification="This is a sufficiently long justification for the test",
            )

        assert func_called
