"""Block F tests — ScoringResult: failed_check_ids, hard/soft, weighted_score."""

import asyncio

import pytest

from sanna.gateway.receipt_v2 import GatewayCheckResult, ReasoningEvaluation
from sanna.reasoning.pipeline import ReasoningPipeline
from sanna.constitution import Constitution, AgentIdentity, Provenance, Boundary, ReasoningConfig


def _make_constitution(checks: dict | None = None) -> Constitution:
    """Create a minimal constitution with reasoning enabled."""
    reasoning = ReasoningConfig(
        require_justification_for=["must_escalate"],
        on_missing_justification="block",
        auto_deny_on_reasoning_failure=True,
        checks=checks or {
            "glc_002_minimum_substance": {
                "enabled": True,
                "min_length": 10,
            },
        },
    )
    return Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test", domain="testing"),
        provenance=Provenance(
            authored_by="dev@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope", severity="high"),
        ],
        reasoning=reasoning,
    )


class TestScoringResult:
    def test_scoring_result_has_failed_ids(self):
        """Scoring result includes failed_check_ids when checks fail."""
        constitution = _make_constitution()
        pipeline = ReasoningPipeline(constitution)

        result = asyncio.run(pipeline.evaluate(
            tool_name="update",
            args={"_justification": "ok"},  # Too short → fails substance
            enforcement_level="must_escalate",
        ))

        assert not result.passed
        assert result.failed_check_ids is not None
        assert len(result.failed_check_ids) > 0
        assert result.passed_check_ids is not None

    def test_scoring_result_hard_vs_soft(self):
        """Deterministic failures in hard_failures, LLM in soft_failures."""
        constitution = _make_constitution()
        pipeline = ReasoningPipeline(constitution)

        result = asyncio.run(pipeline.evaluate(
            tool_name="update",
            args={"_justification": "ok"},  # Fails deterministic glc_002
            enforcement_level="must_escalate",
        ))

        assert result.hard_failures is not None
        # glc_002 is a deterministic check — should be in hard_failures
        assert any("glc_002" in f for f in result.hard_failures)
        # No LLM checks ran, so soft_failures should be empty
        assert result.soft_failures is not None
        assert len(result.soft_failures) == 0

    def test_weighted_score_computed(self):
        """weighted_score is populated and can differ from overall_score."""
        constitution = _make_constitution()
        pipeline = ReasoningPipeline(constitution)

        result = asyncio.run(pipeline.evaluate(
            tool_name="update",
            args={
                "_justification": "This action is needed for compliance with policy requirements",
            },
            enforcement_level="must_escalate",
        ))

        assert result.weighted_score is not None
        # When only deterministic checks run, weighted = det average
        # In this case all pass so both should be 1.0
        assert result.weighted_score > 0

    def test_overall_score_still_min(self):
        """Gating uses min() regardless of weighted score."""
        constitution = _make_constitution()
        pipeline = ReasoningPipeline(constitution)

        result = asyncio.run(pipeline.evaluate(
            tool_name="update",
            args={"_justification": "ok"},  # Too short → min floors to 0.0
            enforcement_level="must_escalate",
        ))

        assert result.overall_score == 0.0
        assert result.scoring_method == "min_gate"

    def test_all_passed_scoring(self):
        """All checks pass → empty failure lists, high scores."""
        constitution = _make_constitution()
        pipeline = ReasoningPipeline(constitution)

        result = asyncio.run(pipeline.evaluate(
            tool_name="update",
            args={
                "_justification": "This action is required for regulatory compliance reporting",
            },
            enforcement_level="must_escalate",
        ))

        assert result.passed
        assert result.failed_check_ids == []
        assert len(result.passed_check_ids) > 0
        assert result.hard_failures == []
        assert result.soft_failures == []
        assert result.overall_score > 0
