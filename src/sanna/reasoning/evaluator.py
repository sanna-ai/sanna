"""High-level interface for reasoning evaluation."""

from __future__ import annotations

from sanna.constitution import Constitution
from sanna.gateway.receipt_v2 import ReasoningEvaluation
from .pipeline import ReasoningPipeline


class ReasoningEvaluator:
    """Facade for reasoning evaluation against a constitution."""

    def __init__(self, constitution: Constitution):
        self.pipeline = ReasoningPipeline(constitution)

    async def evaluate(
        self,
        tool_name: str,
        args: dict,
        enforcement_level: str,
    ) -> ReasoningEvaluation:
        """Evaluate reasoning for a tool call (async)."""
        return await self.pipeline.evaluate(tool_name, args, enforcement_level)

    @staticmethod
    def strip_justification(args: dict) -> dict:
        """Remove _justification from args before forwarding."""
        return ReasoningPipeline.strip_justification(args)
