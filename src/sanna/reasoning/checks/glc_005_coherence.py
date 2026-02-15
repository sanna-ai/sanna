"""glc_005: Evaluate semantic coherence via LLM (async).

Calls an external LLM to judge whether the agent's justification
logically supports executing the specified tool with the given arguments.

Graceful degradation: on timeout or API error, returns score 0.5
(partial assurance) rather than failing hard.
"""

from __future__ import annotations

import os

from .base import Check
from ..llm_client import create_llm_client


class LLMCoherenceCheck(Check):
    """glc_005: Evaluate semantic coherence via LLM (async)."""

    def __init__(self, config: dict | None = None):
        super().__init__(config)

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable required "
                "for LLM coherence check"
            )

        provider = self.config.get("llm_provider", "anthropic")
        # Priority: config > env var > code default (handled in client)
        model = self.config.get("llm_model") or os.getenv("SANNA_LLM_MODEL")

        self.client = create_llm_client(provider, api_key, model)
        self.timeout_ms = self.config.get("timeout_ms", 2000)
        self.score_threshold = self.config.get("score_threshold", 0.6)

    def check_id(self) -> str:
        return "glc_005_llm_coherence"

    def method(self) -> str:
        return "llm_coherence"

    async def _execute(
        self, justification: str, context: dict
    ) -> tuple[bool, float, dict | None]:
        """Execute LLM coherence evaluation (async)."""
        tool_name = context.get("tool_name", "unknown")
        args = context.get("args", {})

        score, error_details = await self.client.evaluate_coherence(
            tool_name=tool_name,
            args=args,
            justification=justification,
            timeout_ms=self.timeout_ms,
        )

        passed = score >= self.score_threshold

        details = None
        if error_details:
            details = error_details
        elif not passed:
            details = {"score": score, "threshold": self.score_threshold}

        return passed, score, details
