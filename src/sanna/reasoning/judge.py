"""Abstract judge interface for reasoning evaluation.

Defines the provider-agnostic contract that all judge implementations
(LLM-based, heuristic, custom) must satisfy.  JudgeResult carries
enough metadata to populate gateway receipts regardless of provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class JudgeVerdict(Enum):
    """Outcome of a single judge evaluation."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    HEURISTIC = "heuristic"


@dataclass
class JudgeResult:
    """Result from a judge evaluation.

    Attributes:
        score: 0.0-1.0, higher = more aligned with governance.
        verdict: Categorical outcome of the evaluation.
        method: How the score was produced (e.g. ``"anthropic_llm"``,
            ``"openai_llm"``, ``"heuristic"``).
        explanation: Human-readable summary of the evaluation.
        latency_ms: Wall-clock time for the evaluation in milliseconds.
        error_detail: Present only when verdict is ERROR; describes the
            failure (timeout, API error, parse error, etc.).
    """

    score: float
    verdict: JudgeVerdict
    method: str
    explanation: str
    latency_ms: float
    error_detail: str | None = None


class BaseJudge(ABC):
    """Abstract base class for all judge implementations."""

    @abstractmethod
    async def evaluate(
        self,
        tool_name: str,
        arguments: dict,
        justification: str,
        invariant_id: str,
        constitution_context: dict | None = None,
    ) -> JudgeResult:
        """Evaluate whether *justification* supports calling *tool_name*.

        Parameters:
            tool_name: The tool being invoked.
            arguments: Tool call arguments (``_justification`` already
                stripped by the caller).
            justification: The agent's stated reasoning.
            invariant_id: The governance invariant being evaluated
                (e.g. ``"glc_005_coherence"``).
            constitution_context: Optional additional context from the
                constitution (invariant text, authority rules, etc.).

        Returns:
            A :class:`JudgeResult` with score, verdict, and metadata.
        """

    @abstractmethod
    def provider_name(self) -> str:
        """Short identifier for the judge provider (e.g. ``"anthropic"``)."""
