"""Reasoning evaluation pipeline — orchestrates governance-level checks.

Runs deterministic checks (glc_001–003) and optionally LLM coherence
(glc_005) against agent justifications.  Results are aggregated into
a ReasoningEvaluation for embedding in gateway receipts.

All check execution is async — the gateway runs in an event loop.
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from sanna.constitution import Constitution
from sanna.gateway.receipt_v2 import GatewayCheckResult, ReasoningEvaluation
from .checks import (
    JustificationPresenceCheck,
    MinimumSubstanceCheck,
    NoParrotingCheck,
    LLMCoherenceCheck,
)

logger = logging.getLogger("sanna.reasoning.pipeline")


class ReasoningPipeline:
    """Orchestrates reasoning checks according to constitution config (async)."""

    def __init__(self, constitution: Constitution):
        self.constitution = constitution
        self.reasoning_config = constitution.reasoning

        if not self.reasoning_config:
            self.enabled = False
            return

        self.enabled = True

        # Deterministic checks — always sequential, glc_001 always runs
        self.checks: list = []
        self.checks.append(JustificationPresenceCheck())

        # glc_002 (minimum substance)
        if self._is_check_enabled("glc_minimum_substance"):
            config = self._check_config_dict("glc_minimum_substance")
            self.checks.append(MinimumSubstanceCheck(config))

        # glc_003 (no parroting)
        if self._is_check_enabled("glc_no_parroting"):
            config = self._check_config_dict("glc_no_parroting")
            self.checks.append(NoParrotingCheck(config))

        # glc_005 (LLM coherence) — stored separately, runs conditionally
        self.llm_check = None
        if self._is_check_enabled("glc_llm_coherence"):
            config = self._check_config_dict("glc_llm_coherence")
            try:
                self.llm_check = LLMCoherenceCheck(config)
            except (ValueError, ImportError) as e:
                logger.warning("LLM coherence check disabled: %s", e)

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _is_check_enabled(self, key: str) -> bool:
        """Check if a specific check is enabled in constitution."""
        if not self.reasoning_config or not self.reasoning_config.checks:
            return False
        config = self.reasoning_config.checks.get(key)
        if config is None:
            return False
        # GLCCheckConfig dataclass has .enabled attribute
        if hasattr(config, "enabled"):
            return config.enabled
        if isinstance(config, dict):
            return config.get("enabled", True)
        return False

    def _check_config_dict(self, key: str) -> dict:
        """Extract check config as a plain dict for Check constructors."""
        config = self.reasoning_config.checks.get(key, {})
        if hasattr(config, "__dataclass_fields__"):
            return asdict(config)
        return config if isinstance(config, dict) else {}

    # ------------------------------------------------------------------
    # Pipeline execution
    # ------------------------------------------------------------------

    async def evaluate(
        self,
        tool_name: str,
        args: dict,
        enforcement_level: str,
    ) -> ReasoningEvaluation:
        """Evaluate reasoning for a tool call (async).

        Returns ReasoningEvaluation with:
        - assurance: full | partial | none
        - checks: list of GatewayCheckResults
        - overall_score: min of all scores
        - passed: bool
        """
        if not self.enabled:
            return ReasoningEvaluation(
                assurance="none",
                checks=[],
                overall_score=1.0,
                passed=True,
                failure_reason="reasoning_disabled",
            )

        justification = args.get("_justification", "")

        # Check if justification is required for this enforcement level
        require_for = self.reasoning_config.require_justification_for
        if enforcement_level in require_for and not justification:
            return ReasoningEvaluation(
                assurance="none",
                checks=[],
                overall_score=0.0,
                passed=False,
                failure_reason="missing_required_justification",
            )

        # If no justification and not required, skip evaluation
        if not justification:
            return ReasoningEvaluation(
                assurance="none",
                checks=[],
                overall_score=1.0,
                passed=True,
                failure_reason="justification_not_required",
            )

        # Run deterministic checks (async)
        check_results: list[GatewayCheckResult] = []
        context = {"tool_name": tool_name, "args": args}

        for check in self.checks:
            result = await check.execute(justification, context)
            check_results.append(result)

            # Early termination on failure when on_check_error == "block"
            if not result.passed:
                on_error = self.reasoning_config.on_check_error
                if on_error == "block":
                    return self._finalize(
                        check_results,
                        assurance="partial",
                        failure_reason=f"{result.check_id}_failed",
                    )

        # Run LLM coherence check if enabled for this enforcement level
        # Only runs when all deterministic checks passed
        if self.llm_check and self._should_run_llm(enforcement_level):
            if all(r.passed for r in check_results):
                llm_result = await self.llm_check.execute(justification, context)
                check_results.append(llm_result)

        # Determine assurance level
        has_errors = any("error" in (r.details or {}) for r in check_results)
        all_passed = all(r.passed for r in check_results)

        if all_passed and not has_errors:
            assurance = "full"
        elif has_errors or not all_passed:
            assurance = "partial"
        else:
            assurance = "none"

        return self._finalize(check_results, assurance)

    def _should_run_llm(self, enforcement_level: str) -> bool:
        """Check if LLM should run for this enforcement level."""
        if not self.llm_check:
            return False

        config = self.reasoning_config.checks.get("glc_llm_coherence")
        if config is None:
            return False

        # Handle both GLCLLMCoherenceConfig and plain dict
        if hasattr(config, "enabled_for"):
            enabled_for = config.enabled_for
        elif isinstance(config, dict):
            enabled_for = config.get("enabled_for", ["must_escalate"])
        else:
            enabled_for = ["must_escalate"]

        return enforcement_level in enabled_for

    def _finalize(
        self,
        check_results: list[GatewayCheckResult],
        assurance: str,
        failure_reason: str | None = None,
    ) -> ReasoningEvaluation:
        """Create final ReasoningEvaluation from results.

        Scoring philosophy: overall_score = min(scores).
        Deterministic checks are absolute requirements — a single 0.0
        floors the entire score.
        """
        if not check_results:
            return ReasoningEvaluation(
                assurance=assurance,
                checks=[],
                overall_score=0.0,
                passed=False,
                failure_reason=failure_reason,
            )

        overall_score = min(r.score for r in check_results)
        passed = all(r.passed for r in check_results)

        return ReasoningEvaluation(
            assurance=assurance,
            checks=check_results,
            overall_score=overall_score,
            passed=passed,
            failure_reason=failure_reason,
        )

    @staticmethod
    def strip_justification(args: dict) -> dict:
        """Remove _justification field from args before forwarding."""
        return {k: v for k, v in args.items() if k != "_justification"}
