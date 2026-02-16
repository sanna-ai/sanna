"""Reasoning evaluation pipeline — orchestrates governance-level checks.

Runs deterministic checks (glc_001–003) and optionally LLM coherence
(glc_005) against agent justifications.  Results are aggregated into
a ReasoningEvaluation for embedding in gateway receipts.

All check execution is async — the gateway runs in an event loop.

v0.12.0: Pipeline uses :class:`BaseJudge` interface (via
:class:`JudgeFactory`) instead of calling ``llm_client`` directly.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict

from sanna.constitution import Constitution
from sanna.gateway.receipt_v2 import GatewayCheckResult, ReasoningEvaluation
from .checks import (
    JustificationPresenceCheck,
    MinimumSubstanceCheck,
    NoParrotingCheck,
    LLMCoherenceCheck,
)
from .judge import BaseJudge, JudgeVerdict

logger = logging.getLogger("sanna.reasoning.pipeline")


class ReasoningPipeline:
    """Orchestrates reasoning checks according to constitution config (async).

    Parameters:
        constitution: The governance constitution.
        judge: Optional judge instance.  If *None* and glc_005 is
            enabled, the pipeline creates one via :class:`JudgeFactory`.
    """

    def __init__(
        self,
        constitution: Constitution,
        judge: BaseJudge | None = None,
    ):
        self.constitution = constitution
        self.reasoning_config = constitution.reasoning

        if not self.reasoning_config:
            self.enabled = False
            self.judge: BaseJudge | None = None
            return

        self.enabled = True
        self._error_policy = getattr(self.reasoning_config, "on_api_error", "block")

        # Deterministic checks — always sequential, glc_001 always runs
        self.checks: list = []
        self.checks.append(JustificationPresenceCheck())

        # glc_002 (minimum substance)
        if self._is_check_enabled("glc_002_minimum_substance"):
            config = self._check_config_dict("glc_002_minimum_substance")
            self.checks.append(MinimumSubstanceCheck(config))

        # glc_003 (no parroting)
        if self._is_check_enabled("glc_003_no_parroting"):
            config = self._check_config_dict("glc_003_no_parroting")
            self.checks.append(NoParrotingCheck(config))

        # glc_005 (LLM coherence) — uses judge interface (v0.12.0+)
        self._llm_coherence_enabled = self._is_check_enabled("glc_005_llm_coherence")
        self._llm_config = self._check_config_dict("glc_005_llm_coherence") if self._llm_coherence_enabled else {}

        # Legacy path: also create LLMCoherenceCheck for backward compat
        # (used when no judge is provided and API key is present)
        self.llm_check = None

        if judge is not None:
            # Caller explicitly provided a judge — use it
            self.judge = judge
        elif self._llm_coherence_enabled:
            # Try to get an LLM judge via factory.
            # If factory returns HeuristicJudge (no API key), don't use it
            # for the LLM coherence step — skip the check instead.
            # Heuristic is only used when explicitly injected.
            candidate = self._create_judge_from_factory()
            if candidate is not None and candidate.provider_name() != "heuristic":
                self.judge = candidate
            else:
                self.judge = None
                # Fallback: try legacy LLMCoherenceCheck
                try:
                    self.llm_check = LLMCoherenceCheck(self._llm_config)
                except (ValueError, ImportError) as e:
                    logger.warning("LLM coherence check disabled: %s", e)
        else:
            self.judge = None

    def _create_judge_from_factory(self) -> BaseJudge | None:
        """Create a judge via JudgeFactory using constitution config."""
        try:
            from .judge_factory import JudgeFactory

            error_policy = getattr(self.reasoning_config, "on_api_error", "block")

            # Pass judge config from constitution if available
            judge_cfg = getattr(self.reasoning_config, "judge", None)
            provider = getattr(judge_cfg, "default_provider", None) if judge_cfg else None
            model = getattr(judge_cfg, "default_model", None) if judge_cfg else None
            cross_provider = getattr(judge_cfg, "cross_provider", False) if judge_cfg else False

            return JudgeFactory.create(
                provider=provider,
                model=model,
                error_policy=error_policy,
                cross_provider=cross_provider,
            )
        except Exception as e:
            logger.warning("JudgeFactory.create() failed: %s", e)
            return None

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

        # Type safety: non-string justification is treated as missing
        if not isinstance(justification, str):
            justification = ""

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
            start_ms = time.perf_counter() * 1000

            try:
                result = await check.execute(justification, context)
            except Exception as exc:
                latency_ms = int((time.perf_counter() * 1000) - start_ms)
                logger.warning(
                    "Check %s raised %s", check.check_id(), type(exc).__name__,
                )
                result = GatewayCheckResult(
                    check_id=check.check_id(),
                    method=check.method(),
                    passed=False,
                    score=0.0,
                    latency_ms=latency_ms,
                    details={
                        "error": "check_exception",
                        "exception_type": type(exc).__name__,
                    },
                )

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
        if self._should_run_llm(enforcement_level):
            if all(r.passed for r in check_results):
                llm_result = await self._run_llm_check(
                    tool_name, args, justification, context,
                )
                if llm_result is not None:
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

    async def _run_llm_check(
        self,
        tool_name: str,
        args: dict,
        justification: str,
        context: dict,
    ) -> GatewayCheckResult | None:
        """Run LLM coherence check via judge interface or legacy check."""
        score_threshold = self._llm_config.get("score_threshold", 0.6)

        # Preferred path: use BaseJudge interface (v0.12.0+)
        if self.judge is not None:
            start_ms = time.perf_counter() * 1000
            try:
                # Build constitution_context from per-invariant judge_override
                constitution_context = None
                llm_check_cfg = self.reasoning_config.checks.get("glc_005_llm_coherence")
                if llm_check_cfg is not None:
                    override = getattr(llm_check_cfg, "judge_override", None)
                    if isinstance(override, dict) and override:
                        constitution_context = override

                judge_result = await self.judge.evaluate(
                    tool_name=tool_name,
                    arguments=args,
                    justification=justification,
                    invariant_id="glc_005_llm_coherence",
                    constitution_context=constitution_context,
                )

                passed = judge_result.score >= score_threshold
                details: dict | None = None
                if not passed:
                    details = {
                        "score_bp": int(round(judge_result.score * 10000)),
                        "threshold_bp": int(round(score_threshold * 10000)),
                    }
                if judge_result.verdict == JudgeVerdict.ERROR:
                    details = details or {}
                    details["error"] = "judge_error"
                    details["error_detail"] = judge_result.error_detail
                    details["judge_method"] = judge_result.method

                return GatewayCheckResult(
                    check_id="glc_005_llm_coherence",
                    method=judge_result.method,
                    passed=passed,
                    score=judge_result.score,
                    latency_ms=int(judge_result.latency_ms),
                    details=details,
                )
            except Exception as exc:
                latency_ms = int((time.perf_counter() * 1000) - start_ms)
                logger.warning("Judge raised %s", type(exc).__name__)
                return GatewayCheckResult(
                    check_id="glc_005_llm_coherence",
                    method="judge_error",
                    passed=False,
                    score=0.0,
                    latency_ms=latency_ms,
                    details={
                        "error": "check_exception",
                        "exception_type": type(exc).__name__,
                    },
                )

        # Legacy fallback: use LLMCoherenceCheck directly
        if self.llm_check is not None:
            start_ms = time.perf_counter() * 1000
            try:
                return await self.llm_check.execute(justification, context)
            except Exception as exc:
                latency_ms = int((time.perf_counter() * 1000) - start_ms)
                logger.warning("LLM check raised %s", type(exc).__name__)
                return GatewayCheckResult(
                    check_id="glc_005_llm_coherence",
                    method="llm_coherence",
                    passed=False,
                    score=0.0,
                    latency_ms=latency_ms,
                    details={
                        "error": "check_exception",
                        "exception_type": type(exc).__name__,
                    },
                )

        return None

    def _should_run_llm(self, enforcement_level: str) -> bool:
        """Check if LLM should run for this enforcement level."""
        if not self._llm_coherence_enabled:
            return False
        if self.judge is None and self.llm_check is None:
            return False

        config = self.reasoning_config.checks.get("glc_005_llm_coherence")
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

    # Deterministic check ID prefixes — checks that are reproducible
    _DETERMINISTIC_PREFIXES = ("glc_001", "glc_002", "glc_003")

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

        Also computes weighted_score (deterministic=0.3, LLM=0.7)
        and classifies failures as hard (deterministic) vs soft (LLM).
        """
        if not check_results:
            return ReasoningEvaluation(
                assurance=assurance,
                checks=[],
                overall_score=0.0,
                passed=False,
                failure_reason=failure_reason,
                failed_check_ids=[],
                passed_check_ids=[],
                weighted_score=0.0,
                hard_failures=[],
                soft_failures=[],
                scoring_method="min_gate",
            )

        # When error_policy is "allow", exclude errored checks from min-gate
        # so API errors don't floor the overall score.
        if self._error_policy == "allow":
            scoring_results = [
                r for r in check_results
                if not (r.details and "error" in r.details)
            ]
        else:
            scoring_results = check_results

        if scoring_results:
            overall_score = min(r.score for r in scoring_results)
            passed = all(r.passed for r in scoring_results)
        else:
            # All checks errored and error_policy is "allow" — pass through
            overall_score = 1.0
            passed = True

        failed_ids = [r.check_id for r in check_results if not r.passed]
        passed_ids = [r.check_id for r in check_results if r.passed]

        # Classify failures
        hard_failures = [
            cid for cid in failed_ids
            if any(cid.startswith(p) for p in self._DETERMINISTIC_PREFIXES)
        ]
        soft_failures = [
            cid for cid in failed_ids
            if not any(cid.startswith(p) for p in self._DETERMINISTIC_PREFIXES)
        ]

        # Weighted score: deterministic=0.3 weight, LLM=0.7 weight
        det_scores = [
            r.score for r in check_results
            if any(r.check_id.startswith(p) for p in self._DETERMINISTIC_PREFIXES)
        ]
        llm_scores = [
            r.score for r in check_results
            if not any(r.check_id.startswith(p) for p in self._DETERMINISTIC_PREFIXES)
        ]

        det_avg = sum(det_scores) / len(det_scores) if det_scores else 1.0
        llm_avg = sum(llm_scores) / len(llm_scores) if llm_scores else 1.0

        if det_scores and llm_scores:
            weighted_score = 0.3 * det_avg + 0.7 * llm_avg
        elif det_scores:
            weighted_score = det_avg
        else:
            weighted_score = llm_avg

        return ReasoningEvaluation(
            assurance=assurance,
            checks=check_results,
            overall_score=overall_score,
            passed=passed,
            failure_reason=failure_reason,
            failed_check_ids=failed_ids,
            passed_check_ids=passed_ids,
            weighted_score=weighted_score,
            hard_failures=hard_failures,
            soft_failures=soft_failures,
            scoring_method="min_gate",
        )

    @staticmethod
    def strip_justification(args: dict) -> dict:
        """Remove _justification field from args before forwarding."""
        return {k: v for k, v in args.items() if k != "_justification"}
