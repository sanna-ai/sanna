"""Judge factory — provider detection, configuration, and fallback.

Resolution order:
  1. Explicit ``provider`` / ``model`` / ``api_key`` arguments.
  2. Constitution ``judge`` config (``default_provider``, ``cross_provider``).
  3. ``SANNA_JUDGE_PROVIDER`` environment variable.
  4. Auto-detect: check ``ANTHROPIC_API_KEY``, then ``OPENAI_API_KEY``.
  5. Fall back to :class:`HeuristicJudge` (no API needed).
"""

from __future__ import annotations

import logging
import os

from .judge import BaseJudge

logger = logging.getLogger("sanna.reasoning.judge_factory")

_OTHER_PROVIDER = {
    "anthropic": "openai",
    "openai": "anthropic",
}


class NoProviderAvailableError(Exception):
    """Raised when auto-detection finds no LLM API key."""


class JudgeFactory:
    """Create judge instances with provider auto-detection."""

    @staticmethod
    def create(
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        error_policy: str = "block",
        cross_provider: bool = False,
        agent_provider: str | None = None,
    ) -> BaseJudge:
        """Create a judge instance.

        Parameters:
            provider: ``"anthropic"``, ``"openai"``, or ``"heuristic"``.
                If *None*, resolved via env vars then auto-detection.
            model: Model name.  Passed through to the LLM judge.
                Defaults to *None* (judge uses its own default).
            api_key: API key.  If *None*, read from env var.
            error_policy: ``"block"`` | ``"allow"`` | ``"score_zero"``.
                Controls the score assigned on API errors.
            cross_provider: If *True*, select a different provider from
                *agent_provider* (if available).
            agent_provider: The provider used by the agent being evaluated
                (e.g. ``"anthropic"``).  Only used when *cross_provider*
                is *True*.

        Returns:
            A :class:`BaseJudge` instance.
        """
        # 1. Explicit heuristic request
        if provider == "heuristic":
            return _make_heuristic()

        # 2. Cross-provider: pick the OTHER provider
        if cross_provider and agent_provider:
            resolved = _resolve_cross_provider(agent_provider, model, error_policy)
            if resolved is not None:
                return resolved
            # Fall through if cross-provider couldn't be resolved

        # 3. Explicit provider with key
        if provider and api_key:
            return _make_llm_judge(provider, api_key, model, error_policy)

        # 4. Explicit provider, resolve key from env
        if provider:
            resolved_key = _key_for_provider(provider)
            if resolved_key:
                judge = _make_llm_judge(provider, resolved_key, model, error_policy)
                logger.info(
                    "Judge initialized: %s (provider=%s)",
                    type(judge).__name__, provider,
                )
                return judge
            raise ValueError(
                f"Explicit provider '{provider}' requested but no API "
                f"key found.  Set the corresponding environment variable "
                f"(e.g. ANTHROPIC_API_KEY) or pass api_key explicitly."
            )

        # 5. SANNA_JUDGE_PROVIDER env var
        env_provider = os.environ.get("SANNA_JUDGE_PROVIDER")
        if env_provider:
            if env_provider == "heuristic":
                return _make_heuristic()
            resolved_key = api_key or _key_for_provider(env_provider)
            if resolved_key:
                return _make_llm_judge(env_provider, resolved_key, model, error_policy)

        # 6. Auto-detect from available API keys
        try:
            detected_provider, detected_key = _detect_provider()
            return _make_llm_judge(detected_provider, detected_key, model, error_policy)
        except NoProviderAvailableError:
            pass

        # 7. Fallback — heuristic
        logger.warning(
            "No LLM API key found (ANTHROPIC_API_KEY, OPENAI_API_KEY). "
            "Using deterministic heuristic judge. "
            "Coherence scoring requires an API key — see docs for setup."
        )
        return _make_heuristic()


def _resolve_cross_provider(
    agent_provider: str,
    model: str | None,
    error_policy: str,
) -> BaseJudge | None:
    """Try to create a judge using a different provider than the agent.

    Returns *None* if the other provider is not available (no API key).
    """
    other = _OTHER_PROVIDER.get(agent_provider)
    if not other:
        logger.warning(
            "cross_provider=True but agent_provider='%s' has no alternative.",
            agent_provider,
        )
        return None

    key = _key_for_provider(other)
    if key:
        logger.info(
            "Cross-provider: agent uses '%s', judge will use '%s'.",
            agent_provider, other,
        )
        return _make_llm_judge(other, key, model, error_policy)

    logger.warning(
        "Cross-provider requested but '%s' API key not available. "
        "Falling back to same-provider judge.",
        other,
    )
    return None


def _detect_provider() -> tuple[str, str]:
    """Auto-detect provider from environment variables.

    Returns:
        ``(provider_name, api_key)``

    Raises:
        NoProviderAvailableError: No LLM API key found.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return ("anthropic", key)
    key = os.environ.get("OPENAI_API_KEY")
    if key:
        return ("openai", key)
    raise NoProviderAvailableError("No LLM API key found.")


def _key_for_provider(provider: str) -> str | None:
    """Look up the API key env var for a given provider."""
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
    }
    var = env_map.get(provider)
    if var:
        return os.environ.get(var)
    return None


def _make_llm_judge(
    provider: str, api_key: str, model: str | None, error_policy: str
) -> BaseJudge:
    """Instantiate an LLM judge, falling back to heuristic if httpx missing."""
    try:
        if provider == "anthropic":
            from .llm_client import AnthropicJudge

            return AnthropicJudge(api_key=api_key, model=model, error_policy=error_policy)
        if provider == "openai":
            from .llm_client import OpenAIJudge

            return OpenAIJudge(api_key=api_key, model=model, error_policy=error_policy)
    except ImportError:
        logger.warning(
            "httpx not installed — cannot use '%s' judge. "
            "Install with: pip install httpx. Falling back to heuristic.",
            provider,
        )
        return _make_heuristic()

    raise ValueError(f"Unsupported judge provider: {provider}")


def _make_heuristic() -> BaseJudge:
    from .heuristic_judge import HeuristicJudge

    return HeuristicJudge()
