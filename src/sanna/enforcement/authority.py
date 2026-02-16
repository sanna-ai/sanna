"""
Authority boundary enforcement engine.

Evaluates whether an action is permitted under a constitution's authority
boundaries. The engine checks three tiers in strict priority order:

1. **cannot_execute** — forbidden actions → ``halt``
2. **must_escalate** — actions requiring human/system review → ``escalate``
3. **can_execute** — explicitly allowed actions → ``allow``
4. **default** — unmatched actions → ``allow`` (uncategorized)

Matching uses case-insensitive substring comparison for action names
and keyword-based heuristic matching for escalation conditions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ..constitution import Constitution, EscalationRule
from .escalation import EscalationTarget, get_escalation_callback

logger = logging.getLogger("sanna.authority")


# =============================================================================
# STOP WORDS (excluded from condition keyword matching)
# =============================================================================

_STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "for", "nor", "so", "yet",
    "in", "on", "at", "to", "of", "by", "is", "it", "as", "if",
    "be", "do", "no", "not", "are", "was", "were", "has", "had",
    "with", "from", "into", "that", "this", "than",
})


# =============================================================================
# DECISION DATA CLASS
# =============================================================================

@dataclass
class AuthorityDecision:
    """Result of evaluating an action against authority boundaries.

    Attributes:
        decision: The enforcement outcome — ``"halt"``, ``"allow"``,
            or ``"escalate"``.
        reason: Human-readable explanation of why this decision was made.
        boundary_type: Which boundary tier matched — ``"cannot_execute"``,
            ``"must_escalate"``, ``"can_execute"``, or ``"uncategorized"``.
        escalation_target: Resolved escalation target (only present when
            ``decision="escalate"``).
    """
    decision: str
    reason: str
    boundary_type: str
    escalation_target: Optional[EscalationTarget] = None


# =============================================================================
# PUBLIC API
# =============================================================================

def evaluate_authority(
    action: str,
    params: dict,
    constitution: Constitution,
) -> AuthorityDecision:
    """Evaluate whether an action is permitted under authority boundaries.

    Evaluation order (strict priority):

    1. ``cannot_execute`` — case-insensitive substring match against action
       name. If any forbidden entry matches → ``decision="halt"``.
    2. ``must_escalate`` — keyword-based condition matching against
       action name + param keys + param values. If any condition matches
       → ``decision="escalate"`` with the rule's escalation target.
    3. ``can_execute`` — case-insensitive substring match against action
       name. If explicitly listed → ``decision="allow"``.
    4. Default — ``decision="allow"`` with ``boundary_type="uncategorized"``.

    Args:
        action: Name of the action the agent intends to take.
        params: Parameters for the action (keys and values are both
            searched during condition matching).
        constitution: Constitution object (may or may not have
            ``authority_boundaries`` defined).

    Returns:
        AuthorityDecision with the enforcement outcome and reason.
    """
    ab = constitution.authority_boundaries
    if ab is None:
        return AuthorityDecision(
            decision="allow",
            reason="No authority boundaries defined in constitution",
            boundary_type="uncategorized",
        )

    if not ab.cannot_execute and not ab.must_escalate and not ab.can_execute:
        return AuthorityDecision(
            decision="allow",
            reason="Authority boundaries section is empty",
            boundary_type="uncategorized",
        )

    # 1. Check cannot_execute (highest priority)
    for forbidden in ab.cannot_execute:
        if _matches_action(forbidden, action):
            return AuthorityDecision(
                decision="halt",
                reason=f"Action matches cannot_execute rule: '{forbidden}'",
                boundary_type="cannot_execute",
            )

    # 2. Check must_escalate
    action_context = _build_action_context(action, params)
    for rule in ab.must_escalate:
        if _matches_condition(rule.condition, action_context):
            target = _resolve_escalation_target(rule, ab.default_escalation)
            return AuthorityDecision(
                decision="escalate",
                reason=f"Action matches escalation condition: '{rule.condition}'",
                boundary_type="must_escalate",
                escalation_target=target,
            )

    # 3. Check can_execute
    for allowed in ab.can_execute:
        if _matches_action(allowed, action):
            return AuthorityDecision(
                decision="allow",
                reason=f"Action matches can_execute rule: '{allowed}'",
                boundary_type="can_execute",
            )

    # 4. Default — allow with uncategorized
    return AuthorityDecision(
        decision="allow",
        reason="Action not matched by any authority boundary rule",
        boundary_type="uncategorized",
    )


# =============================================================================
# MATCHING HELPERS
# =============================================================================

def _normalize_separators(s: str) -> str:
    """Normalize separators (_, -, .) to spaces for matching."""
    return s.replace("_", " ").replace("-", " ").replace(".", " ")


def _matches_action(pattern: str, action: str) -> bool:
    """Case-insensitive bidirectional substring matching with separator normalization.

    Normalizes ``_``, ``-``, and ``.`` to spaces before comparison so that
    ``"delete_user"`` matches ``"delete-user"`` and ``"delete user"``.

    Returns True if the pattern is a substring of the action or the action
    is a substring of the pattern.
    """
    p = _normalize_separators(pattern.strip().lower())
    a = _normalize_separators(action.strip().lower())
    return p in a or a in p


def _build_action_context(action: str, params: dict) -> str:
    """Build a searchable context string from action name and params.

    Includes param keys and values so conditions like "confidence below
    threshold" can match params ``{"confidence": 0.3, "threshold": 0.5}``.
    """
    parts = [action]
    for k, v in params.items():
        parts.append(str(k))
        parts.append(str(v))
    return " ".join(parts)


def _matches_condition(condition: str, action_context: str) -> bool:
    """Keyword-based condition matching (heuristic v1).

    Extracts significant words (3+ chars, not stop words) from the condition
    and checks if ALL appear as a substring of the action context.

    Falls back to full condition substring matching if no significant
    keywords remain after filtering.

    .. versionchanged:: 0.12.0
       Changed from ``any()`` to ``all()`` — ALL significant words must
       be present.  "delete production database" no longer matches
       "list production services".
    """
    context_lower = action_context.lower()
    words = condition.lower().split()
    significant = [w for w in words if len(w) >= 3 and w not in _STOP_WORDS]
    if not significant:
        return False
    return all(word in context_lower for word in significant)


def _resolve_escalation_target(
    rule: EscalationRule,
    default_escalation: str,
) -> EscalationTarget:
    """Convert a constitution EscalationRule to a runtime EscalationTarget.

    Resolves callback handlers from the global registry and falls back
    to the constitution's default escalation type when no target is
    specified on the rule.
    """
    if rule.target is None:
        return EscalationTarget(type=default_escalation)

    target_type = rule.target.type

    if target_type == "callback" and rule.target.handler:
        handler_fn = get_escalation_callback(rule.target.handler)
        return EscalationTarget(
            type="callback",
            handler=handler_fn,
        )

    if target_type == "webhook":
        return EscalationTarget(
            type="webhook",
            url=rule.target.url,
        )

    return EscalationTarget(type=target_type)
