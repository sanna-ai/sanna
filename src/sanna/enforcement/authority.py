"""
Authority boundary enforcement engine.

Evaluates whether an action is permitted under a constitution's authority
boundaries. The engine checks three tiers in strict priority order:

1. **cannot_execute** — forbidden actions → ``halt``
2. **must_escalate** — actions requiring human/system review → ``escalate``
3. **can_execute** — explicitly allowed actions → ``allow``
4. **default** — unmatched actions → ``allow`` (uncategorized)

Matching uses exact-match (with optional ``*`` glob) for action names
and keyword-based heuristic matching for escalation conditions.
"""

from __future__ import annotations

import fnmatch
import logging
import re
import unicodedata
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
        decision: The enforcement outcome. Phase 1 legal values:
            ``"halt"``, ``"allow"``, ``"escalate"``, ``"modify"`` (v1.5+),
            ``"defer"`` (v1.5+). evaluate_authority only returns halt/allow/
            escalate in v1.5; modify and defer are reserved for runtime-
            evaluated outcomes returned by future evaluators (SAN-369+).
        reason: Human-readable explanation of why this decision was made.
        boundary_type: Which boundary tier matched. Phase 1 legal values:
            ``"cannot_execute"``, ``"must_escalate"``, ``"can_execute"``,
            ``"uncategorized"``, ``"modify_with_constraints"`` (v1.5+,
            reserved), ``"defer_for_context"`` (v1.5+, reserved).
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

    1. ``cannot_execute`` — exact-match (or glob) against normalized action
       name. If any forbidden entry matches → ``decision="halt"``.
    2. ``must_escalate`` — keyword-based condition matching against
       action name + param keys + param values. If any condition matches
       → ``decision="escalate"`` with the rule's escalation target.
    3. ``can_execute`` — exact-match (or glob) against normalized action
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

def normalize_authority_name(name: str) -> str:
    """Normalize a tool/action name for authority boundary matching.

    Applies NFKC Unicode normalization first (to collapse fullwidth and
    compatibility characters), then splits camelCase, normalizes separators
    to dots, and applies Unicode-correct casefolding.

    Examples::

        >>> normalize_authority_name("deleteFile")
        'delete.file'
        >>> normalize_authority_name("delete_file")
        'delete.file'

    .. versionadded:: 0.13.2
    """
    # NFKC normalization collapses fullwidth, compatibility chars, etc.
    name = unicodedata.normalize("NFKC", name)
    # Split camelCase and normalize separators to spaces
    name = _normalize_separators(name)
    # Casefold for Unicode-correct lowering (e.g., German eszett -> ss)
    name = name.casefold()
    # Replace spaces with dots for canonical form
    name = re.sub(r'\s+', '.', name.strip())
    return name


def _split_camel_case(s: str) -> str:
    """Insert spaces at camelCase/PascalCase word boundaries.

    Handles:
    - lowercase→Uppercase: ``deleteFile`` → ``delete File``
    - Uppercase run→Uppercase+Lowercase: ``XMLParser`` → ``XML Parser``
    - letter→digit: ``file2delete`` → ``file 2 delete``
    - digit→letter: ``2ndFile`` → ``2nd File``
    """
    # Lowercase followed by uppercase: deleteFile → delete File
    s = re.sub(r'([a-z])([A-Z])', r'\1 \2', s)
    # Uppercase run followed by uppercase+lowercase: XMLParser → XML Parser
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', s)
    # Letter followed by digit: file2delete → file 2delete
    s = re.sub(r'([a-zA-Z])(\d)', r'\1 \2', s)
    # Digit followed by letter: 2ndFile → 2nd File
    s = re.sub(r'(\d)([a-zA-Z])', r'\1 \2', s)
    return s


def _normalize_separators(s: str) -> str:
    """Normalize separators and camelCase to spaces for matching.

    Splits on:
    - Underscore, hyphen, dot (original behavior)
    - Slash, colon, at-sign (namespace separators used by tool ecosystems)
    - camelCase/PascalCase word boundaries
    - letter/digit transitions
    """
    # First split camelCase before replacing separators so that
    # "deleteFile" becomes "delete File" then "delete file" after lowering.
    s = _split_camel_case(s)
    # Replace all common separators with spaces
    s = re.sub(r'[_\-./:\\@]+', ' ', s)
    return s


def _matches_action(pattern: str, action: str) -> bool:
    """Exact-match (with optional glob) authority name matching.

    Normalizes both ``pattern`` and ``action`` — NFKC, camelCase split,
    separator-to-space, casefold — then compares for **exact equality**.
    If the normalized pattern contains ``*``, fnmatch-style glob matching
    is used instead (e.g. ``"read_*"`` matches ``"read_user_profile"``).

    A separatorless fallback strips all non-alphanumeric characters from
    both normalized forms and compares the result exactly, allowing
    ``"sendemail"`` to match ``"send-email"``.

    Returns ``False`` for empty or whitespace-only action/pattern names.

    See ``spec/fixtures/authority-matching-vectors.json`` for the
    cross-SDK contract (21 vectors).

    .. versionchanged:: 1.4.0
       Changed from bidirectional substring matching to exact-match +
       opt-in glob. ``"delete"`` no longer matches ``"delete_user"``.
       Use ``"delete_*"`` for prefix matching. (SAN-224)
    """
    if not action or not action.strip():
        return False
    if not pattern or not pattern.strip():
        return False

    # NFKC normalize before any processing
    pattern = unicodedata.normalize("NFKC", pattern)
    action = unicodedata.normalize("NFKC", action)

    p = _normalize_separators(pattern.strip()).casefold()
    a = _normalize_separators(action.strip()).casefold()

    # Glob opt-in: if the normalized pattern contains '*', use fnmatch
    if '*' in p:
        return fnmatch.fnmatch(a, p)

    # Exact match on normalized forms
    if p == a:
        return True

    # Separatorless fallback: strip all non-alphanumeric chars and compare exactly.
    # Allows "sendemail" to match "send-email" (S-001, S-002 in fixture).
    p_stripped = re.sub(r'[^a-z0-9]', '', p)
    a_stripped = re.sub(r'[^a-z0-9]', '', a)
    if p_stripped and a_stripped:
        return p_stripped == a_stripped

    return False


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
    and checks if ALL appear as whole words in the action context using
    word-boundary regex matching.

    Falls back to no match if no significant keywords remain after filtering.

    .. versionchanged:: 0.12.0
       Changed from ``any()`` to ``all()`` — ALL significant words must
       be present.  "delete production database" no longer matches
       "list production services".

    .. versionchanged:: 0.12.2
       Changed from substring matching to word-boundary regex matching.
       Uses a leading ``\\b`` to prevent "add" matching inside "padder"
       and "can" matching inside "scan", while still allowing
       "delete" to match "deleted" (prefix match).  Separators
       (``_``, ``-``, ``.``) are normalized to spaces before matching
       so that ``send_email`` is treated as ``send email``.
    """
    context_lower = _normalize_separators(unicodedata.normalize("NFKC", action_context)).casefold()
    condition_normalized = _normalize_separators(unicodedata.normalize("NFKC", condition)).casefold()
    words = condition_normalized.split()
    significant = [w for w in words if len(w) >= 3 and w not in _STOP_WORDS]
    if not significant:
        return False
    return all(
        re.search(r'\b' + re.escape(word), context_lower)
        for word in significant
    )


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
