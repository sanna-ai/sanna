"""
Constitution enforcement engine — maps invariants to check functions.

Reads a constitution's invariants and produces a check configuration
that tells the existing check engine which checks to run and at what
enforcement level.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..receipt import (
    CheckResult,
    check_c1_context_contradiction,
    check_c2_unmarked_inference,
    check_c3_false_certainty,
    check_c4_conflict_collapse,
    check_c5_premature_compression,
)
from ..evaluators import get_evaluator
from ..evaluators.regex_deny import is_regex_deny_rule, parse_regex_deny, make_regex_deny_check


# =============================================================================
# NAMESPACED CHECK REGISTRY
# =============================================================================

# Maps sanna.* check implementation IDs to check functions
CHECK_REGISTRY: dict[str, Callable] = {
    "sanna.context_contradiction": check_c1_context_contradiction,
    "sanna.unmarked_inference": check_c2_unmarked_inference,
    "sanna.false_certainty": check_c3_false_certainty,
    "sanna.conflict_collapse": check_c4_conflict_collapse,
    "sanna.premature_compression": check_c5_premature_compression,
}

# Legacy C1-C5 aliases for CHECK_REGISTRY
_LEGACY_CHECK_ALIASES: dict[str, str] = {
    "C1": "sanna.context_contradiction",
    "C2": "sanna.unmarked_inference",
    "C3": "sanna.false_certainty",
    "C4": "sanna.conflict_collapse",
    "C5": "sanna.premature_compression",
}


# =============================================================================
# INVARIANT → CHECK MAPPING
# =============================================================================

# Maps standard invariant IDs to (check_impl_id, check_fn) tuples
INVARIANT_CHECK_MAP: dict[str, tuple[str, Callable]] = {
    "INV_NO_FABRICATION": ("sanna.context_contradiction", check_c1_context_contradiction),
    "INV_MARK_INFERENCE": ("sanna.unmarked_inference", check_c2_unmarked_inference),
    "INV_NO_FALSE_CERTAINTY": ("sanna.false_certainty", check_c3_false_certainty),
    "INV_PRESERVE_TENSION": ("sanna.conflict_collapse", check_c4_conflict_collapse),
    "INV_NO_PREMATURE_COMPRESSION": ("sanna.premature_compression", check_c5_premature_compression),
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CheckConfig:
    """Configuration for a single check derived from a constitution invariant."""
    check_id: str              # "sanna.context_contradiction" (namespaced)
    check_fn: Callable         # the actual check function
    enforcement_level: str     # "halt" | "warn" | "log"
    triggered_by: str          # "INV_NO_FABRICATION"
    check_impl: str = ""       # Namespaced implementation ID (e.g., "sanna.context_contradiction")
    source: str = "builtin"    # "builtin" or "custom_evaluator"


@dataclass
class CustomInvariantRecord:
    """Record for a custom invariant that has no evaluator."""
    invariant_id: str
    rule: str
    enforcement: str
    status: str = "NOT_CHECKED"
    reason: str = "Custom invariant — no evaluator registered."


# =============================================================================
# CONFIGURATION
# =============================================================================

def configure_checks(constitution) -> tuple[list[CheckConfig], list[CustomInvariantRecord]]:
    """Read constitution invariants, return configured checks and custom invariant records.

    Rules:
    - If invariant has a `check` field → look up in CHECK_REGISTRY (or legacy aliases)
    - Else if invariant ID matches a standard INV_* → map to check function
    - Otherwise → record as NOT_CHECKED (custom invariant)
    - If constitution has no invariants → return empty (no checks run)

    Args:
        constitution: A Constitution object with an invariants field.

    Returns:
        Tuple of (check_configs, custom_records).
    """
    check_configs: list[CheckConfig] = []
    custom_records: list[CustomInvariantRecord] = []

    for invariant in constitution.invariants:
        # 1. Try explicit check: field
        if invariant.check:
            check_impl_id = invariant.check
            check_fn = CHECK_REGISTRY.get(check_impl_id)
            # Try legacy alias (e.g., "C1" → "sanna.context_contradiction")
            if check_fn is None and check_impl_id in _LEGACY_CHECK_ALIASES:
                resolved = _LEGACY_CHECK_ALIASES[check_impl_id]
                check_fn = CHECK_REGISTRY.get(resolved)
                check_impl_id = resolved
            if check_fn is not None:
                check_configs.append(CheckConfig(
                    check_id=check_impl_id,
                    check_fn=check_fn,
                    enforcement_level=invariant.enforcement,
                    triggered_by=invariant.id,
                    check_impl=check_impl_id,
                ))
            else:
                custom_records.append(CustomInvariantRecord(
                    invariant_id=invariant.id,
                    rule=invariant.rule,
                    enforcement=invariant.enforcement,
                    reason=f"Check '{invariant.check}' not found in registry.",
                ))
            continue

        # 2. Try standard INVARIANT_CHECK_MAP
        mapping = INVARIANT_CHECK_MAP.get(invariant.id)
        if mapping is not None:
            check_impl_id, check_fn = mapping
            check_configs.append(CheckConfig(
                check_id=check_impl_id,
                check_fn=check_fn,
                enforcement_level=invariant.enforcement,
                triggered_by=invariant.id,
                check_impl=check_impl_id,
            ))
            continue

        # 3. Try regex_deny pattern in rule field
        if is_regex_deny_rule(invariant.rule):
            pattern = parse_regex_deny(invariant.rule)
            if pattern is not None:
                description = getattr(invariant, "description", "") or invariant.id
                check_fn = make_regex_deny_check(
                    invariant_id=invariant.id,
                    description=description,
                    pattern=pattern,
                )
                check_configs.append(CheckConfig(
                    check_id=invariant.id,
                    check_fn=check_fn,
                    enforcement_level=invariant.enforcement,
                    triggered_by=invariant.id,
                    check_impl="regex_deny",
                    source="regex_deny",
                ))
                continue

        # 4. Try custom evaluator registry
        evaluator = get_evaluator(invariant.id)
        if evaluator is not None:
            check_configs.append(CheckConfig(
                check_id=invariant.id,
                check_fn=_wrap_evaluator(evaluator, constitution, invariant),
                enforcement_level=invariant.enforcement,
                triggered_by=invariant.id,
                check_impl="custom_evaluator",
                source="custom_evaluator",
            ))
        else:
            custom_records.append(CustomInvariantRecord(
                invariant_id=invariant.id,
                rule=invariant.rule,
                enforcement=invariant.enforcement,
            ))

    return check_configs, custom_records


def _wrap_evaluator(eval_fn: Callable, constitution, invariant) -> Callable:
    """Wrap a custom evaluator to match the CheckConfig.check_fn interface.

    The wrapper:
    - Converts the constitution object and invariant to dicts
    - Adapts the call signature from ``(context, output, enforcement=)``
      to ``(context, output, constitution_dict, check_config_dict)``
    - Validates the return type is CheckResult
    """
    from ..constitution import constitution_to_dict
    const_dict = constitution_to_dict(constitution)
    inv_config = {
        "id": invariant.id,
        "rule": invariant.rule,
        "enforcement": invariant.enforcement,
        "check": invariant.check,
    }

    def wrapper(context, output, enforcement="log", **kwargs):
        result = eval_fn(context, output, const_dict, inv_config)
        if not isinstance(result, CheckResult):
            raise TypeError(
                f"Evaluator for '{invariant.id}' must return CheckResult, "
                f"got {type(result).__name__}"
            )
        return result
    return wrapper
