"""
Custom invariant evaluator registry.

Allows users to register Python functions as evaluators for custom invariants.
When a constitution defines an invariant that has no built-in check (C1-C5),
the evaluator registry is consulted before falling through to NOT_CHECKED.

Usage::

    from sanna.evaluators import register_invariant_evaluator
    from sanna.receipt import CheckResult

    @register_invariant_evaluator("INV_CUSTOM_PII")
    def check_pii(context, output, constitution, check_config):
        if "SSN" in output:
            return CheckResult(
                check_id="INV_CUSTOM_PII",
                name="PII Check",
                passed=False,
                severity="critical",
                details="Output contains SSN pattern",
            )
        return CheckResult(
            check_id="INV_CUSTOM_PII",
            name="PII Check",
            passed=True,
            severity="info",
        )
"""

from __future__ import annotations

from typing import Callable, Optional

from .receipt import CheckResult

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_EVALUATOR_REGISTRY: dict[str, Callable] = {}


def register_invariant_evaluator(invariant_id: str):
    """Decorator that registers a function as the evaluator for *invariant_id*.

    The decorated function must have the signature::

        (context: str, output: str, constitution: dict, check_config: dict) -> CheckResult

    Raises ``ValueError`` if *invariant_id* is already registered.
    Returns the original function unchanged.
    """
    def decorator(fn: Callable) -> Callable:
        if invariant_id in _EVALUATOR_REGISTRY:
            raise ValueError(
                f"Evaluator already registered for invariant '{invariant_id}'"
            )
        _EVALUATOR_REGISTRY[invariant_id] = fn
        return fn
    return decorator


def get_evaluator(invariant_id: str) -> Optional[Callable]:
    """Return the registered evaluator for *invariant_id*, or ``None``."""
    return _EVALUATOR_REGISTRY.get(invariant_id)


def list_evaluators() -> list[str]:
    """Return all registered invariant IDs."""
    return list(_EVALUATOR_REGISTRY.keys())


def clear_evaluators() -> None:
    """Remove all registered evaluators.  Useful for test isolation."""
    _EVALUATOR_REGISTRY.clear()
