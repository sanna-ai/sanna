"""
Sanna enforcement engine — constitution-driven check configuration
and authority boundary enforcement.

Maps constitution invariants to check functions and enforcement levels.
Evaluates actions against authority boundaries (cannot_execute, must_escalate,
can_execute).
"""

from .constitution_engine import (
    CheckConfig,
    CustomInvariantRecord,
    configure_checks,
    INVARIANT_CHECK_MAP,
    CHECK_REGISTRY,
)

from .authority import (
    AuthorityDecision,
    evaluate_authority,
)

from .escalation import (
    EscalationTarget,
    EscalationResult,
    execute_escalation,
    register_escalation_callback,
    clear_escalation_callbacks,
    get_escalation_callback,
)

__all__ = [
    "CheckConfig",
    "CustomInvariantRecord",
    "configure_checks",
    "INVARIANT_CHECK_MAP",
    "CHECK_REGISTRY",
    "AuthorityDecision",
    "evaluate_authority",
    "EscalationTarget",
    "EscalationResult",
    "execute_escalation",
    "register_escalation_callback",
    "clear_escalation_callbacks",
    "get_escalation_callback",
]
