"""API-specific authority evaluation.

Evaluates HTTP method + URL patterns against constitution api_permissions.
Separate from enforcement/authority.py (which handles MCP tool names) and
cli_authority.py (which handles subprocess binary names).

API authority uses:
- URL pattern: glob matching via fnmatch against the full URL
- Method matching: list of allowed methods, or ["*"] for any
- Rule order: declaration order, first match wins
- Mode: strict (unlisted denied) vs permissive (unlisted allowed with audit)
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ApiAuthorityDecision:
    """Result of evaluating an HTTP request against api_permissions."""
    decision: str          # "halt", "allow", "escalate"
    reason: str
    rule_id: Optional[str] = None
    escalation_target: Optional[str] = None


def evaluate_api_authority(
    method: str,
    url: str,
    constitution,
) -> ApiAuthorityDecision:
    """Evaluate an HTTP request against constitution api_permissions.

    Rule evaluation: declaration order, first match wins.
    URL matching: fnmatch glob patterns against the full URL.
    Method matching: list of allowed methods, or ["*"] for any.
    """
    api_perms = getattr(constitution, "api_permissions", None)
    if api_perms is None:
        return ApiAuthorityDecision(
            decision="allow",
            reason="No api_permissions in constitution",
        )

    for endpoint in api_perms.endpoints:
        # URL match: glob pattern
        if not fnmatch.fnmatch(url, endpoint.url_pattern):
            continue

        # Method match
        methods = endpoint.methods or ["*"]
        if "*" not in methods and method.upper() not in [m.upper() for m in methods]:
            continue

        # Both match: apply authority
        if endpoint.authority == "cannot_execute":
            return ApiAuthorityDecision(
                decision="halt",
                reason=f"URL '{url}' method '{method}' matches cannot_execute rule: {endpoint.id}",
                rule_id=endpoint.id,
            )
        elif endpoint.authority == "must_escalate":
            return ApiAuthorityDecision(
                decision="escalate",
                reason=f"URL '{url}' method '{method}' matches must_escalate rule: {endpoint.id}",
                rule_id=endpoint.id,
                escalation_target=endpoint.escalation_target,
            )
        else:  # can_execute
            # Authority allows — check invariants before returning
            inv_decision = _check_api_invariants(url, api_perms)
            if inv_decision is not None:
                return inv_decision
            return ApiAuthorityDecision(
                decision="allow",
                reason=f"URL '{url}' method '{method}' matches can_execute rule: {endpoint.id}",
                rule_id=endpoint.id,
            )

    # No rule matched: apply mode
    if api_perms.mode == "strict":
        return ApiAuthorityDecision(
            decision="halt",
            reason=f"URL '{url}' not matched in strict mode api_permissions",
        )
    else:  # permissive
        # Still check invariants for permissive mode
        inv_decision = _check_api_invariants(url, api_perms)
        if inv_decision is not None:
            return inv_decision
        return ApiAuthorityDecision(
            decision="allow",
            reason=f"URL '{url}' not matched (permissive mode, audit receipt emitted)",
        )


def check_api_invariants(url: str, constitution):
    """Check URL against api_permissions invariants (regex patterns).

    Returns the matching invariant if found, None otherwise.
    """
    api_perms = getattr(constitution, "api_permissions", None)
    if api_perms is None or not api_perms.invariants:
        return None

    for inv in api_perms.invariants:
        if inv.pattern is None:
            continue
        try:
            if re.search(inv.pattern, url):
                return inv
        except re.error:
            pass

    return None


def _check_api_invariants(url: str, api_perms) -> Optional[ApiAuthorityDecision]:
    """Check URL against api_permissions invariants.

    Returns a halt decision if an invariant matches, None otherwise.
    """
    if not api_perms.invariants:
        return None

    for inv in api_perms.invariants:
        if inv.pattern is None:
            continue
        try:
            if re.search(inv.pattern, url):
                if inv.verdict == "halt":
                    return ApiAuthorityDecision(
                        decision="halt",
                        reason=f"Invariant '{inv.id}' matched: {inv.description}",
                        rule_id=inv.id,
                    )
        except re.error:
            pass

    return None
