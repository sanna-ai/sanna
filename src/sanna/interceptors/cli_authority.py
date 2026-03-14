"""CLI-specific authority evaluation.

Evaluates binary name + argv patterns against constitution cli_permissions.
Separate from enforcement/authority.py (which handles MCP tool names via
case-insensitive substring matching with NFKC normalization).

CLI authority uses:
- Binary name: exact match, case-sensitive
- Argv pattern: glob matching via fnmatch against joined argv string
- Rule order: declaration order, first match wins
- Mode: strict (unlisted denied) vs permissive (unlisted allowed with audit)
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class CliAuthorityDecision:
    """Result of evaluating a CLI invocation against cli_permissions."""
    decision: str          # "halt", "allow", "escalate"
    reason: str
    rule_id: Optional[str] = None
    escalation_target: Optional[str] = None


def evaluate_cli_authority(
    binary: str,
    argv: list[str],
    constitution,
) -> CliAuthorityDecision:
    """Evaluate a CLI invocation against constitution cli_permissions.

    Rule evaluation: declaration order, first match wins.
    Mode: strict = unlisted denied, permissive = unlisted allowed with audit.

    After authority allows, invariants are checked against the full command
    string. Invariant matches can override the allow decision.
    """
    cli_perms = getattr(constitution, "cli_permissions", None)
    if cli_perms is None:
        # No cli_permissions block: allow everything (backward compat)
        return CliAuthorityDecision(
            decision="allow",
            reason="No cli_permissions in constitution",
        )

    argv_str = " ".join(argv)

    for cmd in cli_perms.commands:
        # Binary match: exact, case-sensitive
        if cmd.binary != binary:
            continue

        # Argv pattern match: glob against joined argv string
        pattern = cmd.argv_pattern or "*"
        if pattern == "*" or fnmatch.fnmatch(argv_str, pattern):
            if cmd.authority == "cannot_execute":
                return CliAuthorityDecision(
                    decision="halt",
                    reason=f"Binary '{binary}' matches cannot_execute rule: {cmd.id}",
                    rule_id=cmd.id,
                )
            elif cmd.authority == "must_escalate":
                return CliAuthorityDecision(
                    decision="escalate",
                    reason=f"Binary '{binary}' matches must_escalate rule: {cmd.id}",
                    rule_id=cmd.id,
                    escalation_target=cmd.escalation_target,
                )
            else:  # can_execute
                # Authority allows — check invariants before returning
                inv_decision = _check_invariants(binary, argv, cli_perms)
                if inv_decision is not None:
                    return inv_decision
                return CliAuthorityDecision(
                    decision="allow",
                    reason=f"Binary '{binary}' matches can_execute rule: {cmd.id}",
                    rule_id=cmd.id,
                )

    # No rule matched: apply mode
    if cli_perms.mode == "strict":
        return CliAuthorityDecision(
            decision="halt",
            reason=f"Binary '{binary}' not listed in strict mode cli_permissions",
        )
    else:  # permissive
        # Still check invariants for permissive mode
        inv_decision = _check_invariants(binary, argv, cli_perms)
        if inv_decision is not None:
            return inv_decision
        return CliAuthorityDecision(
            decision="allow",
            reason=f"Binary '{binary}' not listed (permissive mode, audit receipt emitted)",
        )


def _check_invariants(
    binary: str,
    argv: list[str],
    cli_perms,
) -> Optional[CliAuthorityDecision]:
    """Check CLI invariants against the full command string.

    Returns a halt/warn decision if an invariant matches, None otherwise.
    """
    full_cmd = f"{binary} {' '.join(argv)}"

    for inv in cli_perms.invariants:
        if inv.pattern is None:
            continue
        try:
            if re.search(inv.pattern, full_cmd):
                if inv.verdict == "halt":
                    return CliAuthorityDecision(
                        decision="halt",
                        reason=f"Invariant '{inv.id}' matched: {inv.description}",
                        rule_id=inv.id,
                    )
                # "warn" verdict: don't halt, but the receipt will note it
                # Fall through to allow
        except re.error:
            # Invalid regex pattern — skip silently
            pass

    return None
