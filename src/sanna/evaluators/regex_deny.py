"""
Regex-deny evaluator for constitution invariants.

Parses invariants whose ``rule`` field starts with ``regex_deny pattern:``
and checks whether the regex matches the combined context + output text.
A match means the invariant is VIOLATED (the pattern describes something
that should NOT be present).

The regex is compiled with ``re.IGNORECASE`` by default.  Constitutions
control this via the ``/i`` flag suffix in the pattern (e.g.,
``regex_deny pattern: /\\bsudo\\b/i``).

This module is auto-invoked by ``configure_checks()`` in the constitution
engine — no manual registration is required.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from ..receipt import CheckResult

logger = logging.getLogger("sanna.evaluators.regex_deny")

# Prefix that marks a rule as a regex_deny pattern
REGEX_DENY_PREFIX = "regex_deny pattern:"


def is_regex_deny_rule(rule: str) -> bool:
    """Return True if *rule* uses the ``regex_deny pattern:`` syntax."""
    return rule.strip().lower().startswith(REGEX_DENY_PREFIX.lower())


def parse_regex_deny(rule: str) -> Optional[re.Pattern]:
    """Parse a ``regex_deny pattern: /PATTERN/FLAGS`` rule into a compiled regex.

    Supported flags: ``i`` (case-insensitive).  The ``/`` delimiters are
    optional — bare patterns (without slashes) are accepted and compiled
    with ``re.IGNORECASE`` by default.

    Returns ``None`` if the pattern is empty or invalid.
    """
    raw = rule.strip()
    # Strip the prefix (case-insensitive)
    body = raw[len(REGEX_DENY_PREFIX):].strip()
    if not body:
        return None

    flags = re.IGNORECASE  # default

    # Try /pattern/flags format
    if body.startswith("/"):
        last_slash = body.rfind("/")
        if last_slash > 0:
            pattern_str = body[1:last_slash]
            flag_str = body[last_slash + 1:].strip().lower()
            flags = 0
            if "i" in flag_str:
                flags |= re.IGNORECASE
        else:
            # Single slash, treat rest as pattern
            pattern_str = body[1:]
    else:
        pattern_str = body

    if not pattern_str:
        return None

    try:
        return re.compile(pattern_str, flags)
    except re.error as exc:
        logger.warning("Invalid regex_deny pattern in invariant: %s — %s", body, exc)
        return None


def evaluate_regex_deny(
    invariant_id: str,
    description: str,
    pattern: re.Pattern,
    context: str,
    output: str,
    **kwargs,
) -> CheckResult:
    """Check whether *pattern* matches the combined context + output.

    A match means the pattern (something forbidden) was found → check fails.
    No match means the content is clean → check passes.
    """
    combined = f"{context}\n{output}"
    match = pattern.search(combined)
    if match:
        return CheckResult(
            check_id=invariant_id,
            name=description or invariant_id,
            passed=False,
            severity="critical",
            evidence=f"Matched forbidden pattern: '{match.group()}' in content",
        )
    return CheckResult(
        check_id=invariant_id,
        name=description or invariant_id,
        passed=True,
        severity="info",
        evidence="",
    )


def make_regex_deny_check(
    invariant_id: str,
    description: str,
    pattern: re.Pattern,
):
    """Create a check function compatible with CheckConfig.check_fn.

    The returned callable has the signature
    ``(context, output, enforcement="log", **kwargs) -> CheckResult``.
    """
    def check_fn(context, output, enforcement="log", **kwargs):
        return evaluate_regex_deny(
            invariant_id=invariant_id,
            description=description,
            pattern=pattern,
            context=str(context) if context else "",
            output=str(output) if output else "",
        )
    return check_fn
