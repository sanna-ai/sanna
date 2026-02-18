"""Safe JSON parsing with duplicate key detection and non-standard constant rejection.

Security rationale
------------------
Python's ``json.loads()`` uses last-wins semantics on duplicate keys.
An attacker can craft a JSON document with two ``"status"`` keys -- different
parsers (Python, Go, Java) may interpret the value differently, undermining
cross-platform verification.

Additionally, Python's ``json.loads()`` accepts non-standard ``NaN``,
``Infinity``, and ``-Infinity`` constants.  These cannot be round-tripped
through Sanna Canonical JSON (which rejects non-finite floats), so they
are rejected at parse time to prevent downstream crashes.

This module provides drop-in replacements for ``json.loads()`` and
``json.load()`` that reject duplicate keys and non-standard constants
at *all* nesting levels.
"""

from __future__ import annotations

import json
from typing import IO


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """Object pairs hook that raises on duplicate keys."""
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"Duplicate JSON key: {key!r}")
        seen[key] = value
    return seen


def _reject_non_standard_constant(constant: str) -> object:
    """Reject non-standard JSON constants (NaN, Infinity, -Infinity)."""
    raise ValueError(
        f"Non-standard JSON constant not allowed: {constant!r}. "
        f"JSON does not support NaN or Infinity."
    )


def safe_json_loads(s: str) -> dict:
    """Parse JSON string, rejecting duplicate keys and non-standard constants."""
    return json.loads(
        s,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_standard_constant,
    )


def safe_json_load(fp: IO[str]) -> dict:
    """Parse JSON from a file object, rejecting duplicate keys and non-standard constants."""
    return json.load(
        fp,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_standard_constant,
    )
