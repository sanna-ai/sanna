"""Safe JSON parsing with duplicate key detection.

Security rationale
------------------
Python's ``json.loads()`` uses last-wins semantics on duplicate keys.
An attacker can craft a JSON document with two ``"status"`` keys -- different
parsers (Python, Go, Java) may interpret the value differently, undermining
cross-platform verification.

This module provides drop-in replacements for ``json.loads()`` and
``json.load()`` that reject duplicate keys at *all* nesting levels via
``object_pairs_hook``.
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


def safe_json_loads(s: str) -> dict:
    """Parse JSON string, rejecting duplicate keys at all nesting levels."""
    return json.loads(s, object_pairs_hook=_reject_duplicate_keys)


def safe_json_load(fp: IO[str]) -> dict:
    """Parse JSON from a file object, rejecting duplicate keys at all nesting levels."""
    return json.load(fp, object_pairs_hook=_reject_duplicate_keys)
