"""
Canonical hashing for deterministic receipts across platforms.

Canonicalization follows RFC 8785 (JSON Canonicalization Scheme) for the
restricted type set used by Sanna: str, int, bool, None, list, dict.
Floats are rejected at serialization time — all numeric values must be
integers.  This avoids IEEE 754 representation ambiguity and guarantees
deterministic canonical bytes across every Python implementation.
"""

import hashlib
import json
import unicodedata
from typing import Any


def normalize_floats(obj: Any) -> Any:
    """Convert floats to deterministic string representation for hashing.

    RFC 8785 canonical JSON rejects floats because IEEE 754 representation
    is ambiguous across platforms.  This function replaces every float with
    a fixed-precision string (10 decimal places) so the result can pass
    through ``canonical_json_bytes`` without fallback.

    Non-float values (int, str, bool, None, dict, list) pass through
    unchanged.
    """
    if isinstance(obj, float):
        return f"{obj:.10f}"
    if isinstance(obj, dict):
        return {k: normalize_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize_floats(v) for v in obj]
    return obj


def _reject_floats(obj: Any, path: str = "$") -> None:
    """Recursively reject float values in a structure.

    Raises TypeError with the JSON-path of the offending value so the
    caller can fix it before canonicalization.
    """
    if isinstance(obj, float):
        raise TypeError(
            f"Float value {obj!r} at {path} — Sanna requires integers for "
            f"RFC 8785 canonical JSON.  Convert to int (e.g. basis points)."
        )
    if isinstance(obj, dict):
        for key, val in obj.items():
            _reject_floats(val, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for idx, val in enumerate(obj):
            _reject_floats(val, f"{path}[{idx}]")


def canonicalize_text(s: str) -> str:
    """Normalize text for consistent hashing across platforms."""
    if s is None:
        return ""
    # Unicode normalization (NFC)
    s = unicodedata.normalize("NFC", s)
    # Normalize line endings
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # Strip trailing whitespace per line (prevents OS/editor diffs)
    s = "\n".join(line.rstrip() for line in s.split("\n"))
    return s.strip()


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize *obj* to RFC 8785 canonical JSON bytes.

    The implementation covers the restricted type set used by Sanna
    (str, int, bool, None, list, dict).  Floats are rejected — call
    sites must use integers (e.g. basis-points instead of percentages).
    """
    _reject_floats(obj)
    canon = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),  # no spaces
        ensure_ascii=False,
    )
    return canon.encode("utf-8")


def sha256_hex(data: bytes, truncate: int = 16) -> str:
    """SHA256 hash, optionally truncated."""
    full_hash = hashlib.sha256(data).hexdigest()
    return full_hash[:truncate] if truncate else full_hash


def hash_text(s: str, truncate: int = 16) -> str:
    """Hash canonicalized text."""
    return sha256_hex(canonicalize_text(s).encode("utf-8"), truncate)


def hash_obj(obj: Any, truncate: int = 16) -> str:
    """Hash canonicalized JSON object."""
    return sha256_hex(canonical_json_bytes(obj), truncate)
