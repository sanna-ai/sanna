"""
Canonical hashing for deterministic receipts across platforms.

Sanna Canonical JSON — see spec/sanna-specification-v1.0.md

Supported types: str, int, bool, None, list, dict.

Since v0.13.2, ``normalize_floats`` converts exact-integer floats
(e.g. 3.0) to int and rejects non-integer floats (e.g. 3.14) and
non-finite floats (NaN, Infinity).  This ensures identical hashes
for ``{"val": 1.0}`` and ``{"val": 1}`` across all platforms.
"""

import hashlib
import json
import math
import unicodedata
from typing import Any


def normalize_floats(obj: Any) -> Any:
    """Normalize floats for canonical hashing.

    - Exact-integer floats (3.0) are converted to int (3)
    - Negative zero (-0.0) is converted to int(0)
    - Non-finite floats (NaN, Infinity) raise TypeError
    - Non-integer floats (3.14) raise ValueError

    This ensures cross-platform determinism: ``{"val": 1.0}`` and
    ``{"val": 1}`` produce identical canonical bytes.

    Applied recursively to nested dicts, lists, and tuples.
    """
    if isinstance(obj, bool):
        # bool is a subclass of int — must check before int
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise TypeError(
                f"Non-finite float not allowed in canonical JSON: {obj!r}"
            )
        if obj == 0.0 and math.copysign(1.0, obj) < 0:
            return 0  # Normalize -0.0 to 0
        if obj.is_integer():
            return int(obj)
        raise ValueError(
            f"Non-integer float not allowed in canonical JSON: {obj!r}"
        )
    if isinstance(obj, dict):
        return {k: normalize_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize_floats(v) for v in obj]
    return obj


def _reject_floats(obj: Any, path: str = "$") -> None:
    """Reject non-finite float values (NaN, Infinity) in a structure.

    Finite floats are now allowed (since v0.12.2).  Only NaN and
    Infinity are rejected because JSON does not support them.

    Prior to v0.12.2 this rejected ALL floats.
    """
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise TypeError(
                f"Non-finite float {obj!r} at {path} — JSON does not "
                f"support NaN or Infinity."
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
    """Serialize *obj* to Sanna Canonical JSON bytes.

    Sanna Canonical JSON — see spec/sanna-specification-v1.0.md

    Covers str, int, float, bool, None, list, dict.

    Float handling:
    - Exact-integer floats (3.0) are normalized to int (3)
    - Negative zero (-0.0) is normalized to int(0)
    - Non-finite floats (NaN, Infinity) raise TypeError
    - Non-integer floats (3.14) raise ValueError
    """
    obj = normalize_floats(obj)
    canon = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),  # no spaces
        ensure_ascii=False,
    )
    return canon.encode("utf-8")


def sha256_hex(data: bytes, truncate: int = 64) -> str:
    """SHA256 hash, optionally truncated.

    Default is full 64-hex SHA-256.  Pass ``truncate=16`` for the
    short human-readable form used in ``receipt_fingerprint``.
    """
    full_hash = hashlib.sha256(data).hexdigest()
    return full_hash[:truncate] if truncate else full_hash


#: Sentinel hash for absent fields in the fingerprint formula.
#: SHA-256 of zero bytes: e3b0c44298fc1c149afbf4c8996fb924...
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def hash_text(s: str, truncate: int = 64) -> str:
    """Hash canonicalized text."""
    return sha256_hex(canonicalize_text(s).encode("utf-8"), truncate)


def hash_obj(obj: Any, truncate: int = 64) -> str:
    """Hash canonicalized JSON object."""
    return sha256_hex(canonical_json_bytes(obj), truncate)
