"""
Canonical hashing for deterministic receipts across platforms.

Sanna Canonical JSON — see spec/sanna-specification-v1.0.md

Supported types: str, int, float, bool, None, list, dict.

Floats are serialized as JSON numbers by Python's ``json.dumps``,
which uses ``float.__repr__`` (shortest unique decimal representation,
deterministic across platforms since Python 3.1+).  Non-finite floats
(NaN, Infinity) are rejected because JSON does not support them.

Prior to v0.12.2, floats were rejected entirely and
``normalize_floats`` converted them to fixed-precision strings.
This caused a hash collision: ``{"val": 1.0}`` (float) and
``{"val": "1.0000000000"}`` (string) produced identical canonical
bytes.  Since v0.12.2 floats remain as JSON numbers, eliminating
the collision.
"""

import hashlib
import json
import math
import unicodedata
from typing import Any


def normalize_floats(obj: Any) -> Any:
    """Identity pass-through — retained for backward compatibility.

    Prior to v0.12.2 this converted every float to a 10-decimal-place
    string (e.g. ``1.0`` → ``"1.0000000000"``).  That caused a type
    collision: a float and a string with the same digits hashed
    identically.

    Since v0.12.2, ``canonical_json_bytes`` handles floats natively
    as JSON numbers, so no pre-processing is needed.  This function
    is kept so existing callers (``receipt_v2.py``, ``server.py``)
    continue to work without changes.
    """
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

    Covers str, int, float, bool, None, list, dict.  Non-finite
    floats (NaN, Infinity) are rejected.  Finite floats are
    serialized as JSON numbers.
    """
    _reject_floats(obj)
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
