"""SAN-406: com.sanna.anomaly extension field-level redaction (spec Section 2.22.5).

Mirrors the Section 2.14 manifest redaction pattern in manifest.py but with
single-value (not list) semantics. The redacted value substitutes for the
attempted_tool / attempted_command / attempted_endpoint field in
com.sanna.anomaly extension emissions, per the operator-configured
content_mode.

content_mode semantics (spec Section 2.22.5 + 2.14):
- "full" or None: emit raw value (current behavior preserved)
- "redacted": substitute literal "<redacted>"
- "hashes_only": substitute SHA-256 hex (lowercase) of original value
  via the canonical hash_text helper (NFC + UTF-8 + SHA-256 + lowercase
  per Sanna canonical hashing).

Note on "hashes_only" privacy: SHA-256 of short capability names
(e.g., "ls", "/api/users") is rainbow-table reversible. The mode is for
audit-time deterministic comparison, not privacy. Operators relying on
strong privacy MUST use "redacted".
"""
from __future__ import annotations

from typing import Optional


def redact_attempted_field(value: str, content_mode: Optional[str]) -> str:
    """Apply Section 2.22.5 redaction to a com.sanna.anomaly attempted_* field.

    Args:
        value: The raw capability name (tool / command / endpoint).
        content_mode: The receipt's content_mode value. One of "full",
            "redacted", "hashes_only", or None (treated as "full").

    Returns:
        The redacted value per content_mode. For "full" / None, the input is
        returned unchanged.

    Raises:
        ValueError: If content_mode is set but not one of the valid enum
            values. The schema enforces the enum at the receipt level; this
            defensive check catches programming errors at emission time.
    """
    # SAN-406: treat empty/falsy as raw mode (full). Empty string is not a valid
    # spec enum but appears as a sentinel in some test stubs (e.g.,
    # gateway/server.py constructor sets self._content_mode = "" when not
    # configured). Production code paths emit None or one of the 3 enums; the
    # defensive check keeps the helper compatible with both.
    if not content_mode or content_mode == "full":
        return value
    if content_mode == "redacted":
        return "<redacted>"
    if content_mode == "hashes_only":
        from .hashing import hash_text
        return hash_text(value)
    raise ValueError(
        f"unknown content_mode {content_mode!r}; expected one of "
        "'full', 'redacted', 'hashes_only', or None"
    )
