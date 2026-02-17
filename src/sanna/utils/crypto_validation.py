"""Structural validation helpers for cryptographic signatures.

These are lightweight pre-checks — they verify structural validity
(base64 encoding, expected length) without performing full
cryptographic verification against a public key.
"""

from __future__ import annotations

import base64

# Ed25519 signatures are always 64 bytes
ED25519_SIGNATURE_LENGTH = 64


def is_valid_signature_structure(sig) -> bool:
    """Check if a signature has valid Ed25519 structure.

    Validates that the signature value is non-empty, valid base64, and
    decodes to exactly 64 bytes. This is a structural check, not
    cryptographic verification.

    Args:
        sig: A signature object with a ``value`` attribute, or None.

    Returns:
        True if the signature has valid Ed25519 structure.
    """
    if not sig or not getattr(sig, 'value', None):
        return False
    value = sig.value.strip()
    if not value:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
        return len(decoded) == ED25519_SIGNATURE_LENGTH
    except Exception:
        return False
