"""Receipt redaction primitives (spec section 2.11.1).

Applies redaction markers to specified receipt fields BEFORE signing,
so that the receipt signature, context_hash, output_hash, and
fingerprints all cover the markers (not the original PII).

This module is the canonical location for redaction logic. The
gateway server and the @sanna_observe middleware both consume it.

See:
- spec/sanna-specification-v1.5.md section 2.11 Redaction Markers
- spec section 2.11.1 Redaction Marker Schema
- spec section 2.11.4 Pre-existing Marker Injection Guard (FIX-12)
"""

import hashlib
import hmac
import json
import logging
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from .fingerprint import compute_fingerprints
from .hashing import hash_obj

logger = logging.getLogger(__name__)


@dataclass
class RedactionConfig:
    """PII redaction controls for receipt content.

    When enabled, redaction markers replace specified field values
    BEFORE signing. The receipt signature covers the markers, not
    the original content. The receipt's ``content_mode`` metadata is
    set to ``'redacted'`` to declare the redaction state.

    Attributes:
        enabled: Whether redaction is active. ``False`` by default.
        mode: ``'hash_only'`` replaces content with deterministic marker.
            ``'pattern_redact'`` is reserved for future regex-based PII
            detection (not yet implemented).
        fields: Receipt fields to redact. Supported values:
            ``'arguments'`` (inputs.context) and ``'result_text'``
            (outputs.response).
    """

    enabled: bool = False
    mode: str = "hash_only"
    fields: list[str] = field(
        default_factory=lambda: ["arguments", "result_text"],
    )


def _redact_for_storage(
    content: str,
    mode: str = "hash_only",
    salt: str = "",
    secret: bytes | None = None,
) -> str:
    """Replace content with a redacted placeholder for receipt storage.

    Args:
        content: The original content to redact.
        mode: Redaction mode — ``"hash_only"`` replaces with HMAC-SHA256.
        salt: Per-receipt salt (e.g. receipt_id) appended before hashing.
            Prevents rainbow-table reversal of low-entropy inputs.
        secret: Gateway HMAC secret. When provided, uses HMAC-SHA256
            instead of plain SHA-256 (prevents offline brute-force).

    Returns:
        Redacted string with HMAC hash reference for auditability.
    """
    if mode == "hash_only":
        # NFC-normalize Unicode before hashing so that equivalent
        # representations (e.g. e + combining-acute vs. precomposed e-acute)
        # always produce the same redaction hash.
        normalized = unicodedata.normalize("NFC", content)
        payload = (normalized + salt).encode()
        if secret:
            digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            return f"[REDACTED — HMAC-SHA256: {digest}]"
        # Fallback for callers without a secret (shouldn't happen in practice)
        digest = hashlib.sha256(payload).hexdigest()
        return f"[REDACTED — SHA-256-SALTED: {digest}]"
    # "pattern_redact" should be rejected at config load time; raise here
    # as defense-in-depth if it somehow reaches the runtime path.
    raise ValueError(
        f"Unsupported redaction mode: '{mode}'. "
        f"pattern_redact is not yet implemented."
    )


def _make_redaction_marker(original_value: str) -> dict:
    """Build a deterministic redaction marker for a field value.

    The marker replaces the original value in the receipt BEFORE signing,
    so that ``context_hash``/``output_hash`` and the receipt signature
    all cover the marker (not the original content).

    The ``original_hash`` is the SHA-256 hex digest of the original
    string value, allowing offline auditors to confirm provenance
    without access to the raw PII.

    Args:
        original_value: The raw string to redact.

    Returns:
        Deterministic marker dict:
        ``{"__redacted__": True, "original_hash": "<sha256-hex>"}``
    """
    normalized = unicodedata.normalize("NFC", original_value)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return {"__redacted__": True, "original_hash": digest}


def _apply_redaction_markers(receipt: dict, redaction_fields: list[str]) -> tuple[dict, list[str]]:
    """Replace redactable field values with deterministic markers.

    Modifies the receipt **in place** and recomputes ``context_hash``,
    ``output_hash``, ``receipt_fingerprint``, and ``full_fingerprint``
    so that the receipt is internally consistent with the markers.

    Must be called BEFORE signing.

    Args:
        receipt: The receipt dict (mutated in place).
        redaction_fields: List of field names to redact
            (``"arguments"`` maps to ``inputs.context``,
             ``"result_text"`` maps to ``outputs.response``).

    Returns:
        A tuple of ``(receipt, redacted_paths)`` where
        ``redacted_paths`` is a list of JSON-path strings
        for fields that were actually redacted.
    """
    redacted_paths: list[str] = []

    # Apply markers to specified fields
    if "arguments" in redaction_fields:
        ctx = (receipt.get("inputs") or {}).get("context")
        if ctx:
            # FIX-12: If the value is already a dict with __redacted__: True,
            # an attacker may have pre-populated a fake redaction marker.
            # Serialize the entire dict as JSON and re-redact it as content.
            if isinstance(ctx, dict) and ctx.get("__redacted__") is True:
                logger.warning(
                    "Pre-existing redaction marker detected in inputs.context — "
                    "re-redacting to prevent marker injection"
                )
                ctx = json.dumps(ctx, sort_keys=True)
                receipt["inputs"]["context"] = _make_redaction_marker(ctx)
                redacted_paths.append("inputs.context")
            elif isinstance(ctx, str):
                receipt["inputs"]["context"] = _make_redaction_marker(ctx)
                redacted_paths.append("inputs.context")

    if "result_text" in redaction_fields:
        resp = (receipt.get("outputs") or {}).get("response")
        if resp:
            # FIX-12: Same injection guard for outputs.response
            if isinstance(resp, dict) and resp.get("__redacted__") is True:
                logger.warning(
                    "Pre-existing redaction marker detected in outputs.response — "
                    "re-redacting to prevent marker injection"
                )
                resp = json.dumps(resp, sort_keys=True)
                receipt["outputs"]["response"] = _make_redaction_marker(resp)
                redacted_paths.append("outputs.response")
            elif isinstance(resp, str):
                receipt["outputs"]["response"] = _make_redaction_marker(resp)
                redacted_paths.append("outputs.response")

    if not redacted_paths:
        return receipt, redacted_paths

    # Recompute content hashes from marker-bearing inputs/outputs
    inputs = receipt.get("inputs", {})
    outputs = receipt.get("outputs", {})
    receipt["context_hash"] = hash_obj(inputs)
    receipt["output_hash"] = hash_obj(outputs)

    # Record redaction metadata
    receipt["redacted_fields"] = redacted_paths

    # Recompute fingerprint using canonical formula (SAN-524).
    # receipt["context_hash"] and receipt["output_hash"] are already updated above,
    # so compute_fingerprints reads the post-redaction hashes correctly.
    # tool_name is read from the receipt (not the TOOL_NAME constant), which is
    # the correct behavior: the fingerprint covers the receipt's declared tool_name.
    fps = compute_fingerprints(receipt)
    if fps is None:
        raise ValueError(
            f"compute_fingerprints returned None after redaction for "
            f"cv={receipt.get('checks_version')!r}; receipt is missing a "
            f"required field for this cv level"
        )
    receipt["full_fingerprint"] = fps.full_fingerprint
    receipt["receipt_fingerprint"] = fps.receipt_fingerprint

    return receipt, redacted_paths


def apply_redaction(
    receipt: dict, config: RedactionConfig,
) -> tuple[dict, list[str]]:
    """Apply redaction per config; return (receipt, redacted_paths).

    Returns the receipt unchanged with empty paths if config.enabled is False.
    Otherwise delegates to _apply_redaction_markers.
    """
    if not config.enabled:
        return receipt, []
    return _apply_redaction_markers(receipt, config.fields)
