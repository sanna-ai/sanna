"""Receipt v2.0 schema — Receipt Triad and reasoning evaluation.

Introduces the Receipt Triad (input_hash, reasoning_hash, action_hash)
for gateway-level receipts, plus structured reasoning evaluation for
governance-level checks on agent justifications.

All hashes use ``sha256:`` prefix for algorithm agility. Canonical JSON
follows RFC 8785; floats are normalized to fixed-precision strings before
canonicalization (no json.dumps fallback needed).

Dataclass-based models following the existing Sanna patterns.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from sanna.hashing import canonical_json_bytes, normalize_floats


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECEIPT_VERSION_2 = "2.0"

#: Default maximum size (bytes) for stored payloads (result_text, arguments).
#: Content is hashed in full before truncation for storage.
#: Override via ``SANNA_MAX_STORED_PAYLOAD_BYTES`` env var.
MAX_STORED_PAYLOAD_BYTES = int(
    os.environ.get("SANNA_MAX_STORED_PAYLOAD_BYTES", 64 * 1024)
)

_TRUNCATION_MARKER = "\n[TRUNCATED — full content hashed but not stored]"

VALID_CHECK_METHODS = frozenset({
    "deterministic_presence",
    "deterministic_regex",
    "deterministic_blocklist",
    "llm_coherence",
})

VALID_ASSURANCE_LEVELS = frozenset({"full", "partial", "none"})

VALID_OVERRIDE_REASONS = frozenset({
    "false_positive",
    "accepted_risk",
    "emergency_override",
    "threshold_too_strict",
})

VALID_ENFORCEMENT_LEVELS = frozenset({
    "can_execute",
    "must_escalate",
    "cannot_execute",
})


# ---------------------------------------------------------------------------
# Receipt Triad
# ---------------------------------------------------------------------------

@dataclass
class ReceiptTriad:
    """Cryptographic binding of input→reasoning→action.

    At the gateway boundary, ``input_hash`` and ``action_hash`` are
    identical because the gateway can only observe tool call arguments
    (not downstream execution internals).  ``context_limitation``
    documents this constraint for downstream verifiers.

    **Important:** ``input_hash`` and ``action_hash`` represent
    *gateway-boundary attestation*, not end-to-end execution proof.
    The gateway attests to what it observed at its boundary; it cannot
    verify what the downstream server actually executed.  Downstream
    execution attestation would require the downstream server to
    produce its own signed receipts — a future architecture concern.

    Attributes:
        input_hash: SHA-256 of the canonical tool call (tool name + args).
        reasoning_hash: SHA-256 of the agent justification string
            (empty-string hash when no justification provided).
        action_hash: SHA-256 of the action payload.  Equals input_hash
            at the gateway boundary.
        context_limitation: Documents what the gateway can observe.
    """
    input_hash: str       # "sha256:<hex>"
    reasoning_hash: str   # "sha256:<hex>"
    action_hash: str      # "sha256:<hex>"
    context_limitation: str = "gateway_boundary"


# ---------------------------------------------------------------------------
# Reasoning evaluation
# ---------------------------------------------------------------------------

@dataclass
class GatewayCheckResult:
    """Result of a single governance-level reasoning check.

    Attributes:
        check_id: Identifier for the check (e.g., ``"glc_minimum_substance"``).
        method: Algorithm used.
        passed: Whether the check passed.
        score: Confidence score (0.0–1.0).  Stored as integer basis points
            (0–10000) internally for RFC 8785 compatibility.
        latency_ms: Check execution time in milliseconds.
        details: Optional check-specific metadata.
    """
    check_id: str
    method: str           # deterministic_presence, deterministic_regex, etc.
    passed: bool
    score: float          # 0.0-1.0 (user-facing)
    latency_ms: int
    details: Optional[dict] = None


@dataclass
class ReasoningEvaluation:
    """Aggregate result of reasoning evaluation for a tool call.

    Attributes:
        assurance: Quality level — ``"full"`` (all checks passed),
            ``"partial"`` (some passed), ``"none"`` (all failed or no checks).
        checks: Individual check results.
        overall_score: ``min(scores)`` — strictest check, used for gating.
        passed: Whether reasoning evaluation passed overall.
        failure_reason: Human-readable reason for failure (when ``passed=False``).
        failed_check_ids: IDs of checks that failed threshold.
        passed_check_ids: IDs of checks that passed.
        weighted_score: Weighted average (deterministic=0.3, llm=0.7).
        hard_failures: Deterministic check failures (reproducible).
        soft_failures: LLM check failures (non-reproducible, attestation only).
        scoring_method: Scoring algorithm identifier.

    .. versionchanged:: 0.12.0
       Added scoring detail fields: ``failed_check_ids``,
       ``passed_check_ids``, ``weighted_score``, ``hard_failures``,
       ``soft_failures``, ``scoring_method``.
    """
    assurance: str        # "full" | "partial" | "none"
    checks: list          # list[GatewayCheckResult] (as dicts after asdict)
    overall_score: float  # 0.0-1.0 (min gate)
    passed: bool
    failure_reason: Optional[str] = None
    # v0.12.0 scoring detail
    failed_check_ids: Optional[list] = None
    passed_check_ids: Optional[list] = None
    weighted_score: Optional[float] = None
    hard_failures: Optional[list] = None
    soft_failures: Optional[list] = None
    scoring_method: str = "min_gate"


# ---------------------------------------------------------------------------
# Action, enforcement, approval, signature records
# ---------------------------------------------------------------------------

@dataclass
class ActionRecord:
    """Records the tool call that was evaluated.

    Attributes:
        tool: The tool name (unprefixed original name).
        args_hash: Hash of tool arguments (truncated SHA-256).
            Raw args are not stored here because MCP tool arguments
            may contain floats incompatible with RFC 8785 canonical JSON.
        justification_stripped: True if ``_justification`` was extracted
            and removed from args before forwarding.
    """
    tool: str
    args_hash: str = ""
    justification_stripped: bool = False


@dataclass
class EnforcementRecord:
    """Records the enforcement context for this receipt.

    Attributes:
        level: The enforcement decision (``"can_execute"``,
            ``"must_escalate"``, or ``"cannot_execute"``).
        constitution_version: Schema version of the constitution.
        constitution_hash: Policy hash of the constitution.
    """
    level: str
    constitution_version: str
    constitution_hash: str


@dataclass
class GatewayApprovalRecord:
    """Records approval status for escalated tool calls.

    Attributes:
        required: Whether approval was required.
        approved: Whether the action was approved.
        approved_at: ISO 8601 timestamp of approval (if approved).
        approval_token: The HMAC token used for approval (if token-based).
        override_reason: Reason category for overriding a denial.
    """
    required: bool
    approved: bool
    approved_at: Optional[str] = None
    approval_token: Optional[str] = None
    override_reason: Optional[str] = None  # false_positive, accepted_risk, etc.


@dataclass
class SignatureRecord:
    """Ed25519 signature metadata for a v2 receipt.

    Attributes:
        algorithm: Signing algorithm identifier.
        public_key: Hex-encoded public key fingerprint (key_id).
        signature: Base64-encoded Ed25519 signature value.
        canonical_form: Canonicalization scheme used before signing.
    """
    algorithm: str = "ed25519"
    public_key: str = ""
    signature: str = ""
    canonical_form: str = "rfc8785"


@dataclass
class GatewayReceiptV2:
    """Gateway Receipt v2.0 — full receipt with triad and reasoning.

    This is the structured representation of a v2.0 gateway receipt.
    The gateway's ``_generate_receipt`` continues to produce the standard
    SannaReceipt dict (for fingerprint parity with middleware.py and
    verify.py); this class captures the v2-specific extensions that are
    stored in ``extensions.gateway_v2``.
    """
    receipt_version: str
    receipt_id: str
    timestamp_utc: str
    receipt_triad: ReceiptTriad
    action: ActionRecord
    enforcement: EnforcementRecord
    reasoning_evaluation: Optional[ReasoningEvaluation] = None
    approval: Optional[GatewayApprovalRecord] = None
    signature: Optional[SignatureRecord] = None


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_check_result(check: dict) -> list[str]:
    """Validate a GatewayCheckResult dict. Returns error strings."""
    errors: list[str] = []

    method = check.get("method")
    if method is not None and method not in VALID_CHECK_METHODS:
        errors.append(
            f"check_result.method '{method}' must be one of "
            f"{sorted(VALID_CHECK_METHODS)}"
        )

    score = check.get("score")
    if score is not None:
        if not isinstance(score, (int, float)):
            errors.append("check_result.score must be a number")
        elif not (0.0 <= float(score) <= 1.0):
            errors.append(
                f"check_result.score must be 0.0-1.0, got {score}"
            )

    latency = check.get("latency_ms")
    if latency is not None:
        if not isinstance(latency, int) or isinstance(latency, bool):
            errors.append("check_result.latency_ms must be an integer")
        elif latency < 0:
            errors.append(
                f"check_result.latency_ms must be >= 0, got {latency}"
            )

    return errors


def validate_reasoning_evaluation(evaluation: dict) -> list[str]:
    """Validate a ReasoningEvaluation dict. Returns error strings."""
    errors: list[str] = []

    assurance = evaluation.get("assurance")
    if assurance is not None and assurance not in VALID_ASSURANCE_LEVELS:
        errors.append(
            f"reasoning_evaluation.assurance '{assurance}' must be one of "
            f"{sorted(VALID_ASSURANCE_LEVELS)}"
        )

    score = evaluation.get("overall_score")
    if score is not None:
        if not isinstance(score, (int, float)):
            errors.append("reasoning_evaluation.overall_score must be a number")
        elif not (0.0 <= float(score) <= 1.0):
            errors.append(
                f"reasoning_evaluation.overall_score must be 0.0-1.0, got {score}"
            )

    checks = evaluation.get("checks", [])
    if isinstance(checks, list):
        for i, check in enumerate(checks):
            if isinstance(check, dict):
                for err in validate_check_result(check):
                    errors.append(f"checks[{i}].{err}")

    return errors


def validate_approval_record(approval: dict) -> list[str]:
    """Validate a GatewayApprovalRecord dict. Returns error strings."""
    errors: list[str] = []

    override_reason = approval.get("override_reason")
    if override_reason is not None and override_reason not in VALID_OVERRIDE_REASONS:
        errors.append(
            f"approval.override_reason '{override_reason}' must be one of "
            f"{sorted(VALID_OVERRIDE_REASONS)}"
        )

    return errors


# ---------------------------------------------------------------------------
# Receipt Triad computation
# ---------------------------------------------------------------------------

def _sha256_prefixed(data: bytes) -> str:
    """Compute SHA-256 hash with ``sha256:`` prefix."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_json_for_triad(obj: Any) -> str:
    """RFC 8785 canonical JSON with float normalization.

    Floats are converted to fixed-precision strings before
    canonicalization, eliminating the need for a json.dumps fallback.
    """
    normalized = normalize_floats(obj)
    return canonical_json_bytes(normalized).decode("utf-8")


def compute_receipt_triad(
    tool_name: str,
    args: dict[str, Any],
    justification: str | None,
) -> ReceiptTriad:
    """Compute the Receipt Triad for a gateway tool call.

    Hashes:
    - **input_hash**: Canonical JSON of ``{"tool": name, "args": args_without_justification}``.
    - **reasoning_hash**: SHA-256 of the justification string (or empty string).
    - **action_hash**: Same as input_hash (gateway boundary limitation).

    The ``_justification`` key is always excluded from args before hashing
    the input and action components.

    Args:
        tool_name: The unprefixed tool name.
        args: Tool arguments dict (may contain ``_justification``).
        justification: The extracted justification string (or None).

    Returns:
        A ``ReceiptTriad`` with all three hashes and context_limitation.
    """
    # Strip _justification from args for input/action hash
    args_clean = {k: v for k, v in args.items() if k != "_justification"}

    input_obj = {"tool": tool_name, "args": args_clean}
    input_canonical = _canonical_json_for_triad(input_obj)
    input_hash = _sha256_prefixed(input_canonical.encode("utf-8"))

    # Reasoning hash — hash the justification text, or empty string
    justification_bytes = (justification or "").encode("utf-8")
    reasoning_hash = _sha256_prefixed(justification_bytes)

    # At gateway boundary, action_hash == input_hash
    action_hash = input_hash

    return ReceiptTriad(
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        context_limitation="gateway_boundary",
    )


def receipt_triad_to_dict(triad: ReceiptTriad) -> dict:
    """Convert ReceiptTriad to a plain dict for receipt embedding."""
    return asdict(triad)


def reasoning_evaluation_to_dict(
    evaluation: ReasoningEvaluation,
    *,
    for_signing: bool = False,
) -> dict:
    """Convert ReasoningEvaluation to a dict.

    When ``for_signing=True``, float scores are converted to integer
    basis points (0-10000) for RFC 8785 compatibility.
    """
    d = asdict(evaluation)
    if for_signing:
        d["overall_score"] = int(round(evaluation.overall_score * 10000))
        if d.get("weighted_score") is not None:
            d["weighted_score"] = int(round(evaluation.weighted_score * 10000))
        for i, check in enumerate(d.get("checks", [])):
            if isinstance(check, dict) and "score" in check:
                check["score"] = int(round(evaluation.checks[i].score * 10000))
    return d


def gateway_receipt_v2_to_dict(
    receipt: GatewayReceiptV2,
    *,
    for_signing: bool = False,
) -> dict:
    """Convert GatewayReceiptV2 to a plain dict for embedding in extensions."""
    d: dict[str, Any] = {
        "receipt_version": receipt.receipt_version,
        "receipt_id": receipt.receipt_id,
        "timestamp_utc": receipt.timestamp_utc,
        "receipt_triad": receipt_triad_to_dict(receipt.receipt_triad),
        "action": asdict(receipt.action),
        "enforcement": asdict(receipt.enforcement),
    }
    if receipt.reasoning_evaluation is not None:
        d["reasoning_evaluation"] = reasoning_evaluation_to_dict(
            receipt.reasoning_evaluation, for_signing=for_signing,
        )
    if receipt.approval is not None:
        d["approval"] = asdict(receipt.approval)
    if receipt.signature is not None:
        d["signature"] = asdict(receipt.signature)
    return d


# ---------------------------------------------------------------------------
# Payload truncation for storage
# ---------------------------------------------------------------------------


def truncate_for_storage(
    text: str | None,
    max_bytes: int = MAX_STORED_PAYLOAD_BYTES,
) -> str | None:
    """Truncate text for receipt storage, preserving hash integrity.

    The caller is expected to hash the *full* content before calling
    this function.  The truncated value is only for storage/display.

    Args:
        text: The text to potentially truncate (or *None*).
        max_bytes: Maximum byte length (UTF-8).  Defaults to
            :data:`MAX_STORED_PAYLOAD_BYTES` (64 KB, env-configurable).

    Returns:
        The original text (if within limit), truncated text with marker,
        or *None* if input was *None*.
    """
    if text is None:
        return None
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    # Leave room for the truncation marker
    marker_bytes = _TRUNCATION_MARKER.encode("utf-8")
    cut = max_bytes - len(marker_bytes)
    if cut < 0:
        cut = 0
    truncated = encoded[:cut].decode("utf-8", errors="ignore")
    return truncated + _TRUNCATION_MARKER
