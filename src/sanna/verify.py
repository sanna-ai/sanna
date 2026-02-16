"""
Sanna Receipt offline verifier.

Validates receipts without requiring Langfuse or any network access.

Exit codes:
  0 = valid
  2 = schema invalid
  3 = fingerprint mismatch
  4 = internal consistency error
  5 = other error
"""

import json
import re
from dataclasses import dataclass, field as _field
from pathlib import Path
from typing import Optional

from jsonschema import validate, ValidationError

from .hashing import hash_text, hash_obj

# Statuses that represent non-evaluated checks (excluded from pass/fail counting)
_NON_EVALUATED = {"NOT_CHECKED", "ERRORED"}

# Pattern for Receipt Triad hash values: "sha256:" + 64 hex chars
_TRIAD_HASH_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


# =============================================================================
# RECEIPT TRIAD VERIFICATION (Block I)
# =============================================================================

@dataclass
class TriadVerification:
    """Result of Receipt Triad hash verification.

    Attributes:
        present: Whether the receipt contains a gateway_v2 receipt_triad.
        input_hash_valid: Format check passed for input_hash.
        reasoning_hash_valid: Format check passed for reasoning_hash.
        action_hash_valid: Format check passed for action_hash.
        gateway_boundary_consistent: input_hash == action_hash when
            context_limitation is ``"gateway_boundary"``.
        input_recomputed: Re-computed input_hash (when tool name and
            args are recoverable from the receipt).
        input_hash_match: Whether re-computed input hash matches stored.
        context_limitation: The context_limitation value from the triad.
        errors: Verification errors (mismatches, format failures).
        warnings: Non-fatal issues (truncated content, missing fields).
    """
    present: bool = False
    input_hash_valid: bool = False
    reasoning_hash_valid: bool = False
    action_hash_valid: bool = False
    gateway_boundary_consistent: bool = False
    input_recomputed: Optional[str] = None
    input_hash_match: Optional[bool] = None
    context_limitation: str = ""
    errors: list = _field(default_factory=list)
    warnings: list = _field(default_factory=list)


def verify_receipt_triad(receipt: dict) -> TriadVerification:
    """Re-compute and verify Receipt Triad hashes from receipt content.

    Checks performed:

    1. **Format** — all three hashes have ``sha256:`` prefix + 64 hex chars.
    2. **Gateway boundary** — ``input_hash == action_hash`` when
       ``context_limitation`` is ``"gateway_boundary"`` (the gateway can
       only observe what it forwarded, not downstream execution).
    3. **Input hash re-computation** — if the original tool name and
       arguments are recoverable from the receipt extensions and
       ``inputs.context``, re-compute the input hash and compare.

    The reasoning hash cannot be re-computed because the justification
    is hashed and stripped before storage.  Only format validation is
    applied to the reasoning hash.

    Args:
        receipt: A Sanna receipt dict.

    Returns:
        A ``TriadVerification`` with match results and any errors.
    """
    result = TriadVerification()

    extensions = receipt.get("extensions") or {}
    gw_v2 = extensions.get("gateway_v2") or {}
    triad = gw_v2.get("receipt_triad")

    if not triad or not isinstance(triad, dict):
        return result  # No triad — v1 receipt, nothing to verify

    result.present = True
    result.context_limitation = triad.get("context_limitation", "")

    input_hash = triad.get("input_hash", "")
    reasoning_hash = triad.get("reasoning_hash", "")
    action_hash = triad.get("action_hash", "")

    # 1. Format validation
    result.input_hash_valid = bool(_TRIAD_HASH_PATTERN.match(input_hash))
    result.reasoning_hash_valid = bool(_TRIAD_HASH_PATTERN.match(reasoning_hash))
    result.action_hash_valid = bool(_TRIAD_HASH_PATTERN.match(action_hash))

    if not result.input_hash_valid:
        result.errors.append(
            f"input_hash has invalid format: '{input_hash}'"
        )
    if not result.reasoning_hash_valid:
        result.errors.append(
            f"reasoning_hash has invalid format: '{reasoning_hash}'"
        )
    if not result.action_hash_valid:
        result.errors.append(
            f"action_hash has invalid format: '{action_hash}'"
        )

    # 2. Gateway boundary constraint
    if result.context_limitation == "gateway_boundary":
        result.gateway_boundary_consistent = (input_hash == action_hash)
        if not result.gateway_boundary_consistent:
            result.errors.append(
                "Gateway boundary violation: input_hash != action_hash "
                "(at gateway boundary these must be equal)"
            )

    # 3. Input hash re-computation (best-effort)
    action_record = gw_v2.get("action") or {}
    tool_name = action_record.get("tool")
    context_raw = (receipt.get("inputs") or {}).get("context", "")

    if tool_name and context_raw:
        # Check for truncation markers
        truncated = (
            "[TRUNCATED" in context_raw
            or "[REDACTED" in context_raw
        )
        if truncated:
            result.warnings.append(
                "Cannot re-compute input_hash: stored arguments "
                "are truncated or redacted"
            )
        else:
            try:
                args = json.loads(context_raw)
                if isinstance(args, dict):
                    args_clean = {
                        k: v for k, v in args.items()
                        if k != "_justification"
                    }
                    from .gateway.receipt_v2 import (
                        _canonical_json_for_triad,
                        _sha256_prefixed,
                    )
                    input_obj = {"tool": tool_name, "args": args_clean}
                    canonical = _canonical_json_for_triad(input_obj)
                    result.input_recomputed = _sha256_prefixed(
                        canonical.encode("utf-8"),
                    )
                    result.input_hash_match = (
                        result.input_recomputed == input_hash
                    )
                    if not result.input_hash_match:
                        result.errors.append(
                            f"input_hash mismatch: stored {input_hash}, "
                            f"recomputed {result.input_recomputed}"
                        )
            except (json.JSONDecodeError, TypeError):
                result.warnings.append(
                    "Cannot re-compute input_hash: inputs.context "
                    "is not valid JSON"
                )
            except ImportError:
                result.warnings.append(
                    "Cannot re-compute input_hash: gateway module "
                    "not available"
                )

    return result


# =============================================================================
# VERIFICATION RESULT
# =============================================================================

@dataclass
class VerificationResult:
    """Result of receipt verification."""
    valid: bool
    exit_code: int
    errors: list
    warnings: list

    # Computed values for comparison
    computed_fingerprint: Optional[str] = None
    expected_fingerprint: Optional[str] = None
    computed_status: Optional[str] = None
    expected_status: Optional[str] = None


# =============================================================================
# SCHEMA LOADING
# =============================================================================

def get_schema_path() -> Path:
    """Get path to schema file."""
    script_dir = Path(__file__).parent
    candidates = [
        script_dir / "spec" / "receipt.schema.json",
        script_dir / "receipt.schema.json",
        Path("spec/receipt.schema.json"),
        Path("receipt.schema.json"),
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(f"Schema not found. Tried: {[str(p) for p in candidates]}")


def load_schema(schema_path: Optional[str] = None) -> dict:
    """Load the JSON schema."""
    if schema_path:
        path = Path(schema_path)
    else:
        path = get_schema_path()
    with open(path) as f:
        return json.load(f)


# =============================================================================
# VERIFICATION LOGIC
# =============================================================================

def verify_schema(receipt: dict, schema: dict) -> list:
    """Validate receipt against JSON schema. Returns list of errors."""
    errors = []
    try:
        validate(receipt, schema)
    except ValidationError as e:
        errors.append(f"Schema validation failed: {e.message}")
        if e.path:
            errors[-1] += f" (at {'.'.join(str(p) for p in e.path)})"
    return errors


def verify_fingerprint(receipt: dict) -> tuple:
    """
    Verify receipt_fingerprint matches recomputed value.

    Returns (matches, computed, expected)
    """
    trace_id = receipt.get("trace_id", "")
    context_hash = receipt.get("context_hash", "")
    output_hash = receipt.get("output_hash", "")
    checks_version = receipt.get("checks_version", "")

    # Include checks in fingerprint so tampering with check results is detected
    checks = receipt.get("checks", [])
    # v0.6.1: include check_impl and replayable in fingerprint if present
    has_v061_fields = any(c.get("check_impl") is not None or c.get("replayable") is not None for c in checks)
    has_enforcement_fields = any(c.get("triggered_by") is not None for c in checks)
    if has_v061_fields:
        checks_data = [
            {
                "check_id": c.get("check_id", ""),
                "passed": c.get("passed"),
                "severity": c.get("severity", ""),
                "evidence": c.get("evidence"),
                "triggered_by": c.get("triggered_by"),
                "enforcement_level": c.get("enforcement_level"),
                "check_impl": c.get("check_impl"),
                "replayable": c.get("replayable"),
            }
            for c in checks
        ]
    elif has_enforcement_fields:
        checks_data = [
            {
                "check_id": c.get("check_id", ""),
                "passed": c.get("passed"),
                "severity": c.get("severity", ""),
                "evidence": c.get("evidence"),
                "triggered_by": c.get("triggered_by"),
                "enforcement_level": c.get("enforcement_level"),
            }
            for c in checks
        ]
    else:
        checks_data = [{"check_id": c.get("check_id", ""), "passed": c.get("passed"), "severity": c.get("severity", ""), "evidence": c.get("evidence")} for c in checks]
    checks_hash = hash_obj(checks_data)

    # Include constitution_ref, halt_event, and evaluation_coverage in fingerprint
    constitution_ref = receipt.get("constitution_ref")
    halt_event = receipt.get("halt_event")
    evaluation_coverage = receipt.get("evaluation_coverage")
    # Strip mutable constitution_approval before hashing (parity with middleware.py).
    if constitution_ref:
        _cref = {k: v for k, v in constitution_ref.items() if k != "constitution_approval"}
        constitution_hash = hash_obj(_cref)
    else:
        constitution_hash = ""
    halt_hash = hash_obj(halt_event) if halt_event else ""

    # v0.6.1: include evaluation_coverage in fingerprint if present
    if evaluation_coverage is not None:
        coverage_hash = hash_obj(evaluation_coverage)
        fingerprint_input = f"{trace_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{halt_hash}|{coverage_hash}"
    else:
        fingerprint_input = f"{trace_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{halt_hash}"

    # v0.7.0: include authority sections in fingerprint when present
    authority_decisions = receipt.get("authority_decisions")
    escalation_events = receipt.get("escalation_events")
    source_trust_evaluations = receipt.get("source_trust_evaluations")
    if authority_decisions:
        fingerprint_input += f"|{hash_obj(authority_decisions)}"
    if escalation_events:
        fingerprint_input += f"|{hash_obj(escalation_events)}"
    if source_trust_evaluations:
        fingerprint_input += f"|{hash_obj(source_trust_evaluations)}"

    # v0.7.0: include extensions in fingerprint when non-empty
    extensions = receipt.get("extensions")
    if extensions:
        fingerprint_input += f"|{hash_obj(extensions)}"

    computed = hash_text(fingerprint_input)
    expected = receipt.get("receipt_fingerprint", "")

    return (computed == expected, computed, expected)


def verify_status_consistency(receipt: dict) -> tuple:
    """
    Verify coherence_status matches check outcomes.

    Rules:
    - FAIL if any severity=critical check failed
    - WARN if any severity=warning check failed (and no critical)
    - PASS otherwise

    Returns (matches, computed, expected)
    """
    checks = receipt.get("checks", [])
    # Exclude non-evaluated checks (NOT_CHECKED, ERRORED) from status computation
    standard_checks = [c for c in checks if c.get("status") not in _NON_EVALUATED]
    non_evaluated = [c for c in checks if c.get("status") in _NON_EVALUATED]

    critical_fails = sum(1 for c in standard_checks if not c.get("passed") and c.get("severity") == "critical")
    warning_fails = sum(1 for c in standard_checks if not c.get("passed") and c.get("severity") == "warning")

    if critical_fails > 0:
        computed = "FAIL"
    elif warning_fails > 0:
        computed = "WARN"
    elif non_evaluated:
        computed = "PARTIAL"
    else:
        computed = "PASS"

    expected = receipt.get("coherence_status", "")
    return (computed == expected, computed, expected)


def verify_check_counts(receipt: dict) -> list:
    """Verify checks_passed and checks_failed match actual check results."""
    errors = []
    checks = receipt.get("checks", [])
    # Exclude non-evaluated checks (NOT_CHECKED, ERRORED) from count verification
    standard_checks = [c for c in checks if c.get("status") not in _NON_EVALUATED]

    actual_passed = sum(1 for c in standard_checks if c.get("passed"))
    actual_failed = len(standard_checks) - actual_passed

    if receipt.get("checks_passed") != actual_passed:
        errors.append(f"checks_passed mismatch: got {receipt.get('checks_passed')}, expected {actual_passed}")

    if receipt.get("checks_failed") != actual_failed:
        errors.append(f"checks_failed mismatch: got {receipt.get('checks_failed')}, expected {actual_failed}")

    return errors


def verify_hash_format(receipt: dict) -> list:
    """Verify hash fields have correct format (16 hex chars)."""
    errors = []
    hash_fields = ["receipt_id", "receipt_fingerprint", "context_hash", "output_hash"]
    hex_pattern = re.compile(r"^[a-f0-9]{16}$")

    for field in hash_fields:
        value = receipt.get(field, "")
        if not hex_pattern.match(value):
            errors.append(f"{field} has invalid format: '{value}' (expected 16 hex chars)")

    return errors


def verify_content_hashes(receipt: dict) -> list:
    """Verify context_hash and output_hash match actual content."""
    errors = []

    inputs = receipt.get("inputs", {})
    outputs = receipt.get("outputs", {})

    computed_context_hash = hash_obj(inputs)
    stored_context_hash = receipt.get("context_hash", "")

    if computed_context_hash != stored_context_hash:
        errors.append(f"context_hash mismatch: computed {computed_context_hash}, stored {stored_context_hash} (inputs may have been tampered)")

    computed_output_hash = hash_obj(outputs)
    stored_output_hash = receipt.get("output_hash", "")

    if computed_output_hash != stored_output_hash:
        errors.append(f"output_hash mismatch: computed {computed_output_hash}, stored {stored_output_hash} (outputs may have been tampered)")

    return errors


def verify_constitution_hash(receipt: dict) -> list:
    """Verify constitution_ref.policy_hash is a valid hex hash if present.

    Accepts both 16-char (legacy ConstitutionProvenance) and 64-char
    (full SHA-256 from constitution lifecycle) hashes.
    """
    errors = []
    constitution_ref = receipt.get("constitution_ref")
    if constitution_ref:
        doc_hash = constitution_ref.get("policy_hash", "")
        hex_pattern = re.compile(r"^[a-f0-9]{16,64}$")
        if not hex_pattern.match(doc_hash):
            errors.append(f"constitution_ref.policy_hash has invalid format: '{doc_hash}' (expected 16-64 hex chars)")
    return errors


def verify_constitution_chain(
    receipt: dict,
    constitution_path: str,
    constitution_public_key_path: str | None = None,
    approver_public_key_path: str | None = None,
) -> list:
    """Verify the receipt-constitution chain.

    Checks:
    1. Constitution loads and policy_hash is valid.
    2. receipt.constitution_ref.policy_hash matches constitution.
    3. If public key provided, verifies constitution Ed25519 signature.
    4. If constitution_ref.key_id exists, matches constitution's key_id.
    5. If constitution has approval, verifies content_hash and (optionally) approval signature.

    Returns list of error strings.
    """
    errors = []

    from .constitution import load_constitution, compute_constitution_hash, compute_content_hash, SannaConstitutionError

    try:
        constitution = load_constitution(constitution_path)
    except SannaConstitutionError as e:
        errors.append(f"Constitution integrity check failed: {e}")
        return errors, []
    except FileNotFoundError as e:
        errors.append(f"Constitution not found: {e}")
        return errors, []
    except ValueError as e:
        errors.append(f"Constitution validation failed: {e}")
        return errors, []

    if not constitution.policy_hash:
        errors.append("Constitution is not signed (no policy_hash)")
        return errors, []

    # Verify policy_hash matches
    computed = compute_constitution_hash(constitution)
    if computed != constitution.policy_hash:
        errors.append(
            f"Constitution policy_hash mismatch: computed {computed[:16]}..., "
            f"stored {constitution.policy_hash[:16]}..."
        )

    # Check receipt's constitution_ref matches
    const_ref = receipt.get("constitution_ref")
    if const_ref:
        receipt_hash = const_ref.get("policy_hash", "")
        if receipt_hash != constitution.policy_hash:
            errors.append(
                f"Receipt-constitution bond mismatch: receipt has policy_hash={receipt_hash[:16]}..., "
                f"constitution has {constitution.policy_hash[:16]}..."
            )

        # Verify signature value matches between receipt and constitution
        receipt_sig_value = const_ref.get("signature")
        const_sig = constitution.provenance.signature
        const_sig_value = const_sig.value if const_sig else None
        if receipt_sig_value and const_sig_value:
            if receipt_sig_value != const_sig_value:
                errors.append(
                    "Receipt references a different signed version of this constitution."
                )
            receipt_scheme = const_ref.get("scheme")
            const_scheme = const_sig.scheme if const_sig else None
            if receipt_scheme and const_scheme and receipt_scheme != const_scheme:
                errors.append(
                    f"Signature scheme mismatch: receipt has {receipt_scheme}, "
                    f"constitution has {const_scheme}"
                )

        # Verify constitution Ed25519 signature
        if constitution_public_key_path:
            sig = constitution.provenance.signature
            if not sig or not sig.value:
                errors.append("Constitution has no Ed25519 signature but --constitution-public-key was provided")
            else:
                from .crypto import verify_constitution_full
                valid = verify_constitution_full(constitution, constitution_public_key_path)
                if not valid:
                    errors.append("Constitution signature verification FAILED")

                # Check key_id matches
                ref_key_id = const_ref.get("key_id")
                if ref_key_id and sig.key_id and ref_key_id != sig.key_id:
                    errors.append(
                        f"Key ID mismatch: receipt has key_id={ref_key_id}, "
                        f"constitution has key_id={sig.key_id}"
                    )

    # v0.9.0: Verify approval chain
    approval_errors, approval_warnings = _verify_approval_chain(
        receipt, constitution, approver_public_key_path,
    )
    errors.extend(approval_errors)

    return errors, approval_warnings


def _verify_approval_chain(
    receipt: dict,
    constitution,
    approver_public_key_path: str | None = None,
) -> tuple[list, list]:
    """Verify the constitution approval chain.

    Checks:
    1. If constitution has approval, content_hash matches recomputed value.
    2. If approver public key provided, verify approval Ed25519 signature.
    3. Receipt's constitution_approval matches constitution's approval.

    Returns (errors, warnings) tuple.
    """
    from .constitution import compute_content_hash, _approval_record_to_signable_dict
    from .hashing import canonical_json_bytes

    errors = []
    warnings = []
    approval = constitution.approval
    const_ref = receipt.get("constitution_ref") or {}
    receipt_approval = const_ref.get("constitution_approval")

    if approval is not None and approval.current is not None:
        record = approval.current

        # 1. Verify content_hash matches
        computed_hash = compute_content_hash(constitution)
        if record.content_hash != computed_hash:
            errors.append(
                f"Approval content_hash mismatch: recorded {record.content_hash[:16]}..., "
                f"computed {computed_hash[:16]}... — constitution content may have been tampered"
            )

        # 2. Verify approval status — pending/revoked are warnings, not errors
        if record.status not in ("approved", "pending", "revoked"):
            errors.append(
                f"Constitution approval status is '{record.status}' — unknown status"
            )
        elif record.status in ("pending", "revoked"):
            warnings.append(
                f"Constitution approval status is '{record.status}', not 'approved'"
            )

        # 3. Verify approval signature (if approver public key provided)
        if approver_public_key_path:
            if not record.approval_signature:
                errors.append(
                    "Constitution approval has no signature but --approver-public-key was provided"
                )
            else:
                from .crypto import verify_signature, load_public_key
                try:
                    pub_key = load_public_key(approver_public_key_path)
                    signable = _approval_record_to_signable_dict(record)
                    data = canonical_json_bytes(signable)
                    valid = verify_signature(data, record.approval_signature, pub_key)
                    if not valid:
                        errors.append("Approval signature verification FAILED")
                except Exception as e:
                    errors.append(f"Approval signature verification error: {e}")
        elif record.status == "approved" and record.approval_signature:
            warnings.append(
                "Approval signature present but no --approver-public-key provided "
                "— signature not verified"
            )

        # 4. Cross-check receipt's constitution_approval if present
        if receipt_approval:
            if receipt_approval.get("content_hash") != record.content_hash:
                errors.append(
                    "Receipt constitution_approval.content_hash does not match "
                    "constitution's approval record"
                )
            if receipt_approval.get("status") != record.status:
                errors.append(
                    "Receipt constitution_approval.status does not match "
                    "constitution's approval record"
                )
    else:
        # Constitution has no approval — receipt should say "unapproved"
        if receipt_approval:
            if receipt_approval.get("status") == "unapproved":
                pass  # Expected: unapproved constitution, receipt says unapproved
            else:
                errors.append(
                    "Receipt references a constitution_approval but constitution "
                    "has no approval block"
                )

    return errors, warnings


def verify_receipt(
    receipt: dict,
    schema: dict,
    public_key_path: str | None = None,
    constitution_path: str | None = None,
    constitution_public_key_path: str | None = None,
    approver_public_key_path: str | None = None,
) -> VerificationResult:
    """
    Full receipt verification.

    Exit codes:
      0 = valid
      2 = schema invalid
      3 = fingerprint mismatch
      4 = internal consistency error
      5 = other error
    """
    errors = []
    warnings = []

    # 1. Schema validation
    schema_errors = verify_schema(receipt, schema)
    if schema_errors:
        return VerificationResult(
            valid=False, exit_code=2,
            errors=schema_errors, warnings=[]
        )

    # 2. Hash format validation
    hash_errors = verify_hash_format(receipt)
    errors.extend(hash_errors)

    # 2b. Content hash verification (detects content tampering)
    content_hash_errors = verify_content_hashes(receipt)
    if content_hash_errors:
        errors.extend(content_hash_errors)
        return VerificationResult(
            valid=False, exit_code=3,
            errors=errors, warnings=warnings
        )

    # 2c. Constitution hash format check
    constitution_errors = verify_constitution_hash(receipt)
    errors.extend(constitution_errors)

    # 3. Fingerprint verification
    try:
        fp_match, fp_computed, fp_expected = verify_fingerprint(receipt)
    except TypeError as e:
        return VerificationResult(
            valid=False, exit_code=3,
            errors=[f"Fingerprint computation failed (float in receipt data): {e}"],
            warnings=warnings,
        )

    # 4. Status consistency
    status_match, status_computed, status_expected = verify_status_consistency(receipt)

    # 5. Check counts
    count_errors = verify_check_counts(receipt)
    errors.extend(count_errors)

    # 6. Governance warning: FAIL with critical failure but no halt_event
    checks = receipt.get("checks", [])
    has_critical_fail = any(not c.get("passed") and c.get("severity") == "critical" for c in checks)
    if receipt.get("coherence_status") == "FAIL" and has_critical_fail and not receipt.get("halt_event"):
        warnings.append("Receipt has FAIL status with critical check failure but no halt_event recorded")

    # 7. Receipt signature verification (if public key provided)
    if public_key_path:
        sig_block = receipt.get("receipt_signature")
        if not sig_block:
            errors.append("Receipt has no signature but --public-key was provided")
        else:
            from .crypto import verify_receipt_signature
            sig_valid = verify_receipt_signature(receipt, public_key_path)
            if not sig_valid:
                errors.append("Receipt signature verification FAILED — receipt may have been tampered")

    # 8. Constitution chain verification (if constitution path provided)
    if constitution_path:
        chain_errors, chain_warnings = verify_constitution_chain(
            receipt, constitution_path, constitution_public_key_path,
            approver_public_key_path=approver_public_key_path,
        )
        errors.extend(chain_errors)
        warnings.extend(chain_warnings)

    # 9. Receipt Triad verification (Block I — v2 gateway receipts)
    triad_result = verify_receipt_triad(receipt)
    if triad_result.present:
        errors.extend(triad_result.errors)
        warnings.extend(triad_result.warnings)

    # 10. Identity verification reporting (point-in-time, no re-verification)
    iv = receipt.get("identity_verification")
    if iv and isinstance(iv, dict):
        total = iv.get("total_claims", 0)
        verified = iv.get("verified", 0)
        if not iv.get("all_verified", True):
            warnings.append(
                f"Identity claims: {total} total, {verified} verified "
                f"(not all claims verified)"
            )

    # Determine result
    if not fp_match:
        errors.insert(0, f"Fingerprint mismatch: computed {fp_computed}, expected {fp_expected}")
        return VerificationResult(
            valid=False, exit_code=3,
            errors=errors, warnings=warnings,
            computed_fingerprint=fp_computed,
            expected_fingerprint=fp_expected
        )

    if not status_match or count_errors:
        if not status_match:
            errors.insert(0, f"Status mismatch: computed {status_computed}, expected {status_expected}")
        return VerificationResult(
            valid=False, exit_code=4,
            errors=errors, warnings=warnings,
            computed_status=status_computed,
            expected_status=status_expected
        )

    if errors:
        return VerificationResult(
            valid=False, exit_code=5,
            errors=errors, warnings=warnings
        )

    return VerificationResult(
        valid=True, exit_code=0,
        errors=[], warnings=warnings,
        computed_fingerprint=fp_computed,
        expected_fingerprint=fp_expected,
        computed_status=status_computed,
        expected_status=status_expected
    )
