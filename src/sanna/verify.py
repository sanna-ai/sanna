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
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from jsonschema import validate, ValidationError

from .hashing import hash_text, hash_obj


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
    checks_data = [{"check_id": c.get("check_id", ""), "passed": c.get("passed"), "severity": c.get("severity", ""), "evidence": c.get("evidence")} for c in checks]
    checks_hash = hash_obj(checks_data)

    # Include constitution_ref and halt_event in fingerprint
    constitution_ref = receipt.get("constitution_ref")
    halt_event = receipt.get("halt_event")
    constitution_hash = hash_obj(constitution_ref) if constitution_ref else ""
    halt_hash = hash_obj(halt_event) if halt_event else ""

    fingerprint_input = f"{trace_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{halt_hash}"
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

    critical_fails = sum(1 for c in checks if not c.get("passed") and c.get("severity") == "critical")
    warning_fails = sum(1 for c in checks if not c.get("passed") and c.get("severity") == "warning")

    if critical_fails > 0:
        computed = "FAIL"
    elif warning_fails > 0:
        computed = "WARN"
    else:
        computed = "PASS"

    expected = receipt.get("coherence_status", "")
    return (computed == expected, computed, expected)


def verify_check_counts(receipt: dict) -> list:
    """Verify checks_passed and checks_failed match actual check results."""
    errors = []
    checks = receipt.get("checks", [])

    actual_passed = sum(1 for c in checks if c.get("passed"))
    actual_failed = len(checks) - actual_passed

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
    """Verify constitution_ref.document_hash is a valid hex hash if present.

    Accepts both 16-char (legacy ConstitutionProvenance) and 64-char
    (full SHA-256 from constitution lifecycle) hashes.
    """
    errors = []
    constitution_ref = receipt.get("constitution_ref")
    if constitution_ref:
        doc_hash = constitution_ref.get("document_hash", "")
        hex_pattern = re.compile(r"^[a-f0-9]{16,64}$")
        if not hex_pattern.match(doc_hash):
            errors.append(f"constitution_ref.document_hash has invalid format: '{doc_hash}' (expected 16-64 hex chars)")
    return errors


def verify_receipt(receipt: dict, schema: dict) -> VerificationResult:
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
    fp_match, fp_computed, fp_expected = verify_fingerprint(receipt)

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
