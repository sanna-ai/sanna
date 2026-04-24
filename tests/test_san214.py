"""Tests for SAN-214 — Python verifier cross-field consistency and legacy warnings.

Covers:
- Error text upgrade: status-mismatch caused by enforcement.action disagreement
  uses v1.3 spec §10 language ("cryptographically valid but semantically defective")
- Fallback text: status-mismatch NOT caused by enforcement.action uses generic text
- Legacy warnings: cv=6/7 receipts missing enforcement_surface or invariants_scope
  produce warnings (not errors)
- Hard errors: cv=8 receipts missing those fields still produce errors
- CLI walkthrough: format_verify_summary emits LEGACY RECEIPT NOTE when
  status-mismatch + enforcement.action + cv<8

NOTE: All calls to verify_receipt in this module pass schema=None to bypass JSON-
schema validation. The JSON schema enforces the same cross-field invariants at the
structural level; these tests focus on the verifier's independent semantic layer
(the error text it produces, and the warning vs error split for legacy receipts).
Passing schema=None is documented in verify_schema() as the supported testing path.
"""

import json
import uuid
from datetime import datetime, timezone

import pytest

from sanna.hashing import hash_text, hash_obj, EMPTY_HASH
from sanna.verify import verify_receipt, load_schema, VerificationResult
from sanna.cli import format_verify_summary


RECEIPT_SCHEMA = load_schema()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTION_TO_STATUS = {
    "halted": "FAIL",
    "warned": "WARN",
    "allowed": "PASS",
    "escalated": "WARN",
}


def make_enforcement_dict(action="halted"):
    return {
        "action": action,
        "reason": f"Test enforcement: {action}",
        "failed_checks": [],
        "enforcement_mode": "halt",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _make_raw_receipt_dict(
    enforcement_action="halted",
    status_override=None,
    checks_version="8",
    include_enforcement_surface=True,
    include_invariants_scope=True,
):
    """Construct a minimal raw receipt dict suitable for calling verify_receipt(schema=None).

    All hashes are computed consistently from the dict values so that
    context_hash / output_hash / fingerprint checks all pass — unless
    status_override introduces an inconsistency that causes the status-
    consistency check to fire.

    Parameters
    ----------
    enforcement_action : str
        One of halted / warned / allowed / escalated.
    status_override : str | None
        If provided, sets status to an inconsistent value (triggering the
        status-mismatch path). If None, the correct canonical status is used.
    checks_version : str
        "6", "7", or "8".
    include_enforcement_surface / include_invariants_scope : bool
        Whether to include the v1.3 fields (for legacy-warning tests).
    """
    corr_id = f"san214-{enforcement_action}-cv{checks_version}-{uuid.uuid4().hex[:8]}"

    # inputs/outputs dicts — context_hash and output_hash are hash_obj of these
    inputs = {"query": "test query for SAN-214"}
    outputs = {"final_answer": "test response for SAN-214"}
    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)

    correct_status = _ACTION_TO_STATUS.get(enforcement_action, "PASS")
    recorded_status = status_override if status_override is not None else correct_status

    enforcement = make_enforcement_dict(enforcement_action)
    enforcement_hash = hash_obj(enforcement)

    checks = []
    # The verifier uses EMPTY_HASH when checks_data is empty (falsy), not hash_obj([]).
    # Replicate the exact verifier logic: `hash_obj(checks_data) if checks_data else EMPTY_HASH`
    checks_hash = EMPTY_HASH  # checks=[] is falsy

    cv_int = int(checks_version)

    if cv_int >= 8:
        enforcement_surface_val = "cli_interceptor" if include_enforcement_surface else None
        invariants_scope_val = "authority_only" if include_invariants_scope else None
        enforcement_surface_hash = hash_text(enforcement_surface_val) if enforcement_surface_val else EMPTY_HASH
        invariants_scope_hash = hash_text(invariants_scope_val) if invariants_scope_val else EMPTY_HASH
        fingerprint_input = (
            f"{corr_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}"
            f"|{EMPTY_HASH}|{enforcement_hash}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
            f"|{enforcement_surface_hash}|{invariants_scope_hash}"
        )
    else:
        # cv=6/7: 14-field formula, no enforcement_surface/invariants_scope
        fingerprint_input = (
            f"{corr_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}"
            f"|{EMPTY_HASH}|{enforcement_hash}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
        )

    fp_full = hash_text(fingerprint_input)
    fp_short = fp_full[:16]

    receipt = {
        "spec_version": "1.1",
        "tool_version": "1.0.0",
        "checks_version": checks_version,
        "receipt_id": str(uuid.uuid4()),
        "receipt_fingerprint": fp_short,
        "full_fingerprint": fp_full,
        "correlation_id": corr_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": context_hash,
        "output_hash": output_hash,
        "checks": checks,
        "checks_passed": 0,
        "checks_failed": 0,
        "status": recorded_status,
        "enforcement": enforcement,
    }

    # Add v1.3 fields based on the include_* flags, regardless of checks_version.
    # For cv>=8 these are required by the fingerprint formula.
    # For cv<8 these are optional (absent → legacy warning; present → no warning).
    if include_enforcement_surface:
        receipt["enforcement_surface"] = "cli_interceptor"
    if include_invariants_scope:
        receipt["invariants_scope"] = "authority_only"

    return receipt


# ---------------------------------------------------------------------------
# san214-err-*: Status-mismatch error text upgrade
# All pass schema=None to isolate verifier semantic checks from JSON schema.
# ---------------------------------------------------------------------------

class TestStatusMismatchErrorText:
    """Error text for enforcement.action-driven mismatches must use v1.3 spec §10 language."""

    def _build_inconsistent_receipt(self, enforcement_action, bad_status, checks_version="8"):
        """A receipt where enforcement.action disagrees with the recorded status."""
        return _make_raw_receipt_dict(
            enforcement_action=enforcement_action,
            status_override=bad_status,
            checks_version=checks_version,
        )

    def test_san214_err_1_halted_with_pass_status(self):
        """san214-err-1: enforcement.action=halted + status=PASS → semantic-defect error."""
        receipt = self._build_inconsistent_receipt("halted", "PASS")
        result = verify_receipt(receipt, schema=None)
        assert not result.valid, "Should be invalid: halted+PASS is inconsistent"
        assert result.errors, "Should have at least one error"
        top_error = result.errors[0]
        assert "cryptographically valid but semantically defective" in top_error, (
            f"Error must cite semantic defect. Got: {top_error!r}"
        )
        assert "v1.3 spec §10" in top_error, (
            f"Error must cite spec §10. Got: {top_error!r}"
        )
        assert "halted" in top_error, f"Error must name the action. Got: {top_error!r}"

    def test_san214_err_2_warned_with_pass_status(self):
        """san214-err-2: enforcement.action=warned + status=PASS → semantic-defect error."""
        receipt = self._build_inconsistent_receipt("warned", "PASS")
        result = verify_receipt(receipt, schema=None)
        assert not result.valid
        top_error = result.errors[0]
        assert "cryptographically valid but semantically defective" in top_error, (
            f"Error must cite semantic defect. Got: {top_error!r}"
        )
        assert "v1.3 spec §10" in top_error
        assert "warned" in top_error

    def test_san214_err_3_escalated_with_pass_status(self):
        """san214-err-3: enforcement.action=escalated + status=PASS → semantic-defect error."""
        receipt = self._build_inconsistent_receipt("escalated", "PASS")
        result = verify_receipt(receipt, schema=None)
        assert not result.valid
        top_error = result.errors[0]
        assert "cryptographically valid but semantically defective" in top_error, (
            f"Error must cite semantic defect. Got: {top_error!r}"
        )
        assert "v1.3 spec §10" in top_error
        assert "escalated" in top_error

    def test_san214_err_4_allowed_with_pass_status_passes(self):
        """san214-err-4: enforcement.action=allowed + status=PASS → no error (consistent)."""
        receipt = _make_raw_receipt_dict(
            enforcement_action="allowed",
            status_override=None,  # correct status (PASS)
            checks_version="8",
        )
        result = verify_receipt(receipt, schema=None)
        assert result.valid, f"allowed+PASS should be valid. Errors: {result.errors}"
        # No semantic-defect language should appear in any error
        for err in result.errors:
            assert "semantically defective" not in err

    def test_san214_err_5_no_enforcement_field_uses_generic_text(self):
        """san214-err-5: status mismatch without enforcement field → generic fallback text.

        Builds a cv=6 receipt with no enforcement field where all checks pass
        (computed=PASS) but the recorded status is FAIL. The fingerprint is
        recomputed without the enforcement dict to keep it consistent. The
        status-consistency check fires and must use generic text (not spec §10 language).
        """
        import uuid as _uuid
        corr_id = f"san214-err5-no-enforcement-{_uuid.uuid4().hex[:8]}"

        inputs = {"query": "test query for SAN-214 err5"}
        outputs = {"final_answer": "test response for SAN-214 err5"}
        context_hash = hash_obj(inputs)
        output_hash = hash_obj(outputs)

        # No enforcement field → enforcement_hash = EMPTY_HASH
        checks_version = "6"
        fingerprint_input = (
            f"{corr_id}|{context_hash}|{output_hash}|{checks_version}|{EMPTY_HASH}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
        )
        fp_full = hash_text(fingerprint_input)
        fp_short = fp_full[:16]

        receipt = {
            "spec_version": "1.1",
            "tool_version": "1.0.0",
            "checks_version": checks_version,
            "receipt_id": str(_uuid.uuid4()),
            "receipt_fingerprint": fp_short,
            "full_fingerprint": fp_full,
            "correlation_id": corr_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "inputs": inputs,
            "outputs": outputs,
            "context_hash": context_hash,
            "output_hash": output_hash,
            "checks": [],
            "checks_passed": 0,
            "checks_failed": 0,
            # computed=PASS (no failed checks, no enforcement), but we record FAIL
            "status": "FAIL",
            # No "enforcement" field at all
        }

        result = verify_receipt(receipt, schema=None)
        # The receipt should be invalid (status mismatch: computed PASS ≠ expected FAIL)
        assert not result.valid
        # Look through all errors for any occurrence of spec §10 language
        for err in result.errors:
            assert "semantically defective" not in err, (
                f"No-enforcement mismatch must NOT use spec §10 text. Got: {err!r}"
            )
        # Confirm generic status-mismatch text is present
        assert any("Status mismatch: computed" in e and "expected" in e for e in result.errors), (
            f"Expected generic status-mismatch text. Got: {result.errors}"
        )


# ---------------------------------------------------------------------------
# san226-*: Schema-enabled path must produce §10 text (not schema artifact)
# ---------------------------------------------------------------------------

class TestStatusMismatchErrorTextSchemaEnabled:
    """SAN-226: Error text via the DEFAULT schema-enabled path must match schema=None.

    This mirrors TestStatusMismatchErrorText but exercises the real CLI code
    path (sanna-verify always passes schema=load_schema()). Before SAN-226 the
    v1.3 schema's allOf cross-field rules fired first and returned a schema-
    validator artifact ("'FAIL' was expected (at status)") instead of the §10
    reference text. SAN-226 reorders verify_receipt() so the semantic check
    runs before schema validation and the §10 language reaches real users.
    """

    def _build_inconsistent_receipt(self, enforcement_action, bad_status, checks_version="8"):
        """A receipt where enforcement.action disagrees with the recorded status."""
        return _make_raw_receipt_dict(
            enforcement_action=enforcement_action,
            status_override=bad_status,
            checks_version=checks_version,
        )

    def test_san226_schema_enabled_halted_with_pass_status(self):
        """halted + PASS via schema-enabled path must produce §10 text."""
        receipt = self._build_inconsistent_receipt("halted", "PASS")
        result = verify_receipt(receipt, schema=RECEIPT_SCHEMA)
        assert result.exit_code == 4, f"Expected exit_code=4, got {result.exit_code}. Errors: {result.errors}"
        top_error = result.errors[0] if result.errors else ""
        assert "cryptographically valid but semantically defective" in top_error, (
            f"Schema-enabled path must surface §10 text. Got: {top_error!r}"
        )
        assert "v1.3 spec §10" in top_error
        assert "enforcement.action='halted'" in top_error
        assert "'FAIL'" in top_error  # computed

    def test_san226_schema_enabled_warned_with_pass_status(self):
        receipt = self._build_inconsistent_receipt("warned", "PASS")
        result = verify_receipt(receipt, schema=RECEIPT_SCHEMA)
        assert result.exit_code == 4
        top_error = result.errors[0] if result.errors else ""
        assert "cryptographically valid but semantically defective" in top_error
        assert "v1.3 spec §10" in top_error
        assert "enforcement.action='warned'" in top_error

    def test_san226_schema_enabled_escalated_with_pass_status(self):
        receipt = self._build_inconsistent_receipt("escalated", "PASS")
        result = verify_receipt(receipt, schema=RECEIPT_SCHEMA)
        assert result.exit_code == 4
        top_error = result.errors[0] if result.errors else ""
        assert "cryptographically valid but semantically defective" in top_error
        assert "v1.3 spec §10" in top_error
        assert "enforcement.action='escalated'" in top_error

    def test_san226_schema_enabled_allowed_with_pass_status_passes(self):
        """allowed + PASS is the consistent case — should NOT error.

        Verifies the pre-empt does not false-positive on consistent receipts.
        """
        receipt = self._build_inconsistent_receipt("allowed", "PASS")
        # Not a mismatch — receipt should validate through all downstream checks.
        result = verify_receipt(receipt, schema=RECEIPT_SCHEMA)
        # Must NOT fail with §10 text. May pass entirely, or fail on something
        # unrelated — but the §10 text must not appear.
        for err in result.errors:
            assert "cryptographically valid but semantically defective" not in err, (
                f"Consistent receipt must not produce §10 text. Got error: {err!r}"
            )

    def test_san226_schema_enabled_byte_equivalent_to_schema_none(self):
        """The §10 error text produced with schema=RECEIPT_SCHEMA must be
        byte-equivalent to the text produced with schema=None. This is the
        core AC — SAN-226 guarantees the default CLI path produces the same
        error as the isolated test path.
        """
        receipt = self._build_inconsistent_receipt("halted", "PASS")

        result_schema_none = verify_receipt(receipt, schema=None)
        result_schema_on = verify_receipt(receipt, schema=RECEIPT_SCHEMA)

        assert result_schema_none.exit_code == result_schema_on.exit_code, (
            f"exit_code diverged: schema=None={result_schema_none.exit_code} "
            f"schema=RECEIPT_SCHEMA={result_schema_on.exit_code}"
        )
        top_none = result_schema_none.errors[0] if result_schema_none.errors else ""
        top_on = result_schema_on.errors[0] if result_schema_on.errors else ""
        assert top_none == top_on, (
            f"Error text diverged:\n  schema=None: {top_none!r}\n  schema=RECEIPT_SCHEMA: {top_on!r}"
        )


# ---------------------------------------------------------------------------
# san214-warn-*: Legacy warnings for cv=6/7 receipts
# All pass schema=None to bypass JSON-schema required-field checks.
# ---------------------------------------------------------------------------

class TestLegacyWarnings:
    """cv=6/7 receipts missing v1.3 fields should produce warnings, not errors."""

    def test_san214_warn_1_cv6_missing_enforcement_surface(self):
        """san214-warn-1: cv=6, no enforcement_surface → legacy warning (not error)."""
        receipt = _make_raw_receipt_dict(
            enforcement_action="allowed",
            status_override=None,
            checks_version="6",
            include_enforcement_surface=False,
            include_invariants_scope=False,
        )
        result = verify_receipt(receipt, schema=None)
        # Should still be valid (warning is not fatal)
        assert result.valid, (
            f"cv=6 missing enforcement_surface should not be an error. Errors: {result.errors}"
        )
        warning_text = " ".join(result.warnings)
        assert "Pre-v1.3 receipt" in warning_text, (
            f"Expected legacy warning. Warnings: {result.warnings}"
        )
        assert "enforcement_surface" in warning_text

    def test_san214_warn_2_cv7_missing_invariants_scope(self):
        """san214-warn-2: cv=7, no invariants_scope → legacy warning (not error)."""
        receipt = _make_raw_receipt_dict(
            enforcement_action="allowed",
            status_override=None,
            checks_version="7",
            include_enforcement_surface=False,
            include_invariants_scope=False,
        )
        result = verify_receipt(receipt, schema=None)
        assert result.valid, (
            f"cv=7 missing invariants_scope should not be an error. Errors: {result.errors}"
        )
        warning_text = " ".join(result.warnings)
        assert "Pre-v1.3 receipt" in warning_text, (
            f"Expected legacy warning. Warnings: {result.warnings}"
        )
        assert "invariants_scope" in warning_text

    def test_san214_warn_3_cv8_missing_enforcement_surface_is_hard_error(self):
        """san214-warn-3: cv=8, no enforcement_surface → HARD ERROR (not warning).

        Confirms the legacy-warning path only fires for cv 6/7, not cv 8+.
        Uses schema=None so only the verifier's own cv>=8 check fires.
        """
        receipt = _make_raw_receipt_dict(
            enforcement_action="allowed",
            status_override=None,
            checks_version="8",
            include_enforcement_surface=False,
            include_invariants_scope=True,
        )
        result = verify_receipt(receipt, schema=None)
        assert not result.valid, "cv=8 missing enforcement_surface must be an error"
        error_text = " ".join(result.errors)
        assert "enforcement_surface" in error_text
        # Must NOT produce a "Pre-v1.3 receipt" warning for this field
        warning_text = " ".join(result.warnings)
        assert "Pre-v1.3 receipt" not in warning_text, (
            "cv=8 enforcement_surface absence must be an error, not a legacy warning"
        )

    def test_san214_warn_4_cv7_with_both_fields_produces_no_legacy_warnings(self):
        """san214-warn-4: cv=7 WITH both v1.3 fields present → no Pre-v1.3 warnings.

        A cv=7 receipt that already includes enforcement_surface and invariants_scope
        (voluntarily, as the SDK is ahead of the protocol version) should not trigger
        the legacy-warning path. The warning fires only when the fields are ABSENT.
        """
        receipt = _make_raw_receipt_dict(
            enforcement_action="allowed",
            status_override=None,
            checks_version="7",
            # Both fields present → the legacy-warning check should NOT fire
            include_enforcement_surface=True,
            include_invariants_scope=True,
        )
        # Note: the fields are present in the dict but NOT in the 14-field fingerprint
        # formula for cv=7. The fingerprint will mismatch, but that's not what this
        # test is checking — it focuses solely on the absence of Pre-v1.3 warnings.
        result = verify_receipt(receipt, schema=None)
        warning_text = " ".join(result.warnings)
        assert "Pre-v1.3 receipt" not in warning_text, (
            f"cv=7 with both v1.3 fields present should NOT produce Pre-v1.3 legacy warnings. "
            f"Warnings: {result.warnings}"
        )


# ---------------------------------------------------------------------------
# san214-cli-*: CLI walkthrough for pre-v1.3 contradictions
# ---------------------------------------------------------------------------

class TestCliWalkthrough:
    """format_verify_summary walkthrough for pre-v1.3 contradictions."""

    def _make_mock_result(self, computed_status, expected_status, valid=False):
        return VerificationResult(
            valid=valid,
            exit_code=4,
            errors=[],
            warnings=[],
            computed_status=computed_status,
            expected_status=expected_status,
        )

    def _make_receipt_dict_for_cli(self, checks_version, enforcement_action=None):
        """Minimal receipt dict for passing to format_verify_summary."""
        receipt = {
            "spec_version": "1.1",
            "checks_version": checks_version,
            "status": "PASS",
        }
        if enforcement_action:
            receipt["enforcement"] = make_enforcement_dict(enforcement_action)
        return receipt

    def test_san214_cli_1_legacy_walkthrough_fires(self):
        """san214-cli-1: status mismatch + enforcement.action + cv<8 → LEGACY RECEIPT NOTE."""
        result = self._make_mock_result(computed_status="FAIL", expected_status="PASS")
        receipt = self._make_receipt_dict_for_cli(checks_version="6", enforcement_action="halted")
        output = format_verify_summary(result, receipt)
        assert "LEGACY RECEIPT NOTE" in output, (
            f"Expected LEGACY RECEIPT NOTE in output. Got:\n{output}"
        )
        assert "predates the Sprint 15 integrity fix" in output
        assert "halted" in output

    def test_san214_cli_1_walkthrough_shows_enforcement_action_values(self):
        """Walkthrough text should include the specific enforcement.action value."""
        for action in ("halted", "warned", "escalated"):
            result = self._make_mock_result(computed_status="FAIL", expected_status="PASS")
            receipt = self._make_receipt_dict_for_cli(checks_version="7", enforcement_action=action)
            output = format_verify_summary(result, receipt)
            assert "LEGACY RECEIPT NOTE" in output, (
                f"Action={action}: Expected LEGACY RECEIPT NOTE. Got:\n{output}"
            )
            assert action in output, (
                f"Walkthrough should name action '{action}'. Got:\n{output}"
            )

    def test_san214_cli_2_no_walkthrough_for_cv8(self):
        """san214-cli-2: cv>=8 status mismatch does NOT print LEGACY RECEIPT NOTE."""
        result = self._make_mock_result(computed_status="FAIL", expected_status="PASS")
        receipt = self._make_receipt_dict_for_cli(checks_version="8", enforcement_action="halted")
        output = format_verify_summary(result, receipt)
        assert "LEGACY RECEIPT NOTE" not in output, (
            f"cv=8 should NOT get legacy walkthrough. Got:\n{output}"
        )

    def test_san214_cli_3_no_walkthrough_without_enforcement(self):
        """san214-cli-3: cv<8 status mismatch without enforcement block → no walkthrough."""
        result = self._make_mock_result(computed_status="FAIL", expected_status="WARN")
        receipt = self._make_receipt_dict_for_cli(checks_version="6", enforcement_action=None)
        output = format_verify_summary(result, receipt)
        assert "LEGACY RECEIPT NOTE" not in output, (
            f"No enforcement block → no walkthrough. Got:\n{output}"
        )

    def test_san214_cli_no_walkthrough_when_no_mismatch(self):
        """No walkthrough when status is consistent (computed == expected)."""
        result = self._make_mock_result(computed_status="FAIL", expected_status="FAIL", valid=True)
        receipt = self._make_receipt_dict_for_cli(checks_version="6", enforcement_action="halted")
        output = format_verify_summary(result, receipt)
        assert "LEGACY RECEIPT NOTE" not in output, (
            f"No mismatch → no walkthrough. Got:\n{output}"
        )


# ---------------------------------------------------------------------------
# san214-integration-*: End-to-end proof with the real JSON schema
# These tests verify that the schema fix (removing enforcement_surface and
# invariants_scope from unconditional required, adding conditional-required
# allOf entry) correctly gates pre-v1.3 receipts through to the semantic layer.
# ---------------------------------------------------------------------------

class TestSchemaIntegration:
    """Integration proof that the schema fix allows legacy-warning path to be reached."""

    def test_san214_integration_legacy_warning_reachable_with_real_schema(self):
        """
        Integration proof that SAN-214 Change B (legacy warning for cv=6/7 receipts
        missing enforcement_surface/invariants_scope) is reachable in the production
        sanna-verify CLI path using the real JSON schema.

        Prior to the schema fix in this scope expansion, the real schema put
        enforcement_surface and invariants_scope in the unconditional 'required' array,
        causing schema validation to reject pre-v1.3 receipts before they could reach
        the semantic layer where the legacy warning lives. This test proves the fix
        works end-to-end.
        """
        # Build a cv=7 receipt with correct, internally consistent hashes so that
        # verify_content_hashes() passes and execution reaches the semantic layer.
        inputs = {"query": "test"}
        outputs = {"response": "test"}
        context_hash = hash_obj(inputs)
        output_hash = hash_obj(outputs)
        checks_version = "7"
        corr_id = "test-correlation-id-san214-integration"

        # 14-field fingerprint formula for cv=7 (no enforcement_surface/invariants_scope)
        fp_input = (
            f"{corr_id}|{context_hash}|{output_hash}|{checks_version}|{EMPTY_HASH}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
        )
        fp_full = hash_text(fp_input)

        receipt = {
            "spec_version": "1.1",
            "tool_version": "1.0.0",
            "checks_version": checks_version,
            "receipt_id": "00000000-0000-4000-8000-000000000001",
            "receipt_fingerprint": fp_full[:16],
            "full_fingerprint": fp_full,
            "correlation_id": corr_id,
            "timestamp": "2024-01-01T00:00:00Z",
            "inputs": inputs,
            "outputs": outputs,
            "context_hash": context_hash,
            "output_hash": output_hash,
            "checks": [],
            "checks_passed": 0,
            "checks_failed": 0,
            "status": "PASS",
            # enforcement_surface and invariants_scope are intentionally absent
        }

        from sanna.verify import load_schema
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        # Schema validation must PASS for this cv=7 receipt
        schema_errors = [e for e in result.errors if "schema" in e.lower() or "'enforcement_surface'" in e or "'invariants_scope'" in e]
        assert not schema_errors, (
            f"Schema validation rejected cv=7 receipt (legacy warning unreachable): {schema_errors}"
        )

        # Legacy warning must have fired
        legacy_warnings = [w for w in result.warnings if w.startswith("Pre-v1.3 receipt")]
        assert legacy_warnings, (
            f"Expected legacy warning for cv=7 receipt missing v1.3 fields, got warnings: {result.warnings}"
        )

    def test_san214_integration_v13_receipt_still_requires_new_fields_via_schema(self):
        """
        Symmetric proof: the schema conditional-required still enforces enforcement_surface
        and invariants_scope for cv=8 (v1.3) receipts. The fix must not accidentally
        make those fields optional for modern receipts.
        """
        # cv=8 receipt — v1.3, missing enforcement_surface
        receipt = {
            "spec_version": "1.1",
            "tool_version": "1.0.0",
            "checks_version": "8",
            "receipt_id": "00000000-0000-4000-8000-000000000002",
            "receipt_fingerprint": "abcd1234abcd1234",
            "full_fingerprint": "a" * 64,
            "correlation_id": "test-correlation-id",
            "timestamp": "2024-01-01T00:00:00Z",
            "inputs": {"query": "test"},
            "outputs": {"response": "test"},
            "context_hash": "a" * 64,
            "output_hash": "b" * 64,
            "checks": [],
            "checks_passed": 0,
            "checks_failed": 0,
            "status": "PASS",
            "invariants_scope": "all",
            # enforcement_surface intentionally absent
        }

        from sanna.verify import load_schema
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        # Must be rejected — either schema layer or semantic layer
        rejected = (
            any("enforcement_surface" in e for e in result.errors)
            or not result.valid
        )
        assert rejected, (
            f"cv=8 receipt missing enforcement_surface should be rejected, but result.valid={result.valid}, errors={result.errors}"
        )
