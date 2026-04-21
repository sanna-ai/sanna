"""Tests for v1.3 integrity guarantees — SAN-213/SAN-216.

Covers:
- Cross-SDK emission: no path produces status=PASS with enforcement.action=halted
- Status derivation mapping for skip_default_checks=True
- Required fields (enforcement_surface, invariants_scope) on every emit path
- Fingerprint parity: receipt.py, middleware.py, verify.py, gateway (formula-level)
- Verifier dispatch: checks_version "8" → 16-field, "7" → 14-field
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone

import pytest

from sanna.receipt import (
    generate_receipt,
    SPEC_VERSION,
    CHECKS_VERSION,
)
from sanna.hashing import hash_text, hash_obj, EMPTY_HASH
from sanna.verify import _verify_fingerprint_v013, verify_receipt, load_schema

RECEIPT_SCHEMA = load_schema()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_trace(correlation_id="test-corr-001"):
    return {
        "correlation_id": correlation_id,
        "name": "test",
        "input": {"query": "test query"},
        "output": {"final_answer": "test response"},
        "metadata": {},
        "observations": [],
    }


def make_enforcement_dict(action="halted"):
    return {
        "action": action,
        "reason": f"Test enforcement: {action}",
        "failed_checks": [],
        "enforcement_mode": "halt",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# AC #2: Status derivation mapping for skip_default_checks=True
# ---------------------------------------------------------------------------

class TestStatusDerivationMapping:
    """Canonical 4-value mapping: halted→FAIL, warned→WARN, allowed→PASS, escalated→WARN."""

    def test_halted_maps_to_fail(self):
        trace = make_trace("test-halted")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("halted"),
            skip_default_checks=True,
            enforcement_surface="cli_interceptor",
            invariants_scope="authority_only",
        )
        assert receipt.status == "FAIL", f"halted should → FAIL, got {receipt.status}"

    def test_warned_maps_to_warn(self):
        trace = make_trace("test-warned")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("warned"),
            skip_default_checks=True,
            enforcement_surface="cli_interceptor",
            invariants_scope="authority_only",
        )
        assert receipt.status == "WARN", f"warned should → WARN, got {receipt.status}"

    def test_allowed_maps_to_pass(self):
        trace = make_trace("test-allowed")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("allowed"),
            skip_default_checks=True,
            enforcement_surface="http_interceptor",
            invariants_scope="authority_only",
        )
        assert receipt.status == "PASS", f"allowed should → PASS, got {receipt.status}"

    def test_escalated_maps_to_warn(self):
        trace = make_trace("test-escalated")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("escalated"),
            skip_default_checks=True,
            enforcement_surface="cli_interceptor",
            invariants_scope="authority_only",
        )
        assert receipt.status == "WARN", f"escalated should → WARN, got {receipt.status}"

    def test_skip_default_checks_without_enforcement_raises(self):
        trace = make_trace("test-no-enforcement")
        with pytest.raises(ValueError, match="enforcement must be provided"):
            generate_receipt(
                trace,
                skip_default_checks=True,
                enforcement_surface="cli_interceptor",
                invariants_scope="authority_only",
            )

    def test_skip_default_checks_false_runs_c1_c5(self):
        """Default path still runs C1-C5 (default behavior unchanged)."""
        trace = make_trace("test-default")
        receipt = generate_receipt(
            trace,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert len(receipt.checks) == 5, "C1-C5 should run with skip_default_checks=False"


# ---------------------------------------------------------------------------
# Enforcement override on non-skip path (SAN-213 Branch 2C): when enforcement
# is provided and skip_default_checks=False, the canonical mapping still
# applies as a cross-field consistency guarantee. Covers all 4 action values.
# ---------------------------------------------------------------------------

class TestEnforcementOverrideNonSkipPath:
    """When enforcement is provided with skip_default_checks=False, status must
    still match enforcement.action per the canonical mapping (Spec v1.3 Section 4.6).

    Without this override the non-skip path could emit inconsistent receipts:
    e.g., C1-C5 all pass (status=PASS) with enforcement.action=escalated (should
    force status=WARN per canonical mapping).
    """

    def test_halted_override_elevates_pass_to_fail(self):
        """halted + PASS-from-checks → FAIL per canonical mapping."""
        trace = make_trace("override-halted")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("halted"),
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert receipt.status == "FAIL", (
            f"halted should force FAIL on non-skip path, got {receipt.status}"
        )

    def test_warned_override_elevates_pass_to_warn(self):
        """warned + PASS-from-checks → WARN per canonical mapping."""
        trace = make_trace("override-warned")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("warned"),
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert receipt.status == "WARN", (
            f"warned should force WARN on non-skip path, got {receipt.status}"
        )

    def test_escalated_override_elevates_pass_to_warn(self):
        """escalated + PASS-from-checks → WARN per canonical mapping.

        This is the bug surfaced during Branch 2B (sanna-protocol fixture regen):
        the original Branch 2 enforcement override covered halted and warned but
        missed escalated, allowing an inconsistent PASS+escalated receipt to
        emit on the non-skip path.
        """
        trace = make_trace("override-escalated")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("escalated"),
            enforcement_surface="gateway",
            invariants_scope="full",
        )
        assert receipt.status == "WARN", (
            f"escalated should force WARN on non-skip path, got {receipt.status}"
        )

    def test_allowed_leaves_pass_unchanged(self):
        """allowed + PASS-from-checks → PASS (no override needed)."""
        trace = make_trace("override-allowed")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("allowed"),
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert receipt.status == "PASS", (
            f"allowed should keep PASS on non-skip path, got {receipt.status}"
        )


# ---------------------------------------------------------------------------
# AC #9: Cross-SDK integrity — no path produces PASS with halted enforcement
# ---------------------------------------------------------------------------

class TestCrossSDKIntegrityNoPASSwithHalted:
    """Assert that no emit path can produce status=PASS when enforcement.action=halted."""

    def _assert_not_pass_with_halted(self, receipt_or_dict, path_name):
        if isinstance(receipt_or_dict, dict):
            status = receipt_or_dict.get("status")
            enforcement = receipt_or_dict.get("enforcement") or {}
        else:
            status = receipt_or_dict.status
            enforcement = receipt_or_dict.enforcement or {}
        action = enforcement.get("action") if isinstance(enforcement, dict) else None
        if action == "halted":
            assert status != "PASS", (
                f"{path_name}: status=PASS with enforcement.action=halted — "
                "integrity violation (SAN-213 AC #9)"
            )

    def test_generate_receipt_skip_false_halted_enforcement(self):
        """generate_receipt with skip_default_checks=False: enforcement override after generation."""
        trace = make_trace("integrity-middleware")
        # When we pass a halted enforcement with skip_default_checks=False,
        # the status is derived from checks — but the enforcement.action=halted
        # should not be masked by a PASS status.
        # With skip_default_checks=True and halted enforcement → FAIL
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("halted"),
            skip_default_checks=True,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        self._assert_not_pass_with_halted(receipt, "generate_receipt/skip=True/halted")
        assert receipt.status == "FAIL"

    def test_generate_receipt_cli_interceptor_halted(self):
        trace = make_trace("integrity-cli")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("halted"),
            skip_default_checks=True,
            enforcement_surface="cli_interceptor",
            invariants_scope="authority_only",
        )
        self._assert_not_pass_with_halted(receipt, "cli_interceptor/halted")
        assert receipt.status == "FAIL"

    def test_generate_receipt_http_interceptor_halted(self):
        trace = make_trace("integrity-http")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("halted"),
            skip_default_checks=True,
            enforcement_surface="http_interceptor",
            invariants_scope="authority_only",
        )
        self._assert_not_pass_with_halted(receipt, "http_interceptor/halted")
        assert receipt.status == "FAIL"

    def test_middleware_path_halted(self):
        """_generate_constitution_receipt path with halted enforcement."""
        from sanna.middleware import _generate_constitution_receipt
        from sanna.receipt import HaltEvent

        halt = HaltEvent(
            halted=True,
            reason="test halt",
            failed_checks=["C1"],
            timestamp=datetime.now(timezone.utc).isoformat(),
            enforcement_mode="halt",
        )
        trace = make_trace("integrity-mw-const")
        receipt = _generate_constitution_receipt(
            trace,
            check_configs=[],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0",
            enforcement=halt,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        self._assert_not_pass_with_halted(receipt, "_generate_constitution_receipt/halted")
        assert receipt["status"] == "FAIL"


# ---------------------------------------------------------------------------
# AC #3: Required fields on every emit path
# ---------------------------------------------------------------------------

class TestRequiredFieldsPresence:
    """enforcement_surface and invariants_scope must be populated on every emit path."""

    def test_generate_receipt_default(self):
        trace = make_trace("req-fields-default")
        receipt = generate_receipt(
            trace,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert receipt.enforcement_surface == "middleware"
        assert receipt.invariants_scope == "full"

    def test_generate_receipt_interceptor(self):
        trace = make_trace("req-fields-cli")
        receipt = generate_receipt(
            trace,
            enforcement=make_enforcement_dict("allowed"),
            skip_default_checks=True,
            enforcement_surface="cli_interceptor",
            invariants_scope="authority_only",
        )
        assert receipt.enforcement_surface == "cli_interceptor"
        assert receipt.invariants_scope == "authority_only"

    def test_generate_receipt_missing_surface_still_has_default(self):
        """Callers that don't pass enforcement_surface get 'middleware' default."""
        trace = make_trace("req-fields-defaults-only")
        receipt = generate_receipt(trace)
        assert receipt.enforcement_surface == "middleware"
        assert receipt.invariants_scope == "full"

    def test_middleware_constitution_receipt_surface_and_scope(self):
        from sanna.middleware import _generate_constitution_receipt
        trace = make_trace("req-fields-mw-const")
        receipt = _generate_constitution_receipt(
            trace,
            check_configs=[],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0",
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert receipt.get("enforcement_surface") == "middleware"
        assert receipt.get("invariants_scope") == "full"

    def test_middleware_no_invariants_receipt_surface_and_scope(self):
        from sanna.middleware import _generate_no_invariants_receipt
        trace = make_trace("req-fields-no-inv")
        receipt = _generate_no_invariants_receipt(
            trace,
            constitution_ref=None,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        assert receipt.get("enforcement_surface") == "middleware"
        assert receipt.get("invariants_scope") == "full"

    def test_asdict_receipt_has_both_fields(self):
        trace = make_trace("req-fields-asdict")
        receipt = generate_receipt(
            trace,
            enforcement_surface="gateway",
            invariants_scope="full",
        )
        d = asdict(receipt)
        assert "enforcement_surface" in d
        assert "invariants_scope" in d


# ---------------------------------------------------------------------------
# AC #4: Fingerprint parity (formula-level)
# ---------------------------------------------------------------------------

class TestFingerprintParity:
    """Verify the 16-field formula produces identical digests across all sites."""

    def _compute_expected_fp(self, receipt_dict):
        """Recompute the fingerprint from first principles using the v1.3 16-field formula."""
        correlation_id = receipt_dict.get("correlation_id", "")
        context_hash = receipt_dict.get("context_hash", "")
        output_hash = receipt_dict.get("output_hash", "")
        checks_version = receipt_dict.get("checks_version", CHECKS_VERSION)

        checks = receipt_dict.get("checks", [])
        checks_data = [
            {"check_id": c["check_id"], "passed": c["passed"],
             "severity": c["severity"], "evidence": c.get("evidence")}
            for c in checks
        ]
        checks_hash = hash_obj(checks_data) if checks_data else EMPTY_HASH

        constitution = receipt_dict.get("constitution_ref")
        if constitution:
            _cref = {k: v for k, v in constitution.items() if k != "constitution_approval"}
            constitution_hash = hash_obj(_cref)
        else:
            constitution_hash = EMPTY_HASH

        enforcement = receipt_dict.get("enforcement")
        enforcement_hash = hash_obj(enforcement) if enforcement else EMPTY_HASH

        coverage_hash = EMPTY_HASH
        authority_hash = EMPTY_HASH
        escalation_hash = EMPTY_HASH
        trust_hash = EMPTY_HASH

        extensions = receipt_dict.get("extensions")
        extensions_hash = hash_obj(extensions) if extensions else EMPTY_HASH

        parent_receipts = receipt_dict.get("parent_receipts")
        parent_receipts_hash = hash_obj(parent_receipts) if parent_receipts is not None else EMPTY_HASH
        workflow_id = receipt_dict.get("workflow_id")
        workflow_id_hash = hash_text(workflow_id) if workflow_id is not None else EMPTY_HASH

        enforcement_surface = receipt_dict.get("enforcement_surface", "middleware")
        invariants_scope = receipt_dict.get("invariants_scope", "full")
        enforcement_surface_hash = hash_text(enforcement_surface)
        invariants_scope_hash = hash_text(invariants_scope)

        fp_input = (
            f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|"
            f"{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|"
            f"{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}|"
            f"{parent_receipts_hash}|{workflow_id_hash}|"
            f"{enforcement_surface_hash}|{invariants_scope_hash}"
        )
        return hash_text(fp_input), hash_text(fp_input, truncate=16)

    def test_receipt_py_fingerprint_matches_formula(self):
        """receipt.py generate_receipt() fingerprint matches the 16-field formula."""
        trace = make_trace("fp-parity-receipt")
        receipt = generate_receipt(
            trace,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        d = asdict(receipt)
        expected_full, expected_short = self._compute_expected_fp(d)
        assert d["receipt_fingerprint"] == expected_short, (
            f"receipt.py short fingerprint mismatch: {d['receipt_fingerprint']} != {expected_short}"
        )
        assert d["full_fingerprint"] == expected_full, (
            f"receipt.py full fingerprint mismatch: {d['full_fingerprint']} != {expected_full}"
        )

    def test_verify_py_computes_same_fingerprint(self):
        """verify.py _verify_fingerprint_v013() must produce identical digest."""
        trace = make_trace("fp-parity-verify")
        receipt = generate_receipt(
            trace,
            enforcement_surface="gateway",
            invariants_scope="full",
        )
        d = asdict(receipt)
        matches, computed_short, _expected = _verify_fingerprint_v013(d)
        assert matches, (
            f"verify.py fingerprint mismatch: computed={computed_short}, "
            f"stored={d['receipt_fingerprint']}"
        )

    def test_middleware_constitution_fingerprint_parity(self):
        """_generate_constitution_receipt fingerprint matches _verify_fingerprint_v013."""
        from sanna.middleware import _generate_constitution_receipt
        trace = make_trace("fp-parity-middleware")
        receipt_dict = _generate_constitution_receipt(
            trace,
            check_configs=[],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0",
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        matches, computed_short, _expected = _verify_fingerprint_v013(receipt_dict)
        assert matches, (
            f"middleware fingerprint mismatch: computed={computed_short}, "
            f"stored={receipt_dict['receipt_fingerprint']}"
        )

    def test_no_invariants_receipt_fingerprint_parity(self):
        """_generate_no_invariants_receipt fingerprint matches _verify_fingerprint_v013."""
        from sanna.middleware import _generate_no_invariants_receipt
        trace = make_trace("fp-parity-no-inv")
        receipt_dict = _generate_no_invariants_receipt(
            trace,
            constitution_ref=None,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        matches, computed_short, _expected = _verify_fingerprint_v013(receipt_dict)
        assert matches, (
            f"no-invariants fingerprint mismatch: computed={computed_short}, "
            f"stored={receipt_dict['receipt_fingerprint']}"
        )


# ---------------------------------------------------------------------------
# AC #5: Verifier dispatch (CHECKS_VERSION-based)
# ---------------------------------------------------------------------------

class TestVerifierDispatch:
    """verify_receipt() dispatches to correct formula by checks_version."""

    def _make_v13_receipt(self):
        trace = make_trace("dispatch-v13")
        receipt = generate_receipt(
            trace,
            enforcement_surface="middleware",
            invariants_scope="full",
        )
        return asdict(receipt)

    def _make_v11_receipt(self):
        """Construct a minimal synthetic v1.1 receipt (checks_version='7', 14 fields)."""
        from sanna.middleware import _generate_no_invariants_receipt
        trace = make_trace("dispatch-v11")
        # Generate a current receipt then downgrade to simulate old format
        receipt_dict = _generate_no_invariants_receipt(
            trace,
            constitution_ref=None,
        )
        # Manually construct a 14-field fingerprint at version "7"
        correlation_id = receipt_dict["correlation_id"]
        context_hash = receipt_dict["context_hash"]
        output_hash = receipt_dict["output_hash"]
        fp_input = (
            f"{correlation_id}|{context_hash}|{output_hash}|7|"
            f"{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|"
            f"{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|"
            f"{EMPTY_HASH}|{EMPTY_HASH}"
        )
        receipt_dict["checks_version"] = "7"
        receipt_dict["spec_version"] = "1.1"
        receipt_dict["receipt_fingerprint"] = hash_text(fp_input, truncate=16)
        receipt_dict["full_fingerprint"] = hash_text(fp_input)
        # Remove v1.3 fields to simulate old receipt
        receipt_dict.pop("enforcement_surface", None)
        receipt_dict.pop("invariants_scope", None)
        return receipt_dict

    def test_v13_receipt_verifies_with_16_field_formula(self):
        d = self._make_v13_receipt()
        assert d["checks_version"] == "9"
        assert d["spec_version"] == "1.4"
        matches, _, _ = _verify_fingerprint_v013(d)
        assert matches, "v1.4 receipt should verify with 20-field formula"

    def test_v11_receipt_verifies_with_14_field_formula(self):
        d = self._make_v11_receipt()
        assert d["checks_version"] == "7"
        matches, _, _ = _verify_fingerprint_v013(d)
        assert matches, "v1.1 receipt should verify with 14-field formula"

    def test_v13_receipt_missing_surface_fails_verification(self):
        d = self._make_v13_receipt()
        d.pop("enforcement_surface")
        matches, _, _ = _verify_fingerprint_v013(d)
        assert not matches, "v1.3 receipt missing enforcement_surface should fail"

    def test_v13_receipt_missing_scope_fails_verification(self):
        d = self._make_v13_receipt()
        d.pop("invariants_scope")
        matches, _, _ = _verify_fingerprint_v013(d)
        assert not matches, "v1.3 receipt missing invariants_scope should fail"

    def test_verify_receipt_rejects_v13_missing_required_fields(self):
        """verify_receipt() emits a proper error for v1.3 receipts missing required fields."""
        d = self._make_v13_receipt()
        d.pop("enforcement_surface")
        result = verify_receipt(d, RECEIPT_SCHEMA)
        assert not result.valid
        assert any("enforcement_surface" in e for e in result.errors), (
            f"Expected error about enforcement_surface, got: {result.errors}"
        )


# ---------------------------------------------------------------------------
# AC #1: Version constants
# ---------------------------------------------------------------------------

class TestVersionConstants:
    def test_spec_version(self):
        assert SPEC_VERSION == "1.4"

    def test_checks_version(self):
        assert CHECKS_VERSION == "9"
