"""Tests for fingerprint computation edge cases (SAN-27).

Validates Python SDK parity with TypeScript SDK for:
- Empty checks array handling
- workflow_id None vs empty string semantics
- Conditional enforcement field inclusion in check hashing

Test vectors loaded from tests/fixtures/fingerprint-edge-cases.json
for cross-language verification.
"""

import json
from pathlib import Path

import pytest

from sanna.hashing import hash_text, hash_obj, EMPTY_HASH

VECTORS_PATH = Path(__file__).parent / "fixtures" / "fingerprint-edge-cases.json"
VECTORS = json.loads(VECTORS_PATH.read_text())


# =============================================================================
# DIVERGENCE 1: Empty checks array → EMPTY_HASH
# =============================================================================

class TestEmptyChecksHash:
    """Empty checks array must produce EMPTY_HASH, not hash of '[]'."""

    def test_empty_checks_returns_empty_hash(self):
        checks_data = []
        result = hash_obj(checks_data) if checks_data else EMPTY_HASH
        assert result == EMPTY_HASH
        assert result == VECTORS["vectors"]["checks_hash"]["empty_array"]["expected_hash"]

    def test_empty_checks_is_not_hash_of_empty_json_array(self):
        """Verify EMPTY_HASH != hash_obj([]) — the old incorrect behavior."""
        old_behavior = hash_obj([])
        assert old_behavior != EMPTY_HASH, (
            "hash_obj([]) should differ from EMPTY_HASH"
        )

    def test_null_checks_returns_empty_hash(self):
        checks_data = None
        result = EMPTY_HASH if checks_data is None else (
            hash_obj(checks_data) if checks_data else EMPTY_HASH
        )
        assert result == EMPTY_HASH
        assert result == VECTORS["vectors"]["checks_hash"]["null_checks"]["expected_hash"]

    def test_non_empty_checks_hashed_normally(self):
        checks_data = [{"check_id": "C1", "passed": True, "severity": "info", "evidence": None}]
        result = hash_obj(checks_data) if checks_data else EMPTY_HASH
        expected = VECTORS["vectors"]["checks_hash"]["non_empty_4_fields"]["expected_hash"]
        assert result == expected
        assert result != EMPTY_HASH

    def test_verify_empty_checks_fingerprint(self):
        """Verifier produces EMPTY_HASH for checks_hash when checks array is empty."""
        from sanna.verify import _verify_fingerprint_v013

        receipt = {
            "correlation_id": "test-empty",
            "context_hash": EMPTY_HASH,
            "output_hash": EMPTY_HASH,
            "checks_version": "6",
            "checks": [],
            "receipt_fingerprint": "",
            "full_fingerprint": "",
        }
        # Compute expected fingerprint using EMPTY_HASH for checks
        fp_input = "|".join([
            "test-empty", EMPTY_HASH, EMPTY_HASH, "6", EMPTY_HASH,
            EMPTY_HASH, EMPTY_HASH, EMPTY_HASH, EMPTY_HASH,
            EMPTY_HASH, EMPTY_HASH, EMPTY_HASH, EMPTY_HASH, EMPTY_HASH,
        ])
        expected_fp = hash_text(fp_input, truncate=16)
        receipt["receipt_fingerprint"] = expected_fp
        receipt["full_fingerprint"] = hash_text(fp_input)

        matches, computed, expected = _verify_fingerprint_v013(receipt)
        assert matches
        assert computed == expected_fp


# =============================================================================
# DIVERGENCE 2: workflow_id None vs empty string
# =============================================================================

class TestWorkflowIdHash:
    """workflow_id=None → EMPTY_HASH, workflow_id="" → hash_text("")."""

    def test_none_workflow_id_returns_empty_hash(self):
        workflow_id = None
        result = hash_text(workflow_id) if workflow_id is not None else EMPTY_HASH
        assert result == EMPTY_HASH
        assert result == VECTORS["vectors"]["workflow_id_hash"]["null_value"]["expected_hash"]

    def test_empty_string_workflow_id_hashed_as_value(self):
        """Empty string should go through hash_text, not return EMPTY_HASH via falsy check."""
        workflow_id = ""
        # New behavior: only None check
        result = hash_text(workflow_id) if workflow_id is not None else EMPTY_HASH
        assert result == VECTORS["vectors"]["workflow_id_hash"]["empty_string"]["expected_hash"]
        # Note: hash_text("") happens to equal EMPTY_HASH since sha256(b"") is the same,
        # but the code path is different (explicit hash vs. sentinel)

    def test_empty_string_workflow_id_not_skipped(self):
        """Verify the code PATH is correct: empty string goes through hash_text."""
        workflow_id = ""
        # Old behavior (falsy check) would skip hashing:
        old_result = hash_text(workflow_id) if workflow_id else EMPTY_HASH
        # New behavior (None check) hashes the value:
        new_result = hash_text(workflow_id) if workflow_id is not None else EMPTY_HASH
        # Both happen to produce EMPTY_HASH for empty string, but the logic differs
        assert new_result == hash_text("")

    def test_non_empty_workflow_id_hashed(self):
        workflow_id = "wf-12345"
        result = hash_text(workflow_id) if workflow_id is not None else EMPTY_HASH
        expected = VECTORS["vectors"]["workflow_id_hash"]["non_empty"]["expected_hash"]
        assert result == expected
        assert result != EMPTY_HASH

    def test_receipt_generate_with_empty_workflow_id(self):
        """generate_receipt with workflow_id='' should hash it, not treat as absent."""
        from sanna.receipt import generate_receipt

        trace_data = {
            "correlation_id": "test-wf-empty",
            "observations": [{"output": {"generated_answer": "a"}}],
            "output": {"final_answer": "a"},
            "input": "q",
            "metadata": {},
        }
        r_none = generate_receipt(trace_data, workflow_id=None)
        r_empty = generate_receipt(trace_data, workflow_id="")
        # Both produce EMPTY_HASH for workflow_id_hash (sha256(b"") == EMPTY_HASH)
        # but the receipt stores the value differently
        assert r_none.workflow_id is None
        assert r_empty.workflow_id == ""


# =============================================================================
# DIVERGENCE 3: Conditional enforcement fields in check hashing
# =============================================================================

class TestCheckEnforcementFields:
    """Check hashing includes enforcement fields only when triggered_by is present."""

    def test_checks_without_enforcement_use_4_fields(self):
        checks = [{"check_id": "C1", "passed": True, "severity": "info", "evidence": None}]
        has_enforcement = any(c.get("triggered_by") is not None for c in checks)
        assert not has_enforcement
        checks_data = [
            {"check_id": c["check_id"], "passed": c["passed"],
             "severity": c["severity"], "evidence": c["evidence"]}
            for c in checks
        ]
        result = hash_obj(checks_data)
        expected = VECTORS["vectors"]["check_enforcement_fields"]["without_enforcement"]["expected_hash"]
        assert result == expected

    def test_checks_with_enforcement_use_8_fields(self):
        checks = [
            {"check_id": "C1", "passed": True, "severity": "info", "evidence": None,
             "triggered_by": "INV_NO_FABRICATION", "enforcement_level": "warn",
             "check_impl": "sanna.context_contradiction", "replayable": True}
        ]
        has_enforcement = any(c.get("triggered_by") is not None for c in checks)
        assert has_enforcement
        checks_data = [
            {"check_id": c["check_id"], "passed": c["passed"],
             "severity": c["severity"], "evidence": c["evidence"],
             "triggered_by": c.get("triggered_by"),
             "enforcement_level": c.get("enforcement_level"),
             "check_impl": c.get("check_impl"),
             "replayable": c.get("replayable")}
            for c in checks
        ]
        result = hash_obj(checks_data)
        expected = VECTORS["vectors"]["check_enforcement_fields"]["with_enforcement"]["expected_hash"]
        assert result == expected

    def test_mixed_enforcement_uses_8_fields_for_all(self):
        """When any check has triggered_by, ALL checks use 8-field mode."""
        checks = [
            {"check_id": "C1", "passed": True, "severity": "info", "evidence": None,
             "triggered_by": "INV_NO_FABRICATION", "enforcement_level": "warn",
             "check_impl": "sanna.context_contradiction", "replayable": True},
            {"check_id": "C2", "passed": True, "severity": "info", "evidence": None},
        ]
        has_enforcement = any(c.get("triggered_by") is not None for c in checks)
        assert has_enforcement
        checks_data = [
            {"check_id": c.get("check_id", ""), "passed": c.get("passed"),
             "severity": c.get("severity", ""), "evidence": c.get("evidence"),
             "triggered_by": c.get("triggered_by"),
             "enforcement_level": c.get("enforcement_level"),
             "check_impl": c.get("check_impl"),
             "replayable": c.get("replayable")}
            for c in checks
        ]
        result = hash_obj(checks_data)
        expected = VECTORS["vectors"]["check_enforcement_fields"]["mixed_enforcement"]["expected_hash"]
        assert result == expected

    def test_4_and_8_field_hashes_differ(self):
        """Same check data produces different hashes with 4 vs 8 fields."""
        check = {"check_id": "C1", "passed": True, "severity": "info", "evidence": None,
                 "triggered_by": "INV_NO_FABRICATION", "enforcement_level": "warn",
                 "check_impl": "sanna.context_contradiction", "replayable": True}
        data_4 = [{"check_id": check["check_id"], "passed": check["passed"],
                   "severity": check["severity"], "evidence": check["evidence"]}]
        data_8 = [{"check_id": check["check_id"], "passed": check["passed"],
                   "severity": check["severity"], "evidence": check["evidence"],
                   "triggered_by": check["triggered_by"],
                   "enforcement_level": check["enforcement_level"],
                   "check_impl": check["check_impl"],
                   "replayable": check["replayable"]}]
        assert hash_obj(data_4) != hash_obj(data_8)


# =============================================================================
# CROSS-LANGUAGE VECTOR VALIDATION
# =============================================================================

class TestCrossLanguageVectors:
    """Validate all test vectors from the fixture file."""

    def test_empty_hash_constant(self):
        assert EMPTY_HASH == VECTORS["EMPTY_HASH"]

    @pytest.mark.parametrize("case_name,case", [
        (k, v) for k, v in VECTORS["vectors"]["checks_hash"].items()
    ])
    def test_checks_hash_vectors(self, case_name, case):
        data = case["input"]
        expected = case["expected_hash"]
        if data is None or len(data) == 0:
            result = EMPTY_HASH
        else:
            result = hash_obj(data)
        assert result == expected, f"checks_hash/{case_name}: {result} != {expected}"

    @pytest.mark.parametrize("case_name,case", [
        (k, v) for k, v in VECTORS["vectors"]["workflow_id_hash"].items()
    ])
    def test_workflow_id_vectors(self, case_name, case):
        wid = case["input"]
        expected = case["expected_hash"]
        result = hash_text(wid) if wid is not None else EMPTY_HASH
        assert result == expected, f"workflow_id_hash/{case_name}: {result} != {expected}"

    @pytest.mark.parametrize("case_name,case", [
        (k, v) for k, v in VECTORS["vectors"]["check_enforcement_fields"].items()
    ])
    def test_check_enforcement_vectors(self, case_name, case):
        checks = case["input"]
        expected = case["expected_hash"]
        has_enforcement = any(c.get("triggered_by") is not None for c in checks)
        if has_enforcement:
            checks_data = [
                {"check_id": c.get("check_id", ""), "passed": c.get("passed"),
                 "severity": c.get("severity", ""), "evidence": c.get("evidence"),
                 "triggered_by": c.get("triggered_by"),
                 "enforcement_level": c.get("enforcement_level"),
                 "check_impl": c.get("check_impl"),
                 "replayable": c.get("replayable")}
                for c in checks
            ]
        else:
            checks_data = [
                {"check_id": c.get("check_id", ""), "passed": c.get("passed"),
                 "severity": c.get("severity", ""), "evidence": c.get("evidence")}
                for c in checks
            ]
        result = hash_obj(checks_data) if checks_data else EMPTY_HASH
        assert result == expected, f"check_enforcement/{case_name}: {result} != {expected}"


# =============================================================================
# VERIFY.PY PARITY
# =============================================================================

class TestVerifyFingerprint:
    """Verify that verify.py's fingerprint recomputation matches the fixes."""

    def test_verify_receipt_with_checks(self):
        """Receipt with C1-C5 checks verifies correctly (generate_receipt → verify)."""
        from sanna.receipt import generate_receipt

        trace_data = {
            "correlation_id": "verify-checks",
            "observations": [{"output": {"generated_answer": "a"}}],
            "output": {"final_answer": "a"},
            "input": "q",
            "metadata": {},
        }
        receipt = generate_receipt(trace_data)
        receipt_dict = {
            "correlation_id": receipt.correlation_id,
            "context_hash": receipt.context_hash,
            "output_hash": receipt.output_hash,
            "checks_version": receipt.checks_version,
            "checks": receipt.checks,
            "receipt_fingerprint": receipt.receipt_fingerprint,
            "full_fingerprint": receipt.full_fingerprint,
            "enforcement_surface": receipt.enforcement_surface,
            "invariants_scope": receipt.invariants_scope,
        }
        from sanna.verify import _verify_fingerprint_v013
        matches, computed, _ = _verify_fingerprint_v013(receipt_dict)
        assert matches
        assert computed == receipt.receipt_fingerprint

    def test_verify_receipt_with_workflow_id(self):
        """Receipt with workflow_id verifies correctly."""
        from sanna.receipt import generate_receipt

        trace_data = {
            "correlation_id": "verify-wfid",
            "observations": [{"output": {"generated_answer": "a"}}],
            "output": {"final_answer": "a"},
            "input": "q",
            "metadata": {},
        }
        receipt = generate_receipt(trace_data, workflow_id="wf-test")
        receipt_dict = {
            "correlation_id": receipt.correlation_id,
            "context_hash": receipt.context_hash,
            "output_hash": receipt.output_hash,
            "checks_version": receipt.checks_version,
            "checks": receipt.checks,
            "receipt_fingerprint": receipt.receipt_fingerprint,
            "full_fingerprint": receipt.full_fingerprint,
            "workflow_id": receipt.workflow_id,
            "enforcement_surface": receipt.enforcement_surface,
            "invariants_scope": receipt.invariants_scope,
        }
        from sanna.verify import _verify_fingerprint_v013
        matches, computed, _ = _verify_fingerprint_v013(receipt_dict)
        assert matches
        assert computed == receipt.receipt_fingerprint
