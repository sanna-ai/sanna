"""Tests for verify.py handling of ERRORED custom evaluator checks.

Ensures that receipts with ERRORED status (from custom evaluator exceptions)
pass offline verification — the verifier must treat ERRORED like NOT_CHECKED.
"""

import json
from pathlib import Path

import pytest

from sanna.crypto import generate_keypair
from sanna.evaluators import register_invariant_evaluator, clear_evaluators
from sanna.middleware import sanna_observe, SannaHaltError
from sanna.verify import (
    verify_receipt,
    verify_status_consistency,
    verify_check_counts,
    load_schema,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SCHEMA = load_schema()

# Constitution with custom invariant + built-in checks
_CONST_DIR = Path(__file__).parent.parent / "examples" / "constitutions"


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_evaluators()
    yield
    clear_evaluators()


def _raising_evaluator(context, output, constitution, check_config):
    raise RuntimeError("Evaluator crashed")


def _make_receipt_with_errored_checks(tmp_path):
    """Create a real receipt containing an ERRORED custom evaluator check."""
    from sanna.constitution import (
        Constitution, AgentIdentity, Provenance, Boundary, Invariant,
        sign_constitution, save_constitution, compute_constitution_hash,
    )

    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="t@t.com",
            approved_by=["a@t.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        invariants=[
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_CUSTOM_CRASH", rule="Crashes", enforcement="warn"),
        ],
    )
    priv_path, _ = generate_keypair(tmp_path / "keys")
    signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
    path = tmp_path / "const.yaml"
    save_constitution(signed, path)

    register_invariant_evaluator("INV_CUSTOM_CRASH")(_raising_evaluator)

    @sanna_observe(constitution_path=str(path))
    def agent(query, context):
        return "Grounded answer based on known context."

    result = agent(query="test", context="Known context for testing.")
    return result.receipt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestErroredVerification:

    def test_receipt_with_errored_passes_schema(self, tmp_path):
        """Receipt containing ERRORED check passes JSON schema validation."""
        receipt = _make_receipt_with_errored_checks(tmp_path)
        from jsonschema import validate, ValidationError
        try:
            validate(receipt, SCHEMA)
        except ValidationError as e:
            pytest.fail(f"Schema validation failed: {e.message}")

    def test_receipt_with_errored_verifies_valid(self, tmp_path):
        """verify_receipt() returns valid=True for receipt with ERRORED check."""
        receipt = _make_receipt_with_errored_checks(tmp_path)
        result = verify_receipt(receipt, SCHEMA)
        assert result.valid, f"Expected valid=True, got errors: {result.errors}"

    def test_errored_produces_partial_status(self, tmp_path):
        """Receipt with PASS + ERRORED checks has coherence_status=PARTIAL."""
        receipt = _make_receipt_with_errored_checks(tmp_path)
        assert receipt["coherence_status"] == "PARTIAL"

    def test_verify_status_consistency_with_errored(self, tmp_path):
        """verify_status_consistency treats ERRORED like NOT_CHECKED."""
        receipt = _make_receipt_with_errored_checks(tmp_path)
        matches, computed, expected = verify_status_consistency(receipt)
        assert matches, f"Status mismatch: computed={computed}, expected={expected}"
        assert computed == "PARTIAL"

    def test_verify_check_counts_with_errored(self, tmp_path):
        """verify_check_counts excludes ERRORED from pass/fail counting."""
        receipt = _make_receipt_with_errored_checks(tmp_path)
        errors = verify_check_counts(receipt)
        assert errors == [], f"Count verification errors: {errors}"

    def test_all_errored_checks_verify(self):
        """Receipt where every check is ERRORED verifies correctly."""
        receipt = {
            "checks": [
                {"check_id": "INV_A", "passed": True, "severity": "info",
                 "status": "ERRORED", "evidence": None},
                {"check_id": "INV_B", "passed": True, "severity": "info",
                 "status": "ERRORED", "evidence": None},
            ],
            "checks_passed": 0,
            "checks_failed": 0,
            "coherence_status": "PARTIAL",
        }
        matches, computed, expected = verify_status_consistency(receipt)
        assert matches
        assert computed == "PARTIAL"

        errors = verify_check_counts(receipt)
        assert errors == []

    def test_mixed_not_checked_and_errored(self):
        """Receipt with both NOT_CHECKED and ERRORED verifies as PARTIAL."""
        receipt = {
            "checks": [
                {"check_id": "C1", "passed": True, "severity": "info", "evidence": None},
                {"check_id": "INV_A", "passed": True, "severity": "info",
                 "status": "NOT_CHECKED", "evidence": None},
                {"check_id": "INV_B", "passed": True, "severity": "info",
                 "status": "ERRORED", "evidence": None},
            ],
            "checks_passed": 1,
            "checks_failed": 0,
            "coherence_status": "PARTIAL",
        }
        matches, computed, expected = verify_status_consistency(receipt)
        assert matches
        assert computed == "PARTIAL"

        errors = verify_check_counts(receipt)
        assert errors == []
