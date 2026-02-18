"""
Tests for enforcement action recording in receipts.

v0.6.0: Middleware tests updated to use constitution-driven enforcement.
v0.13.0: enforcement field, status field renamed, correlation_id.
"""

import json
import warnings
import pytest
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from sanna.receipt import (
    generate_receipt,
    ConstitutionProvenance,
    HaltEvent,
    Enforcement,
    SannaReceipt,
)
from sanna.hashing import hash_text, hash_obj
from sanna.verify import verify_receipt, load_schema, verify_fingerprint
from sanna.middleware import sanna_observe, SannaHaltError, SannaResult

SCHEMA = load_schema()

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
ALL_HALT_CONST = str(CONSTITUTIONS_DIR / "all_halt.yaml")
ALL_WARN_CONST = str(CONSTITUTIONS_DIR / "all_warn.yaml")

REFUND_CONTEXT = (
    "Our refund policy: Physical products can be returned within 30 days. "
    "Digital products are non-refundable once downloaded. "
    "Subscriptions can be cancelled anytime."
)
REFUND_BAD_OUTPUT = (
    "Based on your purchase history, you are eligible to request a refund. "
    "However, since the software was downloaded, processing may take 5-7 "
    "business days."
)
SIMPLE_CONTEXT = "Paris is the capital of France."
SIMPLE_OUTPUT = "The capital of France is Paris."


def make_trace(**overrides):
    """Build a minimal trace dict."""
    trace = {
        "correlation_id": "test-halt-001",
        "name": "halt-test",
        "timestamp": "2026-01-01T00:00:00Z",
        "input": {"query": "test?"},
        "output": {"final_answer": "The capital of France is Paris."},
        "metadata": {},
        "observations": [
            {
                "id": "obs-ret",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": "test"},
                "output": {"context": "Paris is the capital of France."},
                "metadata": {},
                "start_time": "2026-01-01T00:00:01Z",
                "end_time": "2026-01-01T00:00:02Z",
            }
        ],
    }
    trace.update(overrides)
    return trace


def make_enforcement():
    """Build a sample HaltEvent."""
    return HaltEvent(
        halted=True,
        reason="Coherence check failed: C1",
        failed_checks=["C1"],
        timestamp=datetime.now(timezone.utc).isoformat(),
        enforcement_mode="halt",
    )


class TestHaltEvent:
    def test_receipt_without_enforcement(self):
        """Receipt without enforcement should have enforcement=None."""
        receipt = generate_receipt(make_trace())
        assert receipt.enforcement is None

    def test_receipt_with_enforcement(self):
        """Receipt with enforcement should produce enforcement dict."""
        enforcement_obj = make_enforcement()
        receipt = generate_receipt(make_trace(), enforcement=enforcement_obj)
        assert receipt.enforcement is not None
        assert receipt.enforcement["action"] == "halted"
        assert "C1" in receipt.enforcement["failed_checks"]
        assert receipt.enforcement["enforcement_mode"] == "halt"

    def test_enforcement_changes_fingerprint(self):
        """Adding enforcement should change the fingerprint."""
        trace = make_trace()
        r_without = generate_receipt(trace)
        r_with = generate_receipt(trace, enforcement=make_enforcement())
        assert r_without.receipt_fingerprint != r_with.receipt_fingerprint

    def test_enforcement_receipt_validates(self):
        """Receipt with enforcement should pass schema + fingerprint verification."""
        receipt = generate_receipt(make_trace(), enforcement=make_enforcement())
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
        assert result.exit_code == 0

    def test_enforcement_fingerprint_verification(self):
        """Fingerprint should verify correctly with enforcement included."""
        receipt = generate_receipt(make_trace(), enforcement=make_enforcement())
        receipt_dict = asdict(receipt)
        match, computed, expected = verify_fingerprint(receipt_dict)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_tampering_enforcement_invalidates_fingerprint(self):
        """Modifying enforcement after generation should fail verification."""
        receipt = generate_receipt(make_trace(), enforcement=make_enforcement())
        receipt_dict = asdict(receipt)
        receipt_dict["enforcement"]["action"] = "allowed"
        match, _, _ = verify_fingerprint(receipt_dict)
        assert not match

    def test_both_constitution_and_enforcement(self):
        """Receipt with both constitution and enforcement should verify."""
        constitution = ConstitutionProvenance(
            document_id="policy-v2",
            policy_hash=hash_text("content"),
            version="2.0",
        )
        enforcement_obj = make_enforcement()
        receipt = generate_receipt(
            make_trace(), constitution=constitution, enforcement=enforcement_obj,
        )
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
        assert receipt_dict["constitution_ref"] is not None
        assert receipt_dict["enforcement"] is not None


class TestVerifierEnforcementWarning:
    def test_fail_without_enforcement_warns(self):
        """Verifier should warn when FAIL + critical failure but no enforcement."""
        # Use the refund contradiction trace that produces a FAIL
        trace = {
            "correlation_id": "test-fail-no-halt",
            "name": "fail-no-halt",
            "timestamp": "2026-01-01T00:00:00Z",
            "input": {"query": "refund?"},
            "output": {"final_answer": REFUND_BAD_OUTPUT},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "refund"},
                    "output": {"context": REFUND_CONTEXT},
                    "metadata": {},
                }
            ],
        }
        receipt = generate_receipt(trace)
        assert receipt.status == "FAIL"
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid  # Still valid, just warns
        assert any("enforcement" in w for w in result.warnings)

    def test_fail_with_enforcement_no_warning(self):
        """Verifier should NOT warn when FAIL has enforcement recorded."""
        trace = {
            "correlation_id": "test-fail-with-halt",
            "name": "fail-with-halt",
            "timestamp": "2026-01-01T00:00:00Z",
            "input": {"query": "refund?"},
            "output": {"final_answer": REFUND_BAD_OUTPUT},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "refund"},
                    "output": {"context": REFUND_CONTEXT},
                    "metadata": {},
                }
            ],
        }
        enforcement_obj = HaltEvent(
            halted=True,
            reason="C1 critical failure",
            failed_checks=["C1"],
            timestamp=datetime.now(timezone.utc).isoformat(),
            enforcement_mode="halt",
        )
        receipt = generate_receipt(trace, enforcement=enforcement_obj)
        assert receipt.status == "FAIL"
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid
        assert not any("enforcement" in w for w in result.warnings)


class TestMiddlewareEnforcement:
    def test_halt_creates_enforcement(self):
        """@sanna_observe with halt constitution should auto-create enforcement."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        assert receipt["enforcement"] is not None
        assert receipt["enforcement"]["action"] == "halted"
        assert "sanna.context_contradiction" in receipt["enforcement"]["failed_checks"]
        assert receipt["enforcement"]["enforcement_mode"] == "halt"

    def test_halt_receipt_with_enforcement_verifies(self):
        """Receipt with auto-created enforcement should pass verification."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        result = verify_receipt(receipt, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"

    def test_pass_no_enforcement(self):
        """Passing agent should NOT have enforcement."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert result.receipt.get("enforcement") is None

    def test_warn_no_halt_enforcement(self):
        """Warn mode should NOT create a halted enforcement (only halt mode does)."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_WARN_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        # Warn mode does not produce a "halted" enforcement action
        enforcement = result.receipt.get("enforcement")
        if enforcement is not None:
            assert enforcement["action"] != "halted"

    def test_middleware_with_constitution_and_halt(self):
        """Middleware with constitution should include both in halt receipt."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        assert receipt["constitution_ref"] is not None
        assert receipt["enforcement"] is not None
        assert receipt["enforcement"]["action"] == "halted"

        result = verify_receipt(receipt, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
