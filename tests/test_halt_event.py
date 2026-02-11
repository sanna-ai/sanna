"""
Tests for HaltEvent — enforcement action recording in receipts.
"""

import json
import warnings
import pytest
from dataclasses import asdict
from datetime import datetime, timezone

from sanna.receipt import (
    generate_receipt,
    ConstitutionProvenance,
    HaltEvent,
    SannaReceipt,
)
from sanna.hashing import hash_text, hash_obj
from sanna.verify import verify_receipt, load_schema, verify_fingerprint
from sanna.middleware import sanna_observe, SannaHaltError, SannaResult

SCHEMA = load_schema()

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
        "trace_id": "test-halt-001",
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


def make_halt_event():
    """Build a sample HaltEvent."""
    return HaltEvent(
        halted=True,
        reason="Coherence check failed: C1",
        failed_checks=["C1"],
        timestamp=datetime.now(timezone.utc).isoformat(),
        enforcement_mode="halt",
    )


class TestHaltEvent:
    def test_receipt_without_halt_event(self):
        """Receipt without halt_event should have halt_event=None."""
        receipt = generate_receipt(make_trace())
        assert receipt.halt_event is None

    def test_receipt_with_halt_event(self):
        """Receipt with halt_event should include halt_event dict."""
        halt_event = make_halt_event()
        receipt = generate_receipt(make_trace(), halt_event=halt_event)
        assert receipt.halt_event is not None
        assert receipt.halt_event["halted"] is True
        assert "C1" in receipt.halt_event["failed_checks"]
        assert receipt.halt_event["enforcement_mode"] == "halt"

    def test_halt_event_changes_fingerprint(self):
        """Adding a halt_event should change the fingerprint."""
        trace = make_trace()
        r_without = generate_receipt(trace)
        r_with = generate_receipt(trace, halt_event=make_halt_event())
        assert r_without.receipt_fingerprint != r_with.receipt_fingerprint

    def test_halt_event_receipt_validates(self):
        """Receipt with halt_event should pass schema + fingerprint verification."""
        receipt = generate_receipt(make_trace(), halt_event=make_halt_event())
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
        assert result.exit_code == 0

    def test_halt_event_fingerprint_verification(self):
        """Fingerprint should verify correctly with halt_event included."""
        receipt = generate_receipt(make_trace(), halt_event=make_halt_event())
        receipt_dict = asdict(receipt)
        match, computed, expected = verify_fingerprint(receipt_dict)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_tampering_halt_event_invalidates_fingerprint(self):
        """Modifying halt_event after generation should fail verification."""
        receipt = generate_receipt(make_trace(), halt_event=make_halt_event())
        receipt_dict = asdict(receipt)
        receipt_dict["halt_event"]["halted"] = False
        match, _, _ = verify_fingerprint(receipt_dict)
        assert not match

    def test_both_constitution_and_halt_event(self):
        """Receipt with both constitution and halt_event should verify."""
        constitution = ConstitutionProvenance(
            document_id="policy-v2",
            document_hash=hash_text("content"),
            version="2.0",
        )
        halt_event = make_halt_event()
        receipt = generate_receipt(
            make_trace(), constitution=constitution, halt_event=halt_event,
        )
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
        assert receipt_dict["constitution_ref"] is not None
        assert receipt_dict["halt_event"] is not None


class TestVerifierHaltWarning:
    def test_fail_without_halt_event_warns(self):
        """Verifier should warn when FAIL + critical failure but no halt_event."""
        # Use the refund contradiction trace that produces a FAIL
        trace = {
            "trace_id": "test-fail-no-halt",
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
        assert receipt.coherence_status == "FAIL"
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid  # Still valid, just warns
        assert any("halt_event" in w for w in result.warnings)

    def test_fail_with_halt_event_no_warning(self):
        """Verifier should NOT warn when FAIL has halt_event recorded."""
        trace = {
            "trace_id": "test-fail-with-halt",
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
        halt_event = HaltEvent(
            halted=True,
            reason="C1 critical failure",
            failed_checks=["C1"],
            timestamp=datetime.now(timezone.utc).isoformat(),
            enforcement_mode="halt",
        )
        receipt = generate_receipt(trace, halt_event=halt_event)
        assert receipt.coherence_status == "FAIL"
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid
        assert not any("halt_event" in w for w in result.warnings)


class TestMiddlewareHaltEvent:
    def test_halt_creates_halt_event(self):
        """@sanna_observe with on_violation='halt' should auto-create halt_event."""
        @sanna_observe(on_violation="halt")
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        assert receipt["halt_event"] is not None
        assert receipt["halt_event"]["halted"] is True
        assert "C1" in receipt["halt_event"]["failed_checks"]
        assert receipt["halt_event"]["enforcement_mode"] == "halt"

    def test_halt_receipt_with_halt_event_verifies(self):
        """Receipt with auto-created halt_event should pass verification."""
        @sanna_observe(on_violation="halt")
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        result = verify_receipt(receipt, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"

    def test_pass_no_halt_event(self):
        """Passing agent should NOT have a halt_event."""
        @sanna_observe(on_violation="halt")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert result.receipt.get("halt_event") is None

    def test_warn_no_halt_event(self):
        """Warn mode should NOT create a halt_event (only halt mode does)."""
        @sanna_observe(on_violation="warn")
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        assert result.receipt.get("halt_event") is None

    def test_middleware_with_constitution_and_halt(self):
        """Middleware with constitution should include both in halt receipt."""
        constitution = ConstitutionProvenance(
            document_id="policy-v2",
            document_hash=hash_text("No refunds on digital."),
            version="2.0",
            source="policy-repo",
        )

        @sanna_observe(on_violation="halt", constitution=constitution)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        assert receipt["constitution_ref"] is not None
        assert receipt["constitution_ref"]["document_id"] == "policy-v2"
        assert receipt["halt_event"] is not None
        assert receipt["halt_event"]["halted"] is True

        result = verify_receipt(receipt, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
