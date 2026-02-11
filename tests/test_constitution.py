"""
Tests for ConstitutionProvenance — governance tracking in receipts.
"""

import json
import pytest
from dataclasses import asdict

from sanna.receipt import (
    generate_receipt,
    ConstitutionProvenance,
    SannaReceipt,
)
from sanna.hashing import hash_text, hash_obj
from sanna.verify import verify_receipt, load_schema, verify_fingerprint

SCHEMA = load_schema()


def make_trace(**overrides):
    """Build a minimal trace dict."""
    trace = {
        "trace_id": "test-constitution-001",
        "name": "constitution-test",
        "timestamp": "2026-01-01T00:00:00Z",
        "input": {"query": "Can I get a refund?"},
        "output": {"final_answer": "The capital of France is Paris."},
        "metadata": {},
        "observations": [
            {
                "id": "obs-ret",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": "refund policy"},
                "output": {"context": "Paris is the capital of France."},
                "metadata": {},
                "start_time": "2026-01-01T00:00:01Z",
                "end_time": "2026-01-01T00:00:02Z",
            }
        ],
    }
    trace.update(overrides)
    return trace


def make_constitution():
    """Build a sample ConstitutionProvenance."""
    return ConstitutionProvenance(
        document_id="policy-v2-refund",
        document_hash=hash_text("No refunds on digital products."),
        version="2.0",
        source="policy-repo",
    )


class TestConstitutionProvenance:
    def test_receipt_without_constitution(self):
        """Receipt without constitution should have constitution_ref=None."""
        receipt = generate_receipt(make_trace())
        assert receipt.constitution_ref is None

    def test_receipt_with_constitution(self):
        """Receipt with constitution should include constitution_ref dict."""
        constitution = make_constitution()
        receipt = generate_receipt(make_trace(), constitution=constitution)
        assert receipt.constitution_ref is not None
        assert receipt.constitution_ref["document_id"] == "policy-v2-refund"
        assert receipt.constitution_ref["version"] == "2.0"
        assert receipt.constitution_ref["source"] == "policy-repo"
        assert len(receipt.constitution_ref["document_hash"]) == 16

    def test_constitution_changes_fingerprint(self):
        """Adding a constitution should change the fingerprint."""
        trace = make_trace()
        r_without = generate_receipt(trace)
        r_with = generate_receipt(trace, constitution=make_constitution())
        assert r_without.receipt_fingerprint != r_with.receipt_fingerprint

    def test_different_constitutions_different_fingerprints(self):
        """Different constitution docs should produce different fingerprints."""
        trace = make_trace()
        c1 = ConstitutionProvenance(
            document_id="policy-v1",
            document_hash=hash_text("version 1 content"),
        )
        c2 = ConstitutionProvenance(
            document_id="policy-v2",
            document_hash=hash_text("version 2 content"),
        )
        r1 = generate_receipt(trace, constitution=c1)
        r2 = generate_receipt(trace, constitution=c2)
        assert r1.receipt_fingerprint != r2.receipt_fingerprint

    def test_constitution_receipt_validates(self):
        """Receipt with constitution should pass schema + fingerprint verification."""
        receipt = generate_receipt(make_trace(), constitution=make_constitution())
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
        assert result.exit_code == 0

    def test_constitution_fingerprint_verification(self):
        """Fingerprint should verify correctly with constitution included."""
        receipt = generate_receipt(make_trace(), constitution=make_constitution())
        receipt_dict = asdict(receipt)
        match, computed, expected = verify_fingerprint(receipt_dict)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_tampering_constitution_invalidates_fingerprint(self):
        """Modifying constitution_ref after generation should fail verification."""
        receipt = generate_receipt(make_trace(), constitution=make_constitution())
        receipt_dict = asdict(receipt)
        receipt_dict["constitution_ref"]["document_id"] = "tampered-id"
        match, _, _ = verify_fingerprint(receipt_dict)
        assert not match

    def test_constitution_minimal_fields(self):
        """Constitution with only required fields should work."""
        constitution = ConstitutionProvenance(
            document_id="minimal",
            document_hash=hash_text("content"),
        )
        receipt = generate_receipt(make_trace(), constitution=constitution)
        assert receipt.constitution_ref["version"] is None
        assert receipt.constitution_ref["source"] is None
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"
