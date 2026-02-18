"""
Sanna test suite — golden receipt verification, hashing, checks, and verifier.
"""

import json
import copy
import pytest
from pathlib import Path
from dataclasses import asdict

from sanna.hashing import hash_text, hash_obj, canonicalize_text, sha256_hex, canonical_json_bytes
from sanna.receipt import (
    generate_receipt, CheckResult, SannaReceipt,
    check_c1_context_contradiction, check_c2_unmarked_inference,
    check_c3_false_certainty, check_c4_conflict_collapse,
    check_c5_premature_compression, select_final_answer,
    extract_context, extract_query, find_snippet,
    TOOL_VERSION, SPEC_VERSION, CHECKS_VERSION,
)
from sanna.verify import (
    verify_receipt, load_schema, VerificationResult,
    verify_fingerprint, verify_status_consistency,
    verify_check_counts, verify_hash_format, verify_content_hashes,
)


# =============================================================================
# FIXTURES
# =============================================================================

GOLDEN_DIR = Path(__file__).parent.parent / "golden" / "receipts"
SCHEMA = load_schema()


def load_golden(name: str) -> dict:
    """Load a golden receipt by filename."""
    with open(GOLDEN_DIR / name) as f:
        return json.load(f)


def all_golden_receipts():
    """List all golden receipt files (excluding tampered)."""
    return sorted([f.name for f in GOLDEN_DIR.glob("*.json") if "tampered" not in f.name])


# =============================================================================
# HASHING TESTS
# =============================================================================

class TestHashing:
    def test_hash_text_deterministic(self):
        assert hash_text("hello world") == hash_text("hello world")

    def test_hash_text_different_inputs(self):
        assert hash_text("hello") != hash_text("world")

    def test_hash_text_64_hex_chars(self):
        """hash_text() returns full 64-hex SHA-256 by default (v0.13.0+)."""
        h = hash_text("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_text_truncate_16(self):
        """hash_text(s, truncate=16) returns 16-hex for backward compatibility."""
        h = hash_text("test", truncate=16)
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)
        # Truncated form is a prefix of the full hash
        full = hash_text("test")
        assert full[:16] == h

    def test_hash_obj_deterministic(self):
        obj = {"b": 2, "a": 1}
        assert hash_obj(obj) == hash_obj({"a": 1, "b": 2})

    def test_hash_obj_key_order_independent(self):
        """Canonical JSON sorts keys, so order doesn't matter."""
        assert hash_obj({"z": 1, "a": 2}) == hash_obj({"a": 2, "z": 1})

    def test_canonicalize_text_nfc(self):
        # NFC normalization
        result = canonicalize_text("café")
        assert result == "café"

    def test_canonicalize_text_line_endings(self):
        assert canonicalize_text("a\r\nb") == canonicalize_text("a\nb")
        assert canonicalize_text("a\rb") == canonicalize_text("a\nb")

    def test_canonicalize_text_trailing_whitespace(self):
        assert canonicalize_text("hello   ") == "hello"
        assert canonicalize_text("line1   \nline2  ") == "line1\nline2"

    def test_canonicalize_text_none(self):
        assert canonicalize_text(None) == ""

    def test_sha256_hex_full(self):
        h = sha256_hex(b"test", truncate=0)
        assert len(h) == 64

    def test_sha256_hex_truncated(self):
        h = sha256_hex(b"test", truncate=16)
        assert len(h) == 16

    def test_canonical_json_bytes_no_spaces(self):
        result = canonical_json_bytes({"a": 1})
        assert result == b'{"a":1}'

    def test_canonical_json_bytes_sorted(self):
        result = canonical_json_bytes({"b": 2, "a": 1})
        assert result == b'{"a":1,"b":2}'


# =============================================================================
# C1-C5 CHECK TESTS
# =============================================================================

class TestC1ContextContradiction:
    def test_c1_pass_no_contradiction(self):
        result = check_c1_context_contradiction(
            "Paris is the capital of France.",
            "The capital of France is Paris."
        )
        assert result.passed
        assert result.check_id == "C1"

    def test_c1_fail_refund_contradiction(self):
        result = check_c1_context_contradiction(
            "Digital products are non-refundable once downloaded.",
            "You are eligible to request a refund for the software."
        )
        assert not result.passed
        assert result.severity == "critical"
        assert "non-refundable" in result.evidence.lower()

    def test_c1_pass_empty_context(self):
        result = check_c1_context_contradiction("", "some output")
        assert result.passed

    def test_c1_pass_empty_output(self):
        result = check_c1_context_contradiction("some context", "")
        assert result.passed


class TestC2UnmarkedInference:
    def test_c2_pass_hedged(self):
        result = check_c2_unmarked_inference(
            "Some context",
            "This may work, and it's possible that results could vary."
        )
        assert result.passed

    def test_c2_fail_definitive_no_hedging(self):
        result = check_c2_unmarked_inference(
            "Some context",
            "This will definitely work and is guaranteed to succeed."
        )
        assert not result.passed
        assert result.severity == "warning"

    def test_c2_pass_empty_output(self):
        result = check_c2_unmarked_inference("context", "")
        assert result.passed

    def test_c2_pass_definitive_with_hedging(self):
        result = check_c2_unmarked_inference(
            "context",
            "This is definitely the approach, though it may need adjustments."
        )
        assert result.passed


class TestC3FalseCertainty:
    def test_c3_pass_acknowledges_conditions(self):
        result = check_c3_false_certainty(
            "Available if usage is under 1000 requests. Requires registration.",
            "You can use the API, however this requires registration first."
        )
        assert result.passed

    def test_c3_fail_ignores_conditions(self):
        result = check_c3_false_certainty(
            "Available if usage is under 1000 requests. Requires registration.",
            "You can use the API. Go ahead and start making requests."
        )
        assert not result.passed
        assert result.severity == "warning"

    def test_c3_pass_empty_output(self):
        result = check_c3_false_certainty("context", "")
        assert result.passed


class TestC4ConflictCollapse:
    def test_c4_pass_acknowledges_tension(self):
        result = check_c4_conflict_collapse(
            "Users can access premium features. However, some features require admin approval.",
            "You can access premium features, however some require admin approval."
        )
        assert result.passed

    def test_c4_fail_collapses_tension(self):
        result = check_c4_conflict_collapse(
            "License transfers are permitted for enterprise. Individual licenses cannot be transferred.",
            "Yes, you can transfer your license."
        )
        assert not result.passed
        assert result.severity == "warning"

    def test_c4_pass_no_conflict(self):
        result = check_c4_conflict_collapse(
            "The sky is blue.",
            "The sky is blue on clear days."
        )
        assert result.passed


class TestC5PrematureCompression:
    def test_c5_pass_adequate_detail(self):
        result = check_c5_premature_compression(
            "Option A costs $10. Option B costs $20. Option C is free.",
            "There are three options: A at $10, B at $20, and C which is free. Each has different trade-offs."
        )
        assert result.passed

    def test_c5_fail_oversimplified(self):
        result = check_c5_premature_compression(
            "Deployment options include:\n- AWS\n- GCP\n- Azure\n- On-premise\nEach has different implications.",
            "Deploy to cloud"
        )
        assert not result.passed
        assert result.severity == "warning"

    def test_c5_pass_simple_context(self):
        result = check_c5_premature_compression(
            "The answer is 42.",
            "42"
        )
        assert result.passed


# =============================================================================
# RECEIPT GENERATION TESTS
# =============================================================================

class TestReceiptGeneration:
    def make_trace(self, context="Some context.", output="Some output.", query="question?"):
        return {
            "correlation_id": "test-trace-001",
            "name": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "input": {"query": query},
            "output": {"final_answer": output},
            "metadata": {},
            "observations": [
                {
                    "id": "obs-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": query},
                    "output": {"context": context},
                    "metadata": {},
                    "start_time": "2026-01-01T00:00:01Z",
                    "end_time": "2026-01-01T00:00:02Z",
                }
            ],
        }

    def test_receipt_has_required_fields(self):
        receipt = generate_receipt(self.make_trace())
        d = asdict(receipt)
        for field in ["spec_version", "tool_version", "checks_version",
                       "receipt_id", "receipt_fingerprint", "full_fingerprint",
                       "correlation_id",
                       "timestamp", "inputs", "outputs", "context_hash",
                       "output_hash", "checks",
                       "checks_passed", "checks_failed", "status"]:
            assert field in d, f"Missing field: {field}"

    def test_receipt_versions(self):
        receipt = generate_receipt(self.make_trace())
        assert receipt.spec_version == SPEC_VERSION
        assert receipt.tool_version == TOOL_VERSION
        assert receipt.checks_version == CHECKS_VERSION

    def test_receipt_has_five_checks(self):
        receipt = generate_receipt(self.make_trace())
        assert len(receipt.checks) == 5

    def test_receipt_check_counts_consistent(self):
        receipt = generate_receipt(self.make_trace())
        assert receipt.checks_passed + receipt.checks_failed == 5

    def test_receipt_fingerprint_stable(self):
        """Same trace data should produce same fingerprint."""
        trace = self.make_trace()
        r1 = generate_receipt(trace)
        r2 = generate_receipt(trace)
        assert r1.receipt_fingerprint == r2.receipt_fingerprint

    def test_receipt_id_is_uuid4(self):
        """Receipt ID is UUID v4 (v0.13.0+)."""
        import re
        trace = self.make_trace()
        r1 = generate_receipt(trace)
        r2 = generate_receipt(trace)
        uuid4_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        assert uuid4_re.match(r1.receipt_id), f"Not UUID v4: {r1.receipt_id}"
        assert uuid4_re.match(r2.receipt_id), f"Not UUID v4: {r2.receipt_id}"

    def test_hash_format(self):
        """v0.13.0: receipt_id=UUID4, fingerprint=16-hex, full_fingerprint/hashes=64-hex."""
        receipt = generate_receipt(self.make_trace())
        import re
        uuid4_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        hex16 = re.compile(r"^[a-f0-9]{16}$")
        hex64 = re.compile(r"^[a-f0-9]{64}$")
        assert uuid4_re.match(receipt.receipt_id)
        assert hex16.match(receipt.receipt_fingerprint)
        assert hex64.match(receipt.full_fingerprint)
        assert hex64.match(receipt.context_hash)
        assert hex64.match(receipt.output_hash)


# =============================================================================
# SELECT FINAL ANSWER TESTS
# =============================================================================

class TestSelectFinalAnswer:
    def test_trace_output_preferred(self):
        trace = {
            "correlation_id": "test",
            "output": {"final_answer": "From trace"},
            "observations": [
                {
                    "id": "gen-1",
                    "name": "llm-generation",
                    "type": "GENERATION",
                    "output": {"response": "From span"},
                    "metadata": {},
                    "end_time": "2026-01-01T00:00:05Z",
                }
            ],
        }
        answer, prov = select_final_answer(trace)
        assert answer == "From trace"
        assert prov.source == "trace.output"

    def test_span_output_fallback(self):
        trace = {
            "correlation_id": "test",
            "output": None,
            "observations": [
                {
                    "id": "gen-1",
                    "name": "llm-generation",
                    "type": "GENERATION",
                    "output": {"response": "From span"},
                    "metadata": {"model": "gpt-4"},
                    "end_time": "2026-01-01T00:00:05Z",
                }
            ],
        }
        answer, prov = select_final_answer(trace)
        assert answer == "From span"
        assert prov.source == "span.output"

    def test_no_answer_found(self):
        trace = {"correlation_id": "test", "output": None, "observations": []}
        answer, prov = select_final_answer(trace)
        assert answer == ""
        assert prov.source == "none"


# =============================================================================
# EXTRACTION HELPERS
# =============================================================================

class TestExtractionHelpers:
    def test_extract_context(self):
        trace = {
            "observations": [
                {"name": "retrieval", "output": {"context": "Retrieved context"}}
            ]
        }
        assert extract_context(trace) == "Retrieved context"

    def test_extract_query(self):
        trace = {
            "observations": [
                {"name": "retrieval", "input": {"query": "User question"}}
            ]
        }
        assert extract_query(trace) == "User question"

    def test_find_snippet_found(self):
        result = find_snippet("This is a long text with the keyword here.", ["keyword"])
        assert "keyword" in result

    def test_find_snippet_not_found(self):
        result = find_snippet("Short text.", ["missing"])
        assert result == "Short text."

    def test_find_snippet_empty(self):
        assert find_snippet("", ["any"]) == ""


# =============================================================================
# VERIFIER TESTS
# =============================================================================

class TestVerifier:
    """Verifier tests using golden receipts (old format).

    Golden receipts use the legacy schema (schema_version,
    status) so they cannot pass v1.0 JSON schema validation.
    These tests exercise the individual backward-compatible verification
    functions (fingerprint, content hashes, status, counts) directly.
    """

    def test_valid_receipt_legacy_components(self):
        """Legacy golden receipt passes all backward-compatible verification steps."""
        receipt = load_golden("002_pass_simple_qa.json")
        # Fingerprint
        fp_match, _, _ = verify_fingerprint(receipt)
        assert fp_match, "Legacy fingerprint should match"
        # Content hashes
        assert verify_content_hashes(receipt) == []
        # Hash format (legacy 16-hex)
        assert verify_hash_format(receipt) == []
        # Status consistency
        status_match, _, _ = verify_status_consistency(receipt)
        assert status_match
        # Check counts
        assert verify_check_counts(receipt) == []

    def test_schema_invalid(self):
        receipt = {"not": "a valid receipt"}
        result = verify_receipt(receipt, SCHEMA)
        assert not result.valid
        assert result.exit_code == 2

    def test_fingerprint_mismatch(self):
        receipt = load_golden("002_pass_simple_qa.json")
        receipt["receipt_fingerprint"] = "0000000000000000"
        match, computed, expected = verify_fingerprint(receipt)
        assert not match

    def test_content_tamper_detected(self):
        receipt = load_golden("002_pass_simple_qa.json")
        receipt["outputs"]["response"] = "TAMPERED CONTENT"
        errors = verify_content_hashes(receipt)
        assert len(errors) > 0
        assert any("tampered" in e.lower() for e in errors)

    def test_status_consistency_mismatch(self):
        receipt = load_golden("002_pass_simple_qa.json")
        receipt["status"] = "FAIL"  # Should be PASS
        match, computed, expected = verify_status_consistency(receipt)
        assert not match
        assert computed == "PASS"
        assert expected == "FAIL"

    def test_check_count_mismatch(self):
        receipt = load_golden("002_pass_simple_qa.json")
        receipt["checks_passed"] = 0  # Wrong
        errors = verify_check_counts(receipt)
        assert len(errors) > 0
        assert any("checks_passed" in e for e in errors)


class TestVerifyFingerprint:
    def test_fingerprint_matches(self):
        receipt = load_golden("001_fail_c1_refund.json")
        match, computed, expected = verify_fingerprint(receipt)
        assert match
        assert computed == expected

    def test_fingerprint_mismatch(self):
        receipt = load_golden("001_fail_c1_refund.json")
        receipt["receipt_fingerprint"] = "0000000000000000"
        match, computed, expected = verify_fingerprint(receipt)
        assert not match


class TestVerifyStatusConsistency:
    def test_pass_status(self):
        receipt = {"checks": [{"passed": True, "severity": "info"}], "status": "PASS"}
        match, computed, expected = verify_status_consistency(receipt)
        assert match

    def test_warn_status(self):
        receipt = {"checks": [{"passed": False, "severity": "warning"}], "status": "WARN"}
        match, computed, expected = verify_status_consistency(receipt)
        assert match

    def test_fail_status(self):
        receipt = {"checks": [{"passed": False, "severity": "critical"}], "status": "FAIL"}
        match, computed, expected = verify_status_consistency(receipt)
        assert match


class TestVerifyHashFormat:
    def test_valid_hashes_legacy(self):
        """Legacy receipts (no spec_version/correlation_id) accept 16-hex hashes."""
        receipt = {
            "receipt_id": "abcdef0123456789",
            "receipt_fingerprint": "0123456789abcdef",
            "context_hash": "fedcba9876543210",
            "output_hash": "1234567890abcdef",
        }
        assert verify_hash_format(receipt) == []

    def test_valid_hashes_v013(self):
        """v0.13.0 receipts: receipt_id=UUID4, fingerprint=16-hex, hashes=64-hex."""
        receipt = {
            "spec_version": "1.0",
            "correlation_id": "sanna-test",
            "receipt_id": "12345678-1234-4123-8123-123456789abc",
            "receipt_fingerprint": "0123456789abcdef",
            "full_fingerprint": "a" * 64,
            "context_hash": "b" * 64,
            "output_hash": "c" * 64,
        }
        assert verify_hash_format(receipt) == []

    def test_invalid_hash_length_legacy(self):
        receipt = {
            "receipt_id": "short",
            "receipt_fingerprint": "0123456789abcdef",
            "context_hash": "fedcba9876543210",
            "output_hash": "1234567890abcdef",
        }
        errors = verify_hash_format(receipt)
        assert len(errors) == 1
        assert "receipt_id" in errors[0]

    def test_invalid_hash_format_v013(self):
        """v0.13.0: receipt_id must be UUID v4."""
        receipt = {
            "spec_version": "1.0",
            "correlation_id": "sanna-test",
            "receipt_id": "not-a-uuid",
            "receipt_fingerprint": "0123456789abcdef",
            "context_hash": "b" * 64,
            "output_hash": "c" * 64,
        }
        errors = verify_hash_format(receipt)
        assert len(errors) >= 1
        assert any("receipt_id" in e for e in errors)


# =============================================================================
# GOLDEN RECEIPT TESTS
# =============================================================================

class TestGoldenReceipts:
    """Verify all golden receipts pass backward-compatible verification.

    Golden receipts use the pre-v0.13.0 format (schema_version,
    status, final_answer_provenance).  They are NOT
    updated for v1.0 — they test legacy backward compatibility.  We verify
    them using the individual verification functions that support both formats
    (fingerprint, content hashes, status consistency, check counts).
    """

    @pytest.mark.parametrize("filename", all_golden_receipts())
    def test_golden_receipt_valid(self, filename):
        receipt = load_golden(filename)
        # Fingerprint verification (legacy path)
        fp_match, fp_computed, fp_expected = verify_fingerprint(receipt)
        assert fp_match, f"{filename}: fingerprint mismatch (computed {fp_computed}, expected {fp_expected})"
        # Content hash verification (auto-detects 16-hex legacy length)
        content_errors = verify_content_hashes(receipt)
        assert content_errors == [], f"{filename}: {content_errors}"
        # Hash format verification (legacy 16-hex path)
        hash_errors = verify_hash_format(receipt)
        assert hash_errors == [], f"{filename}: {hash_errors}"
        # Status consistency
        status_match, _, _ = verify_status_consistency(receipt)
        assert status_match, f"{filename}: status mismatch"
        # Check counts
        count_errors = verify_check_counts(receipt)
        assert count_errors == [], f"{filename}: {count_errors}"

    def test_tampered_receipt_detected(self):
        """Tampered receipt has modified outputs so content hash should mismatch."""
        receipt = load_golden("999_tampered.json")
        content_errors = verify_content_hashes(receipt)
        assert len(content_errors) > 0, "Tampered receipt should have content hash errors"
        assert any("tampered" in e.lower() for e in content_errors)

    def test_golden_receipt_count(self):
        """Ensure we have the expected number of golden receipts."""
        receipts = all_golden_receipts()
        assert len(receipts) >= 12, f"Expected at least 12 golden receipts, got {len(receipts)}"

    @pytest.mark.parametrize("filename,expected_status", [
        ("001_fail_c1_refund.json", "FAIL"),
        ("002_pass_simple_qa.json", "PASS"),
        ("005_warn_c2_unmarked_inference.json", "WARN"),
        ("008_fail_c1_factual.json", "FAIL"),
    ])
    def test_golden_expected_status(self, filename, expected_status):
        receipt = load_golden(filename)
        assert receipt["status"] == expected_status

    def test_golden_fail_c1_has_evidence(self):
        receipt = load_golden("001_fail_c1_refund.json")
        c1 = next(c for c in receipt["checks"] if c["check_id"] == "C1")
        assert not c1["passed"]
        assert c1["evidence"] is not None
        assert len(c1["evidence"]) > 0

    def test_golden_span_provenance(self):
        """Legacy golden receipts have final_answer_provenance (removed in v0.13.0)."""
        receipt = load_golden("011_pass_span_provenance.json")
        prov = receipt["final_answer_provenance"]
        assert prov["source"] == "span.output"
        assert prov["span_name"] is not None

    def test_golden_extensions_preserved(self):
        receipt = load_golden("012_pass_with_extensions.json")
        assert "extensions" in receipt
        assert receipt["extensions"]["vendor"] == "test-vendor"


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_empty_trace(self):
        trace = {
            "correlation_id": "empty",
            "name": "empty",
            "timestamp": None,
            "input": None,
            "output": None,
            "metadata": None,
            "observations": [],
        }
        receipt = generate_receipt(trace)
        assert receipt.status == "PASS"
        assert receipt.checks_passed == 5

    def test_unicode_content(self):
        trace = {
            "correlation_id": "unicode-test",
            "name": "unicode",
            "timestamp": None,
            "input": None,
            "output": {"final_answer": "Ünïcödé résponse with émojis 🎉"},
            "metadata": None,
            "observations": [
                {
                    "id": "obs-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "unicode test"},
                    "output": {"context": "Cöntéxt with spëcial chàracters"},
                    "metadata": {},
                }
            ],
        }
        receipt = generate_receipt(trace)
        d = asdict(receipt)
        # Should be valid JSON
        json_str = json.dumps(d)
        reparsed = json.loads(json_str)
        assert reparsed["outputs"]["response"] == "Ünïcödé résponse with émojis 🎉"

    def test_very_long_content(self):
        long_context = "x" * 100000
        long_output = "y" * 100000
        trace = {
            "correlation_id": "long-test",
            "name": "long",
            "timestamp": None,
            "input": None,
            "output": {"final_answer": long_output},
            "metadata": None,
            "observations": [
                {
                    "id": "obs-ret",
                    "name": "retrieval",
                    "type": "SPAN",
                    "input": {"query": "long"},
                    "output": {"context": long_context},
                    "metadata": {},
                }
            ],
        }
        receipt = generate_receipt(trace)
        assert receipt.context_hash is not None
        assert len(receipt.context_hash) == 64
