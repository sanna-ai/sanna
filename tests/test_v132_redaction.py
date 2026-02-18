"""Tests for v0.13.2 Prompt 7: Redaction + Verification Hardening.

Covers:
- FIX-12: Redaction marker injection (pre-existing __redacted__ dicts are re-redacted)
- FIX-45: NFC normalization for redacted hashes
- FIX-4: verify_receipt_signature docstring (verified by code inspection, not runtime)
"""

from __future__ import annotations

import hashlib
import json
import unicodedata

import pytest

mcp = pytest.importorskip("mcp")

from sanna.gateway.server import (
    _apply_redaction_markers,
    _make_redaction_marker,
    _redact_for_storage,
)


# ---------------------------------------------------------------------------
# FIX-12: Redaction Marker Injection
# ---------------------------------------------------------------------------


class TestRedactionMarkerInjection:

    def test_pre_existing_marker_re_redacted(self):
        """Pre-existing __redacted__ dict is treated as content and re-redacted."""
        # Attacker pre-populates a fake redaction marker in the input
        fake_marker = {"__redacted__": True, "original_hash": "fake_hash"}
        receipt = {
            "receipt_id": "injection-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": fake_marker},
            "outputs": {"response": "clean output"},
        }

        _apply_redaction_markers(receipt, ["arguments"])

        ctx = receipt["inputs"]["context"]
        # The result must be a proper redaction marker (re-redacted)
        assert isinstance(ctx, dict)
        assert ctx["__redacted__"] is True

        # The original_hash must NOT be the attacker's fake hash.
        # It should be the SHA-256 of the JSON-serialized fake marker dict.
        serialized = json.dumps(fake_marker, sort_keys=True)
        expected_hash = hashlib.sha256(
            unicodedata.normalize("NFC", serialized).encode("utf-8")
        ).hexdigest()
        assert ctx["original_hash"] == expected_hash
        assert ctx["original_hash"] != "fake_hash"

    def test_pre_existing_marker_in_response_re_redacted(self):
        """Pre-existing __redacted__ dict in outputs.response is also caught."""
        fake_marker = {"__redacted__": True, "original_hash": "injected_hash_123"}
        receipt = {
            "receipt_id": "injection-test-002",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "clean input"},
            "outputs": {"response": fake_marker},
        }

        _apply_redaction_markers(receipt, ["result_text"])

        resp = receipt["outputs"]["response"]
        assert isinstance(resp, dict)
        assert resp["__redacted__"] is True
        assert resp["original_hash"] != "injected_hash_123"

        # Verify the hash is computed from the serialized fake marker
        serialized = json.dumps(fake_marker, sort_keys=True)
        expected_hash = hashlib.sha256(
            unicodedata.normalize("NFC", serialized).encode("utf-8")
        ).hexdigest()
        assert resp["original_hash"] == expected_hash

    def test_normal_string_redacted_normally(self):
        """Normal strings are redacted without issue."""
        receipt = {
            "receipt_id": "normal-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "Patient SSN 123-45-6789"},
            "outputs": {"response": "Treatment plan details"},
        }

        _apply_redaction_markers(receipt, ["arguments", "result_text"])

        ctx = receipt["inputs"]["context"]
        assert isinstance(ctx, dict)
        assert ctx["__redacted__"] is True
        expected_hash = hashlib.sha256(
            "Patient SSN 123-45-6789".encode("utf-8")
        ).hexdigest()
        assert ctx["original_hash"] == expected_hash

        resp = receipt["outputs"]["response"]
        assert isinstance(resp, dict)
        assert resp["__redacted__"] is True
        expected_hash = hashlib.sha256(
            "Treatment plan details".encode("utf-8")
        ).hexdigest()
        assert resp["original_hash"] == expected_hash

    def test_pre_existing_marker_logs_warning(self, caplog):
        """A warning is logged when a pre-existing marker is detected."""
        import logging

        fake_marker = {"__redacted__": True, "original_hash": "fake"}
        receipt = {
            "receipt_id": "warn-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": fake_marker},
            "outputs": {"response": "ok"},
        }

        with caplog.at_level(logging.WARNING, logger="sanna.gateway.server"):
            _apply_redaction_markers(receipt, ["arguments"])

        assert any(
            "Pre-existing redaction marker" in r.message
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# FIX-45: NFC Normalization for Redacted Hashes
# ---------------------------------------------------------------------------


class TestNFCNormalization:

    def test_nfc_equivalent_strings_produce_same_hash(self):
        """NFC-equivalent Unicode strings produce identical redaction hashes."""
        # U+00E9 (precomposed e-acute) vs U+0065 U+0301 (e + combining acute)
        precomposed = "\u00e9"  # e-acute (NFC form)
        decomposed = "e\u0301"  # e + combining acute (NFD form)

        # Sanity: these look the same but are different byte sequences
        assert precomposed != decomposed
        assert unicodedata.normalize("NFC", precomposed) == unicodedata.normalize("NFC", decomposed)

        # _redact_for_storage should produce the same hash for both
        r1 = _redact_for_storage(precomposed, "hash_only", salt="s1")
        r2 = _redact_for_storage(decomposed, "hash_only", salt="s1")
        assert r1 == r2

    def test_nfc_normalization_in_redaction_markers(self):
        """NFC-equivalent strings produce identical redaction marker hashes."""
        precomposed = "caf\u00e9"  # cafe with precomposed e-acute
        decomposed = "cafe\u0301"  # cafe with e + combining acute

        assert precomposed != decomposed

        marker1 = _make_redaction_marker(precomposed)
        marker2 = _make_redaction_marker(decomposed)

        assert marker1["original_hash"] == marker2["original_hash"]

    def test_nfc_normalization_with_hmac(self):
        """NFC-equivalent strings produce same HMAC-SHA256 redaction hash."""
        precomposed = "\u00f1"  # n-tilde precomposed
        decomposed = "n\u0303"  # n + combining tilde

        assert precomposed != decomposed

        r1 = _redact_for_storage(precomposed, "hash_only", salt="", secret=b"key")
        r2 = _redact_for_storage(decomposed, "hash_only", salt="", secret=b"key")
        assert r1 == r2

    def test_ascii_strings_unaffected_by_nfc(self):
        """Pure ASCII strings produce identical results with or without NFC."""
        content = "hello world 123"
        result = _redact_for_storage(content, "hash_only", salt="test")
        # NFC of ASCII is identity, so this should just work
        expected_payload = (content + "test").encode()
        expected_digest = hashlib.sha256(expected_payload).hexdigest()
        assert expected_digest in result
