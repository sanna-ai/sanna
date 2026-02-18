"""Tests for Block 2: Cryptographic Integrity fixes.

Covers:
- Float/string hash collision elimination
- Redaction dual-file model (original signed + separate redacted view)
- Salted PII redaction hashes
- Redaction config warnings
"""

from __future__ import annotations

import hashlib
import json
import logging
import os

import pytest

from sanna.hashing import hash_obj, canonical_json_bytes


# ---------------------------------------------------------------------------
# Float/string hash collision (Gemini #2)
# ---------------------------------------------------------------------------


class TestFloatStringHashCollision:

    def test_float_and_string_produce_different_hashes(self):
        """Critical: {"val": 1.0} and {"val": "1.0"} must hash differently."""
        assert hash_obj({"val": 1.0}) != hash_obj({"val": "1.0"})

    def test_float_and_fixed_string_produce_different_hashes(self):
        """The specific pre-v0.12.2 collision: 1.0 vs "1.0000000000"."""
        assert hash_obj({"val": 1.0}) != hash_obj({"val": "1.0000000000"})

    def test_float_canonicalization_deterministic(self):
        """Same float always produces the same hash."""
        h1 = hash_obj({"score": 0.85})
        h2 = hash_obj({"score": 0.85})
        assert h1 == h2

    def test_float_type_preserved_in_canonical_json(self):
        """Canonical JSON contains a JSON number, not a quoted string."""
        result = canonical_json_bytes({"rate": 1.5})
        assert b'"rate":1.5' in result
        assert b'"rate":"1.5"' not in result

    def test_integer_and_float_produce_different_hashes(self):
        """int 1 and float 1.0 produce different canonical JSON."""
        assert canonical_json_bytes({"val": 1}) != canonical_json_bytes({"val": 1.0})


# ---------------------------------------------------------------------------
# Redaction dual-file model (GPT #2)
# ---------------------------------------------------------------------------


class TestRedactionDualFile:

    def test_redacted_receipt_separate_from_signed(self, tmp_path):
        """Redaction enabled → only redacted file persisted (no original)."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway
        from sanna.gateway.config import RedactionConfig

        receipt = {
            "receipt_id": "dual-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "Patient SSN 123-45-6789"},
            "outputs": {"response": "Prescribed medication"},
        }

        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")
        gw._gateway_secret = b"test-secret"
        gw._redaction_config = RedactionConfig(
            enabled=True,
            mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw._persist_receipt(receipt)

        receipt_dir = tmp_path / "receipts"
        all_files = list(receipt_dir.glob("*.json"))
        originals = [f for f in all_files if ".redacted." not in f.name]
        redacted = list(receipt_dir.glob("*.redacted.json"))

        # CRIT-03: only redacted file persisted, no original on disk
        assert len(originals) == 0, f"Expected 0 originals, got {originals}"
        assert len(redacted) == 1, f"Expected 1 redacted, got {redacted}"

    def test_original_receipt_not_persisted_when_redaction_enabled(self, tmp_path):
        """No original file on disk when redaction is enabled (CRIT-03)."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway
        from sanna.gateway.config import RedactionConfig

        receipt = {
            "receipt_id": "orig-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "Patient SSN 123-45-6789"},
            "outputs": {"response": "Prescribed medication"},
        }

        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")
        gw._gateway_secret = b"test-secret"
        gw._redaction_config = RedactionConfig(
            enabled=True,
            mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw._persist_receipt(receipt)

        receipt_dir = tmp_path / "receipts"
        originals = [
            f for f in receipt_dir.glob("*.json")
            if ".redacted." not in f.name
        ]
        # Only redacted file exists — no original on disk
        assert len(originals) == 0
        redacted = list(receipt_dir.glob("*.redacted.json"))
        assert len(redacted) == 1
        content = json.loads(redacted[0].read_text())
        assert "REDACTED" in content["inputs"]["context"]

    def test_redacted_view_contains_redaction_notice(self, tmp_path):
        """The .redacted.json file has the _redaction_notice field."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway
        from sanna.gateway.config import RedactionConfig

        receipt = {
            "receipt_id": "notice-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "Secret info"},
            "outputs": {"response": "Secret output"},
        }

        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")
        gw._gateway_secret = b"test-secret"
        gw._redaction_config = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw._persist_receipt(receipt)

        redacted_files = list(
            (tmp_path / "receipts").glob("*.redacted.json"),
        )
        content = json.loads(redacted_files[0].read_text())
        assert "_redaction_notice" in content
        assert "original receipt" in content["_redaction_notice"].lower()

    def test_redacted_view_has_redacted_content(self, tmp_path):
        """Sensitive fields are replaced in the redacted view."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway
        from sanna.gateway.config import RedactionConfig

        receipt = {
            "receipt_id": "redact-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "Patient SSN 123-45-6789"},
            "outputs": {"response": "Prescribed medication"},
        }

        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")
        gw._gateway_secret = b"test-secret"
        gw._redaction_config = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw._persist_receipt(receipt)

        redacted_files = list(
            (tmp_path / "receipts").glob("*.redacted.json"),
        )
        content = json.loads(redacted_files[0].read_text())
        assert "123-45-6789" not in content["inputs"]["context"]
        assert "REDACTED" in content["inputs"]["context"]
        assert "Prescribed" not in content["outputs"]["response"]
        assert "REDACTED" in content["outputs"]["response"]

    def test_no_redacted_file_when_disabled(self, tmp_path):
        """No .redacted.json when redaction is disabled."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway
        from sanna.gateway.config import RedactionConfig

        receipt = {
            "receipt_id": "disabled-test-001",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "data"},
            "outputs": {"response": "result"},
        }

        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")
        gw._gateway_secret = b"test-secret"
        gw._redaction_config = RedactionConfig(enabled=False)

        gw._persist_receipt(receipt)

        redacted_files = list(
            (tmp_path / "receipts").glob("*.redacted.json"),
        )
        assert len(redacted_files) == 0


# ---------------------------------------------------------------------------
# Salted PII redaction hashes (Gemini #5)
# ---------------------------------------------------------------------------


class TestSaltedRedactionHashes:

    def test_redaction_hash_is_salted(self):
        """Same content with different salts produces different hashes."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import _redact_for_storage

        content = "sensitive data"
        r1 = _redact_for_storage(content, "hash_only", salt="receipt-001")
        r2 = _redact_for_storage(content, "hash_only", salt="receipt-002")
        assert r1 != r2

    def test_redaction_hash_deterministic_with_same_salt(self):
        """Same content + same salt = same redacted output."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import _redact_for_storage

        content = "sensitive data"
        r1 = _redact_for_storage(content, "hash_only", salt="same-id")
        r2 = _redact_for_storage(content, "hash_only", salt="same-id")
        assert r1 == r2

    def test_redaction_output_contains_salted_marker(self):
        """Redacted output uses SHA-256-SALTED label."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import _redact_for_storage

        result = _redact_for_storage("data", "hash_only", salt="id1")
        assert "SHA-256-SALTED" in result


# ---------------------------------------------------------------------------
# Redaction config warning (GPT #11)
# ---------------------------------------------------------------------------


class TestRedactionConfigWarning:

    def test_redaction_warning_logged(self, tmp_path, caplog):
        """Enabling redaction produces a WARNING log."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig

        redaction_config = RedactionConfig(enabled=True)

        with caplog.at_level(logging.INFO):
            from sanna.gateway.server import SannaGateway

            # Construct with minimal valid params
            try:
                gw = SannaGateway(
                    server_name="test",
                    command="echo",
                    redaction_config=redaction_config,
                    gateway_secret_path=str(
                        tmp_path / "gateway_secret",
                    ),
                )
            except Exception:
                pass  # May fail for other reasons; info still logged

        assert any(
            "Redaction enabled" in r.message
            for r in caplog.records
        )
