"""Tests for @sanna_observe redaction_config parameter (SAN-249).

Covers spec section 2.11.1 marker application through the middleware path:
  1. No config -- receipt has raw strings, no markers
  2. Enabled config -- both configured fields become marker dicts
  3. Signed + redacted receipt verifies
  4. content_mode='redacted' when config.enabled=True (state matches metadata)
  5. arguments-only redaction
  6. result_text-only redaction
  7. FIX-12 pre-existing marker injection guard via middleware
  8. Disabled config is a no-op
"""

import hashlib
import json
import logging
from pathlib import Path

import pytest

from sanna.middleware import sanna_observe, SannaResult
from sanna.redaction import RedactionConfig, apply_redaction


CONTEXT_TEXT = "Patient Jane Doe, SSN 987-65-4321, DOB 1985-03-22"
QUERY_TEXT = "Summarise the patient record"
RESPONSE_TEXT = "Jane Doe presents with stable vitals. BP 120/80."


# =============================================================================
# Helpers
# =============================================================================

def _make_agent(redaction_config=None, private_key_path=None):
    """Create a @sanna_observe-wrapped agent with optional redaction + signing."""
    kwargs = {}
    if redaction_config is not None:
        kwargs["redaction_config"] = redaction_config
    if private_key_path is not None:
        kwargs["private_key_path"] = private_key_path

    @sanna_observe(**kwargs)
    def agent(query: str, context: str) -> str:
        return RESPONSE_TEXT

    return agent


def _call_agent(agent):
    result = agent(query=QUERY_TEXT, context=CONTEXT_TEXT)
    assert isinstance(result, SannaResult)
    return result.receipt


# =============================================================================
# 1. No redaction_config -- raw strings preserved
# =============================================================================

class TestMiddlewareNoConfig:
    """Without redaction_config, receipt fields remain raw strings."""

    def test_middleware_emits_full_without_config(self):
        agent = _make_agent()
        receipt = _call_agent(agent)

        ctx = (receipt.get("inputs") or {}).get("context")
        resp = (receipt.get("outputs") or {}).get("response")

        assert isinstance(ctx, str), "inputs.context should be a plain string without redaction"
        assert isinstance(resp, str), "outputs.response should be a plain string without redaction"
        assert "redacted_fields" not in receipt
        assert receipt.get("content_mode") != "redacted"


# =============================================================================
# 2. Enabled config -- both fields become marker dicts
# =============================================================================

class TestMiddlewareEnabledConfig:
    """With enabled config, configured fields are replaced with spec section 2.11.1 markers."""

    def test_middleware_emits_redacted_with_config(self):
        agent = _make_agent(redaction_config=RedactionConfig(
            enabled=True, fields=["arguments", "result_text"],
        ))
        receipt = _call_agent(agent)

        ctx = (receipt.get("inputs") or {}).get("context")
        resp = (receipt.get("outputs") or {}).get("response")

        assert isinstance(ctx, dict), "inputs.context should be a marker dict"
        assert ctx.get("__redacted__") is True
        assert len(ctx.get("original_hash", "")) == 64

        assert isinstance(resp, dict), "outputs.response should be a marker dict"
        assert resp.get("__redacted__") is True
        assert len(resp.get("original_hash", "")) == 64

        assert receipt.get("content_mode") == "redacted"
        assert receipt.get("content_mode_source") == "middleware_redaction_config"
        assert "inputs.context" in receipt.get("redacted_fields", [])
        assert "outputs.response" in receipt.get("redacted_fields", [])

    def test_marker_original_hash_matches_input(self):
        """original_hash in the marker is the SHA-256 of the NFC-normalised input."""
        agent = _make_agent(redaction_config=RedactionConfig(
            enabled=True, fields=["arguments"],
        ))
        receipt = _call_agent(agent)

        ctx = receipt["inputs"]["context"]
        import unicodedata
        expected = hashlib.sha256(
            unicodedata.normalize("NFC", CONTEXT_TEXT).encode("utf-8")
        ).hexdigest()
        assert ctx["original_hash"] == expected


# =============================================================================
# 3. Signed + redacted receipt verifies
# =============================================================================

class TestMiddlewareRedactedSignatureVerifies:
    """A signed middleware-redacted receipt passes verify_receipt."""

    def test_middleware_redacted_signature_verifies(self, tmp_path):
        from sanna.crypto import generate_keypair
        from sanna.verify import verify_receipt, load_schema

        keys_dir = tmp_path / "keys"
        private_key_path, public_key_path = generate_keypair(str(keys_dir))

        agent = _make_agent(
            redaction_config=RedactionConfig(enabled=True, fields=["arguments", "result_text"]),
            private_key_path=str(private_key_path),
        )
        receipt = _call_agent(agent)

        schema = load_schema()
        result = verify_receipt(receipt, schema, public_key_path=str(public_key_path))
        assert result.valid, f"Signed redacted receipt should verify: {result.errors}"
        assert result.exit_code == 0


# =============================================================================
# 4. content_mode matches redaction state
# =============================================================================

class TestMiddlewareContentModeMatchesState:
    """content_mode is 'redacted' iff redaction_config.enabled is True."""

    def test_content_mode_is_redacted_when_enabled(self):
        agent = _make_agent(redaction_config=RedactionConfig(enabled=True))
        receipt = _call_agent(agent)
        assert receipt.get("content_mode") == "redacted"

    def test_content_mode_not_forced_when_disabled(self):
        agent = _make_agent(redaction_config=RedactionConfig(enabled=False))
        receipt = _call_agent(agent)
        assert receipt.get("content_mode") != "redacted"

    def test_content_mode_not_set_without_config(self):
        agent = _make_agent()
        receipt = _call_agent(agent)
        assert receipt.get("content_mode") != "redacted"


# =============================================================================
# 5. arguments-only redaction
# =============================================================================

class TestMiddlewareArgumentsOnlyRedaction:
    """fields=['arguments'] redacts inputs.context, leaves outputs.response raw."""

    def test_middleware_arguments_only_redaction(self):
        agent = _make_agent(redaction_config=RedactionConfig(
            enabled=True, fields=["arguments"],
        ))
        receipt = _call_agent(agent)

        ctx = (receipt.get("inputs") or {}).get("context")
        resp = (receipt.get("outputs") or {}).get("response")

        assert isinstance(ctx, dict) and ctx.get("__redacted__") is True
        assert resp is None or isinstance(resp, str), (
            "outputs.response should remain a raw string"
        )
        assert "inputs.context" in receipt.get("redacted_fields", [])
        assert "outputs.response" not in receipt.get("redacted_fields", [])


# =============================================================================
# 6. result_text-only redaction
# =============================================================================

class TestMiddlewareResultTextOnlyRedaction:
    """fields=['result_text'] redacts outputs.response, leaves inputs.context raw."""

    def test_middleware_result_text_only_redaction(self):
        agent = _make_agent(redaction_config=RedactionConfig(
            enabled=True, fields=["result_text"],
        ))
        receipt = _call_agent(agent)

        ctx = (receipt.get("inputs") or {}).get("context")
        resp = (receipt.get("outputs") or {}).get("response")

        assert ctx is None or isinstance(ctx, str), (
            "inputs.context should remain a raw string"
        )
        assert isinstance(resp, dict) and resp.get("__redacted__") is True
        assert "outputs.response" in receipt.get("redacted_fields", [])
        assert "inputs.context" not in receipt.get("redacted_fields", [])


# =============================================================================
# 7. FIX-12 pre-existing marker injection guard
# =============================================================================

class TestMiddlewarePreexistingMarkerInjectionGuard:
    """FIX-12: a pre-existing marker dict in context is re-redacted, not passed through."""

    def test_middleware_preexisting_marker_injection_guard(self, caplog):
        """A fake marker already in inputs.context is caught and double-hashed."""
        from sanna.redaction import _apply_redaction_markers

        fake_marker = {"__redacted__": True, "original_hash": "a" * 64}
        fake_receipt = {
            "inputs": {"context": fake_marker, "query": "q"},
            "outputs": {"response": "some response"},
            "checks": [],
            "checks_version": "10",
            "correlation_id": "test-corr",
            "constitution_ref": None,
        }

        with caplog.at_level(logging.WARNING, logger="sanna.redaction"):
            result_receipt, redacted_paths = _apply_redaction_markers(
                fake_receipt, ["arguments"]
            )

        assert "re-redacting to prevent marker injection" in caplog.text.lower() or \
               "pre-existing redaction marker" in caplog.text.lower()

        resulting_ctx = result_receipt["inputs"]["context"]
        assert isinstance(resulting_ctx, dict)
        assert resulting_ctx.get("__redacted__") is True

        expected_json = json.dumps(fake_marker, sort_keys=True)
        import unicodedata
        expected_hash = hashlib.sha256(
            unicodedata.normalize("NFC", expected_json).encode("utf-8")
        ).hexdigest()
        assert resulting_ctx["original_hash"] == expected_hash
        assert "inputs.context" in redacted_paths


# =============================================================================
# 8. Disabled config is a no-op
# =============================================================================

class TestMiddlewareDisabledConfigNoOp:
    """RedactionConfig(enabled=False) leaves the receipt unchanged."""

    def test_middleware_disabled_config_no_op(self):
        agent = _make_agent(redaction_config=RedactionConfig(enabled=False))
        receipt = _call_agent(agent)

        ctx = (receipt.get("inputs") or {}).get("context")
        resp = (receipt.get("outputs") or {}).get("response")

        assert isinstance(ctx, str) or ctx is None
        assert isinstance(resp, str) or resp is None
        assert "redacted_fields" not in receipt
        assert receipt.get("content_mode") != "redacted"
