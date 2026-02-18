"""Tests for SEC-1: Redacted Receipt Verification.

Covers the fix where redaction markers are applied BEFORE signing so that
the receipt signature, content hashes, and fingerprint all cover the
markers (not the original PII).  The verifier recognizes markers and
confirms content integrity via the embedded original_hash.

Test plan:
  1. Receipt with redacted field verifies successfully
  2. Receipt with redacted field AND tampered original_hash fails verification
  3. Receipt with redacted field AND tampered status fails signature verification
  4. Receipt without redaction still verifies normally (backward compat)
  5. Redaction markers are deterministic — same input produces same marker
  6. Verifier output notes which fields are redacted
  7. Multiple redacted fields all verify correctly
"""

import hashlib
import json
from pathlib import Path

import pytest


# =============================================================================
# Helpers
# =============================================================================

def _create_signed_constitution(tmp_path):
    """Create a signed constitution and keypair. Returns (const_path, key_path, pub_key_path)."""
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution,
        AgentIdentity,
        Provenance,
        Boundary,
        Invariant,
        sign_constitution,
        save_constitution,
    )

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    constitution = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@example.com",
            approved_by=["approver@example.com"],
            approval_date="2024-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope",
                     severity="high"),
        ],
        invariants=[
            Invariant(id="INV_NO_FABRICATION", rule="No fabricated claims",
                      enforcement="warn"),
        ],
    )
    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)
    return str(const_path), str(private_key_path), str(public_key_path)


def _generate_gateway_receipt(
    gw,
    arguments=None,
    result_text="The patient status is stable",
):
    """Generate a gateway receipt using the gateway's _generate_receipt method."""
    from sanna.enforcement import AuthorityDecision
    from datetime import datetime, timezone

    if arguments is None:
        arguments = {"search_query": "Patient John Doe, SSN 123-45-6789"}

    decision = AuthorityDecision(
        decision="allow",
        reason="Allowed by policy",
        boundary_type="can_execute",
        escalation_target=None,
    )
    authority_decisions = [{
        "action": "test_tool",
        "params": arguments,
        "decision": "allow",
        "reason": "Allowed by policy",
        "boundary_type": "can_execute",
        "escalation_target": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }]

    receipt = gw._generate_receipt(
        prefixed_name="mock_test_tool",
        original_name="test_tool",
        arguments=arguments,
        result_text=result_text,
        decision=decision,
        authority_decisions=authority_decisions,
    )
    return receipt


# =============================================================================
# 1. Receipt with redacted field verifies successfully
# =============================================================================

class TestRedactedReceiptVerifies:
    """Redacted receipt passes full verification including fingerprint and content hashes."""

    def test_redacted_receipt_verifies_successfully(self, tmp_path):
        """A receipt generated with redaction enabled passes verify_receipt()."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        schema = load_schema()

        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert result.valid, f"Redacted receipt should verify: {result.errors}"
        assert result.exit_code == 0

    def test_redacted_receipt_persisted_verifies(self, tmp_path):
        """A persisted redacted receipt (loaded from disk) passes verify_receipt()."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        gw._persist_receipt(receipt)

        # Load from disk
        files = list(store_dir.glob("*.redacted.json"))
        assert len(files) == 1
        loaded = json.loads(files[0].read_text())

        schema = load_schema()
        result = verify_receipt(loaded, schema, public_key_path=pub_key_path)
        assert result.valid, f"Persisted redacted receipt should verify: {result.errors}"


# =============================================================================
# 2. Tampered original_hash fails verification
# =============================================================================

class TestTamperedOriginalHash:
    """Tampering with the original_hash in a redaction marker breaks verification."""

    def test_tampered_original_hash_fails_content_hash(self, tmp_path):
        """Modifying original_hash in a marker causes context_hash mismatch."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_content_hashes

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)

        # Tamper with the marker
        marker = receipt["inputs"]["context"]
        assert isinstance(marker, dict) and marker.get("__redacted__") is True
        receipt["inputs"]["context"]["original_hash"] = "a" * 64

        errors, _warnings = verify_content_hashes(receipt)
        assert len(errors) > 0
        assert any("context_hash mismatch" in e for e in errors)

    def test_tampered_original_hash_fails_fingerprint(self, tmp_path):
        """Modifying original_hash also causes fingerprint mismatch (full verify)."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        receipt["inputs"]["context"]["original_hash"] = "b" * 64

        schema = load_schema()
        result = verify_receipt(receipt, schema)
        assert not result.valid
        assert any("context_hash mismatch" in e for e in result.errors)


# =============================================================================
# 3. Tampered status fails signature verification
# =============================================================================

class TestTamperedStatusFailsSignature:
    """Tampering with receipt status after signing fails signature verification."""

    def test_tampered_status_fails_signature(self, tmp_path):
        """Modifying status on a signed redacted receipt fails signature check."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)

        # Tamper with status after signing
        original_status = receipt["status"]
        receipt["status"] = "FAIL" if original_status != "FAIL" else "PASS"

        schema = load_schema()
        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert not result.valid
        # Should fail on either status mismatch or signature
        assert result.errors


# =============================================================================
# 4. Receipt without redaction still verifies normally (backward compat)
# =============================================================================

class TestBackwardCompatibility:
    """Non-redacted receipts continue to verify normally."""

    def test_non_redacted_receipt_verifies(self, tmp_path):
        """A receipt generated without redaction passes verify_receipt()."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(enabled=False)

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        schema = load_schema()

        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert result.valid, f"Non-redacted receipt should verify: {result.errors}"

    def test_non_redacted_has_string_fields(self, tmp_path):
        """Without redaction, inputs.context and outputs.response remain strings."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(enabled=False)

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        context = receipt.get("inputs", {}).get("context")
        response = receipt.get("outputs", {}).get("response")

        # Fields should be plain strings, not marker dicts
        assert context is None or isinstance(context, str)
        assert response is None or isinstance(response, str)
        assert "redacted_fields" not in receipt

    def test_no_redaction_warnings_for_normal_receipt(self, tmp_path):
        """verify_content_hashes returns no redaction warnings for normal receipts."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_content_hashes

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(enabled=False)

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        errors, warnings = verify_content_hashes(receipt)
        assert len(errors) == 0
        assert len(warnings) == 0


# =============================================================================
# 5. Redaction markers are deterministic
# =============================================================================

class TestRedactionMarkerDeterminism:
    """Same input produces the same redaction marker."""

    def test_same_input_same_marker(self):
        """_make_redaction_marker is deterministic for the same input."""
        pytest.importorskip("mcp")
        from sanna.gateway.server import _make_redaction_marker

        content = "Patient John Doe, SSN 123-45-6789"
        marker1 = _make_redaction_marker(content)
        marker2 = _make_redaction_marker(content)

        assert marker1 == marker2
        assert marker1["__redacted__"] is True
        assert marker1["original_hash"] == hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()

    def test_different_input_different_marker(self):
        """Different inputs produce different markers."""
        pytest.importorskip("mcp")
        from sanna.gateway.server import _make_redaction_marker

        marker1 = _make_redaction_marker("Patient A")
        marker2 = _make_redaction_marker("Patient B")

        assert marker1 != marker2
        assert marker1["original_hash"] != marker2["original_hash"]

    def test_marker_format(self):
        """Marker has exactly the required fields."""
        pytest.importorskip("mcp")
        from sanna.gateway.server import _make_redaction_marker

        marker = _make_redaction_marker("test content")
        assert set(marker.keys()) == {"__redacted__", "original_hash"}
        assert marker["__redacted__"] is True
        assert len(marker["original_hash"]) == 64

    def test_generate_twice_same_redaction(self, tmp_path):
        """Two receipts from the same input produce the same redaction marker content."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path, _ = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        args = {"search_query": "Patient John Doe"}
        receipt1 = _generate_gateway_receipt(gw, arguments=args)
        receipt2 = _generate_gateway_receipt(gw, arguments=args)

        # Markers should be identical (same content)
        marker1 = receipt1["inputs"]["context"]
        marker2 = receipt2["inputs"]["context"]
        assert marker1 == marker2


# =============================================================================
# 6. Verifier output notes which fields are redacted
# =============================================================================

class TestVerifierNotesRedaction:
    """The verifier notes redacted fields in warnings."""

    def test_verifier_warns_about_redacted_fields(self, tmp_path):
        """verify_receipt includes warnings for redacted fields."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        schema = load_schema()

        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert result.valid

        # Should have warnings noting redacted fields
        redaction_warnings = [
            w for w in result.warnings if "redacted" in w.lower()
        ]
        assert len(redaction_warnings) > 0, (
            f"Expected redaction warnings, got: {result.warnings}"
        )

    def test_verify_content_hashes_returns_redaction_warnings(self, tmp_path):
        """verify_content_hashes returns warnings for redacted fields."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_content_hashes

        const_path, key_path, _ = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        errors, warnings = verify_content_hashes(receipt)

        assert len(errors) == 0
        assert any("inputs.context" in w for w in warnings)
        assert any("outputs.response" in w for w in warnings)


# =============================================================================
# 7. Multiple redacted fields all verify correctly
# =============================================================================

class TestMultipleRedactedFields:
    """Receipts with multiple redacted fields verify correctly."""

    def test_both_arguments_and_result_redacted(self, tmp_path):
        """Both inputs.context and outputs.response redacted — still verifies."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        schema = load_schema()

        # Both fields should be markers
        assert isinstance(receipt["inputs"]["context"], dict)
        assert receipt["inputs"]["context"]["__redacted__"] is True
        assert isinstance(receipt["outputs"]["response"], dict)
        assert receipt["outputs"]["response"]["__redacted__"] is True

        # Redacted_fields metadata should list both
        assert "inputs.context" in receipt.get("redacted_fields", [])
        assert "outputs.response" in receipt.get("redacted_fields", [])

        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert result.valid, f"Multi-redacted receipt should verify: {result.errors}"

    def test_only_arguments_redacted(self, tmp_path):
        """Only inputs.context redacted — outputs.response remains a string."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments"],  # Only arguments, NOT result_text
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        schema = load_schema()

        # Only context should be a marker
        assert isinstance(receipt["inputs"]["context"], dict)
        assert receipt["inputs"]["context"]["__redacted__"] is True

        # Response should remain a string
        response = receipt["outputs"]["response"]
        assert response is None or isinstance(response, str)

        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert result.valid, f"Partially redacted receipt should verify: {result.errors}"

    def test_only_result_text_redacted(self, tmp_path):
        """Only outputs.response redacted — inputs.context remains a string."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec
        from sanna.verify import verify_receipt, load_schema

        const_path, key_path, pub_key_path = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["result_text"],  # Only result_text, NOT arguments
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        schema = load_schema()

        # Context should remain a string
        context = receipt["inputs"]["context"]
        assert context is None or isinstance(context, str)

        # Response should be a marker
        assert isinstance(receipt["outputs"]["response"], dict)
        assert receipt["outputs"]["response"]["__redacted__"] is True

        result = verify_receipt(receipt, schema, public_key_path=pub_key_path)
        assert result.valid, f"Result-only redacted receipt should verify: {result.errors}"

    def test_redacted_fields_metadata_present(self, tmp_path):
        """The redacted_fields list accurately describes which fields were redacted."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path, _ = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        receipt = _generate_gateway_receipt(gw)
        assert "redacted_fields" in receipt
        assert isinstance(receipt["redacted_fields"], list)
        assert "inputs.context" in receipt["redacted_fields"]
        assert "outputs.response" in receipt["redacted_fields"]


# =============================================================================
# Marker detection in verify.py
# =============================================================================

class TestMarkerDetection:
    """Redaction marker detection helpers in verify.py."""

    def test_is_redaction_marker_valid(self):
        """_is_redaction_marker returns True for well-formed markers."""
        from sanna.verify import _is_redaction_marker

        marker = {"__redacted__": True, "original_hash": "a" * 64}
        assert _is_redaction_marker(marker) is True

    def test_is_redaction_marker_missing_flag(self):
        """_is_redaction_marker returns False when __redacted__ is missing."""
        from sanna.verify import _is_redaction_marker

        assert _is_redaction_marker({"original_hash": "a" * 64}) is False

    def test_is_redaction_marker_false_flag(self):
        """_is_redaction_marker returns False when __redacted__ is False."""
        from sanna.verify import _is_redaction_marker

        marker = {"__redacted__": False, "original_hash": "a" * 64}
        assert _is_redaction_marker(marker) is False

    def test_is_redaction_marker_bad_hash(self):
        """_is_redaction_marker returns False for invalid original_hash."""
        from sanna.verify import _is_redaction_marker

        assert _is_redaction_marker({"__redacted__": True, "original_hash": "short"}) is False
        assert _is_redaction_marker({"__redacted__": True, "original_hash": "g" * 64}) is False

    def test_is_redaction_marker_string(self):
        """_is_redaction_marker returns False for plain strings."""
        from sanna.verify import _is_redaction_marker

        assert _is_redaction_marker("some string") is False
        assert _is_redaction_marker(None) is False
        assert _is_redaction_marker(42) is False

    def test_collect_redacted_fields(self):
        """_collect_redacted_fields finds markers in inputs and outputs."""
        from sanna.verify import _collect_redacted_fields

        marker = {"__redacted__": True, "original_hash": "a" * 64}
        inputs = {"query": "test", "context": marker}
        outputs = {"response": marker}

        paths = _collect_redacted_fields(inputs, outputs)
        assert "inputs.context" in paths
        assert "outputs.response" in paths

    def test_collect_redacted_fields_no_markers(self):
        """_collect_redacted_fields returns empty for normal fields."""
        from sanna.verify import _collect_redacted_fields

        inputs = {"query": "test", "context": "some context"}
        outputs = {"response": "some response"}

        paths = _collect_redacted_fields(inputs, outputs)
        assert len(paths) == 0


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases:
    """Edge cases for redaction markers."""

    def test_empty_context_not_redacted(self, tmp_path):
        """Empty/None context values are not replaced with markers."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path, _ = _create_signed_constitution(tmp_path)

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            redaction_config=redaction,
        )

        # Empty arguments and empty result
        receipt = _generate_gateway_receipt(
            gw, arguments={}, result_text="",
        )

        # Fields with no content should not become markers
        context = receipt.get("inputs", {}).get("context")
        response = receipt.get("outputs", {}).get("response")
        if context is not None:
            # context could be "" or None or a marker -- if empty, should not be a marker
            if isinstance(context, str) and context == "":
                pass  # expected
            elif context is None:
                pass  # expected
            else:
                # It's okay if it's a string like "{}" from json.dumps({})
                assert isinstance(context, str), (
                    "Empty arguments should not produce a redaction marker"
                )

    def test_redacted_receipt_no_pii_in_redacted_fields(self, tmp_path):
        """PII must not appear in redacted fields (inputs/outputs) of persisted file."""
        pytest.importorskip("mcp")
        from sanna.gateway.config import RedactionConfig
        from sanna.gateway.server import SannaGateway, DownstreamSpec

        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        store_dir = tmp_path / "receipts"
        store_dir.mkdir()

        redaction = RedactionConfig(
            enabled=True, mode="hash_only",
            fields=["arguments", "result_text"],
        )

        gw = SannaGateway(
            downstreams=[DownstreamSpec(name="mock", command="echo")],
            constitution_path=const_path,
            signing_key_path=key_path,
            receipt_store_path=str(store_dir),
            redaction_config=redaction,
        )

        pii_args = {"patient_name": "Jane Smith", "ssn": "987-65-4321"}
        pii_result = "Jane Smith's blood pressure is 140/90"

        receipt = _generate_gateway_receipt(
            gw, arguments=pii_args, result_text=pii_result,
        )
        gw._persist_receipt(receipt)

        files = list(store_dir.glob("*.redacted.json"))
        assert len(files) == 1
        loaded = json.loads(files[0].read_text())

        # PII must not appear in inputs.context or outputs.response
        context_val = loaded.get("inputs", {}).get("context")
        assert isinstance(context_val, dict), (
            "inputs.context should be a redaction marker dict"
        )
        assert context_val.get("__redacted__") is True
        assert "Jane Smith" not in json.dumps(context_val)
        assert "987-65-4321" not in json.dumps(context_val)

        response_val = loaded.get("outputs", {}).get("response")
        assert isinstance(response_val, dict), (
            "outputs.response should be a redaction marker dict"
        )
        assert response_val.get("__redacted__") is True
        assert "140/90" not in json.dumps(response_val)

        # Markers must be present in the raw file content
        raw_content = files[0].read_text()
        assert "__redacted__" in raw_content
        assert "original_hash" in raw_content
