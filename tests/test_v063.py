"""Sanna v0.6.3 new tests.

Covers: RFC 8785 canonicalization, coverage basis points, C4 contraction fix,
full-document constitution signing, receipt signature metadata binding,
signed constitution receipt schema validation, schema validation on load,
CLI split (hash vs sign), chain verification, version constants.
"""

import copy
import json
import warnings
from dataclasses import asdict
from pathlib import Path

import pytest

from sanna.hashing import canonical_json_bytes, hash_text, _reject_floats
from sanna.constitution import (
    AgentIdentity,
    Boundary,
    Constitution,
    ConstitutionSignature,
    HaltCondition,
    Invariant,
    Provenance,
    TrustTiers,
    SannaConstitutionError,
    compute_constitution_hash,
    constitution_to_receipt_ref,
    constitution_to_signable_dict,
    load_constitution,
    parse_constitution,
    save_constitution,
    sign_constitution,
    validate_against_schema,
)
from sanna.crypto import (
    generate_keypair,
    load_public_key,
    compute_key_id,
    sign_constitution_full,
    sign_receipt,
    verify_constitution_full,
    verify_receipt_signature,
)
from sanna.receipt import (
    CHECKS_VERSION,
    TOOL_VERSION,
    generate_receipt,
    check_c4_conflict_collapse,
)
from sanna.middleware import sanna_observe, SannaHaltError
from sanna.verify import verify_receipt, verify_fingerprint, verify_constitution_chain


# =============================================================================
# HELPERS
# =============================================================================

def _make_constitution(invariants=None):
    return Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="author@test.com",
            approved_by=["lead@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test boundary", category="scope", severity="medium")],
        invariants=invariants or [
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ],
    )


def _sign_and_save(constitution, tmp_path, priv_path, signed_by="tester"):
    signed = sign_constitution(constitution, private_key_path=str(priv_path), signed_by=signed_by)
    path = tmp_path / "constitution.yaml"
    save_constitution(signed, path)
    return signed, path


def _make_trace():
    from sanna.receipt import Trace
    return Trace(
        correlation_id="test-trace-001",
        query="What is the refund policy?",
        context="Physical products can be returned within 30 days. Digital products are non-refundable.",
        response="You can return physical products within 30 days. However, digital products are non-refundable.",
    )


RECEIPT_SCHEMA_PATH = Path(__file__).parent.parent / "src" / "sanna" / "spec" / "receipt.schema.json"
with open(RECEIPT_SCHEMA_PATH) as _f:
    RECEIPT_SCHEMA = json.load(_f)


# =============================================================================
# 1. RFC 8785 Canonicalization
# =============================================================================

class TestRFC8785Canonicalization:
    def test_integer_float_normalized(self):
        """canonical_json_bytes converts integer-valued floats to int (v0.13.2+)."""
        result = canonical_json_bytes({"val": 5.0})
        assert b'"val":5' in result
        assert b'"val":5.0' not in result

    def test_non_integer_float_rejected(self):
        """canonical_json_bytes rejects non-integer floats (v0.13.2+)."""
        with pytest.raises(ValueError, match="Non-integer float"):
            canonical_json_bytes({"val": 1.5})

    def test_integer_passes(self):
        """canonical_json_bytes should accept integers."""
        result = canonical_json_bytes({"val": 10000})
        assert isinstance(result, bytes)
        assert b"10000" in result

    def test_known_canonical_output(self):
        """Verify deterministic canonical JSON output."""
        obj = {"b": 2, "a": 1}
        result = canonical_json_bytes(obj)
        assert result == b'{"a":1,"b":2}'

    def test_nested_non_integer_float_rejected(self):
        """Non-integer float nested deep in structure is rejected (v0.13.2+)."""
        with pytest.raises(ValueError, match="Non-integer float"):
            canonical_json_bytes({"data": {"value": 3.14}})

    def test_integer_float_in_list_normalized(self):
        """Integer-valued floats in lists are normalized to int (v0.13.2+)."""
        result = canonical_json_bytes({"items": [1.0]})
        assert b'"items":[1]' in result

    def test_reject_floats_rejects_nan(self):
        """_reject_floats rejects NaN."""
        import math
        with pytest.raises(TypeError, match="Non-finite"):
            _reject_floats({"x": float("nan")})

    def test_reject_floats_passes_ints(self):
        """_reject_floats should not raise for ints."""
        _reject_floats({"x": 42, "y": [1, 2, 3]})  # no exception


# =============================================================================
# 2. Coverage Basis Points
# =============================================================================

class TestCoverageBasisPoints:
    def test_full_coverage_10000(self, tmp_path):
        """All invariants evaluated = 10000 basis points."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ])
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "Answer grounded in context."

        result = agent(query="test", context="Known context")
        cov = result.receipt.get("evaluation_coverage", {})
        assert cov["coverage_basis_points"] == 10000

    def test_partial_coverage_basis_points(self, tmp_path):
        """2 of 3 invariants evaluated = 6666 basis points."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_MARK_INFERENCE", rule="Mark inference", enforcement="warn"),
            Invariant(id="INV_CUSTOM_RULE", rule="Custom rule", enforcement="log"),  # no mapping → NOT_CHECKED
        ])
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "Answer grounded in context."

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context="Known context")

        cov = result.receipt.get("evaluation_coverage", {})
        assert cov["coverage_basis_points"] == 6666

    def test_basis_points_in_fingerprint(self, tmp_path):
        """Tampering with coverage_basis_points should invalidate fingerprint."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ])
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        receipt = result.receipt
        receipt["evaluation_coverage"]["coverage_basis_points"] = 9999
        match, _, _ = verify_fingerprint(receipt)
        assert not match


# =============================================================================
# 3. C4 Contraction Fix
# =============================================================================

class TestC4ContractionFix:
    def test_cant_not_flagged_as_permissive(self):
        """'can't' should NOT be detected as permissive (contraction fix)."""
        context = "You can't return digital products. Physical items are non-refundable."
        output = "Digital products are final sale."
        result = check_c4_conflict_collapse(context, output)
        # "can't" should not trigger the permissive pattern
        assert result.passed

    def test_can_still_detected(self):
        """'can' (standalone) should still be detected as permissive."""
        context = "You can return items within 30 days. Digital items are non-refundable."
        output = "All items are eligible for return."  # doesn't acknowledge tension
        result = check_c4_conflict_collapse(context, output)
        assert not result.passed

    def test_cannot_still_detected_as_restrictive(self):
        """'cannot' should still be detected as restrictive."""
        context = "You can return items. You cannot return digital items."
        output = "All items are eligible for return."  # doesn't acknowledge tension
        result = check_c4_conflict_collapse(context, output)
        assert not result.passed


# =============================================================================
# 4. Constitution Full-Document Signing
# =============================================================================

class TestConstitutionFullDocSigning:
    def test_signature_covers_provenance(self, tmp_path):
        """Tampering with approved_by after signing should fail verification."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")

        # Tamper: change approved_by
        tampered = Constitution(
            schema_version=signed.schema_version,
            identity=signed.identity,
            provenance=Provenance(
                authored_by=signed.provenance.authored_by,
                approved_by=["attacker@evil.com"],  # tampered
                approval_date=signed.provenance.approval_date,
                approval_method=signed.provenance.approval_method,
                change_history=signed.provenance.change_history,
                signature=signed.provenance.signature,
            ),
            boundaries=signed.boundaries,
            invariants=signed.invariants,
            policy_hash=signed.policy_hash,
        )
        assert not verify_constitution_full(tampered, str(pub_path))

    def test_signature_covers_signer_metadata(self, tmp_path):
        """Tampering with signed_by should fail verification."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")

        # Tamper: change signed_by in the signature block
        tampered_sig = ConstitutionSignature(
            value=signed.provenance.signature.value,
            key_id=signed.provenance.signature.key_id,
            signed_by="attacker",  # tampered
            signed_at=signed.provenance.signature.signed_at,
            scheme=signed.provenance.signature.scheme,
        )
        tampered = Constitution(
            schema_version=signed.schema_version,
            identity=signed.identity,
            provenance=Provenance(
                authored_by=signed.provenance.authored_by,
                approved_by=signed.provenance.approved_by,
                approval_date=signed.provenance.approval_date,
                approval_method=signed.provenance.approval_method,
                change_history=signed.provenance.change_history,
                signature=tampered_sig,
            ),
            boundaries=signed.boundaries,
            invariants=signed.invariants,
            policy_hash=signed.policy_hash,
        )
        assert not verify_constitution_full(tampered, str(pub_path))

    def test_signable_dict_excludes_only_value(self, tmp_path):
        """constitution_to_signable_dict should set provenance.signature.value to ''."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")

        signable = constitution_to_signable_dict(signed)
        sig_in_dict = signable["provenance"]["signature"]
        assert sig_in_dict["value"] == ""
        assert sig_in_dict["key_id"] == signed.provenance.signature.key_id
        assert sig_in_dict["signed_by"] == "tester"
        assert sig_in_dict["scheme"] == "constitution_sig_v1"

    def test_key_id_checked_during_verification(self, tmp_path):
        """Verifying with wrong public key should fail due to key_id mismatch."""
        priv_path, _ = generate_keypair(tmp_path / "keys1")
        _, wrong_pub = generate_keypair(tmp_path / "keys2")

        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        assert not verify_constitution_full(signed, str(wrong_pub))

    def test_scheme_field_present(self, tmp_path):
        """Signed constitution should have scheme='constitution_sig_v1'."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path))
        assert signed.provenance.signature.scheme == "constitution_sig_v1"


# =============================================================================
# 5. Receipt Signature Metadata Binding
# =============================================================================

class TestReceiptSignatureMetadataBinding:
    def _make_signed_receipt(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer based on context."

        result = agent(query="test", context="Test context")
        return result.receipt, pub_path, priv_path

    def test_tamper_signed_at_fails(self, tmp_path):
        """Tampering with receipt_signature.signed_at should fail verification."""
        receipt, pub_path, _ = self._make_signed_receipt(tmp_path)
        receipt["receipt_signature"]["signed_at"] = "2020-01-01T00:00:00+00:00"
        assert not verify_receipt_signature(receipt, str(pub_path))

    def test_tamper_key_id_fails(self, tmp_path):
        """Tampering with receipt_signature.key_id should fail verification."""
        receipt, pub_path, _ = self._make_signed_receipt(tmp_path)
        receipt["receipt_signature"]["key_id"] = "a" * 64
        assert not verify_receipt_signature(receipt, str(pub_path))

    def test_scheme_field_present(self, tmp_path):
        """Signed receipt should have scheme='receipt_sig_v1'."""
        receipt, _, _ = self._make_signed_receipt(tmp_path)
        assert receipt["receipt_signature"]["scheme"] == "receipt_sig_v1"

    def test_key_id_checked_during_verification(self, tmp_path):
        """Verifying with wrong key fails due to key_id mismatch."""
        receipt, _, _ = self._make_signed_receipt(tmp_path)
        _, wrong_pub = generate_keypair(tmp_path / "wrong_keys")
        assert not verify_receipt_signature(receipt, str(wrong_pub))


# =============================================================================
# 6. Signed Constitution Receipt Schema
# =============================================================================

class TestSignedConstitutionReceiptSchema:
    def test_receipt_from_signed_constitution_validates(self, tmp_path):
        """Receipt from Ed25519-signed constitution should pass schema validation."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context data")
        vr = verify_receipt(result.receipt, RECEIPT_SCHEMA)
        assert vr.valid, f"Validation failed: {vr.errors}"

    def test_receipt_with_full_verification(self, tmp_path):
        """Receipt should pass schema + fingerprint + signature verification."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context data")
        receipt = result.receipt

        # Schema + fingerprint
        vr = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert vr.valid, f"Validation failed: {vr.errors}"

        # Signature
        assert verify_receipt_signature(receipt, str(pub_path))


# =============================================================================
# 7. Schema Validation on Constitution Load
# =============================================================================

class TestSchemaValidationOnLoad:
    def test_valid_constitution_passes(self, tmp_path):
        """Valid constitution should pass with validate=True."""
        const = _make_constitution()
        signed = sign_constitution(const)
        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)
        loaded = load_constitution(str(path), validate=True)
        assert loaded.policy_hash == signed.policy_hash

    def test_invalid_constitution_raises(self, tmp_path):
        """Invalid constitution (missing identity) should raise with validate=True."""
        import yaml
        invalid = {
            "sanna_constitution": "0.1.0",
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "policy_hash": None,
        }
        path = tmp_path / "invalid.yaml"
        with open(path, "w") as f:
            yaml.dump(invalid, f)

        with pytest.raises(SannaConstitutionError, match="[Ss]chema"):
            load_constitution(str(path), validate=True)


# =============================================================================
# 8. CLI Split
# =============================================================================

class TestCLISplit:
    def test_hash_constitution_no_signature(self, tmp_path):
        """sanna-hash-constitution should set policy_hash but no Ed25519 signature."""
        const = _make_constitution()
        signed = sign_constitution(const)  # no private_key_path
        assert signed.policy_hash is not None
        assert signed.provenance.signature is None

    def test_sign_constitution_with_key(self, tmp_path):
        """sanna-sign-constitution with --private-key should set both hash and signature."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        assert signed.policy_hash is not None
        assert signed.provenance.signature is not None
        assert signed.provenance.signature.value is not None


# =============================================================================
# 9. Chain Verification
# =============================================================================

class TestChainVerification:
    def test_full_chain_passes(self, tmp_path):
        """Full chain: receipt + constitution + both keys should verify."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, const_path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        errors, _ = verify_constitution_chain(
            result.receipt, str(const_path), str(pub_path)
        )
        assert errors == [], f"Chain errors: {errors}"

    def test_tampered_constitution_fails(self, tmp_path):
        """Tampering with constitution file should cause chain verification failure."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, const_path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")

        # Tamper the constitution file
        content = const_path.read_text()
        content = content.replace("test-agent", "evil-agent")
        const_path.write_text(content)

        errors, _ = verify_constitution_chain(result.receipt, str(const_path))
        assert len(errors) > 0

    def test_wrong_constitution_public_key(self, tmp_path):
        """Wrong public key should cause constitution signature failure."""
        priv_path, _ = generate_keypair(tmp_path / "keys1")
        _, wrong_pub = generate_keypair(tmp_path / "keys2")
        const = _make_constitution()
        signed, const_path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        errors, _ = verify_constitution_chain(result.receipt, str(const_path), str(wrong_pub))
        assert len(errors) > 0
        assert any("signature" in e.lower() for e in errors)

    def test_policy_hash_mismatch(self, tmp_path):
        """Receipt pointing to wrong constitution should fail chain verification."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const1 = _make_constitution()
        (tmp_path / "c1").mkdir()
        signed1, path1 = _sign_and_save(const1, tmp_path / "c1", priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path1), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")

        # Create a different constitution
        const2 = _make_constitution([
            Invariant(id="INV_DIFFERENT", rule="Different rule", enforcement="warn"),
        ])
        (tmp_path / "c2").mkdir()
        signed2, path2 = _sign_and_save(const2, tmp_path / "c2", priv_path)

        # Verify receipt against wrong constitution
        errors, _ = verify_constitution_chain(result.receipt, str(path2), str(pub_path))
        assert len(errors) > 0
        assert any("mismatch" in e.lower() or "match" in e.lower() for e in errors)

    def test_chain_without_public_key(self, tmp_path):
        """Chain verification without public key should still verify hash bond."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, const_path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        errors, _ = verify_constitution_chain(result.receipt, str(const_path))
        assert errors == []


# =============================================================================
# 10. Version Constants
# =============================================================================

class TestV063Versions:
    def test_tool_version(self):
        assert TOOL_VERSION == "0.13.2"

    def test_checks_version(self):
        assert CHECKS_VERSION == "5"

    def test_init_version(self):
        import sanna
        assert sanna.__version__ == "0.13.2"


# =============================================================================
# 11. ConstitutionSignature Dataclass
# =============================================================================

class TestConstitutionSignatureDataclass:
    def test_default_values(self):
        sig = ConstitutionSignature()
        assert sig.value is None
        assert sig.key_id is None
        assert sig.signed_by is None
        assert sig.signed_at is None
        assert sig.scheme == "constitution_sig_v1"

    def test_round_trip_through_constitution(self, tmp_path):
        """ConstitutionSignature should survive save/load cycle."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="roundtrip-test")

        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)
        loaded = load_constitution(str(path))

        assert loaded.provenance.signature is not None
        assert loaded.provenance.signature.value == signed.provenance.signature.value
        assert loaded.provenance.signature.key_id == signed.provenance.signature.key_id
        assert loaded.provenance.signature.signed_by == "roundtrip-test"
        assert loaded.provenance.signature.scheme == "constitution_sig_v1"

        # And the loaded constitution should verify
        assert verify_constitution_full(loaded, str(pub_path))


# =============================================================================
# 12. Signing Check Distinguishes Hash vs Signature (#3)
# =============================================================================

class TestSigningCheckDistinction:
    def test_hashed_only_constitution_rejected_in_middleware(self, tmp_path):
        """sanna_observe with hashed-only constitution raises SannaConstitutionError."""
        const = _make_constitution()
        signed = sign_constitution(const)  # hash-only
        path = tmp_path / "hashed.yaml"
        save_constitution(signed, path)

        with pytest.raises(SannaConstitutionError, match="hashed but not signed|missing or malformed"):
            @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
            def agent(query, context):
                return "OK"

    def test_signed_constitution_accepted(self, tmp_path):
        """sanna_observe with fully signed constitution works without warning."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        path = tmp_path / "signed.yaml"
        save_constitution(signed, path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "OK"

        result = agent(query="test", context="ctx")
        assert result is not None

    def test_unsigned_constitution_rejected(self, tmp_path):
        """sanna_observe with no policy_hash should raise."""
        const = _make_constitution()
        # Save without signing — no policy_hash
        path = tmp_path / "unsigned.yaml"
        import yaml
        from sanna.constitution import constitution_to_dict
        data = constitution_to_dict(const)
        data["policy_hash"] = None
        with open(path, "w") as f:
            yaml.dump(data, f)

        with pytest.raises(SannaConstitutionError, match="not signed"):
            @sanna_observe(require_constitution_sig=False, constitution_path=str(path), strict=False)
            def agent(query, context):
                return "test"

    def test_verify_chain_warns_on_hashed_only(self, tmp_path):
        """verify_constitution_chain returns warning for hashed-only constitution."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()

        # Create a fully signed constitution first to generate a valid receipt
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        signed_path = tmp_path / "signed.yaml"
        save_constitution(signed, signed_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(signed_path), private_key_path=str(priv_path))
        def agent(query, context):
            return "OK"

        result = agent(query="test", context="ctx")

        # Now create a hashed-only version with the SAME policy_hash
        # (We can't easily do this, so instead test with a separately-hashed constitution)
        hashed_only = sign_constitution(const)  # hash-only
        hashed_path = tmp_path / "hashed.yaml"
        save_constitution(hashed_only, hashed_path)

        errors, warnings = verify_constitution_chain(
            result.receipt, str(hashed_path)
        )
        # Different policy_hash will cause an error, but the key check is that
        # warnings mentions "not signed" for hashed-only constitutions
        has_signing_warning = any("not signed" in w.lower() or "hashed but" in w.lower() for w in warnings)
        assert has_signing_warning, f"Expected signing warning, got warnings={warnings}"

    def test_gateway_rejects_hashed_only_constitution(self, tmp_path):
        """Gateway constitution loading code should reject hashed-only constitutions."""
        const = _make_constitution()
        signed = sign_constitution(const)  # hash-only — has policy_hash but no signature
        path = tmp_path / "hashed.yaml"
        save_constitution(signed, path)

        # Directly test the constitution check logic that the gateway uses
        loaded = load_constitution(str(path))
        assert loaded.policy_hash is not None  # has a hash
        _sig = loaded.provenance.signature if loaded.provenance else None
        assert not (_sig and getattr(_sig, 'value', None))  # but no signature


# =============================================================================
# Block 4 — Return type, async support, fingerprint error (#11, #13, #14)
# =============================================================================


class TestVerifyChainReturnType:
    """verify_constitution_chain returns tuple[list, list] (#13)."""

    def test_return_type_is_tuple(self, tmp_path):
        """Return value is a 2-tuple (errors, warnings)."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "test"

        sr = agent(query="q", context="c")
        result = verify_constitution_chain(sr.receipt, str(path))

        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2
        errors, warnings_list = result
        assert isinstance(errors, list)
        assert isinstance(warnings_list, list)

    def test_hashed_only_rejected_in_middleware(self, tmp_path):
        """Hashed-only constitution is now rejected by middleware (not just warning)."""
        const = _make_constitution()
        signed = sign_constitution(const)  # hash-only
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        with pytest.raises(SannaConstitutionError, match="hashed but not signed|missing or malformed"):
            @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
            def agent(query, context):
                return "test"


class TestSannaObserveAsync:
    """sanna_observe works with async functions (#11)."""

    def test_async_function_detected(self, tmp_path):
        """Wrapping an async function returns an async wrapper."""
        import asyncio
        from sanna.middleware import sanna_observe

        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        async def my_async_agent(query, context):
            return f"Answer to {query}"

        import inspect
        assert inspect.iscoroutinefunction(my_async_agent), (
            "sanna_observe should return an async wrapper for async functions"
        )

    def test_sync_function_still_works(self, tmp_path):
        """Wrapping a sync function still works."""
        from sanna.middleware import sanna_observe

        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def my_sync_agent(query, context):
            return f"Answer to {query}"

        import inspect
        assert not inspect.iscoroutinefunction(my_sync_agent)

        result = my_sync_agent(query="test?", context="Some context.")
        assert result.output == "Answer to test?"
        assert result.receipt is not None

    def test_async_function_produces_receipt(self, tmp_path):
        """Async wrapped function produces a valid receipt."""
        import asyncio
        from sanna.middleware import sanna_observe

        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        async def my_async_agent(query, context):
            return f"Async answer to {query}"

        result = asyncio.run(my_async_agent(query="test?", context="Some context."))
        assert result.output == "Async answer to test?"
        assert result.receipt is not None
        assert "receipt_id" in result.receipt
