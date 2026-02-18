"""Tests for SEC-3 (Constitution Verification Bypass) and SEC-4 (Float DoS in Signing).

SEC-3: verify_receipt() should warn when a receipt references a constitution
but no constitution path is provided for verification.

SEC-4: sanitize_for_signing() should convert exact-integer floats to int and
raise ValueError (not TypeError) for non-integer floats.
"""

import json
from pathlib import Path

import pytest

from sanna.crypto import generate_keypair, sanitize_for_signing, sign_receipt
from sanna.hashing import canonical_json_bytes, hash_obj
from sanna.verify import verify_receipt, load_schema

SCHEMA = load_schema()


# =============================================================================
# Helpers
# =============================================================================

def _make_signed_constitution(tmp_path):
    """Create a signed constitution and return (constitution, path, priv_path, pub_path)."""
    from sanna.constitution import (
        Constitution, AgentIdentity, Provenance, Boundary, Invariant,
        sign_constitution, save_constitution,
    )

    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="tester@test.com",
            approved_by=["reviewer@test.com"],
            approval_date="2026-01-01",
            approval_method="automated-test",
        ),
        boundaries=[
            Boundary(id="B001", description="Test boundary",
                     category="scope", severity="medium"),
        ],
        invariants=[
            Invariant(id="INV_NO_FABRICATION",
                      rule="Do not fabricate.", enforcement="halt"),
        ],
    )
    key_dir = tmp_path / "keys"
    priv_path, pub_path = generate_keypair(key_dir)
    signed = sign_constitution(const, private_key_path=str(priv_path),
                                signed_by="tester")
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)
    return signed, const_path, priv_path, pub_path


def _generate_receipt_with_constitution(tmp_path):
    """Generate a real receipt that references a constitution."""
    from sanna.middleware import sanna_observe

    signed, const_path, priv_path, pub_path = _make_signed_constitution(tmp_path)

    @sanna_observe(
        constitution_path=str(const_path),
        constitution_public_key_path=str(pub_path),
        private_key_path=str(priv_path),
    )
    def agent(query, context):
        return f"Based on context: {context}"

    result = agent(
        query="What is the status?",
        context="The status is green.",
    )
    return result.receipt, const_path, pub_path


def _load_golden_receipt_without_constitution():
    """Load a golden receipt that has constitution_ref=null."""
    golden_path = (
        Path(__file__).parent.parent / "golden" / "receipts"
        / "002_pass_simple_qa.json"
    )
    with open(golden_path) as f:
        return json.load(f)


# =============================================================================
# SEC-3: Constitution Verification Bypass — Warning Tests
# =============================================================================

class TestSEC3ConstitutionVerificationWarning:
    """Verify that missing --constitution produces a warning when receipt has constitution_ref."""

    def test_receipt_with_constitution_ref_no_constitution_flag_warns(self, tmp_path):
        """verify_receipt with receipt containing constitution_ref but no
        constitution path should add a warning about unverified chain."""
        receipt, _const_path, _pub_path = _generate_receipt_with_constitution(tmp_path)

        # Verify: receipt has constitution_ref
        assert receipt.get("constitution_ref") is not None
        assert receipt["constitution_ref"].get("policy_hash")

        # Verify without --constitution
        result = verify_receipt(receipt, SCHEMA)

        # Should be valid (warning, not error)
        assert result.valid, f"Expected valid, got errors: {result.errors}"

        # Should contain the constitution chain warning
        chain_warnings = [
            w for w in result.warnings
            if "Constitution chain NOT verified" in w
        ]
        assert len(chain_warnings) == 1, (
            f"Expected exactly one constitution chain warning, got: {result.warnings}"
        )

    def test_receipt_with_constitution_ref_and_constitution_flag_no_warning(self, tmp_path):
        """verify_receipt with receipt containing constitution_ref AND matching
        --constitution should NOT produce the chain warning."""
        receipt, const_path, pub_path = _generate_receipt_with_constitution(tmp_path)

        # Verify WITH constitution
        result = verify_receipt(
            receipt, SCHEMA,
            constitution_path=str(const_path),
        )

        assert result.valid, f"Expected valid, got errors: {result.errors}"

        # Should NOT contain the "NOT verified" warning
        chain_warnings = [
            w for w in result.warnings
            if "Constitution chain NOT verified" in w
        ]
        assert len(chain_warnings) == 0, (
            f"Unexpected constitution chain warning when constitution was provided: "
            f"{result.warnings}"
        )

    def test_receipt_without_constitution_ref_no_warning(self):
        """verify_receipt with receipt containing NO constitution_ref and no
        --constitution flag should NOT produce the chain warning."""
        receipt = _load_golden_receipt_without_constitution()

        # Verify: receipt has no constitution_ref (or it's null)
        assert receipt.get("constitution_ref") is None

        result = verify_receipt(receipt, SCHEMA)

        assert result.valid, f"Expected valid, got errors: {result.errors}"

        # Should NOT contain the chain warning
        chain_warnings = [
            w for w in result.warnings
            if "Constitution chain NOT verified" in w
        ]
        assert len(chain_warnings) == 0, (
            f"Unexpected constitution chain warning for receipt without "
            f"constitution_ref: {result.warnings}"
        )

    def test_constitution_chain_verified_when_path_provided(self, tmp_path):
        """When --constitution is provided and matches, policy_hash is verified."""
        receipt, const_path, pub_path = _generate_receipt_with_constitution(tmp_path)

        # Verify WITH constitution path
        result = verify_receipt(
            receipt, SCHEMA,
            constitution_path=str(const_path),
        )

        assert result.valid, f"Expected valid, got errors: {result.errors}"

        # No chain mismatch errors
        chain_errors = [
            e for e in result.errors
            if "policy_hash" in e or "constitution" in e.lower()
        ]
        assert len(chain_errors) == 0, f"Unexpected chain errors: {chain_errors}"

    def test_constitution_chain_mismatch_detected(self, tmp_path):
        """When --constitution is provided but policy_hash doesn't match, error."""
        receipt, _const_path, _pub_path = _generate_receipt_with_constitution(tmp_path)

        # Create a different constitution
        _, different_const_path, _, _ = _make_signed_constitution(
            tmp_path / "other"
        )

        # Verify with WRONG constitution
        result = verify_receipt(
            receipt, SCHEMA,
            constitution_path=str(different_const_path),
        )

        # Should have error about mismatch
        assert not result.valid or any(
            "mismatch" in e.lower() or "bond" in e.lower()
            for e in result.errors
        ), f"Expected constitution mismatch error, got: {result.errors}"


# =============================================================================
# SEC-4: Float DoS in Signing Pipeline
# =============================================================================

class TestSEC4FloatSanitization:
    """Verify float handling in the signing/canonicalization pipeline."""

    def test_exact_integer_float_converted_to_int(self):
        """Float 3.0 should be silently converted to int 3."""
        result = sanitize_for_signing({"extensions": {"count": 3.0}})
        assert result == {"extensions": {"count": 3}}
        assert isinstance(result["extensions"]["count"], int)

    def test_various_exact_integer_floats(self):
        """Various exact-integer floats should all convert."""
        result = sanitize_for_signing({
            "a": 0.0,
            "b": 1.0,
            "c": -5.0,
            "d": 100.0,
            "e": 1000000.0,
        })
        assert result == {"a": 0, "b": 1, "c": -5, "d": 100, "e": 1000000}
        for v in result.values():
            assert isinstance(v, int)

    def test_non_integer_float_raises_clear_error(self):
        """Float 3.14 should raise ValueError with descriptive message."""
        with pytest.raises(ValueError, match="Non-integer float not allowed"):
            sanitize_for_signing({"pi": 3.14})

    def test_non_integer_float_error_includes_value(self):
        """Error message should include the actual float value."""
        with pytest.raises(ValueError, match="3.14"):
            sanitize_for_signing({"pi": 3.14})

    def test_non_integer_float_error_includes_path(self):
        """Error message should include the JSON path."""
        with pytest.raises(ValueError, match=r"\$\.extensions\.score"):
            sanitize_for_signing({"extensions": {"score": 71.43}})

    def test_non_integer_float_error_not_typeerror(self):
        """Non-integer floats should raise ValueError, not TypeError."""
        with pytest.raises(ValueError):
            sanitize_for_signing({"score": 3.14})

        # Confirm it is NOT a TypeError
        try:
            sanitize_for_signing({"score": 3.14})
            assert False, "Should have raised"
        except ValueError:
            pass  # Expected
        except TypeError:
            pytest.fail("Should raise ValueError, not TypeError")

    def test_integers_pass_through_unchanged(self):
        """Integer values should pass through without modification."""
        data = {"count": 42, "items": [1, 2, 3], "nested": {"val": 0}}
        result = sanitize_for_signing(data)
        assert result == data

    def test_nan_raises_clear_error(self):
        """NaN should raise ValueError, not pass through silently."""
        with pytest.raises(ValueError, match="Non-integer float not allowed"):
            sanitize_for_signing({"val": float("nan")})

    def test_infinity_raises_clear_error(self):
        """Infinity should raise ValueError."""
        with pytest.raises(ValueError, match="Non-integer float not allowed"):
            sanitize_for_signing({"val": float("inf")})

    def test_signing_pipeline_with_exact_integer_float(self, tmp_path):
        """End-to-end: receipt with float 3.0 in extensions signs successfully."""
        from sanna.middleware import sanna_observe

        _signed, const_path, priv_path, pub_path = _make_signed_constitution(tmp_path)

        @sanna_observe(
            constitution_path=str(const_path),
            constitution_public_key_path=str(pub_path),
            private_key_path=str(priv_path),
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test", context="Context info")
        receipt = result.receipt

        # Inject exact-integer float into extensions
        receipt["extensions"] = {"count": 3.0}
        receipt.pop("receipt_signature", None)

        # Should succeed — 3.0 → 3
        signed_receipt = sign_receipt(receipt, str(priv_path))
        assert "receipt_signature" in signed_receipt

    def test_signing_pipeline_with_non_integer_float_fails(self, tmp_path):
        """End-to-end: receipt with float 3.14 in extensions fails signing."""
        from sanna.middleware import sanna_observe

        _signed, const_path, priv_path, pub_path = _make_signed_constitution(tmp_path)

        @sanna_observe(
            constitution_path=str(const_path),
            constitution_public_key_path=str(pub_path),
            private_key_path=str(priv_path),
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test", context="Context info")
        receipt = result.receipt

        # Inject non-integer float into extensions
        receipt["extensions"] = {"score": 3.14}
        receipt.pop("receipt_signature", None)

        with pytest.raises(ValueError, match="3.14"):
            sign_receipt(receipt, str(priv_path))

    def test_canonical_json_bytes_accepts_floats_in_hashing_path(self):
        """canonical_json_bytes allows floats for hashing (non-signing path).

        The hashing path must accept floats to verify existing receipts
        that may contain float values. Only the signing path
        (sanitize_for_signing) restricts floats.
        """
        result = canonical_json_bytes({"score": 3.14})
        assert isinstance(result, bytes)
        assert b"3.14" in result

    def test_hash_obj_with_float_works(self):
        """hash_obj accepts floats for fingerprint computation."""
        h = hash_obj({"score": 3.14})
        assert isinstance(h, str)
        assert len(h) == 64  # Full SHA-256 hex
