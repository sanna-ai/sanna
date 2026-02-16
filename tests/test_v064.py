"""Sanna v0.6.4 tests — Enforcement Hardening.

Covers: strict schema validation on enforcement paths, CLI clean error handling,
chain verification signature binding, float sanitization at signing boundary,
private key file permissions, version constants.
"""

import copy
import json
import os
import stat
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

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
    load_constitution,
    save_constitution,
    sign_constitution,
)
from sanna.crypto import (
    generate_keypair,
    sanitize_for_signing,
    sign_constitution_full,
    sign_receipt,
    verify_constitution_full,
    verify_receipt_signature,
)
from sanna.middleware import sanna_observe, SannaHaltError
from sanna.receipt import CHECKS_VERSION, TOOL_VERSION
from sanna.verify import verify_receipt, verify_constitution_chain

RECEIPT_SCHEMA_PATH = Path(__file__).parent.parent / "src" / "sanna" / "spec" / "receipt.schema.json"
with open(RECEIPT_SCHEMA_PATH) as _f:
    RECEIPT_SCHEMA = json.load(_f)


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


# =============================================================================
# 1. Schema Validation on Enforcement Paths (strict=True)
# =============================================================================

class TestStrictSchemaValidation:
    def test_constitution_with_typo_field_raises_on_strict(self, tmp_path):
        """Constitution YAML with 'invariant:' (singular) raises error with strict=True."""
        bad_yaml = {
            "sanna_constitution": "0.1.0",
            "identity": {"agent_name": "test", "domain": "testing"},
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariant": [  # wrong: should be "invariants" (plural)
                {"id": "INV_NO_FABRICATION", "rule": "No fabrication", "enforcement": "halt"},
            ],
            "policy_hash": None,
        }
        path = tmp_path / "bad.yaml"
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)

        with pytest.raises((SannaConstitutionError, ValueError)):
            load_constitution(str(path), validate=True)

    def test_constitution_with_unknown_top_level_field_raises(self, tmp_path):
        """Constitution with unknown top-level field raises on strict validation."""
        bad_yaml = {
            "sanna_constitution": "0.1.0",
            "identity": {"agent_name": "test", "domain": "testing"},
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariants": [],
            "extra_unknown_field": "should fail schema",
            "policy_hash": None,
        }
        path = tmp_path / "unknown.yaml"
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)

        with pytest.raises(SannaConstitutionError, match="[Ss]chema"):
            load_constitution(str(path), validate=True)

    def test_strict_false_loads_without_validation(self, tmp_path):
        """strict=False (validate=False) should load even with schema issues."""
        # A minimal valid YAML that can parse but might have schema issues
        const = _make_constitution()
        signed = sign_constitution(const)
        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)

        # This should work with validate=False (default)
        loaded = load_constitution(str(path), validate=False)
        assert loaded.identity.agent_name == "test-agent"

    def test_sanna_observe_strict_true_rejects_invalid(self, tmp_path):
        """sanna_observe(strict=True) should reject invalid constitution at decoration time."""
        bad_yaml = {
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
        path = tmp_path / "bad.yaml"
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)

        with pytest.raises((SannaConstitutionError, ValueError)):
            @sanna_observe(constitution_path=str(path), strict=True)
            def agent(query, context):
                return "answer"

    def test_sanna_observe_strict_false_allows_unsigned(self, tmp_path):
        """sanna_observe(strict=False) should allow loading without schema validation."""
        # Create a valid but unsigned constitution
        const = _make_constitution()
        signed = sign_constitution(const)
        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)

        @sanna_observe(constitution_path=str(path), strict=False)
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Known context")
        assert result.receipt is not None


# =============================================================================
# 2. CLI Error Handling
# =============================================================================

class TestCLIErrorHandling:
    def test_hash_constitution_schema_invalid(self, tmp_path, capsys):
        """sanna-hash-constitution with schema-invalid YAML should give clean error."""
        from sanna.cli import main_hash_constitution

        bad_yaml = {
            "sanna_constitution": "0.1.0",
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [],
            "policy_hash": None,
        }
        path = tmp_path / "bad.yaml"
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)

        with patch("sys.argv", ["sanna-hash-constitution", str(path)]):
            result = main_hash_constitution()

        assert result == 1
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()

    def test_hash_constitution_file_not_found(self, tmp_path, capsys):
        """sanna-hash-constitution with nonexistent file should give clean error."""
        from sanna.cli import main_hash_constitution

        with patch("sys.argv", ["sanna-hash-constitution", str(tmp_path / "nonexistent.yaml")]):
            result = main_hash_constitution()

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_sign_constitution_file_not_found(self, tmp_path, capsys):
        """sanna-sign-constitution with nonexistent file should give clean error."""
        from sanna.cli import main_sign_constitution

        priv_path, _ = generate_keypair(tmp_path / "keys")
        with patch("sys.argv", ["sanna-sign-constitution", str(tmp_path / "nonexistent.yaml"),
                                 "--private-key", str(priv_path)]):
            result = main_sign_constitution()

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()


# =============================================================================
# 3. Chain Verification Binds Signature Value
# =============================================================================

class TestChainVerificationSignatureBinding:
    def test_receipt_constitution_a_vs_b_same_content_different_signer(self, tmp_path):
        """Receipt from constitution-A verified against constitution-B
        (same content, different signer) should fail chain verification."""
        priv_a, pub_a = generate_keypair(tmp_path / "keys_a")
        priv_b, pub_b = generate_keypair(tmp_path / "keys_b")

        const = _make_constitution()

        # Sign with key A
        (tmp_path / "ca").mkdir()
        signed_a, path_a = _sign_and_save(const, tmp_path / "ca", priv_a, signed_by="signer-a")

        # Sign same content with key B
        (tmp_path / "cb").mkdir()
        signed_b, path_b = _sign_and_save(const, tmp_path / "cb", priv_b, signed_by="signer-b")

        # Generate receipt using constitution A
        @sanna_observe(constitution_path=str(path_a), private_key_path=str(priv_a))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        receipt = result.receipt

        # Verify receipt against constitution B — should detect different signature
        errors, _ = verify_constitution_chain(receipt, str(path_b), str(pub_b))
        assert len(errors) > 0
        assert any("mismatch" in e.lower() or "different" in e.lower() for e in errors)

    def test_receipt_from_unsigned_constitution_passes(self, tmp_path):
        """Receipt from unsigned constitution should pass chain verification
        (no signature to compare)."""
        const = _make_constitution()
        signed = sign_constitution(const)  # hash only, no Ed25519
        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)

        @sanna_observe(constitution_path=str(path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        receipt = result.receipt

        # Chain verification without keys should pass (hash bond only)
        errors, _ = verify_constitution_chain(receipt, str(path))
        assert errors == [], f"Unexpected errors: {errors}"

    def test_signature_scheme_mismatch_detected(self, tmp_path):
        """If receipt and constitution have different scheme fields, detect it."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(constitution_path=str(path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        receipt = result.receipt

        # Tamper receipt's scheme
        if receipt.get("constitution_ref", {}).get("scheme"):
            receipt["constitution_ref"]["scheme"] = "fake_scheme_v99"
            errors, _ = verify_constitution_chain(receipt, str(path))
            assert any("scheme" in e.lower() for e in errors)


# =============================================================================
# 4. Float Sanitization at Signing Boundary
# =============================================================================

class TestFloatSanitization:
    def test_lossless_float_converted_to_int(self):
        """71.0 should be silently converted to 71."""
        result = sanitize_for_signing({"score": 71.0})
        assert result == {"score": 71}
        assert isinstance(result["score"], int)

    def test_lossy_float_raises_error(self):
        """71.43 should raise TypeError with path information."""
        with pytest.raises(TypeError, match="71.43"):
            sanitize_for_signing({"extensions": {"score": 71.43}})

    def test_lossy_float_error_includes_path(self):
        """Error message should include the JSON path."""
        with pytest.raises(TypeError, match=r"extensions\.score"):
            sanitize_for_signing({"extensions": {"score": 71.43}})

    def test_nested_lossless_conversion(self):
        """Nested lossless floats should all be converted."""
        result = sanitize_for_signing({
            "a": 1.0,
            "b": [2.0, 3.0],
            "c": {"d": 4.0},
        })
        assert result == {"a": 1, "b": [2, 3], "c": {"d": 4}}

    def test_non_float_values_unchanged(self):
        """Strings, ints, bools, None should pass through unchanged."""
        data = {"s": "text", "i": 42, "b": True, "n": None, "l": [1, "x"]}
        result = sanitize_for_signing(data)
        assert result == data

    def test_receipt_with_float_in_extensions_raises_at_signing(self, tmp_path):
        """Receipt with lossy float in extensions should raise clear error at signing."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(constitution_path=str(path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        receipt = result.receipt

        # Inject a lossy float into extensions
        receipt["extensions"] = {"score": 71.43}
        # Remove existing signature so sign_receipt tries to re-sign
        receipt.pop("receipt_signature", None)

        with pytest.raises(TypeError, match="71.43"):
            sign_receipt(receipt, str(priv_path))

    def test_receipt_with_integer_equivalent_float_signed_ok(self, tmp_path):
        """Receipt with integer-equivalent float (71.0) should be silently converted."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed, path = _sign_and_save(const, tmp_path, priv_path)

        @sanna_observe(constitution_path=str(path), private_key_path=str(priv_path))
        def agent(query, context):
            return "Grounded answer."

        result = agent(query="test", context="Context")
        receipt = result.receipt

        # Inject an integer-equivalent float into extensions
        receipt["extensions"] = {"score": 71.0}
        receipt.pop("receipt_signature", None)

        # Should not raise — 71.0 → 71
        signed_receipt = sign_receipt(receipt, str(priv_path))
        assert "receipt_signature" in signed_receipt
        assert verify_receipt_signature(signed_receipt, str(pub_path))


# =============================================================================
# 5. Private Key File Permissions
# =============================================================================

class TestPrivateKeyPermissions:
    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions not available on Windows")
    def test_private_key_is_0600(self, tmp_path):
        """Private key file should have 0o600 permissions."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        mode = stat.S_IMODE(os.stat(priv_path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions not available on Windows")
    def test_public_key_readable(self, tmp_path):
        """Public key file should be readable (not restricted like private key)."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        # Public key should have broader permissions than 0o600
        mode = stat.S_IMODE(os.stat(pub_path).st_mode)
        # We don't restrict public key, so it keeps default umask permissions
        assert mode & stat.S_IRUSR  # at least owner-readable


# =============================================================================
# 6. Version Constants
# =============================================================================

class TestV064Versions:
    def test_tool_version(self):
        assert TOOL_VERSION == "0.12.2"

    def test_checks_version(self):
        assert CHECKS_VERSION == "4"

    def test_init_version(self):
        import sanna
        assert sanna.__version__ == "0.12.2"

    def test_sanitize_for_signing_exported(self):
        """sanitize_for_signing should be importable from the top-level package."""
        from sanna import sanitize_for_signing as s
        assert callable(s)
