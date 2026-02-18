"""
Tests for extension points in AgentIdentity and receipt fingerprint.

Covers:
  1. Constitution with extra identity fields → captured in extensions dict,
     included in policy_hash, survive sign/verify round-trip.
  2. Constitution without extra identity fields → extensions empty dict,
     hash unchanged from pre-extension behavior.
  3. Receipt with empty extensions → fingerprint matches expected.
  4. Receipt extensions included in fingerprint → modifying changes fingerprint.
  5. Existing test suite still passes (verified by running full suite).
"""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from sanna.constitution import (
    AgentIdentity,
    Boundary,
    HaltCondition,
    Provenance,
    TrustTiers,
    Constitution,
    parse_constitution,
    compute_constitution_hash,
    sign_constitution,
    constitution_to_receipt_ref,
    constitution_to_dict,
    load_constitution,
    save_constitution,
    _identity_dict,
)
from sanna.hashing import hash_text, hash_obj
from sanna.verify import verify_receipt, verify_fingerprint, load_schema


RECEIPT_SCHEMA = load_schema()


# =============================================================================
# FIXTURES
# =============================================================================

def _base_constitution_data(**identity_overrides) -> dict:
    """Minimal valid constitution dict, optionally with extra identity fields."""
    identity = {
        "agent_name": "ext-test-agent",
        "domain": "testing",
        "description": "Extension test agent",
    }
    identity.update(identity_overrides)
    return {
        "sanna_constitution": "0.1.0",
        "identity": identity,
        "provenance": {
            "authored_by": "dev@example.com",
            "approved_by": ["lead@example.com"],
            "approval_date": "2026-02-12",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Test boundary",
                "category": "scope",
                "severity": "medium",
            }
        ],
    }


def _make_receipt(extensions=None) -> dict:
    """Build a minimal valid v0.13.0 receipt dict with optional extensions."""
    import uuid as _uuid
    from sanna.hashing import EMPTY_HASH

    correlation_id = "ext-test-001"
    inputs = {"query": "test query", "context": "test context"}
    outputs = {"response": "test response"}
    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)
    checks_version = "5"

    checks = [
        {
            "check_id": "C1",
            "name": "Context Contradiction",
            "passed": True,
            "severity": "info",
            "evidence": None,
            "details": "No contradiction detected",
        }
    ]
    # Fingerprint uses only these 4 fields (basic format, no enforcement fields)
    checks_fingerprint_data = [
        {"check_id": c["check_id"], "passed": c["passed"], "severity": c["severity"], "evidence": c["evidence"]}
        for c in checks
    ]
    checks_hash = hash_obj(checks_fingerprint_data)

    # v0.13.0: unified 12-field fingerprint with EMPTY_HASH sentinels
    constitution_hash = EMPTY_HASH
    enforcement_hash = EMPTY_HASH
    coverage_hash = EMPTY_HASH
    authority_hash = EMPTY_HASH
    escalation_hash = EMPTY_HASH
    trust_hash = EMPTY_HASH
    extensions_hash = hash_obj(extensions) if extensions else EMPTY_HASH

    fingerprint_input = (
        f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}"
        f"|{constitution_hash}|{enforcement_hash}|{coverage_hash}"
        f"|{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}"
    )

    full_fingerprint = hash_text(fingerprint_input)
    receipt_fingerprint = hash_text(fingerprint_input, truncate=16)

    return {
        "spec_version": "1.0",
        "tool_version": "0.13.0",
        "checks_version": checks_version,
        "receipt_id": str(_uuid.uuid4()),
        "receipt_fingerprint": receipt_fingerprint,
        "full_fingerprint": full_fingerprint,
        "correlation_id": correlation_id,
        "timestamp": "2026-02-12T00:00:00+00:00",
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": context_hash,
        "output_hash": output_hash,
        "checks": checks,
        "checks_passed": 1,
        "checks_failed": 0,
        "status": "PASS",
        "constitution_ref": None,
        "enforcement": None,
        "extensions": extensions if extensions else {},
    }


# =============================================================================
# TEST 1: Constitution with extra identity fields
# =============================================================================

class TestConstitutionIdentityExtensions:
    """Extra identity fields are captured in extensions and included in policy_hash."""

    def test_extra_fields_in_extensions(self):
        """Unknown identity keys end up in identity.extensions."""
        data = _base_constitution_data(
            organization="Acme Corp",
            principal="ops-team@acme.com",
            authority_scope="internal-only",
        )
        const = parse_constitution(data)
        assert const.identity.extensions == {
            "organization": "Acme Corp",
            "principal": "ops-team@acme.com",
            "authority_scope": "internal-only",
        }

    def test_extensions_affect_policy_hash(self):
        """Different identity extensions produce different policy hashes."""
        data_plain = _base_constitution_data()
        data_ext = _base_constitution_data(organization="Acme Corp")

        const_plain = parse_constitution(data_plain)
        const_ext = parse_constitution(data_ext)

        hash_plain = compute_constitution_hash(const_plain)
        hash_ext = compute_constitution_hash(const_ext)

        assert hash_plain != hash_ext

    def test_sign_verify_round_trip(self, tmp_path):
        """Constitution with extensions survives sign → save → load → verify."""
        data = _base_constitution_data(
            organization="TestOrg",
            principal="admin@testorg.com",
        )
        const = parse_constitution(data)
        signed = sign_constitution(const)

        # Save to YAML
        yaml_path = tmp_path / "ext_constitution.yaml"
        save_constitution(signed, yaml_path)

        # Load back
        loaded = load_constitution(str(yaml_path))

        # Extensions survive
        assert loaded.identity.extensions["organization"] == "TestOrg"
        assert loaded.identity.extensions["principal"] == "admin@testorg.com"

        # Hash matches (no integrity error on load = success)
        assert loaded.policy_hash == signed.policy_hash

    def test_sign_verify_round_trip_json(self, tmp_path):
        """Constitution with extensions survives sign → save → load via JSON."""
        data = _base_constitution_data(authority_scope="internal")
        const = parse_constitution(data)
        signed = sign_constitution(const)

        json_path = tmp_path / "ext_constitution.json"
        save_constitution(signed, json_path)

        loaded = load_constitution(str(json_path))
        assert loaded.identity.extensions["authority_scope"] == "internal"
        assert loaded.policy_hash == signed.policy_hash

    def test_extensions_in_receipt_ref(self):
        """Extensions don't leak into the receipt constitution_ref."""
        data = _base_constitution_data(organization="Acme")
        const = parse_constitution(data)
        signed = sign_constitution(const)
        ref = constitution_to_receipt_ref(signed)

        # constitution_ref doesn't include identity extensions directly
        assert "organization" not in ref
        # But the policy_hash covers them (tested via hash_ext != hash_plain above)

    def test_ed25519_sign_verify_with_extensions(self, tmp_path):
        """Ed25519 signed constitution with extensions verifies correctly."""
        from sanna.crypto import generate_keypair, verify_constitution_full

        priv_path, pub_path = generate_keypair(tmp_path / "keys", signed_by="test")

        data = _base_constitution_data(
            organization="CryptoTestOrg",
            principal="crypto@test.com",
        )
        const = parse_constitution(data)
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="test")

        assert signed.provenance.signature is not None
        assert signed.provenance.signature.value is not None

        # Verify the Ed25519 signature
        assert verify_constitution_full(signed, str(pub_path))


# =============================================================================
# TEST 2: Constitution without extra identity fields
# =============================================================================

class TestConstitutionNoExtensions:
    """Constitutions without extra identity fields have empty extensions and unchanged hash."""

    def test_empty_extensions(self):
        """Standard identity produces empty extensions dict."""
        data = _base_constitution_data()
        const = parse_constitution(data)
        assert const.identity.extensions == {}

    def test_hash_unchanged(self):
        """Hash of constitution without extensions is stable.

        Backward compat: empty extensions don't change the hash.
        """
        data = _base_constitution_data()
        const = parse_constitution(data)

        # _identity_dict strips empty extensions for backward compat
        id_dict = _identity_dict(const.identity)
        assert "extensions" not in id_dict

    def test_identity_dict_includes_nonempty_extensions(self):
        """_identity_dict flattens extensions into top level."""
        identity = AgentIdentity(
            agent_name="test",
            domain="testing",
            extensions={"org": "Acme"},
        )
        id_dict = _identity_dict(identity)
        assert id_dict["org"] == "Acme"
        assert "extensions" not in id_dict

    def test_existing_constitutions_still_load(self):
        """All existing test constitutions load without hash mismatch."""
        const_dir = Path(__file__).parent / "constitutions"
        for yaml_file in const_dir.glob("*.yaml"):
            # Should not raise SannaConstitutionError
            load_constitution(str(yaml_file))


# =============================================================================
# TEST 3: Receipt with empty extensions — fingerprint matches
# =============================================================================

class TestReceiptEmptyExtensions:
    """Receipts with empty extensions verify correctly."""

    def test_empty_extensions_fingerprint_matches(self):
        """Receipt with extensions={} verifies (extensions not in fingerprint when empty)."""
        receipt = _make_receipt(extensions=None)
        assert receipt["extensions"] == {}

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert result.valid, f"Expected valid, got errors: {result.errors}"

    def test_empty_extensions_same_as_no_extensions(self):
        """Empty extensions don't affect the fingerprint formula."""
        receipt = _make_receipt(extensions=None)
        fp_match, computed, expected = verify_fingerprint(receipt)
        assert fp_match


# =============================================================================
# TEST 4: Receipt extensions included in fingerprint
# =============================================================================

class TestReceiptExtensionsInFingerprint:
    """Non-empty extensions are included in the receipt fingerprint."""

    def test_extensions_change_fingerprint(self):
        """Receipt with extensions has different fingerprint than without."""
        receipt_empty = _make_receipt(extensions=None)
        receipt_ext = _make_receipt(extensions={"vendor": "test"})

        assert receipt_empty["receipt_fingerprint"] != receipt_ext["receipt_fingerprint"]

    def test_modified_extensions_detected(self):
        """Tampering with extensions breaks fingerprint verification."""
        receipt = _make_receipt(extensions={"vendor": "test", "version": 1})

        # Verify original passes
        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert result.valid, f"Expected valid, got errors: {result.errors}"

        # Tamper with extensions
        receipt["extensions"]["vendor"] = "tampered"

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert not result.valid
        assert result.exit_code == 3  # fingerprint mismatch

    def test_added_extensions_detected(self):
        """Adding extensions to a receipt without them breaks fingerprint."""
        receipt = _make_receipt(extensions=None)

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert result.valid

        # Add extensions after generation
        receipt["extensions"] = {"injected": "data"}

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert not result.valid
        assert result.exit_code == 3

    def test_removed_extensions_detected(self):
        """Removing extensions from a receipt breaks fingerprint."""
        receipt = _make_receipt(extensions={"vendor": "test"})

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert result.valid

        # Remove extensions
        receipt["extensions"] = {}

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert not result.valid
        assert result.exit_code == 3

    def test_extensions_with_nested_data(self):
        """Extensions with nested dicts/lists verify correctly."""
        extensions = {
            "pipeline": {
                "name": "prod-v2",
                "steps": ["retrieve", "generate", "check"],
                "config": {"max_tokens": 1000},
            },
            "tags": ["production", "v2"],
        }
        receipt = _make_receipt(extensions=extensions)

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert result.valid

    def test_golden_011_verifies(self):
        """Golden receipt 011 (with extensions) still verifies after changes."""
        golden_path = Path(__file__).parent.parent / "golden" / "receipts" / "011_pass_with_extensions.json"
        with open(golden_path) as f:
            receipt = json.load(f)

        result = verify_receipt(receipt, RECEIPT_SCHEMA)
        assert result.valid, f"Golden 011 failed: {result.errors}"
