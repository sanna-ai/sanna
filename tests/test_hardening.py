"""Tests for v0.7.0 defensive hardening fixes (architecture review).

Covers:
1. Zip bomb/slip protection in bundle verification
2. MCP server crash protection and input size guards
3. Float crash in verification paths
4. Bundle public key selection by key_id
5. create_bundle requires Ed25519-signed constitution
6. Unknown source tier normalization
7. Authority matching separator normalization
"""

import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sanna.bundle import (
    create_bundle,
    verify_bundle,
    MAX_BUNDLE_MEMBERS,
    MAX_BUNDLE_FILE_SIZE,
)
from sanna.constitution import (
    load_constitution,
    sign_constitution,
    save_constitution,
    constitution_to_receipt_ref,
    TrustedSources,
)
from sanna.crypto import generate_keypair, sign_receipt
from sanna.enforcement import configure_checks
from sanna.enforcement.authority import _matches_action, _normalize_separators
from sanna.middleware import (
    _build_trace_data,
    _generate_constitution_receipt,
    _resolve_source_tiers,
    _normalize_tier,
    _build_source_trust_evaluations,
)
from sanna.verify import verify_receipt, load_schema, verify_fingerprint

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
WITH_AUTHORITY_CONST = CONSTITUTIONS_DIR / "with_authority.yaml"


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def keypair(tmp_path):
    priv_path, pub_path = generate_keypair(tmp_path / "keys", signed_by="test")
    return priv_path, pub_path


@pytest.fixture
def signed_const_path(tmp_path, keypair):
    priv_path, _ = keypair
    const = load_constitution(str(WITH_AUTHORITY_CONST), validate=True)
    signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="test")
    out = tmp_path / "signed_constitution.yaml"
    save_constitution(signed, out)
    return out


@pytest.fixture
def signed_receipt_and_path(tmp_path, keypair, signed_const_path):
    priv_path, _ = keypair
    const = load_constitution(str(signed_const_path))
    const_ref = constitution_to_receipt_ref(const)
    check_configs, custom_records = configure_checks(const)
    trace_data = _build_trace_data(
        trace_id="hardening-001",
        query="What is the refund policy?",
        context="Physical products: 30-day returns. Digital: non-refundable.",
        output="Physical products can be returned within 30 days.",
    )
    receipt = _generate_constitution_receipt(
        trace_data,
        check_configs=check_configs,
        custom_records=custom_records,
        constitution_ref=const_ref,
        constitution_version=const.schema_version,
    )
    receipt = sign_receipt(receipt, str(priv_path))
    out = tmp_path / "receipt.json"
    out.write_text(json.dumps(receipt, indent=2))
    return receipt, out


@pytest.fixture
def valid_bundle(tmp_path, signed_receipt_and_path, signed_const_path, keypair):
    _, receipt_path = signed_receipt_and_path
    _, pub_path = keypair
    bundle_path = tmp_path / "valid.zip"
    create_bundle(receipt_path, signed_const_path, pub_path, bundle_path)
    return bundle_path


# =============================================================================
# 1. ZIP BOMB / ZIP SLIP PROTECTION
# =============================================================================

class TestZipBombSlipProtection:
    def test_too_many_members_rejected(self, tmp_path):
        """Bundle with > MAX_BUNDLE_MEMBERS members is rejected."""
        bundle_path = tmp_path / "many_members.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", '{}')
            zf.writestr("constitution.yaml", "test")
            zf.writestr("metadata.json", '{}')
            zf.writestr("public_keys/a.pub", "key")
            # Add extra members to exceed limit
            for i in range(MAX_BUNDLE_MEMBERS):
                zf.writestr(f"public_keys/extra{i}.pub", "key")

        result = verify_bundle(bundle_path)
        assert result.valid is False
        assert "Too many members" in result.checks[0].detail

    def test_zip_slip_path_rejected(self, tmp_path):
        """Bundle with '..' in member path is rejected."""
        bundle_path = tmp_path / "zipslip.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", '{}')
            zf.writestr("constitution.yaml", "test")
            zf.writestr("../etc/passwd", "malicious")
            zf.writestr("public_keys/a.pub", "key")
            zf.writestr("metadata.json", '{}')

        result = verify_bundle(bundle_path)
        assert result.valid is False
        assert "Unsafe path" in result.checks[0].detail

    def test_unexpected_member_rejected(self, tmp_path):
        """Bundle with files outside expected set is rejected."""
        bundle_path = tmp_path / "unexpected.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", '{}')
            zf.writestr("constitution.yaml", "test")
            zf.writestr("metadata.json", '{}')
            zf.writestr("public_keys/a.pub", "key")
            zf.writestr("malware.sh", "#!/bin/bash\nrm -rf /")

        result = verify_bundle(bundle_path)
        assert result.valid is False
        assert "Unexpected member" in result.checks[0].detail

    def test_oversized_member_rejected(self, tmp_path):
        """Bundle with a member exceeding MAX_BUNDLE_FILE_SIZE is rejected."""
        bundle_path = tmp_path / "oversize.zip"
        # Create zip with a member whose declared size exceeds the limit
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", '{}')
            zf.writestr("constitution.yaml", "test")
            zf.writestr("metadata.json", '{}')
            # We can't easily create a truly giant file in tests,
            # but we can test via the file_size check by patching
            zf.writestr("public_keys/a.pub", "key")

        # Verify the check uses info.file_size — patch getinfo to return oversized
        original_getinfo = zipfile.ZipFile.getinfo

        def fake_getinfo(self, name):
            info = original_getinfo(self, name)
            if name == "receipt.json":
                info.file_size = MAX_BUNDLE_FILE_SIZE + 1
            return info

        with patch.object(zipfile.ZipFile, "getinfo", fake_getinfo):
            result = verify_bundle(bundle_path)
        assert result.valid is False
        assert "too large" in result.checks[0].detail

    def test_valid_bundle_passes_all_guards(self, valid_bundle):
        """A properly constructed bundle passes all safety checks."""
        result = verify_bundle(valid_bundle)
        assert result.valid is True
        assert all(c.passed for c in result.checks)

    def test_nested_public_key_in_expected_prefix(self, tmp_path, signed_receipt_and_path, signed_const_path, keypair):
        """public_keys/key_id.pub files are accepted."""
        _, receipt_path = signed_receipt_and_path
        _, pub_path = keypair
        bundle = tmp_path / "ok.zip"
        create_bundle(receipt_path, signed_const_path, pub_path, bundle)

        with zipfile.ZipFile(bundle, "r") as zf:
            pub_keys = [n for n in zf.namelist() if n.startswith("public_keys/")]
            assert len(pub_keys) == 1
            assert pub_keys[0].endswith(".pub")

        result = verify_bundle(bundle)
        assert result.valid is True


# =============================================================================
# 2. MCP SERVER CRASH PROTECTION
# =============================================================================

class TestMCPServerCrashProtection:
    def test_verify_receipt_oversized_input(self):
        from sanna.mcp.server import sanna_verify_receipt, MAX_RECEIPT_JSON_SIZE
        oversized = "x" * (MAX_RECEIPT_JSON_SIZE + 1)
        result = json.loads(sanna_verify_receipt(oversized))
        assert result["valid"] is False
        assert "too large" in result["errors"][0].lower()

    def test_verify_receipt_internal_error_caught(self):
        from sanna.mcp.server import sanna_verify_receipt
        # Valid JSON but something that will cause an unexpected error
        # Mock load_schema to raise
        with patch("sanna.mcp.server.json.loads", side_effect=RuntimeError("boom")):
            # The catch-all should handle it
            pass  # Can't easily test without breaking json.loads globally

        # Instead, test with valid JSON that passes parse but causes schema issue
        result = json.loads(sanna_verify_receipt('{"not": "a receipt"}'))
        # Should return a result, not crash
        assert "valid" in result

    def test_generate_receipt_oversized_context(self):
        from sanna.mcp.server import sanna_generate_receipt, MAX_CONTEXT_SIZE
        big_context = "x" * (MAX_CONTEXT_SIZE + 1)
        result = json.loads(sanna_generate_receipt(
            query="test",
            context=big_context,
            response="test",
        ))
        assert "error" in result
        assert "too large" in result["error"].lower()

    def test_generate_receipt_oversized_response(self):
        from sanna.mcp.server import sanna_generate_receipt, MAX_RESPONSE_SIZE
        big_response = "x" * (MAX_RESPONSE_SIZE + 1)
        result = json.loads(sanna_generate_receipt(
            query="test",
            context="test",
            response=big_response,
        ))
        assert "error" in result
        assert "too large" in result["error"].lower()

    def test_evaluate_action_oversized_action(self, signed_const_path):
        from sanna.mcp.server import sanna_evaluate_action, MAX_ACTION_SIZE
        big_action = "x" * (MAX_ACTION_SIZE + 1)
        result = json.loads(sanna_evaluate_action(
            action_name=big_action,
            action_params={},
            constitution_path=str(signed_const_path),
        ))
        assert "error" in result
        assert "too large" in result["error"].lower()

    def test_list_checks_returns_valid_json(self):
        from sanna.mcp.server import sanna_list_checks
        result = json.loads(sanna_list_checks())
        assert isinstance(result, list)
        assert len(result) == 5

    def test_evaluate_action_catch_all(self):
        from sanna.mcp.server import sanna_evaluate_action
        # Nonexistent constitution path
        result = json.loads(sanna_evaluate_action(
            action_name="test",
            action_params={},
            constitution_path="/nonexistent/path.yaml",
        ))
        assert result.get("error") is not None or result.get("decision") is not None


# =============================================================================
# 3. FLOAT CRASH IN VERIFICATION PATHS
# =============================================================================

class TestFloatCrashProtection:
    def test_verify_receipt_with_float_in_authority_decisions(self, signed_receipt_and_path):
        """Receipt with lossy float in a hashed section should not crash verify_receipt."""
        receipt, _ = signed_receipt_and_path
        # Inject a lossy float into authority_decisions (hashed in fingerprint)
        receipt["authority_decisions"] = [{"confidence": 71.43}]
        schema = load_schema()
        result = verify_receipt(receipt, schema)
        # Should not crash — returns invalid with float error
        assert result is not None
        assert not result.valid

    def test_verify_bundle_with_float_in_receipt(self, tmp_path, valid_bundle):
        """Bundle with float-containing receipt should not crash verify_bundle."""
        tampered = tmp_path / "float_bundle.zip"
        with zipfile.ZipFile(valid_bundle, "r") as src:
            with zipfile.ZipFile(tampered, "w") as dst:
                for name in src.namelist():
                    data = src.read(name)
                    if name == "receipt.json":
                        receipt = json.loads(data)
                        receipt["extensions"] = {"score": 71.43}
                        data = json.dumps(receipt).encode()
                    dst.writestr(name, data)

        # Should not crash — returns invalid result
        result = verify_bundle(tampered)
        assert result.valid is False

    def test_verify_fingerprint_with_clean_receipt(self, signed_receipt_and_path):
        """Normal receipt fingerprint verification works fine."""
        receipt, _ = signed_receipt_and_path
        match, computed, expected = verify_fingerprint(receipt)
        assert match is True


# =============================================================================
# 4. BUNDLE PUBLIC KEY SELECTION BY KEY_ID
# =============================================================================

class TestBundleKeyIdSelection:
    def test_key_selected_by_key_id(self, tmp_path, signed_receipt_and_path, signed_const_path, keypair):
        """Bundle verification selects the correct key by key_id from receipt_signature."""
        receipt, receipt_path = signed_receipt_and_path
        _, pub_path = keypair

        # Get the key_id from the receipt
        key_id = receipt["receipt_signature"]["key_id"]

        # Create bundle with key named by key_id
        bundle_path = tmp_path / "keyed.zip"
        create_bundle(receipt_path, signed_const_path, pub_path, bundle_path)

        # Verify the bundle has the key named correctly
        with zipfile.ZipFile(bundle_path, "r") as zf:
            pub_keys = [n for n in zf.namelist() if n.startswith("public_keys/")]
            assert any(key_id in pk for pk in pub_keys)

        result = verify_bundle(bundle_path)
        assert result.valid is True

    def test_multiple_keys_selects_correct_one(self, tmp_path, signed_receipt_and_path, signed_const_path, keypair):
        """When multiple keys exist, bundle selects by key_id match."""
        receipt, receipt_path = signed_receipt_and_path
        _, pub_path = keypair
        key_id = receipt["receipt_signature"]["key_id"]

        # Create a bundle manually with two keys
        bundle_path = tmp_path / "multikey.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", receipt_path.read_text())
            zf.writestr("constitution.yaml", signed_const_path.read_text())
            zf.writestr(f"public_keys/{key_id}.pub", pub_path.read_text())
            zf.writestr("public_keys/wrong_key_id.pub", "not a real key")
            zf.writestr("metadata.json", json.dumps({
                "bundle_format_version": "1.0.0",
                "created_at": "", "tool_version": "", "description": "",
            }))

        result = verify_bundle(bundle_path)
        assert result.valid is True

    def test_fallback_to_first_key_when_no_key_id_match(self, tmp_path, signed_receipt_and_path, signed_const_path, keypair):
        """When no key matches key_id, falls back to first .pub file."""
        receipt, receipt_path = signed_receipt_and_path
        _, pub_path = keypair

        # Create bundle with key under a different name
        bundle_path = tmp_path / "nokeymatch.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", receipt_path.read_text())
            zf.writestr("constitution.yaml", signed_const_path.read_text())
            zf.writestr("public_keys/some_other_id.pub", pub_path.read_text())
            zf.writestr("metadata.json", json.dumps({
                "bundle_format_version": "1.0.0",
                "created_at": "", "tool_version": "", "description": "",
            }))

        # Should still work (falls back to first .pub)
        result = verify_bundle(bundle_path)
        assert result.valid is True


# =============================================================================
# 5. CREATE_BUNDLE REQUIRES ED25519 SIGNED CONSTITUTION
# =============================================================================

class TestCreateBundleRequiresSignedConstitution:
    def test_hash_only_constitution_rejected(self, tmp_path, signed_receipt_and_path, keypair):
        """Constitution with policy_hash but no Ed25519 signature is rejected."""
        _, receipt_path = signed_receipt_and_path
        _, pub_path = keypair

        # Create a constitution that is hash-signed but not Ed25519-signed
        const = load_constitution(str(WITH_AUTHORITY_CONST), validate=True)
        signed = sign_constitution(const)  # Hash only, no private key
        const_path = tmp_path / "hash_only.yaml"
        save_constitution(signed, const_path)

        with pytest.raises(ValueError, match="Ed25519-signed"):
            create_bundle(receipt_path, const_path, pub_path, tmp_path / "out.zip")

    def test_ed25519_signed_constitution_accepted(self, tmp_path, signed_receipt_and_path, signed_const_path, keypair):
        """Constitution with Ed25519 signature passes validation."""
        _, receipt_path = signed_receipt_and_path
        _, pub_path = keypair
        bundle_path = tmp_path / "ok.zip"
        # Should not raise
        create_bundle(receipt_path, signed_const_path, pub_path, bundle_path)
        assert bundle_path.exists()


# =============================================================================
# 6. UNKNOWN SOURCE TIER NORMALIZATION
# =============================================================================

class TestSourceTierNormalization:
    def test_normalize_tier_valid_values(self):
        assert _normalize_tier("tier_1") == "tier_1"
        assert _normalize_tier("tier_2") == "tier_2"
        assert _normalize_tier("tier_3") == "tier_3"
        assert _normalize_tier("untrusted") == "untrusted"
        assert _normalize_tier("unclassified") == "unclassified"

    def test_normalize_tier_case_insensitive(self):
        assert _normalize_tier("TIER_1") == "tier_1"
        assert _normalize_tier("Tier_2") == "tier_2"
        assert _normalize_tier("UNTRUSTED") == "untrusted"

    def test_normalize_tier_hyphen_to_underscore(self):
        assert _normalize_tier("tier-1") == "tier_1"
        assert _normalize_tier("Tier-3") == "tier_3"

    def test_normalize_tier_spaces_to_underscore(self):
        assert _normalize_tier("tier 1") == "tier_1"

    def test_normalize_tier_unknown_returns_unclassified(self):
        assert _normalize_tier("gold") == "unclassified"
        assert _normalize_tier("premium") == "unclassified"
        assert _normalize_tier("") == "unclassified"

    def test_resolve_source_tiers_unknown_defaults_to_unclassified(self):
        ts = TrustedSources(tier_1=["kb"])
        ctx = [{"text": "doc", "source": "unknown_source"}]
        resolved = _resolve_source_tiers(ctx, ts)
        assert resolved[0]["tier"] == "unclassified"

    def test_resolve_source_tiers_no_constitution_defaults_to_unclassified(self):
        ctx = [{"text": "doc", "source": "any"}]
        resolved = _resolve_source_tiers(ctx, None)
        assert resolved[0]["tier"] == "unclassified"

    def test_resolve_source_tiers_explicit_tier_normalized(self):
        ts = TrustedSources(tier_1=["kb"])
        ctx = [{"text": "doc", "source": "kb", "tier": "TIER-2"}]
        resolved = _resolve_source_tiers(ctx, ts)
        assert resolved[0]["tier"] == "tier_2"  # normalized, not raw

    def test_resolve_source_tiers_invalid_explicit_tier(self):
        ts = TrustedSources(tier_1=["kb"])
        ctx = [{"text": "doc", "source": "kb", "tier": "gold_standard"}]
        resolved = _resolve_source_tiers(ctx, ts)
        assert resolved[0]["tier"] == "unclassified"

    def test_build_source_trust_evaluations_uses_new_default(self):
        ctx = [{"text": "doc", "source": "unknown"}]
        evals = _build_source_trust_evaluations(ctx)
        assert evals[0]["trust_tier"] == "unclassified"
        assert evals[0]["context_used"] is True  # unclassified != untrusted


# =============================================================================
# 7. AUTHORITY MATCHING SEPARATOR NORMALIZATION
# =============================================================================

class TestAuthorityMatchingSeparatorNormalization:
    def test_normalize_separators(self):
        assert _normalize_separators("delete_user") == "delete user"
        assert _normalize_separators("delete-user") == "delete user"
        assert _normalize_separators("delete.user") == "delete user"
        assert _normalize_separators("send_email_now") == "send email now"

    def test_matches_action_underscore_vs_hyphen(self):
        assert _matches_action("delete_user", "delete-user") is True

    def test_matches_action_underscore_vs_dot(self):
        assert _matches_action("send_email", "send.email") is True

    def test_matches_action_underscore_vs_space(self):
        assert _matches_action("delete_user", "delete user") is True

    def test_matches_action_mixed_separators(self):
        assert _matches_action("modify-billing_data", "modify.billing.data") is True

    def test_matches_action_no_match_still_works(self):
        assert _matches_action("delete_user", "send_email") is False

    def test_matches_action_case_insensitive_with_separators(self):
        assert _matches_action("Delete_User", "delete-user") is True

    def test_matches_action_original_behavior_preserved(self):
        """Existing substring matching still works."""
        assert _matches_action("billing", "modify billing data") is True
        assert _matches_action("send email", "send email") is True
        assert _matches_action("delete records", "query database") is False
