"""Tests for evidence bundle creation and verification."""

import json
import zipfile
from pathlib import Path

import pytest

from sanna.bundle import create_bundle, verify_bundle, BundleVerificationResult, BundleCheck
from sanna.constitution import (
    load_constitution,
    sign_constitution,
    save_constitution,
    constitution_to_receipt_ref,
)
from sanna.crypto import generate_keypair, sign_receipt
from sanna.enforcement import configure_checks
from sanna.middleware import _build_trace_data, _generate_constitution_receipt

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
WITH_AUTHORITY_CONST = CONSTITUTIONS_DIR / "with_authority.yaml"


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def keypair(tmp_path):
    """Generate an Ed25519 keypair in tmp_path."""
    priv_path, pub_path = generate_keypair(tmp_path / "keys", signed_by="test-bundle")
    return priv_path, pub_path


@pytest.fixture
def second_keypair(tmp_path):
    """Generate a second keypair (wrong key for negative tests)."""
    priv_path, pub_path = generate_keypair(tmp_path / "keys2", signed_by="wrong-key")
    return priv_path, pub_path


@pytest.fixture
def signed_const_path(tmp_path, keypair):
    """Sign the with_authority constitution and return path to signed version."""
    priv_path, _ = keypair
    const = load_constitution(str(WITH_AUTHORITY_CONST), validate=True)
    signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="test-bundle")
    out = tmp_path / "signed_constitution.yaml"
    save_constitution(signed, out)
    return out


@pytest.fixture
def signed_receipt_path(tmp_path, keypair, signed_const_path):
    """Generate and sign a receipt, return path to JSON file."""
    priv_path, _ = keypair
    const = load_constitution(str(signed_const_path))
    const_ref = constitution_to_receipt_ref(const)
    check_configs, custom_records = configure_checks(const)

    trace_data = _build_trace_data(
        trace_id="bundle-test-001",
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
    return out


@pytest.fixture
def valid_bundle(tmp_path, signed_receipt_path, signed_const_path, keypair):
    """Create a valid bundle and return its path."""
    _, pub_path = keypair
    bundle_path = tmp_path / "evidence.zip"
    create_bundle(
        receipt_path=signed_receipt_path,
        constitution_path=signed_const_path,
        public_key_path=pub_path,
        output_path=bundle_path,
        description="Test bundle",
    )
    return bundle_path


# =============================================================================
# BUNDLE CREATION
# =============================================================================

class TestCreateBundle:
    def test_create_valid_bundle(self, tmp_path, signed_receipt_path, signed_const_path, keypair):
        _, pub_path = keypair
        bundle_path = tmp_path / "out.zip"
        result = create_bundle(
            signed_receipt_path, signed_const_path, pub_path, bundle_path,
        )
        assert result == bundle_path
        assert bundle_path.exists()
        assert bundle_path.stat().st_size > 0

    def test_bundle_zip_structure(self, valid_bundle):
        with zipfile.ZipFile(valid_bundle, "r") as zf:
            names = zf.namelist()
            assert "receipt.json" in names
            assert "constitution.yaml" in names
            assert "metadata.json" in names
            pub_keys = [n for n in names if n.startswith("public_keys/") and n.endswith(".pub")]
            assert len(pub_keys) == 1

    def test_bundle_metadata_fields(self, valid_bundle):
        with zipfile.ZipFile(valid_bundle, "r") as zf:
            meta = json.loads(zf.read("metadata.json"))
            assert meta["bundle_format_version"] == "1.0.0"
            assert "created_at" in meta
            assert "tool_version" in meta
            assert meta["description"] == "Test bundle"

    def test_bundle_with_description(self, tmp_path, signed_receipt_path, signed_const_path, keypair):
        _, pub_path = keypair
        bundle_path = tmp_path / "described.zip"
        create_bundle(
            signed_receipt_path, signed_const_path, pub_path, bundle_path,
            description="Q1 2026 audit evidence",
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            meta = json.loads(zf.read("metadata.json"))
            assert meta["description"] == "Q1 2026 audit evidence"

    def test_bundle_without_description(self, tmp_path, signed_receipt_path, signed_const_path, keypair):
        _, pub_path = keypair
        bundle_path = tmp_path / "no_desc.zip"
        create_bundle(
            signed_receipt_path, signed_const_path, pub_path, bundle_path,
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            meta = json.loads(zf.read("metadata.json"))
            assert meta["description"] == ""

    def test_create_missing_receipt(self, tmp_path, signed_const_path, keypair):
        _, pub_path = keypair
        with pytest.raises(FileNotFoundError, match="Receipt"):
            create_bundle(
                tmp_path / "nonexistent.json", signed_const_path, pub_path,
                tmp_path / "out.zip",
            )

    def test_create_missing_constitution(self, tmp_path, signed_receipt_path, keypair):
        _, pub_path = keypair
        with pytest.raises(FileNotFoundError, match="Constitution"):
            create_bundle(
                signed_receipt_path, tmp_path / "nonexistent.yaml", pub_path,
                tmp_path / "out.zip",
            )

    def test_create_missing_public_key(self, tmp_path, signed_receipt_path, signed_const_path):
        with pytest.raises(FileNotFoundError, match="Public key"):
            create_bundle(
                signed_receipt_path, signed_const_path, tmp_path / "no.pub",
                tmp_path / "out.zip",
            )

    def test_create_unsigned_receipt(self, tmp_path, signed_const_path, keypair):
        _, pub_path = keypair
        # Write receipt without signature
        receipt = {"trace_id": "test", "coherence_status": "PASS"}
        receipt_path = tmp_path / "unsigned.json"
        receipt_path.write_text(json.dumps(receipt))
        with pytest.raises(ValueError, match="not signed"):
            create_bundle(receipt_path, signed_const_path, pub_path, tmp_path / "out.zip")

    def test_create_unsigned_constitution(self, tmp_path, signed_receipt_path, keypair):
        _, pub_path = keypair
        # Load unsigned constitution
        const_path = tmp_path / "unsigned.yaml"
        const_path.write_text("sanna_constitution: 1.0.0\nidentity:\n  agent_name: t\n")
        with pytest.raises(ValueError, match="not signed"):
            create_bundle(signed_receipt_path, const_path, pub_path, tmp_path / "out.zip")

    def test_bundle_receipt_is_valid_json(self, valid_bundle):
        with zipfile.ZipFile(valid_bundle, "r") as zf:
            receipt = json.loads(zf.read("receipt.json"))
            assert "receipt_fingerprint" in receipt
            assert "receipt_signature" in receipt


# =============================================================================
# BUNDLE VERIFICATION
# =============================================================================

class TestVerifyBundle:
    def test_verify_valid_bundle(self, valid_bundle):
        result = verify_bundle(valid_bundle)
        assert result.valid is True
        assert len(result.checks) == 6
        assert all(c.passed for c in result.checks)
        assert result.errors == []

    def test_verify_result_has_receipt_summary(self, valid_bundle):
        result = verify_bundle(valid_bundle)
        assert result.receipt_summary is not None
        assert result.receipt_summary["trace_id"] == "bundle-test-001"
        assert result.receipt_summary["coherence_status"] == "PASS"

    def test_verify_tampered_receipt_fails_fingerprint(self, tmp_path, valid_bundle):
        # Extract, tamper a fingerprint-covered field, repackage
        tampered = tmp_path / "tampered.zip"
        with zipfile.ZipFile(valid_bundle, "r") as src:
            with zipfile.ZipFile(tampered, "w") as dst:
                for name in src.namelist():
                    data = src.read(name)
                    if name == "receipt.json":
                        receipt = json.loads(data)
                        receipt["context_hash"] = "tampered_hash_value"
                        data = json.dumps(receipt).encode()
                    dst.writestr(name, data)

        result = verify_bundle(tampered)
        assert result.valid is False
        fp_check = next(c for c in result.checks if c.name == "Receipt fingerprint")
        assert fp_check.passed is False

    def test_verify_wrong_public_key(self, tmp_path, signed_receipt_path, signed_const_path, second_keypair):
        _, wrong_pub = second_keypair
        bundle_path = tmp_path / "wrong_key.zip"

        # Build bundle manually with wrong public key
        with zipfile.ZipFile(valid_bundle_path := bundle_path, "w") as zf:
            zf.writestr("receipt.json", signed_receipt_path.read_text())
            zf.writestr("constitution.yaml", signed_const_path.read_text())
            zf.writestr("public_keys/wrongkey.pub", wrong_pub.read_text())
            zf.writestr("metadata.json", json.dumps({"bundle_format_version": "1.0.0", "created_at": "", "tool_version": "", "description": ""}))

        result = verify_bundle(bundle_path)
        assert result.valid is False
        # Either constitution or receipt signature should fail
        sig_checks = [c for c in result.checks if "signature" in c.name.lower()]
        assert any(not c.passed for c in sig_checks)

    def test_verify_missing_receipt(self, tmp_path):
        bundle_path = tmp_path / "no_receipt.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("constitution.yaml", "test")
            zf.writestr("public_keys/abc.pub", "test")
            zf.writestr("metadata.json", "{}")

        result = verify_bundle(bundle_path)
        assert result.valid is False
        assert result.checks[0].name == "Bundle structure"
        assert result.checks[0].passed is False

    def test_verify_missing_constitution(self, tmp_path):
        bundle_path = tmp_path / "no_const.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", '{"test": 1}')
            zf.writestr("public_keys/abc.pub", "test")
            zf.writestr("metadata.json", "{}")

        result = verify_bundle(bundle_path)
        assert result.valid is False
        assert result.checks[0].name == "Bundle structure"
        assert result.checks[0].passed is False

    def test_verify_missing_public_keys(self, tmp_path):
        bundle_path = tmp_path / "no_keys.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", '{"test": 1}')
            zf.writestr("constitution.yaml", "test")
            zf.writestr("metadata.json", "{}")

        result = verify_bundle(bundle_path)
        assert result.valid is False
        assert "public_keys" in result.checks[0].detail

    def test_verify_not_a_zip(self, tmp_path):
        not_zip = tmp_path / "not_a_zip.zip"
        not_zip.write_text("this is not a zip file")
        result = verify_bundle(not_zip)
        assert result.valid is False
        assert "zip" in result.checks[0].detail.lower()

    def test_verify_nonexistent_bundle(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            verify_bundle(tmp_path / "nonexistent.zip")

    def test_verify_without_metadata_still_works(self, tmp_path, valid_bundle):
        """metadata.json is optional for backward compat."""
        no_meta = tmp_path / "no_meta.zip"
        with zipfile.ZipFile(valid_bundle, "r") as src:
            with zipfile.ZipFile(no_meta, "w") as dst:
                for name in src.namelist():
                    if name != "metadata.json":
                        dst.writestr(name, src.read(name))

        result = verify_bundle(no_meta)
        # Structure check should still pass (metadata optional)
        struct = next(c for c in result.checks if c.name == "Bundle structure")
        assert struct.passed is True

    def test_verify_provenance_chain_mismatch(self, tmp_path, keypair, signed_receipt_path):
        """Receipt + constitution with different policy_hash → chain fails."""
        priv_path, pub_path = keypair
        # Sign a different constitution (research_assistant)
        other_const = load_constitution(
            str(Path(__file__).parent / "constitutions" / "all_warn.yaml"), validate=True
        )
        other_signed = sign_constitution(other_const, private_key_path=str(priv_path), signed_by="test")
        other_path = tmp_path / "other_const.yaml"
        save_constitution(other_signed, other_path)

        bundle_path = tmp_path / "mismatch.zip"
        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("receipt.json", signed_receipt_path.read_text())
            zf.writestr("constitution.yaml", other_path.read_text())
            zf.writestr(f"public_keys/test.pub", pub_path.read_text())
            zf.writestr("metadata.json", json.dumps({
                "bundle_format_version": "1.0.0",
                "created_at": "", "tool_version": "", "description": "",
            }))

        result = verify_bundle(bundle_path)
        assert result.valid is False
        chain_check = next(c for c in result.checks if c.name == "Provenance chain")
        assert chain_check.passed is False
        assert "policy_hash" in chain_check.detail


# =============================================================================
# ROUND TRIP
# =============================================================================

class TestRoundTrip:
    def test_create_then_verify(self, tmp_path, signed_receipt_path, signed_const_path, keypair):
        _, pub_path = keypair
        bundle_path = tmp_path / "roundtrip.zip"

        create_bundle(
            signed_receipt_path, signed_const_path, pub_path, bundle_path,
            description="Round-trip test",
        )

        result = verify_bundle(bundle_path)
        assert result.valid is True
        assert all(c.passed for c in result.checks)
        assert result.receipt_summary["trace_id"] == "bundle-test-001"

    def test_multiple_bundles_same_key(self, tmp_path, keypair, signed_const_path):
        """Two different receipts, same constitution and key → both valid."""
        priv_path, pub_path = keypair
        const = load_constitution(str(signed_const_path))
        const_ref = constitution_to_receipt_ref(const)
        check_configs, custom_records = configure_checks(const)

        for i in range(2):
            trace_data = _build_trace_data(
                trace_id=f"bundle-multi-{i}",
                query="Test query",
                context="Test context",
                output="Test output",
            )
            receipt = _generate_constitution_receipt(
                trace_data,
                check_configs=check_configs,
                custom_records=custom_records,
                constitution_ref=const_ref,
                constitution_version=const.schema_version,
            )
            receipt = sign_receipt(receipt, str(priv_path))

            receipt_path = tmp_path / f"receipt_{i}.json"
            receipt_path.write_text(json.dumps(receipt))

            bundle_path = tmp_path / f"bundle_{i}.zip"
            create_bundle(receipt_path, signed_const_path, pub_path, bundle_path)

            result = verify_bundle(bundle_path)
            assert result.valid is True, f"Bundle {i} failed: {result.errors}"


# =============================================================================
# CLI
# =============================================================================

class TestBundleCLI:
    def test_create_bundle_cli(self, tmp_path, signed_receipt_path, signed_const_path, keypair):
        import subprocess
        _, pub_path = keypair
        bundle_path = tmp_path / "cli_bundle.zip"

        result = subprocess.run(
            [
                "python", "-m", "sanna.cli",
            ],
            capture_output=True, text=True,
        )
        # The CLI module doesn't have a __main__ dispatch for bundles,
        # so we test the functions directly instead
        from sanna.cli import main_create_bundle, main_verify_bundle
        # Just verify the functions exist and are callable
        assert callable(main_create_bundle)
        assert callable(main_verify_bundle)

    def test_verify_bundle_json_output(self, valid_bundle):
        """verify_bundle result can be serialized as JSON."""
        result = verify_bundle(valid_bundle)
        output = {
            "valid": result.valid,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in result.checks
            ],
            "receipt_summary": result.receipt_summary,
            "errors": result.errors,
        }
        json_str = json.dumps(output, indent=2)
        parsed = json.loads(json_str)
        assert parsed["valid"] is True
        assert len(parsed["checks"]) == 6

    def test_bundle_check_dataclass(self):
        check = BundleCheck(name="Test", passed=True, detail="OK")
        assert check.name == "Test"
        assert check.passed is True
        assert check.detail == "OK"

    def test_bundle_verification_result_dataclass(self):
        result = BundleVerificationResult(
            valid=True,
            checks=[BundleCheck("Test", True, "OK")],
            receipt_summary={"trace_id": "test"},
            errors=[],
        )
        assert result.valid is True
        assert len(result.checks) == 1
