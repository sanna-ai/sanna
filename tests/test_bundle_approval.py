"""Tests for evidence bundle approval integration (Block 5, v0.9.0).

Covers approval metadata in bundles, approver public key inclusion,
approval verification in verify_bundle, and governance_summary.
"""

import json
import zipfile
from pathlib import Path

import pytest

from sanna.bundle import create_bundle, verify_bundle
from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    Invariant,
    sign_constitution,
    save_constitution,
    load_constitution,
    approve_constitution,
)
from sanna.crypto import generate_keypair, sign_receipt
from sanna.middleware import sanna_observe


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def approved_bundle_setup(tmp_path):
    """Create a signed+approved constitution, receipt, and keys for bundle tests."""
    # Keys
    author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
    approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")

    # Constitution
    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="bundle-test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="author@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="manual",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
    )
    signed = sign_constitution(const, private_key_path=str(author_priv))
    const_path = tmp_path / "approved.yaml"
    save_constitution(signed, const_path)
    approve_constitution(const_path, approver_priv, "jane@co.com", "VP Risk", "1.0", verify_author_sig=False)

    # Generate receipt
    @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(author_priv))
    def agent(query, context):
        return "The answer is grounded in context."

    result = agent(query="test?", context="Context about testing.")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(result.receipt, indent=2))

    return {
        "const_path": const_path,
        "receipt_path": receipt_path,
        "author_priv": author_priv,
        "author_pub": author_pub,
        "approver_priv": approver_priv,
        "approver_pub": approver_pub,
        "tmp_path": tmp_path,
    }


@pytest.fixture
def unapproved_bundle_setup(tmp_path):
    """Create a signed but NOT approved constitution and receipt."""
    author_priv, author_pub = generate_keypair(tmp_path / "keys")
    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="unapproved-agent", domain="testing"),
        provenance=Provenance(
            authored_by="a@a.com", approved_by=["b@b.com"],
            approval_date="2026-01-01", approval_method="manual",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
    )
    signed = sign_constitution(const, private_key_path=str(author_priv))
    const_path = tmp_path / "unapproved.yaml"
    save_constitution(signed, const_path)

    @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(author_priv))
    def agent(query, context):
        return "The answer is grounded in context."

    result = agent(query="test?", context="Context about testing.")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(result.receipt, indent=2))

    return {
        "const_path": const_path,
        "receipt_path": receipt_path,
        "author_pub": author_pub,
        "tmp_path": tmp_path,
    }


# =============================================================================
# Bundle creation with approval
# =============================================================================

class TestBundleApprovalCreation:
    def test_bundle_with_approved_constitution_has_approval_metadata(self, approved_bundle_setup):
        """Bundle metadata includes approval fields when constitution is approved."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "approved.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata.json"))
        assert metadata["approval_status"] == "approved"
        assert metadata["approver_id"] == "jane@co.com"
        assert metadata["approver_role"] == "VP Risk"
        assert metadata["constitution_version"] == "1.0"
        assert len(metadata["content_hash"]) == 64

    def test_bundle_with_unapproved_constitution_marks_unapproved(self, unapproved_bundle_setup):
        """Bundle metadata marks status as unapproved when no approval."""
        s = unapproved_bundle_setup
        bundle_path = s["tmp_path"] / "unapproved.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata.json"))
        assert metadata["approval_status"] == "unapproved"
        assert "approver_id" not in metadata or metadata.get("approver_id") is None

    def test_bundle_includes_approver_public_key(self, approved_bundle_setup):
        """Bundle includes approver's public key when provided."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "with_approver_key.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            pub_keys = [n for n in zf.namelist() if n.startswith("public_keys/")]
        # Should have 2 public keys (author + approver)
        assert len(pub_keys) == 2

    def test_bundle_governance_summary_present(self, approved_bundle_setup):
        """Bundle metadata includes governance_summary."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "summary.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata.json"))
        gs = metadata.get("governance_summary")
        assert gs is not None
        assert gs["constitution_author"] == "author@test.com"
        assert "jane@co.com" in gs["constitution_approved_by"]
        assert gs["constitution_version"] == "1.0"

    def test_governance_summary_verified_true_with_approver_key(self, approved_bundle_setup):
        """governance_summary.constitution_approval_verified is True when approver key provided."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "verified_flag.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata.json"))
        gs = metadata["governance_summary"]
        assert gs["constitution_approval_verified"] is True

    def test_governance_summary_verified_false_without_approver_key(self, approved_bundle_setup):
        """governance_summary.constitution_approval_verified is False without approver key."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "unverified_flag.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            # No approver key
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata.json"))
        gs = metadata["governance_summary"]
        assert gs["constitution_approval_verified"] is False

    def test_unapproved_governance_summary_no_approver(self, unapproved_bundle_setup):
        """Unapproved bundle governance_summary has no approver info."""
        s = unapproved_bundle_setup
        bundle_path = s["tmp_path"] / "summary_unapproved.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
        )
        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata.json"))
        gs = metadata.get("governance_summary")
        assert gs is not None
        assert "constitution_approved_by" not in gs


# =============================================================================
# Bundle verification with approval
# =============================================================================

class TestBundleApprovalVerification:
    def test_verify_approved_bundle_passes(self, approved_bundle_setup):
        """verify_bundle passes for a properly approved bundle."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "verify_approved.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        result = verify_bundle(bundle_path)
        assert result.valid is True
        approval_check = [c for c in result.checks if c.name == "Approval verification"]
        assert len(approval_check) == 1
        assert approval_check[0].passed is True
        assert "jane@co.com" in approval_check[0].detail

    def test_verify_unapproved_bundle_passes(self, unapproved_bundle_setup):
        """verify_bundle passes for unapproved (approval is optional)."""
        s = unapproved_bundle_setup
        bundle_path = s["tmp_path"] / "verify_unapproved.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
        )
        result = verify_bundle(bundle_path)
        assert result.valid is True
        approval_check = [c for c in result.checks if c.name == "Approval verification"]
        assert len(approval_check) == 1
        assert approval_check[0].passed is True

    def test_verify_tampered_constitution_fails(self, approved_bundle_setup):
        """Tampering with constitution after approval breaks verification."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "tampered.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        # Tamper with constitution inside the bundle
        tampered_path = s["tmp_path"] / "tampered_bundle.zip"
        with zipfile.ZipFile(bundle_path, "r") as src:
            with zipfile.ZipFile(tampered_path, "w") as dst:
                for name in src.namelist():
                    data = src.read(name)
                    if name == "constitution.yaml":
                        # Tamper with the constitution content
                        data = data.replace(b"bundle-test-agent", b"tampered-agent")
                    dst.writestr(name, data)
        result = verify_bundle(tampered_path)
        assert result.valid is False

    def test_bundle_round_trip_create_verify(self, approved_bundle_setup):
        """Full round-trip: create → verify → all pass."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "roundtrip.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        result = verify_bundle(bundle_path)
        assert result.valid is True
        assert all(c.passed for c in result.checks)
        assert result.errors == []

    def test_approval_signature_verified_with_key_in_bundle(self, approved_bundle_setup):
        """When approver key is in the bundle, approval signature is verified."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "sig_verified.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        result = verify_bundle(bundle_path)
        approval_check = [c for c in result.checks if c.name == "Approval verification"][0]
        assert "signature verified" in approval_check.detail.lower()

    def test_approval_without_approver_key_still_passes(self, approved_bundle_setup):
        """When approver key not in bundle, approval passes but with warning."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "no_approver_key.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            # No approver key
        )
        result = verify_bundle(bundle_path)
        assert result.valid is True
        approval_check = [c for c in result.checks if c.name == "Approval verification"][0]
        assert approval_check.passed is True
        assert "warning" in approval_check.detail.lower()
        assert "not verified" in approval_check.detail.lower()


# =============================================================================
# CRITICAL-1: Approval signature enforcement
# =============================================================================

class TestBundleApprovalSignatureEnforcement:
    def test_empty_approval_signature_fails_verification(self, approved_bundle_setup):
        """Approved constitution with empty approval_signature fails bundle verification."""
        import yaml
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "empty_sig.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        # Tamper: blank out the approval_signature inside the bundle
        tampered_path = s["tmp_path"] / "empty_sig_tampered.zip"
        with zipfile.ZipFile(bundle_path, "r") as src:
            with zipfile.ZipFile(tampered_path, "w") as dst:
                for name in src.namelist():
                    data = src.read(name)
                    if name == "constitution.yaml":
                        const_data = yaml.safe_load(data)
                        const_data["approval"]["records"][0]["approval_signature"] = ""
                        data = yaml.dump(const_data, default_flow_style=False).encode()
                    dst.writestr(name, data)
        result = verify_bundle(tampered_path)
        approval_check = [c for c in result.checks if c.name == "Approval verification"]
        assert len(approval_check) == 1
        assert approval_check[0].passed is False
        assert "missing" in approval_check[0].detail.lower() or "empty" in approval_check[0].detail.lower()

    def test_approval_sig_present_but_no_key_passes_with_warning(self, approved_bundle_setup):
        """Approval signature exists but no approver key — passes with warning."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "sig_no_key.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            # No approver key
        )
        result = verify_bundle(bundle_path)
        assert result.valid is True
        approval_check = [c for c in result.checks if c.name == "Approval verification"][0]
        assert approval_check.passed is True
        assert "not verified" in approval_check.detail.lower()

    def test_valid_signature_and_key_passes_fully_verified(self, approved_bundle_setup):
        """Approval with valid signature AND key passes with 'signature verified'."""
        s = approved_bundle_setup
        bundle_path = s["tmp_path"] / "full_verify.zip"
        create_bundle(
            receipt_path=s["receipt_path"],
            constitution_path=s["const_path"],
            public_key_path=s["author_pub"],
            output_path=bundle_path,
            approver_public_key_path=s["approver_pub"],
        )
        result = verify_bundle(bundle_path)
        assert result.valid is True
        approval_check = [c for c in result.checks if c.name == "Approval verification"][0]
        assert approval_check.passed is True
        assert "signature verified" in approval_check.detail.lower()


# =============================================================================
# HIGH-1: Independent key resolution in bundles
# =============================================================================

class TestBundleKeyResolution:
    def test_separate_constitution_key_included_in_bundle(self, tmp_path):
        """When constitution_public_key_path differs from public_key_path, both are bundled."""
        # Two separate keypairs: one for receipts, one for constitution
        receipt_priv, receipt_pub = generate_keypair(tmp_path / "receipt_keys")
        const_priv, const_pub = generate_keypair(tmp_path / "const_keys")

        # Constitution signed by const_priv
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="dual-key-agent", domain="testing"),
            provenance=Provenance(
                authored_by="author@test.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(const_priv))
        const_path = tmp_path / "dual.yaml"
        save_constitution(signed, const_path)

        # Receipt signed by receipt_priv (different key)
        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(receipt_priv))
        def agent(query, context):
            return "Answer grounded in context."

        result = agent(query="test?", context="Context.")
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(result.receipt, indent=2))

        # Bundle with separate constitution key
        bundle_path = tmp_path / "dual_key.zip"
        create_bundle(
            receipt_path=receipt_path,
            constitution_path=const_path,
            public_key_path=receipt_pub,
            output_path=bundle_path,
            constitution_public_key_path=const_pub,
        )

        with zipfile.ZipFile(bundle_path, "r") as zf:
            pub_keys = [n for n in zf.namelist() if n.startswith("public_keys/")]
        assert len(pub_keys) == 2, f"Expected 2 public keys, got {pub_keys}"

    def test_verify_bundle_resolves_keys_independently(self, tmp_path):
        """verify_bundle resolves receipt and constitution keys by their own key_id."""
        receipt_priv, receipt_pub = generate_keypair(tmp_path / "receipt_keys")
        const_priv, const_pub = generate_keypair(tmp_path / "const_keys")

        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="keyres-agent", domain="testing"),
            provenance=Provenance(
                authored_by="author@test.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(const_priv))
        const_path = tmp_path / "keyres.yaml"
        save_constitution(signed, const_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(receipt_priv))
        def agent(query, context):
            return "Answer grounded in context."

        result = agent(query="test?", context="Context.")
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(result.receipt, indent=2))

        bundle_path = tmp_path / "keyres.zip"
        create_bundle(
            receipt_path=receipt_path,
            constitution_path=const_path,
            public_key_path=receipt_pub,
            output_path=bundle_path,
            constitution_public_key_path=const_pub,
        )

        vr = verify_bundle(bundle_path)
        assert vr.valid is True, f"Expected valid bundle, errors: {vr.errors}"
        const_check = [c for c in vr.checks if c.name == "Constitution signature"][0]
        receipt_check = [c for c in vr.checks if c.name == "Receipt signature"][0]
        assert const_check.passed is True
        assert receipt_check.passed is True

    def test_verify_bundle_fails_without_constitution_key(self, tmp_path):
        """Without the constitution key in bundle, constitution signature fails."""
        receipt_priv, receipt_pub = generate_keypair(tmp_path / "receipt_keys")
        const_priv, const_pub = generate_keypair(tmp_path / "const_keys")

        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="nokey-agent", domain="testing"),
            provenance=Provenance(
                authored_by="author@test.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(const_priv))
        const_path = tmp_path / "nokey.yaml"
        save_constitution(signed, const_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(receipt_priv))
        def agent(query, context):
            return "Answer grounded in context."

        result = agent(query="test?", context="Context.")
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(result.receipt, indent=2))

        # Only include receipt key — no constitution key
        bundle_path = tmp_path / "nokey.zip"
        create_bundle(
            receipt_path=receipt_path,
            constitution_path=const_path,
            public_key_path=receipt_pub,
            output_path=bundle_path,
            # No constitution_public_key_path
        )

        vr = verify_bundle(bundle_path)
        # Constitution signature should fail (wrong key used as fallback)
        const_check = [c for c in vr.checks if c.name == "Constitution signature"][0]
        assert const_check.passed is False
        # But receipt signature should still pass
        receipt_check = [c for c in vr.checks if c.name == "Receipt signature"][0]
        assert receipt_check.passed is True
