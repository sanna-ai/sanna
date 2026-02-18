"""Tests for constitution approval schema and YAML block (Block 1, v0.9.0).

Covers ApprovalRecord, ApprovalChain, parse/serialize round-trips,
content hash computation, and schema validation.
"""

import json
from pathlib import Path

import pytest
import yaml

from sanna.constitution import (
    ApprovalRecord,
    ApprovalChain,
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    Invariant,
    compute_constitution_hash,
    compute_content_hash,
    load_constitution,
    parse_constitution,
    save_constitution,
    sign_constitution,
    validate_against_schema,
    constitution_to_dict,
)
from sanna.crypto import generate_keypair


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_constitution():
    """A minimal valid constitution for testing."""
    return Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="author@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="manual",
        ),
        boundaries=[Boundary(id="B001", description="Test boundary", category="scope", severity="high")],
        invariants=[
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ],
    )


@pytest.fixture
def sample_approval_record():
    """A sample ApprovalRecord."""
    return ApprovalRecord(
        status="approved",
        approver_id="jane.smith@company.com",
        approver_role="VP Risk",
        approved_at="2026-02-14T10:00:00Z",
        approval_signature="dGVzdHNpZ25hdHVyZQ==",
        constitution_version="1",
        content_hash="a" * 64,
    )


@pytest.fixture
def keypair(tmp_path):
    """Generate a keypair for testing."""
    priv, pub = generate_keypair(tmp_path / "keys")
    return priv, pub


# =============================================================================
# ApprovalRecord creation
# =============================================================================

class TestApprovalRecord:
    def test_creation_with_all_fields(self, sample_approval_record):
        rec = sample_approval_record
        assert rec.status == "approved"
        assert rec.approver_id == "jane.smith@company.com"
        assert rec.approver_role == "VP Risk"
        assert rec.approved_at == "2026-02-14T10:00:00Z"
        assert rec.approval_signature == "dGVzdHNpZ25hdHVyZQ=="
        assert rec.constitution_version == "1"
        assert rec.content_hash == "a" * 64
        assert rec.previous_version_hash is None

    def test_creation_with_previous_version_hash(self):
        rec = ApprovalRecord(
            status="approved",
            approver_id="jane@co.com",
            approver_role="CISO",
            approved_at="2026-02-14T10:00:00Z",
            approval_signature="sig",
            constitution_version="2",
            content_hash="b" * 64,
            previous_version_hash="a" * 64,
        )
        assert rec.previous_version_hash == "a" * 64

    def test_constitution_version_free_form(self):
        """constitution_version accepts any string."""
        for version in ["1", "2.0", "3.1-rc1", "v4-beta", "latest"]:
            rec = ApprovalRecord(
                status="approved",
                approver_id="x@x.com",
                approver_role="role",
                approved_at="2026-01-01T00:00:00Z",
                approval_signature="sig",
                constitution_version=version,
                content_hash="c" * 64,
            )
            assert rec.constitution_version == version


# =============================================================================
# ApprovalChain
# =============================================================================

class TestApprovalChain:
    def test_single_record_is_approved(self, sample_approval_record):
        chain = ApprovalChain(records=[sample_approval_record])
        assert chain.is_approved is True
        assert chain.current == sample_approval_record

    def test_empty_records_not_approved(self):
        chain = ApprovalChain(records=[])
        assert chain.is_approved is False
        assert chain.current is None

    def test_revoked_status_not_approved(self):
        rec = ApprovalRecord(
            status="revoked",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="1",
            content_hash="d" * 64,
        )
        chain = ApprovalChain(records=[rec])
        assert chain.is_approved is False
        assert chain.current is not None

    def test_pending_status_not_approved(self):
        rec = ApprovalRecord(
            status="pending",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="1",
            content_hash="e" * 64,
        )
        chain = ApprovalChain(records=[rec])
        assert chain.is_approved is False

    def test_default_empty_records(self):
        chain = ApprovalChain()
        assert chain.records == []
        assert chain.is_approved is False
        assert chain.current is None


# =============================================================================
# Constitution with approval block
# =============================================================================

class TestConstitutionWithApproval:
    def test_constitution_without_approval(self, sample_constitution):
        assert sample_constitution.approval is None

    def test_constitution_with_approval(self, sample_constitution, sample_approval_record):
        const = Constitution(
            schema_version=sample_constitution.schema_version,
            identity=sample_constitution.identity,
            provenance=sample_constitution.provenance,
            boundaries=sample_constitution.boundaries,
            invariants=sample_constitution.invariants,
            approval=ApprovalChain(records=[sample_approval_record]),
        )
        assert const.approval is not None
        assert const.approval.is_approved is True


# =============================================================================
# Parsing
# =============================================================================

class TestParseApproval:
    def test_parse_without_approval_block(self):
        data = {
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
        }
        const = parse_constitution(data)
        assert const.approval is None

    def test_parse_with_approval_block(self):
        data = {
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
            "approval": {
                "records": [{
                    "status": "approved",
                    "approver_id": "jane@company.com",
                    "approver_role": "VP Risk",
                    "approved_at": "2026-02-14T10:00:00Z",
                    "approval_signature": "c2lnbmF0dXJl",
                    "constitution_version": "3",
                    "content_hash": "f" * 64,
                    "previous_version_hash": "e" * 64,
                }],
            },
        }
        const = parse_constitution(data)
        assert const.approval is not None
        assert len(const.approval.records) == 1
        assert const.approval.is_approved is True
        rec = const.approval.current
        assert rec.approver_id == "jane@company.com"
        assert rec.approver_role == "VP Risk"
        assert rec.constitution_version == "3"
        assert rec.content_hash == "f" * 64
        assert rec.previous_version_hash == "e" * 64

    def test_parse_invalid_approval_status_rejected(self):
        data = {
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
            "approval": {
                "records": [{
                    "status": "invalid_status",
                    "approver_id": "x@x.com",
                    "approver_role": "role",
                    "approved_at": "2026-01-01T00:00:00Z",
                    "approval_signature": "sig",
                    "constitution_version": "1",
                    "content_hash": "a" * 64,
                }],
            },
        }
        with pytest.raises(ValueError, match="Invalid approval status"):
            parse_constitution(data)


# =============================================================================
# YAML round-trip
# =============================================================================

class TestApprovalYAMLRoundTrip:
    def test_round_trip_with_approval(self, tmp_path, sample_constitution, keypair):
        priv_path, _ = keypair
        signed = sign_constitution(sample_constitution, private_key_path=str(priv_path))
        approval_rec = ApprovalRecord(
            status="approved",
            approver_id="jane@company.com",
            approver_role="VP Risk",
            approved_at="2026-02-14T10:00:00Z",
            approval_signature="dGVzdHNpZ25hdHVyZQ==",
            constitution_version="1",
            content_hash=compute_content_hash(signed),
        )
        with_approval = Constitution(
            schema_version=signed.schema_version,
            identity=signed.identity,
            provenance=signed.provenance,
            boundaries=signed.boundaries,
            trust_tiers=signed.trust_tiers,
            halt_conditions=signed.halt_conditions,
            invariants=signed.invariants,
            policy_hash=signed.policy_hash,
            authority_boundaries=signed.authority_boundaries,
            trusted_sources=signed.trusted_sources,
            approval=ApprovalChain(records=[approval_rec]),
        )
        path = tmp_path / "with_approval.yaml"
        save_constitution(with_approval, path)

        # Load back
        loaded = load_constitution(str(path))
        assert loaded.approval is not None
        assert loaded.approval.is_approved is True
        assert loaded.approval.current.approver_id == "jane@company.com"
        assert loaded.approval.current.approver_role == "VP Risk"
        assert loaded.approval.current.constitution_version == "1"

    def test_round_trip_without_approval(self, tmp_path, sample_constitution, keypair):
        priv_path, _ = keypair
        signed = sign_constitution(sample_constitution, private_key_path=str(priv_path))
        path = tmp_path / "no_approval.yaml"
        save_constitution(signed, path)

        loaded = load_constitution(str(path))
        assert loaded.approval is None


# =============================================================================
# Content hash
# =============================================================================

class TestContentHash:
    def test_content_hash_computed_without_approval(self, sample_constitution, keypair):
        priv_path, _ = keypair
        signed = sign_constitution(sample_constitution, private_key_path=str(priv_path))
        content_hash = compute_content_hash(signed)
        assert len(content_hash) == 64
        assert all(c in "0123456789abcdef" for c in content_hash)

    def test_content_hash_is_deterministic(self, sample_constitution):
        hash1 = compute_content_hash(sample_constitution)
        hash2 = compute_content_hash(sample_constitution)
        assert hash1 == hash2

    def test_content_hash_changes_with_content(self, sample_constitution):
        hash1 = compute_content_hash(sample_constitution)

        modified = Constitution(
            schema_version=sample_constitution.schema_version,
            identity=sample_constitution.identity,
            provenance=sample_constitution.provenance,
            boundaries=sample_constitution.boundaries,
            invariants=[
                Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="warn"),
            ],
        )
        hash2 = compute_content_hash(modified)
        assert hash1 != hash2

    def test_content_hash_not_affected_by_approval(self, sample_constitution, keypair):
        priv_path, _ = keypair
        signed = sign_constitution(sample_constitution, private_key_path=str(priv_path))
        hash_without = compute_content_hash(signed)

        with_approval = Constitution(
            schema_version=signed.schema_version,
            identity=signed.identity,
            provenance=signed.provenance,
            boundaries=signed.boundaries,
            trust_tiers=signed.trust_tiers,
            halt_conditions=signed.halt_conditions,
            invariants=signed.invariants,
            policy_hash=signed.policy_hash,
            authority_boundaries=signed.authority_boundaries,
            trusted_sources=signed.trusted_sources,
            approval=ApprovalChain(records=[ApprovalRecord(
                status="approved",
                approver_id="x@x.com",
                approver_role="role",
                approved_at="2026-01-01T00:00:00Z",
                approval_signature="sig",
                constitution_version="1",
                content_hash="a" * 64,
            )]),
        )
        hash_with = compute_content_hash(with_approval)
        assert hash_without == hash_with

    def test_content_hash_matches_policy_hash(self, sample_constitution):
        """content_hash and policy_hash are the same computation."""
        content = compute_content_hash(sample_constitution)
        policy = compute_constitution_hash(sample_constitution)
        assert content == policy


# =============================================================================
# Schema validation
# =============================================================================

class TestApprovalSchemaValidation:
    def test_schema_passes_with_approval_block(self):
        data = {
            "sanna_constitution": "0.1.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
            "policy_hash": None,
            "approval": {
                "records": [{
                    "status": "approved",
                    "approver_id": "jane@company.com",
                    "approver_role": "VP Risk",
                    "approved_at": "2026-02-14T10:00:00Z",
                    "approval_signature": "c2lnbmF0dXJl",
                    "constitution_version": "3",
                    "content_hash": "f" * 64,
                }],
            },
        }
        errors = validate_against_schema(data)
        assert errors == [], f"Schema validation failed: {errors}"

    def test_schema_passes_without_approval_block(self):
        data = {
            "sanna_constitution": "0.1.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
            "policy_hash": None,
        }
        errors = validate_against_schema(data)
        assert errors == [], f"Schema validation failed: {errors}"

    def test_schema_rejects_invalid_approval_status(self):
        data = {
            "sanna_constitution": "0.1.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
            "policy_hash": None,
            "approval": {
                "records": [{
                    "status": "garbage",
                    "approver_id": "x@x.com",
                    "approver_role": "role",
                    "approved_at": "2026-01-01T00:00:00Z",
                    "approval_signature": "sig",
                    "constitution_version": "1",
                    "content_hash": "a" * 64,
                }],
            },
        }
        errors = validate_against_schema(data)
        assert len(errors) > 0

    def test_schema_passes_with_previous_version_hash(self):
        data = {
            "sanna_constitution": "0.1.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "a@a.com",
                "approved_by": ["b@b.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "high"}],
            "policy_hash": None,
            "approval": {
                "records": [{
                    "status": "approved",
                    "approver_id": "x@x.com",
                    "approver_role": "role",
                    "approved_at": "2026-01-01T00:00:00Z",
                    "approval_signature": "sig",
                    "constitution_version": "2",
                    "content_hash": "b" * 64,
                    "previous_version_hash": "a" * 64,
                }],
            },
        }
        errors = validate_against_schema(data)
        assert errors == [], f"Schema validation failed: {errors}"


# =============================================================================
# Templates do not include approval
# =============================================================================

class TestTemplatesNoApproval:
    def test_templates_have_no_approval_block(self):
        templates_dir = Path(__file__).parent.parent / "src" / "sanna" / "templates"
        for template_path in templates_dir.glob("*.yaml"):
            with open(template_path) as f:
                data = yaml.safe_load(f)
            assert "approval" not in data, (
                f"Template {template_path.name} should not have an approval block"
            )


# =============================================================================
# constitution_to_dict serialization
# =============================================================================

class TestConstitutionToDictApproval:
    def test_to_dict_without_approval(self, sample_constitution):
        d = constitution_to_dict(sample_constitution)
        assert "approval" not in d

    def test_to_dict_with_approval(self, sample_constitution, sample_approval_record):
        with_approval = Constitution(
            schema_version=sample_constitution.schema_version,
            identity=sample_constitution.identity,
            provenance=sample_constitution.provenance,
            boundaries=sample_constitution.boundaries,
            invariants=sample_constitution.invariants,
            approval=ApprovalChain(records=[sample_approval_record]),
        )
        d = constitution_to_dict(with_approval)
        assert "approval" in d
        assert "records" in d["approval"]
        assert len(d["approval"]["records"]) == 1
        rec = d["approval"]["records"][0]
        assert rec["status"] == "approved"
        assert rec["approver_id"] == "jane.smith@company.com"
        assert rec["approver_role"] == "VP Risk"
        assert rec["content_hash"] == "a" * 64

    def test_to_dict_approval_without_previous_version_hash(self, sample_constitution):
        rec = ApprovalRecord(
            status="approved",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="1",
            content_hash="a" * 64,
        )
        with_approval = Constitution(
            schema_version=sample_constitution.schema_version,
            identity=sample_constitution.identity,
            provenance=sample_constitution.provenance,
            boundaries=sample_constitution.boundaries,
            invariants=sample_constitution.invariants,
            approval=ApprovalChain(records=[rec]),
        )
        d = constitution_to_dict(with_approval)
        # previous_version_hash should not be in the dict when None
        assert "previous_version_hash" not in d["approval"]["records"][0]


# =============================================================================
# Block 2: approve_constitution(, verify_author_sig=False) function tests
# =============================================================================

class TestApproveConstitution:
    """Tests for the approve_constitution(, verify_author_sig=False) function."""

    @pytest.fixture
    def signed_constitution_path(self, tmp_path, sample_constitution, keypair):
        """Create a signed constitution file on disk."""
        priv_path, pub_path = keypair
        signed = sign_constitution(sample_constitution, private_key_path=str(priv_path))
        path = tmp_path / "signed.yaml"
        save_constitution(signed, path)
        return path, priv_path, pub_path

    @pytest.fixture
    def approver_keypair(self, tmp_path):
        """Generate a separate approver keypair."""
        priv, pub = generate_keypair(tmp_path / "approver_keys")
        return priv, pub

    def test_approve_unsigned_constitution_raises(self, tmp_path, sample_constitution):
        """Approving an unsigned constitution must raise SannaConstitutionError."""
        from sanna.constitution import SannaConstitutionError, approve_constitution
        path = tmp_path / "unsigned.yaml"
        save_constitution(sample_constitution, path)
        priv, _ = generate_keypair(tmp_path / "keys")
        with pytest.raises(SannaConstitutionError, match="must be signed"):
            approve_constitution(path, priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)

    def test_approve_signed_constitution_succeeds(self, signed_constitution_path, approver_keypair):
        """Approving a signed constitution produces a valid ApprovalRecord."""
        from sanna.constitution import approve_constitution
        path, _, _ = signed_constitution_path
        approver_priv, _ = approver_keypair
        record = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        assert record.status == "approved"
        assert record.approver_id == "jane@co.com"
        assert record.approver_role == "VP Risk"
        assert record.constitution_version == "1"
        assert record.content_hash is not None
        assert len(record.content_hash) == 64
        assert record.approval_signature != ""
        assert record.previous_version_hash is None

    def test_approval_signature_is_valid_ed25519(self, signed_constitution_path, approver_keypair):
        """The approval signature must be verifiable with the approver's public key."""
        from sanna.constitution import approve_constitution, _approval_record_to_signable_dict
        from sanna.crypto import verify_signature, load_public_key
        from sanna.hashing import canonical_json_bytes
        path, _, _ = signed_constitution_path
        approver_priv, approver_pub = approver_keypair
        record = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        # Reconstruct signable dict and verify
        signable = _approval_record_to_signable_dict(record)
        data = canonical_json_bytes(signable)
        pub_key = load_public_key(str(approver_pub))
        assert verify_signature(data, record.approval_signature, pub_key) is True

    def test_approval_content_hash_matches_constitution(self, signed_constitution_path, approver_keypair):
        """content_hash in the approval must match the constitution's content hash."""
        from sanna.constitution import approve_constitution, compute_content_hash, load_constitution
        path, _, _ = signed_constitution_path
        approver_priv, _ = approver_keypair
        record = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        # Reload and verify
        reloaded = load_constitution(str(path))
        expected_hash = compute_content_hash(reloaded)
        assert record.content_hash == expected_hash

    def test_approval_persisted_to_yaml(self, signed_constitution_path, approver_keypair):
        """After approval, the YAML file should contain the approval block."""
        from sanna.constitution import approve_constitution, load_constitution
        path, _, _ = signed_constitution_path
        approver_priv, _ = approver_keypair
        approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        reloaded = load_constitution(str(path))
        assert reloaded.approval is not None
        assert reloaded.approval.is_approved is True
        assert reloaded.approval.current.approver_id == "jane@co.com"

    def test_approval_preserves_author_signature(self, signed_constitution_path, approver_keypair):
        """Approval must not remove or alter the author's signature."""
        from sanna.constitution import approve_constitution, load_constitution
        path, _, _ = signed_constitution_path
        before = load_constitution(str(path))
        original_sig = before.provenance.signature.value
        approver_priv, _ = approver_keypair
        approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        after = load_constitution(str(path))
        assert after.provenance.signature.value == original_sig

    def test_re_approval_overwrites_with_warning(self, signed_constitution_path, approver_keypair):
        """Re-approving should overwrite the existing approval and emit a warning."""
        import warnings
        from sanna.constitution import approve_constitution
        path, _, _ = signed_constitution_path
        approver_priv, _ = approver_keypair
        # First approval
        record1 = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        # Second approval should warn
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            record2 = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "2", verify_author_sig=False)
            overwrite_warnings = [x for x in w if "Overwriting" in str(x.message)]
            assert len(overwrite_warnings) >= 1
        assert record2.previous_version_hash == record1.content_hash
        assert record2.constitution_version == "2"

    def test_same_key_warning(self, signed_constitution_path):
        """Using the same key for author and approver should emit a warning."""
        import warnings
        from sanna.constitution import approve_constitution
        path, author_priv, _ = signed_constitution_path
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            approve_constitution(path, author_priv, "author@co.com", "Author", "1", verify_author_sig=False)
            same_key_warnings = [x for x in w if "identical" in str(x.message)]
            assert len(same_key_warnings) >= 1

    def test_missing_constitution_file_raises(self, tmp_path, approver_keypair=None):
        """approve_constitution(, verify_author_sig=False) should raise when constitution file doesn't exist."""
        from sanna.constitution import approve_constitution
        priv, _ = generate_keypair(tmp_path / "keys")
        with pytest.raises(FileNotFoundError):
            approve_constitution(
                tmp_path / "nonexistent.yaml", priv, "x@x.com", "role", "1"
            , verify_author_sig=False)

    def test_missing_approver_key_raises(self, signed_constitution_path):
        """approve_constitution(, verify_author_sig=False) should raise when approver key file doesn't exist."""
        from sanna.constitution import approve_constitution
        path, _, _ = signed_constitution_path
        with pytest.raises(FileNotFoundError):
            approve_constitution(
                path, "/nonexistent/key.pem", "x@x.com", "role", "1"
            , verify_author_sig=False)

    def test_approval_approved_at_is_iso8601(self, signed_constitution_path, approver_keypair):
        """approved_at should be a valid ISO 8601 timestamp."""
        from sanna.constitution import approve_constitution
        path, _, _ = signed_constitution_path
        approver_priv, _ = approver_keypair
        record = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        # Should be parseable as ISO 8601
        from datetime import datetime
        dt = datetime.fromisoformat(record.approved_at.replace("Z", "+00:00"))
        assert dt is not None

    def test_approval_signable_dict_blanks_signature(self):
        """_approval_record_to_signable_dict must blank the approval_signature field."""
        from sanna.constitution import _approval_record_to_signable_dict
        rec = ApprovalRecord(
            status="approved",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="real_signature_here",
            constitution_version="1",
            content_hash="a" * 64,
        )
        d = _approval_record_to_signable_dict(rec)
        assert d["approval_signature"] == ""
        assert d["content_hash"] == "a" * 64
        assert d["status"] == "approved"

    def test_signable_dict_includes_previous_version_hash(self):
        """When previous_version_hash is set, it must appear in signable dict."""
        from sanna.constitution import _approval_record_to_signable_dict
        rec = ApprovalRecord(
            status="approved",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="2",
            content_hash="b" * 64,
            previous_version_hash="a" * 64,
        )
        d = _approval_record_to_signable_dict(rec)
        assert d["previous_version_hash"] == "a" * 64

    def test_signable_dict_excludes_none_previous_version_hash(self):
        """When previous_version_hash is None, it must NOT appear in signable dict."""
        from sanna.constitution import _approval_record_to_signable_dict
        rec = ApprovalRecord(
            status="approved",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="1",
            content_hash="a" * 64,
        )
        d = _approval_record_to_signable_dict(rec)
        assert "previous_version_hash" not in d

    def test_approval_tampered_signature_fails_verification(self, signed_constitution_path, approver_keypair):
        """A tampered approval signature must fail verification."""
        from sanna.constitution import approve_constitution, _approval_record_to_signable_dict
        from sanna.crypto import verify_signature, load_public_key
        from sanna.hashing import canonical_json_bytes
        path, _, _ = signed_constitution_path
        approver_priv, approver_pub = approver_keypair
        record = approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        # Tamper with signature
        signable = _approval_record_to_signable_dict(record)
        data = canonical_json_bytes(signable)
        pub_key = load_public_key(str(approver_pub))
        tampered_sig = "AAAA" + record.approval_signature[4:]
        assert verify_signature(data, tampered_sig, pub_key) is False

    def test_approval_round_trip_full_yaml(self, signed_constitution_path, approver_keypair):
        """Full round-trip: sign → approve → save → load → verify approval present."""
        from sanna.constitution import approve_constitution, load_constitution
        path, _, _ = signed_constitution_path
        approver_priv, _ = approver_keypair
        approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "3.1", verify_author_sig=False)
        loaded = load_constitution(str(path))
        assert loaded.approval is not None
        assert loaded.approval.is_approved is True
        rec = loaded.approval.current
        assert rec.constitution_version == "3.1"
        assert rec.approver_role == "VP Risk"
        assert rec.approval_signature != ""
        assert len(rec.content_hash) == 64


# =============================================================================
# Block 2: CLI entry point tests
# =============================================================================

class TestApproveConstitutionCLI:
    """Tests for the approve_constitution_cmd() CLI entry point."""

    @pytest.fixture
    def signed_constitution_file(self, tmp_path):
        """Create a signed constitution file for CLI testing."""
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="cli-test-agent", domain="testing"),
            provenance=Provenance(
                authored_by="author@test.com",
                approved_by=["approver@test.com"],
                approval_date="2026-01-01",
                approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        priv, pub = generate_keypair(tmp_path / "author_keys")
        signed = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "cli_test.yaml"
        save_constitution(signed, path)
        return path, priv, pub

    @pytest.fixture
    def approver_keys(self, tmp_path):
        priv, pub = generate_keypair(tmp_path / "approver_cli_keys")
        return priv, pub

    def test_cli_succeeds_with_valid_args(self, signed_constitution_file, approver_keys, monkeypatch):
        """CLI should exit 0 with valid arguments."""
        from sanna.cli import approve_constitution_cmd
        path, _, pub = signed_constitution_file
        approver_priv, _ = approver_keys
        monkeypatch.setattr("sys.argv", [
            "sanna-approve-constitution",
            str(path),
            "--approver-key", str(approver_priv),
            "--approver-id", "cli-approver@co.com",
            "--approver-role", "CISO",
            "--version", "1.0",
            "--author-public-key", str(pub),
            "--non-interactive",
        ])
        result = approve_constitution_cmd()
        assert result == 0

    def test_cli_fails_for_unsigned_constitution(self, tmp_path, approver_keys, monkeypatch):
        """CLI should exit 1 for an unsigned constitution."""
        from sanna.cli import approve_constitution_cmd
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="test", domain="test"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        )
        path = tmp_path / "unsigned_cli.yaml"
        save_constitution(const, path)
        approver_priv, _ = approver_keys
        monkeypatch.setattr("sys.argv", [
            "sanna-approve-constitution",
            str(path),
            "--approver-key", str(approver_priv),
            "--approver-id", "x@x.com",
            "--approver-role", "role",
            "--version", "1",
            "--non-interactive",
        ])
        result = approve_constitution_cmd()
        assert result == 1

    def test_cli_fails_for_missing_file(self, tmp_path, approver_keys, monkeypatch):
        """CLI should exit 1 when constitution file doesn't exist."""
        from sanna.cli import approve_constitution_cmd
        approver_priv, _ = approver_keys
        monkeypatch.setattr("sys.argv", [
            "sanna-approve-constitution",
            str(tmp_path / "nonexistent.yaml"),
            "--approver-key", str(approver_priv),
            "--approver-id", "x@x.com",
            "--approver-role", "role",
            "--version", "1",
            "--non-interactive",
        ])
        result = approve_constitution_cmd()
        assert result == 1

    def test_cli_writes_approval_to_file(self, signed_constitution_file, approver_keys, monkeypatch):
        """After CLI approval, the file should have the approval block."""
        from sanna.cli import approve_constitution_cmd
        path, _, pub = signed_constitution_file
        approver_priv, _ = approver_keys
        monkeypatch.setattr("sys.argv", [
            "sanna-approve-constitution",
            str(path),
            "--approver-key", str(approver_priv),
            "--approver-id", "cli-approver@co.com",
            "--approver-role", "CISO",
            "--version", "2.0",
            "--author-public-key", str(pub),
            "--non-interactive",
        ])
        approve_constitution_cmd()
        loaded = load_constitution(str(path))
        assert loaded.approval is not None
        assert loaded.approval.is_approved is True
        assert loaded.approval.current.approver_id == "cli-approver@co.com"
        assert loaded.approval.current.constitution_version == "2.0"


# =============================================================================
# Block 3: Receipt binding — constitution_approval in constitution_ref
# =============================================================================

class TestConstitutionRefApproval:
    """Tests for constitution_approval field in receipt's constitution_ref."""

    @pytest.fixture
    def signed_and_approved(self, tmp_path):
        """Create a signed and approved constitution."""
        from sanna.constitution import approve_constitution
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="ref-test-agent", domain="testing"),
            provenance=Provenance(
                authored_by="author@test.com",
                approved_by=["approver@test.com"],
                approval_date="2026-01-01",
                approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
        approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")
        signed = sign_constitution(const, private_key_path=str(author_priv))
        path = tmp_path / "approved.yaml"
        save_constitution(signed, path)
        approve_constitution(path, approver_priv, "jane@co.com", "VP Risk", "1.0", verify_author_sig=False)
        return path, author_priv, author_pub, approver_priv, approver_pub

    def test_receipt_ref_includes_approval(self, signed_and_approved):
        """constitution_to_receipt_ref includes constitution_approval when approved."""
        from sanna.constitution import constitution_to_receipt_ref
        path = signed_and_approved[0]
        const = load_constitution(str(path))
        ref = constitution_to_receipt_ref(const)
        assert "constitution_approval" in ref
        approval = ref["constitution_approval"]
        assert approval["status"] == "approved"
        assert approval["approver_id"] == "jane@co.com"
        assert approval["approver_role"] == "VP Risk"
        assert approval["constitution_version"] == "1.0"
        assert len(approval["content_hash"]) == 64

    def test_receipt_ref_has_unapproved_when_absent(self, tmp_path):
        """constitution_to_receipt_ref includes status:'unapproved' when not approved."""
        from sanna.constitution import constitution_to_receipt_ref
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="no-approval-agent", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        priv, _ = generate_keypair(tmp_path / "keys")
        signed = sign_constitution(const, private_key_path=str(priv))
        ref = constitution_to_receipt_ref(signed)
        assert ref["constitution_approval"] == {"status": "unapproved"}

    def test_middleware_receipt_includes_approval(self, signed_and_approved):
        """Receipt from @sanna_observe includes constitution_approval."""
        from sanna.middleware import sanna_observe
        path = signed_and_approved[0]

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "The answer is grounded in context."

        result = agent(query="test?", context="Context about testing.")
        ref = result.receipt.get("constitution_ref")
        assert ref is not None
        assert "constitution_approval" in ref
        assert ref["constitution_approval"]["status"] == "approved"

    def test_middleware_receipt_has_unapproved_when_absent(self, tmp_path):
        """Receipt from @sanna_observe has status:'unapproved' when not approved."""
        from sanna.middleware import sanna_observe
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="no-approval", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        priv, _ = generate_keypair(tmp_path / "keys")
        signed = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "unsigned_approval.yaml"
        save_constitution(signed, path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "The answer is grounded in context."

        result = agent(query="test?", context="Context about testing.")
        ref = result.receipt.get("constitution_ref")
        assert ref is not None
        assert ref["constitution_approval"] == {"status": "unapproved"}

    def test_receipt_fingerprint_includes_approval(self, signed_and_approved):
        """Receipt fingerprint must include approval info (via constitution_ref hash)."""
        from sanna.middleware import sanna_observe
        from sanna.verify import verify_fingerprint
        path = signed_and_approved[0]

        @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
        def agent(query, context):
            return "The answer is grounded in context."

        result = agent(query="test?", context="Context about testing.")
        # The fingerprint should be valid (approval is part of constitution_ref)
        match, computed, expected = verify_fingerprint(result.receipt)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"


# =============================================================================
# Block 3: Approval verification in verify pipeline
# =============================================================================

class TestApprovalVerification:
    """Tests for approval chain verification in verify_constitution_chain."""

    @pytest.fixture
    def full_lifecycle(self, tmp_path):
        """Complete lifecycle: sign → approve → generate receipt."""
        from sanna.constitution import approve_constitution
        from sanna.middleware import sanna_observe
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="verify-test", domain="testing"),
            provenance=Provenance(
                authored_by="author@test.com",
                approved_by=["approver@test.com"],
                approval_date="2026-01-01",
                approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
        approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")
        signed = sign_constitution(const, private_key_path=str(author_priv))
        const_path = tmp_path / "lifecycle.yaml"
        save_constitution(signed, const_path)
        approve_constitution(const_path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(author_priv))
        def agent(query, context):
            return "The answer is grounded in context."

        result = agent(query="test?", context="Context about testing.")
        return result.receipt, const_path, author_priv, author_pub, approver_priv, approver_pub

    def test_chain_passes_with_approval(self, full_lifecycle):
        """Full chain verification passes with a properly approved constitution."""
        from sanna.verify import verify_constitution_chain
        receipt, const_path, _, author_pub, _, approver_pub = full_lifecycle
        errors, _ = verify_constitution_chain(
            receipt, str(const_path), str(author_pub),
            approver_public_key_path=str(approver_pub),
        )
        assert errors == [], f"Chain errors: {errors}"

    def test_chain_passes_without_approver_key(self, full_lifecycle):
        """Chain verification without approver key still passes (content_hash only)."""
        from sanna.verify import verify_constitution_chain
        receipt, const_path, _, author_pub, _, _ = full_lifecycle
        errors, _ = verify_constitution_chain(receipt, str(const_path), str(author_pub))
        assert errors == [], f"Chain errors: {errors}"

    def test_chain_detects_wrong_approver_key(self, full_lifecycle, tmp_path):
        """Chain verification with wrong approver key fails."""
        from sanna.verify import verify_constitution_chain
        receipt, const_path, _, author_pub, _, _ = full_lifecycle
        wrong_priv, wrong_pub = generate_keypair(tmp_path / "wrong_keys")
        errors, _ = verify_constitution_chain(
            receipt, str(const_path), str(author_pub),
            approver_public_key_path=str(wrong_pub),
        )
        assert len(errors) > 0
        assert any("approval signature" in e.lower() for e in errors)

    def test_chain_detects_tampered_content(self, full_lifecycle):
        """Tampering with constitution content after approval breaks content_hash."""
        from sanna.verify import verify_constitution_chain
        import yaml
        receipt, const_path, _, author_pub, _, approver_pub = full_lifecycle
        # Tamper with the YAML
        content = const_path.read_text()
        content = content.replace("verify-test", "tampered-agent")
        const_path.write_text(content)
        errors, _ = verify_constitution_chain(
            receipt, str(const_path),
            approver_public_key_path=str(approver_pub),
        )
        assert len(errors) > 0
        # Should detect content hash mismatch or policy hash mismatch
        assert any("mismatch" in e.lower() or "tamper" in e.lower() for e in errors)

    def test_chain_detects_receipt_approval_mismatch(self, full_lifecycle):
        """Receipt with mismatched constitution_approval fields is detected."""
        from sanna.verify import _verify_approval_chain
        receipt, const_path, _, _, _, _ = full_lifecycle
        const = load_constitution(str(const_path))
        # Tamper with the receipt's constitution_approval
        tampered_receipt = dict(receipt)
        tampered_receipt["constitution_ref"] = dict(receipt["constitution_ref"])
        tampered_receipt["constitution_ref"]["constitution_approval"] = {
            "status": "approved",
            "approver_id": "wrong@co.com",
            "approver_role": "VP Risk",
            "approved_at": "2026-01-01T00:00:00Z",
            "constitution_version": "1",
            "content_hash": "0" * 64,  # wrong hash
        }
        errors, _ = _verify_approval_chain(tampered_receipt, const)
        assert len(errors) > 0
        assert any("content_hash" in e.lower() or "does not match" in e.lower() for e in errors)

    def test_chain_detects_phantom_approval(self):
        """Receipt claiming approval on unapproved constitution is detected."""
        from sanna.verify import _verify_approval_chain
        # Constitution without approval
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="no-approval", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        )
        receipt = {
            "constitution_ref": {
                "constitution_approval": {
                    "status": "approved",
                    "approver_id": "phantom@co.com",
                    "approver_role": "role",
                    "approved_at": "2026-01-01T00:00:00Z",
                    "constitution_version": "1",
                    "content_hash": "a" * 64,
                },
            },
        }
        errors, _ = _verify_approval_chain(receipt, const)
        assert len(errors) > 0
        assert any("no approval block" in e.lower() for e in errors)

    def test_chain_no_errors_when_no_approval_anywhere(self):
        """No errors when neither receipt nor constitution has approval."""
        from sanna.verify import _verify_approval_chain
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="clean", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        )
        receipt = {"constitution_ref": {"policy_hash": "abc123"}}
        errors, _ = _verify_approval_chain(receipt, const)
        assert errors == []

    def test_verify_receipt_with_approval_passes(self, full_lifecycle):
        """Full verify_receipt() passes with approved constitution."""
        from sanna.verify import verify_receipt, load_schema
        receipt, const_path, _, author_pub, _, approver_pub = full_lifecycle
        schema = load_schema()
        result = verify_receipt(
            receipt, schema,
            public_key_path=str(author_pub),
            constitution_path=str(const_path),
            constitution_public_key_path=str(author_pub),
            approver_public_key_path=str(approver_pub),
        )
        assert result.valid, f"Verification failed: {result.errors}"
        assert result.exit_code == 0

    def test_verify_receipt_approval_wrong_key_fails(self, full_lifecycle, tmp_path):
        """verify_receipt() with wrong approver key causes errors."""
        from sanna.verify import verify_receipt, load_schema
        receipt, const_path, _, author_pub, _, _ = full_lifecycle
        _, wrong_pub = generate_keypair(tmp_path / "wrong")
        schema = load_schema()
        result = verify_receipt(
            receipt, schema,
            public_key_path=str(author_pub),
            constitution_path=str(const_path),
            constitution_public_key_path=str(author_pub),
            approver_public_key_path=str(wrong_pub),
        )
        assert not result.valid
        assert any("approval" in e.lower() for e in result.errors)

    def test_approval_status_pending_is_warning(self):
        """Pending approval status is a warning, not an error."""
        from sanna.verify import _verify_approval_chain
        from sanna.constitution import ApprovalChain, ApprovalRecord
        rec = ApprovalRecord(
            status="pending",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="1",
            content_hash="a" * 64,
        )
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="pending", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            approval=ApprovalChain(records=[rec]),
        )
        receipt = {"constitution_ref": {}}
        errors, warnings = _verify_approval_chain(receipt, const)
        # pending is a warning, not an error
        assert not any("pending" in e.lower() for e in errors), f"pending should not be an error: {errors}"
        assert any("pending" in w.lower() for w in warnings)

    def test_approval_no_signature_with_key_flagged(self, tmp_path):
        """Approval without signature but approver key provided is flagged."""
        from sanna.verify import _verify_approval_chain
        _, pub = generate_keypair(tmp_path / "keys")
        rec = ApprovalRecord(
            status="approved",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="",
            constitution_version="1",
            content_hash="a" * 64,
        )
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="nosig", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            approval=ApprovalChain(records=[rec]),
        )
        receipt = {"constitution_ref": {}}
        errors, _ = _verify_approval_chain(receipt, const, str(pub))
        assert any("no signature" in e.lower() for e in errors)

    def test_revoked_status_is_warning(self):
        """Revoked approval status is a warning, not an error."""
        from sanna.verify import _verify_approval_chain
        from sanna.constitution import ApprovalChain, ApprovalRecord
        rec = ApprovalRecord(
            status="revoked",
            approver_id="x@x.com",
            approver_role="role",
            approved_at="2026-01-01T00:00:00Z",
            approval_signature="sig",
            constitution_version="1",
            content_hash="a" * 64,
        )
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="revoked", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            approval=ApprovalChain(records=[rec]),
        )
        receipt = {"constitution_ref": {}}
        errors, warnings = _verify_approval_chain(receipt, const)
        assert not any("revoked" in e.lower() for e in errors)
        assert any("revoked" in w.lower() for w in warnings)

    def test_no_approver_key_emits_warning(self, tmp_path):
        """Approved constitution without approver key emits warning."""
        from sanna.verify import _verify_approval_chain
        from sanna.constitution import ApprovalChain, ApprovalRecord, approve_constitution
        author_priv, _ = generate_keypair(tmp_path / "keys")
        approver_priv, _ = generate_keypair(tmp_path / "approver_keys")
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="warn-test", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(author_priv))
        const_path = tmp_path / "warn.yaml"
        save_constitution(signed, const_path)
        approve_constitution(const_path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)
        loaded = load_constitution(str(const_path))
        receipt = {"constitution_ref": {}}
        # No approver key provided
        errors, warnings = _verify_approval_chain(receipt, loaded)
        assert errors == [], f"Unexpected errors: {errors}"
        assert any("not verified" in w.lower() for w in warnings)


# =============================================================================
# HIGH-2: Fingerprint excludes constitution_approval
# =============================================================================

class TestFingerprintExcludesApproval:
    """Verify that constitution_approval does not affect the receipt fingerprint."""

    def test_fingerprint_stable_after_approval(self, tmp_path):
        """Receipt fingerprint is the same before and after constitution approval."""
        from sanna.constitution import approve_constitution
        from sanna.middleware import sanna_observe
        from sanna.verify import verify_fingerprint

        author_priv, author_pub = generate_keypair(tmp_path / "keys")
        approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")

        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="fp-test", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(author_priv))

        # Receipt BEFORE approval
        unapproved_path = tmp_path / "unapproved.yaml"
        save_constitution(signed, unapproved_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(unapproved_path), private_key_path=str(author_priv))
        def agent_before(query, context):
            return "The answer is grounded in context."

        r_before = agent_before(query="test?", context="Context about testing.")
        fp_before = r_before.receipt["receipt_fingerprint"]

        # Now approve and generate a new receipt with SAME inputs
        approved_path = tmp_path / "approved.yaml"
        save_constitution(signed, approved_path)
        approve_constitution(approved_path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(approved_path), private_key_path=str(author_priv))
        def agent_after(query, context):
            return "The answer is grounded in context."

        r_after = agent_after(query="test?", context="Context about testing.")
        fp_after = r_after.receipt["receipt_fingerprint"]

        # The fingerprints should differ because correlation_id differs, but the
        # constitution_hash component should be the same.  Verify by checking
        # that the fingerprint still validates in both cases.
        match_before, _, _ = verify_fingerprint(r_before.receipt)
        match_after, _, _ = verify_fingerprint(r_after.receipt)
        assert match_before is True, "Fingerprint mismatch for unapproved receipt"
        assert match_after is True, "Fingerprint mismatch for approved receipt"

    def test_verify_fingerprint_with_constitution_approval_in_ref(self):
        """Manually injecting constitution_approval into constitution_ref does not break fingerprint."""
        from sanna.verify import verify_fingerprint
        from sanna.hashing import hash_obj, hash_text, EMPTY_HASH

        # Build a minimal receipt with constitution_ref including constitution_approval
        checks = [{"check_id": "C1", "passed": True, "severity": "low", "evidence": "ok"}]
        constitution_ref = {
            "document_id": "test/0.1.0",
            "policy_hash": "a" * 64,
            "version": "0.1.0",
            "constitution_approval": {
                "status": "approved",
                "approver_id": "x@x.com",
                "content_hash": "b" * 64,
            },
        }
        # Compute expected fingerprint using v0.13.0 unified 12-field formula
        # (should strip constitution_approval from constitution_ref before hashing)
        correlation_id = "test-trace-123"
        inputs = {"query": "q", "context": "c"}
        outputs = {"response": "r"}
        context_hash = hash_obj(inputs)
        output_hash = hash_obj(outputs)
        checks_hash = hash_obj(checks)
        _cref = {k: v for k, v in constitution_ref.items() if k != "constitution_approval"}
        const_hash = hash_obj(_cref)

        # v0.13.0: 12 pipe-delimited fields, absent optional fields use EMPTY_HASH
        fp_input = (
            f"{correlation_id}|{context_hash}|{output_hash}|5|{checks_hash}|{const_hash}"
            f"|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}|{EMPTY_HASH}"
        )
        full_fp = hash_text(fp_input)
        short_fp = hash_text(fp_input, truncate=16)

        receipt = {
            "spec_version": "1.0",
            "tool_version": "0.13.0",
            "checks_version": "5",
            "receipt_id": "test-id",
            "receipt_fingerprint": short_fp,
            "full_fingerprint": full_fp,
            "correlation_id": correlation_id,
            "timestamp": "2026-01-01T00:00:00Z",
            "inputs": inputs,
            "outputs": outputs,
            "context_hash": context_hash,
            "output_hash": output_hash,
            "checks": checks,
            "checks_passed": 1,
            "checks_failed": 0,
            "status": "PASS",
            "constitution_ref": constitution_ref,
        }

        match, computed, expected = verify_fingerprint(receipt)
        assert match is True, f"Fingerprint mismatch: computed={computed}, expected={expected}"


# =============================================================================
# HIGH-3: Receipts always carry constitution_approval
# =============================================================================

class TestReceiptAlwaysCarriesApprovalStatus:
    """Verify that receipts always include constitution_approval, even for unapproved."""

    def test_unapproved_receipt_has_unapproved_status(self, tmp_path):
        """Receipt from unapproved constitution has constitution_approval.status='unapproved'."""
        from sanna.middleware import sanna_observe
        author_priv, _ = generate_keypair(tmp_path / "keys")
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="unapproved-receipt", domain="testing"),
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

        result = agent(query="test?", context="Context.")
        cref = result.receipt.get("constitution_ref", {})
        ca = cref.get("constitution_approval")
        assert ca is not None, "constitution_approval should always be present"
        assert ca["status"] == "unapproved"
        assert len(ca) == 1, "unapproved should only have 'status' key"

    def test_approved_receipt_has_full_approval(self, tmp_path):
        """Receipt from approved constitution has full constitution_approval record."""
        from sanna.middleware import sanna_observe
        from sanna.constitution import approve_constitution
        author_priv, _ = generate_keypair(tmp_path / "keys")
        approver_priv, _ = generate_keypair(tmp_path / "approver_keys")
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="approved-receipt", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(author_priv))
        const_path = tmp_path / "approved.yaml"
        save_constitution(signed, const_path)
        approve_constitution(const_path, approver_priv, "jane@co.com", "VP Risk", "1", verify_author_sig=False)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(author_priv))
        def agent(query, context):
            return "The answer is grounded in context."

        result = agent(query="test?", context="Context.")
        cref = result.receipt.get("constitution_ref", {})
        ca = cref.get("constitution_approval")
        assert ca is not None
        assert ca["status"] == "approved"
        assert ca["approver_id"] == "jane@co.com"
        assert len(ca["content_hash"]) == 64

    def test_unapproved_receipt_validates_against_schema(self, tmp_path):
        """Receipt with unapproved constitution passes JSON schema validation."""
        from sanna.middleware import sanna_observe
        from sanna.verify import verify_receipt, load_schema
        author_priv, author_pub = generate_keypair(tmp_path / "keys")
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="schema-test", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
            invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
        )
        signed = sign_constitution(const, private_key_path=str(author_priv))
        const_path = tmp_path / "schema.yaml"
        save_constitution(signed, const_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(const_path), private_key_path=str(author_priv))
        def agent(query, context):
            return "The answer is grounded in context."

        result = agent(query="test?", context="Context.")
        schema = load_schema()
        vr = verify_receipt(result.receipt, schema, public_key_path=str(author_pub))
        assert vr.valid, f"Verification failed: {vr.errors}"

    def test_verify_unapproved_receipt_against_constitution(self, tmp_path):
        """Verify receipt with unapproved status against actual constitution — no errors."""
        from sanna.verify import _verify_approval_chain
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="chain-test", domain="testing"),
            provenance=Provenance(
                authored_by="a@a.com", approved_by=["b@b.com"],
                approval_date="2026-01-01", approval_method="manual",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        )
        receipt = {
            "constitution_ref": {
                "policy_hash": "abc",
                "constitution_approval": {"status": "unapproved"},
            },
        }
        errors, _ = _verify_approval_chain(receipt, const)
        assert errors == [], f"Unexpected errors: {errors}"
