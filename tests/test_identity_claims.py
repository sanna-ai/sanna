"""Tests for Identity Verification — KYA Bridge (v0.9.1).

Covers:
- IdentityClaim parsing from constitution YAML
- verify_identity_claims() function
- Receipt integration (middleware + fingerprint)
- CLI reporting
- MCP tool
- Bundle governance_summary
"""

import json
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
import yaml

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    IdentityClaim,
    IdentityVerificationResult,
    IdentityVerificationSummary,
    Provenance,
    Boundary,
    Invariant,
    HaltCondition,
    AuthorityBoundaries,
    EscalationRule,
    verify_identity_claims,
    parse_constitution,
    load_constitution,
    sign_constitution,
    save_constitution,
    _claim_to_signable_dict,
)
from sanna.crypto import (
    generate_keypair,
    sign_bytes,
    load_private_key,
    load_public_key,
    compute_key_id,
)
from sanna.hashing import canonical_json_bytes


# =============================================================================
# HELPERS
# =============================================================================

def _make_constitution(identity_claims=None, invariants=None):
    """Create a minimal test constitution."""
    extensions = {}
    if identity_claims:
        extensions["identity_claims"] = [asdict(c) for c in identity_claims]

    return Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(
            agent_name="test-agent",
            domain="testing",
            description="Test agent",
            extensions=extensions,
            identity_claims=identity_claims or [],
        ),
        provenance=Provenance(
            authored_by="test@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-02-14",
            approval_method="manual",
        ),
        boundaries=[
            Boundary(id="B001", description="test", category="scope", severity="high"),
        ],
        invariants=invariants or [
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ],
    )


def _sign_claim(claim: IdentityClaim, private_key_path) -> IdentityClaim:
    """Sign an identity claim with a private key."""
    priv_key = load_private_key(private_key_path)
    signable = _claim_to_signable_dict(claim)
    data = canonical_json_bytes(signable)
    signature = sign_bytes(data, priv_key)
    return IdentityClaim(
        provider=claim.provider,
        claim_type=claim.claim_type,
        credential_id=claim.credential_id,
        issued_at=claim.issued_at,
        expires_at=claim.expires_at,
        signature=signature,
        public_key_id=claim.public_key_id,
    )


def _make_claim(provider="trulioo", claim_type="digital_agent_passport",
                credential_id="dap-123", expires_at="", signature="",
                public_key_id=""):
    """Create a test IdentityClaim."""
    return IdentityClaim(
        provider=provider,
        claim_type=claim_type,
        credential_id=credential_id,
        issued_at="2026-02-14T00:00:00Z",
        expires_at=expires_at,
        signature=signature,
        public_key_id=public_key_id,
    )


# =============================================================================
# IDENTITY CLAIM PARSING
# =============================================================================

class TestIdentityClaimParsing:
    """Tests for parsing identity_claims from constitution YAML."""

    def test_constitution_with_claims_parses_into_list(self, tmp_path):
        """identity_claims in YAML are parsed into IdentityClaim list."""
        const_data = {
            "sanna_constitution": "0.1.0",
            "identity": {
                "agent_name": "agent-1",
                "domain": "finance",
                "identity_claims": [
                    {
                        "provider": "trulioo",
                        "claim_type": "digital_agent_passport",
                        "credential_id": "dap-123",
                        "issued_at": "2026-02-14T00:00:00Z",
                    },
                ],
            },
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-02-14",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "test", "category": "scope", "severity": "high"},
            ],
        }
        const = parse_constitution(const_data)
        assert len(const.identity.identity_claims) == 1
        claim = const.identity.identity_claims[0]
        assert claim.provider == "trulioo"
        assert claim.claim_type == "digital_agent_passport"
        assert claim.credential_id == "dap-123"

    def test_constitution_without_claims_has_empty_list(self):
        """Constitution without identity_claims has empty list."""
        const_data = {
            "sanna_constitution": "0.1.0",
            "identity": {
                "agent_name": "agent-1",
                "domain": "finance",
            },
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-02-14",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "test", "category": "scope", "severity": "high"},
            ],
        }
        const = parse_constitution(const_data)
        assert const.identity.identity_claims == []

    def test_claims_also_in_extensions(self):
        """identity_claims should also appear in extensions dict (backward compat)."""
        const_data = {
            "sanna_constitution": "0.1.0",
            "identity": {
                "agent_name": "agent-1",
                "domain": "finance",
                "identity_claims": [
                    {
                        "provider": "internal",
                        "claim_type": "deploy",
                        "credential_id": "d-1",
                        "issued_at": "2026-01-01T00:00:00Z",
                    },
                ],
            },
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-02-14",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "test", "category": "scope", "severity": "high"},
            ],
        }
        const = parse_constitution(const_data)
        assert "identity_claims" in const.identity.extensions
        assert const.identity.extensions["identity_claims"][0]["provider"] == "internal"

    def test_malformed_claim_skipped_gracefully(self):
        """Malformed claim entry (non-dict) is skipped."""
        const_data = {
            "sanna_constitution": "0.1.0",
            "identity": {
                "agent_name": "agent-1",
                "domain": "finance",
                "identity_claims": ["not-a-dict", {"provider": "ok", "claim_type": "t", "credential_id": "c", "issued_at": "2026-01-01"}],
            },
            "provenance": {
                "authored_by": "test@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-02-14",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "test", "category": "scope", "severity": "high"},
            ],
        }
        const = parse_constitution(const_data)
        assert len(const.identity.identity_claims) == 1
        assert const.identity.identity_claims[0].provider == "ok"

    def test_round_trip_parse_serialize_parse(self, tmp_path):
        """Claims survive a parse → serialize → parse round-trip."""
        claim = _make_claim(provider="roundtrip", credential_id="rt-1")
        const = _make_constitution(identity_claims=[claim])
        signed = sign_constitution(const)
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)
        loaded = load_constitution(str(path))
        assert len(loaded.identity.identity_claims) == 1
        assert loaded.identity.identity_claims[0].provider == "roundtrip"


# =============================================================================
# VERIFY IDENTITY CLAIMS FUNCTION
# =============================================================================

class TestVerifyIdentityClaims:
    """Tests for the verify_identity_claims() function."""

    def test_claim_with_valid_signature_verified(self, tmp_path):
        """Claim with valid signature and matching key → verified."""
        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[signed_claim],
        )
        summary = verify_identity_claims(identity, {key_id: str(pub)})
        assert summary.total_claims == 1
        assert summary.verified_count == 1
        assert summary.all_verified is True
        assert summary.results[0].status == "verified"

    def test_claim_with_invalid_signature_failed(self, tmp_path):
        """Claim with invalid signature → failed."""
        priv, pub = generate_keypair(tmp_path / "keys")
        _, wrong_pub = generate_keypair(tmp_path / "wrong_keys")
        pub_key = load_public_key(wrong_pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id, signature="YmFkc2lnbmF0dXJl")

        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[claim],
        )
        summary = verify_identity_claims(identity, {key_id: str(wrong_pub)})
        assert summary.total_claims == 1
        assert summary.failed_count == 1
        assert summary.results[0].status == "failed"

    def test_claim_with_no_signature_unverified(self):
        """Claim with no signature → unverified."""
        claim = _make_claim()
        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[claim],
        )
        summary = verify_identity_claims(identity, {})
        assert summary.results[0].status == "unverified"
        assert summary.unverified_count == 1

    def test_claim_with_signature_but_no_matching_key(self, tmp_path):
        """Claim with signature but public_key_id not in provider_keys → no_key."""
        priv, pub = generate_keypair(tmp_path / "keys")
        claim = _make_claim(public_key_id="unknown-key", signature="YmFkc2lnbmF0dXJl")

        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[claim],
        )
        summary = verify_identity_claims(identity, {"other-key": str(pub)})
        assert summary.results[0].status == "no_key"

    def test_claim_expired(self, tmp_path):
        """Claim with valid signature but expired → expired."""
        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        claim = _make_claim(public_key_id=key_id, expires_at=past)
        signed_claim = _sign_claim(claim, priv)

        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[signed_claim],
        )
        summary = verify_identity_claims(identity, {key_id: str(pub)})
        assert summary.results[0].status == "expired"

    def test_claim_with_future_expiry_verified(self, tmp_path):
        """Claim with valid signature and future expiry → verified."""
        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        claim = _make_claim(public_key_id=key_id, expires_at=future)
        signed_claim = _sign_claim(claim, priv)

        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[signed_claim],
        )
        summary = verify_identity_claims(identity, {key_id: str(pub)})
        assert summary.results[0].status == "verified"

    def test_multiple_claims_mixed_results(self, tmp_path):
        """Multiple claims with mixed results → summary counts correct."""
        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        # Claim 1: signed and verifiable
        claim1 = _make_claim(provider="p1", credential_id="c1", public_key_id=key_id)
        signed_claim1 = _sign_claim(claim1, priv)

        # Claim 2: no signature
        claim2 = _make_claim(provider="p2", credential_id="c2")

        # Claim 3: no matching key
        claim3 = _make_claim(provider="p3", credential_id="c3",
                            public_key_id="unknown", signature="YmFk")

        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[signed_claim1, claim2, claim3],
        )
        summary = verify_identity_claims(identity, {key_id: str(pub)})
        assert summary.total_claims == 3
        assert summary.verified_count == 1
        assert summary.unverified_count == 2  # unverified + no_key
        assert summary.all_verified is False

    def test_no_claims_all_verified(self):
        """No claims → all_verified=True, total=0."""
        identity = AgentIdentity(agent_name="test", domain="test")
        summary = verify_identity_claims(identity, {})
        assert summary.all_verified is True
        assert summary.total_claims == 0

    def test_provider_keys_none(self, tmp_path):
        """provider_keys=None → claims with signatures get no_key."""
        priv, pub = generate_keypair(tmp_path / "keys")
        claim = _make_claim(public_key_id="some-key", signature="YmFk")
        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[claim],
        )
        summary = verify_identity_claims(identity, None)
        assert summary.results[0].status == "no_key"

    def test_empty_provider_keys_dict(self, tmp_path):
        """Empty provider_keys → claims with signatures get no_key."""
        claim = _make_claim(public_key_id="some-key", signature="YmFk")
        identity = AgentIdentity(
            agent_name="test", domain="test",
            identity_claims=[claim],
        )
        summary = verify_identity_claims(identity, {})
        assert summary.results[0].status == "no_key"


# =============================================================================
# RECEIPT INTEGRATION
# =============================================================================

class TestReceiptIntegration:
    """Tests for identity verification in receipts."""

    def test_receipt_with_verified_claims(self, tmp_path):
        """Receipt from constitution with claims includes identity_verification."""
        from sanna.middleware import sanna_observe

        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        @sanna_observe(
            constitution_path=str(path),
            identity_provider_keys={key_id: str(pub)},
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        assert "identity_verification" in result.receipt
        iv = result.receipt["identity_verification"]
        assert iv["total_claims"] == 1
        assert iv["verified"] == 1
        assert iv["all_verified"] is True
        assert iv["claims"][0]["status"] == "verified"

    def test_receipt_without_claims_omits_field(self, tmp_path):
        """Receipt from constitution without claims omits identity_verification."""
        from sanna.middleware import sanna_observe

        priv, pub = generate_keypair(tmp_path / "keys")
        const = _make_constitution()
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        @sanna_observe(constitution_path=str(path))
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        assert "identity_verification" not in result.receipt

    def test_identity_verification_not_in_fingerprint(self, tmp_path):
        """Same content, different verification results → same fingerprint."""
        from sanna.middleware import sanna_observe

        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        # Run with provider keys (verified)
        @sanna_observe(
            constitution_path=str(path),
            identity_provider_keys={key_id: str(pub)},
        )
        def agent_verified(query, context):
            return f"Answer: {context}"

        # Run without provider keys (unverified)
        @sanna_observe(constitution_path=str(path))
        def agent_unverified(query, context):
            return f"Answer: {context}"

        r1 = agent_verified(query="test?", context="Context here.")
        r2 = agent_unverified(query="test?", context="Context here.")

        # identity_verification differs between the two
        assert r1.receipt.get("identity_verification", {}).get("verified") == 1
        assert r2.receipt.get("identity_verification", {}).get("verified") == 0
        # But fingerprints should both validate (since identity_verification is NOT in fingerprint)
        from sanna.verify import verify_fingerprint
        match1, _, _ = verify_fingerprint(r1.receipt)
        match2, _, _ = verify_fingerprint(r2.receipt)
        assert match1, "Fingerprint mismatch on receipt with verified claims"
        assert match2, "Fingerprint mismatch on receipt with unverified claims"
        assert match2, "Fingerprint mismatch on receipt without identity_verification"

    def test_receipt_validates_against_schema(self, tmp_path):
        """Receipt with identity_verification passes schema validation."""
        from sanna.middleware import sanna_observe
        from sanna.verify import verify_receipt, load_schema

        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        @sanna_observe(
            constitution_path=str(path),
            identity_provider_keys={key_id: str(pub)},
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        schema = load_schema()
        vr = verify_receipt(result.receipt, schema)
        assert vr.valid, f"Receipt invalid: {vr.errors}"

    def test_middleware_with_identity_provider_keys(self, tmp_path):
        """Middleware with identity_provider_keys parameter works."""
        from sanna.middleware import sanna_observe

        priv, pub = generate_keypair(tmp_path / "keys")

        const = _make_constitution(identity_claims=[_make_claim()])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        # No provider keys — claims should be unverified
        @sanna_observe(constitution_path=str(path))
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        iv = result.receipt["identity_verification"]
        assert iv["claims"][0]["status"] == "unverified"


# =============================================================================
# CLI
# =============================================================================

class TestCLIIdentity:
    """Tests for identity claims in CLI output."""

    def test_verify_constitution_shows_claims(self, tmp_path, capsys):
        """sanna-verify-constitution shows identity claims."""
        priv, pub = generate_keypair(tmp_path / "keys")

        claim = _make_claim(provider="trulioo", credential_id="dap-123")
        const = _make_constitution(identity_claims=[claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        import sys
        original_argv = sys.argv
        sys.argv = ["sanna-verify-constitution", str(path), "--public-key", str(pub)]
        try:
            from sanna.cli import main_verify_constitution
            rc = main_verify_constitution()
        finally:
            sys.argv = original_argv

        captured = capsys.readouterr()
        assert rc == 0
        assert "Identity Claims: 1 claims found" in captured.out
        assert "trulioo/digital_agent_passport" in captured.out

    def test_verify_shows_identity_in_receipt(self, tmp_path, capsys):
        """sanna-verify shows identity verification section in receipt."""
        from sanna.middleware import sanna_observe
        from sanna.cli import format_verify_summary
        from sanna.verify import verify_receipt, load_schema

        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(provider="internal", credential_id="dep-456", public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        @sanna_observe(
            constitution_path=str(path),
            identity_provider_keys={key_id: str(pub)},
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        schema = load_schema()
        vr = verify_receipt(result.receipt, schema)
        summary = format_verify_summary(vr, result.receipt)
        assert "IDENTITY CLAIMS" in summary
        assert "internal/digital_agent_passport" in summary

    def test_verify_constitution_with_provider_keys(self, tmp_path, capsys):
        """--identity-provider-keys verifies claims."""
        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(provider="trulioo", credential_id="dap-789", public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        import sys
        original_argv = sys.argv
        sys.argv = [
            "sanna-verify-constitution", str(path),
            "--public-key", str(pub),
            "--identity-provider-keys", f"{key_id}={pub}",
        ]
        try:
            from sanna.cli import main_verify_constitution
            rc = main_verify_constitution()
        finally:
            sys.argv = original_argv

        captured = capsys.readouterr()
        assert rc == 0
        assert "verified" in captured.out


# =============================================================================
# MCP TOOL
# =============================================================================

class TestMCPIdentityTool:
    """Tests for the verify_identity_claims MCP tool."""

    def test_tool_with_claims_and_keys(self, tmp_path):
        """Tool with claims + keys → verification results."""
        mcp = pytest.importorskip("mcp")

        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        from sanna.mcp.server import sanna_verify_identity_claims
        result = json.loads(sanna_verify_identity_claims(
            constitution_path=str(path),
            provider_keys={key_id: str(pub)},
        ))
        assert result["total_claims"] == 1
        assert result["verified"] == 1
        assert result["all_verified"] is True

    def test_tool_with_claims_no_keys(self, tmp_path):
        """Tool with claims + no keys → all no_key."""
        mcp = pytest.importorskip("mcp")

        claim = _make_claim(public_key_id="some-key", signature="YmFk")
        const = _make_constitution(identity_claims=[claim])
        signed_const = sign_constitution(const)
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        from sanna.mcp.server import sanna_verify_identity_claims
        result = json.loads(sanna_verify_identity_claims(
            constitution_path=str(path),
        ))
        assert result["total_claims"] == 1
        assert result["claims"][0]["status"] == "no_key"

    def test_tool_with_no_claims(self, tmp_path):
        """Tool with no claims → empty results."""
        mcp = pytest.importorskip("mcp")

        const = _make_constitution()
        signed_const = sign_constitution(const)
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        from sanna.mcp.server import sanna_verify_identity_claims
        result = json.loads(sanna_verify_identity_claims(
            constitution_path=str(path),
        ))
        assert result["total_claims"] == 0
        assert result["all_verified"] is True

    def test_tool_bad_constitution_path(self):
        """Tool with bad constitution path → error."""
        mcp = pytest.importorskip("mcp")

        from sanna.mcp.server import sanna_verify_identity_claims
        result = json.loads(sanna_verify_identity_claims(
            constitution_path="/nonexistent/path.yaml",
        ))
        assert "error" in result


# =============================================================================
# BUNDLE INTEGRATION
# =============================================================================

class TestBundleIdentity:
    """Tests for identity verification in evidence bundles."""

    def test_bundle_includes_identity_in_summary(self, tmp_path):
        """Bundle includes identity verification in governance_summary."""
        from sanna.bundle import create_bundle, verify_bundle
        from sanna.middleware import sanna_observe
        from sanna.constitution import approve_constitution

        author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
        approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")
        pub_key = load_public_key(author_pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, author_priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(author_priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)
        approve_constitution(path, approver_priv, "bob@test.com", "VP", "1")

        @sanna_observe(
            constitution_path=str(path),
            private_key_path=str(author_priv),
            identity_provider_keys={key_id: str(author_pub)},
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(result.receipt, indent=2))

        bundle_path = tmp_path / "bundle.zip"
        create_bundle(
            receipt_path=receipt_path,
            constitution_path=path,
            public_key_path=author_pub,
            output_path=bundle_path,
            approver_public_key_path=approver_pub,
        )

        bundle_result = verify_bundle(bundle_path)
        # Check governance summary has identity fields
        import zipfile
        with zipfile.ZipFile(bundle_path, "r") as zf:
            meta = json.loads(zf.read("metadata.json"))
        gs = meta.get("governance_summary", {})
        assert gs.get("identity_claims_total") == 1
        assert gs.get("identity_claims_verified") == 1
        assert gs.get("identity_claims_all_verified") is True

    def test_bundle_without_claims_omits_identity_fields(self, tmp_path):
        """Bundle without identity claims omits identity fields from summary."""
        from sanna.bundle import create_bundle
        from sanna.middleware import sanna_observe
        from sanna.constitution import approve_constitution

        author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
        approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")

        const = _make_constitution()
        signed_const = sign_constitution(const, private_key_path=str(author_priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)
        approve_constitution(path, approver_priv, "bob@test.com", "VP", "1")

        @sanna_observe(
            constitution_path=str(path),
            private_key_path=str(author_priv),
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(result.receipt, indent=2))

        bundle_path = tmp_path / "bundle.zip"
        create_bundle(
            receipt_path=receipt_path,
            constitution_path=path,
            public_key_path=author_pub,
            output_path=bundle_path,
            approver_public_key_path=approver_pub,
        )

        import zipfile
        with zipfile.ZipFile(bundle_path, "r") as zf:
            meta = json.loads(zf.read("metadata.json"))
        gs = meta.get("governance_summary", {})
        assert "identity_claims_total" not in gs


# =============================================================================
# VERIFY.PY REPORTING
# =============================================================================

class TestVerifyReporting:
    """Tests for identity verification in the verification pipeline."""

    def test_verify_warns_when_not_all_verified(self, tmp_path):
        """Verification emits warning when not all claims verified."""
        from sanna.middleware import sanna_observe
        from sanna.verify import verify_receipt, load_schema

        priv, pub = generate_keypair(tmp_path / "keys")

        claim = _make_claim(public_key_id="missing-key", signature="YmFk")
        const = _make_constitution(identity_claims=[claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        @sanna_observe(constitution_path=str(path))
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        schema = load_schema()
        vr = verify_receipt(result.receipt, schema)
        assert any("not all claims verified" in w for w in vr.warnings)

    def test_verify_no_warning_when_all_verified(self, tmp_path):
        """No warning when all claims are verified."""
        from sanna.middleware import sanna_observe
        from sanna.verify import verify_receipt, load_schema

        priv, pub = generate_keypair(tmp_path / "keys")
        pub_key = load_public_key(pub)
        key_id = compute_key_id(pub_key)

        claim = _make_claim(public_key_id=key_id)
        signed_claim = _sign_claim(claim, priv)

        const = _make_constitution(identity_claims=[signed_claim])
        signed_const = sign_constitution(const, private_key_path=str(priv))
        path = tmp_path / "const.yaml"
        save_constitution(signed_const, path)

        @sanna_observe(
            constitution_path=str(path),
            identity_provider_keys={key_id: str(pub)},
        )
        def agent(query, context):
            return f"Answer: {context}"

        result = agent(query="test?", context="Context here.")
        schema = load_schema()
        vr = verify_receipt(result.receipt, schema)
        assert not any("identity" in w.lower() for w in vr.warnings)
