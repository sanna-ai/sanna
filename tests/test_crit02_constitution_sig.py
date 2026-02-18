"""CRIT-02: Constitution Signature Verification in All Enforcement Paths.

Tests that cryptographic verification of constitution signatures is enforced
in @sanna_observe (middleware), sanna_generate_receipt (MCP server), and
SannaGateway (gateway).

The ``require_constitution_sig`` parameter (default True) controls behavior:
- True: cryptographic verification required; fails without public key
- False: permissive mode for local dev; warns but proceeds without key
"""

import json
import warnings
from pathlib import Path

import pytest

from sanna.constitution import (
    AgentIdentity,
    Boundary,
    Constitution,
    Invariant,
    Provenance,
    load_constitution,
    save_constitution,
    sign_constitution,
    SannaConstitutionError,
)
from sanna.crypto import generate_keypair
from sanna.middleware import sanna_observe, SannaHaltError

# Test keys for pre-built constitutions
TESTS_DIR = Path(__file__).parent
TEST_PUBLIC_KEY = str(
    TESTS_DIR / ".test_keys"
    / "c7065a8b70d9ad93611125691c762cedbef6c15e8f4fc25a86cabb4ceecbd3d8.pub"
)
CONSTITUTIONS_DIR = TESTS_DIR / "constitutions"
ALL_HALT_CONST = str(CONSTITUTIONS_DIR / "all_halt.yaml")

SIMPLE_CONTEXT = "Paris is the capital of France."
SIMPLE_OUTPUT = "The capital of France is Paris."


# =============================================================================
# Helpers
# =============================================================================

def _make_constitution(invariants=None):
    """Create a basic constitution dataclass."""
    return Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="t@t.com",
            approved_by=["a@t.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[
            Boundary(
                id="B001",
                description="Test",
                category="scope",
                severity="medium",
            )
        ],
        invariants=invariants or [],
    )


def _sign_and_save(tmp_path, invariants=None):
    """Create a signed constitution and return (path, pub_key_path)."""
    const = _make_constitution(invariants or [
        Invariant(
            id="INV_NO_FABRICATION",
            rule="Do not claim facts absent from sources.",
            enforcement="halt",
        ),
    ])
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = generate_keypair(keys_dir)
    signed = sign_constitution(
        const, private_key_path=str(priv_path), signed_by="test"
    )
    path = tmp_path / "constitution.yaml"
    save_constitution(signed, path)
    return str(path), str(pub_path)


def _save_unsigned(tmp_path, invariants=None):
    """Create an unsigned constitution (no Ed25519 signature) and save it."""
    const = _make_constitution(invariants or [
        Invariant(
            id="INV_NO_FABRICATION",
            rule="Do not claim facts absent from sources.",
            enforcement="halt",
        ),
    ])
    # Give it a policy_hash but no Ed25519 signature
    from sanna.constitution import compute_constitution_hash
    const.policy_hash = compute_constitution_hash(const)
    path = tmp_path / "unsigned_constitution.yaml"
    save_constitution(const, path)
    return str(path)


def _try_import_mcp_server():
    """Try to import sanna.mcp.server; return module or None on MCP compat failure."""
    try:
        from sanna.mcp import server as mcp_server
        return mcp_server
    except (ImportError, TypeError):
        return None


# =============================================================================
# 1. Signed constitution + valid key -> signature_verified: true
# =============================================================================

class TestSignedConstitutionValidKey:
    def test_middleware_signature_verified_true(self, tmp_path):
        """@sanna_observe with signed constitution and valid key sets
        signature_verified=true in constitution_ref."""
        const_path, pub_path = _sign_and_save(tmp_path)

        @sanna_observe(
            constitution_path=const_path,
            constitution_public_key_path=pub_path,
            require_constitution_sig=True,
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        cref = result.receipt.get("constitution_ref", {})
        assert cref.get("signature_verified") is True

    def test_mcp_signature_verified_true(self, tmp_path):
        """MCP sanna_generate_receipt with signed constitution and valid key
        sets signature_verified=true."""
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path, pub_path = _sign_and_save(tmp_path)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            constitution_public_key_path=pub_path,
            require_constitution_sig=True,
        )
        receipt = json.loads(result_json)
        assert "error" not in receipt or receipt.get("error") is None
        cref = receipt.get("constitution_ref", {})
        assert cref.get("signature_verified") is True


# =============================================================================
# 2. Tampered constitution -> rejected
# =============================================================================

class TestTamperedConstitution:
    def test_middleware_rejects_tampered(self, tmp_path):
        """Modifying a signed constitution after signing causes verification
        failure — either hash mismatch or signature failure."""
        const_path, pub_path = _sign_and_save(tmp_path)

        # Tamper with the constitution file
        path = Path(const_path)
        content = path.read_text()
        content = content.replace("test-agent", "tampered-agent")
        path.write_text(content)

        with pytest.raises(SannaConstitutionError, match="modified|tampered|mismatch"):
            @sanna_observe(
                constitution_path=const_path,
                constitution_public_key_path=pub_path,
                require_constitution_sig=True,
            )
            def agent(query, context):
                return SIMPLE_OUTPUT

    def test_mcp_rejects_tampered(self, tmp_path):
        """MCP path rejects tampered constitutions."""
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path, pub_path = _sign_and_save(tmp_path)

        # Tamper
        path = Path(const_path)
        content = path.read_text()
        content = content.replace("test-agent", "tampered-agent")
        path.write_text(content)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            constitution_public_key_path=pub_path,
            require_constitution_sig=True,
        )
        result = json.loads(result_json)
        assert result.get("error") is not None
        assert "modified" in result["error"] or "tampered" in result["error"]


# =============================================================================
# 3. Signed constitution + no public key + require=True -> hard fail
# =============================================================================

class TestSignedNoKeyRequired:
    def test_middleware_fails_without_key(self, tmp_path, monkeypatch):
        """@sanna_observe with signed constitution but no public key and
        require_constitution_sig=True raises SannaConstitutionError."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        const_path, _pub_path = _sign_and_save(tmp_path)

        with pytest.raises(
            SannaConstitutionError,
            match="no public key configured",
        ):
            @sanna_observe(
                constitution_path=const_path,
                require_constitution_sig=True,
                # No constitution_public_key_path
            )
            def agent(query, context):
                return SIMPLE_OUTPUT

    def test_mcp_fails_without_key(self, tmp_path, monkeypatch):
        """MCP sanna_generate_receipt fails when no public key is provided
        and require_constitution_sig=True."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path, _pub_path = _sign_and_save(tmp_path)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            require_constitution_sig=True,
            # No constitution_public_key_path
        )
        result = json.loads(result_json)
        assert result.get("error") is not None
        assert "no public key configured" in result["error"]


# =============================================================================
# 4. Unsigned (hash-only) constitution -> always rejected regardless of flag
# =============================================================================

class TestUnsignedAlwaysRejected:
    def test_middleware_rejects_unsigned_strict(self, tmp_path, monkeypatch):
        """@sanna_observe with unsigned (hash-only) constitution and
        require_constitution_sig=True raises SannaConstitutionError."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        const_path = _save_unsigned(tmp_path)

        with pytest.raises(
            SannaConstitutionError,
            match="missing or malformed",
        ):
            @sanna_observe(
                constitution_path=const_path,
                require_constitution_sig=True,
            )
            def agent(query, context):
                return SIMPLE_OUTPUT

    def test_middleware_rejects_unsigned_permissive(self, tmp_path, monkeypatch):
        """@sanna_observe with unsigned (hash-only) constitution and
        require_constitution_sig=False STILL raises SannaConstitutionError.
        Hash-only constitutions are always rejected."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        const_path = _save_unsigned(tmp_path)

        with pytest.raises(
            SannaConstitutionError,
            match="missing or malformed",
        ):
            @sanna_observe(
                constitution_path=const_path,
                require_constitution_sig=False,
            )
            def agent(query, context):
                return SIMPLE_OUTPUT

    def test_mcp_rejects_unsigned_strict(self, tmp_path, monkeypatch):
        """MCP sanna_generate_receipt rejects unsigned constitution
        when require_constitution_sig=True."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path = _save_unsigned(tmp_path)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            require_constitution_sig=True,
        )
        result = json.loads(result_json)
        assert result.get("error") is not None
        assert "missing or malformed" in result["error"].lower()

    def test_mcp_rejects_unsigned_permissive(self, tmp_path, monkeypatch):
        """MCP sanna_generate_receipt rejects unsigned constitution
        even with require_constitution_sig=False."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path = _save_unsigned(tmp_path)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            require_constitution_sig=False,
        )
        result = json.loads(result_json)
        assert result.get("error") is not None
        assert "missing or malformed" in result["error"].lower()


# =============================================================================
# 6. require=False + signed + no key -> warning, proceeds
# =============================================================================

class TestPermissiveSignedNoKey:
    def test_middleware_warns_signed_no_key(self, tmp_path, monkeypatch):
        """@sanna_observe with signed constitution, no public key, and
        require_constitution_sig=False logs a warning but proceeds."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        const_path, _pub_path = _sign_and_save(tmp_path)

        @sanna_observe(
            constitution_path=const_path,
            require_constitution_sig=False,
            # No constitution_public_key_path
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        cref = result.receipt.get("constitution_ref", {})
        # signature_verified is False because we couldn't verify
        assert cref.get("signature_verified") is False

    def test_mcp_warns_signed_no_key(self, tmp_path, monkeypatch):
        """MCP sanna_generate_receipt with signed constitution, no public
        key, and require_constitution_sig=False warns but proceeds."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path, _pub_path = _sign_and_save(tmp_path)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            require_constitution_sig=False,
            # No constitution_public_key_path
        )
        receipt = json.loads(result_json)
        assert "error" not in receipt or receipt.get("error") is None
        cref = receipt.get("constitution_ref", {})
        assert cref.get("signature_verified") is False


# =============================================================================
# 7. require=False + signed + valid key -> verifies, signature_verified: true
# =============================================================================

class TestPermissiveVerifiesWhenPossible:
    def test_middleware_verifies_with_key(self, tmp_path):
        """@sanna_observe with signed constitution, valid key, and
        require_constitution_sig=False still verifies and sets
        signature_verified=true."""
        const_path, pub_path = _sign_and_save(tmp_path)

        @sanna_observe(
            constitution_path=const_path,
            constitution_public_key_path=pub_path,
            require_constitution_sig=False,
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        cref = result.receipt.get("constitution_ref", {})
        assert cref.get("signature_verified") is True

    def test_mcp_verifies_with_key(self, tmp_path):
        """MCP sanna_generate_receipt with signed constitution, valid key,
        and require_constitution_sig=False still verifies."""
        mcp_server = _try_import_mcp_server()
        if mcp_server is None:
            pytest.skip("MCP SDK incompatible")

        const_path, pub_path = _sign_and_save(tmp_path)

        result_json = mcp_server.sanna_generate_receipt(
            query="test",
            context=SIMPLE_CONTEXT,
            response=SIMPLE_OUTPUT,
            constitution_path=const_path,
            constitution_public_key_path=pub_path,
            require_constitution_sig=False,
        )
        receipt = json.loads(result_json)
        assert "error" not in receipt or receipt.get("error") is None
        cref = receipt.get("constitution_ref", {})
        assert cref.get("signature_verified") is True


# =============================================================================
# 8. Pre-built test constitutions with known test key
# =============================================================================

class TestPreBuiltConstitutionsWithKey:
    def test_all_halt_with_test_key(self):
        """Pre-built all_halt.yaml constitution verifies with the test key."""
        @sanna_observe(
            constitution_path=ALL_HALT_CONST,
            constitution_public_key_path=TEST_PUBLIC_KEY,
            require_constitution_sig=True,
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        cref = result.receipt.get("constitution_ref", {})
        assert cref.get("signature_verified") is True


# =============================================================================
# 9. Wrong key -> fails even with require=False
# =============================================================================

class TestWrongKeyAlwaysFails:
    def test_wrong_key_strict(self, tmp_path):
        """Using the wrong public key always fails verification."""
        const_path, _pub_path = _sign_and_save(tmp_path)

        # Generate a different keypair
        other_keys = tmp_path / "other_keys"
        other_keys.mkdir()
        _, wrong_pub = generate_keypair(other_keys)

        with pytest.raises(SannaConstitutionError, match="tampered"):
            @sanna_observe(
                constitution_path=const_path,
                constitution_public_key_path=str(wrong_pub),
                require_constitution_sig=True,
            )
            def agent(query, context):
                return SIMPLE_OUTPUT

    def test_wrong_key_permissive(self, tmp_path):
        """Using the wrong public key fails even with require=False."""
        const_path, _pub_path = _sign_and_save(tmp_path)

        # Generate a different keypair
        other_keys = tmp_path / "other_keys"
        other_keys.mkdir()
        _, wrong_pub = generate_keypair(other_keys)

        with pytest.raises(SannaConstitutionError, match="tampered"):
            @sanna_observe(
                constitution_path=const_path,
                constitution_public_key_path=str(wrong_pub),
                require_constitution_sig=False,
            )
            def agent(query, context):
                return SIMPLE_OUTPUT


# =============================================================================
# 10. Default require_constitution_sig is True
# =============================================================================

class TestDefaultIsStrict:
    def test_default_requires_sig(self, tmp_path, monkeypatch):
        """Default require_constitution_sig=True: signed constitution
        without public key fails."""
        monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)
        const_path, _pub_path = _sign_and_save(tmp_path)

        with pytest.raises(SannaConstitutionError, match="no public key"):
            @sanna_observe(
                constitution_path=const_path,
                # No constitution_public_key_path, default require_constitution_sig=True
            )
            def agent(query, context):
                return SIMPLE_OUTPUT

    def test_default_with_key_works(self, tmp_path):
        """Default require_constitution_sig=True: signed constitution
        with valid public key succeeds."""
        const_path, pub_path = _sign_and_save(tmp_path)

        @sanna_observe(
            constitution_path=const_path,
            constitution_public_key_path=pub_path,
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert result.receipt.get("constitution_ref", {}).get("signature_verified") is True
