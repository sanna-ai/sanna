"""Tests for gateway constitution signature verification at startup.

Tests cover: valid signature, invalid/missing/tampered signature,
wrong public key, no public key configured, missing key file,
and end-to-end flows.
"""

import asyncio
import json
import sys
import textwrap

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import SannaGateway


# =============================================================================
# MOCK SERVER SCRIPT
# =============================================================================

MOCK_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream")

    @mcp.tool()
    def get_status() -> str:
        \"\"\"Get the current server status.\"\"\"
        return json.dumps({"status": "ok", "version": "1.0"})

    mcp.run(transport="stdio")
""")


# =============================================================================
# HELPERS
# =============================================================================

def _create_signed_constitution(tmp_path, authority_boundaries=None):
    """Create a signed constitution and keypair for testing.

    Returns (constitution_path, private_key_path, public_key_path).
    """
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution,
        AgentIdentity,
        Provenance,
        Boundary,
        sign_constitution,
        save_constitution,
    )

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    identity = AgentIdentity(
        agent_name="test-agent",
        domain="testing",
    )
    provenance = Provenance(
        authored_by="test@example.com",
        approved_by=["approver@example.com"],
        approval_date="2024-01-01",
        approval_method="manual-sign-off",
    )
    boundaries = [
        Boundary(
            id="B001",
            description="Test boundary",
            category="scope",
            severity="high",
        ),
    ]

    constitution = Constitution(
        schema_version="0.1.0",
        identity=identity,
        provenance=provenance,
        boundaries=boundaries,
        authority_boundaries=authority_boundaries,
    )

    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )

    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)

    return str(const_path), str(private_key_path), str(public_key_path)


def _create_gateway_key(tmp_path):
    """Create a separate keypair for gateway receipt signing.

    Returns (private_key_path, public_key_path).
    """
    from sanna.crypto import generate_keypair

    gw_keys_dir = tmp_path / "gw_keys"
    return generate_keypair(str(gw_keys_dir))


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def mock_server_path(tmp_path):
    """Write the mock server script to a temp file."""
    path = tmp_path / "mock_server.py"
    path.write_text(MOCK_SERVER_SCRIPT)
    return str(path)


@pytest.fixture()
def signed_constitution(tmp_path):
    """Create a signed constitution.

    Returns (constitution_path, private_key_path, public_key_path).
    """
    return _create_signed_constitution(tmp_path)


@pytest.fixture()
def gateway_key(tmp_path):
    """Create a separate keypair for gateway receipt signing.

    Returns (private_key_path, public_key_path).
    """
    return _create_gateway_key(tmp_path)


# =============================================================================
# 1. VALID SIGNATURE + MATCHING PUBLIC KEY
# =============================================================================

class TestConstitutionSignatureVerification:

    def test_valid_signature_startup_succeeds(
        self, mock_server_path, signed_constitution, gateway_key,
    ):
        """Valid signature + matching public key -> startup succeeds."""
        const_path, _, const_pub_key = signed_constitution
        gw_key_path, _ = gateway_key

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=const_pub_key,
            )
            await gw.start()
            try:
                assert gw.constitution is not None
                assert len(gw.tool_map) > 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_invalid_signature_startup_fails(
        self, mock_server_path, tmp_path, gateway_key,
    ):
        """Invalid signature (corrupted value) + public key -> startup fails."""
        from sanna.crypto import generate_keypair
        from sanna.constitution import (
            Constitution,
            AgentIdentity,
            Provenance,
            Boundary,
            ConstitutionSignature,
            sign_constitution,
            save_constitution,
        )

        keys_dir = tmp_path / "author_keys"
        private_key_path, public_key_path = generate_keypair(str(keys_dir))
        gw_key_path, _ = gateway_key

        constitution = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(
                agent_name="test-agent", domain="testing",
            ),
            provenance=Provenance(
                authored_by="test@example.com",
                approved_by=["approver@example.com"],
                approval_date="2024-01-01",
                approval_method="manual-sign-off",
            ),
            boundaries=[
                Boundary(
                    id="B001", description="Test",
                    category="scope", severity="high",
                ),
            ],
        )

        signed = sign_constitution(
            constitution, private_key_path=str(private_key_path),
        )

        # Corrupt the signature value
        signed.provenance.signature.value = "AAAA" + signed.provenance.signature.value[4:]

        const_path = tmp_path / "constitution.yaml"
        save_constitution(signed, const_path)

        from sanna.constitution import SannaConstitutionError

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=str(const_path),
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=str(public_key_path),
            )
            with pytest.raises(SannaConstitutionError, match="tampered"):
                await gw.start()

        asyncio.run(_test())

    def test_missing_signature_startup_fails(
        self, mock_server_path, tmp_path, gateway_key,
    ):
        """Constitution with no signature + public key -> startup fails."""
        from sanna.crypto import generate_keypair
        from sanna.constitution import (
            Constitution,
            AgentIdentity,
            Provenance,
            Boundary,
            save_constitution,
            compute_constitution_hash,
        )

        keys_dir = tmp_path / "author_keys"
        _, public_key_path = generate_keypair(str(keys_dir))
        gw_key_path, _ = gateway_key

        # Create a constitution with policy_hash but no Ed25519 signature
        constitution = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(
                agent_name="test-agent", domain="testing",
            ),
            provenance=Provenance(
                authored_by="test@example.com",
                approved_by=["approver@example.com"],
                approval_date="2024-01-01",
                approval_method="manual-sign-off",
            ),
            boundaries=[
                Boundary(
                    id="B001", description="Test",
                    category="scope", severity="high",
                ),
            ],
        )

        # Set policy_hash manually so it passes the initial check
        constitution.policy_hash = compute_constitution_hash(constitution)

        const_path = tmp_path / "constitution.yaml"
        save_constitution(constitution, const_path)

        from sanna.constitution import SannaConstitutionError

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=str(const_path),
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=str(public_key_path),
            )
            with pytest.raises(
                SannaConstitutionError,
                match="hashed but not signed|no cryptographic signature",
            ):
                await gw.start()

        asyncio.run(_test())

    def test_tampered_constitution_startup_fails(
        self, mock_server_path, tmp_path, gateway_key,
    ):
        """Tampered constitution (content edited after signing) -> fails."""
        from sanna.crypto import generate_keypair
        from sanna.constitution import (
            Constitution,
            AgentIdentity,
            Provenance,
            Boundary,
            sign_constitution,
            save_constitution,
            load_constitution,
            compute_constitution_hash,
        )

        keys_dir = tmp_path / "author_keys"
        private_key_path, public_key_path = generate_keypair(str(keys_dir))
        gw_key_path, _ = gateway_key

        constitution = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(
                agent_name="test-agent", domain="testing",
            ),
            provenance=Provenance(
                authored_by="test@example.com",
                approved_by=["approver@example.com"],
                approval_date="2024-01-01",
                approval_method="manual-sign-off",
            ),
            boundaries=[
                Boundary(
                    id="B001", description="Test",
                    category="scope", severity="high",
                ),
            ],
        )

        signed = sign_constitution(
            constitution, private_key_path=str(private_key_path),
        )

        # Tamper: change the agent name after signing
        signed.identity.agent_name = "attacker-agent"
        # Recompute policy_hash so load_constitution won't reject it
        signed.policy_hash = compute_constitution_hash(signed)

        const_path = tmp_path / "constitution.yaml"
        save_constitution(signed, const_path)

        from sanna.constitution import SannaConstitutionError

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=str(const_path),
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=str(public_key_path),
            )
            with pytest.raises(SannaConstitutionError, match="tampered"):
                await gw.start()

        asyncio.run(_test())

    def test_wrong_public_key_startup_fails(
        self, mock_server_path, signed_constitution, tmp_path,
        gateway_key,
    ):
        """Constitution signed with key A, gateway given key B -> fails."""
        const_path, _, _ = signed_constitution
        gw_key_path, _ = gateway_key

        # Generate a different keypair
        from sanna.crypto import generate_keypair
        other_keys_dir = tmp_path / "other_keys"
        _, wrong_pub_key = generate_keypair(str(other_keys_dir))

        from sanna.constitution import SannaConstitutionError

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=str(wrong_pub_key),
            )
            with pytest.raises(SannaConstitutionError, match="tampered"):
                await gw.start()

        asyncio.run(_test())

    def test_no_public_key_startup_succeeds(
        self, mock_server_path, signed_constitution, gateway_key,
    ):
        """No public key configured -> current behavior, startup succeeds."""
        const_path, _, _ = signed_constitution
        gw_key_path, _ = gateway_key

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=str(gw_key_path),
                # No constitution_public_key_path
            )
            await gw.start()
            try:
                assert gw.constitution is not None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_public_key_file_missing_startup_fails(
        self, mock_server_path, signed_constitution, gateway_key,
    ):
        """Public key file doesn't exist -> startup fails with clear error."""
        const_path, _, _ = signed_constitution
        gw_key_path, _ = gateway_key

        from sanna.constitution import SannaConstitutionError

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=str(gw_key_path),
                constitution_public_key_path="/nonexistent/key.pub",
            )
            with pytest.raises(Exception):
                await gw.start()

        asyncio.run(_test())


# =============================================================================
# 2. END-TO-END FLOWS
# =============================================================================

class TestConstitutionSigEndToEnd:

    def test_e2e_sign_and_verify_succeeds(
        self, mock_server_path, signed_constitution, gateway_key,
    ):
        """End-to-end: create, sign with key A, start with key A's pub -> OK."""
        const_path, _, const_pub_key = signed_constitution
        gw_key_path, _ = gateway_key

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=const_pub_key,
            )
            await gw.start()
            try:
                # Gateway is operational
                result = await gw._forward_call(
                    "mock_get_status", {},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ok"

                # Receipt was generated
                receipt = gw.last_receipt
                assert receipt is not None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_e2e_sign_key_a_verify_key_b_fails(
        self, mock_server_path, signed_constitution, tmp_path,
        gateway_key,
    ):
        """End-to-end: sign with key A, start with key B's pub -> fails."""
        const_path, _, _ = signed_constitution
        gw_key_path, _ = gateway_key

        from sanna.crypto import generate_keypair
        other_keys_dir = tmp_path / "key_b"
        _, key_b_pub = generate_keypair(str(other_keys_dir))

        from sanna.constitution import SannaConstitutionError

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=str(gw_key_path),
                constitution_public_key_path=str(key_b_pub),
            )
            with pytest.raises(SannaConstitutionError, match="tampered"):
                await gw.start()

        asyncio.run(_test())


# =============================================================================
# 3. CONFIG INTEGRATION
# =============================================================================

class TestConstitutionPublicKeyConfig:

    def test_config_parses_constitution_public_key(self, tmp_path):
        """Config parser extracts constitution_public_key path."""
        from sanna.gateway.config import load_gateway_config

        const_path, key_path, pub_key_path = _create_signed_constitution(
            tmp_path,
        )
        _, gw_pub_key = _create_gateway_key(tmp_path)

        config_yaml = textwrap.dedent(f"""\
            gateway:
              constitution: {const_path}
              constitution_public_key: {pub_key_path}
              signing_key: {key_path}

            downstream:
              - name: mock
                command: echo
                args: ["hello"]
        """)
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(config_yaml)

        config = load_gateway_config(str(config_file))
        assert config.constitution_public_key_path == pub_key_path

    def test_config_omitted_key_is_empty(self, tmp_path):
        """Config without constitution_public_key -> empty string."""
        from sanna.gateway.config import load_gateway_config

        const_path, key_path, _ = _create_signed_constitution(tmp_path)

        config_yaml = textwrap.dedent(f"""\
            gateway:
              constitution: {const_path}
              signing_key: {key_path}

            downstream:
              - name: mock
                command: echo
                args: ["hello"]
        """)
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(config_yaml)

        config = load_gateway_config(str(config_file))
        assert config.constitution_public_key_path == ""

    def test_config_missing_key_file_raises(self, tmp_path):
        """Config with nonexistent constitution_public_key file -> error."""
        from sanna.gateway.config import (
            GatewayConfigError,
            load_gateway_config,
        )

        const_path, key_path, _ = _create_signed_constitution(tmp_path)

        config_yaml = textwrap.dedent(f"""\
            gateway:
              constitution: {const_path}
              constitution_public_key: /nonexistent/author.pub
              signing_key: {key_path}

            downstream:
              - name: mock
                command: echo
                args: ["hello"]
        """)
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(config_yaml)

        with pytest.raises(
            GatewayConfigError,
            match="Constitution public key file not found",
        ):
            load_gateway_config(str(config_file))
