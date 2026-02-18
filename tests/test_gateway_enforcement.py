"""Tests for gateway constitution enforcement (Block C).

Tests cover: policy resolution, cannot_execute halt, must_escalate escalation,
can_execute forwarding, receipt generation, receipt signing, fingerprint
verification, policy overrides, and edge cases.

Note: Block E changed must_escalate from deny to structured ESCALATION_REQUIRED.
"""

import asyncio
import json
import sys
import textwrap

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import SannaGateway, _dict_to_tool


# =============================================================================
# MOCK SERVER SCRIPT (same as Block B tests)
# =============================================================================

MOCK_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream")

    @mcp.tool()
    def get_status() -> str:
        \"\"\"Get the current server status.\"\"\"
        return json.dumps({"status": "ok", "version": "1.0"})

    @mcp.tool()
    def search(query: str, limit: int = 10) -> str:
        \"\"\"Search for items matching a query.\"\"\"
        return json.dumps({"query": query, "limit": limit, "results": ["a", "b"]})

    @mcp.tool()
    def create_item(name: str, tags: list[str], metadata: dict) -> str:
        \"\"\"Create a new item with tags and metadata.\"\"\"
        return json.dumps({
            "created": True, "name": name,
            "tags": tags, "metadata": metadata,
        })

    @mcp.tool()
    def delete_item(item_id: str) -> str:
        \"\"\"Delete an item by ID.\"\"\"
        return json.dumps({"deleted": True, "item_id": item_id})

    @mcp.tool()
    def update_item(item_id: str, name: str) -> str:
        \"\"\"Update an item.\"\"\"
        return json.dumps({"updated": True, "item_id": item_id, "name": name})

    @mcp.tool()
    def error_tool() -> str:
        \"\"\"A tool that always errors.\"\"\"
        raise ValueError("Intentional error for testing")

    mcp.run(transport="stdio")
""")


# =============================================================================
# HELPERS
# =============================================================================

def _create_signed_constitution(
    tmp_path,
    authority_boundaries=None,
    invariants=None,
):
    """Create a signed constitution and keypair for testing.

    Returns (constitution_path, private_key_path, public_key_path).
    """
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution,
        AgentIdentity,
        Provenance,
        Boundary,
        Invariant,
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

    invariant_objs = []
    if invariants:
        for inv in invariants:
            invariant_objs.append(Invariant(
                id=inv["id"],
                rule=inv["rule"],
                enforcement=inv["enforcement"],
                check=inv.get("check"),
            ))

    constitution = Constitution(
        schema_version="0.1.0",
        identity=identity,
        provenance=provenance,
        boundaries=boundaries,
        invariants=invariant_objs,
        authority_boundaries=authority_boundaries,
    )

    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )

    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)

    return str(const_path), str(private_key_path), str(public_key_path)


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
    """Create a signed constitution with authority boundaries."""
    from sanna.constitution import (
        AuthorityBoundaries,
        EscalationRule,
    )

    ab = AuthorityBoundaries(
        cannot_execute=["delete_item"],
        must_escalate=[
            EscalationRule(condition="update"),
        ],
        can_execute=["get_status", "search"],
    )
    return _create_signed_constitution(tmp_path, authority_boundaries=ab)


@pytest.fixture()
def constitution_with_invariants(tmp_path):
    """Create a signed constitution with authority boundaries and invariants."""
    from sanna.constitution import (
        AuthorityBoundaries,
        EscalationRule,
    )

    ab = AuthorityBoundaries(
        cannot_execute=["delete_item"],
        must_escalate=[
            EscalationRule(condition="update"),
        ],
        can_execute=["get_status", "search"],
    )
    invariants = [
        {
            "id": "INV_NO_FABRICATION",
            "rule": "Do not fabricate facts.",
            "enforcement": "halt",
        },
        {
            "id": "INV_MARK_INFERENCE",
            "rule": "Mark inferences.",
            "enforcement": "warn",
        },
    ]
    return _create_signed_constitution(
        tmp_path, authority_boundaries=ab, invariants=invariants,
    )


@pytest.fixture()
def minimal_constitution(tmp_path):
    """Constitution with no authority boundaries and no invariants."""
    return _create_signed_constitution(tmp_path)


# =============================================================================
# 1. TRANSPARENT PASSTHROUGH (NO CONSTITUTION)
# =============================================================================

class TestNoConstitution:
    def test_passthrough_without_constitution(self, mock_server_path):
        """Without constitution, calls pass through transparently."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ok"
                assert gw.last_receipt is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_constitution_not_loaded(self, mock_server_path):
        """Constitution property is None without constitution_path."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                assert gw.constitution is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 2. CONSTITUTION LOADING
# =============================================================================

class TestConstitutionLoading:
    def test_loads_constitution_on_start(
        self, mock_server_path, signed_constitution,
    ):
        """Constitution is loaded during start()."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                assert gw.constitution is not None
                assert gw.constitution.policy_hash is not None
                assert gw.constitution.identity.agent_name == "test-agent"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_constitution_cleared_on_shutdown(
        self, mock_server_path, signed_constitution,
    ):
        """Constitution state is cleaned up on shutdown."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            assert gw.constitution is not None
            await gw.shutdown()
            assert gw.constitution is None

        asyncio.run(_test())

    def test_unsigned_constitution_raises(self, mock_server_path, tmp_path):
        """Start fails with unsigned constitution."""
        from sanna.constitution import (
            Constitution, AgentIdentity, Provenance, Boundary,
            save_constitution, SannaConstitutionError,
        )

        # Create unsigned constitution
        constitution = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="test", domain="test"),
            provenance=Provenance(
                authored_by="test@test.com",
                approved_by=["approver@test.com"],
                approval_date="2024-01-01",
                approval_method="manual",
            ),
            boundaries=[
                Boundary(id="B001", description="x", category="scope",
                         severity="high"),
            ],
        )
        const_path = tmp_path / "unsigned.yaml"
        save_constitution(constitution, const_path)

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=str(const_path),
                require_constitution_sig=False,
            )
            with pytest.raises(SannaConstitutionError):
                await gw.start()

        asyncio.run(_test())


# =============================================================================
# 3. CANNOT_EXECUTE (HALT)
# =============================================================================

class TestCannotExecute:
    def test_halt_blocks_tool_call(
        self, mock_server_path, signed_constitution,
    ):
        """cannot_execute tool returns isError and is not forwarded."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                assert result.isError is True
                assert "denied" in result.content[0].text.lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_halt_generates_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """Halted call still generates a receipt."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                receipt = gw.last_receipt
                assert receipt is not None
                assert receipt["enforcement"] is not None
                assert receipt["enforcement"]["action"] == "halted"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_halt_receipt_has_authority_decision(
        self, mock_server_path, signed_constitution,
    ):
        """Halt receipt documents the authority decision."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert len(ad) == 1
                assert ad[0]["decision"] == "halt"
                assert ad[0]["boundary_type"] == "cannot_execute"
                assert ad[0]["action"] == "delete_item"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 4. MUST_ESCALATE
# =============================================================================

class TestMustEscalate:
    def test_escalate_returns_escalation_required(
        self, mock_server_path, signed_constitution,
    ):
        """must_escalate tool returns ESCALATION_REQUIRED (not a deny)."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                # Block E: escalation returns structured JSON, not isError
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
                assert "escalation_id" in data
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_escalate_generates_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """Escalated call generates a receipt."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                receipt = gw.last_receipt
                assert receipt is not None
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "escalate"
                assert ad[0]["boundary_type"] == "must_escalate"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_escalate_has_no_enforcement(
        self, mock_server_path, signed_constitution,
    ):
        """Escalation receipt has no enforcement (not the same as halt)."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                receipt = gw.last_receipt
                assert receipt.get("enforcement") is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 5. CAN_EXECUTE (ALLOW + FORWARD)
# =============================================================================

class TestCanExecute:
    def test_allow_forwards_and_returns_result(
        self, mock_server_path, signed_constitution,
    ):
        """Allowed tool call is forwarded and result is returned."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ok"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_allow_generates_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """Allowed call generates a receipt with allow decision."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                receipt = gw.last_receipt
                assert receipt is not None
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "allow"
                assert receipt.get("enforcement") is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_allow_with_params(
        self, mock_server_path, signed_constitution,
    ):
        """Allowed call with params forwards correctly."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search", {"query": "hello", "limit": 5},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["query"] == "hello"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_uncategorized_allowed(
        self, mock_server_path, signed_constitution,
    ):
        """Tool not in any boundary list is allowed (uncategorized)."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_create_item", {
                    "name": "widget",
                    "tags": ["red"],
                    "metadata": {"weight": 42},
                })
                assert result.isError is not True
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "allow"
                assert ad[0]["boundary_type"] == "uncategorized"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 6. RECEIPT STRUCTURE AND VERIFICATION
# =============================================================================

class TestReceiptStructure:
    def test_receipt_has_required_fields(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt contains all required fields."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                assert "spec_version" in r
                assert "tool_version" in r
                assert "checks_version" in r
                assert "receipt_id" in r
                assert "receipt_fingerprint" in r
                assert "correlation_id" in r
                assert "timestamp" in r
                assert "inputs" in r
                assert "outputs" in r
                assert "context_hash" in r
                assert "output_hash" in r
                assert "status" in r
                assert "constitution_ref" in r
                assert "authority_decisions" in r
                assert "extensions" in r
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_has_constitution_ref(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt has constitution_ref with policy_hash."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                cref = r["constitution_ref"]
                assert cref is not None
                assert "policy_hash" in cref
                assert cref["policy_hash"] == gw.constitution.policy_hash
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_has_gateway_extensions(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt extensions include gateway metadata."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                gw_ext = r["extensions"]["com.sanna.gateway"]
                assert gw_ext["server_name"] == "mock"
                assert gw_ext["tool_name"] == "get_status"
                assert gw_ext["prefixed_name"] == "mock_get_status"
                assert gw_ext["decision"] == "allow"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_fingerprint_verifies(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt fingerprint passes offline verification."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            from sanna.verify import verify_fingerprint

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                matches, computed, expected = verify_fingerprint(r)
                assert matches, (
                    f"Fingerprint mismatch: computed={computed}, "
                    f"expected={expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_halt_receipt_fingerprint_verifies(
        self, mock_server_path, signed_constitution,
    ):
        """Halt receipt fingerprint also passes verification."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            from sanna.verify import verify_fingerprint

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_delete_item", {"item_id": "x"},
                )
                r = gw.last_receipt
                matches, computed, expected = verify_fingerprint(r)
                assert matches, (
                    f"Fingerprint mismatch: computed={computed}, "
                    f"expected={expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_escalate_receipt_fingerprint_verifies(
        self, mock_server_path, signed_constitution,
    ):
        """Escalation receipt fingerprint passes verification."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            from sanna.verify import verify_fingerprint

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                r = gw.last_receipt
                matches, computed, expected = verify_fingerprint(r)
                assert matches, (
                    f"Fingerprint mismatch: computed={computed}, "
                    f"expected={expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 7. RECEIPT SIGNING
# =============================================================================

class TestReceiptSigning:
    def test_receipt_signed_when_key_provided(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt has receipt_signature when signing key is provided."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                assert "receipt_signature" in r
                assert r["receipt_signature"]["signature"] != ""
                assert r["receipt_signature"]["scheme"] == "receipt_sig_v1"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_signature_verifies(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt signature passes Ed25519 verification."""
        const_path, key_path, pub_key_path = signed_constitution
        async def _test():
            from sanna.crypto import verify_receipt_signature

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                assert verify_receipt_signature(r, pub_key_path)
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_not_signed_without_key(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt has no signature when no signing key is provided."""
        const_path, _, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                assert "receipt_signature" not in r
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 8. POLICY OVERRIDES
# =============================================================================

class TestPolicyOverrides:
    def test_override_cannot_execute(
        self, mock_server_path, signed_constitution,
    ):
        """Per-tool cannot_execute override halts even if constitution allows."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"get_status": "cannot_execute"},
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "halt"
                assert ad[0]["boundary_type"] == "cannot_execute"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_override_must_escalate(
        self, mock_server_path, signed_constitution,
    ):
        """Per-tool must_escalate override forces escalation."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"search": "must_escalate"},
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                # Block E: escalation returns structured JSON, not isError
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "escalate"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_override_can_execute(
        self, mock_server_path, signed_constitution,
    ):
        """Per-tool can_execute override allows even if constitution denies."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                # delete_item is cannot_execute in constitution,
                # but we override to can_execute
                policy_overrides={"delete_item": "can_execute"},
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["deleted"] is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_override_takes_precedence(
        self, mock_server_path, signed_constitution,
    ):
        """Override receipt documents the override, not the constitution."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"get_status": "cannot_execute"},
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert "Policy override" in ad[0]["reason"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 9. CONSTITUTION WITH INVARIANTS
# =============================================================================

class TestConstitutionInvariants:
    def test_checks_run_with_invariants(
        self, mock_server_path, constitution_with_invariants,
    ):
        """Receipt contains check results when constitution has invariants."""
        const_path, key_path, _ = constitution_with_invariants
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                assert len(r["checks"]) == 2
                check_ids = {c["check_id"] for c in r["checks"]}
                assert "sanna.context_contradiction" in check_ids
                assert "sanna.unmarked_inference" in check_ids
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_invariant_receipt_fingerprint_verifies(
        self, mock_server_path, constitution_with_invariants,
    ):
        """Receipt with invariant checks has valid fingerprint."""
        const_path, key_path, _ = constitution_with_invariants
        async def _test():
            from sanna.verify import verify_fingerprint

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                matches, computed, expected = verify_fingerprint(r)
                assert matches
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_no_invariants_empty_checks(
        self, mock_server_path, minimal_constitution,
    ):
        """Constitution without invariants produces receipt with empty checks."""
        const_path, key_path, _ = minimal_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                assert r["checks"] == []
                assert r["status"] == "PASS"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 10. EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_multiple_calls_generate_separate_receipts(
        self, mock_server_path, signed_constitution,
    ):
        """Each tool call generates a unique receipt."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r1 = gw.last_receipt

                await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                r2 = gw.last_receipt

                assert r1["receipt_id"] != r2["receipt_id"]
                assert r1["correlation_id"] != r2["correlation_id"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_unknown_tool_no_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """Unknown tool returns error without generating receipt."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_nonexistent", {})
                assert result.isError is True
                # No receipt for unknown tools (pre-enforcement)
                assert gw.last_receipt is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_correlation_id_has_gateway_prefix(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt correlation_id starts with 'gw-' prefix."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                assert gw.last_receipt["correlation_id"].startswith("gw-")
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_no_authority_boundaries_allows_all(
        self, mock_server_path, minimal_constitution,
    ):
        """Constitution without authority_boundaries allows all tools."""
        const_path, key_path, _ = minimal_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_item", {"item_id": "1"},
                )
                assert result.isError is not True
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "allow"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_constitution_approval_in_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt constitution_ref includes constitution_approval."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                r = gw.last_receipt
                cref = r["constitution_ref"]
                assert "constitution_approval" in cref
                # Our test constitution is not approved
                assert cref["constitution_approval"]["status"] == "unapproved"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 11. POLICY CASCADE — DEFAULT_POLICY + CONSTITUTION FALLTHROUGH
# =============================================================================

class TestPolicyCascadeFallthrough:
    """Regression tests for the policy cascade bug (v0.10.1).

    The bug: _resolve_policy() returned self._default_policy ("can_execute")
    when there was no per-tool override. This was treated as an explicit
    allow, so constitution evaluation never fired on the default path.

    The fix: _resolve_policy() returns None when effective policy is
    can_execute (no per-tool override AND default_policy is can_execute
    or None), allowing fallthrough to constitution evaluation.
    """

    def test_default_can_execute_constitution_blocks(
        self, mock_server_path, signed_constitution,
    ):
        """default_policy=can_execute + constitution cannot_execute → BLOCKED.

        This is the core bug: before the fix, delete_item was allowed
        because default_policy="can_execute" short-circuited constitution
        evaluation.
        """
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                default_policy="can_execute",
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                assert result.isError is True
                assert "denied" in result.content[0].text.lower()
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "halt"
                assert ad[0]["boundary_type"] == "cannot_execute"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_default_can_execute_constitution_escalates(
        self, mock_server_path, signed_constitution,
    ):
        """default_policy=can_execute + constitution must_escalate → ESCALATION.

        update_item matches the "update" escalation condition in the
        constitution. With default_policy=can_execute, the cascade must
        fall through to constitution evaluation.
        """
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                default_policy="can_execute",
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "escalate"
                assert ad[0]["boundary_type"] == "must_escalate"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_default_can_execute_constitution_no_opinion(
        self, mock_server_path, signed_constitution,
    ):
        """default_policy=can_execute + constitution has no opinion → ALLOWED.

        create_item is not in any authority boundary list. Constitution
        fallthrough defaults to allow (uncategorized).
        """
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                default_policy="can_execute",
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_create_item", {
                    "name": "widget",
                    "tags": ["a"],
                    "metadata": {"k": 1},
                })
                assert result.isError is not True
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "allow"
                assert ad[0]["boundary_type"] == "uncategorized"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_default_must_escalate_fires_without_constitution(
        self, mock_server_path, signed_constitution,
    ):
        """default_policy=must_escalate + no per-tool override → ESCALATION.

        Restrictive default_policy takes effect without falling through
        to constitution evaluation.
        """
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                default_policy="must_escalate",
            )
            await gw.start()
            try:
                # get_status is can_execute in the constitution, but
                # default_policy=must_escalate overrides at server level
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "escalate"
                assert "Policy override" in ad[0]["reason"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_per_tool_can_execute_overrides_constitution(
        self, mock_server_path, signed_constitution,
    ):
        """Explicit per-tool can_execute → ALLOWED regardless of constitution.

        delete_item is cannot_execute in the constitution, but an explicit
        per-tool override to can_execute is intentional and wins.
        """
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                default_policy="can_execute",
                policy_overrides={"delete_item": "can_execute"},
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["deleted"] is True
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "allow"
                assert "Policy override" in ad[0]["reason"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_per_tool_cannot_execute_overrides_default(
        self, mock_server_path, signed_constitution,
    ):
        """Explicit per-tool cannot_execute → BLOCKED regardless of default_policy.

        get_status is can_execute in the constitution and default_policy
        is can_execute, but the per-tool override blocks it.
        """
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                default_policy="can_execute",
                policy_overrides={"get_status": "cannot_execute"},
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_get_status", {})
                assert result.isError is True
                receipt = gw.last_receipt
                ad = receipt["authority_decisions"]
                assert ad[0]["decision"] == "halt"
                assert ad[0]["boundary_type"] == "cannot_execute"
                assert "Policy override" in ad[0]["reason"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# RECEIPT FIDELITY TESTS (v0.10.1)
# =============================================================================


class TestReceiptFidelity:
    """Tests for receipt fidelity: argument/output hashes, error marking."""

    def test_receipt_has_arguments_hash(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt gateway extensions include arguments_hash."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_get_status", {},
                )
                r = gw.last_receipt
                gw_ext = r["extensions"]["com.sanna.gateway"]
                assert "arguments_hash" in gw_ext
                assert len(gw_ext["arguments_hash"]) == 64  # full SHA-256
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_has_tool_output_hash(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt gateway extensions include tool_output_hash."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_get_status", {},
                )
                r = gw.last_receipt
                gw_ext = r["extensions"]["com.sanna.gateway"]
                assert "tool_output_hash" in gw_ext
                assert len(gw_ext["tool_output_hash"]) == 64
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_downstream_is_error_false_on_success(
        self, mock_server_path, signed_constitution,
    ):
        """downstream_is_error is False when downstream succeeds."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_get_status", {},
                )
                r = gw.last_receipt
                gw_ext = r["extensions"]["com.sanna.gateway"]
                assert gw_ext["downstream_is_error"] is False
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_arguments_hash_differs_for_different_args(
        self, mock_server_path, signed_constitution,
    ):
        """Different arguments produce different hashes."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "alpha"},
                )
                hash_1 = gw.last_receipt["extensions"]["com.sanna.gateway"][
                    "arguments_hash"
                ]

                await gw._forward_call(
                    "mock_search", {"query": "beta"},
                )
                hash_2 = gw.last_receipt["extensions"]["com.sanna.gateway"][
                    "arguments_hash"
                ]

                assert hash_1 != hash_2
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_arguments_hash_deterministic(
        self, mock_server_path, signed_constitution,
    ):
        """Same arguments produce same hash (canonical JSON)."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "same", "limit": 5},
                )
                hash_1 = gw.last_receipt["extensions"]["com.sanna.gateway"][
                    "arguments_hash"
                ]

                await gw._forward_call(
                    "mock_search", {"query": "same", "limit": 5},
                )
                hash_2 = gw.last_receipt["extensions"]["com.sanna.gateway"][
                    "arguments_hash"
                ]

                assert hash_1 == hash_2
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_halt_receipt_has_fidelity_fields(
        self, mock_server_path, signed_constitution,
    ):
        """Halted (cannot_execute) receipts also include fidelity hashes."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"get_status": "cannot_execute"},
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_get_status", {},
                )
                assert result.isError is True
                r = gw.last_receipt
                gw_ext = r["extensions"]["com.sanna.gateway"]
                assert "arguments_hash" in gw_ext
                assert "tool_output_hash" in gw_ext
                # downstream_is_error is False for halt (never reached downstream)
                assert gw_ext["downstream_is_error"] is False
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_fingerprint_still_verifies(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt with fidelity fields passes fingerprint verification."""
        from sanna.verify import verify_fingerprint
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_get_status", {},
                )
                r = gw.last_receipt
                matches, _, _ = verify_fingerprint(r)
                assert matches
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# PUBLIC API PROMOTION TESTS (v0.10.1)
# =============================================================================


class TestPublicAPIPromotion:
    """Tests that promoted middleware functions are accessible."""

    def test_build_trace_data_importable_from_sanna(self):
        """build_trace_data is importable from sanna.middleware."""
        from sanna.middleware import build_trace_data
        td = build_trace_data(
            correlation_id="test-123",
            query="what is X?",
            context="X is Y.",
            output="X is Y.",
        )
        assert td["correlation_id"] == "test-123"
        assert td["input"]["query"] == "what is X?"
        assert td["output"]["final_answer"] == "X is Y."

    def test_generate_constitution_receipt_importable_from_sanna(self):
        """generate_constitution_receipt is importable from sanna.middleware."""
        from sanna.middleware import generate_constitution_receipt, build_trace_data
        td = build_trace_data(
            correlation_id="test-456",
            query="q",
            context="c",
            output="o",
        )
        receipt = generate_constitution_receipt(
            td,
            check_configs=[],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0.0",
        )
        assert receipt["correlation_id"] == "test-456"
        assert "receipt_id" in receipt

    def test_build_trace_data_importable_from_middleware(self):
        """build_trace_data is importable from sanna.middleware."""
        from sanna.middleware import build_trace_data
        assert callable(build_trace_data)

    def test_generate_constitution_receipt_importable_from_middleware(self):
        """generate_constitution_receipt is importable from middleware."""
        from sanna.middleware import generate_constitution_receipt
        assert callable(generate_constitution_receipt)
