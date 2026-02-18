"""Tests for gateway must_escalate UX (Block E).

Tests cover: escalation lifecycle (create, approve, deny), receipt chain,
expiry, meta-tool registration, concurrent escalations, and edge cases.
"""

import asyncio
import json
import sys
import textwrap

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import (
    SannaGateway,
    EscalationStore,
    PendingEscalation,
    _META_TOOL_APPROVE,
    _META_TOOL_DENY,
)


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

    @mcp.tool()
    def search(query: str, limit: int = 10) -> str:
        \"\"\"Search for items matching a query.\"\"\"
        return json.dumps({"query": query, "limit": limit, "results": ["a", "b"]})

    @mcp.tool()
    def update_item(item_id: str, name: str) -> str:
        \"\"\"Update an item.\"\"\"
        return json.dumps({"updated": True, "item_id": item_id, "name": name})

    @mcp.tool()
    def delete_item(item_id: str) -> str:
        \"\"\"Delete an item by ID.\"\"\"
        return json.dumps({"deleted": True, "item_id": item_id})

    mcp.run(transport="stdio")
""")


# =============================================================================
# HELPERS
# =============================================================================

def _get_approval_token(gw, escalation_id: str) -> str:
    """Compute the valid approval token for a pending escalation.

    Uses the gateway's internal HMAC computation — mirrors what the
    gateway prints to stderr during escalation creation.
    """
    entry = gw.escalation_store.get(escalation_id)
    assert entry is not None, f"Escalation {escalation_id} not in store"
    return gw._compute_approval_token(entry)


def _create_signed_constitution(
    tmp_path,
    authority_boundaries=None,
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
    """Create a signed constitution with must_escalate for update_item."""
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


# =============================================================================
# 1. ESCALATION REQUIRED — CREATING PENDING ESCALATION
# =============================================================================

class TestEscalationRequired:
    def test_escalation_returns_structured_json(
        self, mock_server_path, signed_constitution,
    ):
        """must_escalate tool call returns ESCALATION_REQUIRED with
        escalation_id (not a deny)."""
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
                # Not an error — it's an escalation prompt
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
                assert data["escalation_id"].startswith("esc_")
                assert data["tool"] == "mock_update_item"
                assert data["parameters"] == {"item_id": "1", "name": "new"}
                assert "reason" in data
                assert "instruction" in data
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_escalation_creates_pending_entry(
        self, mock_server_path, signed_constitution,
    ):
        """Escalation adds entry to the escalation store."""
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
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]
                entry = gw.escalation_store.get(esc_id)
                assert entry is not None
                assert entry.original_name == "update_item"
                assert entry.arguments == {"item_id": "1", "name": "new"}
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 2. APPROVE ESCALATION
# =============================================================================

class TestApproveEscalation:
    def test_approve_forwards_to_downstream(
        self, mock_server_path, signed_constitution,
    ):
        """Approve valid escalation → original request forwarded to
        downstream, result returned."""
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
                # Trigger escalation
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "42", "name": "approved-name"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                # Approve it
                approve_result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert approve_result.isError is not True
                data = json.loads(approve_result.content[0].text)
                assert data["updated"] is True
                assert data["item_id"] == "42"
                assert data["name"] == "approved-name"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approve_receipt_has_chain(
        self, mock_server_path, signed_constitution,
    ):
        """Approve valid escalation → receipt includes full approval chain."""
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
                # Trigger escalation
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                esc_receipt = gw.last_receipt
                esc_receipt_id = esc_receipt["receipt_id"]
                token = _get_approval_token(gw, esc_id)

                # Approve
                await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                approval_receipt = gw.last_receipt

                # Chain fields in extensions
                gw_ext = approval_receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["escalation_id"] == esc_id
                assert gw_ext["escalation_receipt_id"] == esc_receipt_id
                assert gw_ext["escalation_resolution"] == "approved"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approve_removes_from_store(
        self, mock_server_path, signed_constitution,
    ):
        """After approval, the escalation is removed from the store."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                assert len(gw.escalation_store) == 1
                token = _get_approval_token(gw, esc_id)

                await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert len(gw.escalation_store) == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 3. DENY ESCALATION
# =============================================================================

class TestDenyEscalation:
    def test_deny_generates_halt_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """Deny valid escalation → denial receipt generated with enforcement,
        no downstream call."""
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
                # Trigger escalation
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                # Deny
                deny_result = await gw._forward_call(
                    _META_TOOL_DENY,
                    {"escalation_id": esc_id},
                )
                assert deny_result.isError is not True
                deny_data = json.loads(deny_result.content[0].text)
                assert deny_data["status"] == "denied"

                # Receipt has enforcement
                receipt = gw.last_receipt
                assert receipt["enforcement"] is not None
                assert receipt["enforcement"]["action"] == "halted"
                assert esc_id in receipt["enforcement"]["reason"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_deny_receipt_has_chain(
        self, mock_server_path, signed_constitution,
    ):
        """Denial receipt references the original escalation receipt ID."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                esc_receipt_id = gw.last_receipt["receipt_id"]

                await gw._forward_call(
                    _META_TOOL_DENY,
                    {"escalation_id": esc_id},
                )
                deny_receipt = gw.last_receipt
                gw_ext = deny_receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["escalation_id"] == esc_id
                assert gw_ext["escalation_receipt_id"] == esc_receipt_id
                assert gw_ext["escalation_resolution"] == "denied"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 4. EXPIRED AND NOT FOUND
# =============================================================================

class TestExpiredAndNotFound:
    def test_approve_nonexistent_returns_not_found(
        self, mock_server_path, signed_constitution,
    ):
        """Approve nonexistent escalation_id → ESCALATION_NOT_FOUND error."""
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
                    _META_TOOL_APPROVE,
                    {"escalation_id": "esc_does_not_exist"},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_NOT_FOUND"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_deny_nonexistent_returns_not_found(
        self, mock_server_path, signed_constitution,
    ):
        """Deny nonexistent escalation_id → ESCALATION_NOT_FOUND error."""
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
                    _META_TOOL_DENY,
                    {"escalation_id": "esc_does_not_exist"},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_NOT_FOUND"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approve_expired_returns_expired(
        self, mock_server_path, signed_constitution,
    ):
        """Approve expired escalation → ESCALATION_EXPIRED error."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_timeout=1,  # 1 second
            )
            await gw.start()
            try:
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                # Wait for expiry
                await asyncio.sleep(1.2)

                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_EXPIRED"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_deny_expired_returns_expired(
        self, mock_server_path, signed_constitution,
    ):
        """Deny expired escalation → ESCALATION_EXPIRED error."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_timeout=1,  # 1 second
            )
            await gw.start()
            try:
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                await asyncio.sleep(1.2)

                result = await gw._forward_call(
                    _META_TOOL_DENY,
                    {"escalation_id": esc_id},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_EXPIRED"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 5. RECEIPT VERIFICATION
# =============================================================================

class TestReceiptVerification:
    def test_escalation_receipt_verifies_offline(
        self, mock_server_path, signed_constitution,
    ):
        """Escalation receipt fingerprint passes offline verification."""
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
                    f"Escalation receipt fingerprint mismatch: "
                    f"computed={computed}, expected={expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approval_receipt_verifies_offline(
        self, mock_server_path, signed_constitution,
    ):
        """Approval receipt fingerprint passes offline verification."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                r = gw.last_receipt
                matches, computed, expected = verify_fingerprint(r)
                assert matches, (
                    f"Approval receipt fingerprint mismatch: "
                    f"computed={computed}, expected={expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_denial_receipt_verifies_offline(
        self, mock_server_path, signed_constitution,
    ):
        """Denial receipt fingerprint passes offline verification."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                await gw._forward_call(
                    _META_TOOL_DENY,
                    {"escalation_id": esc_id},
                )
                r = gw.last_receipt
                matches, computed, expected = verify_fingerprint(r)
                assert matches, (
                    f"Denial receipt fingerprint mismatch: "
                    f"computed={computed}, expected={expected}"
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approval_receipt_references_escalation_receipt_id(
        self, mock_server_path, signed_constitution,
    ):
        """Approval receipt references the original escalation receipt ID."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                esc_receipt_id = gw.last_receipt["receipt_id"]
                token = _get_approval_token(gw, esc_id)

                await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                approval_receipt = gw.last_receipt
                chain_ref = approval_receipt["extensions"]["com.sanna.gateway"][
                    "escalation_receipt_id"
                ]
                assert chain_ref == esc_receipt_id
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 6. META-TOOL REGISTRATION
# =============================================================================

class TestMetaToolRegistration:
    def test_meta_tools_visible_in_tool_list(
        self, mock_server_path, signed_constitution,
    ):
        """Meta-tools (approve/deny) are registered and visible in
        gateway's tool list."""
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
                tools = gw._build_tool_list()
                names = {t.name for t in tools}
                assert _META_TOOL_APPROVE in names
                assert _META_TOOL_DENY in names
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_meta_tools_not_prefixed(
        self, mock_server_path, signed_constitution,
    ):
        """Meta-tools do NOT get prefixed with a server name."""
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
                tools = gw._build_tool_list()
                for t in tools:
                    if t.name in (_META_TOOL_APPROVE, _META_TOOL_DENY):
                        assert not t.name.startswith("mock_")
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_meta_tools_have_schemas(
        self, mock_server_path, signed_constitution,
    ):
        """Meta-tools have proper input schemas with escalation_id."""
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
                tools = gw._build_tool_list()
                meta_tools = {t.name: t for t in tools
                              if t.name in (_META_TOOL_APPROVE, _META_TOOL_DENY)}
                for name, tool in meta_tools.items():
                    schema = tool.inputSchema
                    assert "escalation_id" in schema["properties"]
                    assert "escalation_id" in schema["required"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 7. CONCURRENT ESCALATIONS
# =============================================================================

class TestConcurrentEscalations:
    def test_two_escalations_approve_one_deny_other(
        self, mock_server_path, signed_constitution,
    ):
        """Two different escalation IDs: approve one, deny the other."""
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
                # Trigger two escalations
                r1 = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "first"},
                )
                esc_id_1 = json.loads(r1.content[0].text)["escalation_id"]

                r2 = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "2", "name": "second"},
                )
                esc_id_2 = json.loads(r2.content[0].text)["escalation_id"]

                assert esc_id_1 != esc_id_2
                assert len(gw.escalation_store) == 2
                token_1 = _get_approval_token(gw, esc_id_1)

                # Approve first
                approve_result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id_1, "approval_token": token_1},
                )
                data = json.loads(approve_result.content[0].text)
                assert data["updated"] is True
                assert data["item_id"] == "1"

                # Deny second
                deny_result = await gw._forward_call(
                    _META_TOOL_DENY,
                    {"escalation_id": esc_id_2},
                )
                deny_data = json.loads(deny_result.content[0].text)
                assert deny_data["status"] == "denied"

                assert len(gw.escalation_store) == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 8. DOUBLE RESOLUTION
# =============================================================================

class TestDoubleResolution:
    def test_double_approve_returns_not_found(
        self, mock_server_path, signed_constitution,
    ):
        """Double-approve same escalation_id → second call returns NOT_FOUND."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_id = json.loads(
                    esc_result.content[0].text,
                )["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                # First approve succeeds
                r1 = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert r1.isError is not True

                # Second approve → NOT_FOUND (entry removed)
                r2 = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert r2.isError is True
                data = json.loads(r2.content[0].text)
                assert data["error"] == "ESCALATION_NOT_FOUND"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approve_then_deny_returns_not_found(
        self, mock_server_path, signed_constitution,
    ):
        """Approve then deny same escalation → deny returns NOT_FOUND."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_id = json.loads(
                    esc_result.content[0].text,
                )["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )

                deny_result = await gw._forward_call(
                    _META_TOOL_DENY,
                    {"escalation_id": esc_id},
                )
                assert deny_result.isError is True
                data = json.loads(deny_result.content[0].text)
                assert data["error"] == "ESCALATION_NOT_FOUND"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 9. EDGE CASES
# =============================================================================

class TestEscalationEdgeCases:
    def test_approve_missing_escalation_id(
        self, mock_server_path, signed_constitution,
    ):
        """Approve with missing escalation_id → MISSING_PARAMETER error."""
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
                    _META_TOOL_APPROVE, {},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "escalation_id must be a string"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_deny_missing_escalation_id(
        self, mock_server_path, signed_constitution,
    ):
        """Deny with missing escalation_id → MISSING_PARAMETER error."""
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
                    _META_TOOL_DENY, {},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "escalation_id must be a string"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_escalation_store_cleared_on_shutdown(
        self, mock_server_path, signed_constitution,
    ):
        """Escalation store is cleared on gateway shutdown."""
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
                assert len(gw.escalation_store) == 1
            finally:
                await gw.shutdown()
            assert len(gw.escalation_store) == 0

        asyncio.run(_test())


# =============================================================================
# 10. APPROVAL TOKEN VERIFICATION
# =============================================================================

class TestApprovalToken:
    """Tests for HMAC-bound approval tokens (human-binding)."""

    def test_valid_token_succeeds_with_token_verified(
        self, mock_server_path, signed_constitution,
    ):
        """Valid token succeeds, receipt shows approval_method: token_verified."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                approve_result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert approve_result.isError is not True

                receipt = gw.last_receipt
                gw_ext = receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["approval_method"] == "token_verified"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_missing_token_rejected(
        self, mock_server_path, signed_constitution,
    ):
        """Approval without token is rejected with MISSING_APPROVAL_TOKEN."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "MISSING_APPROVAL_TOKEN"
                assert data["escalation_id"] == esc_id
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_wrong_token_rejected(
        self, mock_server_path, signed_constitution,
    ):
        """Approval with wrong token is rejected with INVALID_APPROVAL_TOKEN."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {
                        "escalation_id": esc_id,
                        "approval_token": "wrong_token_value",
                    },
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "INVALID_APPROVAL_TOKEN"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_token_from_other_escalation_rejected(
        self, mock_server_path, signed_constitution,
    ):
        """Token from escalation A cannot approve escalation B."""
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
                # Create two escalations
                r1 = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "first"},
                )
                esc_id_1 = json.loads(r1.content[0].text)["escalation_id"]
                token_1 = _get_approval_token(gw, esc_id_1)

                r2 = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "2", "name": "second"},
                )
                esc_id_2 = json.loads(r2.content[0].text)["escalation_id"]

                # Try to use token_1 to approve escalation 2
                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {
                        "escalation_id": esc_id_2,
                        "approval_token": token_1,
                    },
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "INVALID_APPROVAL_TOKEN"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_token_expires_with_escalation(
        self, mock_server_path, signed_constitution,
    ):
        """Token is useless after escalation times out."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_timeout=1,
            )
            await gw.start()
            try:
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                await asyncio.sleep(1.2)

                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_EXPIRED"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_no_token_mode_succeeds_without_token(
        self, mock_server_path, signed_constitution,
    ):
        """--no-approval-token mode: approval succeeds without token,
        receipt shows approval_method: unverified."""
        const_path, key_path, _ = signed_constitution
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                require_approval_token=False,
            )
            await gw.start()
            try:
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                approve_result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id},
                )
                assert approve_result.isError is not True
                data = json.loads(approve_result.content[0].text)
                assert data["updated"] is True

                receipt = gw.last_receipt
                gw_ext = receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["approval_method"] == "unverified"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_stderr_contains_token_on_escalation(
        self, mock_server_path, signed_constitution, capsys,
    ):
        """Token is printed to stderr on escalation creation."""
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
            finally:
                await gw.shutdown()

        asyncio.run(_test())
        captured = capsys.readouterr()
        assert "[SANNA] Approval token for escalation" in captured.err
        assert "esc_" in captured.err

    def test_token_not_in_mcp_response(
        self, mock_server_path, signed_constitution,
    ):
        """Token is NOT present in the MCP response to the model."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                # The raw MCP response text must NOT contain the token
                response_text = esc_result.content[0].text
                assert token not in response_text
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_receipt_includes_token_hash_not_raw(
        self, mock_server_path, signed_constitution,
    ):
        """Receipt includes token_hash (SHA-256 of token), not raw token."""
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
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                receipt = gw.last_receipt
                gw_ext = receipt["extensions"]["com.sanna.gateway"]

                # token_hash is present and is a SHA-256 hex
                assert "token_hash" in gw_ext
                assert len(gw_ext["token_hash"]) == 64
                # Raw token is NOT in the receipt
                receipt_str = json.dumps(receipt)
                assert token not in receipt_str
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_end_to_end_escalation_approve_with_token(
        self, mock_server_path, signed_constitution,
    ):
        """Full flow: escalate -> token printed -> approve with token ->
        forwarded -> receipt with full chain."""
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
                # Step 1: Trigger escalation
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "99", "name": "e2e-test"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                assert esc_data["status"] == "ESCALATION_REQUIRED"
                esc_id = esc_data["escalation_id"]
                esc_receipt = gw.last_receipt
                esc_receipt_id = esc_receipt["receipt_id"]

                # Escalation receipt fingerprint is valid
                matches, _, _ = verify_fingerprint(esc_receipt)
                assert matches

                # Step 2: Get the token
                token = _get_approval_token(gw, esc_id)

                # Step 3: Approve with token
                approve_result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert approve_result.isError is not True
                data = json.loads(approve_result.content[0].text)
                assert data["updated"] is True
                assert data["item_id"] == "99"
                assert data["name"] == "e2e-test"

                # Step 4: Verify approval receipt
                approval_receipt = gw.last_receipt
                gw_ext = approval_receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["escalation_id"] == esc_id
                assert gw_ext["escalation_receipt_id"] == esc_receipt_id
                assert gw_ext["escalation_resolution"] == "approved"
                assert gw_ext["approval_method"] == "token_verified"
                assert "token_hash" in gw_ext
                assert len(gw_ext["token_hash"]) == 64

                # Approval receipt fingerprint is valid
                matches, _, _ = verify_fingerprint(approval_receipt)
                assert matches
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# ESCALATION STORE HARDENING TESTS
# =============================================================================


class TestEscalationStoreHardening:
    """Tests for escalation store hardening (v0.10.1)."""

    # -- Full UUID IDs -------------------------------------------------------

    def test_escalation_id_is_full_uuid(self):
        """Escalation IDs use full uuid4.hex (32 chars), not truncated."""
        store = EscalationStore(timeout=300)
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )
        # esc_ prefix + 32 hex chars = 36 total
        assert entry.escalation_id.startswith("esc_")
        hex_part = entry.escalation_id[4:]
        assert len(hex_part) == 32
        int(hex_part, 16)  # valid hex

    def test_no_id_collisions_across_1000(self):
        """1000 IDs are all unique (full UUID prevents collisions)."""
        store = EscalationStore(timeout=300, max_pending=2000, max_per_tool=2000)
        ids = set()
        for _ in range(1000):
            entry = store.create(
                prefixed_name="srv_tool",
                original_name="tool",
                arguments={},
                server_name="srv",
                reason="test",
            )
            ids.add(entry.escalation_id)
        assert len(ids) == 1000

    # -- TTL purge on create() -----------------------------------------------

    def test_purge_expired_cleans_old_entries(self):
        """purge_expired() removes expired entries."""
        store = EscalationStore(timeout=1)
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )
        # Backdate to make it expired
        from datetime import datetime, timezone, timedelta
        old_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        entry.created_at = old_time.isoformat()

        assert len(store) == 1
        purged = store.purge_expired()
        assert purged == 1
        assert len(store) == 0

    def test_create_purges_expired_first(self):
        """create() purges expired entries before adding new one."""
        store = EscalationStore(timeout=1, max_pending=2)
        e1 = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="first",
        )
        e2 = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="second",
        )
        assert len(store) == 2

        # Backdate both to make them expired
        from datetime import datetime, timezone, timedelta
        old_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        e1.created_at = old_time.isoformat()
        e2.created_at = old_time.isoformat()

        # Creating a new one should succeed (expired ones get purged first)
        e3 = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="third",
        )
        assert len(store) == 1
        assert store.get(e3.escalation_id) is not None

    # -- Max pending limit ---------------------------------------------------

    def test_max_pending_default_is_100(self):
        """Default max_pending is 100."""
        store = EscalationStore(timeout=300)
        assert store.max_pending == 100

    def test_max_pending_configurable(self):
        """max_pending can be set via constructor."""
        store = EscalationStore(timeout=300, max_pending=5)
        assert store.max_pending == 5

    def test_create_raises_at_capacity(self):
        """create() raises RuntimeError when store is at capacity."""
        store = EscalationStore(timeout=300, max_pending=2)
        store.create(
            prefixed_name="srv_t1",
            original_name="t1",
            arguments={},
            server_name="srv",
            reason="first",
        )
        store.create(
            prefixed_name="srv_t2",
            original_name="t2",
            arguments={},
            server_name="srv",
            reason="second",
        )
        with pytest.raises(RuntimeError, match="at capacity"):
            store.create(
                prefixed_name="srv_t3",
                original_name="t3",
                arguments={},
                server_name="srv",
                reason="third",
            )

    def test_capacity_freed_after_remove(self):
        """After removing an entry, capacity is available again."""
        store = EscalationStore(timeout=300, max_pending=1)
        e1 = store.create(
            prefixed_name="srv_t1",
            original_name="t1",
            arguments={},
            server_name="srv",
            reason="first",
        )
        store.remove(e1.escalation_id)
        # Now should succeed
        e2 = store.create(
            prefixed_name="srv_t2",
            original_name="t2",
            arguments={},
            server_name="srv",
            reason="second",
        )
        assert store.get(e2.escalation_id) is not None

    # -- Status field --------------------------------------------------------

    def test_default_status_is_pending(self):
        """New escalations have status 'pending'."""
        store = EscalationStore(timeout=300)
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )
        assert entry.status == "pending"

    def test_mark_status(self):
        """mark_status() updates the status in-place."""
        store = EscalationStore(timeout=300)
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )
        store.mark_status(entry.escalation_id, "approved")
        assert entry.status == "approved"
        # Still in store
        assert store.get(entry.escalation_id) is not None

    def test_mark_status_nonexistent_returns_none(self):
        """mark_status() returns None for unknown IDs."""
        store = EscalationStore(timeout=300)
        result = store.mark_status("esc_nonexistent", "approved")
        assert result is None

    # -- Escalation store full error in gateway ------------------------------

    def test_store_full_returns_error(self, signed_constitution, tmp_path):
        """When store is full, escalation returns ESCALATION_STORE_FULL."""
        mcp = pytest.importorskip("mcp")
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=["-c", MOCK_SERVER_SCRIPT],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"update_item": "must_escalate"},
                escalation_timeout=300,
                max_pending_escalations=1,
                require_approval_token=False,
            )
            try:
                await gw.start()
                # First escalation should succeed
                result1 = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "p1", "name": "first"},
                )
                data1 = json.loads(result1.content[0].text)
                assert data1["status"] == "ESCALATION_REQUIRED"

                # Second escalation should fail (store full)
                result2 = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "p2", "name": "second"},
                )
                data2 = json.loads(result2.content[0].text)
                assert data2["error"] == "ESCALATION_STORE_FULL"
                assert result2.isError is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- Approve-then-execute ordering (the critical fix) --------------------

    def test_approve_marks_approved_before_execution(
        self, signed_constitution, tmp_path,
    ):
        """Approved escalation is marked 'approved' before downstream call."""
        mcp = pytest.importorskip("mcp")
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=["-c", MOCK_SERVER_SCRIPT],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"update_item": "must_escalate"},
                escalation_timeout=300,
                require_approval_token=False,
            )
            try:
                await gw.start()
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "p1", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]

                # After successful approval, entry should be removed
                approve_result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id},
                )
                assert approve_result.isError is not True

                # Entry should be gone (execution succeeded)
                assert gw._escalation_store.get(esc_id) is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approve_downstream_failure_keeps_entry_as_failed(
        self, signed_constitution, tmp_path,
    ):
        """If downstream call raises, entry stays in store as 'failed'."""
        mcp = pytest.importorskip("mcp")
        from unittest.mock import AsyncMock
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=["-c", MOCK_SERVER_SCRIPT],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                policy_overrides={"update_item": "must_escalate"},
                escalation_timeout=300,
                require_approval_token=False,
            )
            try:
                await gw.start()
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "p1", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]

                # Monkey-patch downstream to fail
                ds_state = gw._downstream_states["mock"]
                original_call = ds_state.connection.call_tool
                ds_state.connection.call_tool = AsyncMock(
                    side_effect=Exception("downstream crashed"),
                )

                with pytest.raises(Exception, match="downstream crashed"):
                    await gw._forward_call(
                        _META_TOOL_APPROVE,
                        {"escalation_id": esc_id},
                    )

                # Entry should still be in store with 'failed' status
                entry = gw._escalation_store.get(esc_id)
                assert entry is not None
                assert entry.status == "failed"

                # Restore original call_tool
                ds_state.connection.call_tool = original_call
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- Config integration --------------------------------------------------

    def test_max_pending_escalations_from_config(self, tmp_path):
        """max_pending_escalations is wired from gateway config."""
        from sanna.gateway.config import load_gateway_config

        # Create minimal signed constitution and key for config loading
        from sanna.constitution import (
            Constitution, AgentIdentity, Provenance, Boundary,
            sign_constitution, save_constitution,
        )
        from sanna.crypto import generate_keypair

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        key_path, _ = generate_keypair(str(keys_dir), label="test")

        const = Constitution(
            schema_version="1.0.0",
            identity=AgentIdentity(
                agent_name="test",
                domain="test",
                description="test",
            ),
            provenance=Provenance(
                authored_by="test@test.com",
                approved_by=["test@test.com"],
                approval_date="2026-02-15",
                approval_method="test",
            ),
            boundaries=[Boundary(
                id="B001",
                description="test boundary",
                category="scope",
                severity="high",
            )],
        )
        const_path = tmp_path / "constitution.yaml"
        sign_constitution(const, str(key_path))
        save_constitution(const, str(const_path))

        config_yaml = f"""
gateway:
  constitution: {const_path}
  signing_key: {key_path}
  max_pending_escalations: 42

downstream:
  - name: test
    command: echo
    args: ["hello"]
"""
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(config_yaml)

        config = load_gateway_config(str(config_file))
        assert config.max_pending_escalations == 42


# =============================================================================
# APPROVAL IDEMPOTENCY (Fix 5)
# =============================================================================

class TestApprovalIdempotency:
    def test_approve_already_approved_returns_error(
        self, mock_server_path, signed_constitution,
    ):
        """Approving an already-approved escalation returns ALREADY_EXECUTING."""
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
                # Trigger escalation
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                # Manually set status to "approved" (simulates crash during
                # execution)
                gw.escalation_store.mark_status(esc_id, "approved")

                # Second approve should fail
                token = _get_approval_token(gw, esc_id)
                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_ALREADY_EXECUTING"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approve_failed_entry_returns_error(
        self, mock_server_path, signed_constitution,
    ):
        """Approving a failed escalation returns ESCALATION_FAILED."""
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
                # Trigger escalation
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                # Manually set status to "failed"
                gw.escalation_store.mark_status(esc_id, "failed")

                # Approve should fail
                token = _get_approval_token(gw, esc_id)
                result = await gw._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert result.isError is True
                data = json.loads(result.content[0].text)
                assert data["error"] == "ESCALATION_FAILED"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# Block 3 — EscalationStore hardening tests (#7 chmod guard, #8 per-tool limit)
# =============================================================================


class TestEscalationStoreNoChmodCwd:
    """EscalationStore with filename-only persist_path doesn't chmod cwd (#7)."""

    def test_persist_path_filename_only_resolves_to_home(self, tmp_path, monkeypatch):
        """When persist_path is just a filename, _save_to_disk should NOT
        ensure_secure_dir on '.' — it should resolve to a safe fallback."""
        from unittest.mock import patch

        # Use a filename-only persist_path (no directory component)
        store = EscalationStore(persist_path="escalations.json", max_pending=10)

        calls: list[str] = []

        def tracking_ensure(d, *a, **kw):
            calls.append(str(d))
            # Don't actually create dirs during test
            return

        def noop_write(*a, **kw):
            return

        with patch("sanna.utils.safe_io.ensure_secure_dir", side_effect=tracking_ensure), \
             patch("sanna.utils.safe_io.atomic_write_sync", side_effect=noop_write):
            store.create(
                prefixed_name="mock_update",
                original_name="update",
                arguments={"id": "1"},
                server_name="mock",
                reason="test",
            )

        # Should NOT have called ensure_secure_dir on "." or cwd
        assert len(calls) == 1
        called_dir = calls[0]
        assert called_dir != "."
        assert ".sanna" in called_dir, (
            f"Expected fallback to ~/.sanna path, got: {called_dir}"
        )

    def test_persist_path_with_directory_uses_that_directory(self, tmp_path):
        """When persist_path includes a directory, use it as-is."""
        from unittest.mock import patch

        persist = str(tmp_path / "subdir" / "store.json")
        store = EscalationStore(persist_path=persist, max_pending=10)

        calls: list[str] = []

        def tracking_ensure(d, *a, **kw):
            calls.append(str(d))

        def noop_write(*a, **kw):
            return

        with patch("sanna.utils.safe_io.ensure_secure_dir", side_effect=tracking_ensure), \
             patch("sanna.utils.safe_io.atomic_write_sync", side_effect=noop_write):
            store.create(
                prefixed_name="mock_update",
                original_name="update",
                arguments={"id": "1"},
                server_name="mock",
                reason="test",
            )

        assert len(calls) == 1
        assert str(tmp_path / "subdir") in calls[0]


class TestEscalationPerToolLimit:
    """Per-tool escalation limit prevents single-tool DoS (#8)."""

    def test_per_tool_limit_blocks_flood(self):
        """Flooding one tool hits the per-tool cap."""
        store = EscalationStore(max_pending=100, max_per_tool=3)

        for i in range(3):
            store.create(
                prefixed_name="mock_delete",
                original_name="delete",
                arguments={"id": str(i)},
                server_name="mock",
                reason="test",
            )

        with pytest.raises(RuntimeError, match="Too many pending.*mock_delete"):
            store.create(
                prefixed_name="mock_delete",
                original_name="delete",
                arguments={"id": "overflow"},
                server_name="mock",
                reason="test",
            )

    def test_per_tool_limit_other_tools_still_work(self):
        """Flooding tool A does NOT block tool B."""
        store = EscalationStore(max_pending=100, max_per_tool=2)

        # Saturate tool A
        for i in range(2):
            store.create(
                prefixed_name="mock_delete",
                original_name="delete",
                arguments={"id": str(i)},
                server_name="mock",
                reason="test",
            )

        # Tool B should still work
        entry = store.create(
            prefixed_name="mock_update",
            original_name="update",
            arguments={"id": "1"},
            server_name="mock",
            reason="test",
        )
        assert entry.prefixed_name == "mock_update"

    def test_global_cap_still_works(self):
        """Global capacity limit still applies as a safety net."""
        store = EscalationStore(max_pending=5, max_per_tool=100)

        for i in range(5):
            store.create(
                prefixed_name=f"tool_{i}",
                original_name=f"tool_{i}",
                arguments={},
                server_name="mock",
                reason="test",
            )

        with pytest.raises(RuntimeError, match="at capacity"):
            store.create(
                prefixed_name="tool_overflow",
                original_name="tool_overflow",
                arguments={},
                server_name="mock",
                reason="test",
            )

    def test_per_tool_limit_approving_frees_slot(self):
        """Approving an escalation (changing status from 'pending') frees
        the per-tool slot for new requests."""
        store = EscalationStore(max_pending=100, max_per_tool=2)

        entries = []
        for i in range(2):
            e = store.create(
                prefixed_name="mock_delete",
                original_name="delete",
                arguments={"id": str(i)},
                server_name="mock",
                reason="test",
            )
            entries.append(e)

        # At limit — should fail
        with pytest.raises(RuntimeError, match="Too many pending"):
            store.create(
                prefixed_name="mock_delete",
                original_name="delete",
                arguments={"id": "blocked"},
                server_name="mock",
                reason="test",
            )

        # Mark first as approved — frees a slot
        store.mark_status(entries[0].escalation_id, "approved")

        # Now it should work
        new_entry = store.create(
            prefixed_name="mock_delete",
            original_name="delete",
            arguments={"id": "unblocked"},
            server_name="mock",
            reason="test",
        )
        assert new_entry.prefixed_name == "mock_delete"


# =============================================================================
# SEC-5 & SEC-10: ESCALATION PERSISTENCE SECURITY TESTS
# =============================================================================


class TestEscalationPersistenceForgedTokenHash:
    """SEC-5: Forged persistence file with attacker-controlled token_hash
    must NOT allow approval when HMAC re-derivation is enforced."""

    def test_forged_token_hash_does_not_allow_approval(
        self, mock_server_path, signed_constitution, tmp_path,
    ):
        """Attacker writes crafted persistence JSON with
        token_hash = sha256("attacker-token"). Gateway restarts and
        loads it. Approving with "attacker-token" must fail because
        the HMAC re-derivation produces a different expected token."""
        import hashlib as _hashlib
        import hmac as _hmac

        const_path, key_path, _ = signed_constitution
        persist_file = tmp_path / "escalations.json"

        async def _test():
            # Step 1: Create a real gateway and trigger an escalation
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_persist_path=str(persist_file),
            )
            await gw.start()
            try:
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "forged"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                # Capture the gateway secret and persist file content
                # BEFORE shutdown (shutdown clears the store)
                secret = gw._gateway_secret
                persist_content = persist_file.read_text()
            finally:
                await gw.shutdown()

            # Step 2: Tamper with the captured persistence data — replace
            # token_hash with sha256("attacker-token") and re-sign with
            # correct record HMAC so it passes integrity check
            data = json.loads(persist_content)

            attacker_token = "attacker-token"
            attacker_hash = _hashlib.sha256(
                attacker_token.encode()
            ).hexdigest()

            record = data[esc_id]
            record.pop("_record_hmac", None)
            record["token_hash"] = attacker_hash

            # Re-compute record HMAC so the record passes integrity check
            clean = {k: v for k, v in record.items() if k != "_record_hmac"}
            payload = json.dumps(clean, sort_keys=True).encode()
            record["_record_hmac"] = _hmac.new(
                secret, payload, _hashlib.sha256,
            ).hexdigest()
            data[esc_id] = record

            # Write tampered file with correct permissions
            persist_file.write_text(json.dumps(data))
            import os
            os.chmod(str(persist_file), 0o600)

            # Step 3: Create a new gateway that loads the tampered file
            gw2 = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_persist_path=str(persist_file),
            )
            await gw2.start()
            try:
                # The entry should have loaded (record HMAC is valid)
                entry = gw2.escalation_store.get(esc_id)
                assert entry is not None, (
                    "Record should load since record HMAC is valid"
                )

                # Step 4: Try to approve with "attacker-token"
                # This MUST fail because _compute_approval_token re-derives
                # from the HMAC secret, not from stored token_hash
                result = await gw2._forward_call(
                    _META_TOOL_APPROVE,
                    {
                        "escalation_id": esc_id,
                        "approval_token": attacker_token,
                    },
                )
                assert result.isError is True
                err_data = json.loads(result.content[0].text)
                assert err_data["error"] == "INVALID_APPROVAL_TOKEN"
            finally:
                await gw2.shutdown()

        asyncio.run(_test())


class TestEscalationPersistenceValidRoundTrip:
    """SEC-5: Valid persistence file with correct HMAC still loads
    and allows approval normally."""

    def test_valid_persistence_round_trip(
        self, mock_server_path, signed_constitution, tmp_path,
    ):
        """Create escalation -> persist -> restart -> approve with
        the correct token. Should succeed."""
        const_path, key_path, _ = signed_constitution
        persist_file = tmp_path / "escalations.json"

        async def _test():
            # Create gateway and trigger escalation
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_persist_path=str(persist_file),
            )
            await gw.start()
            try:
                esc_result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "42", "name": "roundtrip"},
                )
                esc_data = json.loads(esc_result.content[0].text)
                esc_id = esc_data["escalation_id"]

                # Get the valid token and save persist content BEFORE
                # shutdown (shutdown clears the store + persist file)
                entry = gw.escalation_store.get(esc_id)
                token = gw._compute_approval_token(entry)
                persist_content = persist_file.read_text()
            finally:
                await gw.shutdown()

            # Restore the persisted file (shutdown clears it)
            persist_file.write_text(persist_content)
            import os
            os.chmod(str(persist_file), 0o600)

            # Restart gateway — loads from persisted file
            gw2 = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                escalation_persist_path=str(persist_file),
            )
            await gw2.start()
            try:
                # Entry should be loaded
                entry2 = gw2.escalation_store.get(esc_id)
                assert entry2 is not None

                # Approve with valid token
                result = await gw2._forward_call(
                    _META_TOOL_APPROVE,
                    {"escalation_id": esc_id, "approval_token": token},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["updated"] is True
                assert data["item_id"] == "42"
            finally:
                await gw2.shutdown()

        asyncio.run(_test())


class TestEscalationPersistenceTamperedHMAC:
    """SEC-5: Persistence file with tampered record HMAC is rejected on load."""

    def test_tampered_record_hmac_rejected(self, tmp_path):
        """Record with invalid _record_hmac is skipped during load."""
        persist_file = tmp_path / "escalations.json"
        secret = b"x" * 32

        # Create a valid store and entry
        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={"key": "value"},
            server_name="srv",
            reason="test",
        )
        esc_id = entry.escalation_id
        assert persist_file.exists()

        # Tamper with the HMAC
        data = json.loads(persist_file.read_text())
        data[esc_id]["_record_hmac"] = "deadbeef" * 8
        persist_file.write_text(json.dumps(data))
        import os
        os.chmod(str(persist_file), 0o600)

        # Reload — tampered record should be rejected
        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        assert store2.get(esc_id) is None
        assert len(store2) == 0


class TestEscalationPersistenceSymlinkRejected:
    """SEC-10: Symlinked persistence file is rejected."""

    def test_symlink_persistence_rejected(self, tmp_path):
        """Load from a symlinked file is refused."""
        real_file = tmp_path / "real_escalations.json"
        real_file.write_text("{}")
        import os
        os.chmod(str(real_file), 0o600)

        link_path = tmp_path / "symlinked_escalations.json"
        os.symlink(str(real_file), str(link_path))

        # Should refuse to load (symlink detected)
        store = EscalationStore(
            timeout=300,
            persist_path=str(link_path),
            secret=b"x" * 32,
        )
        assert len(store) == 0


class TestEscalationPersistenceOversized:
    """SEC-10: Oversized persistence file is rejected."""

    def test_oversized_persistence_rejected(self, tmp_path):
        """File exceeding 10MB limit is refused."""
        persist_file = tmp_path / "escalations.json"
        # Write > 10MB of data
        persist_file.write_text("x" * (11 * 1024 * 1024))
        import os
        os.chmod(str(persist_file), 0o600)

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=b"x" * 32,
        )
        assert len(store) == 0


class TestEscalationPersistenceMalformedRecords:
    """SEC-10: Malformed records are individually skipped."""

    def test_malformed_records_skipped_individually(self, tmp_path):
        """Good and bad records in the same file: good ones load, bad
        ones are skipped."""
        persist_file = tmp_path / "escalations.json"
        secret = b"y" * 32

        # Create two valid entries
        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        e1 = store.create(
            prefixed_name="srv_search",
            original_name="search",
            arguments={"q": "test"},
            server_name="srv",
            reason="test reason",
        )
        e2 = store.create(
            prefixed_name="srv_update",
            original_name="update",
            arguments={"id": "1"},
            server_name="srv",
            reason="another reason",
        )
        good_id = e1.escalation_id
        bad_id = e2.escalation_id

        # Tamper: make the second record have an invalid status
        data = json.loads(persist_file.read_text())

        # Remove HMAC, change status to invalid, recompute HMAC
        record = data[bad_id]
        record.pop("_record_hmac", None)
        record["status"] = "invalid_status_value"
        import hmac as _hmac
        import hashlib as _hashlib
        clean = {k: v for k, v in record.items() if k != "_record_hmac"}
        payload = json.dumps(clean, sort_keys=True).encode()
        record["_record_hmac"] = _hmac.new(
            secret, payload, _hashlib.sha256,
        ).hexdigest()
        data[bad_id] = record

        persist_file.write_text(json.dumps(data))
        import os
        os.chmod(str(persist_file), 0o600)

        # Reload — good record should load, bad one should be skipped
        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        assert len(store2) == 1
        assert store2.get(good_id) is not None
        assert store2.get(bad_id) is None

    def test_non_string_tool_name_rejected(self, tmp_path):
        """Record where original_name is not a string is rejected."""
        persist_file = tmp_path / "escalations.json"
        secret = b"z" * 32

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )
        esc_id = entry.escalation_id

        # Tamper: change original_name to an integer, recompute HMAC
        data = json.loads(persist_file.read_text())
        record = data[esc_id]
        record.pop("_record_hmac", None)
        record["original_name"] = 12345
        import hmac as _hmac
        import hashlib as _hashlib
        clean = {k: v for k, v in record.items() if k != "_record_hmac"}
        payload = json.dumps(clean, sort_keys=True).encode()
        record["_record_hmac"] = _hmac.new(
            secret, payload, _hashlib.sha256,
        ).hexdigest()
        data[esc_id] = record

        persist_file.write_text(json.dumps(data))
        import os
        os.chmod(str(persist_file), 0o600)

        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        assert len(store2) == 0

    def test_non_dict_arguments_rejected(self, tmp_path):
        """Record where arguments is not a dict is rejected."""
        persist_file = tmp_path / "escalations.json"
        secret = b"a" * 32

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={"k": "v"},
            server_name="srv",
            reason="test",
        )
        esc_id = entry.escalation_id

        # Tamper: change arguments to a list
        data = json.loads(persist_file.read_text())
        record = data[esc_id]
        record.pop("_record_hmac", None)
        record["arguments"] = ["not", "a", "dict"]
        import hmac as _hmac
        import hashlib as _hashlib
        clean = {k: v for k, v in record.items() if k != "_record_hmac"}
        payload = json.dumps(clean, sort_keys=True).encode()
        record["_record_hmac"] = _hmac.new(
            secret, payload, _hashlib.sha256,
        ).hexdigest()
        data[esc_id] = record

        persist_file.write_text(json.dumps(data))
        import os
        os.chmod(str(persist_file), 0o600)

        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        assert len(store2) == 0


class TestEscalationPersistenceIssuedAtRoundTrip:
    """SEC-5: issued_at round-trips as integer, not float."""

    def test_issued_at_is_integer_in_persistence(self, tmp_path):
        """issued_at is stored as an integer in JSON and loaded back
        as an integer."""
        persist_file = tmp_path / "escalations.json"
        secret = b"b" * 32

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={"key": "value"},
            server_name="srv",
            reason="test",
        )
        esc_id = entry.escalation_id

        # Verify issued_at is an int on the entry
        assert isinstance(entry.issued_at, int)
        assert entry.issued_at > 0

        # Verify it's an int in the JSON
        data = json.loads(persist_file.read_text())
        assert isinstance(data[esc_id]["issued_at"], int)

        # Reload and verify
        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        entry2 = store2.get(esc_id)
        assert entry2 is not None
        assert isinstance(entry2.issued_at, int)
        assert entry2.issued_at == entry.issued_at

    def test_args_digest_round_trips(self, tmp_path):
        """args_digest is stored as a hex string and reloaded correctly."""
        import hashlib as _hashlib
        persist_file = tmp_path / "escalations.json"
        secret = b"c" * 32

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        args = {"item_id": "42", "name": "test"}
        entry = store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments=args,
            server_name="srv",
            reason="test",
        )
        esc_id = entry.escalation_id

        expected_digest = _hashlib.sha256(
            json.dumps(args, sort_keys=True).encode(),
        ).hexdigest()
        assert entry.args_digest == expected_digest

        # Reload
        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        entry2 = store2.get(esc_id)
        assert entry2 is not None
        assert entry2.args_digest == expected_digest


class TestEscalationPersistencePermissions:
    """SEC-10: File with overly permissive permissions is rejected."""

    def test_world_readable_persistence_rejected(self, tmp_path):
        """File with 0o644 permissions is rejected (too open)."""
        persist_file = tmp_path / "escalations.json"
        persist_file.write_text("{}")
        import os
        os.chmod(str(persist_file), 0o644)

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=b"x" * 32,
        )
        assert len(store) == 0

    def test_group_writable_persistence_rejected(self, tmp_path):
        """File with 0o660 permissions is rejected (group write)."""
        persist_file = tmp_path / "escalations.json"
        persist_file.write_text("{}")
        import os
        os.chmod(str(persist_file), 0o660)

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=b"x" * 32,
        )
        assert len(store) == 0

    def test_owner_only_persistence_accepted(self, tmp_path):
        """File with 0o600 permissions is accepted."""
        persist_file = tmp_path / "escalations.json"
        secret = b"d" * 32

        # Create a valid store to produce a correctly-formatted file
        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )

        # Reload with 0o600 — should work
        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        assert len(store2) == 1

    def test_owner_plus_group_read_accepted(self, tmp_path):
        """File with 0o640 permissions is accepted (within limit)."""
        persist_file = tmp_path / "escalations.json"
        secret = b"e" * 32

        store = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        store.create(
            prefixed_name="srv_tool",
            original_name="tool",
            arguments={},
            server_name="srv",
            reason="test",
        )

        # Change permissions to 0o640
        import os
        os.chmod(str(persist_file), 0o640)

        store2 = EscalationStore(
            timeout=300,
            persist_path=str(persist_file),
            secret=secret,
        )
        assert len(store2) == 1
