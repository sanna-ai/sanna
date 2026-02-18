"""Block E tests — approval override_reason + token delivery mechanisms."""

import asyncio
import json
import os
import sys
import textwrap

import pytest

mcp = pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import (
    SannaGateway,
    EscalationStore,
    PendingEscalation,
    _META_TOOL_APPROVE,
)


# =============================================================================
# MOCK SERVER + HELPERS
# =============================================================================

MOCK_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream")

    @mcp.tool()
    def search(query: str) -> str:
        \"\"\"Search items.\"\"\"
        return json.dumps({"query": query, "results": ["a"]})

    @mcp.tool()
    def update_item(item_id: str, name: str) -> str:
        \"\"\"Update an item.\"\"\"
        return json.dumps({"updated": True, "item_id": item_id, "name": name})

    mcp.run(transport="stdio")
""")


def _create_signed_constitution(tmp_path, authority_boundaries=None):
    """Create a signed constitution for testing."""
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution, AgentIdentity, Provenance, Boundary,
        sign_constitution, save_constitution,
    )

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    constitution = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@example.com",
            approved_by=["approver@example.com"],
            approval_date="2024-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope", severity="high"),
        ],
        authority_boundaries=authority_boundaries,
    )

    signed = sign_constitution(constitution, private_key_path=str(private_key_path))
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)
    return str(const_path), str(private_key_path), str(public_key_path)


def _get_approval_token(gw, escalation_id: str) -> str:
    """Compute valid approval token for a pending escalation."""
    entry = gw.escalation_store.get(escalation_id)
    assert entry is not None
    return gw._compute_approval_token(entry)


@pytest.fixture()
def mock_server_path(tmp_path):
    mock = tmp_path / "mock_server.py"
    mock.write_text(MOCK_SERVER_SCRIPT)
    return str(mock)


@pytest.fixture()
def escalation_constitution(tmp_path):
    """Constitution with must_escalate for update_item."""
    from sanna.constitution import AuthorityBoundaries, EscalationRule
    ab = AuthorityBoundaries(
        can_execute=["search"],
        must_escalate=[EscalationRule(condition="update")],
    )
    return _create_signed_constitution(tmp_path, authority_boundaries=ab)


# =============================================================================
# APPROVAL WITH OVERRIDE REASON
# =============================================================================

class TestApprovalOverrideReason:
    def test_approval_with_reason(
        self, mock_server_path, escalation_constitution, tmp_path,
    ):
        """Approve with override_reason → recorded in receipt."""
        const_path, key_path, _ = escalation_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                # Trigger escalation
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "123", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                # Approve with reason
                await gw._handle_approve({
                    "escalation_id": esc_id,
                    "approval_token": token,
                    "override_reason": "Customer requested urgent update",
                    "override_detail": "Ticket #4567",
                })

                receipt = gw._last_receipt
                assert receipt is not None
                gw_ext = receipt.get("extensions", {}).get("com.sanna.gateway", {})
                assert gw_ext.get("override_reason") == "Customer requested urgent update"
                assert gw_ext.get("override_detail") == "Ticket #4567"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approval_without_reason_allowed(
        self, mock_server_path, escalation_constitution, tmp_path,
    ):
        """Default config: approve without override_reason succeeds."""
        const_path, key_path, _ = escalation_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                approval_requires_reason=False,
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "123", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                approve_result = await gw._handle_approve({
                    "escalation_id": esc_id,
                    "approval_token": token,
                    # No override_reason
                })

                # Should succeed (not an error)
                assert not approve_result.isError
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_approval_without_reason_rejected(
        self, mock_server_path, escalation_constitution, tmp_path,
    ):
        """approval_requires_reason=True + no reason → rejected."""
        const_path, key_path, _ = escalation_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                approval_requires_reason=True,
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "123", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]
                token = _get_approval_token(gw, esc_id)

                approve_result = await gw._handle_approve({
                    "escalation_id": esc_id,
                    "approval_token": token,
                    # No override_reason — should be rejected
                })

                assert approve_result.isError
                error_data = json.loads(approve_result.content[0].text)
                assert error_data["error"] == "MISSING_OVERRIDE_REASON"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# TOKEN DELIVERY
# =============================================================================

class TestTokenDelivery:
    def test_token_delivery_file(
        self, mock_server_path, escalation_constitution, tmp_path,
        monkeypatch,
    ):
        """Token written to pending_tokens.json."""
        const_path, key_path, _ = escalation_constitution

        # Redirect home dir to tmp_path so we write to
        # tmp_path/.sanna/pending_tokens.json
        sanna_dir = str(tmp_path / "home" / ".sanna")
        tokens_path = os.path.join(sanna_dir, "pending_tokens.json")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                token_delivery=["file"],
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "123", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]

                # Token file should exist
                assert os.path.exists(tokens_path)
                with open(tokens_path) as f:
                    tokens = json.load(f)
                assert len(tokens) == 1
                assert tokens[0]["escalation_id"] == esc_id
                assert "token" in tokens[0]
                assert tokens[0]["tool_name"] == "mock_update_item"
                assert "ttl_remaining" in tokens[0]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_token_delivery_stderr(
        self, mock_server_path, escalation_constitution, tmp_path,
        capsys,
    ):
        """Token printed to stderr (existing behavior preserved)."""
        const_path, key_path, _ = escalation_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                token_delivery=["stderr"],
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "123", "name": "test"},
                )
                data = json.loads(result.content[0].text)
                esc_id = data["escalation_id"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())

        captured = capsys.readouterr()
        assert "[SANNA] Approval token for escalation" in captured.err

    def test_token_delivery_both(
        self, mock_server_path, escalation_constitution, tmp_path,
        capsys, monkeypatch,
    ):
        """Both file and stderr delivery work together."""
        const_path, key_path, _ = escalation_constitution

        sanna_dir = str(tmp_path / "home" / ".sanna")
        tokens_path = os.path.join(sanna_dir, "pending_tokens.json")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
                token_delivery=["file", "stderr"],
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "123", "name": "test"},
                )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

        # Both delivery methods should have fired
        assert os.path.exists(tokens_path)
        captured = capsys.readouterr()
        assert "[SANNA] Approval token for escalation" in captured.err
