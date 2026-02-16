"""Block F tests — downstream error receipt labeling."""

import asyncio
import json
import sys
import textwrap

import pytest

mcp = pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import (
    SannaGateway,
    CircuitState,
    _META_TOOL_APPROVE,
)


# =============================================================================
# MOCK SERVER
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
    def update_item(item_id: str) -> str:
        \"\"\"Update an item.\"\"\"
        return json.dumps({"updated": True, "item_id": item_id})

    mcp.run(transport="stdio")
""")


def _create_signed_constitution(tmp_path, authority_boundaries=None):
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


@pytest.fixture()
def mock_server_path(tmp_path):
    mock = tmp_path / "mock_server.py"
    mock.write_text(MOCK_SERVER_SCRIPT)
    return str(mock)


@pytest.fixture()
def constitution_with_boundaries(tmp_path):
    from sanna.constitution import AuthorityBoundaries, EscalationRule
    ab = AuthorityBoundaries(
        can_execute=["search"],
        cannot_execute=["drop database"],
    )
    return _create_signed_constitution(tmp_path, authority_boundaries=ab)


# =============================================================================
# TESTS
# =============================================================================

class TestDownstreamErrorLabels:
    def test_downstream_unreachable_labeled_unhealthy(
        self, mock_server_path, constitution_with_boundaries, tmp_path,
    ):
        """Circuit breaker OPEN → boundary_type = 'downstream_unhealthy'."""
        const_path, key_path, _ = constitution_with_boundaries

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                # Force circuit breaker OPEN
                ds_state = gw._first_ds
                ds_state.circuit_state = CircuitState.OPEN

                result = await gw._forward_call(
                    "mock_search", {"query": "test"},
                )

                assert result.isError
                receipt = gw._last_receipt
                assert receipt is not None
                gw_ext = receipt.get("extensions", {}).get("gateway", {})
                assert gw_ext.get("boundary_type") == "downstream_unhealthy"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_policy_block_still_cannot_execute(
        self, mock_server_path, constitution_with_boundaries, tmp_path,
    ):
        """Policy decision (cannot_execute) → boundary_type remains 'cannot_execute'."""
        const_path, key_path, _ = constitution_with_boundaries

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
                policy_overrides={"search": "cannot_execute"},
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search", {"query": "test"},
                )

                receipt = gw._last_receipt
                assert receipt is not None
                gw_ext = receipt.get("extensions", {}).get("gateway", {})
                assert gw_ext.get("boundary_type") == "cannot_execute"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_error_receipt_default_is_execution_failed(
        self, mock_server_path, constitution_with_boundaries, tmp_path,
    ):
        """Default _generate_error_receipt boundary_type is 'execution_failed'."""
        const_path, key_path, _ = constitution_with_boundaries

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
                gateway_secret_path=str(tmp_path / "secret"),
            )
            await gw.start()
            try:
                # Call _generate_error_receipt directly with default params
                receipt = gw._generate_error_receipt(
                    prefixed_name="mock_search",
                    original_name="search",
                    arguments={"query": "test"},
                    error_text="Internal Server Error",
                    server_name="mock",
                )
                gw_ext = receipt.get("extensions", {}).get("gateway", {})
                assert gw_ext.get("boundary_type") == "execution_failed"
            finally:
                await gw.shutdown()

        asyncio.run(_test())
