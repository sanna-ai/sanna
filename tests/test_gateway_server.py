"""Tests for the gateway MCP server (SannaGateway — Block B).

Tests cover: tool discovery with prefixed names, schema fidelity,
end-to-end call forwarding, error handling, and lifecycle management.
"""

import asyncio
import json
import sys
import textwrap

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.mcp_client import DownstreamConnectionError
from sanna.gateway.server import (
    SannaGateway,
    DownstreamSpec,
    CircuitState,
    _dict_to_tool,
    _META_TOOL_NAMES,
)

# =============================================================================
# MOCK SERVER SCRIPT (same tools as Block A tests)
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
    def error_tool() -> str:
        \"\"\"A tool that always errors.\"\"\"
        raise ValueError("Intentional error for testing")

    mcp.run(transport="stdio")
""")


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def mock_server_path(tmp_path):
    """Write the mock server script to a temp file."""
    path = tmp_path / "mock_server.py"
    path.write_text(MOCK_SERVER_SCRIPT)
    return str(path)


# =============================================================================
# 1. TOOL DISCOVERY WITH PREFIXED NAMES
# =============================================================================

class TestToolDiscovery:
    def test_discovers_downstream_tools_with_prefix(self, mock_server_path):
        """Gateway discovers tools and prefixes them with server name."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                names = {t.name for t in tools}
                assert "mock_get_status" in names
                assert "mock_search" in names
                assert "mock_create_item" in names
                assert "mock_error_tool" in names
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_correct_tool_count(self, mock_server_path):
        """Number of gateway tools matches downstream + meta-tools."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                downstream = [t for t in tools if t.name not in _META_TOOL_NAMES]
                meta = [t for t in tools if t.name in _META_TOOL_NAMES]
                assert len(downstream) == 4
                assert len(meta) == 2
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_tool_names_follow_prefix_pattern(self, mock_server_path):
        """Every downstream tool name follows {server_name}/{tool_name}
        pattern. Meta-tools are not prefixed."""
        async def _test():
            gw = SannaGateway(
                server_name="my-server",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                for t in tools:
                    if t.name in _META_TOOL_NAMES:
                        continue  # meta-tools are not prefixed
                    assert t.name.startswith("my-server_"), t.name
                    original = t.name[len("my-server_"):]
                    assert "_" not in original or original in gw.tool_map.values()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_tool_map_matches_tool_list(self, mock_server_path):
        """tool_map keys correspond to the prefixed downstream tool names.
        Meta-tools are not in tool_map."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                downstream_names = {
                    t.name for t in tools if t.name not in _META_TOOL_NAMES
                }
                assert set(gw.tool_map.keys()) == downstream_names
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 2. SCHEMA FIDELITY
# =============================================================================

class TestSchemaFidelity:
    def test_input_schema_identical(self, mock_server_path):
        """inputSchema is identical between downstream and gateway tools."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                downstream_by_name = {
                    t["name"]: t for t in gw.downstream.tools
                }
                for gw_tool in gw._build_tool_list():
                    if gw_tool.name in _META_TOOL_NAMES:
                        continue
                    original_name = gw.tool_map[gw_tool.name]
                    ds_tool = downstream_by_name[original_name]
                    assert gw_tool.inputSchema == ds_tool["inputSchema"], (
                        f"Schema mismatch for {original_name}"
                    )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_description_preserved(self, mock_server_path):
        """Tool descriptions are preserved through the gateway."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                downstream_by_name = {
                    t["name"]: t for t in gw.downstream.tools
                }
                for gw_tool in gw._build_tool_list():
                    if gw_tool.name in _META_TOOL_NAMES:
                        continue
                    original_name = gw.tool_map[gw_tool.name]
                    ds_tool = downstream_by_name[original_name]
                    assert gw_tool.description == ds_tool.get("description"), (
                        f"Description mismatch for {original_name}"
                    )
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_only_name_changes(self, mock_server_path):
        """The only difference between downstream and gateway tool is the
        prefixed name — all other fields are identical."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                downstream_by_name = {
                    t["name"]: t for t in gw.downstream.tools
                }
                for gw_tool in gw._build_tool_list():
                    if gw_tool.name in _META_TOOL_NAMES:
                        continue
                    original_name = gw.tool_map[gw_tool.name]
                    ds_tool = downstream_by_name[original_name]

                    # Dump the gateway tool to dict for comparison
                    gw_dict = gw_tool.model_dump(exclude_none=True)
                    # Replace name with original for comparison
                    gw_dict["name"] = original_name
                    # annotations are ToolAnnotations objects in gw_dict
                    # but plain dicts in ds_tool — normalize
                    assert gw_dict["name"] == ds_tool["name"]
                    assert gw_dict["inputSchema"] == ds_tool["inputSchema"]
                    assert gw_dict.get("description") == ds_tool.get("description")
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 3. CALL FORWARDING (END-TO-END)
# =============================================================================

class TestCallForwarding:
    def test_forward_no_params_tool(self, mock_server_path):
        """Forwarding a no-params tool returns the correct result."""
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
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_forward_with_params(self, mock_server_path):
        """Forwarding a tool call with params works correctly."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search", {"query": "hello", "limit": 5},
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["query"] == "hello"
                assert data["limit"] == 5
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_forward_complex_params(self, mock_server_path):
        """Forwarding nested params (list, dict) works correctly."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_create_item", {
                    "name": "widget",
                    "tags": ["red", "large"],
                    "metadata": {"weight": 42},
                })
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["created"] is True
                assert data["tags"] == ["red", "large"]
                assert data["metadata"] == {"weight": 42}
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_multiple_tools_all_work(self, mock_server_path):
        """All tools from the same downstream can be called."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                r1 = await gw._forward_call("mock_get_status", {})
                assert r1.isError is not True

                r2 = await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                assert r2.isError is not True

                r3 = await gw._forward_call("mock_create_item", {
                    "name": "x", "tags": [], "metadata": {},
                })
                assert r3.isError is not True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_error_tool_preserves_is_error(self, mock_server_path):
        """Error from downstream preserves isError=True."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_error_tool", {})
                assert result.isError is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 4. ERROR HANDLING
# =============================================================================

class TestErrorHandling:
    def test_nonexistent_downstream_command(self):
        """Startup with bad command raises DownstreamConnectionError."""
        async def _test():
            gw = SannaGateway(
                server_name="bad",
                command="/nonexistent/binary/that/does/not/exist",
            )
            with pytest.raises(DownstreamConnectionError):
                await gw.start()

        asyncio.run(_test())

    def test_unknown_tool_name_returns_error(self, mock_server_path):
        """Calling a tool that doesn't exist returns isError."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call("mock_nonexistent", {})
                assert result.isError is True
                assert "unknown tool" in result.content[0].text.lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_call_without_prefix_returns_error(self, mock_server_path):
        """Calling by original name (no prefix) returns error."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                # "search" exists on downstream but gateway exposes "mock_search"
                result = await gw._forward_call("search", {})
                assert result.isError is True
                assert "unknown tool" in result.content[0].text.lower()
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_call_with_wrong_prefix_returns_error(self, mock_server_path):
        """Calling with wrong server prefix returns error."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                result = await gw._forward_call("other/search", {})
                assert result.isError is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 5. LIFECYCLE
# =============================================================================

class TestLifecycle:
    def test_shutdown_disconnects_downstream(self, mock_server_path):
        """Shutdown terminates the downstream connection."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            assert gw.downstream is not None
            assert gw.downstream.connected is True
            await gw.shutdown()
            assert gw.downstream is None

        asyncio.run(_test())

    def test_double_shutdown_is_safe(self, mock_server_path):
        """Calling shutdown twice doesn't raise."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            await gw.shutdown()
            await gw.shutdown()  # Should not raise

        asyncio.run(_test())

    def test_tool_map_cleared_on_shutdown(self, mock_server_path):
        """Tool map is empty after shutdown."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            assert len(gw.tool_map) > 0
            await gw.shutdown()
            assert gw.tool_map == {}

        asyncio.run(_test())

    def test_tool_list_only_meta_tools_before_start(self):
        """Tool list contains only meta-tools before start."""
        gw = SannaGateway(
            server_name="mock",
            command="unused",
        )
        tools = gw._build_tool_list()
        tool_names = {t.name for t in tools}
        # Only meta-tools, no downstream tools
        assert tool_names == {
            "sanna_approve_escalation",
            "sanna_deny_escalation",
        }
        assert gw.tool_map == {}


# =============================================================================
# 6. EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_server_name_property(self):
        """server_name property returns the configured name."""
        gw = SannaGateway(server_name="notion", command="unused")
        assert gw.server_name == "notion"

    def test_tool_map_is_copy(self, mock_server_path):
        """tool_map returns a copy, not the internal dict."""
        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
            )
            await gw.start()
            try:
                m = gw.tool_map
                m["injected"] = "bad"
                assert "injected" not in gw.tool_map
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_dict_to_tool_preserves_fields(self):
        """_dict_to_tool helper preserves all schema fields."""
        import mcp.types as types

        tool_dict = {
            "name": "original",
            "description": "A test tool",
            "inputSchema": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"],
            },
        }
        tool = _dict_to_tool("pfx/original", tool_dict)
        assert tool.name == "pfx/original"
        assert tool.description == "A test tool"
        assert tool.inputSchema == tool_dict["inputSchema"]
        assert isinstance(tool, types.Tool)


# =============================================================================
# SECOND MOCK SERVER (different tools for multi-downstream tests)
# =============================================================================

MOCK_SERVER_B_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream_b")

    @mcp.tool()
    def list_files(path: str = "/") -> str:
        \"\"\"List files in a directory.\"\"\"
        return json.dumps({"path": path, "files": ["a.txt", "b.txt"]})

    @mcp.tool()
    def read_file(path: str) -> str:
        \"\"\"Read a file by path.\"\"\"
        return json.dumps({"path": path, "content": "hello"})

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        \"\"\"Write content to a file.\"\"\"
        return json.dumps({"written": True, "path": path})

    mcp.run(transport="stdio")
""")


# =============================================================================
# 7. MULTI-DOWNSTREAM TESTS
# =============================================================================

class TestMultiDownstream:
    """Tests for multi-downstream support: tool routing, namespacing,
    per-downstream circuit breakers, and backward compatibility."""

    @pytest.fixture()
    def server_a_path(self, tmp_path):
        path = tmp_path / "server_a.py"
        path.write_text(MOCK_SERVER_SCRIPT)
        return str(path)

    @pytest.fixture()
    def server_b_path(self, tmp_path):
        path = tmp_path / "server_b.py"
        path.write_text(MOCK_SERVER_B_SCRIPT)
        return str(path)

    # -- 1. Discovery from both downstreams --

    def test_discovers_tools_from_both_downstreams(
        self, server_a_path, server_b_path,
    ):
        """Gateway with 2 mock downstreams discovers tools from both."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                names = {t.name for t in tools if t.name not in _META_TOOL_NAMES}
                # alpha has 4 tools, beta has 3 tools
                assert len(names) == 7
                # Check alpha tools
                assert "alpha_get_status" in names
                assert "alpha_search" in names
                assert "alpha_create_item" in names
                assert "alpha_error_tool" in names
                # Check beta tools
                assert "beta_list_files" in names
                assert "beta_read_file" in names
                assert "beta_write_file" in names
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 2. Tool namespacing correct --

    def test_tool_namespacing_correct(
        self, server_a_path, server_b_path,
    ):
        """Tool names follow {server}_{tool} pattern for both downstreams."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                for prefixed, original in gw.tool_map.items():
                    assert (
                        prefixed.startswith("alpha_")
                        or prefixed.startswith("beta_")
                    ), f"Unexpected prefix: {prefixed}"
                    if prefixed.startswith("alpha_"):
                        assert prefixed == f"alpha_{original}"
                    else:
                        assert prefixed == f"beta_{original}"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 3. Forwarding routes to correct downstream --

    def test_forwarding_routes_to_correct_downstream(
        self, server_a_path, server_b_path,
    ):
        """Calls are routed to the correct downstream based on prefix."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                # Call alpha tool
                r1 = await gw._forward_call("alpha_get_status", {})
                assert not r1.isError
                data1 = json.loads(r1.content[0].text)
                assert data1["status"] == "ok"

                # Call beta tool
                r2 = await gw._forward_call(
                    "beta_list_files", {"path": "/home"},
                )
                assert not r2.isError
                data2 = json.loads(r2.content[0].text)
                assert data2["path"] == "/home"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 4. Per-server default_policy --

    def test_per_server_default_policy(
        self, server_a_path, server_b_path,
    ):
        """Per-server default_policy applies correctly to each downstream."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                        default_policy="can_execute",
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                        default_policy="must_escalate",
                    ),
                ],
            )
            await gw.start()
            try:
                ds_alpha = gw.downstream_states["alpha"]
                ds_beta = gw.downstream_states["beta"]
                # alpha: can_execute → None (fall through)
                assert gw._resolve_policy("get_status", ds_alpha) is None
                # beta: must_escalate
                assert gw._resolve_policy("list_files", ds_beta) == "must_escalate"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 5. Per-tool overrides across servers --

    def test_per_tool_overrides_across_servers(
        self, server_a_path, server_b_path,
    ):
        """Per-tool overrides work independently for each downstream."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                        policy_overrides={"create_item": "must_escalate"},
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                        policy_overrides={"write_file": "cannot_execute"},
                    ),
                ],
            )
            await gw.start()
            try:
                ds_alpha = gw.downstream_states["alpha"]
                ds_beta = gw.downstream_states["beta"]
                # alpha: create_item is must_escalate, search falls through
                assert gw._resolve_policy("create_item", ds_alpha) == "must_escalate"
                assert gw._resolve_policy("search", ds_alpha) is None
                # beta: write_file is cannot_execute, read_file falls through
                assert gw._resolve_policy("write_file", ds_beta) == "cannot_execute"
                assert gw._resolve_policy("read_file", ds_beta) is None
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 6. Unknown tool returns error --

    def test_unknown_tool_returns_error(
        self, server_a_path, server_b_path,
    ):
        """Calling an unknown tool returns an error, not a crash."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                result = await gw._forward_call("gamma_nonexistent", {})
                assert result.isError
                assert "Unknown tool" in result.content[0].text
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 7. One downstream crash doesn't affect other --

    def test_one_downstream_crash_other_continues(
        self, server_a_path, server_b_path,
    ):
        """When one downstream is disconnected, the other continues."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                # Close beta's connection to simulate a crash
                ds_beta = gw._downstream_states["beta"]
                if ds_beta.connection:
                    await ds_beta.connection.close()

                # Alpha still works
                r = await gw._forward_call("alpha_get_status", {})
                assert not r.isError
                data = json.loads(r.content[0].text)
                assert data["status"] == "ok"

                # Beta call fails but doesn't crash the gateway
                r2 = await gw._forward_call(
                    "beta_list_files", {"path": "/"},
                )
                assert r2.isError
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 8. Circuit breaker is per-downstream --

    def test_circuit_breaker_per_downstream(
        self, server_a_path, server_b_path,
    ):
        """Circuit breaker state is independent per downstream."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                ds_alpha = gw._downstream_states["alpha"]
                ds_beta = gw._downstream_states["beta"]

                # Both start CLOSED
                assert ds_alpha.circuit_state == CircuitState.CLOSED
                assert ds_beta.circuit_state == CircuitState.CLOSED
                assert gw.healthy is True

                # Open beta's circuit
                from datetime import datetime, timezone
                ds_beta.circuit_state = CircuitState.OPEN
                ds_beta.circuit_opened_at = datetime.now(timezone.utc)

                # Alpha still healthy, gateway reports unhealthy (not all closed)
                assert ds_alpha.circuit_state == CircuitState.CLOSED
                assert ds_beta.circuit_state == CircuitState.OPEN
                assert gw.healthy is False

                # Alpha calls still work
                r = await gw._forward_call("alpha_get_status", {})
                assert not r.isError

                # Beta calls are blocked
                r2 = await gw._forward_call(
                    "beta_list_files", {"path": "/"},
                )
                assert r2.isError
                assert "unhealthy" in r2.content[0].text
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 9. Restart one downstream, tools re-discovered --

    def test_restart_one_downstream_tools_rediscovered(
        self, server_a_path, server_b_path,
    ):
        """Restarting one downstream only re-discovers its tools."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
            )
            await gw.start()
            try:
                # Verify initial state
                assert "alpha_get_status" in gw.tool_map
                assert "beta_list_files" in gw.tool_map

                ds_beta = gw._downstream_states["beta"]
                # Rebuild beta only
                gw._rebuild_tool_map_for(ds_beta)

                # Alpha tools still present
                assert "alpha_get_status" in gw.tool_map
                assert "alpha_search" in gw.tool_map
                # Beta tools re-discovered
                assert "beta_list_files" in gw.tool_map
                assert "beta_read_file" in gw.tool_map
                assert "beta_write_file" in gw.tool_map
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 10. Single downstream identical to v0.10.0 --

    def test_single_downstream_backward_compat(self, server_a_path):
        """Single downstream via DownstreamSpec behaves like legacy constructor."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="mock",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                ],
            )
            await gw.start()
            try:
                # Works like the legacy single-downstream mode
                assert gw.server_name == "mock"
                assert gw.downstream is not None
                assert gw.circuit_state == CircuitState.CLOSED
                assert gw.consecutive_failures == 0
                assert gw.healthy is True

                # Tool discovery works
                assert "mock_get_status" in gw.tool_map
                r = await gw._forward_call("mock_get_status", {})
                assert not r.isError
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 11. Zero downstreams raises error --

    def test_zero_downstreams_raises_error(self):
        """Empty downstreams list raises ValueError."""
        with pytest.raises(ValueError, match="at least one entry"):
            SannaGateway(downstreams=[])

    # -- 12. Duplicate downstream names rejected --

    def test_duplicate_downstream_names_rejected(self):
        """Duplicate downstream names raise ValueError."""
        with pytest.raises(ValueError, match="Duplicate downstream name"):
            SannaGateway(
                downstreams=[
                    DownstreamSpec(name="dup", command="unused"),
                    DownstreamSpec(name="dup", command="unused2"),
                ],
            )

    # -- 13. Receipts include server_name --

    def test_receipts_include_server_name(
        self, server_a_path, server_b_path, tmp_path,
    ):
        """Receipts include server_name identifying which downstream."""
        async def _test():
            # Create a minimal signed constitution
            from sanna.constitution import (
                Constitution,
                AgentIdentity,
                Provenance,
                Boundary,
                sign_constitution,
                save_constitution,
            )
            from sanna.crypto import generate_keypair

            key_dir = tmp_path / "keys"
            priv, pub = generate_keypair(str(key_dir))
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
            signed = sign_constitution(constitution, private_key_path=priv)
            const_path = str(tmp_path / "const.yaml")
            save_constitution(signed, const_path)

            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="alpha",
                        command=sys.executable,
                        args=[server_a_path],
                    ),
                    DownstreamSpec(
                        name="beta",
                        command=sys.executable,
                        args=[server_b_path],
                    ),
                ],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=priv,
            )
            await gw.start()
            try:
                # Call alpha tool — receipt should show server_name=alpha
                await gw._forward_call("alpha_get_status", {})
                r1 = gw.last_receipt
                assert r1 is not None
                assert r1["extensions"]["com.sanna.gateway"]["server_name"] == "alpha"

                # Call beta tool — receipt should show server_name=beta
                await gw._forward_call(
                    "beta_list_files", {"path": "/"},
                )
                r2 = gw.last_receipt
                assert r2 is not None
                assert r2["extensions"]["com.sanna.gateway"]["server_name"] == "beta"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    # -- 14. downstream_states property returns copy --

    def test_downstream_states_is_copy(self, server_a_path):
        """downstream_states property returns a copy, not internal dict."""
        gw = SannaGateway(
            downstreams=[
                DownstreamSpec(
                    name="alpha",
                    command=sys.executable,
                    args=[server_a_path],
                ),
            ],
        )
        states = gw.downstream_states
        states["injected"] = None
        assert "injected" not in gw.downstream_states

    # -- 15. Missing server_name and command raises error --

    def test_missing_server_name_and_command_raises(self):
        """Must provide either downstreams or server_name+command."""
        with pytest.raises(ValueError, match="Either 'downstreams'"):
            SannaGateway()


# =============================================================================
# NAMESPACE COLLISION VALIDATION (Fix 2)
# =============================================================================

class TestNamespaceCollision:
    def test_underscore_in_downstreams_list_accepted(self):
        """Underscore in downstream name is now accepted (Block G)."""
        # No exception — underscores allowed since Block G
        gw = SannaGateway(
            downstreams=[
                DownstreamSpec(
                    name="my_server",
                    command="echo",
                ),
            ],
        )
        assert "my_server" in gw._downstream_states

    def test_underscore_in_server_name_accepted(self):
        """Underscore in legacy server_name is now accepted (Block G)."""
        gw = SannaGateway(
            server_name="my_server",
            command="echo",
        )
        assert "my_server" in gw._downstream_states

    def test_special_chars_in_downstreams_rejected(self):
        """Special characters in downstream name still rejected."""
        with pytest.raises(ValueError, match="invalid.*characters"):
            SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="my server!",
                        command="echo",
                    ),
                ],
            )

    def test_special_chars_in_server_name_rejected(self):
        """Special characters in legacy server_name rejected."""
        with pytest.raises(ValueError, match="invalid.*characters"):
            SannaGateway(
                server_name="my server!",
                command="echo",
            )

    def test_hyphen_in_name_accepted(self, mock_server_path):
        """Hyphen in downstream name is accepted."""
        gw = SannaGateway(
            server_name="my-server",
            command=sys.executable,
            args=[mock_server_path],
        )
        assert gw.server_name == "my-server"


# =============================================================================
# OPTIONAL DOWNSTREAM STARTUP (Fix 6)
# =============================================================================

class TestOptionalDownstream:
    def test_optional_failure_does_not_kill_startup(
        self, mock_server_path,
    ):
        """Optional downstream failure → gateway starts with remaining."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="good",
                        command=sys.executable,
                        args=[mock_server_path],
                    ),
                    DownstreamSpec(
                        name="bad",
                        command="nonexistent-command-xyz",
                        optional=True,
                    ),
                ],
            )
            await gw.start()
            try:
                # Good downstream connected
                ds_good = gw.downstream_states["good"]
                assert ds_good.connection is not None

                # Bad downstream connection is None
                ds_bad = gw.downstream_states["bad"]
                assert ds_bad.connection is None

                # Good downstream tools are available
                tools = gw._build_tool_list()
                names = {t.name for t in tools if t.name not in _META_TOOL_NAMES}
                assert any(n.startswith("good_") for n in names)
                assert not any(n.startswith("bad_") for n in names)
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_required_failure_kills_startup(self, mock_server_path):
        """Required downstream failure → gateway startup fails."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="good",
                        command=sys.executable,
                        args=[mock_server_path],
                    ),
                    DownstreamSpec(
                        name="bad",
                        command="nonexistent-command-xyz",
                        optional=False,
                    ),
                ],
            )
            with pytest.raises(Exception):
                await gw.start()

        asyncio.run(_test())

    def test_all_optional_all_fail(self):
        """All optional downstreams fail → gateway starts with no tools."""
        async def _test():
            gw = SannaGateway(
                downstreams=[
                    DownstreamSpec(
                        name="opt-a",
                        command="nonexistent-a-xyz",
                        optional=True,
                    ),
                    DownstreamSpec(
                        name="opt-b",
                        command="nonexistent-b-xyz",
                        optional=True,
                    ),
                ],
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                # Only meta-tools, no downstream tools
                names = {t.name for t in tools if t.name not in _META_TOOL_NAMES}
                assert len(names) == 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())
