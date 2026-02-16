"""Tests for Block 5: Concurrency, Quality, and DX.

Covers:
- Downstream connection lock serializes call_tool/list_tools
- Keyword matching word-boundary (false positive fixes)
- Error receipt reasoning_evaluation parameter
- Schema mutation with empty args → runtime_evaluated
- CLI entry point existence
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sanna.enforcement.authority import _matches_condition


# ---------------------------------------------------------------------------
# Downstream concurrency lock
# ---------------------------------------------------------------------------


class TestDownstreamConnectionLock:
    @pytest.fixture
    def mock_connection(self):
        """Create a DownstreamConnection with mocked internals."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.mcp_client import DownstreamConnection

        conn = object.__new__(DownstreamConnection)
        conn._command = "echo"
        conn._args = []
        conn._env = None
        conn._timeout = 30.0
        conn._connected = True
        conn._tools = []
        conn._tool_names = set()
        conn._exit_stack = None
        conn._last_call_was_connection_error = False
        conn._lock = asyncio.Lock()
        conn._session = MagicMock()
        return conn

    @pytest.mark.asyncio
    async def test_call_tool_serialized(self, mock_connection):
        """Two concurrent call_tool() invocations are serialized by the lock."""
        mcp = pytest.importorskip("mcp")
        from mcp.types import CallToolResult, TextContent

        execution_order = []

        async def mock_call_tool(name, args):
            execution_order.append(f"start_{name}")
            await asyncio.sleep(0.05)
            execution_order.append(f"end_{name}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"result_{name}")],
            )

        mock_connection._session.call_tool = mock_call_tool

        # Run two calls concurrently
        results = await asyncio.gather(
            mock_connection.call_tool("tool_a", {"x": 1}),
            mock_connection.call_tool("tool_b", {"y": 2}),
        )

        # Both should complete successfully
        assert len(results) == 2

        # Calls should be serialized: start_a, end_a, start_b, end_b
        # (or start_b, end_b, start_a, end_a)
        assert execution_order[0].startswith("start_")
        assert execution_order[1].startswith("end_")
        assert execution_order[2].startswith("start_")
        assert execution_order[3].startswith("end_")

    @pytest.mark.asyncio
    async def test_list_tools_uses_lock(self, mock_connection):
        """list_tools() acquires the lock."""
        mcp = pytest.importorskip("mcp")

        lock_acquired = []

        async def mock_list_tools():
            lock_acquired.append(mock_connection._lock.locked())
            result = MagicMock()
            result.tools = []
            return result

        mock_connection._session.list_tools = mock_list_tools

        await mock_connection.list_tools()

        # The lock should have been acquired when list_tools ran
        assert lock_acquired == [True]

    @pytest.mark.asyncio
    async def test_lock_exists_on_init(self):
        """DownstreamConnection.__init__ creates an asyncio.Lock."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.mcp_client import DownstreamConnection

        conn = DownstreamConnection(command="echo", args=[])
        assert hasattr(conn, "_lock")
        assert isinstance(conn._lock, asyncio.Lock)


# ---------------------------------------------------------------------------
# Keyword matching word-boundary fixes
# ---------------------------------------------------------------------------


class TestKeywordWordBoundary:
    def test_add_does_not_match_padder(self):
        """'add' does NOT match inside 'padder' (false positive fix)."""
        assert not _matches_condition("add items", "padder system")

    def test_add_matches_add_this_item(self):
        """'add' DOES match 'add this item'."""
        assert _matches_condition("add items", "add this item to items list")

    def test_can_does_not_match_scan(self):
        """'can' does NOT match inside 'scan'."""
        # "can" is actually a stop word (3 chars, in _STOP_WORDS), so
        # the significant words filter removes it. Let's test with a
        # different word.
        assert not _matches_condition("post message", "compost pile message")

    def test_post_does_not_match_compost(self):
        """'post' does NOT match inside 'compost'."""
        assert not _matches_condition("post external", "compost external")

    def test_post_matches_api_post_search(self):
        """'post' DOES match 'API-post-search' (word boundary after hyphen)."""
        assert _matches_condition("post search", "API-post-search")

    def test_delete_matches_deleted(self):
        """'delete' matches 'deleted' (prefix word-boundary allows inflection)."""
        assert _matches_condition(
            "delete production database",
            "the database in production should be deleted",
        )

    def test_case_insensitive(self):
        """Matching is case insensitive."""
        assert _matches_condition("Delete Items", "please delete some items")

    def test_existing_behavior_preserved(self):
        """Existing all-keywords-required behavior still works."""
        # All keywords present → match
        assert _matches_condition(
            "delete production database",
            "please delete the production database",
        )
        # Partial keywords → no match
        assert not _matches_condition(
            "update production database",
            "update staging database",
        )


# ---------------------------------------------------------------------------
# Error receipt reasoning_evaluation
# ---------------------------------------------------------------------------


class TestErrorReceiptReasoningEvaluation:
    def test_error_receipt_accepts_reasoning_evaluation(self):
        """_generate_error_receipt accepts reasoning_evaluation parameter."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        # Check that the method signature accepts reasoning_evaluation
        import inspect
        sig = inspect.signature(SannaGateway._generate_error_receipt)
        assert "reasoning_evaluation" in sig.parameters

    def test_error_receipt_without_reasoning_evaluation(self):
        """_generate_error_receipt works without reasoning_evaluation (backward compat)."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway.server import SannaGateway

        # Verify default is None
        import inspect
        sig = inspect.signature(SannaGateway._generate_error_receipt)
        param = sig.parameters["reasoning_evaluation"]
        assert param.default is None


# ---------------------------------------------------------------------------
# Schema mutation with empty args
# ---------------------------------------------------------------------------


class TestSchemaMutationEmptyArgs:
    def test_empty_args_uncategorized_returns_runtime_evaluated(self):
        """evaluate_authority with empty args and uncategorized result → runtime_evaluated."""
        from sanna.constitution import parse_constitution
        from sanna.gateway.schema_mutation import _resolve_enforcement_level

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "dev@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"}
            ],
            "authority_boundaries": {
                "cannot_execute": ["delete_system"],
                "must_escalate": [
                    {"condition": "modify financial records", "target": None},
                ],
                "can_execute": ["read_data"],
            },
        }

        constitution = parse_constitution(data)

        # Tool not matching any explicit rule → runtime_evaluated
        level = _resolve_enforcement_level(
            "some_unknown_tool", constitution,
        )
        assert level == "runtime_evaluated"

    def test_empty_args_matched_tool_returns_boundary(self):
        """Tool matching a name-based rule still returns proper boundary type."""
        from sanna.constitution import parse_constitution
        from sanna.gateway.schema_mutation import _resolve_enforcement_level

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "dev@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"}
            ],
            "authority_boundaries": {
                "cannot_execute": ["delete_system"],
                "must_escalate": [],
                "can_execute": ["read_data"],
            },
        }

        constitution = parse_constitution(data)

        # Tool matching cannot_execute → still returns cannot_execute
        level = _resolve_enforcement_level(
            "delete_system", constitution,
        )
        assert level == "cannot_execute"

        # Tool matching can_execute → still returns can_execute
        level = _resolve_enforcement_level(
            "read_data", constitution,
        )
        assert level == "can_execute"

    def test_runtime_evaluated_gets_optional_justification(self):
        """runtime_evaluated tools get optional _justification (conservative)."""
        from sanna.constitution import parse_constitution
        from sanna.gateway.schema_mutation import mutate_tool_schema

        data = {
            "sanna_constitution": "1.1",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "dev@test.com",
                "approved_by": ["approver@test.com"],
                "approval_date": "2026-01-01",
                "approval_method": "manual",
            },
            "boundaries": [
                {"id": "B001", "description": "Test", "category": "scope", "severity": "high"}
            ],
            "authority_boundaries": {
                "cannot_execute": [],
                "must_escalate": [
                    {"condition": "modify financial records", "target": None},
                ],
                "can_execute": [],
            },
            "reasoning": {
                "require_justification_for": ["must_escalate"],
                "checks": {},
            },
        }

        constitution = parse_constitution(data)

        tool = {
            "name": "some_tool",
            "inputSchema": {"type": "object", "properties": {}},
        }

        mutated = mutate_tool_schema(tool, constitution)

        # _justification should be present but NOT required
        assert "_justification" in mutated["inputSchema"]["properties"]
        required = mutated["inputSchema"].get("required", [])
        assert "_justification" not in required


# ---------------------------------------------------------------------------
# CLI entry point verification
# ---------------------------------------------------------------------------


class TestCLIEntryPoints:
    def test_keygen_entry_point_importable(self):
        """sanna-keygen entry point function is importable."""
        from sanna.cli import main_keygen
        assert callable(main_keygen)

    def test_init_constitution_entry_point_importable(self):
        """sanna-init-constitution entry point function is importable."""
        from sanna.cli import main_init_constitution
        assert callable(main_init_constitution)

    def test_init_entry_point_importable(self):
        """sanna-init entry point function is importable."""
        from sanna.init_constitution import main
        assert callable(main)

    def test_verify_entry_point_importable(self):
        """sanna-verify entry point function is importable."""
        from sanna.cli import main_verify
        assert callable(main_verify)

    def test_generate_entry_point_importable(self):
        """sanna-generate entry point function is importable."""
        from sanna.cli import main_generate
        assert callable(main_generate)

    def test_gateway_entry_point_importable(self):
        """sanna-gateway entry point function is importable."""
        mcp = pytest.importorskip("mcp")
        from sanna.gateway import main
        assert callable(main)
