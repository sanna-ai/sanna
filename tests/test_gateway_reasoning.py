"""Tests for gateway reasoning integration (Block G).

Tests cover: reasoning evaluation in enforcement flow, _justification
stripping before forwarding, reasoning results in receipts, schema
mutation in tool listing, and escalation interactions.
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
        return json.dumps({"status": "ok"})

    @mcp.tool()
    def search(query: str) -> str:
        \"\"\"Search for items.\"\"\"
        return json.dumps({"query": query, "results": ["a", "b"]})

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

def _create_signed_constitution_v11(
    tmp_path,
    authority_boundaries=None,
    reasoning_data=None,
):
    """Create a signed v1.1 constitution with reasoning config.

    Returns (constitution_path, private_key_path, public_key_path).
    """
    from sanna.constitution import parse_constitution, sign_constitution, save_constitution
    from sanna.crypto import generate_keypair

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    data = {
        "sanna_constitution": "1.1",
        "identity": {"agent_name": "test-agent", "domain": "testing"},
        "provenance": {
            "authored_by": "dev@test.com",
            "approved_by": ["approver@test.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {"id": "B001", "description": "Test", "category": "scope", "severity": "high"},
        ],
        "version": "1.1",
    }

    if authority_boundaries:
        ab = authority_boundaries
        data["authority_boundaries"] = {
            "cannot_execute": ab.get("cannot_execute", []),
            "must_escalate": [
                {"condition": r} for r in ab.get("must_escalate", [])
            ],
            "can_execute": ab.get("can_execute", []),
        }

    if reasoning_data:
        data["reasoning"] = reasoning_data

    constitution = parse_constitution(data)
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
def reasoning_constitution(tmp_path):
    """Constitution with reasoning config and authority boundaries."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "cannot_execute": ["delete_item"],
            "must_escalate": ["update"],
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["must_escalate"],
            "on_missing_justification": "block",
            "on_check_error": "block",
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
                "glc_003_no_parroting": {"enabled": True},
            },
        },
    )


@pytest.fixture()
def auto_deny_constitution(tmp_path):
    """Constitution with auto_deny_on_reasoning_failure enabled."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["can_execute"],
            "on_missing_justification": "block",
            "on_check_error": "block",
            "auto_deny_on_reasoning_failure": True,
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
                "glc_003_no_parroting": {"enabled": True},
            },
        },
    )


# =============================================================================
# SCHEMA MUTATION IN TOOL LISTING
# =============================================================================

class TestSchemaMutation:
    def test_justification_added_for_must_escalate_tools(
        self, mock_server_path, reasoning_constitution,
    ):
        """Tools requiring escalation get _justification in schema."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                # Find the update_item tool (must_escalate)
                update_tool = None
                for t in tools:
                    if t.name == "mock_update_item":
                        update_tool = t
                        break

                assert update_tool is not None
                props = update_tool.inputSchema.get("properties", {})
                assert "_justification" in props
                assert props["_justification"]["type"] == "string"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_justification_optional_for_can_execute_tools(
        self, mock_server_path, reasoning_constitution,
    ):
        """Tools that are can_execute get _justification as OPTIONAL (not required)."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                tools = gw._build_tool_list()
                search_tool = None
                for t in tools:
                    if t.name == "mock_search":
                        search_tool = t
                        break

                assert search_tool is not None
                props = search_tool.inputSchema.get("properties", {})
                # _justification is present but optional (not in required)
                assert "_justification" in props
                assert props["_justification"]["type"] == "string"
                required = search_tool.inputSchema.get("required", [])
                assert "_justification" not in required
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# REASONING IN ENFORCEMENT FLOW
# =============================================================================

class TestReasoningEnforcement:
    def test_allow_with_valid_justification(
        self, mock_server_path, reasoning_constitution,
    ):
        """Valid justification with can_execute tool passes through."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_get_status", {},
                )
                assert result.isError is not True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_justification_stripped_before_forwarding(
        self, mock_server_path, reasoning_constitution,
    ):
        """_justification is stripped from args before forwarding to downstream."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # search is can_execute, forwards normally
                result = await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "Need to search for data",
                    },
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["query"] == "test"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_reasoning_evaluation_in_receipt(
        self, mock_server_path, reasoning_constitution,
    ):
        """Reasoning evaluation is embedded in the receipt."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "Searching for compliance data in database",
                    },
                )
                receipt = gw.last_receipt
                assert receipt is not None

                # Check gateway_v2 has reasoning evaluation
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert "reasoning_evaluation" in gw_v2

                reasoning = gw_v2["reasoning_evaluation"]
                assert reasoning["assurance"] == "full"
                assert reasoning["passed"] is True
                assert len(reasoning["checks"]) > 0
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# REASONING FAILURE HANDLING
# =============================================================================

class TestReasoningFailure:
    def test_auto_deny_on_reasoning_failure(
        self, mock_server_path, auto_deny_constitution,
    ):
        """auto_deny_on_reasoning_failure=True blocks on bad justification."""
        const_path, key_path, _ = auto_deny_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # "ok" is too short for min_length=20
                result = await gw._forward_call(
                    "mock_search",
                    {"query": "test", "_justification": "ok"},
                )
                assert result.isError is True

                receipt = gw.last_receipt
                assert receipt is not None
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert "reasoning_evaluation" in gw_v2
                assert gw_v2["reasoning_evaluation"]["passed"] is False
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_parroting_justification_blocked(
        self, mock_server_path, auto_deny_constitution,
    ):
        """Parroting justification is caught and denied."""
        const_path, key_path, _ = auto_deny_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "because you asked me to search",
                    },
                )
                assert result.isError is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# JUSTIFICATION STRIPPING
# =============================================================================

class TestJustificationStripping:
    def test_receipt_records_justification_stripped(
        self, mock_server_path, reasoning_constitution,
    ):
        """Receipt records that _justification was stripped."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "Searching for compliance data in database",
                    },
                )
                receipt = gw.last_receipt
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert gw_v2["action"]["justification_stripped"] is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_no_justification_not_stripped(
        self, mock_server_path, reasoning_constitution,
    ):
        """Without _justification, justification_stripped is False."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call("mock_get_status", {})
                receipt = gw.last_receipt
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert gw_v2["action"]["justification_stripped"] is False
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# NO REASONING CONFIG
# =============================================================================

class TestNoReasoningConfig:
    def test_no_reasoning_no_mutation(self, mock_server_path, tmp_path):
        """Without reasoning config, schemas are unchanged and no evaluation runs."""
        from sanna.constitution import (
            AuthorityBoundaries, EscalationRule,
        )

        const_path, key_path, _ = _create_signed_constitution_v11(
            tmp_path,
            authority_boundaries={
                "can_execute": ["get_status", "search"],
            },
        )

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # No reasoning evaluator initialized
                assert gw._reasoning_evaluator is None

                # Tool schemas should not have _justification
                tools = gw._build_tool_list()
                for t in tools:
                    if t.name.startswith("sanna_"):
                        continue  # Skip meta-tools
                    props = t.inputSchema.get("properties", {})
                    assert "_justification" not in props

                # Calls work without justification
                result = await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                assert result.isError is not True

                # Receipt has no reasoning_evaluation
                receipt = gw.last_receipt
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert "reasoning_evaluation" not in gw_v2
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# ON_MISSING_JUSTIFICATION ENFORCEMENT
# =============================================================================

@pytest.fixture()
def missing_justification_block_constitution(tmp_path):
    """Constitution where on_missing_justification='block' for must_escalate."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "cannot_execute": ["delete_item"],
            "must_escalate": ["update"],
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["must_escalate"],
            "on_missing_justification": "block",
            "on_check_error": "allow",
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
                "glc_003_no_parroting": {"enabled": True},
            },
        },
    )


@pytest.fixture()
def missing_justification_escalate_constitution(tmp_path):
    """Constitution where on_missing_justification='escalate' for can_execute."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["can_execute"],
            "on_missing_justification": "escalate",
            "on_check_error": "allow",
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
            },
        },
    )


@pytest.fixture()
def missing_justification_allow_constitution(tmp_path):
    """Constitution where on_missing_justification='allow' for can_execute."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["can_execute"],
            "on_missing_justification": "allow",
            "on_check_error": "allow",
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
            },
        },
    )


class TestOnMissingJustification:
    def test_block_halts_on_missing_justification(
        self, mock_server_path, missing_justification_block_constitution,
    ):
        """on_missing_justification='block' halts when justification is missing."""
        const_path, key_path, _ = missing_justification_block_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # update_item matches must_escalate, no justification
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                # Should be halted (not escalated) due to block
                assert result.isError is True
                assert "Missing required justification" in result.content[0].text
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_escalate_overrides_on_missing_justification(
        self, mock_server_path, missing_justification_escalate_constitution,
    ):
        """on_missing_justification='escalate' overrides to escalation."""
        const_path, key_path, _ = missing_justification_escalate_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # search is can_execute, no justification
                result = await gw._forward_call(
                    "mock_search",
                    {"query": "test"},
                )
                # Should be escalated (not halted)
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_allow_passes_on_missing_justification(
        self, mock_server_path, missing_justification_allow_constitution,
    ):
        """on_missing_justification='allow' passes through without justification."""
        const_path, key_path, _ = missing_justification_allow_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search",
                    {"query": "test"},
                )
                # Should pass through (allow)
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["query"] == "test"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# ON_CHECK_ERROR: "BLOCK" ENFORCEMENT
# =============================================================================

@pytest.fixture()
def check_error_block_constitution(tmp_path):
    """Constitution with on_check_error='block' for can_execute."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["can_execute"],
            "on_missing_justification": "block",
            "on_check_error": "block",
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
                "glc_003_no_parroting": {"enabled": True},
            },
        },
    )


class TestOnCheckErrorBlock:
    def test_block_halts_on_check_failure(
        self, mock_server_path, check_error_block_constitution,
    ):
        """on_check_error='block' halts when a reasoning check fails."""
        const_path, key_path, _ = check_error_block_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # "ok" is too short for min_length=20
                result = await gw._forward_call(
                    "mock_search",
                    {"query": "test", "_justification": "ok"},
                )
                assert result.isError is True
                assert "Reasoning check failed" in result.content[0].text

                receipt = gw.last_receipt
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert "reasoning_evaluation" in gw_v2
                assert gw_v2["reasoning_evaluation"]["passed"] is False
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_block_allows_on_check_pass(
        self, mock_server_path, check_error_block_constitution,
    ):
        """on_check_error='block' allows when reasoning checks pass."""
        const_path, key_path, _ = check_error_block_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "Searching for compliance data in database",
                    },
                )
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["query"] == "test"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# EVALUATE_BEFORE_ESCALATION
# =============================================================================

@pytest.fixture()
def deferred_eval_constitution(tmp_path):
    """Constitution with evaluate_before_escalation=false."""
    return _create_signed_constitution_v11(
        tmp_path,
        authority_boundaries={
            "must_escalate": ["update"],
            "can_execute": ["get_status", "search"],
        },
        reasoning_data={
            "require_justification_for": ["must_escalate"],
            "on_missing_justification": "block",
            "on_check_error": "block",
            "evaluate_before_escalation": False,
            "checks": {
                "glc_002_minimum_substance": {"enabled": True, "min_length": 20},
                "glc_003_no_parroting": {"enabled": True},
            },
        },
    )


class TestEvaluateBeforeEscalation:
    def test_deferred_eval_skips_before_escalation(
        self, mock_server_path, deferred_eval_constitution,
    ):
        """evaluate_before_escalation=false skips reasoning at escalation time."""
        const_path, key_path, _ = deferred_eval_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # update_item matches must_escalate, no justification
                # With evaluate_before_escalation=false, should NOT halt
                # even though justification is missing — just escalate
                result = await gw._forward_call(
                    "mock_update_item",
                    {"item_id": "1", "name": "new"},
                )
                # Should be escalated (reasoning deferred)
                assert result.isError is not True
                data = json.loads(result.content[0].text)
                assert data["status"] == "ESCALATION_REQUIRED"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_deferred_eval_still_runs_for_can_execute(
        self, mock_server_path, deferred_eval_constitution,
    ):
        """evaluate_before_escalation=false only affects escalate decisions."""
        const_path, key_path, _ = deferred_eval_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # search is can_execute, valid justification
                result = await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "Searching for compliance data in database",
                    },
                )
                assert result.isError is not True
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# EVALUATOR ERROR SAFETY
# =============================================================================

class TestJustificationStrippedAudit:
    def test_non_string_justification_stripped_is_true(
        self, mock_server_path, reasoning_constitution,
    ):
        """justification_stripped is True when _justification is present but non-string."""
        const_path, key_path, _ = reasoning_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # _justification is a list (non-string) — should still be stripped
                await gw._forward_call(
                    "mock_search",
                    {"query": "test", "_justification": ["not", "a", "string"]},
                )
                receipt = gw.last_receipt
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert gw_v2["action"]["justification_stripped"] is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_list_justification_treated_as_missing_in_gateway(
        self, mock_server_path, auto_deny_constitution,
    ):
        """Non-string _justification in gateway → treated as missing by pipeline."""
        const_path, key_path, _ = auto_deny_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                result = await gw._forward_call(
                    "mock_search",
                    {"query": "test", "_justification": [1, 2, 3]},
                )
                # auto_deny + missing justification → halt
                assert result.isError is True
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# EVALUATOR ERROR SAFETY
# =============================================================================

class TestEvaluatorErrorSafety:
    def test_evaluator_exception_produces_safe_fallback(
        self, mock_server_path, auto_deny_constitution,
    ):
        """Evaluator exception produces safe fallback ReasoningEvaluation."""
        const_path, key_path, _ = auto_deny_constitution

        async def _test():
            from unittest.mock import AsyncMock

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                # Patch evaluator to raise
                gw._reasoning_evaluator.evaluate = AsyncMock(
                    side_effect=RuntimeError("LLM connection failed"),
                )

                result = await gw._forward_call(
                    "mock_search",
                    {
                        "query": "test",
                        "_justification": "Testing evaluator error handling",
                    },
                )
                # auto_deny_on_reasoning_failure=True + evaluator error
                # → should halt
                assert result.isError is True

                receipt = gw.last_receipt
                gw_v2 = receipt["extensions"]["gateway_v2"]
                assert "reasoning_evaluation" in gw_v2
                assert gw_v2["reasoning_evaluation"]["passed"] is False
                assert gw_v2["reasoning_evaluation"]["failure_reason"] == "evaluator_error"
            finally:
                await gw.shutdown()

        asyncio.run(_test())
