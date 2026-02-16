"""Block D tests — schema mutation v2: required vs optional _justification."""

import pytest

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    AuthorityBoundaries,
    EscalationRule,
    ReasoningConfig,
)
from sanna.gateway.schema_mutation import mutate_tool_schema


def _make_tool(name: str) -> dict:
    return {
        "name": name,
        "description": f"Tool: {name}",
        "inputSchema": {"type": "object"},
    }


def _make_constitution(
    *,
    reasoning: ReasoningConfig | None = None,
    authority_boundaries: AuthorityBoundaries | None = None,
) -> Constitution:
    return Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test", domain="testing"),
        provenance=Provenance(
            authored_by="dev@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope", severity="high"),
        ],
        version="1.1",
        reasoning=reasoning,
        authority_boundaries=authority_boundaries,
    )


class TestSchemaJustificationRequired:
    def test_justification_required_for_must_escalate(self):
        """must_escalate tool → _justification in properties AND required."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(
            must_escalate=[EscalationRule(condition="update")],
        )
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("update_item")

        result = mutate_tool_schema(tool, constitution)

        props = result["inputSchema"]["properties"]
        assert "_justification" in props
        assert props["_justification"]["type"] == "string"
        assert "_justification" in result["inputSchema"]["required"]

    def test_justification_optional_for_can_execute(self):
        """can_execute tool → _justification in properties but NOT in required."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(can_execute=["search"])
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("search")

        result = mutate_tool_schema(tool, constitution)

        props = result["inputSchema"]["properties"]
        assert "_justification" in props
        assert props["_justification"]["type"] == "string"
        # NOT in required
        assert "_justification" not in result["inputSchema"].get("required", [])

    def test_justification_when_reasoning_disabled(self):
        """No reasoning config → no _justification added at all."""
        constitution = _make_constitution()  # No reasoning
        tool = _make_tool("search")

        result = mutate_tool_schema(tool, constitution)

        # Original object returned unchanged
        assert result is tool
        assert "_justification" not in result["inputSchema"].get("properties", {})
