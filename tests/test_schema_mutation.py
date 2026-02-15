"""Tests for gateway schema mutation — adding _justification to tool schemas."""

import pytest

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    AuthorityBoundaries,
    EscalationRule,
    ReasoningConfig,
    GLCMinimumSubstanceConfig,
    GLCNoParrotingConfig,
)
from sanna.gateway.schema_mutation import mutate_tool_schema, _resolve_enforcement_level


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tool(name: str, properties: dict | None = None) -> dict:
    """Build a minimal MCP tool dict."""
    schema = {"type": "object"}
    if properties:
        schema["properties"] = properties
        schema["required"] = list(properties.keys())
    return {
        "name": name,
        "description": f"Tool: {name}",
        "inputSchema": schema,
    }


def _make_constitution(
    *,
    reasoning: ReasoningConfig | None = None,
    authority_boundaries: AuthorityBoundaries | None = None,
) -> Constitution:
    """Build a minimal Constitution for testing."""
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


# ---------------------------------------------------------------------------
# No mutation cases
# ---------------------------------------------------------------------------

class TestNoMutation:
    def test_no_reasoning_config(self):
        """No reasoning config -> tool unchanged."""
        tool = _make_tool("search", {"query": {"type": "string"}})
        constitution = _make_constitution()

        result = mutate_tool_schema(tool, constitution)

        assert result is tool  # Same object, no copy needed
        assert "_justification" not in result["inputSchema"].get("properties", {})

    def test_empty_require_justification_for(self):
        """Empty require_justification_for -> no mutation."""
        reasoning = ReasoningConfig(require_justification_for=[])
        constitution = _make_constitution(reasoning=reasoning)
        tool = _make_tool("search")

        result = mutate_tool_schema(tool, constitution)

        assert result is tool

    def test_can_execute_not_in_require_for(self):
        """can_execute tool when only must_escalate requires justification."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(can_execute=["search"])
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("search")

        result = mutate_tool_schema(tool, constitution)

        assert result is tool


# ---------------------------------------------------------------------------
# Mutation applied
# ---------------------------------------------------------------------------

class TestMutationApplied:
    def test_must_escalate_gets_justification(self):
        """must_escalate tool gets _justification added."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(
            must_escalate=[EscalationRule(condition="update")],
        )
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("update_item", {"item_id": {"type": "string"}})

        result = mutate_tool_schema(tool, constitution)

        props = result["inputSchema"]["properties"]
        assert "_justification" in props
        assert props["_justification"]["type"] == "string"
        assert "_justification" in result["inputSchema"]["required"]

    def test_cannot_execute_gets_justification(self):
        """cannot_execute tool gets _justification when in require_for."""
        reasoning = ReasoningConfig(
            require_justification_for=["must_escalate", "cannot_execute"],
        )
        ab = AuthorityBoundaries(cannot_execute=["delete_item"])
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("delete_item")

        result = mutate_tool_schema(tool, constitution)

        assert "_justification" in result["inputSchema"]["properties"]

    def test_original_tool_not_modified(self):
        """Mutation returns a deep copy; original is unchanged."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(
            must_escalate=[EscalationRule(condition="update")],
        )
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("update_item", {"item_id": {"type": "string"}})
        original_props = set(tool["inputSchema"]["properties"].keys())

        mutate_tool_schema(tool, constitution)

        # Original tool dict should be unmodified
        assert set(tool["inputSchema"]["properties"].keys()) == original_props
        assert "_justification" not in tool["inputSchema"].get("properties", {})

    def test_existing_properties_preserved(self):
        """Existing schema properties are preserved after mutation."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(
            must_escalate=[EscalationRule(condition="update")],
        )
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("update_item", {
            "item_id": {"type": "string"},
            "name": {"type": "string"},
        })

        result = mutate_tool_schema(tool, constitution)

        props = result["inputSchema"]["properties"]
        assert "item_id" in props
        assert "name" in props
        assert "_justification" in props

    def test_justification_not_duplicated(self):
        """If _justification already exists, it's not added again to required."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(
            must_escalate=[EscalationRule(condition="update")],
        )
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("update_item")
        # Pre-add _justification to required
        tool["inputSchema"]["required"] = ["_justification"]

        result = mutate_tool_schema(tool, constitution)

        assert result["inputSchema"]["required"].count("_justification") == 1


# ---------------------------------------------------------------------------
# Policy cascade
# ---------------------------------------------------------------------------

class TestPolicyCascade:
    def test_per_tool_override_wins(self):
        """Per-tool policy override takes precedence over everything."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(can_execute=["search"])  # Constitution says can_execute
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("search")

        # Override to must_escalate
        result = mutate_tool_schema(
            tool, constitution,
            policy_overrides={"search": "must_escalate"},
        )

        assert "_justification" in result["inputSchema"]["properties"]

    def test_default_policy_overrides_constitution(self):
        """Server default_policy overrides constitution boundaries."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        ab = AuthorityBoundaries(can_execute=["search"])
        constitution = _make_constitution(reasoning=reasoning, authority_boundaries=ab)
        tool = _make_tool("search")

        # Server default_policy = must_escalate
        result = mutate_tool_schema(
            tool, constitution,
            default_policy="must_escalate",
        )

        assert "_justification" in result["inputSchema"]["properties"]

    def test_per_tool_override_beats_default_policy(self):
        """Per-tool override beats default_policy."""
        reasoning = ReasoningConfig(require_justification_for=["must_escalate"])
        constitution = _make_constitution(reasoning=reasoning)
        tool = _make_tool("search")

        # default_policy=must_escalate but per-tool says can_execute
        result = mutate_tool_schema(
            tool, constitution,
            policy_overrides={"search": "can_execute"},
            default_policy="must_escalate",
        )

        assert result is tool  # No mutation (can_execute)


# ---------------------------------------------------------------------------
# _resolve_enforcement_level
# ---------------------------------------------------------------------------

class TestResolveEnforcementLevel:
    def test_per_tool_override(self):
        constitution = _make_constitution()
        level = _resolve_enforcement_level(
            "search", constitution,
            policy_overrides={"search": "cannot_execute"},
        )
        assert level == "cannot_execute"

    def test_default_policy(self):
        constitution = _make_constitution()
        level = _resolve_enforcement_level(
            "search", constitution,
            default_policy="must_escalate",
        )
        assert level == "must_escalate"

    def test_can_execute_default_policy_falls_through(self):
        """default_policy='can_execute' falls through to constitution."""
        constitution = _make_constitution()
        level = _resolve_enforcement_level(
            "search", constitution,
            default_policy="can_execute",
        )
        assert level == "can_execute"

    def test_no_authority_boundaries_defaults_to_can_execute(self):
        constitution = _make_constitution()
        level = _resolve_enforcement_level("anything", constitution)
        assert level == "can_execute"

    def test_constitution_authority_boundaries(self):
        ab = AuthorityBoundaries(
            cannot_execute=["delete_item"],
        )
        constitution = _make_constitution(authority_boundaries=ab)
        level = _resolve_enforcement_level("delete_item", constitution)
        assert level == "cannot_execute"
