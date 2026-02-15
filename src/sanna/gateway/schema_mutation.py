"""Tool schema mutation for governance-level reasoning.

Adds ``_justification`` parameter to downstream tool schemas for
tools that require justification based on the constitution's
reasoning configuration and enforcement levels.

Schema mutation happens at tool listing time — before any tool calls
are made.  The ``_justification`` parameter is added as a required
string field so MCP clients (Claude Desktop, Claude Code) include it
in their tool calls.
"""

from __future__ import annotations

import copy
from typing import Any

from sanna.constitution import Constitution


def mutate_tool_schema(
    tool_dict: dict[str, Any],
    constitution: Constitution,
    policy_overrides: dict[str, str] | None = None,
    default_policy: str | None = None,
) -> dict[str, Any]:
    """Add ``_justification`` parameter to a tool schema if required.

    Uses the policy cascade (per-tool override > default_policy >
    constitution authority boundaries) to determine enforcement level,
    then checks if that level is in the constitution's
    ``require_justification_for`` list.

    Returns a deep copy of the tool dict with ``_justification`` added,
    or the original dict unchanged if no mutation is needed.

    Args:
        tool_dict: Downstream tool schema dict (must have ``name``).
        constitution: Constitution with reasoning config.
        policy_overrides: Per-tool policy overrides from gateway config.
        default_policy: Default policy for the downstream server.

    Returns:
        Possibly-mutated tool dict.
    """
    if not constitution.reasoning:
        return tool_dict

    require_for = constitution.reasoning.require_justification_for
    if not require_for:
        return tool_dict

    tool_name = tool_dict.get("name", "")
    enforcement_level = _resolve_enforcement_level(
        tool_name, constitution, policy_overrides, default_policy,
    )

    if enforcement_level not in require_for:
        return tool_dict

    # Deep copy to avoid mutating the original (stored in connection.tools)
    mutated = copy.deepcopy(tool_dict)
    input_schema = mutated.setdefault("inputSchema", {"type": "object"})
    properties = input_schema.setdefault("properties", {})
    required = input_schema.setdefault("required", [])

    properties["_justification"] = {
        "type": "string",
        "description": (
            "Explain why this action should be taken. "
            "Required for governance."
        ),
    }

    if "_justification" not in required:
        required.append("_justification")

    return mutated


def _resolve_enforcement_level(
    tool_name: str,
    constitution: Constitution,
    policy_overrides: dict[str, str] | None = None,
    default_policy: str | None = None,
) -> str:
    """Resolve the enforcement level for a tool.

    Mirrors the policy cascade in ``SannaGateway._resolve_policy()``:

    1. Per-tool override (exact match on unprefixed name)
    2. Restrictive default_policy (must_escalate or cannot_execute)
    3. Constitution authority boundary evaluation
    """
    # 1. Per-tool override — exact match, highest priority
    if policy_overrides:
        override = policy_overrides.get(tool_name)
        if override is not None:
            return override

    # 2. Restrictive default_policy
    if default_policy and default_policy != "can_execute":
        return default_policy

    # 3. Constitution authority boundary evaluation
    if constitution.authority_boundaries:
        from sanna.enforcement import evaluate_authority

        decision = evaluate_authority(tool_name, {}, constitution)
        return decision.boundary_type

    return "can_execute"
