"""Tool schema mutation for governance-level reasoning.

Adds ``_justification`` parameter to downstream tool schemas when
reasoning is enabled in the constitution.

- **Required** for tools whose enforcement level is in
  ``require_justification_for`` (typically ``must_escalate`` /
  ``cannot_execute``).
- **Optional** for all other tools when reasoning is enabled
  (catches argument-dependent rules that fire at call time).

Schema mutation happens at tool listing time — before any tool calls
are made.
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
    """Add ``_justification`` parameter to a tool schema.

    When reasoning is enabled, *every* tool gets ``_justification``
    added to its schema.  The difference is whether it's required:

    - Tools matching ``require_justification_for`` levels → **required**.
    - All other tools → **optional** (catches argument-dependent rules
      that may fire at call time).

    Returns a deep copy of the tool dict with ``_justification`` added,
    or the original dict unchanged if reasoning is disabled.

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

    # Deep copy to avoid mutating the original (stored in connection.tools)
    mutated = copy.deepcopy(tool_dict)

    if enforcement_level in require_for:
        _add_justification_required(mutated)
    else:
        _add_justification_optional(mutated)

    return mutated


def _add_justification_optional(schema: dict) -> None:
    """Add ``_justification`` as an optional string parameter."""
    input_schema = schema.setdefault("inputSchema", {"type": "object"})
    properties = input_schema.setdefault("properties", {})
    properties["_justification"] = {
        "type": "string",
        "description": (
            "Optional reasoning justification for governance evaluation"
        ),
    }
    # Do NOT add to required array


def _add_justification_required(schema: dict) -> None:
    """Add ``_justification`` as a required string parameter."""
    _add_justification_optional(schema)
    # Override description to indicate it's required
    props = schema["inputSchema"]["properties"]
    props["_justification"]["description"] = (
        "Explain why this action should be taken. "
        "Required for governance."
    )
    required = schema["inputSchema"].setdefault("required", [])
    if "_justification" not in required:
        required.append("_justification")


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
    # When args is empty (tool-listing time), condition-based rules that
    # depend on argument values cannot be definitively resolved. We still
    # evaluate to get the best-guess enforcement level, but callers should
    # treat this as advisory — the actual enforcement happens at call time
    # with real arguments.
    if constitution.authority_boundaries:
        from sanna.enforcement import evaluate_authority

        decision = evaluate_authority(tool_name, {}, constitution)
        # When evaluated with empty args and the tool wasn't matched by
        # name-based rules (cannot_execute / can_execute), conservatively
        # treat it as potentially requiring justification. Argument-dependent
        # conditions may fire at call time.
        if decision.boundary_type == "uncategorized":
            return "runtime_evaluated"
        return decision.boundary_type

    return "can_execute"
