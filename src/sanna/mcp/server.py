"""
Sanna MCP server — exposes receipt verification, generation, check listing,
and action evaluation as MCP tools over stdio transport.

Usage:
    python -m sanna.mcp          # stdio transport (Claude Desktop, Cursor)
    sanna-mcp                    # via entry point

Tools:
    sanna_verify_receipt     — Verify a Sanna reasoning receipt offline
    sanna_generate_receipt   — Generate a receipt from query/context/response
    sanna_list_checks        — List all C1-C5 checks and their descriptions
    sanna_evaluate_action    — Authority boundary enforcement
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

logger = logging.getLogger("sanna.mcp")

# =============================================================================
# INPUT SIZE LIMITS
# =============================================================================

MAX_RECEIPT_JSON_SIZE = 1 * 1024 * 1024     # 1 MB
MAX_CONTEXT_SIZE = 500 * 1024               # 500 KB
MAX_RESPONSE_SIZE = 500 * 1024              # 500 KB
MAX_ACTION_SIZE = 10 * 1024                 # 10 KB

# =============================================================================
# SERVER
# =============================================================================

mcp = FastMCP("sanna_mcp")


# =============================================================================
# PYDANTIC INPUT MODELS
# =============================================================================

class VerifyReceiptInput(BaseModel):
    """Input for sanna_verify_receipt tool."""
    receipt_json: str = Field(
        description="JSON string of a Sanna reasoning receipt to verify."
    )


class GenerateReceiptInput(BaseModel):
    """Input for sanna_generate_receipt tool."""
    query: str = Field(
        description="The user query or prompt that was sent to the agent."
    )
    context: str = Field(
        description="The retrieved context or documents provided to the agent."
    )
    response: str = Field(
        description="The agent's response or output."
    )
    constitution_path: Optional[str] = Field(
        default=None,
        description=(
            "Optional path to a signed Sanna constitution YAML file. "
            "When provided, the constitution's invariants drive which checks "
            "run and at what enforcement level."
        ),
    )


class EvaluateActionInput(BaseModel):
    """Input for sanna_evaluate_action tool."""
    action_name: str = Field(
        description="Name of the action the agent intends to take."
    )
    action_params: dict = Field(
        description="Parameters for the action."
    )
    constitution_path: str = Field(
        description="Path to the constitution YAML that defines authority boundaries."
    )


# =============================================================================
# TOOL: sanna_verify_receipt
# =============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
    ),
)
def sanna_verify_receipt(receipt_json: str) -> str:
    """Verify a Sanna reasoning receipt offline.

    Validates the receipt's schema, fingerprint, content hashes, status
    consistency, and check counts. Returns a structured JSON result
    indicating whether the receipt is VALID or INVALID, with detailed
    error and warning messages.

    Args:
        receipt_json: JSON string of a Sanna reasoning receipt.

    Returns:
        JSON string with verification result including valid (bool),
        exit_code, errors, and warnings.
    """
    try:
        if len(receipt_json) > MAX_RECEIPT_JSON_SIZE:
            return json.dumps({
                "valid": False,
                "exit_code": 5,
                "errors": [f"Input too large: {len(receipt_json)} bytes (max {MAX_RECEIPT_JSON_SIZE})"],
                "warnings": [],
            })

        from sanna.verify import verify_receipt, load_schema

        try:
            receipt = json.loads(receipt_json)
        except json.JSONDecodeError as e:
            return json.dumps({
                "valid": False,
                "exit_code": 5,
                "errors": [f"Invalid JSON: {e}"],
                "warnings": [],
            })

        schema = load_schema()
        result = verify_receipt(receipt, schema)

        return json.dumps({
            "valid": result.valid,
            "exit_code": result.exit_code,
            "errors": result.errors,
            "warnings": result.warnings,
            "computed_fingerprint": result.computed_fingerprint,
            "expected_fingerprint": result.expected_fingerprint,
            "computed_status": result.computed_status,
            "expected_status": result.expected_status,
        })
    except Exception as e:
        logger.exception("sanna_verify_receipt failed")
        return json.dumps({
            "valid": False,
            "exit_code": 5,
            "errors": [f"Internal error: {e}"],
            "warnings": [],
        })


# =============================================================================
# TOOL: sanna_generate_receipt
# =============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
    ),
)
def sanna_generate_receipt(
    query: str,
    context: str,
    response: str,
    constitution_path: str | None = None,
) -> str:
    """Generate a Sanna reasoning receipt from query, context, and response.

    Runs the same coherence check pipeline as @sanna_observe but as a
    standalone function. When a constitution_path is provided, the
    constitution's invariants drive which checks run (C1-C5) and at what
    enforcement level (halt/warn/log).

    Without a constitution, a minimal receipt is generated with no checks.

    Args:
        query: The user query or prompt.
        context: The retrieved context or documents.
        response: The agent's response.
        constitution_path: Optional path to a signed constitution YAML.

    Returns:
        JSON string of the generated receipt.
    """
    try:
        # Input size guards
        for field_name, field_val, limit in [
            ("context", context, MAX_CONTEXT_SIZE),
            ("response", response, MAX_RESPONSE_SIZE),
        ]:
            if len(field_val) > limit:
                return json.dumps({
                    "error": f"Input '{field_name}' too large: {len(field_val)} bytes (max {limit})",
                    "receipt": None,
                })

        from sanna.middleware import (
            _build_trace_data,
            _generate_constitution_receipt,
            _generate_no_invariants_receipt,
        )

        trace_id = f"mcp-{uuid.uuid4().hex[:12]}"
        trace_data = _build_trace_data(
            trace_id=trace_id,
            query=query,
            context=context,
            output=response,
        )

        if constitution_path is not None:
            from sanna.constitution import (
                load_constitution,
                constitution_to_receipt_ref,
                SannaConstitutionError,
            )
            from sanna.enforcement import configure_checks

            try:
                constitution = load_constitution(constitution_path, validate=True)
            except (SannaConstitutionError, FileNotFoundError, ValueError) as e:
                return json.dumps({
                    "error": str(e),
                    "receipt": None,
                })

            if not constitution.policy_hash:
                return json.dumps({
                    "error": (
                        f"Constitution is not signed: {constitution_path}. "
                        f"Run: sanna-sign-constitution {constitution_path}"
                    ),
                    "receipt": None,
                })

            constitution_ref = constitution_to_receipt_ref(constitution)
            check_configs, custom_records = configure_checks(constitution)
            constitution_version = constitution.schema_version

            if not check_configs and not custom_records:
                receipt = _generate_no_invariants_receipt(
                    trace_data,
                    constitution_ref=constitution_ref,
                )
            else:
                receipt = _generate_constitution_receipt(
                    trace_data,
                    check_configs=check_configs,
                    custom_records=custom_records,
                    constitution_ref=constitution_ref,
                    constitution_version=constitution_version,
                )
        else:
            receipt = _generate_no_invariants_receipt(
                trace_data,
                constitution_ref=None,
            )

        return json.dumps(receipt, indent=2)
    except Exception as e:
        logger.exception("sanna_generate_receipt failed")
        return json.dumps({
            "error": f"Internal error: {e}",
            "receipt": None,
        })


# =============================================================================
# TOOL: sanna_list_checks
# =============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
    ),
)
def sanna_list_checks() -> str:
    """List all Sanna coherence checks (C1-C5) with descriptions.

    Returns a JSON array describing each check, its invariant mapping,
    default enforcement level, and severity. These checks are heuristic
    pattern-matching evaluators that detect reasoning integrity issues
    in agent outputs.

    Returns:
        JSON string with array of check descriptions.
    """
    try:
        return _list_checks_impl()
    except Exception as e:
        logger.exception("sanna_list_checks failed")
        return json.dumps({"error": f"Internal error: {e}"})


def _list_checks_impl() -> str:
    checks = [
        {
            "check_id": "C1",
            "name": "Context Contradiction",
            "invariant": "INV_NO_FABRICATION",
            "check_impl": "sanna.context_contradiction",
            "description": (
                "Detects when an agent's output contradicts explicit "
                "statements in the provided context. For example, claiming "
                "a refund is possible when context says 'non-refundable'."
            ),
            "default_severity": "critical",
            "default_enforcement": "halt",
        },
        {
            "check_id": "C2",
            "name": "Mark Inferences",
            "invariant": "INV_MARK_INFERENCE",
            "check_impl": "sanna.unmarked_inference",
            "description": (
                "Checks whether speculative or inferential statements are "
                "properly hedged. Flags outputs that use definitive language "
                "(e.g., 'definitely', 'always') without appropriate hedging."
            ),
            "default_severity": "warning",
            "default_enforcement": "warn",
        },
        {
            "check_id": "C3",
            "name": "No False Certainty",
            "invariant": "INV_NO_FALSE_CERTAINTY",
            "check_impl": "sanna.false_certainty",
            "description": (
                "Detects when confidence level exceeds evidence strength. "
                "Flags outputs that make confident claims when the context "
                "contains conditional language ('if', 'unless', 'except')."
            ),
            "default_severity": "warning",
            "default_enforcement": "warn",
        },
        {
            "check_id": "C4",
            "name": "Preserve Tensions",
            "invariant": "INV_PRESERVE_TENSION",
            "check_impl": "sanna.conflict_collapse",
            "description": (
                "Checks whether conflicting information in context is "
                "preserved in the output rather than collapsed into a "
                "single narrative. Detects when policy tensions are lost."
            ),
            "default_severity": "warning",
            "default_enforcement": "warn",
        },
        {
            "check_id": "C5",
            "name": "No Premature Compression",
            "invariant": "INV_NO_PREMATURE_COMPRESSION",
            "check_impl": "sanna.premature_compression",
            "description": (
                "Flags when multi-faceted context is compressed into an "
                "oversimplified response. Triggers when context has 3+ "
                "distinct points but the output is a single sentence."
            ),
            "default_severity": "warning",
            "default_enforcement": "warn",
        },
    ]

    return json.dumps(checks, indent=2)


# =============================================================================
# TOOL: sanna_evaluate_action
# =============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
    ),
)
def sanna_evaluate_action(
    action_name: str,
    action_params: dict,
    constitution_path: str,
) -> str:
    """Evaluate whether an action is permitted under a constitution's authority boundaries.

    Loads the constitution and evaluates the action against its authority
    boundaries (cannot_execute, must_escalate, can_execute). Returns a
    structured JSON result with the enforcement decision.

    If the constitution has no authority_boundaries section, the action
    is allowed by default.

    Args:
        action_name: Name of the action the agent intends to take.
        action_params: Parameters for the action.
        constitution_path: Path to the constitution YAML.

    Returns:
        JSON string with decision, reason, boundary_type, and optional
        escalation_target.
    """
    try:
        # Input size guards
        if action_params:
            params_json = json.dumps(action_params)
            if len(params_json) > 100_000:  # 100KB
                return json.dumps({
                    "error": f"action_params too large: {len(params_json)} bytes (max 100000)",
                    "decision": None,
                })

        if len(action_name) > MAX_ACTION_SIZE:
            return json.dumps({
                "error": f"action_name too large: {len(action_name)} bytes (max {MAX_ACTION_SIZE})",
                "decision": None,
            })

        from sanna.constitution import load_constitution, SannaConstitutionError
        from sanna.enforcement.authority import evaluate_authority

        try:
            constitution = load_constitution(constitution_path, validate=True)
        except (SannaConstitutionError, FileNotFoundError, ValueError) as e:
            return json.dumps({
                "error": str(e),
                "decision": None,
            })

        decision = evaluate_authority(action_name, action_params, constitution)

        result = {
            "decision": decision.decision,
            "reason": decision.reason,
            "boundary_type": decision.boundary_type,
            "action_name": action_name,
            "constitution_path": constitution_path,
        }

        if decision.escalation_target is not None:
            result["escalation_target"] = {
                "type": decision.escalation_target.type,
            }
        else:
            result["escalation_target"] = None

        return json.dumps(result)
    except Exception as e:
        logger.exception("sanna_evaluate_action failed")
        return json.dumps({
            "error": f"Internal error: {e}",
            "decision": None,
        })


# =============================================================================
# SERVER RUNNER
# =============================================================================

def run_server() -> None:
    """Run the Sanna MCP server with stdio transport."""
    mcp.run(transport="stdio")
