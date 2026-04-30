"""
Manifest Phase 1: governed capability surface receipt builder.

Reads a constitution and (optionally) an MCP tool catalog and produces a
com.sanna.manifest extension dict per v1.5 spec Section 2.20. The dict
flows into a session_manifest receipt emitted at session initialization.

This module is shared composition logic. The gateway calls it for the
MCP surface; CLI + HTTP interceptors call it for their respective surfaces
in SAN-206.
"""

from __future__ import annotations

from typing import Any, Optional

from .constitution import Constitution
from .enforcement.authority import evaluate_authority


# Stable suppression_reason enum per v1.5 spec Section 2.21
SUPPRESSION_REASON_CANNOT_EXECUTE = "cannot_execute"
SUPPRESSION_REASON_POLICY_DENIED = "policy_denied"
SUPPRESSION_REASON_ESCALATION_SUPPRESSED = "escalation_suppressed"
SUPPRESSION_REASON_SERVER_DEFAULT_DENIED = "server_default_denied"
SUPPRESSION_REASON_CONSTITUTION_INVALID = "constitution_invalid"
SUPPRESSION_REASON_CONTENT_MODE_REDACTED = "content_mode_redacted"
SUPPRESSION_REASON_UNKNOWN = "unknown"

VALID_SUPPRESSION_REASONS = frozenset({
    SUPPRESSION_REASON_CANNOT_EXECUTE,
    SUPPRESSION_REASON_POLICY_DENIED,
    SUPPRESSION_REASON_ESCALATION_SUPPRESSED,
    SUPPRESSION_REASON_SERVER_DEFAULT_DENIED,
    SUPPRESSION_REASON_CONSTITUTION_INVALID,
    SUPPRESSION_REASON_CONTENT_MODE_REDACTED,
    SUPPRESSION_REASON_UNKNOWN,
})

MANIFEST_VERSION = "0.1"


def generate_manifest(
    constitution: Optional[Constitution],
    mcp_tools: Optional[list[str]] = None,
    surfaces: Optional[list[str]] = None,
    content_mode: Optional[str] = None,
) -> dict[str, Any]:
    """Generate the com.sanna.manifest extension dict for a session.

    Args:
        constitution: The active constitution. May be None (returns a
            fail-closed empty surface with constitution_invalid reasons
            for any provided MCP tools).
        mcp_tools: Optional list of MCP tool names from the gateway's
            downstream catalog. If None, the MCP surface section is
            omitted. If provided, each tool is evaluated via
            evaluate_authority and bucketed into delivered or suppressed.
        surfaces: Optional list of surface names to include. When None
            (default), all surfaces are included. When provided, only
            listed surfaces appear in the returned dict.
        content_mode: Optional content mode. "redacted" applies
            v1.5 Section 2.14 (post-SAN-377) redaction. "hashes_only"
            replaces names with SHA-256 hex via canonical hash_text.

    Returns:
        A dict with keys: version, composition_basis, surfaces. surfaces
        contains optional sub-objects mcp / cli / http depending on what
        the constitution declares + what mcp_tools provides + the surfaces
        filter.
    """
    surfaces_dict: dict[str, Any] = {}

    if mcp_tools is not None:
        surfaces_dict["mcp"] = _generate_mcp_surface(constitution, mcp_tools)

    if constitution is not None and constitution.cli_permissions is not None:
        surfaces_dict["cli"] = _generate_cli_surface(constitution)

    if constitution is not None and constitution.api_permissions is not None:
        surfaces_dict["http"] = _generate_http_surface(constitution)

    # SAN-206: surfaces filter
    if surfaces is not None:
        surfaces_dict = {k: v for k, v in surfaces_dict.items() if k in surfaces}

    # SAN-206: content_mode redaction (per v1.5 Section 2.14 + SAN-377)
    if content_mode == "redacted":
        for surface in surfaces_dict.values():
            _redact_for_redacted_mode(surface)
    elif content_mode == "hashes_only":
        for surface in surfaces_dict.values():
            _redact_for_hashes_only_mode(surface)

    return {
        "version": MANIFEST_VERSION,
        "composition_basis": "static",
        "surfaces": surfaces_dict,
    }


def _generate_mcp_surface(
    constitution: Optional[Constitution],
    mcp_tools: list[str],
) -> dict[str, Any]:
    """Build the MCP surface sub-object."""
    delivered: list[str] = []
    suppressed: list[str] = []
    suppression_reasons: dict[str, str] = {}

    if constitution is None or constitution.authority_boundaries is None:
        for name in sorted(mcp_tools):
            suppressed.append(name)
            suppression_reasons[name] = SUPPRESSION_REASON_CONSTITUTION_INVALID
        return {
            "tools_delivered": [],
            "tools_suppressed": suppressed,
            "suppression_reasons": suppression_reasons,
        }

    ab = constitution.authority_boundaries
    escalation_visibility = ab.escalation_visibility

    for name in sorted(mcp_tools):
        decision = evaluate_authority(name, {}, constitution)
        if decision.decision == "halt":
            suppressed.append(name)
            suppression_reasons[name] = SUPPRESSION_REASON_CANNOT_EXECUTE
        elif decision.decision == "escalate":
            if escalation_visibility == "suppressed":
                suppressed.append(name)
                suppression_reasons[name] = SUPPRESSION_REASON_ESCALATION_SUPPRESSED
            else:
                delivered.append(name)
        else:
            delivered.append(name)

    return {
        "tools_delivered": delivered,
        "tools_suppressed": suppressed,
        "suppression_reasons": suppression_reasons,
    }


def _generate_cli_surface(constitution: Constitution) -> dict[str, Any]:
    """Build the CLI surface sub-object from constitution.cli_permissions."""
    cp = constitution.cli_permissions
    if cp is None:
        return {
            "patterns_delivered": [],
            "patterns_suppressed": [],
            "suppression_reasons": {},
            "mode": "strict",
        }

    ab = constitution.authority_boundaries
    escalation_visibility = ab.escalation_visibility if ab is not None else "visible"

    delivered: list[str] = []
    suppressed: list[str] = []
    suppression_reasons: dict[str, str] = {}
    for cmd in cp.commands:
        pattern = cmd.binary
        authority = getattr(cmd, "authority", "can_execute")
        if authority == "cannot_execute":
            suppressed.append(pattern)
            suppression_reasons[pattern] = SUPPRESSION_REASON_CANNOT_EXECUTE
        elif authority == "must_escalate":
            if escalation_visibility == "suppressed":
                suppressed.append(pattern)
                suppression_reasons[pattern] = SUPPRESSION_REASON_ESCALATION_SUPPRESSED
            else:
                delivered.append(pattern)
        else:
            delivered.append(pattern)

    return {
        "patterns_delivered": sorted(delivered),
        "patterns_suppressed": sorted(suppressed),
        "suppression_reasons": suppression_reasons,
        "mode": cp.mode,
    }


def _generate_http_surface(constitution: Constitution) -> dict[str, Any]:
    """Build the HTTP surface sub-object from constitution.api_permissions."""
    ap = constitution.api_permissions
    if ap is None:
        return {
            "patterns_delivered": [],
            "patterns_suppressed": [],
            "suppression_reasons": {},
            "mode": "strict",
        }

    ab = constitution.authority_boundaries
    escalation_visibility = ab.escalation_visibility if ab is not None else "visible"

    delivered: list[str] = []
    suppressed: list[str] = []
    suppression_reasons: dict[str, str] = {}
    for ep in ap.endpoints:
        pattern = ep.url_pattern
        authority = getattr(ep, "authority", "can_execute")
        if authority == "cannot_execute":
            suppressed.append(pattern)
            suppression_reasons[pattern] = SUPPRESSION_REASON_CANNOT_EXECUTE
        elif authority == "must_escalate":
            if escalation_visibility == "suppressed":
                suppressed.append(pattern)
                suppression_reasons[pattern] = SUPPRESSION_REASON_ESCALATION_SUPPRESSED
            else:
                delivered.append(pattern)
        else:
            delivered.append(pattern)

    return {
        "patterns_delivered": sorted(delivered),
        "patterns_suppressed": sorted(suppressed),
        "suppression_reasons": suppression_reasons,
        "mode": ap.mode,
    }


def _redact_for_redacted_mode(surface: dict[str, Any]) -> None:
    """v1.5 Section 2.14 + SAN-377 content_mode=redacted transform.

    Order critical for cross-SDK reproducibility: capture aggregate BEFORE
    redaction, then redact, then drop suppression_reasons and add aggregate.
    The suppressed list (already sorted) drives aggregate index alignment.
    """
    suppressed_list = (
        surface.get("tools_suppressed") or surface.get("patterns_suppressed") or []
    )
    sup_reasons_dict = surface.get("suppression_reasons", {})
    aggregate = [sup_reasons_dict.get(name, "unknown") for name in suppressed_list]

    for list_field in (
        "tools_delivered", "tools_suppressed",
        "patterns_delivered", "patterns_suppressed",
    ):
        if list_field in surface:
            count = len(surface[list_field])
            surface[list_field] = ["<redacted>"] * count

    surface.pop("suppression_reasons", None)
    if aggregate:
        surface["aggregate_suppression_reasons"] = aggregate


def _redact_for_hashes_only_mode(surface: dict[str, Any]) -> None:
    """v1.5 Section 2.14 + SAN-377 content_mode=hashes_only transform.

    Names hashed via canonical hash_text helper. Lists re-sorted by hash
    alphabetically after hashing. suppression_reasons keys also hashed;
    values remain cleartext.
    """
    from .hashing import hash_text

    for list_field in (
        "tools_delivered", "tools_suppressed",
        "patterns_delivered", "patterns_suppressed",
    ):
        if list_field in surface:
            hashed = [hash_text(name) for name in surface[list_field]]
            surface[list_field] = sorted(hashed)

    sup_reasons = surface.get("suppression_reasons")
    if sup_reasons:
        surface["suppression_reasons"] = {
            hash_text(k): v for k, v in sup_reasons.items()
        }
