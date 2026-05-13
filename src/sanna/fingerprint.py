"""Canonical fingerprint construction for Sanna receipts (SAN-524).

Single source of truth for the cv-dispatched fingerprint formula.
All emission sites (receipt.py, middleware.py) and the verifier
reconstruction (verify.py:_verify_fingerprint_v013) delegate to
this module.

Cross-SDK alignment: sanna-ts has the equivalent computeFingerprintInput
and computeFingerprints in packages/core/src/receipt.ts. Maintaining
identical semantics across SDKs is the load-bearing byte-parity claim.

Public API:
    compute_fingerprint_input(receipt) -> str | None
    compute_fingerprints(receipt)      -> FingerprintPair | None
    FingerprintPair  (NamedTuple of receipt_fingerprint + full_fingerprint)

Returns None when the receipt is missing cv-specific required fields
(e.g., cv=10 without agent_identity). Verifier path translates None to
(False, "", ""). Emission paths assert non-None or fail-loud, per
each site's existing contract.
"""

from typing import NamedTuple, Optional

from .hashing import hash_text, hash_obj, EMPTY_HASH


class FingerprintPair(NamedTuple):
    """Pair of (truncated, full) fingerprint hashes.

    receipt_fingerprint: hash_text(input, truncate=16)
    full_fingerprint:    hash_text(input)
    """
    receipt_fingerprint: str
    full_fingerprint: str


def compute_fingerprint_input(receipt: dict) -> Optional[str]:
    """Build the cv-dispatched pipe-delimited fingerprint input string.

    Returns None if the receipt is missing required cv-specific fields:
        cv >= 10: requires tool_name, enforcement_surface, invariants_scope, agent_identity
        cv >=  9: requires tool_name, enforcement_surface, invariants_scope
        cv >=  8: requires enforcement_surface, invariants_scope
        cv >=  6: (no extra required fields beyond cv<=5 set)
        cv <=  5: legacy 12-field formula

    Field count by cv (spec section 4):
        cv >= 10: 21 fields (spec v1.5)
        cv >=  9: 20 fields (spec v1.4)
        cv >=  8: 16 fields (spec v1.3)
        cv >=  6: 14 fields (spec v1.0-v1.1)
        cv <=  5: 12 fields (legacy)
    """
    correlation_id = receipt.get("correlation_id", "")
    context_hash = receipt.get("context_hash", "")
    output_hash = receipt.get("output_hash", "")
    checks_version = receipt.get("checks_version", "")

    checks = receipt.get("checks", [])
    has_enforcement_fields = any(c.get("triggered_by") is not None for c in checks)
    if has_enforcement_fields:
        checks_data = [
            {
                "check_id": c.get("check_id", ""),
                "passed": c.get("passed"),
                "severity": c.get("severity", ""),
                "evidence": c.get("evidence"),
                "triggered_by": c.get("triggered_by"),
                "enforcement_level": c.get("enforcement_level"),
                "check_impl": c.get("check_impl"),
                "replayable": c.get("replayable"),
            }
            for c in checks
        ]
    else:
        checks_data = [
            {
                "check_id": c.get("check_id", ""),
                "passed": c.get("passed"),
                "severity": c.get("severity", ""),
                "evidence": c.get("evidence"),
            }
            for c in checks
        ]
    checks_hash = hash_obj(checks_data) if checks_data else EMPTY_HASH

    constitution_ref = receipt.get("constitution_ref")
    if constitution_ref:
        _cref = {k: v for k, v in constitution_ref.items() if k != "constitution_approval"}
        constitution_hash = hash_obj(_cref)
    else:
        constitution_hash = EMPTY_HASH

    enforcement = receipt.get("enforcement")
    enforcement_hash = hash_obj(enforcement) if enforcement else EMPTY_HASH

    evaluation_coverage = receipt.get("evaluation_coverage")
    coverage_hash = hash_obj(evaluation_coverage) if evaluation_coverage else EMPTY_HASH

    authority_decisions = receipt.get("authority_decisions")
    authority_hash = hash_obj(authority_decisions) if authority_decisions else EMPTY_HASH

    escalation_events = receipt.get("escalation_events")
    escalation_hash = hash_obj(escalation_events) if escalation_events else EMPTY_HASH

    source_trust_evaluations = receipt.get("source_trust_evaluations")
    trust_hash = hash_obj(source_trust_evaluations) if source_trust_evaluations else EMPTY_HASH

    extensions = receipt.get("extensions")
    extensions_hash = hash_obj(extensions) if extensions else EMPTY_HASH

    parent_receipts = receipt.get("parent_receipts")
    parent_receipts_hash = hash_obj(parent_receipts) if parent_receipts is not None else EMPTY_HASH
    workflow_id = receipt.get("workflow_id")
    workflow_id_hash = hash_text(workflow_id) if workflow_id is not None else EMPTY_HASH

    enforcement_surface = receipt.get("enforcement_surface")
    invariants_scope = receipt.get("invariants_scope")

    try:
        cv_int = int(checks_version)
    except (ValueError, TypeError):
        cv_int = 5

    if cv_int >= 10:
        tool_name = receipt.get("tool_name")
        if not tool_name:
            return None
        tool_name_hash = hash_text(tool_name)

        agent_model = receipt.get("agent_model")
        agent_model_hash = hash_text(agent_model) if agent_model else EMPTY_HASH
        agent_model_provider = receipt.get("agent_model_provider")
        agent_model_provider_hash = hash_text(agent_model_provider) if agent_model_provider else EMPTY_HASH
        agent_model_version = receipt.get("agent_model_version")
        agent_model_version_hash = hash_text(agent_model_version) if agent_model_version else EMPTY_HASH

        if not enforcement_surface or not invariants_scope:
            return None
        enforcement_surface_hash = hash_text(enforcement_surface)
        invariants_scope_hash = hash_text(invariants_scope)

        agent_identity = receipt.get("agent_identity")
        if not agent_identity:
            return None
        agent_identity_hash = hash_obj(agent_identity)

        return (
            f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|"
            f"{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|"
            f"{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}|"
            f"{parent_receipts_hash}|{workflow_id_hash}|"
            f"{enforcement_surface_hash}|{invariants_scope_hash}|"
            f"{tool_name_hash}|{agent_model_hash}|"
            f"{agent_model_provider_hash}|{agent_model_version_hash}|"
            f"{agent_identity_hash}"
        )
    elif cv_int >= 9:
        tool_name = receipt.get("tool_name")
        if not tool_name:
            return None
        tool_name_hash = hash_text(tool_name)

        agent_model = receipt.get("agent_model")
        agent_model_hash = hash_text(agent_model) if agent_model else EMPTY_HASH
        agent_model_provider = receipt.get("agent_model_provider")
        agent_model_provider_hash = hash_text(agent_model_provider) if agent_model_provider else EMPTY_HASH
        agent_model_version = receipt.get("agent_model_version")
        agent_model_version_hash = hash_text(agent_model_version) if agent_model_version else EMPTY_HASH

        if not enforcement_surface or not invariants_scope:
            return None
        enforcement_surface_hash = hash_text(enforcement_surface)
        invariants_scope_hash = hash_text(invariants_scope)

        return (
            f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|"
            f"{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|"
            f"{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}|"
            f"{parent_receipts_hash}|{workflow_id_hash}|"
            f"{enforcement_surface_hash}|{invariants_scope_hash}|"
            f"{tool_name_hash}|{agent_model_hash}|"
            f"{agent_model_provider_hash}|{agent_model_version_hash}"
        )
    elif cv_int >= 8:
        if not enforcement_surface or not invariants_scope:
            return None
        enforcement_surface_hash = hash_text(enforcement_surface)
        invariants_scope_hash = hash_text(invariants_scope)
        return (
            f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|"
            f"{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|"
            f"{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}|"
            f"{parent_receipts_hash}|{workflow_id_hash}|"
            f"{enforcement_surface_hash}|{invariants_scope_hash}"
        )
    elif cv_int >= 6:
        return (
            f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|"
            f"{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|"
            f"{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}|"
            f"{parent_receipts_hash}|{workflow_id_hash}"
        )
    else:
        return (
            f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}|"
            f"{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|"
            f"{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}"
        )


def compute_fingerprints(receipt: dict) -> Optional[FingerprintPair]:
    """Return FingerprintPair(receipt_fingerprint, full_fingerprint).

    Returns None on missing-required-field cases (mirrors compute_fingerprint_input).
    """
    fp_input = compute_fingerprint_input(receipt)
    if fp_input is None:
        return None
    return FingerprintPair(
        receipt_fingerprint=hash_text(fp_input, truncate=16),
        full_fingerprint=hash_text(fp_input),
    )
