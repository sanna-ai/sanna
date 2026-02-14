"""
Sanna middleware — runtime enforcement decorator for AI agent pipelines.

@sanna_observe wraps agent functions, captures I/O, runs coherence checks
driven by constitution invariants, and enforces policy (halt/warn/log) per
check. Every execution produces a reasoning receipt.

v0.6.0: The constitution is the control plane. Invariants drive which checks
run and at what enforcement level.
"""

import functools
import inspect
import json
import logging
import time
import uuid
import warnings
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence

from .receipt import (
    generate_receipt,
    check_c1_context_contradiction,
    check_c2_unmarked_inference,
    check_c3_false_certainty,
    check_c4_conflict_collapse,
    check_c5_premature_compression,
    CheckResult,
    ConstitutionProvenance,
    HaltEvent,
    SannaReceipt,
    TOOL_VERSION,
    SCHEMA_VERSION,
    CHECKS_VERSION,
    select_final_answer,
    extract_context,
    extract_query,
    FinalAnswerProvenance,
)
from .hashing import hash_text, hash_obj

logger = logging.getLogger("sanna.middleware")

# Check function registry keyed by check ID
_CHECK_FUNCTIONS = {
    "C1": check_c1_context_contradiction,
    "C2": check_c2_unmarked_inference,
    "C3": check_c3_false_certainty,
    "C4": check_c4_conflict_collapse,
    "C5": check_c5_premature_compression,
}

# Parameter names to auto-detect for context and query
_CONTEXT_PARAM_NAMES = {"context", "retrieved_context", "documents", "retrieved_docs"}
_QUERY_PARAM_NAMES = {"query", "prompt", "input", "user_input", "question"}
_OUTPUT_PARAM_NAMES = {"response", "output", "answer", "result"}


# =============================================================================
# PUBLIC TYPES
# =============================================================================

class SannaHaltError(Exception):
    """Raised when reasoning checks fail and enforcement_level='halt'."""

    def __init__(self, message: str, receipt: dict):
        super().__init__(message)
        self.receipt = receipt


class SannaResult:
    """Wrapper around agent output with receipt attached."""

    def __init__(self, output: Any, receipt: dict):
        self.output = output
        self.receipt = receipt

    @property
    def status(self) -> str:
        return self.receipt.get("coherence_status", "UNKNOWN")

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def __repr__(self) -> str:
        return f"SannaResult(status={self.status!r}, output={self.output!r})"


# =============================================================================
# INPUT MAPPING
# =============================================================================

def _resolve_inputs(
    func,
    args: tuple,
    kwargs: dict,
    context_param: Optional[str],
    query_param: Optional[str],
) -> dict:
    """
    Resolve context and query from function arguments.

    Precedence:
    1. Explicit mapping via context_param/query_param
    2. Convention-based parameter name matching
    3. Single dict argument: look for keys inside it

    Returns dict with ``context`` (str), ``query`` (str), and
    ``structured_context`` (list or None).
    """
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    all_args = dict(bound.arguments)

    context = ""
    query = ""
    structured_context = None
    raw_context = None  # preserve raw value for structured extraction

    # --- Explicit mapping ---
    if context_param and context_param in all_args:
        raw_context = all_args[context_param]
        context = _to_str(raw_context)
    if query_param and query_param in all_args:
        query = _to_str(all_args[query_param])

    # --- Convention-based ---
    if not context:
        for name in _CONTEXT_PARAM_NAMES:
            if name in all_args:
                raw_context = all_args[name]
                context = _to_str(raw_context)
                break

    if not query:
        for name in _QUERY_PARAM_NAMES:
            if name in all_args:
                query = _to_str(all_args[name])
                break

    # --- Single dict argument fallback ---
    if (not context or not query) and len(all_args) == 1:
        single_val = next(iter(all_args.values()))
        if isinstance(single_val, dict):
            if not context:
                for name in _CONTEXT_PARAM_NAMES:
                    if name in single_val:
                        raw_context = single_val[name]
                        context = _to_str(raw_context)
                        break
            if not query:
                for name in _QUERY_PARAM_NAMES:
                    if name in single_val:
                        query = _to_str(single_val[name])
                        break

    # Extract structured context if raw value is a list of source-annotated dicts
    if raw_context is not None:
        structured_context = _extract_structured_context(raw_context)

    return {"context": context, "query": query, "structured_context": structured_context}


def _to_str(val: Any) -> str:
    """Coerce a value to string for check inputs.

    When ``val`` is a list of dicts with ``"text"`` keys (structured
    context), extracts the text portions for a clean string representation.
    """
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        parts = []
        for item in val:
            if isinstance(item, dict) and "text" in item:
                parts.append(item["text"])
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(val)


def _extract_structured_context(val: Any) -> Optional[list]:
    """Extract structured context if val is a list of source-annotated dicts.

    Returns the list if every item is a dict with at least a ``"text"`` key.
    Returns None otherwise (including for plain strings).
    """
    if not isinstance(val, list) or not val:
        return None
    if all(isinstance(item, dict) and "text" in item for item in val):
        return val
    return None


# =============================================================================
# TRACE CONSTRUCTION
# =============================================================================

def _build_trace_data(
    *,
    trace_id: str,
    query: str,
    context: str,
    output: str,
) -> dict:
    """
    Build a trace_data dict in the shape generate_receipt() expects.

    Constructs a minimal trace with a retrieval span (for context/query)
    and a trace-level output (for the final answer).
    """
    return {
        "trace_id": trace_id,
        "name": "sanna_observe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input": {"query": query},
        "output": {"final_answer": output},
        "metadata": {},
        "observations": [
            {
                "id": f"obs-retrieval-{trace_id}",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": query},
                "output": {"context": context},
                "metadata": {},
                "start_time": None,
                "end_time": None,
            }
        ],
    }


# =============================================================================
# SOURCE TRUST HELPERS
# =============================================================================

_VALID_TIERS = frozenset({"tier_1", "tier_2", "tier_3", "untrusted", "unclassified"})


def _normalize_tier(tier: str) -> str:
    """Normalize a tier string to a canonical value.

    Handles case insensitivity, underscores/hyphens/spaces, and returns
    ``"unclassified"`` for unrecognized values.
    """
    normalized = tier.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in _VALID_TIERS:
        return normalized
    return "unclassified"


def _resolve_source_tiers(
    structured_context: list,
    trusted_sources,
) -> list:
    """Resolve trust tiers for each source in structured context.

    Looks up each source name in the constitution's ``trusted_sources``
    mapping. Sources not found in any tier default to ``"unclassified"``.

    Returns the structured context list with ``tier`` resolved on each item.
    """
    if trusted_sources is None:
        # No trusted_sources in constitution → use explicit tier or unclassified
        return [
            {**item, "tier": _normalize_tier(item["tier"]) if item.get("tier") else "unclassified"}
            for item in structured_context
        ]

    # Build reverse lookup: source_name → tier
    tier_map: dict[str, str] = {}
    for tier_name in ("tier_1", "tier_2", "tier_3", "untrusted"):
        for source in getattr(trusted_sources, tier_name, []):
            tier_map[source] = tier_name

    resolved = []
    for item in structured_context:
        source_name = item.get("source", "unknown")
        # Explicit tier in the context item takes precedence
        explicit_tier = item.get("tier")
        if explicit_tier:
            tier = _normalize_tier(explicit_tier)
        else:
            tier = tier_map.get(source_name, "unclassified")
        resolved.append({**item, "tier": tier})
    return resolved


def _build_source_trust_evaluations(
    structured_context: list,
) -> list:
    """Build source_trust_evaluations records for the receipt.

    Deduplicates by source name. Each record documents what tier
    a source was classified as during this trace.
    """
    evaluations = []
    seen: set[str] = set()
    timestamp = datetime.now(timezone.utc).isoformat()

    for item in structured_context:
        source_name = item.get("source", "unknown")
        if source_name in seen:
            continue
        seen.add(source_name)

        tier = item.get("tier", "unclassified")
        evaluations.append({
            "source_name": source_name,
            "trust_tier": tier,
            "evaluated_at": timestamp,
            "verification_flag": tier == "tier_2",
            "context_used": tier in ("tier_1", "tier_2", "tier_3"),
        })
    return evaluations


# =============================================================================
# CONSTITUTION-DRIVEN RECEIPT GENERATION
# =============================================================================

def _generate_constitution_receipt(
    trace_data: dict,
    check_configs: list,
    custom_records: list,
    constitution_ref: Optional[dict],
    constitution_version: str,
    extensions: Optional[dict] = None,
    halt_event: Optional[HaltEvent] = None,
    authority_decisions: Optional[list] = None,
    escalation_events: Optional[list] = None,
    source_trust_evaluations: Optional[list] = None,
    structured_context: Optional[list] = None,
) -> dict:
    """Generate a receipt using constitution-driven check configs.

    Runs only the checks specified by check_configs, at their enforcement
    levels, and includes custom invariant records as NOT_CHECKED.
    """
    final_answer, answer_provenance = select_final_answer(trace_data)
    context = extract_context(trace_data)
    query_text = extract_query(trace_data)

    # Run configured checks
    check_results = []
    for cfg in check_configs:
        try:
            # C1 gets structured context for source-aware evaluation
            if structured_context and cfg.check_id == "sanna.context_contradiction":
                result = cfg.check_fn(
                    context, final_answer,
                    enforcement=cfg.enforcement_level,
                    structured_context=structured_context,
                )
            else:
                result = cfg.check_fn(context, final_answer, enforcement=cfg.enforcement_level)
        except Exception as exc:
            if cfg.source == "custom_evaluator":
                check_results.append({
                    "check_id": cfg.check_id,
                    "name": "Custom Invariant",
                    "passed": True,
                    "severity": "info",
                    "evidence": None,
                    "details": f"Evaluator error: {exc}",
                    "triggered_by": cfg.triggered_by,
                    "enforcement_level": cfg.enforcement_level,
                    "constitution_version": constitution_version,
                    "check_impl": cfg.check_impl or None,
                    "replayable": False,
                    "source": "custom_evaluator",
                    "status": "ERRORED",
                })
                continue
            raise

        entry = {
            "check_id": cfg.check_id,
            "name": result.name,
            "passed": result.passed,
            "severity": result.severity,
            "evidence": result.evidence,
            "details": result.details,
            "triggered_by": cfg.triggered_by,
            "enforcement_level": cfg.enforcement_level,
            "constitution_version": constitution_version,
            "check_impl": cfg.check_impl or None,
            "replayable": cfg.source != "custom_evaluator",
        }
        if cfg.source == "custom_evaluator":
            entry["source"] = "custom_evaluator"
        check_results.append(entry)

    # Add custom invariants as NOT_CHECKED
    for custom in custom_records:
        check_results.append({
            "check_id": custom.invariant_id,
            "name": "Custom Invariant",
            "passed": True,  # NOT_CHECKED counts as not-failed
            "severity": "info",
            "evidence": None,
            "details": custom.rule,
            "triggered_by": custom.invariant_id,
            "enforcement_level": custom.enforcement,
            "constitution_version": constitution_version,
            "status": custom.status,
            "reason": custom.reason,
            "check_impl": None,
            "replayable": False,
        })

    # Count pass/fail (NOT_CHECKED and ERRORED don't count as failures)
    _NON_EVALUATED = ("NOT_CHECKED", "ERRORED")
    standard_checks = [c for c in check_results if c.get("status") not in _NON_EVALUATED]
    not_evaluated = [c for c in check_results if c.get("status") in _NON_EVALUATED]
    passed = sum(1 for c in standard_checks if c["passed"])
    failed = len(standard_checks) - passed

    # Determine status from standard checks only
    critical_fails = sum(1 for c in standard_checks if not c["passed"] and c["severity"] == "critical")
    warning_fails = sum(1 for c in standard_checks if not c["passed"] and c["severity"] == "warning")

    if critical_fails > 0:
        status = "FAIL"
    elif warning_fails > 0:
        status = "WARN"
    elif not_evaluated:
        status = "PARTIAL"
    else:
        status = "PASS"

    # Build evaluation_coverage
    total_invariants = len(check_results)
    evaluated_count = len(standard_checks)
    not_checked_count = len(not_evaluated)
    coverage_basis_points = (evaluated_count * 10000) // total_invariants if total_invariants > 0 else 10000
    evaluation_coverage = {
        "total_invariants": total_invariants,
        "evaluated": evaluated_count,
        "not_checked": not_checked_count,
        "coverage_basis_points": coverage_basis_points,
    }

    inputs = {"query": query_text if query_text else None, "context": context if context else None}
    outputs = {"response": final_answer if final_answer else None}

    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)

    constitution_hash_val = hash_obj(constitution_ref) if constitution_ref else ""
    halt_event_dict = asdict(halt_event) if halt_event else None
    halt_hash_val = hash_obj(halt_event_dict) if halt_event_dict else ""

    # Build fingerprint from check results (include all enforcement and impl fields)
    checks_fingerprint_data = [
        {
            "check_id": c["check_id"],
            "passed": c["passed"],
            "severity": c["severity"],
            "evidence": c["evidence"],
            "triggered_by": c.get("triggered_by"),
            "enforcement_level": c.get("enforcement_level"),
            "check_impl": c.get("check_impl"),
            "replayable": c.get("replayable"),
        }
        for c in check_results
    ]
    checks_hash = hash_obj(checks_fingerprint_data)
    coverage_hash = hash_obj(evaluation_coverage)
    fingerprint_input = f"{trace_data['trace_id']}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash_val}|{halt_hash_val}|{coverage_hash}"

    # v0.7.0: include authority sections in fingerprint when present
    if authority_decisions:
        fingerprint_input += f"|{hash_obj(authority_decisions)}"
    if escalation_events:
        fingerprint_input += f"|{hash_obj(escalation_events)}"
    if source_trust_evaluations:
        fingerprint_input += f"|{hash_obj(source_trust_evaluations)}"

    # v0.7.0: include extensions in fingerprint when non-empty
    if extensions:
        fingerprint_input += f"|{hash_obj(extensions)}"

    receipt_fingerprint = hash_text(fingerprint_input)

    receipt_dict = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "checks_version": CHECKS_VERSION,
        "receipt_id": hash_text(f"{trace_data['trace_id']}{datetime.now(timezone.utc).isoformat()}"),
        "receipt_fingerprint": receipt_fingerprint,
        "trace_id": trace_data["trace_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": context_hash,
        "output_hash": output_hash,
        "final_answer_provenance": asdict(answer_provenance),
        "checks": check_results,
        "checks_passed": passed,
        "checks_failed": failed,
        "coherence_status": status,
        "evaluation_coverage": evaluation_coverage,
        "constitution_ref": constitution_ref,
        "halt_event": halt_event_dict,
    }

    # v0.7.0: authority enforcement sections (only included when present)
    if authority_decisions:
        receipt_dict["authority_decisions"] = authority_decisions
    if escalation_events:
        receipt_dict["escalation_events"] = escalation_events
    if source_trust_evaluations:
        receipt_dict["source_trust_evaluations"] = source_trust_evaluations

    receipt_dict["extensions"] = extensions if extensions else {}

    return receipt_dict


def _generate_no_invariants_receipt(
    trace_data: dict,
    constitution_ref: Optional[dict],
    extensions: Optional[dict] = None,
) -> dict:
    """Generate a receipt for a constitution with no invariants.

    No checks run. The receipt documents that no invariants were defined.
    """
    final_answer, answer_provenance = select_final_answer(trace_data)
    context = extract_context(trace_data)
    query_text = extract_query(trace_data)

    inputs = {"query": query_text if query_text else None, "context": context if context else None}
    outputs = {"response": final_answer if final_answer else None}

    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)

    constitution_hash_val = hash_obj(constitution_ref) if constitution_ref else ""

    checks_hash = hash_obj([])
    fingerprint_input = f"{trace_data['trace_id']}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash_val}|"

    # v0.7.0: include extensions in fingerprint when non-empty
    if extensions:
        fingerprint_input += f"|{hash_obj(extensions)}"

    receipt_fingerprint = hash_text(fingerprint_input)

    receipt_dict = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "checks_version": CHECKS_VERSION,
        "receipt_id": hash_text(f"{trace_data['trace_id']}{datetime.now(timezone.utc).isoformat()}"),
        "receipt_fingerprint": receipt_fingerprint,
        "trace_id": trace_data["trace_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": context_hash,
        "output_hash": output_hash,
        "final_answer_provenance": asdict(answer_provenance),
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "coherence_status": "PASS",
        "constitution_ref": constitution_ref,
        "halt_event": None,
    }

    receipt_dict["extensions"] = extensions if extensions else {}

    return receipt_dict


# =============================================================================
# FILE OUTPUT
# =============================================================================

def _write_receipt(receipt: dict, receipt_dir: str) -> Path:
    """Write receipt JSON to the configured directory."""
    dir_path = Path(receipt_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    filename = f"{receipt['receipt_id']}_{receipt['trace_id']}.json"
    filepath = dir_path / filename

    with open(filepath, "w") as f:
        json.dump(receipt, f, indent=2)

    logger.debug("Receipt written to %s", filepath)
    return filepath


# =============================================================================
# THE DECORATOR
# =============================================================================

def sanna_observe(
    _func=None,
    *,
    receipt_dir: Optional[str] = None,
    store=None,
    context_param: Optional[str] = None,
    query_param: Optional[str] = None,
    constitution_path: Optional[str] = None,
    private_key_path: Optional[str] = None,
    strict: bool = True,
    # Legacy parameters — ignored when constitution has invariants
    on_violation: str = "halt",
    checks: Optional[List[str]] = None,
    halt_on: Optional[List[str]] = None,
    constitution: Optional[ConstitutionProvenance] = None,
):
    """
    Decorator that wraps an agent function with Sanna coherence checks.

    v0.6.0: The constitution is the control plane. When a constitution with
    invariants is provided, the invariants drive which checks run and at what
    enforcement level. Each check enforces independently based on its invariant.

    Args:
        constitution_path: Path to a Sanna constitution YAML/JSON file.
            This is the primary way to configure checks. The constitution's
            invariants drive which checks run and how they enforce.
        receipt_dir: Directory to write receipt JSON. None to skip.
        store: Optional ReceiptStore instance or db_path string. When
            provided, receipts are auto-saved after generation. Store
            failures are logged but never break receipt generation.
        context_param: Explicit name of the context parameter.
        query_param: Explicit name of the query parameter.
        strict: If True (default), validate constitution against JSON schema
            on load. Catches typos like ``invariant:`` instead of ``invariants:``.
        on_violation: Legacy. Used when no constitution invariants are present.
        checks: Legacy. Used when no constitution invariants are present.
        halt_on: Legacy. Used when no constitution invariants are present.
        constitution: Legacy ConstitutionProvenance for governance tracking.

    Returns:
        SannaResult wrapping the function output and receipt, or raises
        SannaHaltError if policy dictates halt.
    """
    if on_violation not in ("halt", "warn", "log"):
        raise ValueError(f"on_violation must be 'halt', 'warn', or 'log', got {on_violation!r}")

    # Resolve store at decoration time
    _store_instance = None
    if store is not None:
        if isinstance(store, str):
            from .store import ReceiptStore as _ReceiptStore
            _store_instance = _ReceiptStore(store)
        else:
            _store_instance = store

    # Decoration-time constitution loading
    loaded_constitution = None
    constitution_ref_override = None
    check_configs = None
    custom_records = None

    if constitution_path is not None:
        from .constitution import load_constitution as _load_constitution, constitution_to_receipt_ref, SannaConstitutionError
        from .enforcement import configure_checks

        loaded_constitution = _load_constitution(constitution_path, validate=strict)
        if not loaded_constitution.policy_hash:
            raise SannaConstitutionError(
                f"Constitution is not signed: {constitution_path}. "
                f"Run: sanna-sign-constitution {constitution_path}"
            )
        constitution_ref_override = constitution_to_receipt_ref(loaded_constitution)

        # Configure checks from invariants
        check_configs, custom_records = configure_checks(loaded_constitution)

        logger.info(
            "Constitution loaded from %s (hash=%s, invariants=%d, checks=%d)",
            constitution_path,
            loaded_constitution.policy_hash[:16],
            len(loaded_constitution.invariants),
            len(check_configs),
        )

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            trace_id = f"sanna-{uuid.uuid4().hex[:12]}"

            # 1. Capture inputs
            resolved = _resolve_inputs(func, args, kwargs, context_param, query_param)

            # 2. Execute the wrapped function
            start_ms = time.monotonic_ns() // 1_000_000
            result = func(*args, **kwargs)
            end_ms = time.monotonic_ns() // 1_000_000
            execution_time_ms = end_ms - start_ms

            # 3. Capture output
            output_str = _to_str(result)

            # 4. Build trace
            trace_data = _build_trace_data(
                trace_id=trace_id,
                query=resolved["query"],
                context=resolved["context"],
                output=output_str,
            )

            enforcement_decision = "PASSED"

            # NOTE: Extensions include middleware runtime metadata (execution_time_ms,
            # decorator name, etc.) which makes fingerprints execution-specific.
            # This is intentional: the fingerprint captures the complete execution
            # artifact, not just reasoning content. For content-only fingerprinting,
            # see receipt modes planned for v0.8.0.
            extensions = {
                "middleware": {
                    "decorator": "@sanna_observe",
                    "on_violation": on_violation,
                    "enforcement_decision": enforcement_decision,
                    "function_name": func.__name__,
                    "execution_time_ms": execution_time_ms,
                }
            }

            # 4b. Resolve structured context and source tiers
            raw_structured = resolved.get("structured_context")
            resolved_structured = None
            source_trust_evals = None
            if raw_structured and loaded_constitution:
                resolved_structured = _resolve_source_tiers(
                    raw_structured,
                    loaded_constitution.trusted_sources,
                )
                source_trust_evals = _build_source_trust_evaluations(resolved_structured)

            # 5. Generate receipt — constitution-driven or legacy
            if check_configs is not None:
                # Constitution-driven: invariants control everything
                constitution_version = loaded_constitution.schema_version if loaded_constitution else ""

                if not check_configs and not custom_records:
                    # No invariants defined — no checks run
                    receipt = _generate_no_invariants_receipt(
                        trace_data,
                        constitution_ref=constitution_ref_override,
                        extensions=extensions,
                    )
                else:
                    # First pass: generate with tentative "PASSED" to analyze checks
                    receipt = _generate_constitution_receipt(
                        trace_data,
                        check_configs=check_configs,
                        custom_records=custom_records,
                        constitution_ref=constitution_ref_override,
                        constitution_version=constitution_version,
                        extensions=extensions,
                        source_trust_evaluations=source_trust_evals,
                        structured_context=resolved_structured,
                    )

                    # Per-check enforcement: determine what to do
                    halt_checks = []
                    warn_checks = []
                    log_checks = []

                    for check in receipt.get("checks", []):
                        if check.get("status") == "NOT_CHECKED":
                            continue
                        if not check.get("passed"):
                            level = check.get("enforcement_level", "log")
                            if level == "halt":
                                halt_checks.append(check)
                            elif level == "warn":
                                warn_checks.append(check)
                            else:
                                log_checks.append(check)

                    if halt_checks:
                        enforcement_decision = "HALTED"
                    elif warn_checks:
                        enforcement_decision = "WARNED"
                    elif log_checks:
                        enforcement_decision = "LOGGED"
                    else:
                        enforcement_decision = "PASSED"

                    # Regenerate with final enforcement_decision in extensions
                    # (extensions are fingerprinted, so they must be final before generation)
                    if enforcement_decision != "PASSED":
                        extensions["middleware"]["enforcement_decision"] = enforcement_decision

                        halt_event_obj = None
                        if enforcement_decision == "HALTED":
                            failed_ids = [c["check_id"] for c in halt_checks]
                            halt_event_obj = HaltEvent(
                                halted=True,
                                reason=f"Coherence check failed: {', '.join(failed_ids)}",
                                failed_checks=failed_ids,
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                enforcement_mode="halt",
                            )

                        receipt = _generate_constitution_receipt(
                            trace_data,
                            check_configs=check_configs,
                            custom_records=custom_records,
                            constitution_ref=constitution_ref_override,
                            constitution_version=constitution_version,
                            extensions=extensions,
                            halt_event=halt_event_obj,
                            source_trust_evaluations=source_trust_evals,
                            structured_context=resolved_structured,
                        )

            else:
                # No constitution path — run with no checks, document in receipt
                receipt = _generate_no_invariants_receipt(
                    trace_data,
                    constitution_ref=asdict(constitution) if constitution else None,
                    extensions=extensions,
                )
                enforcement_decision = "PASSED"

            # 5b. Sign receipt if private key provided
            if private_key_path is not None:
                from .crypto import sign_receipt as _sign_receipt
                receipt = _sign_receipt(receipt, private_key_path)

            # 6. Write receipt to disk if configured
            if receipt_dir is not None:
                _write_receipt(receipt, receipt_dir)

            # 6b. Save to store if configured
            if _store_instance is not None:
                try:
                    _store_instance.save(receipt)
                except Exception:
                    logger.warning("Failed to save receipt to store", exc_info=True)

            # 7. Apply enforcement
            if enforcement_decision == "HALTED":
                failed = [c for c in receipt["checks"] if not c.get("passed") and c.get("enforcement_level") == "halt"]
                names = ", ".join(f"{c['check_id']} ({c['name']})" for c in failed)
                raise SannaHaltError(
                    f"Sanna coherence check failed: {names}",
                    receipt=receipt,
                )

            if enforcement_decision == "WARNED":
                warned = [c for c in receipt["checks"] if not c.get("passed") and c.get("enforcement_level") == "warn"]
                names = ", ".join(f"{c['check_id']} ({c['name']})" for c in warned)
                warnings.warn(
                    f"Sanna coherence warning: {names} — status={receipt['coherence_status']}",
                    stacklevel=2,
                )

            return SannaResult(output=result, receipt=receipt)

        return wrapper

    # Support both @sanna_observe and @sanna_observe(...)
    if _func is not None:
        return decorator(_func)
    return decorator
