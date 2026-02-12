"""
Sanna middleware — runtime enforcement decorator for AI agent pipelines.

@sanna_observe wraps agent functions, captures I/O, runs C1-C5 coherence
checks after execution, and enforces policy (halt/warn/log). Every execution
produces a reasoning receipt.

TODO: async support (Phase 2)
TODO: mid-execution checkpoints (Phase 2)
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
    """Raised when reasoning checks fail and on_violation='halt'."""

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
    """
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    all_args = dict(bound.arguments)

    context = ""
    query = ""

    # --- Explicit mapping ---
    if context_param and context_param in all_args:
        context = _to_str(all_args[context_param])
    if query_param and query_param in all_args:
        query = _to_str(all_args[query_param])

    # --- Convention-based ---
    if not context:
        for name in _CONTEXT_PARAM_NAMES:
            if name in all_args:
                context = _to_str(all_args[name])
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
                        context = _to_str(single_val[name])
                        break
            if not query:
                for name in _QUERY_PARAM_NAMES:
                    if name in single_val:
                        query = _to_str(single_val[name])
                        break

    return {"context": context, "query": query}


def _to_str(val: Any) -> str:
    """Coerce a value to string for check inputs."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        return "\n".join(str(item) for item in val)
    return str(val)


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
# RECEIPT GENERATION WITH CHECK SUBSET
# =============================================================================

def _generate_receipt_with_checks(
    trace_data: dict,
    checks: Sequence[str],
    extensions: Optional[dict] = None,
    constitution: Optional[ConstitutionProvenance] = None,
    halt_event: Optional[HaltEvent] = None,
    constitution_ref_override: Optional[dict] = None,
) -> dict:
    """
    Generate a receipt, optionally running only a subset of checks.

    If checks is the full set ["C1"..."C5"], delegates entirely to
    generate_receipt(). Otherwise runs only the requested checks and
    assembles the receipt manually (reusing the same hashing/fingerprint
    logic).

    Args:
        constitution_ref_override: Rich dict to use directly as constitution_ref
            in both the fingerprint and the receipt body. Takes precedence over
            the ``constitution`` parameter.
    """
    all_check_ids = sorted(_CHECK_FUNCTIONS.keys())
    requested = sorted(checks)

    if requested == all_check_ids:
        # Full check set — use existing pipeline directly
        receipt_obj = generate_receipt(
            trace_data,
            constitution=constitution,
            halt_event=halt_event,
            constitution_ref_override=constitution_ref_override,
        )
        receipt_dict = asdict(receipt_obj)
        if extensions:
            receipt_dict["extensions"] = extensions
        return receipt_dict

    # Subset of checks — run only the requested ones
    from .receipt import (
        select_final_answer,
        extract_context,
        extract_query,
        FinalAnswerProvenance,
    )

    final_answer, answer_provenance = select_final_answer(trace_data)
    context = extract_context(trace_data)
    query_text = extract_query(trace_data)

    check_results: List[CheckResult] = []
    for cid in requested:
        fn = _CHECK_FUNCTIONS.get(cid)
        if fn:
            check_results.append(fn(context, final_answer))

    passed = sum(1 for c in check_results if c.passed)
    failed = len(check_results) - passed

    critical_fails = sum(1 for c in check_results if not c.passed and c.severity == "critical")
    warning_fails = sum(1 for c in check_results if not c.passed and c.severity == "warning")

    if critical_fails > 0:
        status = "FAIL"
    elif warning_fails > 0:
        status = "WARN"
    else:
        status = "PASS"

    inputs = {"query": query_text if query_text else None, "context": context if context else None}
    outputs = {"response": final_answer if final_answer else None}

    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)

    # Resolve constitution_ref: override takes precedence over legacy dataclass
    if constitution_ref_override is not None:
        constitution_dict = constitution_ref_override
    else:
        constitution_dict = asdict(constitution) if constitution else None

    halt_event_dict = asdict(halt_event) if halt_event else None
    constitution_hash_val = hash_obj(constitution_dict) if constitution_dict else ""
    halt_hash_val = hash_obj(halt_event_dict) if halt_event_dict else ""

    checks_data = [{"check_id": c.check_id, "passed": c.passed, "severity": c.severity, "evidence": c.evidence} for c in check_results]
    checks_hash = hash_obj(checks_data)
    fingerprint_input = f"{trace_data['trace_id']}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash_val}|{halt_hash_val}"
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
        "checks": [asdict(c) for c in check_results],
        "checks_passed": passed,
        "checks_failed": failed,
        "coherence_status": status,
        "constitution_ref": constitution_dict,
        "halt_event": halt_event_dict,
    }

    if extensions:
        receipt_dict["extensions"] = extensions

    return receipt_dict


# =============================================================================
# ENFORCEMENT
# =============================================================================

def _should_halt(receipt: dict, halt_on: Sequence[str]) -> bool:
    """Determine if any failed check has a severity in halt_on."""
    for check in receipt.get("checks", []):
        if not check.get("passed") and check.get("severity") in halt_on:
            return True
    return False


# =============================================================================
# THE DECORATOR
# =============================================================================

def sanna_observe(
    _func=None,
    *,
    on_violation: str = "halt",
    checks: Optional[List[str]] = None,
    halt_on: Optional[List[str]] = None,
    receipt_dir: Optional[str] = None,
    context_param: Optional[str] = None,
    query_param: Optional[str] = None,
    constitution: Optional[ConstitutionProvenance] = None,
    constitution_path: Optional[str] = None,
):
    """
    Decorator that wraps an agent function with Sanna coherence checks.

    After the wrapped function executes, builds a trace from captured I/O,
    runs the configured checks, generates a receipt, and enforces the
    violation policy.

    Args:
        on_violation: "halt" | "warn" | "log"
            - "halt": raise SannaHaltError if checks fail at halt severity
            - "warn": return SannaResult, emit warnings.warn
            - "log": return SannaResult, log only
        checks: Which checks to run, e.g. ["C1", "C3"]. Default: all.
        halt_on: Severity levels that trigger halt. Default: ["critical"].
        receipt_dir: Directory to write receipt JSON. None to skip.
        context_param: Explicit name of the context parameter.
        query_param: Explicit name of the query parameter.
        constitution: Optional ConstitutionProvenance for governance tracking.
        constitution_path: Path to a Sanna constitution YAML/JSON file.
            Loaded and signed at decoration time; the rich constitution_ref
            dict flows through the entire pipeline (fingerprint + receipt body).
            Takes precedence over the ``constitution`` parameter.

    Returns:
        SannaResult wrapping the function output and receipt, or raises
        SannaHaltError if policy dictates halt.
    """
    if checks is None:
        checks = list(_CHECK_FUNCTIONS.keys())
    if halt_on is None:
        halt_on = ["critical"]

    if on_violation not in ("halt", "warn", "log"):
        raise ValueError(f"on_violation must be 'halt', 'warn', or 'log', got {on_violation!r}")

    # Decoration-time constitution loading: load, sign, build receipt ref once
    constitution_ref_override = None
    if constitution_path is not None:
        from .constitution import load_constitution, sign_constitution, constitution_to_receipt_ref
        loaded = load_constitution(constitution_path)
        if not loaded.document_hash:
            loaded = sign_constitution(loaded)
        constitution_ref_override = constitution_to_receipt_ref(loaded)
        logger.info(
            "Constitution loaded from %s (hash=%s)",
            constitution_path,
            loaded.document_hash[:16],
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

            # 4. Build trace and generate receipt (without halt_event yet)
            trace_data = _build_trace_data(
                trace_id=trace_id,
                query=resolved["query"],
                context=resolved["context"],
                output=output_str,
            )

            enforcement_decision = "PASSED"

            extensions = {
                "middleware": {
                    "decorator": "@sanna_observe",
                    "on_violation": on_violation,
                    "enforcement_decision": enforcement_decision,  # updated below
                    "function_name": func.__name__,
                    "execution_time_ms": execution_time_ms,
                }
            }

            # First pass: generate receipt without halt_event to determine enforcement
            receipt = _generate_receipt_with_checks(
                trace_data, checks, extensions=extensions,
                constitution=constitution,
                constitution_ref_override=constitution_ref_override,
            )

            # 5. Enforcement decision
            halt_event_obj = None
            if receipt["coherence_status"] != "PASS":
                if on_violation == "halt" and _should_halt(receipt, halt_on):
                    enforcement_decision = "HALTED"
                    failed_check_ids = [
                        c["check_id"] for c in receipt["checks"]
                        if not c["passed"] and c["severity"] in halt_on
                    ]
                    halt_event_obj = HaltEvent(
                        halted=True,
                        reason=f"Coherence check failed: {', '.join(failed_check_ids)}",
                        failed_checks=failed_check_ids,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        enforcement_mode=on_violation,
                    )
                elif on_violation == "warn":
                    enforcement_decision = "WARNED"
                else:
                    enforcement_decision = "LOGGED"
            else:
                enforcement_decision = "PASSED"

            # If we created a halt_event, regenerate receipt with it included
            if halt_event_obj is not None:
                receipt = _generate_receipt_with_checks(
                    trace_data, checks, extensions=extensions,
                    constitution=constitution,
                    halt_event=halt_event_obj,
                    constitution_ref_override=constitution_ref_override,
                )

            # Update the extensions with final decision
            receipt["extensions"]["middleware"]["enforcement_decision"] = enforcement_decision

            # 6. Write receipt to disk if configured
            if receipt_dir is not None:
                _write_receipt(receipt, receipt_dir)

            # 7. Apply policy
            if enforcement_decision == "HALTED":
                failed_checks = [
                    c for c in receipt["checks"]
                    if not c["passed"] and c["severity"] in halt_on
                ]
                names = ", ".join(f"{c['check_id']} ({c['name']})" for c in failed_checks)
                raise SannaHaltError(
                    f"Sanna coherence check failed: {names}",
                    receipt=receipt,
                )

            if enforcement_decision == "WARNED":
                failed_checks = [c for c in receipt["checks"] if not c["passed"]]
                names = ", ".join(f"{c['check_id']} ({c['name']})" for c in failed_checks)
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
