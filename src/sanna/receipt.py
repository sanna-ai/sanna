"""
Sanna Receipt generation — C1-C5 coherence checks and receipt assembly.

Renamed from c3m_receipt. Original implementations preserved.
"""

import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Any, List, Tuple

from .hashing import hash_text, hash_obj, EMPTY_HASH


# =============================================================================
# VERSION CONSTANTS
# =============================================================================

from .version import __version__ as TOOL_VERSION  # single source of truth
SPEC_VERSION = "1.0"
CHECKS_VERSION = "5"  # v0.13.0: schema migration, fail_closed default, Sanna Canonical JSON


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CheckResult:
    """Result of a single coherence check."""
    check_id: str
    name: str
    passed: bool
    severity: str  # "info", "warning", "critical", "high", "medium", "low"
    evidence: Optional[str] = None
    details: Optional[str] = None


@dataclass
class FinalAnswerProvenance:
    """Tracks where the final answer was selected from.

    Deprecated in v0.13.0 — kept for backward compatibility with
    ``select_final_answer()`` but no longer emitted in receipts.
    """
    source: str  # "trace.output", "span.output", "none"
    span_id: Optional[str] = None
    span_name: Optional[str] = None
    field: Optional[str] = None


@dataclass
class ConstitutionProvenance:
    """Provenance of the constitution/policy document that defined check boundaries."""
    document_id: str
    policy_hash: str  # SHA256 hash of the constitution content
    version: Optional[str] = None
    source: Optional[str] = None  # e.g., "policy-repo", "compliance-api"


@dataclass
class HaltEvent:
    """Deprecated in v0.13.0 — replaced by top-level ``enforcement`` object.

    Kept for backward compatibility with legacy code that constructs
    HaltEvent instances.
    """
    halted: bool
    reason: str
    failed_checks: list  # List of check_id strings that triggered the halt
    timestamp: str
    enforcement_mode: str  # "halt", "warn", "log"


@dataclass
class Enforcement:
    """Top-level enforcement outcome (v0.13.0+).

    Records the enforcement decision for this receipt.
    """
    action: str  # "halted", "warned", "allowed", "escalated"
    reason: str
    failed_checks: list  # List of check_id strings
    enforcement_mode: str  # "halt", "warn", "log"
    timestamp: str


@dataclass
class SannaReceipt:
    """The reasoning receipt artifact (v0.13.0 format)."""
    spec_version: str
    tool_version: str
    checks_version: str
    receipt_id: str
    receipt_fingerprint: str
    full_fingerprint: str
    correlation_id: str
    timestamp: str
    inputs: dict
    outputs: dict
    context_hash: str
    output_hash: str
    checks: list
    checks_passed: int
    checks_failed: int
    status: str  # "PASS", "WARN", "FAIL", "PARTIAL"
    constitution_ref: Optional[dict] = None
    enforcement: Optional[dict] = None


# =============================================================================
# MULTI-STEP TRACE HANDLING
# =============================================================================

def select_final_answer(trace_data: dict) -> Tuple[str, FinalAnswerProvenance]:
    """
    Select the final answer from a trace with explicit precedence.

    Precedence:
    1. trace.output["final_answer"] (explicit trace-level)
    2. Last LLM generation span with response
    3. Any span with response-like output

    Returns (answer_text, provenance)
    """
    # 1) Trace-level output
    trace_output = trace_data.get("output") or {}
    if isinstance(trace_output, dict):
        for key in ["final_answer", "answer", "response", "final"]:
            val = trace_output.get(key)
            if isinstance(val, str) and val.strip():
                return val, FinalAnswerProvenance(source="trace.output", field=key)

    # 2) Find generation spans with responses
    observations = trace_data.get("observations") or []
    candidates = []

    for obs in observations:
        name = (obs.get("name") or "").lower()
        obs_output = obs.get("output") or {}
        metadata = obs.get("metadata") or {}

        response = None
        response_field = None

        if isinstance(obs_output, dict):
            for key in ["response", "final_answer", "answer", "text", "content"]:
                val = obs_output.get(key)
                if isinstance(val, str) and val.strip():
                    response = val
                    response_field = key
                    break
        elif isinstance(obs_output, str) and obs_output.strip():
            response = obs_output
            response_field = "output"

        if response:
            # Determine if this looks like an LLM generation
            is_generation = (
                "generation" in name or
                "llm" in name or
                obs.get("type") == "GENERATION" or
                "model" in metadata or
                "tokens" in metadata
            )

            # Exclude tool-call-like spans
            is_tool = "tool" in name or "retrieval" in name or "search" in name

            candidates.append({
                "obs": obs,
                "response": response,
                "response_field": response_field,
                "is_generation": is_generation,
                "is_tool": is_tool,
                "start_time": obs.get("start_time") or obs.get("startTime") or "",
                "end_time": obs.get("end_time") or obs.get("endTime") or "",
            })

    if candidates:
        # Filter: prefer non-tool spans
        non_tool = [c for c in candidates if not c["is_tool"]]
        pool = non_tool if non_tool else candidates

        # Sort: prefer generations, then by time (latest first)
        def sort_key(c):
            return (
                c["end_time"],
                c["start_time"],
                1 if c["is_generation"] else 0,
                c["obs"].get("id") or ""
            )

        best = sorted(pool, key=sort_key)[-1]
        return best["response"], FinalAnswerProvenance(
            source="span.output",
            span_id=best["obs"].get("id"),
            span_name=best["obs"].get("name"),
            field=best["response_field"]
        )

    # 3) Nothing found
    return "", FinalAnswerProvenance(source="none")


# =============================================================================
# EXTRACTION HELPERS
# =============================================================================

def extract_context(trace_data: dict) -> str:
    """Extract context from retrieval spans."""
    for obs in trace_data.get("observations", []):
        if obs.get("name") == "retrieval" and obs.get("output"):
            ctx = obs["output"]
            if isinstance(ctx, dict):
                return ctx.get("context", str(ctx))
            return str(ctx)
    return ""


def extract_query(trace_data: dict) -> str:
    """Extract user query from retrieval spans."""
    for obs in trace_data.get("observations", []):
        if obs.get("name") == "retrieval" and obs.get("input"):
            inp = obs["input"]
            if isinstance(inp, dict):
                return inp.get("query", str(inp))
            return str(inp)
    return ""


def find_snippet(text: str, keywords: list, max_len: int = 80) -> str:
    """Find a snippet containing keywords."""
    if not text:
        return ""
    text_lower = text.lower()
    for kw in keywords:
        idx = text_lower.find(kw.lower())
        if idx >= 0:
            start = max(0, idx - 20)
            end = min(len(text), idx + len(kw) + 40)
            snippet = text[start:end].strip()
            if start > 0:
                snippet = "..." + snippet
            if end < len(text):
                snippet = snippet + "..."
            return snippet[:max_len]
    return text[:max_len] + "..." if len(text) > max_len else text


# =============================================================================
# C1-C5 HEURISTIC CHECKS
# =============================================================================

def _check_c1_context_contradiction(
    context: str,
    output: str,
    enforcement: str = "halt",
    *,
    structured_context: Optional[List[dict]] = None,
) -> CheckResult:
    """
    C1: Context Contradiction
    Check if output contradicts explicit statements in context.

    Heuristic v0: Pattern matching for common contradiction patterns.

    When ``structured_context`` is provided (list of dicts with ``text``,
    ``source``, and ``tier`` keys), C1 evaluates per-source:

    - **tier_1**: full trust — contradiction is a critical failure.
    - **tier_2**: evidence — contradiction is a critical failure with
      verification note in evidence.
    - **tier_3**: reference only — contradiction from *only* tier_3
      sources is a pass with warning details.
    - **untrusted**: excluded from contradiction checking entirely.

    When ``structured_context`` is None, C1 behaves exactly as v0.6.x
    (flat string context, all equally trusted).
    """
    if not context or not output:
        return CheckResult(
            check_id="C1", name="Context Contradiction",
            passed=True, severity="info",
            details="Insufficient data for contradiction check"
        )

    # Source-aware path
    if structured_context:
        return _c1_source_aware(structured_context, output)

    # v0.6.x path — flat string context
    return _c1_flat(context, output)


def _c1_flat(context: str, output: str) -> CheckResult:
    """C1 heuristic on flat string context (v0.6.x behavior)."""
    context_lower = context.lower()
    output_lower = output.lower()

    issues = []
    context_snippet = ""
    output_snippet = ""

    # Pattern: Context says X is non-refundable, output says refund OK
    if "non-refundable" in context_lower and "eligible" in output_lower and "refund" in output_lower:
        issues.append("Output suggests eligibility despite 'non-refundable' in context")
        context_snippet = find_snippet(context, ["non-refundable"])
        output_snippet = find_snippet(output, ["eligible"])

    if "digital products are non-refundable" in context_lower:
        if "software" in output_lower or "digital" in output_lower:
            if "eligible" in output_lower or "can get" in output_lower or "you are able" in output_lower:
                issues.append("Context states digital products non-refundable, but output implies refund possible")
                context_snippet = find_snippet(context, ["digital products are non-refundable"])
                output_snippet = find_snippet(output, ["eligible", "can get", "you are able"])

    if issues:
        evidence_parts = [issues[0]]
        if context_snippet:
            evidence_parts.append(f'Context: "{context_snippet}"')
        if output_snippet:
            evidence_parts.append(f'Output: "{output_snippet}"')

        return CheckResult(
            check_id="C1", name="Context Contradiction",
            passed=False, severity="critical",
            evidence=" | ".join(evidence_parts),
            details="Output may contradict provided context."
        )

    return CheckResult(
        check_id="C1", name="Context Contradiction",
        passed=True, severity="info",
        details="No obvious contradiction detected (heuristic check)"
    )


def _c1_source_aware(structured_context: List[dict], output: str) -> CheckResult:
    """C1 heuristic with per-source trust tier evaluation."""
    # Partition sources by tier
    tier_1_texts = []
    tier_2_texts = []
    tier_3_texts = []
    # untrusted sources are excluded

    for item in structured_context:
        text = item.get("text", "")
        tier = item.get("tier", "tier_1")  # default to tier_1 if not specified
        if tier == "tier_1":
            tier_1_texts.append((text, item.get("source", "unknown")))
        elif tier == "tier_2":
            tier_2_texts.append((text, item.get("source", "unknown")))
        elif tier == "tier_3":
            tier_3_texts.append((text, item.get("source", "unknown")))
        # untrusted → skip

    # Check tier_1 sources first (highest trust)
    for text, source in tier_1_texts:
        result = _c1_flat(text, output)
        if not result.passed:
            return CheckResult(
                check_id="C1", name="Context Contradiction",
                passed=False, severity="critical",
                evidence=f"[tier_1 source: {source}] {result.evidence}",
                details="Output contradicts tier_1 (fully trusted) source."
            )

    # Check tier_2 sources (evidence with verification)
    for text, source in tier_2_texts:
        result = _c1_flat(text, output)
        if not result.passed:
            return CheckResult(
                check_id="C1", name="Context Contradiction",
                passed=False, severity="critical",
                evidence=f"[tier_2 source: {source}, verification_needed] {result.evidence}",
                details="Output contradicts tier_2 source. Verification recommended."
            )

    # Check tier_3 sources (reference only)
    for text, source in tier_3_texts:
        result = _c1_flat(text, output)
        if not result.passed:
            # tier_3 contradiction is NOT a failure — it's a pass with warning
            return CheckResult(
                check_id="C1", name="Context Contradiction",
                passed=True, severity="info",
                evidence=f"[tier_3 source: {source}, reference_only] {result.evidence}",
                details=(
                    "Potential contradiction found in tier_3 (reference-only) source. "
                    "tier_3 sources cannot be sole basis for failure."
                )
            )

    return CheckResult(
        check_id="C1", name="Context Contradiction",
        passed=True, severity="info",
        details="No obvious contradiction detected (source-aware check)"
    )


def _check_c2_unmarked_inference(context: str, output: str, enforcement: str = "warn") -> CheckResult:
    """
    C2: Mark Inferences
    Check if speculative/inferential statements are properly hedged.

    Heuristic v0: Look for definitive statements without hedging language.
    """
    if not output:
        return CheckResult(
            check_id="C2", name="Mark Inferences",
            passed=True, severity="info", details="No output to check"
        )

    hedges = ["may", "might", "could", "possibly", "likely", "appears", "seems",
              "suggest", "indicate", "probably", "perhaps", "it's possible"]
    definitive = ["definitely", "certainly", "always", "never", "guaranteed",
                  "absolutely", "without doubt", "100%"]

    output_lower = output.lower()
    has_hedging = any(h in output_lower for h in hedges)
    has_definitive = any(d in output_lower for d in definitive)
    found_definitive = [d for d in definitive if d in output_lower]

    if has_definitive and not has_hedging:
        return CheckResult(
            check_id="C2", name="Mark Inferences",
            passed=False, severity="warning",
            evidence=f"Found definitive language: {', '.join(found_definitive)}",
            details="Output contains strong definitive statements"
        )

    return CheckResult(
        check_id="C2", name="Mark Inferences",
        passed=True, severity="info",
        details="Inference marking appears adequate (heuristic check)"
    )


def _check_c3_false_certainty(context: str, output: str, enforcement: str = "warn") -> CheckResult:
    """
    C3: No False Certainty
    Check if confidence level matches evidence strength.

    Heuristic v0: Detect high-confidence claims when context has conditions.
    """
    if not output:
        return CheckResult(
            check_id="C3", name="No False Certainty",
            passed=True, severity="info", details="No output to check"
        )

    output_lower = output.lower()
    context_lower = context.lower() if context else ""

    conditional_markers = ["if", "unless", "except", "however", "but", "require"]
    confidence_markers = ["you are eligible", "you can", "you will", "go ahead and"]

    context_has_conditions = any(m in context_lower for m in conditional_markers)
    output_is_confident = any(m in output_lower for m in confidence_markers)
    found_confident = [m for m in confidence_markers if m in output_lower]

    if context_has_conditions and output_is_confident:
        acknowledges = any(m in output_lower for m in ["however", "but", "note that", "keep in mind", "require"])
        if not acknowledges:
            return CheckResult(
                check_id="C3", name="No False Certainty",
                passed=False, severity="warning",
                evidence=f'Confident claim without acknowledging conditions: "{found_confident[0]}"',
                details="Output confidence may exceed evidence support"
            )

    return CheckResult(
        check_id="C3", name="No False Certainty",
        passed=True, severity="info",
        details="Certainty level appears appropriate (heuristic check)"
    )


def _check_c4_conflict_collapse(context: str, output: str, enforcement: str = "warn") -> CheckResult:
    """
    C4: Preserve Tensions
    Check if conflicting information is preserved rather than collapsed.

    Heuristic v0: Look for contradictory evidence that gets flattened.
    """
    if not context or not output:
        return CheckResult(
            check_id="C4", name="Preserve Tensions",
            passed=True, severity="info",
            details="Insufficient data for conflict check"
        )

    import re as _re

    context_lower = context.lower()
    output_lower = output.lower()

    # Pattern: Context has both permissive and restrictive rules
    # Use word-boundary matching to avoid substring collisions (e.g., "can" inside "cannot")
    _permissive_terms = [r"\bcan(?!'t)\b", r"\beligible\b", r"\ballowed\b", r"\bpermitted\b"]
    _restrictive_terms = [r"\bnon-refundable\b", r"\bcannot\b", r"\bnot allowed\b", r"\bprohibited\b", r"\brequire\b"]
    has_permissive = any(_re.search(p, context_lower) for p in _permissive_terms)
    has_restrictive = any(_re.search(r, context_lower) for r in _restrictive_terms)

    if has_permissive and has_restrictive:
        acknowledges_tension = any(t in output_lower for t in
            ["however", "but", "although", "on the other hand", "exception", "note that"])

        if not acknowledges_tension:
            return CheckResult(
                check_id="C4", name="Preserve Tensions",
                passed=False, severity="warning",
                evidence="Context contains conflicting rules not reflected in output",
                details="Output may have collapsed policy tensions"
            )

    return CheckResult(
        check_id="C4", name="Preserve Tensions",
        passed=True, severity="info",
        details="No obvious conflict collapse detected (heuristic check)"
    )


def _check_c5_premature_compression(context: str, output: str, enforcement: str = "warn") -> CheckResult:
    """
    C5: No Premature Compression
    Check if output appropriately represents complexity of input.

    Heuristic v0: Flag if multi-faceted context gets single-sentence answer.
    """
    if not context or not output:
        return CheckResult(
            check_id="C5", name="No Premature Compression",
            passed=True, severity="info",
            details="Insufficient data for compression check"
        )

    import re as _re

    # Count distinct policy points in context
    # Only count bullet-point hyphens (line-start), not hyphens in words like "non-refundable"
    context_bullets = len(_re.findall(r'(?:^|\n)\s*[-•]', context))
    context_sentences = context.count(".") + context.count("!")
    context_complexity = max(context_bullets, context_sentences)

    # Count output sentences
    output_sentences = output.count(".") + output.count("!") + output.count("?")

    if context_complexity >= 3 and output_sentences <= 1:
        return CheckResult(
            check_id="C5", name="No Premature Compression",
            passed=False, severity="warning",
            evidence=f"Context has ~{context_complexity} points, output has {output_sentences} sentences",
            details="Output may over-compress multi-faceted context"
        )

    return CheckResult(
        check_id="C5", name="No Premature Compression",
        passed=True, severity="info",
        details="Compression level appears appropriate (heuristic check)"
    )


# =============================================================================
# RECEIPT GENERATION
# =============================================================================

def generate_receipt(
    trace_data: dict,
    constitution: Optional[ConstitutionProvenance] = None,
    enforcement: Optional[HaltEvent] = None,
    constitution_ref_override: Optional[dict] = None,
) -> SannaReceipt:
    """Generate a Sanna receipt from trace data.

    Args:
        trace_data: Trace data dict with correlation_id, observations, etc.
        constitution: Optional constitution provenance for governance tracking.
        enforcement: Optional enforcement action recording.
        constitution_ref_override: Rich dict to use directly as constitution_ref
            in both the fingerprint and the receipt body. When provided, takes
            precedence over the ``constitution`` parameter (the legacy
            ConstitutionProvenance dataclass). This ensures the fingerprint is
            computed over the exact same dict that ends up in the receipt.
    """
    # Select final answer
    final_answer, _answer_provenance = select_final_answer(trace_data)

    # Extract context once for all checks
    context = extract_context(trace_data)

    # Run all checks with shared context and output
    checks = [
        check_c1_context_contradiction(context, final_answer),
        check_c2_unmarked_inference(context, final_answer),
        check_c3_false_certainty(context, final_answer),
        check_c4_conflict_collapse(context, final_answer),
        check_c5_premature_compression(context, final_answer),
    ]

    passed = sum(1 for c in checks if c.passed)
    failed = len(checks) - passed

    # Determine overall status
    critical_fails = sum(1 for c in checks if not c.passed and c.severity == "critical")
    warning_fails = sum(1 for c in checks if not c.passed and c.severity == "warning")

    if critical_fails > 0:
        status = "FAIL"
    elif warning_fails > 0:
        status = "WARN"
    else:
        status = "PASS"

    # Build input/output summaries
    query = extract_query(trace_data)
    inputs = {"query": query if query else None, "context": context if context else None}
    outputs = {"response": final_answer if final_answer else None}

    # Canonical hashes for tamper-evidence (64-hex SHA-256)
    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)

    # Resolve constitution_ref: override takes precedence over legacy dataclass
    if constitution_ref_override is not None:
        constitution_dict = constitution_ref_override
    else:
        constitution_dict = asdict(constitution) if constitution else None

    # Build enforcement object if provided
    enforcement_dict = None
    if enforcement is not None:
        enforcement_obj_dict = asdict(enforcement)
        enforcement_dict = {
            "action": "halted" if enforcement.halted else "allowed",
            "reason": enforcement.reason,
            "failed_checks": enforcement.failed_checks,
            "enforcement_mode": enforcement.enforcement_mode,
            "timestamp": enforcement.timestamp,
        }
    else:
        enforcement_obj_dict = None

    # Strip mutable constitution_approval before hashing (parity with middleware/verify).
    if constitution_dict:
        _cref = {k: v for k, v in constitution_dict.items() if k != "constitution_approval"}
        constitution_hash = hash_obj(_cref)
    else:
        constitution_hash = EMPTY_HASH
    enforcement_hash = hash_obj(enforcement_dict) if enforcement_dict else EMPTY_HASH

    # Unified fingerprint formula (v0.13.0) — always 12 pipe-delimited fields
    correlation_id = trace_data.get("correlation_id", "")
    checks_data = [{"check_id": c.check_id, "passed": c.passed, "severity": c.severity, "evidence": c.evidence} for c in checks]
    checks_hash = hash_obj(checks_data)
    coverage_hash = EMPTY_HASH
    authority_hash = EMPTY_HASH
    escalation_hash = EMPTY_HASH
    trust_hash = EMPTY_HASH
    extensions_hash = EMPTY_HASH

    fingerprint_input = f"{correlation_id}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}"
    full_fp = hash_text(fingerprint_input)
    receipt_fingerprint = hash_text(fingerprint_input, truncate=16)

    return SannaReceipt(
        spec_version=SPEC_VERSION,
        tool_version=TOOL_VERSION,
        checks_version=CHECKS_VERSION,
        receipt_id=str(uuid.uuid4()),
        receipt_fingerprint=receipt_fingerprint,
        full_fingerprint=full_fp,
        correlation_id=correlation_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        inputs=inputs,
        outputs=outputs,
        context_hash=context_hash,
        output_hash=output_hash,
        checks=[asdict(c) for c in checks],
        checks_passed=passed,
        checks_failed=failed,
        status=status,
        constitution_ref=constitution_dict,
        enforcement=enforcement_dict,
    )


# =============================================================================
# TRACE DATA EXTRACTION
# =============================================================================

def extract_trace_data(trace) -> dict:
    """Extract relevant data from a trace object.

    Works with any trace object that exposes .id, .name, .timestamp,
    .input, .output, .metadata, and .observations attributes.

    Context extraction: scans observation outputs for common retrieval
    keys (documents, context, retrieved, chunks, retrieval,
    search_results) and synthesises a retrieval observation when context
    is found only in the trace input.
    """
    correlation_id = getattr(trace, "id", "unknown")

    observations_raw = getattr(trace, "observations", None) or []
    observations = []
    context = ""

    for obs in observations_raw:
        obs_output = getattr(obs, "output", None)
        # Scan observation outputs for retrieval context
        if obs_output and isinstance(obs_output, dict):
            for key in ("documents", "context", "retrieved", "chunks",
                        "retrieval", "search_results"):
                if key in obs_output:
                    ctx_val = obs_output[key]
                    if not context:
                        context = (
                            "\n".join(str(d) for d in ctx_val)
                            if isinstance(ctx_val, list)
                            else str(ctx_val)
                        )
                    break

        obs_data = {
            "id": getattr(obs, "id", None),
            "name": getattr(obs, "name", None),
            "type": getattr(obs, "type", None),
            "input": getattr(obs, "input", None),
            "output": getattr(obs, "output", None),
            "metadata": getattr(obs, "metadata", None),
            "start_time": (
                str(getattr(obs, "start_time", None))
                if getattr(obs, "start_time", None)
                else None
            ),
            "end_time": (
                str(getattr(obs, "end_time", None))
                if getattr(obs, "end_time", None)
                else None
            ),
        }
        observations.append(obs_data)

    # Extract query from trace input
    trace_input = getattr(trace, "input", None)
    query = ""
    if isinstance(trace_input, dict):
        query = trace_input.get("query", trace_input.get("question",
                trace_input.get("input", "")))
    elif isinstance(trace_input, str):
        query = trace_input

    # If no retrieval span found, check trace input for context
    if not context and isinstance(trace_input, dict):
        ctx_val = trace_input.get("context", "")
        if ctx_val:
            context = str(ctx_val)
            observations.insert(0, {
                "id": "synthetic-retrieval",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": query},
                "output": {"context": context},
                "metadata": {},
                "start_time": None,
                "end_time": None,
            })

    trace_output = getattr(trace, "output", None)

    return {
        "correlation_id": correlation_id,
        "name": getattr(trace, "name", None),
        "timestamp": (
            str(getattr(trace, "timestamp", None))
            if getattr(trace, "timestamp", None)
            else None
        ),
        "input": trace_input if isinstance(trace_input, dict) else {"query": query},
        "output": trace_output if isinstance(trace_output, dict) else None,
        "metadata": getattr(trace, "metadata", None),
        "observations": observations,
    }


# ---------------------------------------------------------------------------
# Backward-compat aliases (internal use only — do not add to public API)
# ---------------------------------------------------------------------------
check_c1_context_contradiction = _check_c1_context_contradiction
check_c2_unmarked_inference = _check_c2_unmarked_inference
check_c3_false_certainty = _check_c3_false_certainty
check_c4_conflict_collapse = _check_c4_conflict_collapse
check_c5_premature_compression = _check_c5_premature_compression
