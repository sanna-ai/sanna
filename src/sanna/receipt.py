"""
Sanna Receipt generation — C1-C5 coherence checks and receipt assembly.

Renamed from c3m_receipt. Original implementations preserved.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Any, Tuple

from .hashing import hash_text, hash_obj


# =============================================================================
# VERSION CONSTANTS
# =============================================================================

TOOL_VERSION = "0.4.0"
SCHEMA_VERSION = "0.1"
CHECKS_VERSION = "1"  # Increment when check logic changes


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CheckResult:
    """Result of a single coherence check."""
    check_id: str
    name: str
    passed: bool
    severity: str  # "info", "warning", "critical"
    evidence: Optional[str] = None
    details: Optional[str] = None


@dataclass
class FinalAnswerProvenance:
    """Tracks where the final answer was selected from."""
    source: str  # "trace.output", "span.output", "none"
    span_id: Optional[str] = None
    span_name: Optional[str] = None
    field: Optional[str] = None


@dataclass
class ConstitutionProvenance:
    """Provenance of the constitution/policy document that defined check boundaries."""
    document_id: str
    document_hash: str  # SHA256 hash of the constitution content
    version: Optional[str] = None
    source: Optional[str] = None  # e.g., "policy-repo", "compliance-api"


@dataclass
class HaltEvent:
    """Records when execution was halted due to check failures."""
    halted: bool
    reason: str
    failed_checks: list  # List of check_id strings that triggered the halt
    timestamp: str
    enforcement_mode: str  # "halt", "warn", "log"


@dataclass
class SannaReceipt:
    """The reasoning receipt artifact."""
    schema_version: str
    tool_version: str
    checks_version: str
    receipt_id: str
    receipt_fingerprint: str
    trace_id: str
    timestamp: str
    inputs: dict
    outputs: dict
    context_hash: str
    output_hash: str
    final_answer_provenance: dict
    checks: list
    checks_passed: int
    checks_failed: int
    coherence_status: str  # "PASS", "WARN", "FAIL"
    constitution_ref: Optional[dict] = None
    halt_event: Optional[dict] = None


# Legacy alias
C3MReceipt = SannaReceipt


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

def check_c1_context_contradiction(context: str, output: str) -> CheckResult:
    """
    C1: Context Contradiction
    Check if output contradicts explicit statements in context.

    Heuristic v0: Pattern matching for common contradiction patterns.
    """
    if not context or not output:
        return CheckResult(
            check_id="C1", name="Context Contradiction",
            passed=True, severity="info",
            details="Insufficient data for contradiction check"
        )

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


def check_c2_unmarked_inference(context: str, output: str) -> CheckResult:
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


def check_c3_false_certainty(context: str, output: str) -> CheckResult:
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


def check_c4_conflict_collapse(context: str, output: str) -> CheckResult:
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

    context_lower = context.lower()
    output_lower = output.lower()

    # Pattern: Context has both permissive and restrictive rules
    has_permissive = any(p in context_lower for p in ["can", "eligible", "allowed", "permitted"])
    has_restrictive = any(r in context_lower for r in ["non-refundable", "cannot", "not allowed", "prohibited", "require"])

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


def check_c5_premature_compression(context: str, output: str) -> CheckResult:
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

    # Count distinct policy points in context
    context_bullets = context.count("-") + context.count("•") + context.count("\n")
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
    halt_event: Optional[HaltEvent] = None,
) -> SannaReceipt:
    """Generate a Sanna receipt from trace data.

    Args:
        trace_data: Trace data dict with trace_id, observations, etc.
        constitution: Optional constitution provenance for governance tracking.
        halt_event: Optional halt event recording enforcement action.
    """
    # Select final answer with provenance tracking
    final_answer, answer_provenance = select_final_answer(trace_data)

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

    # Canonical hashes for tamper-evidence
    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)

    # Serialize optional blocks for fingerprint
    constitution_dict = asdict(constitution) if constitution else None
    halt_event_dict = asdict(halt_event) if halt_event else None
    constitution_hash = hash_obj(constitution_dict) if constitution_dict else ""
    halt_hash = hash_obj(halt_event_dict) if halt_event_dict else ""

    # Stable fingerprint for diffs/golden tests (doesn't change across runs of same trace)
    # Include checks, constitution, and halt_event in fingerprint so tampering invalidates it
    checks_data = [{"check_id": c.check_id, "passed": c.passed, "severity": c.severity, "evidence": c.evidence} for c in checks]
    checks_hash = hash_obj(checks_data)
    fingerprint_input = f"{trace_data['trace_id']}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash}|{halt_hash}"
    receipt_fingerprint = hash_text(fingerprint_input)

    return SannaReceipt(
        schema_version=SCHEMA_VERSION,
        tool_version=TOOL_VERSION,
        checks_version=CHECKS_VERSION,
        receipt_id=hash_text(f"{trace_data['trace_id']}{datetime.now(timezone.utc).isoformat()}"),
        receipt_fingerprint=receipt_fingerprint,
        trace_id=trace_data["trace_id"],
        timestamp=datetime.now(timezone.utc).isoformat(),
        inputs=inputs,
        outputs=outputs,
        context_hash=context_hash,
        output_hash=output_hash,
        final_answer_provenance=asdict(answer_provenance),
        checks=[asdict(c) for c in checks],
        checks_passed=passed,
        checks_failed=failed,
        coherence_status=status,
        constitution_ref=constitution_dict,
        halt_event=halt_event_dict,
    )


# =============================================================================
# LANGFUSE TRACE EXTRACTION
# =============================================================================

def extract_trace_data(trace) -> dict:
    """Extract relevant data from a Langfuse trace object."""
    data = {
        "trace_id": trace.id,
        "name": trace.name,
        "timestamp": str(trace.timestamp) if trace.timestamp else None,
        "input": trace.input,
        "output": trace.output,
        "metadata": trace.metadata,
        "observations": []
    }

    # Get observations (spans/generations) - v3 API returns ObservationsView objects
    if hasattr(trace, 'observations') and trace.observations:
        for obs in trace.observations:
            obs_data = {
                "id": getattr(obs, 'id', None),
                "name": getattr(obs, 'name', None),
                "type": getattr(obs, 'type', None),
                "input": getattr(obs, 'input', None),
                "output": getattr(obs, 'output', None),
                "metadata": getattr(obs, 'metadata', None),
                "start_time": str(getattr(obs, 'start_time', None)) if getattr(obs, 'start_time', None) else None,
                "end_time": str(getattr(obs, 'end_time', None)) if getattr(obs, 'end_time', None) else None,
            }
            data["observations"].append(obs_data)

    return data
