"""
Sanna OpenTelemetry exporter — convert receipts into OTel spans.

Spans carry a POINTER + INTEGRITY HASH to the receipt, NOT the full
receipt JSON.  This keeps span payloads small while preserving the
ability to verify artifact integrity from traces.

Usage::

    from sanna.exporters.otel_exporter import receipt_to_span
    from opentelemetry import trace

    tracer = trace.get_tracer("sanna")
    receipt_to_span(receipt, tracer, artifact_uri="s3://bucket/receipt.json")

Requires ``pip install sanna[otel]``.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional, Sequence

from sanna.hashing import canonical_json_bytes

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from opentelemetry.trace import StatusCode
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

logger = logging.getLogger("sanna.exporters.otel")

if not HAS_OTEL:
    raise ImportError(
        "opentelemetry is required for the Sanna OTel exporter. "
        "Install it with: pip install sanna[otel]"
    )


# =============================================================================
# HELPERS
# =============================================================================

NAMESPACED_TO_LEGACY = {
    "sanna.context_contradiction": "C1",
    "sanna.unmarked_inference": "C2",
    "sanna.false_certainty": "C3",
    "sanna.conflict_collapse": "C4",
    "sanna.premature_compression": "C5",
}


def _content_hash(receipt: dict) -> str:
    """SHA-256 of Sanna canonical JSON of the receipt."""
    return hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()


def _check_status(checks: list, check_id: str) -> str:
    """Extract status string for a specific check ID.

    Accepts legacy IDs ("C1") and namespaced IDs
    ("sanna.context_contradiction").  Also checks the ``check_impl``
    field for a namespaced match.

    Returns "pass", "fail", "not_checked", or "absent".
    """
    for check in checks:
        cid = check.get("check_id", "")
        impl = check.get("check_impl", "")

        # Direct legacy match (e.g. check_id == "C1")
        if cid == check_id:
            if check.get("status") == "NOT_CHECKED":
                return "not_checked"
            return "pass" if check.get("passed") else "fail"

        # Namespaced check_id → legacy match
        if cid in NAMESPACED_TO_LEGACY and NAMESPACED_TO_LEGACY[cid] == check_id:
            if check.get("status") == "NOT_CHECKED":
                return "not_checked"
            return "pass" if check.get("passed") else "fail"

        # check_impl field → legacy match
        if impl in NAMESPACED_TO_LEGACY and NAMESPACED_TO_LEGACY[impl] == check_id:
            if check.get("status") == "NOT_CHECKED":
                return "not_checked"
            return "pass" if check.get("passed") else "fail"

    return "absent"


def _evaluation_coverage_pct(receipt: dict) -> float:
    """Calculate evaluation coverage percentage from receipt checks.

    Returns the percentage of checks that were actually evaluated
    (passed or failed, excluding NOT_CHECKED).
    """
    evaluation_coverage = receipt.get("evaluation_coverage")
    if evaluation_coverage:
        basis_points = evaluation_coverage.get("coverage_basis_points", 10000)
        return basis_points / 100.0

    checks = receipt.get("checks", [])
    if not checks:
        return 100.0
    evaluated = sum(1 for c in checks if c.get("status") != "NOT_CHECKED")
    return (evaluated / len(checks)) * 100.0


# =============================================================================
# RECEIPT TO SPAN
# =============================================================================

def receipt_to_span(
    receipt: dict,
    tracer: trace.Tracer,
    artifact_uri: Optional[str] = None,
) -> None:
    """Create an OTel span from a Sanna receipt.

    The span captures governance evaluation metadata as structured
    attributes.  The full receipt is NOT embedded — only a content
    hash and optional artifact URI for retrieval.

    Args:
        receipt: A Sanna receipt dict.
        tracer: An OpenTelemetry Tracer instance.
        artifact_uri: Optional URI where the full receipt is stored
            (e.g. ``s3://bucket/receipt.json``).
    """
    status = receipt.get("status", "UNKNOWN")
    checks = receipt.get("checks", [])

    # Build span attributes
    attributes: dict[str, str | int | float | bool] = {
        "sanna.receipt.id": receipt.get("correlation_id", ""),
        "sanna.status": status,
        "sanna.artifact.content_hash": _content_hash(receipt),
    }

    # Enforcement decision (from extensions.middleware if present)
    extensions = receipt.get("extensions", {})
    middleware_ext = extensions.get("middleware", {})
    if middleware_ext.get("enforcement_decision"):
        attributes["sanna.enforcement_decision"] = middleware_ext["enforcement_decision"]

    # Constitution reference
    constitution_ref = receipt.get("constitution_ref")
    if constitution_ref:
        if constitution_ref.get("policy_hash"):
            attributes["sanna.constitution.policy_hash"] = constitution_ref["policy_hash"]
        if constitution_ref.get("version"):
            attributes["sanna.constitution.version"] = constitution_ref["version"]

    # Evaluation coverage
    attributes["sanna.evaluation_coverage.pct"] = _evaluation_coverage_pct(receipt)

    # Per-check status (C1–C5)
    for i in range(1, 6):
        check_id = f"C{i}"
        attributes[f"sanna.check.c{i}.status"] = _check_status(checks, check_id)

    # Authority decisions
    authority_decisions = receipt.get("authority_decisions")
    if authority_decisions and len(authority_decisions) > 0:
        attributes["sanna.authority.decision"] = authority_decisions[0].get("decision", "")
    else:
        attributes["sanna.authority.decision"] = ""

    # Escalation events
    escalation_events = receipt.get("escalation_events")
    attributes["sanna.escalation.triggered"] = bool(escalation_events)

    # Source trust evaluations
    source_trust_evaluations = receipt.get("source_trust_evaluations")
    if source_trust_evaluations:
        flag_count = sum(
            1 for st in source_trust_evaluations
            if st.get("verification_flag")
        )
        attributes["sanna.source_trust.flags"] = flag_count
    else:
        attributes["sanna.source_trust.flags"] = 0

    # Artifact URI
    if artifact_uri:
        attributes["sanna.artifact.uri"] = artifact_uri

    # Determine span status
    if status in ("FAIL", "HALT"):
        span_status = trace.Status(StatusCode.ERROR, f"status={status}")
    else:
        span_status = trace.Status(StatusCode.OK)

    # Create the span
    with tracer.start_as_current_span(
        "sanna.governance.evaluation",
        kind=trace.SpanKind.INTERNAL,
        attributes=attributes,
    ) as span:
        span.set_status(span_status)

        # Add events for each check result
        for check in checks:
            span.add_event(
                f"check.{check.get('check_id', 'unknown')}",
                attributes={
                    "check_id": check.get("check_id", ""),
                    "name": check.get("name", ""),
                    "passed": check.get("passed", False),
                    "severity": check.get("severity", ""),
                    "evidence": check.get("evidence") or "",
                },
            )

        # Add events for authority decisions
        if authority_decisions:
            for ad in authority_decisions:
                span.add_event(
                    f"authority.{ad.get('decision', 'unknown')}",
                    attributes={
                        "action": ad.get("action_name", ""),
                        "decision": ad.get("decision", ""),
                        "reason": ad.get("reason", ""),
                        "boundary_type": ad.get("boundary_type", ""),
                    },
                )


# =============================================================================
# SPAN EXPORTER (for BatchSpanProcessor integration)
# =============================================================================

class SannaOTelExporter(SpanExporter):
    """SpanExporter that processes spans containing Sanna receipt data.

    This exporter works with BatchSpanProcessor. It looks for spans
    that have ``sanna.receipt.id`` in their attributes and forwards
    them to a delegate exporter (or logs them).

    Args:
        delegate: Optional SpanExporter to forward processed spans to.
            If None, spans are logged at DEBUG level.
    """

    def __init__(self, delegate: Optional[SpanExporter] = None):
        self._delegate = delegate

    def export(self, spans: Sequence) -> SpanExportResult:
        """Export spans, filtering for Sanna governance spans."""
        sanna_spans = []
        for span in spans:
            attrs = span.attributes or {}
            if "sanna.receipt.id" in attrs:
                sanna_spans.append(span)
                logger.debug(
                    "Sanna span: receipt=%s status=%s",
                    attrs.get("sanna.receipt.id"),
                    attrs.get("sanna.status"),
                )

        if self._delegate and sanna_spans:
            return self._delegate.export(sanna_spans)

        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        """Shut down the exporter."""
        if self._delegate:
            self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush the delegate exporter."""
        if self._delegate:
            return self._delegate.force_flush(timeout_millis)
        return True
