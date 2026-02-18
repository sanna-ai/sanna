"""
Tests for the Sanna OpenTelemetry exporter.

Covers:
  - receipt_to_span with various receipt shapes
  - SannaOTelExporter with BatchSpanProcessor
  - Attribute mapping, span status, events
  - Graceful handling of missing optional sections
  - Backward compatibility with v0.6.x receipts
"""

import hashlib

import pytest

pytest.importorskip("opentelemetry.sdk", reason="opentelemetry-sdk not installed")

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from sanna.exporters.otel_exporter import (
    receipt_to_span,
    SannaOTelExporter,
    _content_hash,
    _check_status,
    _evaluation_coverage_pct,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def tracer_and_exporter():
    """Set up a tracer with InMemorySpanExporter for test collection."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    tracer = provider.get_tracer("sanna.test")
    yield tracer, exporter, provider
    provider.shutdown()


def _pass_receipt(**overrides) -> dict:
    """Minimal PASS receipt for testing."""
    receipt = {
        "schema_version": "0.1",
        "tool_version": "0.7.2",
        "checks_version": "2",
        "receipt_id": "abc123def456",
        "receipt_fingerprint": "fedcba9876543210",
        "correlation_id": "test-trace-001",
        "timestamp": "2026-02-13T00:00:00+00:00",
        "inputs": {"query": "test", "context": "test context"},
        "outputs": {"response": "test response"},
        "context_hash": "1234567890abcdef",
        "output_hash": "fedcba0987654321",
        "checks": [
            {"check_id": "C1", "name": "Context Contradiction", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "C2", "name": "Mark Inferences", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "C3", "name": "No False Certainty", "passed": True, "severity": "info", "evidence": None},
        ],
        "checks_passed": 3,
        "checks_failed": 0,
        "status": "PASS",
        "constitution_ref": None,
        "enforcement": None,
        "extensions": {},
    }
    receipt.update(overrides)
    return receipt


def _fail_receipt(**overrides) -> dict:
    """Receipt with FAIL status."""
    receipt = _pass_receipt(
        status="FAIL",
        checks=[
            {"check_id": "C1", "name": "Context Contradiction", "passed": False, "severity": "critical", "evidence": "Fabricated claim"},
            {"check_id": "C2", "name": "Mark Inferences", "passed": True, "severity": "info", "evidence": None},
        ],
        checks_passed=1,
        checks_failed=1,
    )
    receipt.update(overrides)
    return receipt


# =============================================================================
# TEST 1: PASS receipt → span status OK, correct attributes
# =============================================================================

class TestPassReceipt:
    def test_span_status_ok(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]

        assert span.name == "sanna.governance.evaluation"
        assert span.status.status_code.name == "OK"

    def test_correct_attributes(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        attrs = dict(span.attributes)

        assert attrs["sanna.receipt.id"] == "test-trace-001"
        assert attrs["sanna.status"] == "PASS"
        assert attrs["sanna.check.c1.status"] == "pass"
        assert attrs["sanna.check.c2.status"] == "pass"
        assert attrs["sanna.check.c3.status"] == "pass"
        assert attrs["sanna.check.c4.status"] == "absent"
        assert attrs["sanna.check.c5.status"] == "absent"

    def test_check_events(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        events = span.events
        assert len(events) == 3
        assert events[0].name == "check.C1"
        assert events[1].name == "check.C2"
        assert events[2].name == "check.C3"


# =============================================================================
# TEST 2: FAIL/HALT receipt → span status ERROR
# =============================================================================

class TestFailReceipt:
    def test_fail_status_error(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _fail_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.status.status_code.name == "ERROR"

    def test_halt_status_error(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _fail_receipt(status="HALT")

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.status.status_code.name == "ERROR"


# =============================================================================
# TEST 3: authority_decisions → sanna.authority.decision attribute
# =============================================================================

class TestAuthorityDecisions:
    def test_authority_decision_attribute(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(authority_decisions=[
            {"action_name": "send_email", "decision": "halt", "reason": "forbidden", "boundary_type": "cannot_execute"},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.authority.decision"] == "halt"

    def test_authority_decision_event(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(authority_decisions=[
            {"action_name": "send_email", "decision": "halt", "reason": "forbidden", "boundary_type": "cannot_execute"},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        authority_events = [e for e in span.events if e.name.startswith("authority.")]
        assert len(authority_events) == 1
        assert authority_events[0].name == "authority.halt"


# =============================================================================
# TEST 4-5: escalation_events → sanna.escalation.triggered
# =============================================================================

class TestEscalationTriggered:
    def test_escalation_triggered_true(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(escalation_events=[
            {"condition": "PII access", "target_type": "log", "timestamp": "2026-02-13T00:00:00Z"},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.escalation.triggered"] is True

    def test_escalation_triggered_false(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.escalation.triggered"] is False


# =============================================================================
# TEST 6: source_trust_evaluations with flags → correct count
# =============================================================================

class TestSourceTrustFlags:
    def test_source_trust_flag_count(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(source_trust_evaluations=[
            {"source_name": "db", "trust_tier": "tier_1", "verification_flag": False, "context_used": True},
            {"source_name": "api", "trust_tier": "tier_2", "verification_flag": True, "context_used": True},
            {"source_name": "web", "trust_tier": "tier_2", "verification_flag": True, "context_used": True},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.source_trust.flags"] == 2


# =============================================================================
# TEST 7: missing optional sections → no crash
# =============================================================================

class TestMissingSections:
    def test_no_optional_sections(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()
        # Ensure no optional sections
        receipt.pop("authority_decisions", None)
        receipt.pop("escalation_events", None)
        receipt.pop("source_trust_evaluations", None)

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.authority.decision"] == ""
        assert span.attributes["sanna.escalation.triggered"] is False
        assert span.attributes["sanna.source_trust.flags"] == 0


# =============================================================================
# TEST 8: artifact_uri flows through
# =============================================================================

class TestArtifactUri:
    def test_artifact_uri_set(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer, artifact_uri="s3://bucket/receipts/test.json")
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.artifact.uri"] == "s3://bucket/receipts/test.json"

    def test_artifact_uri_absent_when_not_provided(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert "sanna.artifact.uri" not in span.attributes


# =============================================================================
# TEST 9: content_hash is valid SHA-256
# =============================================================================

class TestContentHash:
    def test_content_hash_is_sha256(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt()

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        content_hash = span.attributes["sanna.artifact.content_hash"]

        # Verify it's a valid 64-char hex string
        assert len(content_hash) == 64
        int(content_hash, 16)  # raises if not hex

        # Verify it matches direct computation
        expected = _content_hash(receipt)
        assert content_hash == expected

    def test_content_hash_deterministic(self):
        receipt = _pass_receipt()
        assert _content_hash(receipt) == _content_hash(receipt)

    def test_content_hash_changes_on_modification(self):
        receipt = _pass_receipt()
        hash1 = _content_hash(receipt)
        receipt["status"] = "FAIL"
        hash2 = _content_hash(receipt)
        assert hash1 != hash2


# =============================================================================
# TEST 10: evaluation_coverage.pct calculated correctly
# =============================================================================

class TestEvaluationCoverage:
    def test_coverage_from_evaluation_coverage_block(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(evaluation_coverage={
            "total_invariants": 5,
            "evaluated": 3,
            "not_checked": 2,
            "coverage_basis_points": 6000,
        })

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        assert span.attributes["sanna.evaluation_coverage.pct"] == 60.0

    def test_coverage_from_checks_fallback(self, tracer_and_exporter):
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(checks=[
            {"check_id": "C1", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "C2", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "INV_CUSTOM_1", "passed": True, "severity": "info", "evidence": None, "status": "NOT_CHECKED"},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        # 2 of 3 checks evaluated
        assert abs(span.attributes["sanna.evaluation_coverage.pct"] - 66.666) < 1.0

    def test_helper_function_direct(self):
        assert _evaluation_coverage_pct({"checks": []}) == 100.0
        assert _evaluation_coverage_pct({
            "evaluation_coverage": {"coverage_basis_points": 10000}
        }) == 100.0
        assert _evaluation_coverage_pct({
            "evaluation_coverage": {"coverage_basis_points": 5000}
        }) == 50.0


# =============================================================================
# TEST 11: BatchSpanProcessor integration
# =============================================================================

class TestBatchSpanProcessor:
    def test_exporter_with_batch_processor(self):
        """SannaOTelExporter works as a delegate with BatchSpanProcessor."""
        collector = InMemorySpanExporter()
        sanna_exporter = SannaOTelExporter(delegate=collector)
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(sanna_exporter))
        tracer = provider.get_tracer("sanna.test")

        receipt = _pass_receipt()
        receipt_to_span(receipt, tracer)
        provider.force_flush()

        # The SannaOTelExporter should have forwarded sanna spans to the collector
        spans = collector.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].attributes["sanna.receipt.id"] == "test-trace-001"

        provider.shutdown()

    def test_exporter_without_delegate(self):
        """SannaOTelExporter works without a delegate (just logs)."""
        sanna_exporter = SannaOTelExporter()
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(sanna_exporter))
        tracer = provider.get_tracer("sanna.test")

        receipt = _pass_receipt()
        receipt_to_span(receipt, tracer)
        provider.force_flush()
        provider.shutdown()
        # No crash = success


# =============================================================================
# TEST 12: v0.6.4 receipt (no extensions, no authority) converts cleanly
# =============================================================================

class TestBackwardCompatibility:
    def test_v064_receipt_converts(self, tracer_and_exporter):
        """Receipt without v0.7.0 sections still converts to span."""
        tracer, exporter, provider = tracer_and_exporter
        receipt = {
            "schema_version": "0.1",
            "tool_version": "0.6.4",
            "checks_version": "2",
            "receipt_id": "legacy123",
            "receipt_fingerprint": "abcdef1234567890",
            "correlation_id": "legacy-trace-001",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "inputs": {"query": "test", "context": "old context"},
            "outputs": {"response": "old response"},
            "context_hash": "1111111111111111",
            "output_hash": "2222222222222222",
            "checks": [
                {"check_id": "C1", "passed": True, "severity": "info", "evidence": None},
            ],
            "checks_passed": 1,
            "checks_failed": 0,
            "status": "PASS",
            "constitution_ref": None,
            "enforcement": None,
        }

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        attrs = dict(span.attributes)
        assert attrs["sanna.receipt.id"] == "legacy-trace-001"
        assert attrs["sanna.status"] == "PASS"
        assert attrs["sanna.authority.decision"] == ""
        assert attrs["sanna.escalation.triggered"] is False
        assert attrs["sanna.source_trust.flags"] == 0
        # No crash, no missing required attributes


# =============================================================================
# UNIT TESTS: helper functions
# =============================================================================

class TestHelpers:
    def test_check_status_pass(self):
        checks = [{"check_id": "C1", "passed": True}]
        assert _check_status(checks, "C1") == "pass"

    def test_check_status_fail(self):
        checks = [{"check_id": "C1", "passed": False}]
        assert _check_status(checks, "C1") == "fail"

    def test_check_status_absent(self):
        checks = [{"check_id": "C1", "passed": True}]
        assert _check_status(checks, "C5") == "absent"

    def test_check_status_not_checked(self):
        checks = [{"check_id": "INV_CUSTOM", "passed": True, "status": "NOT_CHECKED"}]
        assert _check_status(checks, "INV_CUSTOM") == "not_checked"


# =============================================================================
# TEST: content_hash uses Sanna canonical JSON
# =============================================================================

class TestContentHashCanonical:
    def test_non_ascii_content_matches_canonical(self):
        """content_hash must use canonical_json_bytes, not json.dumps."""
        from sanna.hashing import canonical_json_bytes

        receipt = _pass_receipt(
            inputs={"query": "What is café?", "context": "Le café ☕ est délicieux 🇫🇷"},
            outputs={"response": "Café means coffee — très bon!"},
        )
        expected = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        assert _content_hash(receipt) == expected

    def test_unicode_emoji_receipt(self):
        """Receipts with emoji produce correct canonical hash."""
        from sanna.hashing import canonical_json_bytes

        receipt = _pass_receipt(
            inputs={"query": "🤖💡", "context": "日本語テスト"},
            outputs={"response": "Ответ на русском"},
        )
        expected = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        assert _content_hash(receipt) == expected


# =============================================================================
# TEST: namespaced check IDs map correctly to C1-C5
# =============================================================================

class TestNamespacedCheckIDs:
    def test_namespaced_check_ids_populate_attributes(self, tracer_and_exporter):
        """Constitution-driven receipts use namespaced check_id values."""
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(checks=[
            {"check_id": "sanna.context_contradiction", "check_impl": "sanna.context_contradiction", "name": "C1", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "sanna.unmarked_inference", "check_impl": "sanna.unmarked_inference", "name": "C2", "passed": False, "severity": "warning", "evidence": "unmarked"},
            {"check_id": "sanna.false_certainty", "check_impl": "sanna.false_certainty", "name": "C3", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "sanna.conflict_collapse", "check_impl": "sanna.conflict_collapse", "name": "C4", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "sanna.premature_compression", "check_impl": "sanna.premature_compression", "name": "C5", "passed": False, "severity": "warning", "evidence": "compressed"},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        attrs = dict(span.attributes)
        assert attrs["sanna.check.c1.status"] == "pass"
        assert attrs["sanna.check.c2.status"] == "fail"
        assert attrs["sanna.check.c3.status"] == "pass"
        assert attrs["sanna.check.c4.status"] == "pass"
        assert attrs["sanna.check.c5.status"] == "fail"

    def test_mixed_legacy_and_namespaced_ids(self, tracer_and_exporter):
        """Receipt mixing legacy C1/C2 and namespaced IDs for C3-C5."""
        tracer, exporter, provider = tracer_and_exporter
        receipt = _pass_receipt(checks=[
            {"check_id": "C1", "name": "Context Contradiction", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "C2", "name": "Mark Inferences", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "sanna.false_certainty", "check_impl": "sanna.false_certainty", "name": "C3", "passed": False, "severity": "critical", "evidence": "overcertain"},
            {"check_id": "sanna.conflict_collapse", "check_impl": "sanna.conflict_collapse", "name": "C4", "passed": True, "severity": "info", "evidence": None},
            {"check_id": "sanna.premature_compression", "check_impl": "sanna.premature_compression", "name": "C5", "passed": True, "severity": "info", "evidence": None},
        ])

        receipt_to_span(receipt, tracer)
        provider.force_flush()

        span = exporter.get_finished_spans()[0]
        attrs = dict(span.attributes)
        assert attrs["sanna.check.c1.status"] == "pass"
        assert attrs["sanna.check.c2.status"] == "pass"
        assert attrs["sanna.check.c3.status"] == "fail"
        assert attrs["sanna.check.c4.status"] == "pass"
        assert attrs["sanna.check.c5.status"] == "pass"

    def test_check_impl_field_used_for_matching(self):
        """check_impl field resolves namespaced ID even if check_id differs."""
        checks = [
            {"check_id": "INV_NO_FABRICATION", "check_impl": "sanna.context_contradiction", "passed": True},
        ]
        assert _check_status(checks, "C1") == "pass"

    def test_namespaced_check_status_helper(self):
        """_check_status handles namespaced IDs directly."""
        checks = [
            {"check_id": "sanna.context_contradiction", "passed": True},
            {"check_id": "sanna.unmarked_inference", "passed": False},
        ]
        assert _check_status(checks, "C1") == "pass"
        assert _check_status(checks, "C2") == "fail"
        assert _check_status(checks, "C3") == "absent"
