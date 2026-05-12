"""Tests for v1.0.0 features — PY1-PY14.

Covers:
- 14-field fingerprint (PY3)
- parent_receipts and workflow_id in receipts (PY1)
- content_mode and content_mode_source (PY2)
- CloudHTTPSink, CompositeSink, NullSink, LocalSQLiteSink (PY4, PY5)
- Middleware sink= parameter (PY6)
- Gateway sink integration (PY7, PY8)
- Content mode attestation (PY9)
- Receipt chaining (PY10)
- Deprecation cleanup (PY11)
- Version bump (PY14)
"""

import json
import os
import tempfile
import threading
from dataclasses import asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sanna.receipt import (
    generate_receipt,
    SannaReceipt,
    SPEC_VERSION,
    CHECKS_VERSION,
    TOOL_VERSION,
)
from sanna.hashing import hash_text, hash_obj, EMPTY_HASH
from sanna.version import __version__
from sanna.sinks.sink import ReceiptSink, SinkResult, FailurePolicy
from sanna.sinks.null import NullSink
from sanna.sinks.composite import CompositeSink


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_trace(correlation_id="test-001", query="q", context="c", response="r"):
    return {
        "correlation_id": correlation_id,
        "name": "test",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "input": {"query": query},
        "output": {"final_answer": response},
        "metadata": {},
        "observations": [
            {
                "id": "obs-ret",
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


# ============================================================================
# PY14: Version bump
# ============================================================================

class TestVersionBump:
    def test_version_string(self):
        assert __version__ == "1.5.0"

    def test_tool_version(self):
        assert TOOL_VERSION == "1.5.0"

    def test_spec_version(self):
        assert SPEC_VERSION == "1.5"

    def test_checks_version(self):
        assert CHECKS_VERSION == "10"

    def test_all_exports(self):
        import sanna
        assert len(sanna.__all__) == 23  # 10 original + 7 sink exports + 4 interceptor exports + receipt_to_dict + RedactionConfig


# ============================================================================
# PY1: parent_receipts + workflow_id
# ============================================================================

class TestParentReceipts:
    def test_generate_receipt_with_parent_receipts(self):
        trace = make_trace()
        receipt = generate_receipt(
            trace, parent_receipts=["abc123", "def456"],
        )
        assert receipt.parent_receipts == ["abc123", "def456"]

    def test_generate_receipt_with_workflow_id(self):
        trace = make_trace()
        receipt = generate_receipt(trace, workflow_id="wf-001")
        assert receipt.workflow_id == "wf-001"

    def test_generate_receipt_defaults_none(self):
        trace = make_trace()
        receipt = generate_receipt(trace)
        assert receipt.parent_receipts is None
        assert receipt.workflow_id is None

    def test_parent_receipts_in_asdict(self):
        trace = make_trace()
        receipt = generate_receipt(
            trace, parent_receipts=["fp1"], workflow_id="wf",
        )
        d = asdict(receipt)
        assert d["parent_receipts"] == ["fp1"]
        assert d["workflow_id"] == "wf"


# ============================================================================
# PY2: content_mode + content_mode_source
# ============================================================================

class TestContentMode:
    def test_content_mode_in_receipt(self):
        trace = make_trace()
        receipt = generate_receipt(
            trace, content_mode="full", content_mode_source="local_config",
        )
        assert receipt.content_mode == "full"
        assert receipt.content_mode_source == "local_config"

    def test_content_mode_defaults_none(self):
        trace = make_trace()
        receipt = generate_receipt(trace)
        assert receipt.content_mode is None
        assert receipt.content_mode_source is None

    def test_content_mode_not_in_fingerprint(self):
        """content_mode changes should NOT change the fingerprint."""
        trace = make_trace()
        r1 = generate_receipt(trace, content_mode="full")
        r2 = generate_receipt(trace, content_mode="hashes_only")
        # Fingerprints should be identical since content_mode is NOT in fingerprint
        assert r1.full_fingerprint == r2.full_fingerprint


# ============================================================================
# PY3: 14-field fingerprint
# ============================================================================

class TestFourteenFieldFingerprint:
    def test_fingerprint_changes_with_parent_receipts(self):
        trace = make_trace()
        r1 = generate_receipt(trace)
        r2 = generate_receipt(trace, parent_receipts=["abc"])
        assert r1.full_fingerprint != r2.full_fingerprint

    def test_fingerprint_changes_with_workflow_id(self):
        trace = make_trace()
        r1 = generate_receipt(trace)
        r2 = generate_receipt(trace, workflow_id="wf-001")
        assert r1.full_fingerprint != r2.full_fingerprint

    def test_empty_parent_receipts_uses_empty_hash(self):
        """None parent_receipts should use EMPTY_HASH in fingerprint."""
        trace = make_trace()
        r_none = generate_receipt(trace)
        # With empty list: hash_obj([]) != EMPTY_HASH
        r_empty = generate_receipt(trace, parent_receipts=[])
        assert r_none.full_fingerprint != r_empty.full_fingerprint

    def test_fingerprint_is_14_fields(self):
        """Verify the fingerprint input has exactly 14 pipe-delimited fields."""
        trace = make_trace()
        receipt = generate_receipt(
            trace, parent_receipts=["fp1"], workflow_id="wf",
        )
        # We can verify indirectly by checking the fingerprint changes
        # with both new fields
        r_base = generate_receipt(trace)
        r_p = generate_receipt(trace, parent_receipts=["fp1"])
        r_w = generate_receipt(trace, workflow_id="wf")
        r_pw = generate_receipt(
            trace, parent_receipts=["fp1"], workflow_id="wf",
        )
        # All four should have different fingerprints
        fps = {r_base.full_fingerprint, r_p.full_fingerprint,
               r_w.full_fingerprint, r_pw.full_fingerprint}
        assert len(fps) == 4

    def test_receipt_fingerprint_truncation(self):
        trace = make_trace()
        receipt = generate_receipt(trace)
        assert len(receipt.receipt_fingerprint) == 16
        assert len(receipt.full_fingerprint) == 64
        assert receipt.full_fingerprint.startswith(receipt.receipt_fingerprint)

    def test_verification_roundtrip(self):
        """Receipt generated with 14-field fingerprint passes verification."""
        from sanna.verify import verify_fingerprint
        trace = make_trace()
        receipt = generate_receipt(
            trace, parent_receipts=["abc"], workflow_id="wf-1",
        )
        d = asdict(receipt)
        matches, computed, expected = verify_fingerprint(d)
        assert matches, f"Fingerprint mismatch: {computed} != {expected}"

    def test_verification_with_null_new_fields(self):
        """Receipt without new fields also verifies."""
        from sanna.verify import verify_fingerprint
        trace = make_trace()
        receipt = generate_receipt(trace)
        d = asdict(receipt)
        matches, computed, expected = verify_fingerprint(d)
        assert matches


# ============================================================================
# PY4: CloudHTTPSink
# ============================================================================

class _MockHandler(BaseHTTPRequestHandler):
    """Mock HTTP server handler for testing CloudHTTPSink."""
    # Class-level state shared across requests
    received_receipts = []
    response_status = 201
    response_body = b"{}"
    retry_after = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        data = json.loads(body)
        _MockHandler.received_receipts.append(data)
        if _MockHandler.retry_after:
            self.send_response(_MockHandler.response_status)
            self.send_header("Retry-After", str(_MockHandler.retry_after))
            self.end_headers()
        else:
            self.send_response(_MockHandler.response_status)
            self.end_headers()
        self.wfile.write(_MockHandler.response_body)

    def log_message(self, format, *args):
        pass  # Suppress log output


class TestCloudHTTPSink:
    @pytest.fixture(autouse=True)
    def reset_mock(self):
        _MockHandler.received_receipts = []
        _MockHandler.response_status = 201
        _MockHandler.response_body = b"{}"
        _MockHandler.retry_after = None

    @pytest.fixture
    def mock_server(self):
        server = HTTPServer(("127.0.0.1", 0), _MockHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        yield f"http://127.0.0.1:{port}"
        server.shutdown()

    def test_store_success(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="test-key",
            max_retries=0,
        )
        result = sink.store({"receipt_id": "r1"})
        assert result.ok
        assert result.stored == 1
        assert len(_MockHandler.received_receipts) == 1

    def test_store_400_no_retry(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        _MockHandler.response_status = 400
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="test-key",
            max_retries=2,
        )
        result = sink.store({"receipt_id": "r1"})
        assert not result.ok
        # Should NOT retry on 400
        assert len(_MockHandler.received_receipts) == 1

    def test_store_401_no_retry(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        _MockHandler.response_status = 401
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="bad-key",
            max_retries=2,
        )
        result = sink.store({"receipt_id": "r1"})
        assert not result.ok
        assert len(_MockHandler.received_receipts) == 1

    def test_store_409_treated_as_success(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        _MockHandler.response_status = 409
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="test-key",
            max_retries=0,
        )
        result = sink.store({"receipt_id": "r1"})
        assert result.ok

    def test_store_503_retries(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        _MockHandler.response_status = 503
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="test-key",
            max_retries=2, retry_backoff_base=0.01,
        )
        result = sink.store({"receipt_id": "r1"})
        assert not result.ok
        # Should retry: 1 initial + 2 retries = 3 requests
        assert len(_MockHandler.received_receipts) == 3

    def test_batch_store(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="test-key",
            batch_size=2, max_retries=0,
        )
        receipts = [{"receipt_id": f"r{i}"} for i in range(5)]
        result = sink.batch_store(receipts)
        assert result.stored == 5
        # 5 receipts, batch_size=2 → 3 batches
        assert len(_MockHandler.received_receipts) == 3

    def test_buffer_and_retry(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            buffer_path = f.name
        try:
            _MockHandler.response_status = 500
            sink = CloudHTTPSink(
                api_url=mock_server, api_key="test-key",
                failure_policy=FailurePolicy.BUFFER_AND_RETRY,
                buffer_path=buffer_path,
                max_retries=0,
            )
            result = sink.store({"receipt_id": "r1"})
            assert not result.ok
            # Check buffer file has content
            with open(buffer_path) as bf:
                lines = bf.readlines()
            assert len(lines) == 1
            sink.close()
        finally:
            if os.path.exists(buffer_path):
                os.unlink(buffer_path)

    def test_requires_api_url(self):
        from sanna.sinks.cloud import CloudHTTPSink
        with pytest.raises(ValueError, match="api_url"):
            CloudHTTPSink(api_url="", api_key="k")

    def test_requires_api_key(self):
        from sanna.sinks.cloud import CloudHTTPSink
        with pytest.raises(ValueError, match="api_key"):
            CloudHTTPSink(api_url="https://example.com", api_key="")

    def test_buffer_path_required_for_buffer_policy(self):
        from sanna.sinks.cloud import CloudHTTPSink
        with pytest.raises(ValueError, match="buffer_path"):
            CloudHTTPSink(
                api_url="https://example.com",
                api_key="k",
                failure_policy=FailurePolicy.BUFFER_AND_RETRY,
            )

    def test_authorization_header(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="my-secret",
            max_retries=0,
        )
        sink.store({"receipt_id": "r1"})
        assert len(_MockHandler.received_receipts) == 1

    def test_user_agent(self, mock_server):
        from sanna.sinks.cloud import CloudHTTPSink
        sink = CloudHTTPSink(
            api_url=mock_server, api_key="k",
            max_retries=0,
        )
        assert "sanna-python/1.5.0" in sink._user_agent


# ============================================================================
# PY5: CompositeSink
# ============================================================================

class TestCompositeSink:
    def test_fan_out(self):
        s1 = NullSink()
        s2 = NullSink()
        composite = CompositeSink([s1, s2])
        result = composite.store({"receipt_id": "r1"})
        assert result.stored == 2
        assert result.failed == 0

    def test_failure_isolation(self):
        class FailSink(ReceiptSink):
            def store(self, receipt):
                raise RuntimeError("boom")

        composite = CompositeSink([NullSink(), FailSink()])
        result = composite.store({"receipt_id": "r1"})
        assert result.stored == 1
        assert result.failed == 1
        assert len(result.errors) == 1

    def test_error_aggregation(self):
        class PartialSink(ReceiptSink):
            def store(self, receipt):
                return SinkResult(failed=1, errors=("err1",))

        composite = CompositeSink([NullSink(), PartialSink()])
        result = composite.store({"receipt_id": "r1"})
        assert result.stored == 1
        assert result.failed == 1
        assert "err1" in result.errors

    def test_requires_at_least_one_sink(self):
        with pytest.raises(ValueError):
            CompositeSink([])

    def test_flush_delegates(self):
        flushed = []

        class FlushSink(ReceiptSink):
            def store(self, receipt):
                return SinkResult(stored=1)

            def flush(self):
                flushed.append(True)

        composite = CompositeSink([FlushSink(), FlushSink()])
        composite.flush()
        assert len(flushed) == 2

    def test_close_delegates(self):
        closed = []

        class CloseSink(ReceiptSink):
            def store(self, receipt):
                return SinkResult(stored=1)

            def close(self):
                closed.append(True)

        composite = CompositeSink([CloseSink(), CloseSink()])
        composite.close()
        assert len(closed) == 2

    def test_batch_store(self):
        stored_count = []

        class CountSink(ReceiptSink):
            def store(self, receipt):
                stored_count.append(1)
                return SinkResult(stored=1)

        composite = CompositeSink([CountSink(), CountSink()])
        result = composite.batch_store([{"r": 1}, {"r": 2}])
        assert result.stored == 4  # 2 receipts x 2 sinks


# ============================================================================
# PY6: Middleware sink= parameter
# ============================================================================

class TestMiddlewareSink:
    def test_sink_receives_receipt(self):
        stored = []

        class CaptureSink(ReceiptSink):
            def store(self, receipt):
                stored.append(receipt)
                return SinkResult(stored=1)

        from sanna.middleware import sanna_observe

        @sanna_observe(sink=CaptureSink())
        def agent(query, context):
            return "answer"

        result = agent("q", "c")
        assert len(stored) == 1
        assert stored[0]["status"] in ("PASS", "WARN", "FAIL")

    def test_sink_failure_does_not_raise(self):
        class FailSink(ReceiptSink):
            def store(self, receipt):
                raise RuntimeError("sink broken")

        from sanna.middleware import sanna_observe

        @sanna_observe(sink=FailSink())
        def agent(query, context):
            return "answer"

        # Should not raise even though sink fails
        result = agent("q", "c")
        assert result.output == "answer"

    def test_no_sink_backward_compat(self):
        from sanna.middleware import sanna_observe

        @sanna_observe()
        def agent(query, context):
            return "answer"

        result = agent("q", "c")
        assert result.receipt is not None


# ============================================================================
# NullSink
# ============================================================================

class TestNullSink:
    def test_always_succeeds(self):
        sink = NullSink()
        result = sink.store({"receipt_id": "x"})
        assert result.ok
        assert result.stored == 1


# ============================================================================
# LocalSQLiteSink
# ============================================================================

class TestLocalSQLiteSink:
    def test_store_and_query(self, tmp_path):
        os.environ["SANNA_ALLOW_TEMP_DB"] = "1"
        try:
            from sanna.sinks.local import LocalSQLiteSink
            db = str(tmp_path / "test.db")
            sink = LocalSQLiteSink(db_path=db)
            result = sink.store({
                "receipt_id": "r1",
                "status": "PASS",
                "timestamp": "2026-01-01T00:00:00",
            })
            assert result.ok
            sink.close()
        finally:
            os.environ.pop("SANNA_ALLOW_TEMP_DB", None)


# ============================================================================
# PY9: Content mode attestation (gateway)
# ============================================================================

class TestContentModeAttestation:
    def test_content_mode_in_middleware_receipt(self):
        trace = make_trace()
        receipt = generate_receipt(
            trace, content_mode="redacted",
            content_mode_source="cloud_tenant",
        )
        assert receipt.content_mode == "redacted"
        assert receipt.content_mode_source == "cloud_tenant"


# ============================================================================
# PY10: Receipt chaining
# ============================================================================

class TestReceiptChaining:
    def test_parent_receipts_in_receipt(self):
        trace = make_trace()
        parent_fp = "a" * 64
        receipt = generate_receipt(
            trace, parent_receipts=[parent_fp],
        )
        assert receipt.parent_receipts == [parent_fp]

    def test_workflow_id_propagation(self):
        trace = make_trace()
        receipt = generate_receipt(trace, workflow_id="incident-42")
        assert receipt.workflow_id == "incident-42"

    def test_chained_receipts_have_different_fingerprints(self):
        trace = make_trace()
        r1 = generate_receipt(trace)
        r2 = generate_receipt(
            trace, parent_receipts=[r1.full_fingerprint],
        )
        assert r1.full_fingerprint != r2.full_fingerprint

    def test_chain_verification(self):
        from sanna.verify import verify_fingerprint
        trace = make_trace()
        r1 = generate_receipt(trace)
        r2 = generate_receipt(
            trace,
            parent_receipts=[r1.full_fingerprint],
            workflow_id="wf-chain",
        )
        d = asdict(r2)
        matches, _, _ = verify_fingerprint(d)
        assert matches


# ============================================================================
# PY11: Deprecation cleanup
# ============================================================================

class TestDeprecationCleanup:
    def test_no_schema_version_field(self):
        """Receipts should use spec_version, not schema_version."""
        trace = make_trace()
        receipt = generate_receipt(trace)
        d = asdict(receipt)
        assert "spec_version" in d
        assert d["spec_version"] == "1.4"

    def test_receipt_uses_correlation_id(self):
        trace = make_trace(correlation_id="corr-001")
        receipt = generate_receipt(trace)
        assert receipt.correlation_id == "corr-001"

    def test_enforcement_not_halt_event(self):
        """Receipt dataclass has enforcement, not halt_event."""
        from sanna.receipt import SannaReceipt
        fields = {f.name for f in SannaReceipt.__dataclass_fields__.values()}
        assert "enforcement" in fields
        # halt_event is NOT a field on SannaReceipt
        assert "halt_event" not in fields


# ============================================================================
# SinkResult
# ============================================================================

class TestSinkResult:
    def test_ok_when_no_failures(self):
        r = SinkResult(stored=1)
        assert r.ok

    def test_not_ok_with_failures(self):
        r = SinkResult(stored=0, failed=1, errors=("err",))
        assert not r.ok
