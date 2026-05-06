"""Tests for api_invocation_anomaly emission (SAN-397).

Covers: anomaly_tracking.http opt-in, extension shape, parent_receipts chain,
verifier pass, fallback to standard receipt when opt-out or manifest failed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sanna.interceptors import patch_http, unpatch_http
from sanna.sinks.sink import ReceiptSink, SinkResult
from sanna.verify_manifest import verify_invocation_anomaly_receipt


CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
API_ANOMALY_CONSTITUTION = str(CONSTITUTIONS_DIR / "api-anomaly-test.yaml")
API_TEST_CONSTITUTION = str(CONSTITUTIONS_DIR / "api-test.yaml")


class CaptureSink(ReceiptSink):
    def __init__(self):
        self.receipts: list[dict] = []

    def store(self, receipt: dict) -> SinkResult:
        self.receipts.append(receipt)
        return SinkResult(stored=1)

    @property
    def last(self) -> dict:
        return self.receipts[-1]

    @property
    def count(self) -> int:
        return len(self.receipts)

    def by_event_type(self, event_type: str) -> list[dict]:
        return [r for r in self.receipts if r.get("event_type") == event_type]


@pytest.fixture(autouse=True)
def cleanup():
    yield
    unpatch_http()


@pytest.fixture
def sink():
    return CaptureSink()


@pytest.fixture
def anomaly_sink(sink):
    """Patch HTTP with anomaly_tracking.http=True constitution."""
    patch_http(
        constitution_path=API_ANOMALY_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    sink.receipts.clear()
    return sink


@pytest.fixture
def no_anomaly_sink(sink):
    """Patch HTTP with standard constitution (anomaly_tracking.http=False)."""
    patch_http(
        constitution_path=API_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    sink.receipts.clear()
    return sink


def _call_suppressed_url(url="https://internal.evil.com/api/data"):
    """Attempt an HTTP call that should be suppressed."""
    from sanna.interceptors.http_interceptor import _enforce_http_call
    _enforce_http_call("GET", url, {}, None)


class TestHttpInvocationAnomaly:
    """SAN-397: HTTP interceptor emits api_invocation_anomaly when opted in."""

    def test_anomaly_emitted_when_opted_in_and_endpoint_suppressed(self, anomaly_sink):
        """anomaly_tracking.http=True + suppressed endpoint -> api_invocation_anomaly."""
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        anomaly_receipts = anomaly_sink.by_event_type("api_invocation_anomaly")
        assert len(anomaly_receipts) == 1, "Expected exactly one api_invocation_anomaly receipt"

    def test_anomaly_not_emitted_when_opted_out(self, no_anomaly_sink):
        """anomaly_tracking.http=False (default) + suppressed endpoint -> api_invocation_halted."""
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        assert len(no_anomaly_sink.by_event_type("api_invocation_anomaly")) == 0
        assert len(no_anomaly_sink.by_event_type("api_invocation_halted")) == 1

    def test_anomaly_has_correct_extension_shape(self, anomaly_sink):
        """extensions['com.sanna.anomaly']['attempted_endpoint'] == matched_pattern."""
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        receipt = anomaly_sink.by_event_type("api_invocation_anomaly")[0]
        ext = receipt.get("extensions", {}).get("com.sanna.anomaly", {})
        assert ext.get("attempted_endpoint") == "https://internal.evil.com/*"
        assert ext.get("suppression_basis") == "session_manifest"

    def test_anomaly_has_parent_receipts_chain(self, sink):
        """parent_receipts contains the HTTP session_manifest's full_fingerprint."""
        patch_http(
            constitution_path=API_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        manifest_receipts = sink.by_event_type("session_manifest")
        assert len(manifest_receipts) == 1
        manifest_fp = manifest_receipts[0].get("full_fingerprint")
        assert manifest_fp is not None

        sink.receipts.clear()

        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        anomaly_receipts = sink.by_event_type("api_invocation_anomaly")
        assert len(anomaly_receipts) == 1
        parent_receipts = anomaly_receipts[0].get("parent_receipts") or []
        assert manifest_fp in parent_receipts, (
            f"Manifest fingerprint {manifest_fp[:16]} not in parent_receipts {parent_receipts}"
        )

    def test_anomaly_receipt_passes_verifier(self, sink):
        """api_invocation_anomaly passes verify_invocation_anomaly_receipt (SAN-358)."""
        patch_http(
            constitution_path=API_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        anomaly_receipts = sink.by_event_type("api_invocation_anomaly")
        assert len(anomaly_receipts) == 1
        receipt = anomaly_receipts[0]

        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        failed = [c for c in checks if c.status == "FAIL"]
        assert not failed, f"Verifier FAIL checks: {failed}"

        checks_full = verify_invocation_anomaly_receipt(receipt, receipt_set=sink.receipts)
        failed_full = [c for c in checks_full if c.status == "FAIL"]
        assert not failed_full, f"Verifier FAIL checks (full set): {failed_full}"

    def test_non_suppressed_halt_still_emits_standard_receipt(self, anomaly_sink):
        """URL halted by strict mode (not in suppressed patterns) -> api_invocation_halted."""
        # Use api-anomaly-test.yaml which is strict and doesn't list this domain
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://unknown-blocked.com/api")

        # Not a suppressed pattern -> standard halted
        assert len(anomaly_sink.by_event_type("api_invocation_anomaly")) == 0
        assert len(anomaly_sink.by_event_type("api_invocation_halted")) == 1

    def test_no_anomaly_when_manifest_failed(self, sink):
        """If manifest_full_fingerprint is None (manifest failed), standard halted fires."""
        from sanna.interceptors import http_interceptor

        patch_http(
            constitution_path=API_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        http_interceptor._http_state["manifest_full_fingerprint"] = None
        sink.receipts.clear()

        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        assert len(sink.by_event_type("api_invocation_anomaly")) == 0
        assert len(sink.by_event_type("api_invocation_halted")) == 1

    def test_anomaly_status_is_fail(self, anomaly_sink):
        """api_invocation_anomaly receipt has status=FAIL."""
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        receipt = anomaly_sink.by_event_type("api_invocation_anomaly")[0]
        assert receipt.get("status") == "FAIL"

    def test_anomaly_enforcement_surface(self, anomaly_sink):
        """api_invocation_anomaly receipt has enforcement_surface=http_interceptor."""
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")

        receipt = anomaly_sink.by_event_type("api_invocation_anomaly")[0]
        assert receipt.get("enforcement_surface") == "http_interceptor"

    def test_anomaly_raises_connectionerror(self, anomaly_sink):
        """Anomaly path raises ConnectionError like standard halted path."""
        exc = None
        try:
            _call_suppressed_url("https://internal.evil.com/api/data")
        except ConnectionError as e:
            exc = e
        assert exc is not None

    def test_second_suppressed_pattern_triggers_anomaly(self, anomaly_sink):
        """Second suppressed pattern also triggers anomaly emission."""
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://blocked.example.com/api/endpoint")

        anomaly_receipts = anomaly_sink.by_event_type("api_invocation_anomaly")
        assert len(anomaly_receipts) == 1
        ext = anomaly_receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        assert ext.get("attempted_endpoint") == "https://blocked.example.com/api/*"


class TestHttpAnomalyRedaction:
    """SAN-406: Section 2.22.5 field-level redaction at http_interceptor emission site."""

    @pytest.fixture(autouse=True)
    def cleanup(self):
        yield
        unpatch_http()

    def test_redacted_mode_masks_attempted_endpoint(self, sink):
        import re
        patch_http(
            constitution_path=API_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
            content_mode="redacted",
        )
        sink.receipts.clear()
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")
        receipts = sink.by_event_type("api_invocation_anomaly")
        assert len(receipts) == 1
        ext = receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        assert ext.get("attempted_endpoint") == "<redacted>"

    def test_hashes_only_mode_hashes_attempted_endpoint(self, sink):
        import re
        _SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
        patch_http(
            constitution_path=API_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
            content_mode="hashes_only",
        )
        sink.receipts.clear()
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")
        receipts = sink.by_event_type("api_invocation_anomaly")
        assert len(receipts) == 1
        ext = receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        val = ext.get("attempted_endpoint")
        assert _SHA256_HEX_RE.match(val), f"{val!r} not 64-hex lowercase"

    def test_hashes_only_is_deterministic_across_calls(self, sink):
        patch_http(
            constitution_path=API_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
            content_mode="hashes_only",
        )
        sink.receipts.clear()
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/data")
        with pytest.raises(ConnectionError):
            _call_suppressed_url("https://internal.evil.com/api/other")
        receipts = sink.by_event_type("api_invocation_anomaly")
        assert len(receipts) == 2
        hash1 = receipts[0]["extensions"]["com.sanna.anomaly"]["attempted_endpoint"]
        hash2 = receipts[1]["extensions"]["com.sanna.anomaly"]["attempted_endpoint"]
        assert hash1 == hash2, "Same pattern should hash to same value"
