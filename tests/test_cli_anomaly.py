"""Tests for cli_invocation_anomaly emission (SAN-397).

Covers: anomaly_tracking.cli opt-in, extension shape, parent_receipts chain,
verifier pass, fallback to standard receipt when opt-out or manifest failed.
"""

from __future__ import annotations

import errno
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sanna.interceptors import patch_subprocess, unpatch_subprocess
from sanna.sinks.sink import ReceiptSink, SinkResult
from sanna.verify_manifest import verify_invocation_anomaly_receipt


CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
CLI_ANOMALY_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-anomaly-test.yaml")
CLI_TEST_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-test.yaml")


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
    unpatch_subprocess()


@pytest.fixture
def sink():
    return CaptureSink()


@pytest.fixture
def anomaly_sink(sink):
    """Patch subprocess with anomaly_tracking.cli=True constitution."""
    patch_subprocess(
        constitution_path=CLI_ANOMALY_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    # session_manifest emitted at startup; clear to isolate per-test assertions
    sink.receipts.clear()
    return sink


@pytest.fixture
def no_anomaly_sink(sink):
    """Patch subprocess with standard constitution (anomaly_tracking.cli=False)."""
    patch_subprocess(
        constitution_path=CLI_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    sink.receipts.clear()
    return sink


class TestCliInvocationAnomaly:
    """SAN-397: CLI interceptor emits cli_invocation_anomaly when opted in."""

    def test_anomaly_emitted_when_opted_in_and_command_suppressed(self, anomaly_sink):
        """anomaly_tracking.cli=True + suppressed command -> cli_invocation_anomaly."""
        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "-rf", "/tmp/x"])

        anomaly_receipts = anomaly_sink.by_event_type("cli_invocation_anomaly")
        assert len(anomaly_receipts) == 1, "Expected exactly one cli_invocation_anomaly receipt"

    def test_anomaly_not_emitted_when_opted_out(self, no_anomaly_sink):
        """anomaly_tracking.cli=False (default) + suppressed command -> cli_invocation_halted."""
        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "-rf", "/tmp/x"])

        # Should emit cli_invocation_halted, NOT cli_invocation_anomaly
        assert len(no_anomaly_sink.by_event_type("cli_invocation_anomaly")) == 0
        assert len(no_anomaly_sink.by_event_type("cli_invocation_halted")) == 1

    def test_anomaly_has_correct_extension_shape(self, anomaly_sink):
        """extensions['com.sanna.anomaly']['attempted_command'] == binary_name."""
        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])

        receipt = anomaly_sink.by_event_type("cli_invocation_anomaly")[0]
        ext = receipt.get("extensions", {}).get("com.sanna.anomaly", {})
        assert ext.get("attempted_command") == "rm"
        assert ext.get("suppression_basis") == "session_manifest"

    def test_anomaly_has_parent_receipts_chain(self, sink):
        """parent_receipts contains the CLI session_manifest's full_fingerprint."""
        patch_subprocess(
            constitution_path=CLI_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        manifest_receipts = sink.by_event_type("session_manifest")
        assert len(manifest_receipts) == 1
        manifest_fp = manifest_receipts[0].get("full_fingerprint")
        assert manifest_fp is not None

        sink.receipts.clear()

        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])

        anomaly_receipts = sink.by_event_type("cli_invocation_anomaly")
        assert len(anomaly_receipts) == 1
        parent_receipts = anomaly_receipts[0].get("parent_receipts") or []
        assert manifest_fp in parent_receipts, (
            f"Manifest fingerprint {manifest_fp[:16]} not in parent_receipts {parent_receipts}"
        )

    def test_anomaly_receipt_passes_verifier(self, sink):
        """cli_invocation_anomaly passes verify_invocation_anomaly_receipt (SAN-358)."""
        patch_subprocess(
            constitution_path=CLI_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])

        anomaly_receipts = sink.by_event_type("cli_invocation_anomaly")
        assert len(anomaly_receipts) == 1
        receipt = anomaly_receipts[0]

        # With receipt_set=None: cross-receipt checks skip as WARN
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        failed = [c for c in checks if c.status == "FAIL"]
        assert not failed, f"Verifier FAIL checks: {failed}"

        # With receipt_set: cross-receipt parent resolution
        checks_full = verify_invocation_anomaly_receipt(receipt, receipt_set=sink.receipts)
        failed_full = [c for c in checks_full if c.status == "FAIL"]
        assert not failed_full, f"Verifier FAIL checks (full set): {failed_full}"

    def test_non_suppressed_halt_still_emits_standard_receipt(self, anomaly_sink):
        """Command denied by strict mode (not in manifest suppressed) -> cli_invocation_halted."""
        import subprocess
        # 'wget' is not listed in cli-anomaly-test.yaml at all (strict mode -> halt)
        with pytest.raises(FileNotFoundError):
            subprocess.run(["wget", "https://example.com"])

        # Not a suppressed pattern -> standard halted
        assert len(anomaly_sink.by_event_type("cli_invocation_anomaly")) == 0
        assert len(anomaly_sink.by_event_type("cli_invocation_halted")) == 1

    def test_no_anomaly_when_manifest_failed(self, sink):
        """If manifest_full_fingerprint is None (manifest failed), standard halted fires."""
        from sanna.interceptors import subprocess_interceptor

        patch_subprocess(
            constitution_path=CLI_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        # Simulate manifest fingerprint missing (e.g., manifest generation failure)
        subprocess_interceptor._state["manifest_full_fingerprint"] = None
        sink.receipts.clear()

        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])

        # Without fingerprint, anomaly path skips -> standard halted
        assert len(sink.by_event_type("cli_invocation_anomaly")) == 0
        assert len(sink.by_event_type("cli_invocation_halted")) == 1

    def test_anomaly_status_is_fail(self, anomaly_sink):
        """cli_invocation_anomaly receipt has status=FAIL."""
        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])

        receipt = anomaly_sink.by_event_type("cli_invocation_anomaly")[0]
        assert receipt.get("status") == "FAIL"

    def test_anomaly_enforcement_surface(self, anomaly_sink):
        """cli_invocation_anomaly receipt has enforcement_surface=cli_interceptor."""
        import subprocess
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])

        receipt = anomaly_sink.by_event_type("cli_invocation_anomaly")[0]
        assert receipt.get("enforcement_surface") == "cli_interceptor"

    def test_anomaly_raises_filenotfounderror(self, anomaly_sink):
        """Anomaly path raises FileNotFoundError like standard halted path."""
        import subprocess
        exc = None
        try:
            subprocess.run(["rm", "/tmp/x"])
        except FileNotFoundError as e:
            exc = e
        assert exc is not None
        assert exc.errno == errno.ENOENT
        assert exc.filename == "rm"


@pytest.mark.skip(
    reason=(
        "SAN-487: blocked on authority-bypass design gap fix. "
        "CLI/HTTP interceptor enforcement state populated from redacted "
        "manifest under content_mode=redacted, so the anomaly emission "
        "path is unreachable in tests. Re-enable when SAN-487 fixes the "
        "state-population to read from constitution (raw) instead of "
        "manifest (redacted)."
    )
)
class TestCliAnomalyRedaction:
    """SAN-406: Section 2.22.5 field-level redaction at subprocess_interceptor emission site."""

    @pytest.fixture(autouse=True)
    def cleanup(self):
        yield
        unpatch_subprocess()

    def test_redacted_mode_masks_attempted_command(self, sink):
        import re
        import subprocess
        patch_subprocess(
            constitution_path=CLI_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
            content_mode="redacted",
        )
        sink.receipts.clear()
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])
        receipts = sink.by_event_type("cli_invocation_anomaly")
        assert len(receipts) == 1
        ext = receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        assert ext.get("attempted_command") == "<redacted>"

    def test_hashes_only_mode_hashes_attempted_command(self, sink):
        import re
        import subprocess
        _SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
        patch_subprocess(
            constitution_path=CLI_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
            content_mode="hashes_only",
        )
        sink.receipts.clear()
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x"])
        receipts = sink.by_event_type("cli_invocation_anomaly")
        assert len(receipts) == 1
        ext = receipts[0].get("extensions", {}).get("com.sanna.anomaly", {})
        val = ext.get("attempted_command")
        assert _SHA256_HEX_RE.match(val), f"{val!r} not 64-hex lowercase"

    def test_hashes_only_is_deterministic_across_calls(self, sink):
        import subprocess
        patch_subprocess(
            constitution_path=CLI_ANOMALY_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
            content_mode="hashes_only",
        )
        sink.receipts.clear()
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x1"])
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "/tmp/x2"])
        receipts = sink.by_event_type("cli_invocation_anomaly")
        assert len(receipts) == 2
        hash1 = receipts[0]["extensions"]["com.sanna.anomaly"]["attempted_command"]
        hash2 = receipts[1]["extensions"]["com.sanna.anomaly"]["attempted_command"]
        assert hash1 == hash2, "Same command should hash to same value"
