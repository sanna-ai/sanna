"""Tests for drift analysis timestamp handling.

Ensures _parse_ts() and DriftAnalyzer handle naive timestamps,
"Z" suffix, and "+00:00" offset correctly without crashing.
"""

from datetime import datetime, timedelta, timezone

import pytest

from sanna.drift import DriftAnalyzer, _parse_ts
from sanna.store import ReceiptStore


def _make_receipt(receipt_id, timestamp, agent_name="ts-agent"):
    doc_id = f"{agent_name}/1.0.0"
    return {
        "receipt_id": receipt_id,
        "trace_id": f"trace-{receipt_id}",
        "timestamp": timestamp,
        "coherence_status": "PASS",
        "checks": [
            {"check_id": "C1", "name": "Context Contradiction",
             "passed": True, "severity": "critical"},
        ],
        "checks_passed": 1,
        "checks_failed": 0,
        "constitution_ref": {"document_id": doc_id, "policy_hash": "abc"},
    }


@pytest.fixture
def store(tmp_path):
    s = ReceiptStore(str(tmp_path / "ts.db"))
    yield s
    s.close()


@pytest.fixture
def analyzer(store):
    return DriftAnalyzer(store)


# ---------------------------------------------------------------------------
# _parse_ts unit tests
# ---------------------------------------------------------------------------

class TestParseTs:

    def test_offset_format(self):
        dt = _parse_ts("2026-02-14T10:00:00+00:00")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_z_suffix(self):
        dt = _parse_ts("2026-02-14T10:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_naive_timestamp(self):
        dt = _parse_ts("2026-02-14T10:00:00")
        assert dt is not None
        assert dt.tzinfo is not None  # normalized to UTC

    def test_empty_string(self):
        assert _parse_ts("") is None

    def test_invalid_string(self):
        assert _parse_ts("not-a-date") is None

    def test_z_and_offset_produce_same_result(self):
        a = _parse_ts("2026-02-14T10:00:00Z")
        b = _parse_ts("2026-02-14T10:00:00+00:00")
        assert a == b

    def test_naive_treated_as_utc(self):
        naive = _parse_ts("2026-02-14T10:00:00")
        aware = _parse_ts("2026-02-14T10:00:00+00:00")
        assert naive == aware


# ---------------------------------------------------------------------------
# Integration: drift analysis with various timestamp formats
# ---------------------------------------------------------------------------

class TestDriftTimestampIntegration:

    def test_naive_timestamps_dont_crash(self, store, analyzer):
        """Receipts with naive timestamps should not cause TypeError."""
        now = datetime.now(timezone.utc)
        for i in range(6):
            ts = (now - timedelta(days=i)).strftime("%Y-%m-%dT%H:%M:%S")  # naive
            store.save(_make_receipt(f"r{i}", ts))

        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        assert report.agents[0].total_receipts == 6

    def test_z_suffix_timestamps(self, store, analyzer):
        """Receipts with Z suffix timestamps should work."""
        now = datetime.now(timezone.utc)
        for i in range(6):
            ts = (now - timedelta(days=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            store.save(_make_receipt(f"r{i}", ts))

        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        assert report.agents[0].total_receipts == 6

    def test_offset_timestamps_regression(self, store, analyzer):
        """Receipts with +00:00 offset continue to work."""
        now = datetime.now(timezone.utc)
        for i in range(6):
            ts = (now - timedelta(days=i)).isoformat()  # includes +00:00
            store.save(_make_receipt(f"r{i}", ts))

        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        assert report.agents[0].total_receipts == 6

    def test_mixed_timestamp_formats(self, store, analyzer):
        """Mix of naive, Z, and offset timestamps all contribute."""
        now = datetime.now(timezone.utc)
        store.save(_make_receipt("r0", (now - timedelta(days=0)).strftime("%Y-%m-%dT%H:%M:%S")))
        store.save(_make_receipt("r1", (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        store.save(_make_receipt("r2", (now - timedelta(days=2)).isoformat()))
        store.save(_make_receipt("r3", (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")))
        store.save(_make_receipt("r4", (now - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        store.save(_make_receipt("r5", (now - timedelta(days=5)).isoformat()))

        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        assert report.agents[0].total_receipts == 6
        # All receipts should have been parsed (not silently dropped)
        c1 = [c for c in report.agents[0].checks if c.check_id == "C1"]
        assert len(c1) == 1
        assert c1[0].total_evaluated == 6
