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
        "correlation_id": f"trace-{receipt_id}",
        "timestamp": timestamp,
        "status": "PASS",
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

    # FIX 4: Non-string inputs must not crash
    def test_integer_returns_none(self):
        assert _parse_ts(1730000000) is None

    def test_float_returns_none(self):
        assert _parse_ts(123.45) is None

    def test_bool_returns_none(self):
        assert _parse_ts(True) is None

    def test_none_returns_none(self):
        assert _parse_ts(None) is None

    def test_dict_returns_none(self):
        assert _parse_ts({"timestamp": "2026-01-01"}) is None


# ---------------------------------------------------------------------------
# Integration: drift analysis with various timestamp formats
# ---------------------------------------------------------------------------

class TestDriftErroredChecks:
    """FIX 5: ERRORED checks excluded from pass/fail metrics."""

    def test_errored_checks_not_counted_as_pass(self, store, analyzer):
        now = datetime.now(timezone.utc)
        for i in range(6):
            ts = (now - timedelta(days=i)).isoformat()
            store.save({
                "receipt_id": f"r{i}",
                "correlation_id": f"trace-r{i}",
                "timestamp": ts,
                "status": "PARTIAL",
                "checks": [
                    {"check_id": "C1", "name": "C1", "passed": True,
                     "severity": "critical"},
                    {"check_id": "C2", "name": "C2", "passed": True,
                     "severity": "warning"},
                    {"check_id": "C3", "name": "C3", "passed": True,
                     "severity": "warning"},
                    {"check_id": "INV_CUSTOM", "name": "Custom",
                     "passed": True, "severity": "info",
                     "status": "ERRORED"},
                    {"check_id": "INV_CUSTOM_2", "name": "Custom2",
                     "passed": True, "severity": "info",
                     "status": "ERRORED"},
                ],
                "checks_passed": 3,
                "checks_failed": 0,
                "constitution_ref": {
                    "document_id": "ts-agent/1.0.0",
                    "policy_hash": "abc",
                },
            })

        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        agent = report.agents[0]
        # ERRORED checks should not appear in check stats
        check_ids = {c.check_id for c in agent.checks}
        assert "INV_CUSTOM" not in check_ids
        assert "INV_CUSTOM_2" not in check_ids
        # Only the 3 real checks should be counted
        total_eval = sum(c.total_evaluated for c in agent.checks)
        assert total_eval == 18  # 3 checks * 6 receipts

    def test_errored_plus_fail_correct_rate(self, store, analyzer):
        now = datetime.now(timezone.utc)
        for i in range(6):
            ts = (now - timedelta(days=i)).isoformat()
            store.save({
                "receipt_id": f"r{i}",
                "correlation_id": f"trace-r{i}",
                "timestamp": ts,
                "status": "FAIL",
                "checks": [
                    {"check_id": "C1", "name": "C1", "passed": False,
                     "severity": "critical"},
                    {"check_id": "INV_ERR", "name": "Err",
                     "passed": True, "severity": "info",
                     "status": "ERRORED"},
                ],
                "checks_passed": 0,
                "checks_failed": 1,
                "constitution_ref": {
                    "document_id": "ts-agent/1.0.0",
                    "policy_hash": "abc",
                },
            })

        report = analyzer.analyze(window_days=30)
        agent = report.agents[0]
        # Only C1 should be in stats with 100% fail rate
        assert len(agent.checks) == 1
        assert agent.checks[0].check_id == "C1"
        assert agent.checks[0].fail_count == 6
        assert agent.checks[0].pass_count == 0


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

    def test_corrupted_integer_timestamp_skipped(self, store, analyzer):
        """Receipt with integer timestamp is skipped without crash."""
        now = datetime.now(timezone.utc)
        # Store 5 good receipts + 1 with corrupted timestamp
        for i in range(5):
            ts = (now - timedelta(days=i)).isoformat()
            store.save(_make_receipt(f"r{i}", ts))
        # Manually insert a receipt with integer timestamp
        bad_receipt = _make_receipt("bad", 1730000000)
        store.save(bad_receipt)

        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        # The bad receipt has an integer timestamp so it's excluded by
        # the store's SQL timestamp filter — only the 5 good receipts appear.
        assert report.agents[0].total_receipts == 5

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
