"""Tests for multi-report export in CLI drift report.

Ensures that exporting multiple reports to a single file produces
combined output instead of overwriting.
"""

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from sanna.store import ReceiptStore
from sanna.drift import DriftAnalyzer


def _ts(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _make_receipt(receipt_id, agent_name, timestamp):
    return {
        "receipt_id": receipt_id,
        "correlation_id": f"trace-{receipt_id}",
        "timestamp": timestamp,
        "status": "PASS",
        "checks": [
            {"check_id": "C1", "passed": True, "severity": "critical"},
        ],
        "checks_passed": 1,
        "checks_failed": 0,
        "constitution_ref": {
            "document_id": f"{agent_name}/1.0.0",
            "policy_hash": "abc",
        },
    }


@pytest.fixture
def populated_store(tmp_path):
    db_path = str(tmp_path / "export.db")
    store = ReceiptStore(db_path)
    for i in range(10):
        store.save(_make_receipt(f"a-{i}", "agent-a", _ts(i)))
        store.save(_make_receipt(f"b-{i}", "agent-b", _ts(i)))
    yield store, db_path
    store.close()


class TestMultiReportExport:

    def test_json_export_combined(self, populated_store, tmp_path):
        """JSON export with multiple reports produces a JSON array."""
        store, db_path = populated_store
        output_path = str(tmp_path / "out.json")

        from sanna.cli import main_drift_report
        with patch("sys.argv", [
            "sanna-drift-report",
            "--db", db_path,
            "--window", "30",
            "--window", "90",
            "--export", "json",
            "--output", output_path,
        ]):
            main_drift_report()

        with open(output_path) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 2  # 2 windows
        assert data[0]["window_days"] == 30
        assert data[1]["window_days"] == 90

    def test_csv_export_combined(self, populated_store, tmp_path):
        """CSV export with multiple reports produces rows from all reports."""
        store, db_path = populated_store
        output_path = str(tmp_path / "out.csv")

        from sanna.cli import main_drift_report
        with patch("sys.argv", [
            "sanna-drift-report",
            "--db", db_path,
            "--window", "30",
            "--window", "90",
            "--export", "csv",
            "--output", output_path,
        ]):
            main_drift_report()

        with open(output_path) as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Should have exactly 1 header row
        header_count = sum(1 for r in rows if r and r[0] == "window_days")
        assert header_count == 1

        # Should have data rows from both windows
        data_rows = [r for r in rows if r and r[0] != "window_days"]
        windows_seen = {r[0] for r in data_rows if r[0]}
        assert "30" in windows_seen
        assert "90" in windows_seen

    def test_single_report_export_unchanged(self, populated_store, tmp_path):
        """Single report export still works correctly."""
        store, db_path = populated_store
        output_path = str(tmp_path / "single.json")

        from sanna.cli import main_drift_report
        with patch("sys.argv", [
            "sanna-drift-report",
            "--db", db_path,
            "--export", "json",
            "--output", output_path,
        ]):
            main_drift_report()

        with open(output_path) as f:
            data = json.load(f)
        # Single report is still wrapped in an array for consistency
        assert isinstance(data, list)
        assert len(data) == 1
