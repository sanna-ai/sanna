"""Tests for DriftReport export (JSON / CSV) and CLI --export/--output flags."""

import csv
import io
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from sanna.drift import (
    DriftAnalyzer,
    DriftReport,
    AgentDriftSummary,
    CheckDriftDetail,
    export_drift_report,
    export_drift_report_to_file,
)
from sanna.store import ReceiptStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_receipt(agent_name, check_id, passed, ts_offset_h=0):
    """Build a minimal receipt dict for store insertion."""
    from datetime import datetime, timedelta, timezone

    ts = datetime.now(timezone.utc) - timedelta(hours=ts_offset_h)
    return {
        "receipt_id": f"r-{agent_name}-{check_id}-{ts_offset_h}-{passed}",
        "correlation_id": f"t-{ts_offset_h}",
        "timestamp": ts.isoformat(),
        "status": "PASS" if passed else "FAIL",
        "constitution_ref": {
            "document_id": f"{agent_name}/v1",
            "policy_hash": "abc123",
        },
        "checks": [
            {
                "check_id": check_id,
                "name": check_id,
                "passed": passed,
                "status": "PASS" if passed else "FAIL",
                "severity": "warning",
                "evidence": {},
                "details": "",
            }
        ],
    }


@pytest.fixture()
def populated_store(tmp_path):
    """Create a store with 10 receipts across 2 agents."""
    db = str(tmp_path / "test.db")
    store = ReceiptStore(db)
    for i in range(6):
        store.save(_make_receipt("agent-a", "C1", passed=(i % 3 != 0), ts_offset_h=i * 12))
    for i in range(4):
        store.save(_make_receipt("agent-b", "C2", passed=True, ts_offset_h=i * 6))
    yield store
    store.close()


@pytest.fixture()
def sample_report(populated_store):
    """Generate a drift report from the populated store."""
    analyzer = DriftAnalyzer(populated_store)
    return analyzer.analyze(window_days=30, threshold=0.15)


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

class TestJSONExport:
    def test_export_json_is_valid(self, sample_report):
        result = export_drift_report(sample_report, fmt="json")
        data = json.loads(result)
        assert data["window_days"] == 30
        assert data["fleet_status"] in ("HEALTHY", "WARNING", "CRITICAL", "INSUFFICIENT_DATA")

    def test_export_json_round_trip(self, sample_report):
        result = export_drift_report(sample_report, fmt="json")
        data = json.loads(result)
        assert data == asdict(sample_report)

    def test_export_json_agents_present(self, sample_report):
        result = export_drift_report(sample_report, fmt="json")
        data = json.loads(result)
        agent_ids = [a["agent_id"] for a in data["agents"]]
        assert "agent-a" in agent_ids
        assert "agent-b" in agent_ids

    def test_analyzer_export_method(self, populated_store, sample_report):
        analyzer = DriftAnalyzer(populated_store)
        result = analyzer.export(sample_report, fmt="json")
        data = json.loads(result)
        assert data["window_days"] == sample_report.window_days


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

class TestCSVExport:
    def test_export_csv_has_header(self, sample_report):
        result = export_drift_report(sample_report, fmt="csv")
        reader = csv.reader(io.StringIO(result))
        header = next(reader)
        assert "agent_id" in header
        assert "check_id" in header
        assert "fleet_status" in header

    def test_export_csv_rows(self, sample_report):
        result = export_drift_report(sample_report, fmt="csv")
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        # Header + at least one data row per agent
        assert len(rows) >= 3  # header + agent-a + agent-b

    def test_export_csv_agent_ids(self, sample_report):
        result = export_drift_report(sample_report, fmt="csv")
        reader = csv.DictReader(io.StringIO(result))
        agent_ids = {row["agent_id"] for row in reader}
        assert "agent-a" in agent_ids
        assert "agent-b" in agent_ids

    def test_analyzer_export_csv_method(self, populated_store, sample_report):
        analyzer = DriftAnalyzer(populated_store)
        result = analyzer.export(sample_report, fmt="csv")
        assert "agent_id" in result
        assert "agent-a" in result


# ---------------------------------------------------------------------------
# File export
# ---------------------------------------------------------------------------

class TestFileExport:
    def test_export_to_file_json(self, sample_report, tmp_path):
        out = str(tmp_path / "report.json")
        result_path = export_drift_report_to_file(sample_report, out, fmt="json")
        assert Path(result_path).exists()
        data = json.loads(Path(result_path).read_text())
        assert data["window_days"] == 30

    def test_export_to_file_csv(self, sample_report, tmp_path):
        out = str(tmp_path / "report.csv")
        result_path = export_drift_report_to_file(sample_report, out, fmt="csv")
        assert Path(result_path).exists()
        content = Path(result_path).read_text()
        assert "agent_id" in content

    def test_export_to_file_creates_dirs(self, sample_report, tmp_path):
        out = str(tmp_path / "nested" / "dir" / "report.json")
        result_path = export_drift_report_to_file(sample_report, out, fmt="json")
        assert Path(result_path).exists()

    def test_analyzer_export_to_file(self, populated_store, sample_report, tmp_path):
        out = str(tmp_path / "report.json")
        analyzer = DriftAnalyzer(populated_store)
        result_path = analyzer.export_to_file(sample_report, out, fmt="json")
        assert Path(result_path).exists()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestExportErrors:
    def test_invalid_format(self, sample_report):
        with pytest.raises(ValueError, match="Unsupported format"):
            export_drift_report(sample_report, fmt="xml")

    def test_invalid_format_via_analyzer(self, populated_store, sample_report):
        analyzer = DriftAnalyzer(populated_store)
        with pytest.raises(ValueError, match="Unsupported format"):
            analyzer.export(sample_report, fmt="yaml")


# ---------------------------------------------------------------------------
# Empty report export
# ---------------------------------------------------------------------------

class TestEmptyReportExport:
    def test_empty_report_json(self):
        report = DriftReport(
            window_days=7,
            threshold=0.15,
            generated_at="2025-01-01T00:00:00",
            agents=[],
            fleet_status="HEALTHY",
        )
        result = export_drift_report(report, fmt="json")
        data = json.loads(result)
        assert data["agents"] == []

    def test_empty_report_csv(self):
        report = DriftReport(
            window_days=7,
            threshold=0.15,
            generated_at="2025-01-01T00:00:00",
            agents=[],
            fleet_status="HEALTHY",
        )
        result = export_drift_report(report, fmt="csv")
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 2  # header + one summary row
