"""Tests for the Fleet Governance Demo (examples/fleet_governance_demo.py).

Imports and runs the demo programmatically, then asserts on the returned
results dict.  Each test uses the shared ``demo_results`` fixture to
avoid re-running the (relatively expensive) simulation multiple times.
"""

import csv
import io
import json
from pathlib import Path

import pytest

from sanna.evaluators import clear_evaluators


# ---------------------------------------------------------------------------
# Fixture: run the demo once per module, share results
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def demo_results(tmp_path_factory):
    """Run the fleet governance demo and return its result dict."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "examples"))
    from fleet_governance_demo import run_demo

    export_dir = str(tmp_path_factory.mktemp("fleet_export"))
    results = run_demo(output_dir=export_dir)
    yield results
    # Cleanup: clear custom evaluators registered by the demo
    clear_evaluators()


# ---------------------------------------------------------------------------
# 1. Demo runs without error
# ---------------------------------------------------------------------------

class TestDemoExecution:
    def test_demo_runs_successfully(self, demo_results):
        """Demo completes and returns a result dict."""
        assert demo_results is not None
        assert isinstance(demo_results, dict)

    def test_demo_returns_expected_keys(self, demo_results):
        expected = {
            "total_receipts", "agent_counts", "reports",
            "fleet_statuses", "agent_statuses_30d", "agent_statuses_90d",
            "csv_path", "json_path", "sample_receipts", "verification_results",
        }
        assert expected.issubset(demo_results.keys())


# ---------------------------------------------------------------------------
# 2. Receipt generation
# ---------------------------------------------------------------------------

class TestReceiptGeneration:
    def test_creates_receipts_for_all_three_agents(self, demo_results):
        agent_counts = demo_results["agent_counts"]
        assert "snow-agent" in agent_counts
        assert "sfdc-agent" in agent_counts
        assert "custom-agent" in agent_counts

    def test_each_agent_has_sufficient_receipts(self, demo_results):
        for name, count in demo_results["agent_counts"].items():
            assert count >= 50, f"{name} has only {count} receipts (expected >= 50)"

    def test_total_receipts_reasonable(self, demo_results):
        total = demo_results["total_receipts"]
        assert 300 <= total <= 700, f"Total receipts {total} outside expected range"


# ---------------------------------------------------------------------------
# 3. Drift analysis
# ---------------------------------------------------------------------------

class TestDriftAnalysis:
    def test_produces_two_reports(self, demo_results):
        assert len(demo_results["reports"]) == 2

    def test_report_windows_are_30_and_90(self, demo_results):
        windows = [r.window_days for r in demo_results["reports"]]
        assert windows == [30, 90]

    def test_reports_contain_correct_agent_names(self, demo_results):
        for report in demo_results["reports"]:
            agent_ids = {a.agent_id for a in report.agents}
            assert "snow-agent" in agent_ids
            assert "sfdc-agent" in agent_ids
            assert "custom-agent" in agent_ids

    def test_sfdc_agent_is_drifting(self, demo_results):
        """sfdc-agent should show WARNING or CRITICAL (it's the drifting agent)."""
        statuses_90d = demo_results["agent_statuses_90d"]
        assert statuses_90d.get("sfdc-agent") in ("WARNING", "CRITICAL"), (
            f"sfdc-agent 90d status is {statuses_90d.get('sfdc-agent')}, expected WARNING or CRITICAL"
        )

    def test_snow_agent_is_healthy(self, demo_results):
        statuses_90d = demo_results["agent_statuses_90d"]
        assert statuses_90d.get("snow-agent") == "HEALTHY"

    def test_custom_agent_is_healthy(self, demo_results):
        statuses_90d = demo_results["agent_statuses_90d"]
        assert statuses_90d.get("custom-agent") == "HEALTHY"

    def test_fleet_status_not_healthy(self, demo_results):
        """Fleet status should reflect the drifting sfdc-agent."""
        # At least one window should be WARNING or CRITICAL
        statuses = list(demo_results["fleet_statuses"].values())
        assert any(s in ("WARNING", "CRITICAL") for s in statuses)


# ---------------------------------------------------------------------------
# 4. Export
# ---------------------------------------------------------------------------

class TestExport:
    def test_csv_file_exists(self, demo_results):
        assert Path(demo_results["csv_path"]).exists()

    def test_csv_is_valid(self, demo_results):
        content = Path(demo_results["csv_path"]).read_text()
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) >= 1
        assert "agent_id" in rows[0]

    def test_json_file_exists(self, demo_results):
        assert Path(demo_results["json_path"]).exists()

    def test_json_is_valid(self, demo_results):
        content = Path(demo_results["json_path"]).read_text()
        data = json.loads(content)
        assert "window_days" in data
        assert "agents" in data
        assert data["window_days"] == 90


# ---------------------------------------------------------------------------
# 5. Offline verification
# ---------------------------------------------------------------------------

class TestVerification:
    def test_snow_agent_receipt_verifies(self, demo_results):
        vr = demo_results["verification_results"].get("snow-agent")
        assert vr is not None
        assert vr.valid is True

    def test_sfdc_agent_receipt_verifies(self, demo_results):
        vr = demo_results["verification_results"].get("sfdc-agent")
        assert vr is not None
        assert vr.valid is True

    def test_custom_agent_receipt_verifies(self, demo_results):
        """Custom evaluator receipts now pass offline verification."""
        vr = demo_results["verification_results"].get("custom-agent")
        assert vr is not None
        assert vr.valid is True

    def test_sample_receipts_have_required_fields(self, demo_results):
        for name, receipt in demo_results["sample_receipts"].items():
            assert "status" in receipt
            assert "checks" in receipt
            assert "receipt_id" in receipt
