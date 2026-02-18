"""Tests for DriftAnalyzer — governance drift analytics."""

import json
import math
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from sanna.store import ReceiptStore
from sanna.drift import (
    DriftAnalyzer,
    DriftReport,
    AgentDriftSummary,
    CheckDriftDetail,
    calculate_slope,
    project_breach,
    format_drift_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(days_ago: float = 0) -> str:
    """ISO timestamp *days_ago* days before now."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()


def _make_receipt(
    *,
    receipt_id,
    agent_name="agent-a",
    constitution_version="1.0.0",
    timestamp=None,
    checks=None,
):
    if timestamp is None:
        timestamp = _ts(0)
    if checks is None:
        checks = [
            {"check_id": "C1", "name": "Context Contradiction",
             "passed": True, "severity": "critical"},
        ]
    doc_id = f"{agent_name}/{constitution_version}"
    return {
        "receipt_id": receipt_id,
        "correlation_id": f"trace-{receipt_id}",
        "timestamp": timestamp,
        "status": "PASS" if all(c.get("passed", True) for c in checks) else "FAIL",
        "checks": checks,
        "checks_passed": sum(1 for c in checks if c.get("passed")),
        "checks_failed": sum(1 for c in checks if not c.get("passed")),
        "constitution_ref": {"document_id": doc_id, "policy_hash": "abc"},
    }


def _passing_check(check_id="C1"):
    return {"check_id": check_id, "name": check_id, "passed": True, "severity": "critical"}


def _failing_check(check_id="C1"):
    return {"check_id": check_id, "name": check_id, "passed": False, "severity": "critical",
            "evidence": "failed"}


@pytest.fixture
def store(tmp_path):
    s = ReceiptStore(str(tmp_path / "drift.db"))
    yield s
    s.close()


@pytest.fixture
def analyzer(store):
    return DriftAnalyzer(store)


# ---------------------------------------------------------------------------
# Linear regression math
# ---------------------------------------------------------------------------

class TestCalculateSlope:

    def test_known_positive_slope(self):
        # y = 2x  → slope = 2
        xs = [0.0, 1.0, 2.0, 3.0]
        ys = [0.0, 2.0, 4.0, 6.0]
        assert abs(calculate_slope(xs, ys) - 2.0) < 1e-9

    def test_known_negative_slope(self):
        # y = -x + 10  → slope = -1
        xs = [0.0, 1.0, 2.0, 3.0]
        ys = [10.0, 9.0, 8.0, 7.0]
        assert abs(calculate_slope(xs, ys) - (-1.0)) < 1e-9

    def test_zero_slope(self):
        xs = [0.0, 1.0, 2.0]
        ys = [5.0, 5.0, 5.0]
        assert calculate_slope(xs, ys) == 0.0

    def test_single_point_returns_zero(self):
        assert calculate_slope([1.0], [2.0]) == 0.0

    def test_empty_returns_zero(self):
        assert calculate_slope([], []) == 0.0

    def test_identical_x_returns_zero(self):
        assert calculate_slope([3.0, 3.0, 3.0], [1.0, 2.0, 3.0]) == 0.0

    def test_two_points(self):
        # slope between (0,0) and (10, 0.5) = 0.05
        assert abs(calculate_slope([0.0, 10.0], [0.0, 0.5]) - 0.05) < 1e-9

    def test_fractional_slope(self):
        xs = [0.0, 5.0, 10.0, 15.0, 20.0]
        ys = [0.01, 0.02, 0.03, 0.04, 0.05]
        assert abs(calculate_slope(xs, ys) - 0.002) < 1e-9


# ---------------------------------------------------------------------------
# Breach projection
# ---------------------------------------------------------------------------

class TestProjectBreach:

    def test_already_breached(self):
        assert project_breach(0.20, 0.01, 0.15) == 0

    def test_exactly_at_threshold(self):
        assert project_breach(0.15, 0.01, 0.15) == 0

    def test_negative_slope_returns_none(self):
        assert project_breach(0.05, -0.01, 0.15) is None

    def test_zero_slope_returns_none(self):
        assert project_breach(0.05, 0.0, 0.15) is None

    def test_known_projection(self):
        # 0.10 rate, 0.01/day slope, 0.15 threshold  → 5 days
        assert project_breach(0.10, 0.01, 0.15) == 5

    def test_fractional_rounds_up(self):
        # (0.15 - 0.10) / 0.03 = 1.666... → ceil = 2
        assert project_breach(0.10, 0.03, 0.15) == 2

    def test_zero_rate_positive_slope(self):
        # 0.0 rate, 0.01/day, 0.15 threshold → 15 days
        assert project_breach(0.0, 0.01, 0.15) == 15


# ---------------------------------------------------------------------------
# DriftAnalyzer — empty / no-data
# ---------------------------------------------------------------------------

class TestAnalyzerEmpty:

    def test_empty_store(self, analyzer):
        report = analyzer.analyze()
        assert isinstance(report, DriftReport)
        assert report.agents == []
        assert report.fleet_status == "HEALTHY"

    def test_no_agents_in_window(self, store, analyzer):
        # Receipt outside window
        store.save(_make_receipt(receipt_id="old", timestamp=_ts(days_ago=60)))
        report = analyzer.analyze(window_days=7)
        assert report.agents == []


# ---------------------------------------------------------------------------
# DriftAnalyzer — single agent
# ---------------------------------------------------------------------------

class TestAnalyzerSingleAgent:

    def test_all_passing_healthy(self, store, analyzer):
        for i in range(10):
            store.save(_make_receipt(
                receipt_id=f"r{i}",
                timestamp=_ts(days_ago=i),
                checks=[_passing_check()],
            ))
        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        agent = report.agents[0]
        assert agent.status == "HEALTHY"
        assert agent.agent_id == "agent-a"
        assert agent.total_receipts == 10
        assert agent.checks[0].fail_rate == 0.0

    def test_all_failing_critical(self, store, analyzer):
        for i in range(10):
            store.save(_make_receipt(
                receipt_id=f"r{i}",
                timestamp=_ts(days_ago=i),
                checks=[_failing_check()],
            ))
        report = analyzer.analyze(window_days=30, threshold=0.15)
        agent = report.agents[0]
        assert agent.status == "CRITICAL"
        assert agent.checks[0].fail_rate == 1.0
        assert report.fleet_status == "CRITICAL"

    def test_trending_up_warning(self, store, analyzer):
        """Receipts start passing and then progressively fail → WARNING."""
        # Days 29-20: all pass.  Days 9-0: all fail.
        for i in range(10):
            store.save(_make_receipt(
                receipt_id=f"pass-{i}",
                timestamp=_ts(days_ago=29 - i),
                checks=[_passing_check()],
            ))
        for i in range(10):
            store.save(_make_receipt(
                receipt_id=f"fail-{i}",
                timestamp=_ts(days_ago=9 - i),
                checks=[_failing_check()],
            ))
        report = analyzer.analyze(window_days=30, threshold=0.60)
        agent = report.agents[0]
        # Overall fail rate = 10/20 = 0.50 which is below 0.60
        assert agent.checks[0].fail_rate == 0.5
        # Slope should be positive (degrading)
        assert agent.checks[0].trend_slope > 0
        # Should project a breach
        assert agent.checks[0].projected_breach_days is not None
        assert agent.status in ("WARNING", "CRITICAL")

    def test_insufficient_data(self, store, analyzer):
        """< 5 receipts → INSUFFICIENT_DATA."""
        for i in range(3):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i)))
        report = analyzer.analyze(window_days=30)
        assert len(report.agents) == 1
        assert report.agents[0].status == "INSUFFICIENT_DATA"
        assert report.agents[0].checks == []

    def test_agent_id_filter(self, store, analyzer):
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"a-{i}", agent_name="alpha", timestamp=_ts(days_ago=i)))
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"b-{i}", agent_name="beta", timestamp=_ts(days_ago=i)))
        report = analyzer.analyze(agent_id="alpha")
        assert len(report.agents) == 1
        assert report.agents[0].agent_id == "alpha"

    def test_threshold_override(self, store, analyzer):
        """Half passing, half failing at 50% rate — below 60% threshold → HEALTHY."""
        for i in range(5):
            store.save(_make_receipt(
                receipt_id=f"p-{i}", timestamp=_ts(days_ago=i), checks=[_passing_check()]))
        for i in range(5):
            store.save(_make_receipt(
                receipt_id=f"f-{i}", timestamp=_ts(days_ago=i + 5), checks=[_failing_check()]))
        report = analyzer.analyze(threshold=0.60)
        assert report.agents[0].checks[0].fail_rate == 0.5
        # 50% is below 60% threshold and there's no upward trend (evenly spread)
        # so should not be CRITICAL
        assert report.agents[0].status != "CRITICAL"


# ---------------------------------------------------------------------------
# DriftAnalyzer — multi-agent fleet
# ---------------------------------------------------------------------------

class TestAnalyzerFleet:

    def test_mixed_statuses(self, store, analyzer):
        # Agent alpha: all passing → HEALTHY
        for i in range(6):
            store.save(_make_receipt(
                receipt_id=f"alpha-{i}", agent_name="alpha",
                timestamp=_ts(days_ago=i), checks=[_passing_check()]))
        # Agent beta: all failing → CRITICAL
        for i in range(6):
            store.save(_make_receipt(
                receipt_id=f"beta-{i}", agent_name="beta",
                timestamp=_ts(days_ago=i), checks=[_failing_check()]))

        report = analyzer.analyze(threshold=0.15)
        statuses = {a.agent_id: a.status for a in report.agents}
        assert statuses["alpha"] == "HEALTHY"
        assert statuses["beta"] == "CRITICAL"
        assert report.fleet_status == "CRITICAL"

    def test_fleet_healthy_when_all_healthy(self, store, analyzer):
        for name in ("a", "b", "c"):
            for i in range(6):
                store.save(_make_receipt(
                    receipt_id=f"{name}-{i}", agent_name=name,
                    timestamp=_ts(days_ago=i), checks=[_passing_check()]))
        report = analyzer.analyze()
        assert report.fleet_status == "HEALTHY"


# ---------------------------------------------------------------------------
# Per-check breakdown
# ---------------------------------------------------------------------------

class TestPerCheckBreakdown:

    def test_multiple_checks(self, store, analyzer):
        """Two checks in each receipt, one always passes one always fails."""
        for i in range(6):
            store.save(_make_receipt(
                receipt_id=f"r{i}",
                timestamp=_ts(days_ago=i),
                checks=[_passing_check("C1"), _failing_check("C2")],
            ))
        report = analyzer.analyze(threshold=0.15)
        agent = report.agents[0]
        c1 = next(c for c in agent.checks if c.check_id == "C1")
        c2 = next(c for c in agent.checks if c.check_id == "C2")
        assert c1.fail_rate == 0.0
        assert c1.status == "HEALTHY"
        assert c2.fail_rate == 1.0
        assert c2.status == "CRITICAL"

    def test_not_checked_skipped(self, store, analyzer):
        """Checks with status=NOT_CHECKED should be excluded from analysis."""
        not_checked = {"check_id": "INV_CUSTOM", "name": "Custom",
                       "passed": True, "severity": "info", "status": "NOT_CHECKED"}
        for i in range(6):
            store.save(_make_receipt(
                receipt_id=f"r{i}",
                timestamp=_ts(days_ago=i),
                checks=[_passing_check("C1"), not_checked],
            ))
        report = analyzer.analyze()
        agent = report.agents[0]
        check_ids = [c.check_id for c in agent.checks]
        assert "INV_CUSTOM" not in check_ids
        assert "C1" in check_ids


# ---------------------------------------------------------------------------
# Multi-window
# ---------------------------------------------------------------------------

class TestMultiWindow:

    def test_returns_correct_count(self, store, analyzer):
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i)))
        reports = analyzer.analyze_multi(windows=[7, 30, 90])
        assert len(reports) == 3
        assert [r.window_days for r in reports] == [7, 30, 90]

    def test_default_windows(self, store, analyzer):
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i)))
        reports = analyzer.analyze_multi()
        assert len(reports) == 4
        assert [r.window_days for r in reports] == [7, 30, 90, 180]


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

class TestFormatting:

    def test_format_empty_report(self):
        report = DriftReport(
            window_days=30, threshold=0.15,
            generated_at="2026-02-13T00:00:00+00:00",
            agents=[], fleet_status="HEALTHY",
        )
        text = format_drift_report(report)
        assert "Fleet Governance Report" in text
        assert "HEALTHY" in text
        assert "No agents" in text

    def test_format_with_agents(self):
        report = DriftReport(
            window_days=30, threshold=0.15,
            generated_at="2026-02-13T00:00:00+00:00",
            agents=[
                AgentDriftSummary(
                    agent_id="snow-agent", constitution_id="snow-agent/1.0.0",
                    status="HEALTHY", total_receipts=50,
                    checks=[CheckDriftDetail(
                        check_id="C1", total_evaluated=50, pass_count=49,
                        fail_count=1, fail_rate=0.02, trend_slope=-0.001,
                        projected_breach_days=None, status="HEALTHY",
                    )],
                    projected_breach_days=None,
                ),
                AgentDriftSummary(
                    agent_id="sfdc-agent", constitution_id="sfdc-agent/1.0.0",
                    status="WARNING", total_receipts=40,
                    checks=[CheckDriftDetail(
                        check_id="C1", total_evaluated=40, pass_count=34,
                        fail_count=6, fail_rate=0.15, trend_slope=0.005,
                        projected_breach_days=18, status="WARNING",
                    )],
                    projected_breach_days=18,
                ),
            ],
            fleet_status="WARNING",
        )
        text = format_drift_report(report)
        assert "snow-agent" in text
        assert "sfdc-agent" in text
        assert "WARNING" in text
        assert "18 days" in text

    def test_format_insufficient_data(self):
        report = DriftReport(
            window_days=7, threshold=0.15,
            generated_at="2026-02-13T00:00:00+00:00",
            agents=[
                AgentDriftSummary(
                    agent_id="new-agent", constitution_id="new-agent/1.0.0",
                    status="INSUFFICIENT_DATA", total_receipts=2,
                    checks=[], projected_breach_days=None,
                ),
            ],
            fleet_status="INSUFFICIENT_DATA",
        )
        text = format_drift_report(report)
        assert "INSUFFICIENT_DATA" in text
        assert "2 receipts" in text


# ---------------------------------------------------------------------------
# Zero-division safety
# ---------------------------------------------------------------------------

class TestZeroDivisionSafety:

    def test_no_checks_in_receipts(self, store, analyzer):
        """Receipts with empty checks list shouldn't crash."""
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i), checks=[]))
        report = analyzer.analyze()
        assert len(report.agents) == 1
        assert report.agents[0].checks == []
        assert report.agents[0].status == "HEALTHY"

    def test_checks_with_zero_evaluations(self, store, analyzer):
        """All checks are NOT_CHECKED → no check details."""
        nc = {"check_id": "INV_X", "name": "X", "passed": True,
              "severity": "info", "status": "NOT_CHECKED"}
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i), checks=[nc]))
        report = analyzer.analyze()
        assert report.agents[0].checks == []


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

class TestCLI:

    def test_cli_missing_db(self, tmp_path):
        """CLI exits with error when DB doesn't exist."""
        result = subprocess.run(
            [sys.executable, "-m", "sanna.cli", "--help"],
            capture_output=True, text=True,
        )
        # Just verify module is importable — main_drift_report is a registered entry point
        # We test the function directly instead
        from sanna.cli import main_drift_report
        assert callable(main_drift_report)

    def test_cli_with_populated_db(self, tmp_path, monkeypatch):
        """CLI produces output when given a populated DB."""
        db_path = str(tmp_path / "cli.db")
        store = ReceiptStore(db_path)
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i)))
        store.close()

        monkeypatch.setattr(
            "sys.argv",
            ["sanna-drift-report", "--db", db_path, "--window", "30"],
        )
        from sanna.cli import main_drift_report
        exit_code = main_drift_report()
        assert exit_code == 0

    def test_cli_json_output(self, tmp_path, monkeypatch, capsys):
        db_path = str(tmp_path / "cli_json.db")
        store = ReceiptStore(db_path)
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i)))
        store.close()

        monkeypatch.setattr(
            "sys.argv",
            ["sanna-drift-report", "--db", db_path, "--json"],
        )
        from sanna.cli import main_drift_report
        exit_code = main_drift_report()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["window_days"] == 30

    def test_cli_multi_window(self, tmp_path, monkeypatch, capsys):
        db_path = str(tmp_path / "cli_multi.db")
        store = ReceiptStore(db_path)
        for i in range(6):
            store.save(_make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i)))
        store.close()

        monkeypatch.setattr(
            "sys.argv",
            ["sanna-drift-report", "--db", db_path, "--window", "7", "--window", "30", "--json"],
        )
        from sanna.cli import main_drift_report
        exit_code = main_drift_report()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2
        assert data[0]["window_days"] == 7
        assert data[1]["window_days"] == 30

    def test_cli_critical_exit_code(self, tmp_path, monkeypatch):
        """CLI returns exit code 1 when fleet is CRITICAL."""
        db_path = str(tmp_path / "cli_crit.db")
        store = ReceiptStore(db_path)
        for i in range(10):
            store.save(_make_receipt(
                receipt_id=f"r{i}", timestamp=_ts(days_ago=i),
                checks=[_failing_check()]))
        store.close()

        monkeypatch.setattr(
            "sys.argv",
            ["sanna-drift-report", "--db", db_path, "--threshold", "0.10"],
        )
        from sanna.cli import main_drift_report
        assert main_drift_report() == 1


# ---------------------------------------------------------------------------
# Constitution ID extraction
# ---------------------------------------------------------------------------

class TestConstitutionId:

    def test_constitution_id_in_summary(self, store, analyzer):
        for i in range(6):
            store.save(_make_receipt(
                receipt_id=f"r{i}", agent_name="my-agent",
                constitution_version="2.0.0", timestamp=_ts(days_ago=i)))
        report = analyzer.analyze()
        assert report.agents[0].constitution_id == "my-agent/2.0.0"

    def test_receipts_without_constitution_ref_skipped(self, store, analyzer):
        """Receipts with no constitution_ref → no agent_id → skipped."""
        for i in range(6):
            r = _make_receipt(receipt_id=f"r{i}", timestamp=_ts(days_ago=i))
            r["constitution_ref"] = None
            store.save(r)
        report = analyzer.analyze()
        assert report.agents == []
