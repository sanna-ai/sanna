"""
Sanna DriftAnalyzer — governance drift analytics over stored receipts.

Calculates per-agent, per-check failure rates with trend analysis and
threshold breach projection.  Pure Python — no numpy/scipy/pandas.
"""

from __future__ import annotations

import csv
import io
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .store import ReceiptStore


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CheckDriftDetail:
    """Per-check drift statistics for a single agent."""
    check_id: str
    total_evaluated: int
    pass_count: int
    fail_count: int
    fail_rate: float            # 0.0 – 1.0
    trend_slope: float          # positive = degrading (rate per day)
    projected_breach_days: Optional[int]
    status: str                 # HEALTHY / WARNING / CRITICAL


@dataclass
class AgentDriftSummary:
    """Per-agent drift summary."""
    agent_id: str
    constitution_id: str
    status: str                 # HEALTHY / WARNING / CRITICAL / INSUFFICIENT_DATA
    total_receipts: int
    checks: list[CheckDriftDetail]
    projected_breach_days: Optional[int]  # worst check's breach, None if healthy


@dataclass
class DriftReport:
    """Fleet-level drift report for a single analysis window."""
    window_days: int
    threshold: float
    generated_at: str           # ISO timestamp
    agents: list[AgentDriftSummary]
    fleet_status: str           # worst across all agents


# ---------------------------------------------------------------------------
# Pure-Python linear regression helpers
# ---------------------------------------------------------------------------

def calculate_slope(xs: list[float], ys: list[float]) -> float:
    """Least-squares slope: slope = (nΣxy − ΣxΣy) / (nΣx² − (Σx)²).

    Returns 0.0 when there are fewer than 2 data points or when the
    denominator is zero (all x values identical).
    """
    n = len(xs)
    if n < 2 or n != len(ys):
        return 0.0

    sum_x = sum(xs)
    sum_y = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_x2 = sum(x * x for x in xs)

    denom = n * sum_x2 - sum_x * sum_x
    if denom == 0.0:
        return 0.0

    return (n * sum_xy - sum_x * sum_y) / denom


def project_breach(
    current_rate: float,
    slope: float,
    threshold: float,
) -> Optional[int]:
    """Days until *current_rate* reaches *threshold* at *slope* per day.

    Returns:
        0      if current_rate already >= threshold
        None   if slope <= 0 (not trending toward breach)
        int    days until breach (ceiling)
    """
    if current_rate >= threshold:
        return 0
    if slope <= 0:
        return None
    days = (threshold - current_rate) / slope
    return math.ceil(days)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MIN_RECEIPTS = 5  # below this, mark INSUFFICIENT_DATA

_STATUS_RANK = {"HEALTHY": 0, "INSUFFICIENT_DATA": 1, "WARNING": 2, "CRITICAL": 3}


def _worst_status(*statuses: str) -> str:
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 0))


def _extract_agent_id(receipt: dict) -> Optional[str]:
    ref = receipt.get("constitution_ref")
    if not ref or not isinstance(ref, dict):
        return None
    doc_id = ref.get("document_id")
    if not doc_id or not isinstance(doc_id, str):
        return None
    parts = doc_id.split("/", 1)
    return parts[0] if parts[0] else None


def _extract_constitution_id(receipt: dict) -> Optional[str]:
    ref = receipt.get("constitution_ref")
    if not ref or not isinstance(ref, dict):
        return None
    doc_id = ref.get("document_id")
    return doc_id if doc_id and isinstance(doc_id, str) else None


def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Best-effort ISO-8601 parse (stdlib only).

    Handles "Z" suffix (all Python versions) and normalizes naive
    timestamps to UTC so subtraction against timezone-aware values
    never raises TypeError.
    """
    if not ts_str:
        return None
    try:
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _day_offset(ts: datetime, window_start: datetime) -> float:
    """Fractional days since *window_start*."""
    return (ts - window_start).total_seconds() / 86400.0


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class DriftAnalyzer:
    """Governance drift analytics over a :class:`ReceiptStore`.

    Usage::

        analyzer = DriftAnalyzer(store)
        report = analyzer.analyze(window_days=30, threshold=0.15)
        for agent in report.agents:
            print(agent.agent_id, agent.status)
    """

    def __init__(self, store: ReceiptStore):
        self._store = store

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def analyze(
        self,
        window_days: int = 30,
        agent_id: str | None = None,
        threshold: float = 0.15,
        projection_days: int = 90,
    ) -> DriftReport:
        """Run drift analysis for a single time window.

        Args:
            window_days: How many days back to look.
            agent_id: Restrict to a single agent (None = all agents).
            threshold: Failure-rate threshold (0–1) above which a check
                is CRITICAL.
            projection_days: How far ahead to project for WARNING status.

        Returns:
            A :class:`DriftReport`.
        """
        now = datetime.now(timezone.utc)
        since = now - timedelta(days=window_days)

        query_kw: dict = {"since": since}
        if agent_id is not None:
            query_kw["agent_id"] = agent_id

        receipts = self._store.query(**query_kw)

        # Group by agent
        agent_buckets: dict[str, list[dict]] = {}
        agent_const: dict[str, str] = {}
        for r in receipts:
            aid = _extract_agent_id(r)
            if aid is None:
                continue
            agent_buckets.setdefault(aid, []).append(r)
            cid = _extract_constitution_id(r)
            if cid:
                agent_const[aid] = cid

        agent_summaries: list[AgentDriftSummary] = []
        for aid in sorted(agent_buckets):
            bucket = agent_buckets[aid]
            cid = agent_const.get(aid, "")
            summary = self._analyze_agent(
                aid, cid, bucket, since, threshold, projection_days,
            )
            agent_summaries.append(summary)

        if agent_summaries:
            fleet = _worst_status(*(a.status for a in agent_summaries))
        else:
            fleet = "HEALTHY"

        return DriftReport(
            window_days=window_days,
            threshold=threshold,
            generated_at=now.isoformat(),
            agents=agent_summaries,
            fleet_status=fleet,
        )

    def analyze_multi(
        self,
        windows: list[int] | None = None,
        agent_id: str | None = None,
        threshold: float = 0.15,
        projection_days: int = 90,
    ) -> list[DriftReport]:
        """Run :meth:`analyze` for each window, return list of reports."""
        if windows is None:
            windows = [7, 30, 90, 180]
        return [
            self.analyze(
                window_days=w,
                agent_id=agent_id,
                threshold=threshold,
                projection_days=projection_days,
            )
            for w in windows
        ]

    def export(
        self,
        report: DriftReport,
        fmt: str = "json",
    ) -> str:
        """Export a drift report as a JSON or CSV string.

        Args:
            report: A :class:`DriftReport` to export.
            fmt: ``"json"`` or ``"csv"``.

        Returns:
            The serialised report.
        """
        return export_drift_report(report, fmt=fmt)

    def export_to_file(
        self,
        report: DriftReport,
        path: str,
        fmt: str = "json",
    ) -> str:
        """Export a drift report to a file.

        Args:
            report: A :class:`DriftReport` to export.
            path: Destination file path.
            fmt: ``"json"`` or ``"csv"``.

        Returns:
            The absolute path written.
        """
        return export_drift_report_to_file(report, path, fmt=fmt)

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------

    def _analyze_agent(
        self,
        agent_id: str,
        constitution_id: str,
        receipts: list[dict],
        window_start: datetime,
        threshold: float,
        projection_days: int,
    ) -> AgentDriftSummary:
        total = len(receipts)

        if total < _MIN_RECEIPTS:
            return AgentDriftSummary(
                agent_id=agent_id,
                constitution_id=constitution_id,
                status="INSUFFICIENT_DATA",
                total_receipts=total,
                checks=[],
                projected_breach_days=None,
            )

        # Collect per-check pass/fail across all receipts and per-day buckets
        # check_id → {"pass": int, "fail": int, "days": {day_offset: [0|1, ...]}}
        check_stats: dict[str, dict] = {}

        for r in receipts:
            ts = _parse_ts(r.get("timestamp", ""))
            day_off = _day_offset(ts, window_start) if ts else None

            for check in r.get("checks", []):
                if not isinstance(check, dict):
                    continue
                # Skip NOT_CHECKED entries
                if check.get("status") == "NOT_CHECKED":
                    continue

                cid = check.get("check_id", "unknown")
                if cid not in check_stats:
                    check_stats[cid] = {"pass": 0, "fail": 0, "day_points": {}}

                passed = check.get("passed", True)
                if passed:
                    check_stats[cid]["pass"] += 1
                else:
                    check_stats[cid]["fail"] += 1

                if day_off is not None:
                    day_key = int(day_off)
                    check_stats[cid]["day_points"].setdefault(day_key, []).append(
                        0.0 if passed else 1.0
                    )

        check_details: list[CheckDriftDetail] = []
        worst_breach: Optional[int] = None
        agent_status = "HEALTHY"

        for cid in sorted(check_stats):
            st = check_stats[cid]
            total_eval = st["pass"] + st["fail"]
            if total_eval == 0:
                continue

            fail_rate = st["fail"] / total_eval

            # Build per-day failure rates for trend
            day_points = st["day_points"]
            days_sorted = sorted(day_points.keys())
            if len(days_sorted) >= 2:
                xs = [float(d) for d in days_sorted]
                ys = [
                    sum(day_points[d]) / len(day_points[d])
                    for d in days_sorted
                ]
                slope = calculate_slope(xs, ys)
            else:
                slope = 0.0

            breach = project_breach(fail_rate, slope, threshold)

            # Status for this check
            if fail_rate >= threshold:
                check_status = "CRITICAL"
            elif breach is not None and breach <= projection_days:
                check_status = "WARNING"
            else:
                check_status = "HEALTHY"

            agent_status = _worst_status(agent_status, check_status)

            if breach is not None:
                if worst_breach is None or breach < worst_breach:
                    worst_breach = breach

            check_details.append(CheckDriftDetail(
                check_id=cid,
                total_evaluated=total_eval,
                pass_count=st["pass"],
                fail_count=st["fail"],
                fail_rate=fail_rate,
                trend_slope=slope,
                projected_breach_days=breach,
                status=check_status,
            ))

        return AgentDriftSummary(
            agent_id=agent_id,
            constitution_id=constitution_id,
            status=agent_status,
            total_receipts=total,
            checks=check_details,
            projected_breach_days=worst_breach if agent_status != "HEALTHY" else None,
        )


# ---------------------------------------------------------------------------
# Report formatting (used by CLI)
# ---------------------------------------------------------------------------

def format_drift_report(report: DriftReport) -> str:
    """Format a DriftReport as a human-readable terminal string."""
    lines: list[str] = []

    lines.append("")
    lines.append("Sanna Fleet Governance Report")
    lines.append("=" * 55)
    lines.append(
        f"Window: {report.window_days} days | "
        f"Threshold: {report.threshold * 100:.1f}% | "
        f"Generated: {report.generated_at}"
    )
    lines.append("")

    if not report.agents:
        lines.append("  No agents with receipts in this window.")
    else:
        for agent in report.agents:
            if agent.status == "INSUFFICIENT_DATA":
                lines.append(
                    f"  {agent.agent_id:<20} | "
                    f"{agent.total_receipts} receipts | "
                    f"INSUFFICIENT_DATA"
                )
                continue

            # Aggregate fail rate across all checks
            total_eval = sum(c.total_evaluated for c in agent.checks)
            total_fail = sum(c.fail_count for c in agent.checks)
            agg_rate = total_fail / total_eval if total_eval else 0.0

            # Aggregate trend direction
            slopes = [c.trend_slope for c in agent.checks if c.total_evaluated > 0]
            avg_slope = sum(slopes) / len(slopes) if slopes else 0.0
            if avg_slope > 0.001:
                trend_str = "^ degrading"
            elif avg_slope < -0.001:
                trend_str = "v improving"
            else:
                trend_str = "- stable"

            status_tag = agent.status
            line = (
                f"  {agent.agent_id:<20} | "
                f"Fail rate: {agg_rate * 100:5.1f}% | "
                f"Trend: {trend_str:<13} | "
                f"{status_tag}"
            )
            lines.append(line)

            if agent.projected_breach_days is not None and agent.projected_breach_days > 0:
                lines.append(
                    f"  {'':<20}   "
                    f"Projected threshold breach in {agent.projected_breach_days} days"
                )

    lines.append("")
    lines.append(f"Fleet Status: {report.fleet_status}")
    lines.append("=" * 55)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

_VALID_FORMATS = ("json", "csv")

_CSV_COLUMNS = [
    "window_days",
    "threshold",
    "generated_at",
    "fleet_status",
    "agent_id",
    "constitution_id",
    "agent_status",
    "total_receipts",
    "projected_breach_days",
    "check_id",
    "total_evaluated",
    "pass_count",
    "fail_count",
    "fail_rate",
    "trend_slope",
    "check_projected_breach_days",
    "check_status",
]


def export_drift_report(report: DriftReport, *, fmt: str = "json") -> str:
    """Serialise a :class:`DriftReport` as JSON or CSV.

    Args:
        report: The report to serialise.
        fmt: ``"json"`` or ``"csv"``.

    Returns:
        A string in the requested format.

    Raises:
        ValueError: If *fmt* is not ``"json"`` or ``"csv"``.
    """
    fmt = fmt.lower().strip()
    if fmt not in _VALID_FORMATS:
        raise ValueError(f"Unsupported format: {fmt!r} (expected 'json' or 'csv')")

    if fmt == "json":
        return json.dumps(asdict(report), indent=2)

    return _report_to_csv(report)


def export_drift_report_to_file(
    report: DriftReport,
    path: str,
    *,
    fmt: str = "json",
) -> str:
    """Write a drift report to *path* in the given format.

    Returns the absolute path written.
    """
    content = export_drift_report(report, fmt=fmt)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return str(p.resolve())


def _report_to_csv(report: DriftReport) -> str:
    """Flatten a DriftReport into one CSV row per check per agent."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)

    if not report.agents:
        # Write a single summary row with no agent detail
        writer.writerow([
            report.window_days,
            report.threshold,
            report.generated_at,
            report.fleet_status,
            "", "", "", "", "",
            "", "", "", "", "", "", "", "",
        ])
    else:
        for agent in report.agents:
            if not agent.checks:
                # Agent with INSUFFICIENT_DATA — one row, no check detail
                writer.writerow([
                    report.window_days,
                    report.threshold,
                    report.generated_at,
                    report.fleet_status,
                    agent.agent_id,
                    agent.constitution_id,
                    agent.status,
                    agent.total_receipts,
                    agent.projected_breach_days or "",
                    "", "", "", "", "", "", "", "",
                ])
            else:
                for check in agent.checks:
                    writer.writerow([
                        report.window_days,
                        report.threshold,
                        report.generated_at,
                        report.fleet_status,
                        agent.agent_id,
                        agent.constitution_id,
                        agent.status,
                        agent.total_receipts,
                        agent.projected_breach_days or "",
                        check.check_id,
                        check.total_evaluated,
                        check.pass_count,
                        check.fail_count,
                        check.fail_rate,
                        check.trend_slope,
                        check.projected_breach_days or "",
                        check.status,
                    ])

    return buf.getvalue()
