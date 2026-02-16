# Drift Report Exports

Sanna drift analytics detect governance degradation over time using per-agent, per-check failure-rate trending with linear regression. Reports export to JSON and CSV for ingestion into external monitoring tools.

## Generating Reports

### CLI

```bash
# Default 30-day window, console output
sanna-drift-report --db .sanna/receipts.db

# Custom window with JSON export
sanna-drift-report --db .sanna/receipts.db --window 14 --export json --output drift.json

# CSV export for spreadsheet/BI tools
sanna-drift-report --db .sanna/receipts.db --window 30 --export csv --output drift.csv
```

### Python API

```python
from sanna import DriftAnalyzer, ReceiptStore
from sanna.drift import export_drift_report, export_drift_report_to_file

store = ReceiptStore(".sanna/receipts.db")
analyzer = DriftAnalyzer(store)
report = analyzer.analyze(window_days=30)

# Console summary
print(f"Fleet status: {report.fleet_status}")
for agent in report.agents:
    print(f"  {agent.agent_id}: {agent.fail_rate:.1%} fail rate, {agent.trend}")

# Export
json_str = export_drift_report(report, format="json")
export_drift_report_to_file(report, "drift.csv", format="csv")
```

## Export Formats

### JSON

```json
{
  "generated_at": "2026-02-14T18:32:07+00:00",
  "window_days": 30,
  "threshold": 0.15,
  "fleet_status": "WARNING",
  "agents": [
    {
      "agent_id": "support-agent",
      "fail_rate": 0.021,
      "trend": "stable",
      "projected_breach_days": null,
      "checks": [
        {
          "check_id": "C1",
          "fail_rate": 0.015,
          "trend_slope": -0.001,
          "status": "HEALTHY"
        }
      ]
    }
  ]
}
```

### CSV

```csv
agent_id,check_id,fail_rate,trend_slope,projected_breach_days,status
support-agent,C1,0.015,-0.001,,HEALTHY
support-agent,C2,0.032,0.002,,HEALTHY
research-agent,C1,0.113,0.008,14,WARNING
```

## Integration Examples

### Splunk

Ingest JSON drift reports via HTTP Event Collector (HEC):

```bash
# Export and send to Splunk
sanna-drift-report --db .sanna/receipts.db --export json --output /dev/stdout | \
  curl -k https://splunk:8088/services/collector/event \
    -H "Authorization: Splunk YOUR_HEC_TOKEN" \
    -d @-
```

Or set up a cron job:

```bash
# /etc/cron.d/sanna-drift
0 */6 * * * sanna-drift-report --db /var/sanna/receipts.db --export json --output /var/log/sanna/drift.json
```

### Datadog

Create custom metrics from drift data using the Datadog API:

```python
from datadog import api
from sanna import DriftAnalyzer, ReceiptStore

store = ReceiptStore(".sanna/receipts.db")
analyzer = DriftAnalyzer(store)
report = analyzer.analyze(window_days=7)

for agent in report.agents:
    api.Metric.send(
        metric="sanna.governance.fail_rate",
        points=agent.fail_rate,
        tags=[f"agent:{agent.agent_id}"],
    )
```

### Grafana

Connect Grafana to the SQLite receipt store directly using the SQLite datasource plugin, or query the JSON exports. Example panel query:

```sql
SELECT
  json_extract(metadata, '$.agent_id') AS agent_id,
  coherence_status,
  COUNT(*) AS count,
  timestamp
FROM receipts
WHERE timestamp > datetime('now', '-30 days')
GROUP BY agent_id, coherence_status
ORDER BY timestamp
```

### Tableau

Connect directly to the CSV export or SQLite database:

1. Open Tableau Desktop
2. Connect to "Text file" and select the CSV export
3. Create a worksheet with `agent_id` on rows, `fail_rate` on columns
4. Add `projected_breach_days` as a color dimension to highlight agents approaching threshold

For live data, connect to the SQLite database directly:
1. Connect to "Other Databases (ODBC)" with an SQLite driver
2. Point to `.sanna/receipts.db`
3. Use the `receipts` table with `metadata` JSON fields
