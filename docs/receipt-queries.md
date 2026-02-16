# Querying and Visualizing Receipts

Sanna stores receipts in SQLite via `ReceiptStore`. This document covers common queries, dashboard setup, and integration patterns.

## SQLite Receipt Store

```python
from sanna import ReceiptStore

store = ReceiptStore(".sanna/receipts.db")

# Save a receipt
store.save(receipt)

# Query with filters
results = store.query(
    agent_id="support-agent",
    status="FAIL",
    since="2026-02-01",
    until="2026-02-14",
    limit=100,
    offset=0,
)

# Count matching receipts
count = store.count(agent_id="support-agent", status="FAIL")

store.close()
```

### Available Filters

| Filter | Type | Description |
|--------|------|-------------|
| `agent_id` | str | Filter by agent name |
| `constitution_id` | str | Filter by constitution document ID |
| `trace_id` | str | Filter by trace ID |
| `status` | str | Filter by coherence status (PASS/WARN/FAIL/PARTIAL) |
| `halt_event` | bool | Filter for halted receipts only |
| `check_status` | str | Filter by specific check outcome |
| `since` | str | ISO 8601 start time |
| `until` | str | ISO 8601 end time |
| `limit` | int | Maximum results (default 100, max 500) |
| `offset` | int | Pagination offset |

## Common SQL Queries

The receipt store uses a `receipts` table with indexed `metadata` (JSON) and `receipt_json` columns. You can query it directly with any SQLite client.

### Failure rate by agent (last 30 days)

```sql
SELECT
  json_extract(metadata, '$.agent_id') AS agent_id,
  COUNT(*) AS total,
  SUM(CASE WHEN json_extract(metadata, '$.coherence_status') = 'FAIL' THEN 1 ELSE 0 END) AS failures,
  ROUND(
    CAST(SUM(CASE WHEN json_extract(metadata, '$.coherence_status') = 'FAIL' THEN 1 ELSE 0 END) AS REAL)
    / COUNT(*) * 100, 2
  ) AS fail_rate_pct
FROM receipts
WHERE json_extract(metadata, '$.timestamp') > datetime('now', '-30 days')
GROUP BY agent_id
ORDER BY fail_rate_pct DESC;
```

### Halted actions (all time)

```sql
SELECT
  json_extract(metadata, '$.agent_id') AS agent_id,
  json_extract(metadata, '$.timestamp') AS ts,
  json_extract(receipt_json, '$.halt_event.reason') AS halt_reason
FROM receipts
WHERE json_extract(receipt_json, '$.halt_event.halted') = 1
ORDER BY ts DESC
LIMIT 50;
```

### Check failure breakdown

```sql
SELECT
  json_extract(value, '$.check_id') AS check_id,
  json_extract(value, '$.name') AS check_name,
  COUNT(*) AS failure_count
FROM receipts, json_each(json_extract(receipt_json, '$.checks'))
WHERE json_extract(value, '$.passed') = 0
  AND json_extract(metadata, '$.timestamp') > datetime('now', '-7 days')
GROUP BY check_id
ORDER BY failure_count DESC;
```

### Gateway authority decisions

```sql
SELECT
  json_extract(value, '$.action') AS tool,
  json_extract(value, '$.decision') AS decision,
  json_extract(value, '$.reason') AS reason,
  COUNT(*) AS count
FROM receipts, json_each(json_extract(receipt_json, '$.authority_decisions'))
WHERE json_extract(metadata, '$.timestamp') > datetime('now', '-7 days')
GROUP BY tool, decision
ORDER BY count DESC;
```

### Receipt Triad verification status

```sql
SELECT
  json_extract(receipt_json, '$.extensions.gateway_v2.receipt_triad.context_limitation') AS context,
  json_extract(receipt_json, '$.extensions.gateway_v2.action.tool') AS tool,
  json_extract(receipt_json, '$.extensions.gateway_v2.receipt_triad.input_hash') AS input_hash,
  json_extract(receipt_json, '$.extensions.gateway_v2.reasoning_evaluation.passed') AS reasoning_passed
FROM receipts
WHERE json_extract(receipt_json, '$.extensions.gateway_v2') IS NOT NULL
ORDER BY json_extract(metadata, '$.timestamp') DESC
LIMIT 20;
```

## MCP Query Tool

The `sanna_query_receipts` MCP tool provides receipt queries and drift analysis directly from Claude Desktop or other MCP clients:

```
Tool: sanna_query_receipts
Parameters:
  db_path: ".sanna/receipts.db"
  agent_id: "support-agent"
  status: "FAIL"
  since: "2026-02-01"
  limit: 50
  analysis: "drift"   # optional — run drift analysis instead of listing
```

## Grafana Dashboard

### Setup with SQLite datasource

1. Install the [frser-sqlite-datasource](https://grafana.com/grafana/plugins/frser-sqlite-datasource/) plugin
2. Add a new datasource pointing to your receipt database
3. Import the dashboard JSON below

### Example panel: Failure rate over time

```json
{
  "title": "Governance Failure Rate",
  "type": "timeseries",
  "datasource": "SQLite",
  "targets": [
    {
      "rawSql": "SELECT date(json_extract(metadata, '$.timestamp')) AS time, ROUND(CAST(SUM(CASE WHEN json_extract(metadata, '$.coherence_status') = 'FAIL' THEN 1 ELSE 0 END) AS REAL) / COUNT(*) * 100, 2) AS fail_rate FROM receipts GROUP BY time ORDER BY time",
      "format": "time_series"
    }
  ]
}
```

### Example panel: Authority decisions

```json
{
  "title": "Authority Decisions",
  "type": "piechart",
  "datasource": "SQLite",
  "targets": [
    {
      "rawSql": "SELECT json_extract(value, '$.decision') AS decision, COUNT(*) AS count FROM receipts, json_each(json_extract(receipt_json, '$.authority_decisions')) GROUP BY decision",
      "format": "table"
    }
  ]
}
```
