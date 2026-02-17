# OpenTelemetry Integration

Sanna emits OpenTelemetry signals to help correlate governed actions with the receipts it writes and signs. Receipts are the canonical audit artifact. Telemetry is optional and intended for operational visibility (dashboards, alerts, correlation), not as an audit substitute.

## Installation

```bash
pip install "sanna[otel]"
```

OTel dependencies are optional. Without them, Sanna operates normally with no telemetry overhead.

## Usage

```python
from sanna.exporters.otel_exporter import receipt_to_span
from opentelemetry import trace

tracer = trace.get_tracer("sanna")
receipt_to_span(receipt, tracer, artifact_uri="s3://bucket/receipt.json")
```

`receipt_to_span()` creates an OTel span from a Sanna receipt dict. The `artifact_uri` parameter is optional and records where the full receipt is stored (filesystem path, S3 URI, etc.).

### Exporter class

```python
from sanna.exporters.otel_exporter import SannaOTelExporter

exporter = SannaOTelExporter(delegate=your_span_exporter)
```

`SannaOTelExporter` wraps a standard OTel `SpanExporter` and filters for Sanna governance spans.

## Guaranteed Signals (stable)

These attributes are part of the public contract and will not change without a major version bump:

| Attribute | Description |
|---|---|
| Span name: `sanna.governance.evaluation` | One span per governance evaluation |
| `sanna.receipt.id` | Receipt trace ID for correlation |
| `sanna.artifact.uri` | File path or URI where full receipt is stored |
| `sanna.artifact.content_hash` | SHA-256 of canonical receipt JSON |
| Status mapping | `PASS` → `StatusCode.OK`, `HALT`/`FAIL` → `StatusCode.ERROR` |

## Experimental Signals (may change)

These attributes are emitted but their names, types, or presence may change in future releases:

- `sanna.check.c1.status` through `sanna.check.c5.status` — individual check results (`pass`/`fail`/`not_checked`/`absent`)
- `sanna.coherence_status` — overall coherence status
- `sanna.enforcement_decision` — enforcement decision from middleware
- `sanna.authority.decision` — authority boundary decision
- `sanna.escalation.triggered` — whether escalation occurred (boolean)
- `sanna.constitution.policy_hash` — constitution policy hash
- `sanna.constitution.version` — constitution schema version
- `sanna.evaluation_coverage.pct` — evaluation coverage percentage
- `sanna.source_trust.flags` — count of source trust verification flags

### Span Events

Each check result is recorded as a span event named `check.{check_id}` with attributes: `check_id`, `name`, `passed`, `severity`, `evidence`.

Each authority decision is recorded as a span event named `authority.{decision}` with attributes: `action`, `decision`, `reason`, `boundary_type`.

## Design: Pointer + Hash

Sanna does NOT embed full receipt JSON in OTel spans. Instead, spans carry a pointer (`artifact.uri`) and integrity hash (`artifact.content_hash`). This keeps span payloads small while enabling full audit trail retrieval from the receipt store.

To verify a receipt referenced by a span:

1. Retrieve the receipt from the location in `sanna.artifact.uri`
2. Compute SHA-256 of the canonical JSON
3. Compare with `sanna.artifact.content_hash`
4. Run `sanna verify` for full integrity check

## Off by Default

No telemetry is emitted unless you explicitly create and configure an exporter. No OTel dependency is installed unless you use `pip install "sanna[otel]"`.
