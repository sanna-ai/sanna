# Receipt Format

Sanna receipts are JSON documents conforming to `spec/receipt.schema.json`. Each receipt is deterministically fingerprinted and optionally Ed25519-signed.

## Scores and Numeric Values

Scores in receipts use **integer basis points** (8500 = 85.00%) for deterministic canonicalization. Floating-point numbers cause hash instability across platforms due to IEEE 754 representation differences. The `sanitize_for_signing()` function enforces this: lossless floats (e.g., 71.0) are silently converted to integers; lossy floats (e.g., 71.43) raise a `TypeError` with the JSON path.

## Complete Receipt Example

```json
{
  "schema_version": "0.1",
  "tool_version": "0.12.3",
  "checks_version": "4",
  "receipt_id": "sanna-receipt-a1b2c3d4",
  "receipt_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "trace_id": "trace-550e8400-e29b",
  "timestamp": "2026-02-16T12:00:00+00:00",
  "inputs": {
    "query": "What was revenue growth?",
    "context": "Annual report: revenue increased 12% YoY to $4.2B."
  },
  "outputs": {
    "output": "Based on the data, revenue grew 12% year-over-year."
  },
  "context_hash": "a1b2c3d4e5f6...",
  "output_hash": "f6e5d4c3b2a1...",
  "final_answer_provenance": {
    "source": "function_return",
    "span_id": null,
    "span_name": null,
    "field": null
  },
  "checks": [
    {
      "check_id": "C1",
      "name": "Context Contradiction",
      "passed": true,
      "severity": "high",
      "evidence": "",
      "details": null,
      "triggered_by": "INV_NO_FABRICATION",
      "enforcement_level": "halt",
      "check_impl": "sanna.context_contradiction",
      "replayable": true
    },
    {
      "check_id": "C2",
      "name": "Unmarked Inference",
      "passed": true,
      "severity": "medium",
      "evidence": "",
      "details": null,
      "triggered_by": "INV_MARK_INFERENCE",
      "enforcement_level": "warn",
      "check_impl": "sanna.unmarked_inference",
      "replayable": true
    }
  ],
  "checks_passed": 2,
  "checks_failed": 0,
  "coherence_status": "PASS",
  "evaluation_coverage": {
    "total_invariants": 2,
    "evaluated": 2,
    "not_checked": [],
    "coverage_basis_points": 10000
  },
  "constitution_ref": {
    "document_id": "support-agent",
    "policy_hash": "abc123def456...",
    "version": "0.1.0",
    "source": "/path/to/constitution.yaml",
    "scheme": "Ed25519",
    "key_id": "sha256-fingerprint...",
    "constitution_approval": {
      "status": "unapproved"
    }
  },
  "halt_event": {
    "halted": false,
    "reason": null,
    "failed_checks": [],
    "timestamp": null,
    "enforcement_mode": null
  },
  "receipt_signature": {
    "value": "base64-encoded-ed25519-signature...",
    "key_id": "sha256-fingerprint...",
    "scheme": "Ed25519"
  }
}
```

## Field Reference

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Receipt schema version (currently `"0.1"`) |
| `tool_version` | string | Sanna package version that generated this receipt |
| `checks_version` | string | Check algorithm version (part of fingerprint) |
| `receipt_id` | string | Unique receipt identifier |
| `receipt_fingerprint` | string | SHA-256 deterministic fingerprint of all receipt content |
| `trace_id` | string | Trace identifier linking the receipt to a specific execution |
| `timestamp` | string | ISO 8601 UTC timestamp |
| `inputs` | object | Query and context provided to the agent |
| `outputs` | object | Agent's response |
| `context_hash` | string | SHA-256 of the input context |
| `output_hash` | string | SHA-256 of the output |
| `coherence_status` | string | Overall status: `PASS`, `WARN`, or `FAIL` |
| `checks_passed` | int | Number of checks that passed |
| `checks_failed` | int | Number of checks that failed |

### Check Result

| Field | Type | Description |
|-------|------|-------------|
| `check_id` | string | Check identifier (e.g., `C1`, `INV_PII_CHECK`) |
| `name` | string | Human-readable check name |
| `passed` | bool | Whether the check passed |
| `severity` | string | `high`, `medium`, or `low` |
| `evidence` | string | Evidence string (populated on failure) |
| `triggered_by` | string | Invariant ID that triggered this check |
| `enforcement_level` | string | `halt`, `warn`, or `log` |
| `check_impl` | string | Namespaced check implementation ID |
| `replayable` | bool | Whether this check can be re-run offline |

### Evaluation Coverage

| Field | Type | Description |
|-------|------|-------------|
| `total_invariants` | int | Total invariants in the constitution |
| `evaluated` | int | Number actually evaluated |
| `not_checked` | list | Invariant IDs that were not evaluated |
| `coverage_basis_points` | int | Coverage as basis points (10000 = 100%) |

### Constitution Reference

| Field | Type | Description |
|-------|------|-------------|
| `document_id` | string | Agent name from the constitution |
| `policy_hash` | string | SHA-256 of the constitution content |
| `version` | string | Constitution schema version |
| `source` | string | Path to the constitution file |
| `scheme` | string | Signature scheme (e.g., `Ed25519`) |
| `key_id` | string | SHA-256 fingerprint of the signing key |
| `constitution_approval` | object | Approval status: `{"status": "unapproved"}` or full approval record |

### Gateway Extensions

Gateway receipts include additional fields in `extensions`:

| Field | Type | Description |
|-------|------|-------------|
| `arguments_hash` | string | SHA-256 of tool call arguments |
| `arguments_hash_method` | string | `jcs` (canonical JSON) or `json_dumps_fallback` |
| `tool_output_hash` | string | SHA-256 of downstream tool output |
| `downstream_is_error` | bool | Whether the downstream returned an error |

## Fingerprint Construction

The receipt fingerprint is a SHA-256 hash of a pipe-delimited string:

```
{trace_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{halt_hash}|{coverage_hash}
```

Optional fields appended when present (in order):
- `authority_decisions`
- `escalation_events`
- `source_trust_evaluations`
- `extensions`

`constitution_approval` is stripped from `constitution_ref` before hashing (approval is mutable metadata, verified separately).

## Inspecting Receipts

```bash
sanna inspect receipt.json         # Pretty-printed summary
sanna inspect receipt.json --json  # Formatted JSON
sanna verify receipt.json          # Full integrity verification
```
