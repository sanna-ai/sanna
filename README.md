# Sanna

Truth infrastructure for AI agents. Checks reasoning during execution, halts when constraints are violated, generates portable receipts proving governance was enforced.

Observability tools show you what happened. Guardrails filter I/O. Sanna proves the reasoning held together — and gives you a portable receipt you can verify offline, hand to an auditor, or use in court.

## Install

```bash
pip install sanna                # core library
pip install sanna[mcp]           # MCP server for Claude Desktop / Cursor
pip install sanna[otel]          # OpenTelemetry bridge
pip install sanna[langfuse]      # Langfuse adapter
```

Requires Python 3.10+.

## Quickstart

**1. Generate a constitution**

```bash
sanna-init
```

This walks you through template selection (Enterprise IT, Customer-Facing, or General Purpose), agent identity, and enforcement levels. It produces a YAML file ready for signing.

Or write one manually:

```yaml
# constitution.yaml
sanna_constitution: "1.0.0"

identity:
  agent_name: "my-agent"
  domain: "customer-service"

provenance:
  authored_by: "team@company.com"
  approved_by: ["lead@company.com"]
  approval_date: "2026-02-13"
  approval_method: "manual-sign-off"

boundaries:
  - id: "B001"
    description: "Only answer product questions"
    category: "scope"
    severity: "high"

invariants:
  - id: "INV_NO_FABRICATION"
    rule: "Do not claim facts absent from provided sources."
    enforcement: "halt"
  - id: "INV_MARK_INFERENCE"
    rule: "Clearly mark inferences and speculation."
    enforcement: "warn"

policy_hash: null
```

**2. Sign it**

```bash
sanna-keygen --signed-by "team@company.com"
sanna-sign-constitution constitution.yaml --private-key <your-key-id>.key
```

**3. Wrap your agent function**

```python
from sanna import sanna_observe, SannaHaltError

@sanna_observe(constitution_path="constitution.yaml")
def my_agent(query: str, context: str) -> str:
    return "Based on the data, revenue grew 12% year-over-year."

try:
    result = my_agent(
        query="What was revenue growth?",
        context="Annual report: revenue increased 12% YoY to $4.2B."
    )
    print(result.output)   # the agent's response
    print(result.receipt)  # the reasoning receipt (dict)
except SannaHaltError as e:
    print(f"HALTED: {e}")
    print(e.receipt)       # receipt is still generated on halt
```

**4. Verify offline**

```bash
sanna-verify receipt.json
sanna-verify receipt.json --public-key <your-key-id>.pub
sanna-verify receipt.json \
  --constitution constitution.yaml \
  --constitution-public-key <your-key-id>.pub
```

No network. No API keys. Full chain verification.

## What Sanna Does

Three primitives:

**Constitutions** define agent boundaries — identity, provenance, invariants (which reasoning checks to run and at what enforcement level), authority boundaries (what actions the agent can/cannot take), trusted source tiers, and halt conditions. Written in YAML, Ed25519-signed, tamper-detected on load.

**Checks** run during execution, not after. Five built-in coherence checks (C1-C5) evaluate the agent's output against its input context in real time. Each check enforces independently — halt (stop execution), warn (Python warning), or log (record silently).

**Receipts** are portable JSON artifacts that prove governance was enforced. Each receipt contains the check results, input/output hashes, a deterministic fingerprint, constitution provenance, and optionally an Ed25519 signature. Receipts are schema-validated and offline-verifiable.

## Features

### Coherence Checks (C1-C5)

| Check | Invariant | What it catches |
|-------|-----------|-----------------|
| C1 | `INV_NO_FABRICATION` | Output contradicts explicit statements in the context |
| C2 | `INV_MARK_INFERENCE` | Definitive claims without hedging language |
| C3 | `INV_NO_FALSE_CERTAINTY` | Confidence exceeding evidence strength |
| C4 | `INV_PRESERVE_TENSION` | Conflicting information collapsed into one answer |
| C5 | `INV_NO_PREMATURE_COMPRESSION` | Complex input reduced to a single sentence |

Built-in checks are deterministic heuristics (pattern matching). They run without external dependencies or API calls.

### Custom Invariant Evaluators

Register domain-specific checks that participate in the receipt pipeline:

```python
from sanna.evaluators import register_invariant_evaluator
from sanna.receipt import CheckResult

@register_invariant_evaluator("INV_CUSTOM_PII")
def check_pii(context, output, constitution, check_config):
    if "SSN" in output:
        return CheckResult(
            check_id="INV_CUSTOM_PII", name="PII Check",
            passed=False, severity="critical",
            details="Output contains SSN pattern",
        )
    return CheckResult(
        check_id="INV_CUSTOM_PII", name="PII Check",
        passed=True, severity="info",
    )
```

Custom evaluators that raise exceptions produce `ERRORED` status — the pipeline continues and the receipt records the error.

### LLM-as-Judge Evaluators

Optional semantic evaluation using an LLM for C1-C5 checks. Uses stdlib `urllib.request` — no extra dependencies.

```python
from sanna.evaluators.llm import enable_llm_checks

# Register LLM evaluators for all 5 checks
enable_llm_checks(api_key="sk-ant-...")

# Or a subset
enable_llm_checks(api_key="sk-ant-...", checks=["C1", "C3"])
```

On failure (timeout, HTTP error, malformed response), checks return `ERRORED` status rather than crashing the pipeline. Module: `sanna.evaluators.llm`.

### Constitution System

Constitutions are YAML or JSON documents that define the agent's governance surface:

- **Identity**: agent name, domain, description, extensions
- **Provenance**: author, approvers, approval date/method, change history
- **Boundaries**: operational constraints with category and severity
- **Invariants**: which checks to run and at what enforcement level (`halt`/`warn`/`log`)
- **Authority boundaries**: `cannot_execute`, `must_escalate`, `can_execute`
- **Trusted sources**: 4-tier source classification for C1 evaluation
- **Halt conditions**: when the agent should stop

Three built-in templates via `sanna-init`: Enterprise IT (strict), Customer-Facing (standard), General Purpose (advisory).

Constitutions are Ed25519-signed. The signature covers the full document. Hash integrity is verified on load — any modification after signing is detected.

### Authority Boundaries

Three-tier action control defined in the constitution:

| Boundary | Behavior |
|----------|----------|
| `cannot_execute` | Action is halted immediately |
| `must_escalate` | Action is routed to an escalation target |
| `can_execute` | Action is explicitly allowed |

Escalation targets: `log` (Python logging), `webhook` (HTTP POST via httpx), `callback` (registry-based callable).

```python
from sanna import evaluate_authority, load_constitution

const = load_constitution("constitution.yaml")
decision = evaluate_authority("send_email", {"to": "user@example.com"}, const)
# decision.decision = "halt", decision.boundary_type = "cannot_execute"
```

### Trusted Source Tiers

Constitutions classify data sources into trust tiers that affect C1 evaluation:

| Tier | C1 Behavior |
|------|-------------|
| `tier_1` | Full trust — claims count as grounded evidence |
| `tier_2` | Evidence with verification flag in receipt |
| `tier_3` | Reference only — cannot be sole basis for failure |
| `untrusted` | Excluded from C1 evaluation |

### Cryptographic Signing

- **Ed25519 keypair generation**: `sanna-keygen`
- **Constitution signing**: full-document signature with scheme versioning (`constitution_sig_v1`)
- **Receipt signing**: metadata-binding signature (`receipt_sig_v1`)
- **Key ID**: SHA-256 fingerprint of the public key (64 hex chars)

Module: `sanna.crypto`

### Offline Verification

`verify_receipt()` checks schema validation, hash format, content hashes, fingerprint recomputation, status consistency, check counts, and optionally Ed25519 signature and constitution chain.

```python
from sanna import verify_receipt, load_schema

schema = load_schema()
result = verify_receipt(receipt, schema)
# result.valid, result.errors, result.warnings
```

### Evidence Bundles

Self-contained zip archives with receipt + constitution + public key for offline verification:

```bash
sanna-create-bundle \
  --receipt receipt.json \
  --constitution constitution.yaml \
  --public-key <your-key-id>.pub \
  --output evidence.zip

sanna-verify-bundle evidence.zip
```

Seven-step verification: bundle structure, receipt schema, receipt fingerprint, constitution signature, provenance chain, receipt signature, approval verification.

Module: `sanna.bundle`

### Receipt Persistence

SQLite-backed storage with indexed metadata columns:

```python
from sanna import ReceiptStore

store = ReceiptStore(".sanna/receipts.db")
store.save(receipt)
results = store.query(agent_id="my-agent", status="FAIL", limit=50)
count = store.count(agent_id="my-agent")
store.close()
```

Auto-save from the decorator:

```python
@sanna_observe(constitution_path="constitution.yaml", store=".sanna/receipts.db")
def my_agent(query: str, context: str) -> str:
    ...
```

Supports combinable filters: `agent_id`, `constitution_id`, `trace_id`, `status`, `halt_event`, `check_status`, `since`, `until`, `limit`, `offset`.

Module: `sanna.store`

### Drift Analytics

Per-agent, per-check failure-rate trending with linear regression:

```python
from sanna import DriftAnalyzer, ReceiptStore

store = ReceiptStore(".sanna/receipts.db")
analyzer = DriftAnalyzer(store)
report = analyzer.analyze(window_days=30)
# report.fleet_status: "HEALTHY" / "WARNING" / "CRITICAL"
# report.agents[0].checks[0].trend_slope, .projected_breach_days
```

Multi-window analysis, threshold breach projection, fleet health status. Export to JSON or CSV via `export_drift_report()` / `export_drift_report_to_file()`.

```
$ sanna-drift-report --db .sanna/receipts.db --window 30

Sanna Fleet Governance Report
=======================================================
Window: 30 days | Threshold: 15.0% | Generated: 2026-02-14T18:32:07+00:00

  support-agent        | Fail rate:   2.1% | Trend: - stable       | HEALTHY
  research-agent       | Fail rate:  11.3% | Trend: ^ degrading    | WARNING
                         Projected threshold breach in 14 days
  summarizer-agent     | Fail rate:  22.7% | Trend: ^ degrading    | CRITICAL

Fleet Status: CRITICAL
=======================================================
```

Module: `sanna.drift`

### OpenTelemetry Bridge

Exports receipts as OTel spans with a pointer + integrity hash design — span payloads stay small while preserving verifiability.

```python
from sanna.exporters.otel_exporter import receipt_to_span
from opentelemetry import trace

tracer = trace.get_tracer("sanna")
receipt_to_span(receipt, tracer, artifact_uri="s3://bucket/receipt.json")
```

15 `sanna.*` span attributes. Requires `pip install sanna[otel]`.

Module: `sanna.exporters.otel_exporter`

### Langfuse Adapter

Convert Langfuse traces to Sanna receipts:

```python
from sanna.adapters.langfuse import langfuse_trace_to_trace_data
from sanna import generate_receipt

trace_data = langfuse_trace_to_trace_data(langfuse_trace.data)
receipt = generate_receipt(trace_data)
```

Requires `pip install sanna[langfuse]`.

Module: `sanna.adapters.langfuse`

### Golden Test Vectors

Deterministic test vectors in `tests/vectors/` for third-party verifier implementations. Cover RFC 8785 canonical JSON, Ed25519 constitution signatures, and receipt signatures using fixed seeds.

## Reasoning Receipts

Sanna generates **reasoning receipts** — cryptographically-signed artifacts that prove an AI agent's reasoning was evaluated against governance rules.

### Receipt Triad

Every reasoning receipt cryptographically binds three components:
- **Input Hash**: What the agent saw (context leading to action)
- **Reasoning Hash**: Why it decided (justification for action)
- **Action Hash**: What it did (tool call + parameters)

### Gateway Checks

Reasoning is evaluated through four checks:
1. **Presence**: Justification exists and is non-empty
2. **Substance**: Meets minimum length requirement (default 20 chars)
3. **No Parroting**: Doesn't contain blocklist phrases like "because you asked"
4. **LLM Coherence**: Semantic alignment between reasoning and action (0.0-1.0 score)

Configure reasoning governance in your constitution's `reasoning:` section. Model selection for LLM coherence is configured via the `SANNA_LLM_MODEL` environment variable.

See [docs/reasoning-receipts.md](docs/reasoning-receipts.md) for full details.

## CLI Reference

| Command | Description |
|---------|-------------|
| `sanna-init` | Interactive constitution generator with template selection |
| `sanna-init-constitution` | Scaffold a blank constitution YAML |
| `sanna-keygen` | Generate Ed25519 keypair (`--signed-by` for metadata) |
| `sanna-sign-constitution` | Sign a constitution (`--private-key KEY`) |
| `sanna-hash-constitution` | Compute policy hash without Ed25519 signing |
| `sanna-verify-constitution` | Verify a constitution's Ed25519 signature |
| `sanna-verify` | Verify receipt integrity, signature, and provenance chain |
| `sanna-verify-bundle` | Verify an evidence bundle (7-step check) |
| `sanna-create-bundle` | Create an evidence bundle zip |
| `sanna-generate` | Generate a receipt from a Langfuse trace |
| `sanna-drift-report` | Fleet governance drift report (`--window`, `--export`, `--output`) |
| `sanna-approve-constitution` | Approve a signed constitution with Ed25519 |
| `sanna-diff` | Diff two constitutions (text/JSON/markdown) |
| `sanna-mcp` | Start MCP server (stdio transport) |
| `sanna-gateway` | Start MCP enforcement proxy (stdio transport) |

## MCP Server

Sanna exposes 7 tools over [MCP](https://modelcontextprotocol.io/) stdio transport for Claude Desktop, Cursor, and other MCP clients.

```bash
pip install sanna[mcp]
```

Add to your MCP client config (e.g., `~/.config/claude/config.json`):

```json
{
  "mcpServers": {
    "sanna": {
      "command": "sanna-mcp",
      "args": []
    }
  }
}
```

**Tools:**

| Tool | Parameters | Description |
|------|-----------|-------------|
| `sanna_verify_receipt` | `receipt_json` | Verify a receipt offline |
| `sanna_generate_receipt` | `query`, `context`, `response`, `constitution_path?` | Generate a receipt with constitution enforcement |
| `sanna_list_checks` | — | List C1-C5 checks with descriptions |
| `sanna_evaluate_action` | `action_name`, `action_params`, `constitution_path` | Evaluate action against authority boundaries |
| `sanna_query_receipts` | `db_path?`, `agent_id?`, `status?`, `since?`, `until?`, `halt_only?`, `limit?`, `analysis?` | Query stored receipts or run drift analysis |
| `check_constitution_approval` | `constitution_path`, `author_public_key_path?`, `approver_public_key_path?` | Check approval status with optional key verification |
| `sanna_verify_identity_claims` | `constitution_path`, `provider_keys?` | Verify identity claims against provider public keys |

## MCP Enforcement Gateway

The gateway sits between any MCP client (Claude Desktop, Claude Code) and downstream MCP servers. Every tool call is evaluated against a constitution before forwarding. Every call — allowed, denied, or escalated — generates a receipt.

```
MCP Client (Claude Desktop / Claude Code)
        ↓ (MCP stdio)
sanna-gateway
        ↓ evaluate against constitution
        ↓ generate receipt
        ↓ (MCP stdio, child processes)
Downstream MCP Servers (Notion, GitHub, filesystem, etc.)
```

### Gateway Quickstart

```bash
pip install sanna[mcp]

# Generate a signing key for the gateway
sanna-keygen --signed-by "you@company.com" --label gateway

# Create a gateway config (see below) and start
sanna-gateway --config gateway.yaml
```

### Claude Desktop Integration

Add the gateway to your Claude Desktop config (`~/.config/claude/config.json`):

```json
{
  "mcpServers": {
    "governed-notion": {
      "command": "sanna-gateway",
      "args": ["--config", "/path/to/gateway.yaml"]
    }
  }
}
```

The gateway discovers all tools from downstream servers and exposes them with a namespace prefix (e.g., `notion_search`, `notion_update_page`). Claude sees governed tools — the gateway enforces policy transparently.

### Gateway Configuration

```yaml
gateway:
  transport: stdio
  constitution: ./constitutions/openclaw-personal.yaml
  receipt_store: ./receipts/

downstream:
  - name: notion
    command: npx
    args: ["-y", "@notionhq/notion-mcp-server"]
    env:
      NOTION_API_KEY: "${NOTION_API_KEY}"
    timeout: 30
```

### Policy Reference

Constitution authority boundaries control gateway behavior:

| Boundary | Gateway Behavior |
|----------|-----------------|
| `can_execute` | Tool call forwarded to downstream server |
| `must_escalate` | Client prompted for approval before forwarding |
| `cannot_execute` | Tool call denied, error returned to client |

Priority: `cannot_execute` > `must_escalate` > `can_execute` > default (allow).

Actions not matching any boundary are allowed by default. The matching algorithm uses bidirectional substring matching with separator normalization (`_`, `-`, `.` treated as spaces).

### Constitution Templates

Five pre-built constitutions in `examples/constitutions/`:

| Template | Use Case | Autonomous | Escalated | Halted |
|----------|----------|-----------|-----------|--------|
| `openclaw-personal` | Individual agents on personal machines | File reads/writes, search, summarize | Email, delete, calendar, database | Financial, credentials, exfiltration, destructive |
| `openclaw-developer` | Skill builders for marketplace | File reads/writes within scope | File deletion, database writes | Everything else (email, financial, system config) |
| `cowork-personal` | Knowledge workers with Claude Desktop | File reads/writes, search, draft | Email, delete, calendar, database, financial | Credentials, PII, exfiltration, destructive |
| `cowork-team` | Small teams sharing MCP infrastructure | File reads/writes, search | Email, delete, shared drives, team channels, financial | Team config, access controls, credentials, destructive |
| `claude-code-standard` | Developers with Claude Code + MCP | File reads/writes, git commit, tests | Push to main, email, delete, package publish, staging DB | Production deploy, credentials, force push, destructive |

### Constitution Approval

Constitutions can be cryptographically approved after signing:

```bash
sanna-approve-constitution constitution.yaml \
  --approver-id "lead@company.com" \
  --approver-role "tech-lead" \
  --private-key <approver-key-id>.key
```

Approval adds a signed `ApprovalRecord` with content hash binding. Receipts always carry approval status. Approval is mutable metadata — it can be added or revoked after the constitution is signed, and is verified separately from the constitution signature.

## Extension Points

**Custom evaluators**: Register Python functions for domain-specific invariants via `@register_invariant_evaluator()`. Functions receive `(context, output, constitution, check_config)` and return a `CheckResult`. Module: `sanna.evaluators`.

**LLM evaluators**: Call `enable_llm_checks(api_key=...)` to register LLM-backed evaluators for C1-C5. Accepts `checks` parameter for subset registration. Module: `sanna.evaluators.llm`.

**OpenTelemetry**: Use `receipt_to_span()` to export receipts as OTel spans. Module: `sanna.exporters.otel_exporter`.

**Langfuse**: Use `langfuse_trace_to_trace_data()` to convert Langfuse traces to the format `generate_receipt()` expects. Module: `sanna.adapters.langfuse`.

**Escalation callbacks**: Register handlers via `register_escalation_callback(name, fn)` for `must_escalate` rules with `type: "callback"`.

## Architecture

```
Constitution (YAML) ─→ load + verify hash
                            │
                            ▼
@sanna_observe ─→ capture inputs ─→ execute function ─→ capture output
                            │
                            ▼
                 Configure checks from invariants
                            │
                            ▼
                 Run C1-C5 checks + custom evaluators
                            │
                            ▼
                 Generate receipt (fingerprint, hashes, status)
                            │
                            ▼
                 Sign receipt (optional, Ed25519)
                            │
                            ▼
                 Enforce (halt / warn / log)
                            │
                            ▼
              Store (SQLite) ─→ Export (OTel / Langfuse / CSV / JSON)
```

The receipt fingerprint is deterministic over: trace ID, content hashes, checks version, check results, constitution ref, halt event, evaluation coverage, authority decisions, escalation events, source trust evaluations, and extensions. Both `middleware.py` and `verify.py` compute identical fingerprints — this is a design invariant.

## Development

```bash
git clone https://github.com/nicallen-exd/sanna.git
cd sanna
pip install -e ".[dev]"
python -m pytest tests/ -q
```

1488 tests. 0 failures.

## License

Apache 2.0
