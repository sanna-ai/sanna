# Sanna — Trust Infrastructure for AI Agents

Sanna checks reasoning during execution, halts when constraints are violated, and generates portable cryptographic receipts proving governance was enforced. Constitution-as-code: your governance rules live in version-controlled YAML, not in a vendor dashboard.

## Quick Start — Library Mode

```bash
pip install sanna
```

Set up governance (one-time):

```bash
sanna init         # Choose template, set agent name, enforcement level
sanna keygen       # Generate Ed25519 keypair (~/.sanna/keys/)
sanna sign constitution.yaml --private-key ~/.sanna/keys/<key-id>.key
```

Now wrap the functions you want to govern. `@sanna_observe` decorates the functions you choose — internal reasoning, prompt construction, and non-governed function calls produce no receipts.

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
    print(result.output)   # The agent's response
    print(result.receipt)  # Cryptographic governance receipt (JSON)
except SannaHaltError as e:
    print(f"HALTED: {e}")  # Constitution violation detected
```

## Quick Start — Gateway Mode

No code changes to your agent. The gateway sits between your MCP client and downstream servers.

```bash
pip install sanna[mcp]

sanna init         # Creates constitution.yaml + gateway.yaml
sanna keygen --label gateway
sanna sign constitution.yaml --private-key ~/.sanna/keys/<key-id>.key
sanna gateway --config gateway.yaml
```

Point your MCP client (Claude Desktop, Claude Code, Cursor) at the gateway instead of directly at your downstream servers. Every tool call is now governed. The gateway governs tool calls that pass through it — internal LLM reasoning generates zero receipts, only actions that cross the governance boundary are documented.

```
MCP Client (Claude Desktop / Claude Code / Cursor)
        |
        v  (MCP stdio)
sanna-gateway
        |  1. Receive tool call
        |  2. Evaluate against constitution
        |  3. Enforce policy (allow / escalate / deny)
        |  4. Generate signed receipt
        |  5. Forward to downstream (if allowed)
        v  (MCP stdio)
Downstream MCP Servers (Notion, GitHub, filesystem, etc.)
```

## Demo

Run a self-contained governance demo — no external dependencies:

```bash
sanna demo
```

This generates keys, creates a constitution, simulates a governed tool call, generates a receipt, and verifies it.

## Core Concepts

**Constitution** — YAML document defining what the agent can, cannot, and must escalate. Ed25519-signed. Modification after signing is detected on load.

**Receipt** — JSON artifact binding inputs, reasoning, action, and check results into a cryptographically signed, schema-validated, deterministically fingerprinted record. Receipts are generated per governed action — when an agent calls a tool or executes a decorated function — not per conversational turn. An agent that reasons for twenty turns and executes one action produces one receipt.

**Coherence Checks (C1-C5)** — Five built-in deterministic heuristics. No API calls or external dependencies.

| Check | Invariant | What it catches |
|-------|-----------|-----------------|
| C1 | `INV_NO_FABRICATION` | Output contradicts provided context |
| C2 | `INV_MARK_INFERENCE` | Definitive claims without hedging |
| C3 | `INV_NO_FALSE_CERTAINTY` | Confidence exceeding evidence strength |
| C4 | `INV_PRESERVE_TENSION` | Conflicting information collapsed |
| C5 | `INV_NO_PREMATURE_COMPRESSION` | Complex input reduced to single sentence |

**Authority Boundaries** — `can_execute` (forward), `must_escalate` (prompt user), `cannot_execute` (deny). Policy cascade: per-tool override > server default > constitution.

## Custom Evaluators

Register domain-specific invariant evaluators alongside the built-in C1-C5 checks:

```python
from sanna.evaluators import register_invariant_evaluator
from sanna.receipt import CheckResult

@register_invariant_evaluator("INV_PII_CHECK")
def pii_check(query, context, output, **kwargs):
    """Flag outputs containing email addresses."""
    import re
    has_pii = bool(re.search(r'\b[\w.+-]+@[\w-]+\.[\w.]+\b', output))
    return CheckResult(
        check_id="INV_PII_CHECK",
        name="PII Detection",
        passed=not has_pii,
        severity="high",
        evidence="Email address detected in output" if has_pii else "",
    )
```

Add the invariant to your constitution and it runs alongside C1-C5 automatically.

## Receipt Querying

```python
from sanna import ReceiptStore

store = ReceiptStore(".sanna/receipts.db")

# Query with filters
receipts = store.query(agent_id="support-agent", status="FAIL", limit=10)

# Drift analysis
from sanna import DriftAnalyzer
analyzer = DriftAnalyzer(store)
report = analyzer.analyze(window_days=30, threshold=0.15)
```

Or via CLI:

```bash
sanna drift-report --db .sanna/receipts.db --window 30 --json
```

## Constitution Templates

`sanna init` offers three interactive templates plus blank:

| Template | Use Case |
|----------|----------|
| Enterprise IT | Strict enforcement, ServiceNow-style compliance |
| Customer-Facing | Standard enforcement, Salesforce-style support agents |
| General Purpose | Advisory enforcement, starter template |
| Blank | Empty constitution for custom configuration |

Five additional gateway-oriented templates are available in `examples/constitutions/`:

| Template | Use Case |
|----------|----------|
| `openclaw-personal` | Individual agents on personal machines |
| `openclaw-developer` | Skill builders for marketplace distribution |
| `cowork-personal` | Knowledge workers with Claude Desktop |
| `cowork-team` | Small teams sharing governance via Git (each dev runs own gateway) |
| `claude-code-standard` | Developers with Claude Code + MCP connectors |

## CLI Reference

All commands are available as `sanna <command>` or `sanna-<command>`:

| Command | Description |
|---------|-------------|
| `sanna init` | Interactive constitution generator with template selection |
| `sanna keygen` | Generate Ed25519 keypair (`--label` for human-readable name) |
| `sanna sign` | Sign a constitution with Ed25519 |
| `sanna verify` | Verify receipt integrity, signature, and provenance chain |
| `sanna verify-constitution` | Verify constitution signature |
| `sanna approve` | Approve a signed constitution |
| `sanna demo` | Run self-contained governance demo |
| `sanna inspect` | Pretty-print receipt contents |
| `sanna check-config` | Validate gateway config (dry-run) |
| `sanna gateway` | Start MCP enforcement proxy |
| `sanna mcp` | Start MCP server (7 tools, stdio transport) |
| `sanna diff` | Diff two constitutions (text/JSON/markdown) |
| `sanna drift-report` | Fleet governance drift report |
| `sanna bundle-create` | Create evidence bundle zip |
| `sanna bundle-verify` | Verify evidence bundle (7-step) |
| `sanna generate` | Generate receipt from trace-data JSON |

## API Reference

The top-level `sanna` package exports 10 names:

```python
from sanna import (
    __version__,          # Package version string
    sanna_observe,        # Decorator: governance wrapper for agent functions
    SannaResult,          # Return type from @sanna_observe-wrapped functions
    SannaHaltError,       # Raised when a halt-enforcement invariant fails
    generate_receipt,     # Generate a receipt from trace data
    SannaReceipt,         # Receipt dataclass
    verify_receipt,       # Offline receipt verification
    VerificationResult,   # Verification result dataclass
    ReceiptStore,         # SQLite-backed receipt persistence
    DriftAnalyzer,        # Per-agent failure-rate trending
)
```

Everything else imports from submodules: `sanna.constitution`, `sanna.crypto`, `sanna.enforcement`, `sanna.evaluators`, `sanna.verify`, `sanna.bundle`, `sanna.hashing`, `sanna.drift`.

## Verification

```bash
# Verify receipt integrity
sanna verify receipt.json

# Verify with signature check
sanna verify receipt.json --public-key <key-id>.pub

# Full chain: receipt + constitution + approval
sanna verify receipt.json \
  --constitution constitution.yaml \
  --constitution-public-key <key-id>.pub

# Evidence bundle (self-contained zip)
sanna bundle-create \
  --receipt receipt.json \
  --constitution constitution.yaml \
  --public-key <key-id>.pub \
  --output evidence.zip

sanna bundle-verify evidence.zip
```

No network. No API keys. No vendor dependency.

## Enterprise Features

- **DMARC-style adoption**: Start with `log` enforcement (observe), move to `warn` (escalate), then `halt` (enforce).
- **Ed25519 cryptographic signatures**: Constitutions, receipts, and approval records are independently signed and verifiable.
- **Offline verification**: No platform dependency. Verify receipts with a public key and the CLI.
- **Evidence bundles**: Self-contained zip archives with receipt, constitution, and public keys for auditors.
- **Drift analytics**: Per-agent failure-rate trending with linear regression and breach projection. See [docs/drift-reports.md](docs/drift-reports.md).
- **Receipt Triad**: Cryptographic binding of input, reasoning, and action for auditability. See [docs/reasoning-receipts.md](docs/reasoning-receipts.md).
- **Receipt queries**: SQL recipes, MCP query tool. See [docs/receipt-queries.md](docs/receipt-queries.md).
- **Key management**: SHA-256 key fingerprints, labeled keypairs. See [docs/key-management.md](docs/key-management.md).
- **Production deployment**: Docker, logging, retention, failure modes. See [docs/production.md](docs/production.md).
- **Gateway configuration**: Full config reference. See [docs/gateway-config.md](docs/gateway-config.md).

## Observability (OpenTelemetry)

Sanna can emit OpenTelemetry signals to correlate governed actions with receipts on disk. Receipts are the canonical audit artifact — telemetry is optional and intended for dashboards, alerts, and correlation.

```bash
pip install "sanna[otel]"
```

See [docs/otel-integration.md](docs/otel-integration.md) for configuration and signal reference.

## Install

```bash
pip install sanna                # Core library (Python 3.10+)
pip install sanna[mcp]           # MCP server + gateway
pip install sanna[otel]          # OpenTelemetry bridge
```

## Development

```bash
git clone https://github.com/nicallen-exd/sanna.git
cd sanna
pip install -e ".[dev]"
python -m pytest tests/ -q
```

## License

Apache 2.0
