# Sanna — Trust Infrastructure for AI Agents

Sanna generates cryptographically signed **reasoning receipts** that prove an AI agent's actions were evaluated against governance rules. Receipts are portable JSON artifacts — verify them offline, hand them to an auditor, or archive them for compliance. Constitution-as-code means your governance rules live in version-controlled YAML, not in a vendor dashboard.

## The Problem

AI agents execute tool calls — updating databases, sending emails, modifying files. Today there is no standard way to prove the reasoning behind those actions was sound, or that governance constraints were checked before execution happened.

## What Sanna Does

- **Intercepts** tool calls at the MCP layer (or via Python decorator)
- **Evaluates** each call against a signed constitution defining what the agent can, cannot, and must escalate
- **Generates** a cryptographically signed receipt binding inputs, reasoning, and action into a verifiable record
- **Enforces** halt/escalate/allow decisions before the tool call reaches its destination

No runtime dependency on Sanna's infrastructure. Receipts verify offline with standard Ed25519 public keys.

## Quickstart

```bash
pip install sanna[mcp]

# Generate a constitution from a template
sanna-init

# Generate a signing key
sanna-keygen --signed-by "you@company.com" --label gateway

# Sign the constitution
sanna-sign-constitution constitution.yaml --private-key ~/.sanna/keys/<key-id>.key

# Start the gateway (see gateway.yaml below)
sanna-gateway --config gateway.yaml
```

Point your MCP client (Claude Desktop, Claude Code, Cursor) at the gateway instead of directly at your downstream servers. Tool calls are now governed.

## How It Works

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

Every tool call — allowed, denied, or escalated — produces a receipt. The receipt contains content hashes, check results, authority decisions, and an Ed25519 signature. Receipts are JSON, schema-validated, and deterministically fingerprinted.

## Three Deployment Tiers

### Tier 1: Gateway Only (any language)

MCP enforcement proxy. No code changes to your agent. Install, configure, run.

```yaml
# gateway.yaml
gateway:
  constitution: ./constitution.yaml
  signing_key: ~/.sanna/keys/<key-id>.key
  receipt_store: ./receipts/

downstream:
  - name: notion
    command: npx
    args: ["-y", "@notionhq/notion-mcp-server"]
    env:
      OPENAPI_MCP_HEADERS: "${OPENAPI_MCP_HEADERS}"
```

You get: policy enforcement, signed receipts, audit trail. Works with any agent framework, any language.

### Tier 2: Gateway + Reasoning Receipts (any language)

Agent includes `_justification` in tool call arguments. The gateway extracts it, evaluates reasoning quality, and binds it cryptographically to the action via a Receipt Triad (input hash + reasoning hash + action hash).

```json
{
  "tool": "notion_update-page",
  "arguments": {
    "page_id": "abc123",
    "title": "Q4 Report",
    "_justification": "Updating title to match the approved quarterly naming convention per team policy."
  }
}
```

You get: everything in Tier 1, plus provable reasoning quality evaluation and the Receipt Triad binding.

### Tier 3: Full Library Embedding (Python)

Deep integration with the `@sanna_observe` decorator, custom evaluator hooks, and programmatic receipt generation.

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
    print(result.output)
    print(result.receipt)
except SannaHaltError as e:
    print(f"HALTED: {e}")
```

You get: everything in Tier 2, plus five built-in coherence checks (C1-C5), custom evaluator registration, LLM-as-judge evaluation, drift analytics, and receipt persistence.

See [docs/deployment-tiers.md](docs/deployment-tiers.md) for detailed setup instructions.

## Verification

```bash
# Verify receipt integrity
sanna-verify receipt.json

# Verify with signature check
sanna-verify receipt.json --public-key <key-id>.pub

# Full chain: receipt + constitution + approval
sanna-verify receipt.json \
  --constitution constitution.yaml \
  --constitution-public-key <key-id>.pub

# Evidence bundle (self-contained zip)
sanna-create-bundle \
  --receipt receipt.json \
  --constitution constitution.yaml \
  --public-key <key-id>.pub \
  --output evidence.zip

sanna-verify-bundle evidence.zip
```

No network. No API keys. No vendor dependency.

## Constitution System

Constitutions are YAML documents defining the agent's governance surface:

```yaml
sanna_constitution: "1.0"

identity:
  agent_name: "support-agent"
  domain: "customer-service"

provenance:
  authored_by: "team@company.com"
  approved_by: ["lead@company.com"]
  approval_date: "2026-02-14"
  approval_method: "code-review"

boundaries:
  - id: "B001"
    description: "Only answer product questions"
    category: "scope"
    severity: "high"

invariants:
  - id: "INV_NO_FABRICATION"
    rule: "Do not claim facts absent from provided sources."
    enforcement: "halt"

authority_boundaries:
  can_execute: [read_file, search, summarize]
  cannot_execute: [deploy, delete_repo, read_credentials]
  must_escalate:
    - condition: "send email"
      target: { type: log }
```

Constitutions are Ed25519-signed. Modification after signing is detected on load. Five pre-built templates are included for common deployment patterns.

| Template | Use Case |
|----------|----------|
| `openclaw-personal` | Individual agents on personal machines |
| `openclaw-developer` | Skill builders for marketplace distribution |
| `cowork-personal` | Knowledge workers with Claude Desktop |
| `cowork-team` | Small teams sharing MCP infrastructure |
| `claude-code-standard` | Developers with Claude Code + MCP connectors |
| `financial-analyst` | Financial services — trade/PII/regulatory controls |
| `healthcare-triage` | Healthcare — prescription/PHI/patient communication controls |

## Authority Boundaries

| Boundary | Behavior |
|----------|----------|
| `can_execute` | Tool call forwarded to downstream |
| `must_escalate` | Client prompted for approval before forwarding |
| `cannot_execute` | Tool call denied, error returned |

Escalation targets: `log` (Python logging), `webhook` (async HTTP POST), `callback` (registry-based Python callable).

## Coherence Checks (C1-C5)

Five built-in deterministic checks evaluate agent output against input context:

| Check | Invariant | What it catches |
|-------|-----------|-----------------|
| C1 | `INV_NO_FABRICATION` | Output contradicts provided context |
| C2 | `INV_MARK_INFERENCE` | Definitive claims without hedging |
| C3 | `INV_NO_FALSE_CERTAINTY` | Confidence exceeding evidence strength |
| C4 | `INV_PRESERVE_TENSION` | Conflicting information collapsed |
| C5 | `INV_NO_PREMATURE_COMPRESSION` | Complex input reduced to a single sentence |

Built-in checks are deterministic heuristics. They run without API calls or external dependencies.

## Enterprise Features

- **DMARC-style adoption**: Start with `log` enforcement (observe), move to `warn` (escalate), then `halt` (enforce). No big-bang rollout.
- **Constitution templates**: Pre-built governance profiles for regulated industries and common deployment patterns.
- **Ed25519 cryptographic signatures**: Constitutions, receipts, and approval records are independently signed and verifiable.
- **Offline verification**: No platform dependency. Verify receipts with a public key and the CLI.
- **Evidence bundles**: Self-contained zip archives with receipt, constitution, and public keys for auditors.
- **Drift analytics**: Per-agent failure-rate trending with linear regression and breach projection. See [docs/drift-reports.md](docs/drift-reports.md).
- **Receipt Triad**: Cryptographic binding of input, reasoning, and action for auditability.
- **Receipt queries**: SQL recipes, MCP query tool, Grafana dashboards. See [docs/receipt-queries.md](docs/receipt-queries.md).
- **Key management**: SHA-256 key fingerprints, labeled keypairs, multi-key environments. See [docs/key-management.md](docs/key-management.md).

## CLI Reference

| Command | Description |
|---------|-------------|
| `sanna-init` | Interactive constitution generator with template selection |
| `sanna-keygen` | Generate Ed25519 keypair (`--label` for human-readable name) |
| `sanna-sign-constitution` | Sign a constitution |
| `sanna-verify-constitution` | Verify constitution signature |
| `sanna-approve-constitution` | Approve a signed constitution |
| `sanna-verify` | Verify receipt integrity, signature, and provenance chain |
| `sanna-create-bundle` | Create evidence bundle zip |
| `sanna-verify-bundle` | Verify evidence bundle (7-step) |
| `sanna-diff` | Diff two constitutions (text/JSON/markdown) |
| `sanna-drift-report` | Fleet governance drift report |
| `sanna-gateway` | Start MCP enforcement proxy |
| `sanna-mcp` | Start MCP server (7 tools, stdio transport) |

## Install

```bash
pip install sanna                # Core library (Python 3.10+)
pip install sanna[mcp]           # MCP server + gateway
pip install sanna[otel]          # OpenTelemetry bridge
pip install sanna[langfuse]      # Langfuse adapter
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
