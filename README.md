# Sanna

AI governance infrastructure that generates cryptographically signed "reasoning receipts" — portable JSON artifacts that document AI agent decisions and verify reasoning integrity offline. Constitutions define the rules. Checks enforce them. Receipts prove it happened. The name means "truth" in Swedish.

```bash
pip install sanna
```

## How It Works

### 1. Define a constitution

A constitution is a YAML file that declares which reasoning invariants your agent must uphold, what actions it can take, and what happens when rules are violated.

```yaml
# constitution.yaml
sanna_constitution: "1.0.0"

identity:
  agent_name: "support-agent"
  domain: "customer-service"

provenance:
  authored_by: "cs-team@company.com"
  approved_by:
    - "cs-director@company.com"
  approval_date: "2026-01-15"
  approval_method: "compliance-review"

invariants:
  - id: "INV_NO_FABRICATION"
    rule: "Do not claim facts absent from provided sources."
    enforcement: "halt"
  - id: "INV_MARK_INFERENCE"
    rule: "Clearly mark inferences and speculation as such."
    enforcement: "warn"

boundaries:
  - id: "B001"
    description: "Only answer product and service questions"
    category: "scope"
    severity: "high"

authority_boundaries:
  cannot_execute:
    - "delete_records"
    - "send_email"
  must_escalate:
    - condition: "refund amount exceeds threshold"
      target:
        type: "log"
  can_execute:
    - "query_database"
    - "generate_report"

trusted_sources:
  tier_1:
    - "internal_database"
  tier_2:
    - "partner_api"
  tier_3:
    - "web_search"
  untrusted:
    - "user_paste"
```

Each invariant maps to a coherence check. The `enforcement` field controls what happens when that check fails — `halt` stops execution, `warn` emits a Python warning, `log` records silently.

### 2. Sign it

```bash
sanna-keygen --signed-by "your-name@company.com"
sanna-sign-constitution constitution.yaml --private-key sanna_ed25519.key
```

Constitutions are Ed25519-signed. The signature covers the full document — identity, provenance, invariants, authority boundaries, trusted sources, and signer metadata.

### 3. Wrap your agent function

```python
from sanna import sanna_observe, SannaHaltError

@sanna_observe(
    constitution_path="constitution.yaml",
    private_key_path="sanna_ed25519.key",
)
def support_agent(query: str, context: str) -> str:
    return llm.generate(query=query, context=context)

try:
    result = support_agent(
        query="Can I get a refund on my software?",
        context="Digital products are non-refundable once downloaded."
    )
    print(result.output)          # The agent's response
    print(result.receipt)         # The reasoning receipt (dict)
except SannaHaltError as e:
    print(f"HALTED: {e}")
    print(e.receipt)              # Receipt is still available
```

The constitution drives enforcement at runtime. Only invariants listed in the constitution are evaluated. Each check enforces independently — halt, warn, or log.

### 4. Verify offline

```bash
sanna-verify receipt.json
sanna-verify receipt.json --public-key sanna_ed25519.pub
sanna-verify receipt.json --constitution constitution.yaml --constitution-public-key sanna_ed25519.pub
```

No network. No API keys. No platform access. Full chain verification: receipt integrity, Ed25519 signature, receipt-to-constitution provenance bond, constitution signature.

## MCP Server

Sanna exposes its capabilities as an [MCP](https://modelcontextprotocol.io/) server for Claude Desktop, Cursor, and other MCP-compatible clients.

```bash
pip install sanna[mcp]
sanna-mcp  # starts stdio transport
```

Four tools available:

| Tool | Description |
|------|-------------|
| `sanna_verify_receipt` | Verify a receipt's schema, fingerprint, hashes, and status |
| `sanna_generate_receipt` | Generate a receipt from query/context/response with constitution enforcement |
| `sanna_list_checks` | List all C1-C5 checks with descriptions and mappings |
| `sanna_evaluate_action` | Evaluate whether an action is permitted under authority boundaries |

See [examples/CLAUDE_DESKTOP_SETUP.md](examples/CLAUDE_DESKTOP_SETUP.md) for Claude Desktop configuration and [src/sanna/mcp/README.md](src/sanna/mcp/README.md) for full MCP server documentation.

## Authority Boundaries

Constitutions can define authority boundaries that control which actions an agent may take:

| Boundary | Behavior | Receipt Field |
|----------|----------|---------------|
| `cannot_execute` | Action is halted immediately | `authority_decisions[].decision = "halt"` |
| `must_escalate` | Action is routed to an escalation target | `authority_decisions[].decision = "escalate"` |
| `can_execute` | Action is explicitly allowed | `authority_decisions[].decision = "allow"` |

Escalation targets support three types: `log` (Python logging), `webhook` (HTTP POST), and `callback` (registry-based callable).

```python
from sanna import evaluate_authority, load_constitution

const = load_constitution("constitution.yaml")
decision = evaluate_authority("send_email", {"to": "user@example.com"}, const)
# decision.decision = "halt", decision.boundary_type = "cannot_execute"
```

Authority decisions are recorded in the receipt's `authority_decisions` section and covered by the receipt fingerprint.

## Trusted Source Tiers

Constitutions can classify data sources into trust tiers that affect C1 (context contradiction) evaluation:

| Tier | Trust Level | C1 Behavior |
|------|-------------|-------------|
| `tier_1` | Full trust | Claims count as grounded evidence |
| `tier_2` | Verification required | Evidence with verification flag |
| `tier_3` | Reference only | Cannot be sole basis for claims |
| `untrusted` | Excluded | Not used in C1 evaluation |

Source trust evaluations are recorded in the receipt's `source_trust_evaluations` section.

## Evidence Bundles

An evidence bundle is a self-contained zip archive containing everything needed for offline verification — the receipt, the constitution that governed it, and the public key for signature verification.

```bash
# Create a bundle
sanna-create-bundle \
  --receipt receipt.json \
  --constitution constitution.yaml \
  --public-key sanna_ed25519.pub \
  --output evidence.zip

# Verify a bundle (6-step verification)
sanna-verify-bundle evidence.zip
```

Bundle verification runs six checks: bundle structure, receipt schema, receipt fingerprint, constitution signature, provenance chain (receipt-to-constitution binding), and receipt signature.

## Coherence Checks

| Invariant | Check | What it catches |
|---|---|---|
| `INV_NO_FABRICATION` | C1 — Context Contradiction | Output contradicts explicit statements in the context |
| `INV_MARK_INFERENCE` | C2 — Mark Inferences | Definitive claims stated without hedging language |
| `INV_NO_FALSE_CERTAINTY` | C3 — No False Certainty | Confidence that exceeds what the evidence supports |
| `INV_PRESERVE_TENSION` | C4 — Preserve Tensions | Conflicting information collapsed into a single answer |
| `INV_NO_PREMATURE_COMPRESSION` | C5 — No Premature Compression | Complex, multi-faceted input reduced to a single sentence |

All checks are heuristic (pattern matching). They flag potential issues for human review. Custom invariants (any ID not in the built-in mapping) appear in the receipt as `NOT_CHECKED` — they document the policy but have no built-in evaluator.

## CLI Tools

| Command | Description |
|---|---|
| `sanna-verify` | Verify receipt integrity and full provenance chain |
| `sanna-generate` | Generate a receipt from a Langfuse trace |
| `sanna-keygen` | Generate Ed25519 keypair for signing |
| `sanna-sign-constitution` | Cryptographically sign a constitution with Ed25519 |
| `sanna-hash-constitution` | Compute policy hash without Ed25519 signing |
| `sanna-verify-constitution` | Verify a constitution's Ed25519 signature |
| `sanna-init-constitution` | Scaffold a new constitution YAML |
| `sanna-mcp` | Start the MCP server (stdio transport) |
| `sanna-create-bundle` | Create an evidence bundle for offline verification |
| `sanna-verify-bundle` | Verify an evidence bundle (6-step check) |

## Demos

```bash
python examples/three_constitutions_demo.py       # Three enforcement modes
python examples/one_more_connector_demo.py         # MCP governance connector
```

See [examples/README.md](examples/README.md) for full documentation.

## Test Vectors

Deterministic test vectors for third-party verifier implementations are provided in [`tests/vectors/`](tests/vectors/README.md). These cover RFC 8785-style canonical JSON, Ed25519 constitution signatures, and receipt signatures using a fixed seed for reproducibility.

## Langfuse Integration

```bash
pip install sanna[langfuse]
```

```python
from sanna.adapters.langfuse import export_receipt

langfuse = Langfuse(...)
trace = langfuse.fetch_trace(trace_id)
receipt = export_receipt(trace.data, constitution_path="constitution.yaml")
```

## Install

```bash
pip install sanna                    # Core library
pip install sanna[mcp]               # With MCP server
pip install sanna[langfuse]          # With Langfuse adapter
```

Development:

```bash
git clone https://github.com/nicallen-exd/sanna.git
cd sanna
pip install -e ".[dev]"
python -m pytest tests/ -q
```

646 tests. 0 failures.

## License

Apache 2.0

[PyPI](https://pypi.org/project/sanna/) · [GitHub](https://github.com/nicallen-exd/sanna)

---

*Sanna is Swedish for "truth."*
