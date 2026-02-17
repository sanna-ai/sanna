# Three-Tier Deployment Guide

Sanna supports three deployment tiers with increasing integration depth. Start with Tier 1 (zero code changes) and move to deeper tiers as your governance requirements grow.

## Tier 1: Gateway Only

**Who it's for:** Teams using MCP-compatible agents (Claude Desktop, Claude Code, Cursor) who want policy enforcement and an audit trail without modifying their agent code.

**Language requirements:** Any. The gateway is a standalone process.

**What you get:**
- Constitution-based policy enforcement (allow / escalate / deny)
- Signed receipt for every tool call
- Filesystem receipt store for audit trail
- Circuit breaker protection for downstream failures
- PII redaction controls for stored receipts

**What you don't get:**
- Reasoning quality evaluation (no Receipt Triad)
- Built-in coherence checks (C1-C5)
- Custom evaluator hooks
- Drift analytics

### Setup

**1. Install**

```bash
pip install sanna[mcp]
```

**2. Generate keys and constitution**

```bash
# Generate a signing key for the gateway
sanna-keygen --signed-by "you@company.com" --label gateway

# Generate a constitution from a template
sanna-init
# Select a template (e.g., cowork-personal, claude-code-standard)

# Sign the constitution
sanna-sign-constitution constitution.yaml \
  --private-key ~/.sanna/keys/<key-id>.key
```

**3. Create gateway config**

```yaml
# gateway.yaml
gateway:
  transport: stdio
  constitution: ./constitution.yaml
  signing_key: ~/.sanna/keys/<key-id>.key
  receipt_store: ./receipts/

downstream:
  - name: notion
    command: npx
    args: ["-y", "@notionhq/notion-mcp-server"]
    env:
      OPENAPI_MCP_HEADERS: "${OPENAPI_MCP_HEADERS}"
    timeout: 30
```

**4. Configure your MCP client**

For Claude Desktop (`~/.config/claude/config.json`):

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

**5. Verify it works**

Start Claude Desktop. The gateway discovers downstream tools and exposes them with a namespace prefix (e.g., `notion_API-post-search`). Try a tool call — you should see a receipt file appear in `./receipts/`.

### Policy overrides

You can override constitution policy for specific tools in the gateway config:

```yaml
downstream:
  - name: notion
    command: npx
    args: ["-y", "@notionhq/notion-mcp-server"]
    env:
      OPENAPI_MCP_HEADERS: "${OPENAPI_MCP_HEADERS}"
    default_policy: can_execute
    tools:
      "API-patch-page":
        policy: must_escalate
        reason: "Page mutations require approval"
      "API-delete-block":
        policy: cannot_execute
        reason: "Block deletion is prohibited"
```

Policy cascade: per-tool override > server `default_policy` > constitution authority boundaries.

---

## Tier 2: Gateway + Reasoning Receipts

**Who it's for:** Teams that want provable reasoning quality — a cryptographic record of WHY the agent took each action, not just WHAT it did.

**Language requirements:** Any. The agent just needs to include a `_justification` field in tool call arguments.

**What you get (in addition to Tier 1):**
- Receipt Triad: cryptographic binding of input hash + reasoning hash + action hash
- Reasoning quality evaluation (presence, substance, parroting detection)
- Optional LLM coherence check for semantic alignment
- Weighted scoring with configurable thresholds

**What you don't get:**
- Built-in C1-C5 coherence checks on agent output
- Custom Python evaluator hooks
- Drift analytics
- Receipt persistence to SQLite

### Setup

**1. Complete Tier 1 setup** (above)

**2. Add reasoning configuration to your constitution**

```yaml
sanna_constitution: "1.1"

# ... identity, provenance, boundaries, invariants ...

reasoning:
  require_justification_for: [must_escalate, cannot_execute]
  on_missing_justification: block    # block | escalate | allow
  on_check_error: allow              # block | escalate | allow
  evaluate_before_escalation: true
  checks:
    glc_002_minimum_substance:
      enabled: true
      min_length: 20
    glc_003_no_parroting:
      enabled: true
    glc_005_llm_coherence:
      enabled: false   # Enable when ready for LLM evaluation
```

**3. Re-sign the constitution**

```bash
sanna-sign-constitution constitution.yaml \
  --private-key ~/.sanna/keys/<key-id>.key
```

**4. Include `_justification` in your agent's tool calls**

Your agent needs to include a `_justification` field when making tool calls. The field name starts with an underscore — Sanna strips it before forwarding to the downstream server.

```json
{
  "tool": "notion_API-patch-page",
  "arguments": {
    "page_id": "abc123",
    "properties": {"title": "Updated Report"},
    "_justification": "Updating page title to match the approved Q4 naming convention. The current title 'Draft Report' is outdated per the team's style guide."
  }
}
```

The gateway:
1. Extracts `_justification` from arguments
2. Evaluates reasoning quality (presence, substance, parroting)
3. Computes the Receipt Triad (input hash, reasoning hash, action hash)
4. Strips `_justification` before forwarding to the downstream server
5. Embeds the triad and evaluation results in the receipt

### Enforcement modes

The `on_missing_justification` setting controls what happens when a tool call requires justification but doesn't include one:

| Setting | Behavior |
|---------|----------|
| `block` | Tool call denied immediately |
| `escalate` | Tool call routed to escalation flow |
| `allow` | Tool call forwarded, receipt records the absence |

### LLM coherence

For semantic alignment checking between justification and action, enable `glc_005_llm_coherence` and set the `SANNA_LLM_MODEL` environment variable:

```bash
export SANNA_LLM_MODEL="claude-sonnet-4-5-20250929"
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Tier 3: Full Library Embedding

**Who it's for:** Python teams that want deep integration — custom evaluators, coherence checks on agent output, drift analytics, and programmatic receipt generation.

**Language requirements:** Python 3.10+

**What you get (in addition to Tier 2):**
- `@sanna_observe` decorator for wrapping agent functions
- Five built-in coherence checks (C1-C5) on agent output
- Custom evaluator registration for domain-specific checks
- LLM-as-judge evaluators
- SQLite receipt persistence with queryable metadata
- Drift analytics with linear regression and breach projection
- OpenTelemetry integration
- Evidence bundles for compliance

### Setup

**1. Install**

```bash
pip install sanna
# Optional extras:
pip install sanna[otel]       # OpenTelemetry bridge
```

**2. Wrap your agent function**

```python
from sanna import sanna_observe, SannaHaltError

@sanna_observe(
    constitution_path="constitution.yaml",
    store=".sanna/receipts.db",   # SQLite persistence
)
def my_agent(query: str, context: str) -> str:
    # Your agent logic here
    return "Based on the data, revenue grew 12% year-over-year."

try:
    result = my_agent(
        query="What was revenue growth?",
        context="Annual report: revenue increased 12% YoY to $4.2B."
    )
    print(result.output)   # The agent's response
    print(result.receipt)  # The reasoning receipt (dict)
except SannaHaltError as e:
    print(f"HALTED: {e}")
    print(e.receipt)       # Receipt is still generated on halt
```

**3. Register custom evaluators** (optional)

```python
from sanna.evaluators import register_invariant_evaluator
from sanna.receipt import CheckResult

@register_invariant_evaluator("INV_CUSTOM_PII")
def check_pii(context, output, constitution, check_config):
    if "SSN" in output:
        return CheckResult(
            check_id="INV_CUSTOM_PII",
            name="PII Check",
            passed=False,
            severity="critical",
            details="Output contains SSN pattern",
        )
    return CheckResult(
        check_id="INV_CUSTOM_PII",
        name="PII Check",
        passed=True,
        severity="info",
    )
```

Add the corresponding invariant to your constitution:

```yaml
invariants:
  - id: "INV_CUSTOM_PII"
    rule: "Do not include PII in output."
    enforcement: "halt"
```

**4. Run drift analytics**

```python
from sanna import DriftAnalyzer, ReceiptStore

store = ReceiptStore(".sanna/receipts.db")
analyzer = DriftAnalyzer(store)
report = analyzer.analyze(window_days=30)
print(f"Fleet status: {report.fleet_status}")
```

Or from the CLI:

```bash
sanna-drift-report --db .sanna/receipts.db --window 30
```

**5. Export to observability platforms** (optional)

OpenTelemetry:

```python
from sanna.exporters.otel_exporter import receipt_to_span
from opentelemetry import trace

tracer = trace.get_tracer("sanna")
receipt_to_span(receipt, tracer, artifact_uri="s3://bucket/receipt.json")
```

---

## Migration Path

Moving between tiers is additive — each tier builds on the previous one.

| From | To | What Changes |
|------|----|-------------|
| Tier 1 | Tier 2 | Add `reasoning:` section to constitution, include `_justification` in tool calls |
| Tier 2 | Tier 3 | Add `@sanna_observe` decorator, register custom evaluators, set up receipt store |
| None | Tier 1 | Install sanna, create constitution, configure gateway |

You can run Tier 1 (gateway) and Tier 3 (library) simultaneously — the gateway governs MCP tool calls while the library governs your Python agent's internal reasoning.
