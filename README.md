# Sanna — Coherence Checks for AI Agents

Checks AI agent reasoning during execution. Halts when constraints are violated. Generates portable receipts documenting what checks ran and whether they passed.

## The Problem

Observability tools show you what happened. Guardrails filter outputs. Neither proves the reasoning was sound.

When an agent makes a bad decision, teams spend hours in trace viewers reconstructing what went wrong. The traces show every step — but not whether the logic held together. Did the agent contradict its own context? Did it collapse nuance into a single answer? Did it state something with certainty when the evidence was conditional?

Sanna answers **"was the reasoning valid?"** — not just **"what happened?"**

## Quick Demo

```python
from sanna import sanna_observe, SannaHaltError

@sanna_observe(on_violation="halt")
def my_agent(query, context):
    return "You are eligible for a refund."

try:
    result = my_agent(
        query="Can I get a refund on my software?",
        context="Digital products are non-refundable."
    )
except SannaHaltError as e:
    print("HALTED!")
    print(f"Status: {e.receipt['coherence_status']}")
    for check in e.receipt['checks']:
        print(f"  [{'✓' if check['passed'] else '✗'}] {check['name']}")
```

```
HALTED!
Status: FAIL
  [✗] Context Contradiction
  [✓] Mark Inferences
  [✓] No False Certainty
  [✓] Preserve Tensions
  [✓] No Premature Compression
```

The context says non-refundable. The output says eligible. C1 catches the contradiction and halts execution before the agent can act on it.

## Install

```bash
pip install sanna                    # Core
pip install sanna[langfuse]          # With Langfuse trace integration
```

For development:

```bash
git clone https://github.com/nicallen-exd/sanna.git
cd sanna
pip install -e ".[dev]"
pytest tests/ -v
```

## The Checks

| Check | Name | Severity | What it catches |
|-------|------|----------|-----------------|
| C1 | Context Contradiction | critical | Output contradicts explicit context statements |
| C2 | Mark Inferences | warning | Definitive claims without hedging language |
| C3 | No False Certainty | warning | Confidence that exceeds what the evidence supports |
| C4 | Preserve Tensions | warning | Conflicting information collapsed into a single answer |
| C5 | No Premature Compression | warning | Multi-faceted input reduced to a single sentence |

All checks are heuristic (pattern matching). They flag for human review — they don't claim to definitively prove reasoning failure.

## Three Modes

| Mode | Behavior |
|------|----------|
| `halt` | Raises `SannaHaltError` and stops execution when a critical check fails. Records a `halt_event` in the receipt. |
| `warn` | Returns the result but emits Python warnings for failed checks |
| `log` | Returns the result silently; failures are recorded in the receipt only |

```python
@sanna_observe(on_violation="halt")   # Stop the agent
@sanna_observe(on_violation="warn")   # Warn but continue
@sanna_observe(on_violation="log")    # Silent — receipt only
```

## Constitution Provenance

Track which policy document defined the check boundaries:

```python
from sanna import sanna_observe, ConstitutionProvenance, hash_text

constitution = ConstitutionProvenance(
    document_id="refund-policy-v2",
    document_hash=hash_text("No refunds on digital products."),
    version="2.0",
    source="policy-repo",
)

@sanna_observe(on_violation="halt", constitution=constitution)
def my_agent(query, context):
    return "..."
```

The `constitution_ref` is included in the receipt and covered by the fingerprint. If anyone modifies the constitution reference after generation, verification detects the inconsistency.

## Halt Events

When `on_violation="halt"` triggers, the receipt automatically records a `halt_event`:

```json
{
  "halt_event": {
    "halted": true,
    "reason": "Coherence check failed: C1",
    "failed_checks": ["C1"],
    "timestamp": "2026-02-11T...",
    "enforcement_mode": "halt"
  }
}
```

The verifier warns when a receipt has FAIL status with a critical failure but no `halt_event` recorded — indicating the failure was not enforced.

## CLI Tools

**Generate a receipt from a Langfuse trace:**

```bash
sanna-generate <trace_id>                              # Human-readable summary
sanna-generate <trace_id> --format json -o receipt.json # Machine-readable JSON
```

**Verify a receipt offline (no network, no API keys):**

```bash
sanna-verify receipt.json                  # Human-readable
sanna-verify receipt.json --format json    # Machine-readable

# Exit codes: 0=valid, 2=schema, 3=fingerprint mismatch, 4=consistency
```

## Receipt Format

A receipt is a self-contained JSON artifact documenting one agent decision:

```
trace_id:    golden-001-fail-c1-refund
status:      FAIL
checks:      4 passed, 1 failed

  [✗] C1  Context Contradiction  (critical)
      Output suggests eligibility despite 'non-refundable' in context
  [✓] C2  Mark Inferences
  [✓] C3  No False Certainty
  [✓] C4  Preserve Tensions
  [✓] C5  No Premature Compression

fingerprint: 8eb30aad285f0629
context_hash: 8f215f8ed9b85078
output_hash:  42b19b29a5ef758b
```

Receipts include consistency-verified hashes (canonical SHA256). If anyone modifies the inputs, outputs, or check results, verification detects the inconsistency. Receipts can be verified by third parties without platform access.

## What This Is NOT

- **Not observability.** That's LangSmith, Langfuse, etc. They show what happened. Sanna checks whether the reasoning held together.
- **Not guardrails.** That's NeMo Guardrails, Guardrails AI, etc. They filter inputs and outputs. Sanna evaluates the logic between them.
- **Not governance policy.** That's Credo AI, etc. They define what should happen. Sanna proves what did happen.

Sanna runs coherence checks — verifying the agent's output was consistent with its context, constraints, and evidence.

## Status

**v0.4.0** — Constitution provenance + halt events for governance tracking. CLI tools + `@sanna_observe` middleware decorator. Looking for design partners running agents in production.

## License

Apache 2.0

---

*Sanna is Swedish for "Truth."*
