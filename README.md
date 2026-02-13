# Sanna

Reasoning receipts for AI agents.

```bash
pip install sanna
```

## The Problem

Observability tools show you what your agent did. Guardrails filter what it says. Neither proves the reasoning was sound.

When an agent tells a customer they're eligible for a refund — but the policy says digital products are non-refundable — that's not a hallucination problem. It's a coherence problem. The output contradicts the context the agent was given.

Sanna catches this at runtime. It checks whether agent output is consistent with the context, constraints, and evidence it received. When it's not, Sanna can halt execution before the bad answer leaves the system. Every execution produces a signed receipt — a portable JSON artifact that documents what checks ran, what passed, and what failed. Anyone can verify a receipt offline, without platform access.

## How It Works

### 1. Define a constitution

A constitution is a YAML file that declares which reasoning invariants your agent must uphold, and what happens when they're violated.

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
  - id: "INV_PRESERVE_TENSION"
    rule: "Do not collapse conflicting evidence."
    enforcement: "log"

boundaries:
  - id: "B001"
    description: "Only answer product and service questions"
    category: "scope"
    severity: "high"
```

Each invariant maps to a coherence check. The `enforcement` field controls what happens when that check fails — `halt` stops execution, `warn` emits a Python warning, `log` records silently.

### 2. Wrap your agent function

```python
from sanna import sanna_observe, SannaHaltError

@sanna_observe(constitution_path="constitution.yaml")
def support_agent(query: str, context: str) -> str:
    # Your agent logic here — call an LLM, run a chain, whatever
    return llm.generate(query=query, context=context)

try:
    result = support_agent(
        query="Can I get a refund on my software?",
        context="Digital products are non-refundable once downloaded."
    )
    print(result.output)          # The agent's response
    print(result.receipt)         # The reasoning receipt
except SannaHaltError as e:
    print(f"HALTED: {e}")
    print(e.receipt)              # Receipt is still available
```

### 3. The constitution drives enforcement

The constitution is the control plane. It determines:
- **Which checks run** — only invariants listed in the constitution are evaluated
- **How each check enforces** — halt, warn, or log, independently per check
- **What the receipt records** — each check result includes which invariant triggered it and at what enforcement level

No constitution, no checks. The same check engine produces completely different behavior depending on which constitution you wire in.

### 4. Every execution produces a receipt

```json
{
  "schema_version": "0.1",
  "tool_version": "0.6.0",
  "checks_version": "2",
  "receipt_id": "fcd1c4918c31b76c",
  "receipt_fingerprint": "8c7e0b940153957d",
  "trace_id": "sanna-610f457a11ae",
  "coherence_status": "FAIL",
  "checks": [
    {
      "check_id": "C1",
      "name": "Context Contradiction",
      "passed": false,
      "severity": "critical",
      "evidence": "Output suggests eligibility despite 'non-refundable' in context",
      "triggered_by": "INV_NO_FABRICATION",
      "enforcement_level": "halt",
      "constitution_version": "1.0.0"
    }
  ],
  "constitution_ref": {
    "document_id": "strict-financial-analyst/1.0.0",
    "document_hash": "5ba94fe48ed5532f...",
    "approved_by": ["cfo@company.com", "compliance@company.com"]
  },
  "halt_event": {
    "halted": true,
    "reason": "Coherence check failed: C1",
    "failed_checks": ["C1"],
    "enforcement_mode": "halt"
  }
}
```

Receipts include consistency-verified hashes (canonical SHA-256). If anyone modifies the inputs, outputs, check results, or constitution reference after generation, verification detects the tampering.

### 5. Verify offline

```bash
sanna-verify receipt.json
```

No network. No API keys. No platform access. Exit codes: 0=valid, 2=schema invalid, 3=fingerprint mismatch, 4=consistency error.

## Three Constitutions Demo

Same agent. Same input. Same bad output. Three different constitutions. Three different outcomes.

The input: a customer asks about a software refund. The context says digital products are non-refundable. The agent says they're eligible. This contradicts the context — C1 should catch it.

| Constitution | Invariants | C1 Enforcement | Outcome |
|---|---|---|---|
| **Strict Financial Analyst** | All 5 at `halt` | halt | **HALTED** — execution stopped |
| **Permissive Support Agent** | 2 at `warn` + 1 custom | warn | **WARNED** — continued with warning |
| **Research Assistant** | C1 `halt`, rest `log` | halt | **HALTED** — only C1 can stop it |

The permissive agent has the same C1 failure, but its constitution says `warn` — so the agent continues and the violation is recorded in the receipt. The strict analyst halts immediately. The research assistant halts on fabrication but only logs everything else.

Run it yourself:

```bash
python examples/three_constitutions_demo.py
```

## Coherence Checks

Every invariant in your constitution maps to a check function:

| Invariant | Check | What it catches |
|---|---|---|
| `INV_NO_FABRICATION` | C1 — Context Contradiction | Output contradicts explicit statements in the context |
| `INV_MARK_INFERENCE` | C2 — Mark Inferences | Definitive claims stated without hedging language |
| `INV_NO_FALSE_CERTAINTY` | C3 — No False Certainty | Confidence that exceeds what the evidence supports |
| `INV_PRESERVE_TENSION` | C4 — Preserve Tensions | Conflicting information collapsed into a single answer |
| `INV_NO_PREMATURE_COMPRESSION` | C5 — No Premature Compression | Complex, multi-faceted input reduced to a single sentence |

All checks are heuristic (pattern matching). They flag potential issues for human review — they don't claim to definitively prove reasoning failure.

Custom invariants (any ID starting with `INV_CUSTOM_`) appear in the receipt as `NOT_CHECKED` — they document the policy but have no built-in evaluator.

## CLI Tools

```bash
# Scaffold a new constitution
sanna-init-constitution -o constitution.yaml

# Validate and sign a constitution (sets document_hash)
sanna-sign-constitution constitution.yaml

# Verify a receipt offline
sanna-verify receipt.json
sanna-verify receipt.json --format json

# Generate a receipt from a Langfuse trace
sanna-generate <trace_id>
sanna-generate <trace_id> --format json -o receipt.json
```

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

## What Sanna Is NOT

- **Not observability.** LangSmith, Langfuse, etc. show you what happened. Sanna checks whether the reasoning held together.
- **Not guardrails.** NeMo Guardrails, Guardrails AI, etc. filter inputs and outputs. Sanna evaluates the logic between them.
- **Not testing.** Tests run before deployment. Sanna runs during execution, on every call, with production data.

Sanna sits at the boundary between the agent and the world. It answers: **was the reasoning valid?** — not just **what happened?**

## Why Receipts Matter

The critical moment is the handover — when an agent's output leaves the platform and becomes someone else's input. A customer gets an answer. A downstream system gets a decision. A report gets filed.

At that point, the trace is gone. The observability dashboard is behind a login. The guardrail logs are in a different system. Nobody outside the team can verify what happened.

A receipt is the artifact that survives the handover. It's portable, self-contained, and offline-verifiable. It documents what checks ran, what passed, what failed, and what the enforcement decision was. The constitution reference proves which policy was in effect. The fingerprint proves nothing was modified after generation.

Receipts turn "trust us, we checked" into "here's the proof — verify it yourself."

## Roadmap

- **v0.6.0** — Constitution enforcement. The constitution drives the check engine. Per-invariant enforcement levels. Custom invariants. Three Constitutions Demo. *(current release)*
- **v0.7.0** — MCP server. Expose Sanna checks as Model Context Protocol tools.
- **v0.8.0** — Constitution lifecycle. Version history, approval workflows, diff-and-sign.

## Install

```bash
pip install sanna                    # Core library
pip install sanna[langfuse]          # With Langfuse adapter
```

Development:

```bash
git clone https://github.com/nicallen-exd/sanna.git
cd sanna
pip install -e ".[dev]"
python -m pytest tests/ -q
```

300 tests. 0 failures.

## License

Apache 2.0

[PyPI](https://pypi.org/project/sanna/) · [GitHub](https://github.com/nicallen-exd/sanna)

---

*Sanna is Swedish for "truth."*
