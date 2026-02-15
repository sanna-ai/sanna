# Reasoning Receipts

Reasoning receipts are cryptographically-signed artifacts that prove an AI agent's reasoning was evaluated against governance rules before an action was taken.

Standard receipts prove *what* happened. Reasoning receipts prove *why* it happened — and that the "why" was checked.

## Receipt Triad

Every reasoning receipt cryptographically binds three components:

```
input_hash     →  What the agent saw (tool name + arguments)
reasoning_hash →  Why it decided (justification text)
action_hash    →  What it did (tool call + parameters)
```

All hashes use SHA-256 with a `sha256:` prefix for algorithm agility. At the gateway boundary, `input_hash` and `action_hash` are identical because the gateway observes tool call arguments but not downstream execution internals. This constraint is documented in each receipt via `context_limitation: "gateway_boundary"`.

```yaml
receipt_triad:
  input_hash: "sha256:a1b2c3..."
  reasoning_hash: "sha256:d4e5f6..."
  action_hash: "sha256:a1b2c3..."
  context_limitation: gateway_boundary
```

## How It Works

### 1. Schema Mutation

When a tool is governed (`must_escalate` or `cannot_execute`), the gateway injects a `_justification` parameter into the tool's schema at runtime. The MCP client (Claude Desktop, Claude Code) sees this parameter and includes a reasoning string with the tool call.

```
Before mutation:              After mutation:
┌─────────────────────┐       ┌─────────────────────┐
│ delete_file          │       │ delete_file          │
│   path: string      │  →    │   path: string      │
│                     │       │   _justification:    │
│                     │       │     string (required) │
└─────────────────────┘       └─────────────────────┘
```

### 2. Reasoning Evaluation

Before forwarding (or escalating), the gateway evaluates the justification through a pipeline of checks:

| Check | ID | Method | What it evaluates |
|-------|----|--------|-------------------|
| Presence | `glc_001_justification_present` | `deterministic_presence` | Justification exists and is non-empty |
| Substance | `glc_002_minimum_substance` | `deterministic_regex` | Meets minimum length (default 20 chars) |
| No Parroting | `glc_003_no_parroting` | `deterministic_blocklist` | Not a blocklist phrase ("because you asked") |
| LLM Coherence | `glc_005_llm_coherence` | `llm_coherence` | Semantic alignment between reasoning and action (0.0-1.0) |

The first three checks are deterministic and run without external dependencies. LLM Coherence requires an API call and is optional.

### 3. Justification Stripping

After evaluation, `_justification` is removed from the tool arguments before forwarding to the downstream server. The downstream never sees it. The receipt records `justification_stripped: true`.

### 4. Receipt Generation

The gateway generates a receipt containing the triad, check results, assurance level, and enforcement context — then signs it with the gateway's Ed25519 key.

## Assurance Levels

The `assurance` field summarizes reasoning evaluation quality:

| Level | Meaning |
|-------|---------|
| `full` | All configured checks passed |
| `partial` | Some checks passed, some failed or errored |
| `none` | All checks failed, or no checks were configured |

## Constitution Configuration

Reasoning governance is configured in the constitution's `reasoning:` section (v1.1):

```yaml
sanna_constitution: "1.1"

# ... identity, provenance, boundaries, invariants, authority_boundaries ...

reasoning:
  # Which enforcement levels require justification
  require_justification_for:
    - must_escalate
    - cannot_execute

  # What happens when justification is missing
  on_missing_justification: block    # block | escalate | allow

  # What happens when a check fails
  on_check_error: block              # block | escalate | allow

  checks:
    glc_002_minimum_substance:
      enabled: true
      min_length: 20

    glc_003_no_parroting:
      enabled: true
      blocklist:
        - "because you asked"
        - "you told me to"
        - "you requested"

    glc_005_llm_coherence:
      enabled: true
      enabled_for:
        - must_escalate
      timeout_ms: 2000
      score_threshold: 0.6    # 0.0-1.0, higher = more aligned

  # Evaluate reasoning before showing escalation to human approver
  evaluate_before_escalation: true

  # On reasoning failure: false = escalate with warning, true = auto-deny
  auto_deny_on_reasoning_failure: false
```

### Model Configuration

LLM Coherence uses the Anthropic Messages API. Configure the model via environment variable:

```bash
export SANNA_LLM_MODEL="<your-model>"
```

If not set, the code defaults to the latest Sonnet model. No model strings are hardcoded in constitutions or gateway configs.

### Per-Action Thresholds

Override the global `score_threshold` for specific enforcement categories by configuring `enabled_for` on `glc_005_llm_coherence`. Only tool calls matching the listed enforcement levels trigger the LLM check.

## Receipt Structure

A v2.0 reasoning receipt contains:

```yaml
receipt_version: "2.0"

receipt_triad:
  input_hash: "sha256:..."
  reasoning_hash: "sha256:..."
  action_hash: "sha256:..."
  context_limitation: gateway_boundary

reasoning_evaluation:
  assurance: full
  overall_score: 0.85
  passed: true
  checks:
    - check_id: glc_001_justification_present
      method: deterministic_presence
      passed: true
      score: 1.0
      latency_ms: 0
    - check_id: glc_002_minimum_substance
      method: deterministic_regex
      passed: true
      score: 1.0
      latency_ms: 1
    - check_id: glc_005_llm_coherence
      method: llm_coherence
      passed: true
      score: 0.85
      latency_ms: 1200

action:
  tool: delete_file
  args_hash: "sha256:..."
  justification_stripped: true

enforcement:
  level: must_escalate
  constitution_version: "1.1"
  constitution_hash: "abc123..."

signature:
  algorithm: ed25519
  public_key: "..."
  signature: "..."
  canonical_form: rfc8785
```

## Approval Integration

When a tool call requires escalation (`must_escalate`), the human approver sees the reasoning evaluation alongside the action details:

1. Gateway evaluates reasoning
2. Reasoning scores are included in the escalation prompt
3. Human approver can approve, deny, or override
4. Override reasons are recorded: `false_positive`, `accepted_risk`, `emergency_override`, `threshold_too_strict`
5. The receipt records both the reasoning evaluation and the approval decision

## Backward Compatibility

- **v1.0 constitutions** work without changes — reasoning is not required
- **v1.0 receipts** continue to verify normally
- **Gateway without reasoning config** operates exactly as v0.10.x
- The `reasoning:` section is optional in v1.1 constitutions

## Migration from v0.10.x

Run `sanna-gateway migrate` to generate a new constitution. The migrated constitution includes a commented `reasoning:` section. Uncomment and configure to enable:

```bash
# Migrate existing setup
sanna-gateway migrate --client claude-desktop

# Edit the generated constitution to enable reasoning
# Uncomment the reasoning: section in ~/.sanna/constitution.yaml
```

## Module Reference

| Module | Purpose |
|--------|---------|
| `sanna.reasoning.pipeline` | `ReasoningPipeline` — orchestrates check execution |
| `sanna.reasoning.evaluator` | `ReasoningEvaluator` — high-level facade |
| `sanna.reasoning.checks` | Check implementations (presence, substance, parroting, coherence) |
| `sanna.reasoning.llm_client` | Anthropic API client for LLM coherence |
| `sanna.gateway.receipt_v2` | Receipt Triad and v2.0 dataclasses |
| `sanna.constitution` | `ReasoningConfig` and related dataclasses (v1.1) |
