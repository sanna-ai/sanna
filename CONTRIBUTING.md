# Contributing to Sanna

Sanna is an AI agent governance platform that generates cryptographically signed reasoning receipts — portable proof that AI agent decisions were sound. The project is pre-launch, solo-founded, and under active development. This document describes the engineering standards anyone working in this codebase needs to follow.

## Project Status

Sanna is published on PyPI. The current release is v0.9.1 (1214 tests, CI green across Python 3.10–3.12). The codebase is sole-author through v0.9.x. The v0.10.0 release introduces `sanna-gateway`, the MCP enforcement proxy — this is the product form factor.

If you're reading this, you're likely one of: a future engineering hire, someone in the founder's trusted network evaluating the codebase, or an AI coding agent operating on the repository. Standards apply equally regardless.

## Core Architecture

Sanna implements a constitution-as-control-plane architecture (see ADR-001). YAML constitutions with typed invariants drive all check behavior and enforcement levels. The constitution is the single source of authority — everything else derives from it.

**Enforcement engine (shipped v0.7.0):** Evaluates tool calls against authority boundaries defined in a constitution. Three enforcement levels: `can_execute` (forward), `must_escalate` (require approval before forwarding), `cannot_execute` (deny). These are the product's vocabulary. Use them precisely.

**Deterministic checks:** Schema validation, policy compliance, fingerprint verification, contraction detection, context contradiction patterns. Heuristic-based, run locally, produce consistent results.

**Probabilistic checks (LLM evaluator, shipped v0.8.1):** Coherence evaluation using external language models. These use their own invariant ID namespace — they are semantically distinct from deterministic checks and must never shadow deterministic check IDs. API failures are surfaced as evaluation errors, not check failures.

**Receipts:** Both check categories produce results packaged into Ed25519-signed, offline-verifiable JSON receipts. Receipts bind to constitutions via content hash, carry constitution approval status (v0.9.0), and include identity verification context when available (v0.9.1). The receipt is the artifact — it's what crosses organizational boundaries and what third parties verify.

**Gateway (v0.10.0):** MCP enforcement proxy. Sits between an MCP client (Claude Desktop, Claude Code) and downstream MCP servers (Notion, GitHub, etc.). Intercepts tool calls, enforces constitution policy, generates receipts, and manages the `must_escalate` approval flow. The gateway is both an MCP server (upstream) and an MCP client (downstream).

## Development Workflow

This is a solo-founder project using AI coding agents (Claude Code) for rapid development. The workflow is:

1. Scope the work (build sequence, spec pages, backlog audit)
2. Build with Claude Code using block-level prompts that include test specifications
3. Run the full test suite — zero regressions is mandatory, every release
4. Multi-version CI validation (Python 3.10, 3.11, 3.12)
5. GPT architecture review on each release for independent validation
6. Tag, build, publish to PyPI

When additional engineers join, the process will introduce pull requests and code review. Until then, the test suite and CI are the quality gates.

### Branch Naming

Use descriptive branch names: `feature/gateway-mcp-client`, `fix/c3-false-positive`, `docs/quickstart-guide`.

## Adding Deterministic Checks

1. Each check must be deterministic — same input, same output, every time
2. Golden test coverage with both pass and fail cases
3. Document false positive/negative tradeoffs explicitly
4. Map the check to a constitution invariant with clear enforcement semantics (`can_execute` / `must_escalate` / `cannot_execute`)
5. Check IDs are permanent. Once shipped, a check ID is part of the public contract.

## Adding LLM Evaluator Invariants

1. LLM invariants use their own ID namespace — never reuse or shadow deterministic check IDs
2. Evaluator failures (API timeout, rate limit, model error) must be distinguishable from actual check failures. This was a v0.8.1 hardening fix — the separation is load-bearing.
3. Test coverage must include both successful evaluation and graceful degradation on API failure
4. Document what the invariant measures and why it requires probabilistic evaluation
5. Never name specific LLM models in code, comments, or documentation. Model choice is an implementation detail.

## Adding Platform Adapters

Adapters bridge Sanna receipts to observability and orchestration platforms. Existing adapters:

- **OpenTelemetry**: `sanna/exporters/otel_exporter.py` — governance semantic conventions for OTel-compatible backends
- **MCP**: `sanna/mcp/` — FastMCP server exposing Sanna tools as MCP tool calls
- **Gateway**: `sanna/gateway/` — (v0.10.0) MCP enforcement proxy with downstream client

New adapters should:
- Use the `sanna[adapter-name]` optional dependency pattern in `pyproject.toml`
- Not introduce hard dependencies on the adapter's SDK
- Include integration tests that can run without a live backend (mock the client)

## Constitution Templates

Templates are accessible via `sanna init-constitution --template <name>`. As of v0.10.0, five gateway-oriented templates ship:

- `openclaw-personal` — individuals running autonomous agents
- `openclaw-developer` — skill builders proving safety for marketplace distribution
- `cowork-personal` — knowledge workers using Cowork/Claude Desktop with MCP
- `cowork-team` — small teams sharing governance via Git (each dev runs own gateway)
- `claude-code-standard` — developers using Claude Code with MCP connectors

When adding templates:
- Define enforcement levels per tool action, not per abstract category. The enforcement engine resolves specific tool names, not categories.
- Include a comment block explaining who the template is for and what it assumes
- Test that the template loads, validates, and produces correct enforcement decisions for representative tool actions
- Templates that use `must_escalate` must work correctly with the gateway's approval flow

## Cryptographic Integrity

Non-negotiable:

- All golden receipts must verify with `sanna verify`
- Receipt signatures use Ed25519 and bind the full document via RFC 8785 JCS canonicalization
- Constitution approval signatures (v0.9.0) bind provenance, approver identity, and policy content. The approval chain is the gateway's legitimacy source.
- Receipt-to-constitution provenance bonds must remain intact — receipts reference their governing constitution by content hash
- Identity verification context (v0.9.1) is included in receipts when available and must not break verification when absent
- Never modify the signature scheme without a versioned migration path and cross-language verifier impact analysis

If your change touches signing, verification, canonicalization, or the approval chain, it requires exhaustive review.

## Schema Changes

The receipt schema is a public contract. External verifiers depend on it. Changes require:

- Backward compatibility or a versioned migration
- Updated golden test fixtures
- Documentation of what changed and why
- Consideration of cross-language verifier impact — the schema must remain portable and verifiable by any implementation that follows the spec

Keep the core schema strict. Use the `extensions` field for vendor-specific or experimental data.

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# Verify all golden receipts
for f in golden/receipts/*.json; do sanna verify "$f"; done

# Run with coverage
pytest tests/ -v --cov=sanna --cov-report=term-missing

# Gateway tests (v0.10.0+)
pytest tests/test_gateway_mcp_client.py -v
pytest tests/test_gateway_server.py -v
pytest tests/test_gateway_enforcement.py -v
pytest tests/test_gateway_escalation.py -v
pytest tests/test_gateway_config.py -v
pytest tests/test_gateway_hardening.py -v
pytest tests/test_template_matrix.py -v
```

The test suite has 1214 tests as of v0.9.1 (target: 1400+ for v0.10.0). PRs that reduce coverage will be rejected.

## CLI Commands

Sanna exposes these CLI entry points. If your change affects CLI behavior, update the relevant command's help text and test end-to-end:

- `sanna check` — run checks against a constitution
- `sanna verify` — verify receipt integrity and signature chain
- `sanna keygen` — generate Ed25519 signing key pairs (`--label` for human-readable naming)
- `sanna sign` — sign constitutions and receipts
- `sanna init-constitution` — initialize constitutions from templates
- `sanna approve-constitution` — approve a constitution with Ed25519 signature (establishes the legitimacy chain)
- `sanna diff` — compare constitution versions with content hash verification
- `sanna-gateway` — (v0.10.0+) MCP enforcement proxy server

## What Not to Do

- Don't name specific LLM models in code, comments, changelogs, or documentation. Model choice is an implementation detail.
- Don't add hard dependencies without discussion. Sanna's core must remain lightweight.
- Don't weaken enforcement semantics. If a constitution says `cannot_execute`, the system denies. If it says `must_escalate`, the system requires approval. That's the product.
- Don't conflate deterministic checks with LLM evaluator invariants. They are separate namespaces with separate failure semantics. This distinction is load-bearing.
- Don't treat receipts as internal logging. Receipts are portable, signed artifacts designed for third-party verification. Every field is part of the public contract.

## Questions

Open an issue. If it's about architecture or direction, label it `discussion`.
