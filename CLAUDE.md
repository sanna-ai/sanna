# CLAUDE.md — Sanna Project Context

## What Sanna Is
Trust infrastructure for AI agents. Checks reasoning during execution, halts when constraints are violated, generates portable cryptographic receipts proving governance was enforced. Constitution enforcement is the product. MCP is the distribution channel.

## Current State
- **Version:** v0.7.0 on PyPI (703 tests, 10 xfailed, 0 failures)
- **CI:** Green across Python 3.10, 3.11, 3.12
- **Package:** `pip install sanna` / `pip install sanna[mcp]`

## Architecture

### Core modules
- `src/sanna/checks/` — C1-C5 coherence checks
- `src/sanna/enforcement/constitution_engine.py` — Invariant-to-check mapping, enforcement levels
- `src/sanna/enforcement/authority.py` — Authority boundary evaluation (can_execute, cannot_execute, must_escalate)
- `src/sanna/enforcement/escalation.py` — Escalation targets (log, webhook, callback)
- `src/sanna/middleware.py` — @sanna_observe decorator, receipt generation, fingerprinting
- `src/sanna/verify.py` — Offline receipt verification, fingerprint parity with middleware.py
- `src/sanna/constitution.py` — Constitution parsing, signing, hashing. AgentIdentity with extensions dict
- `src/sanna/crypto.py` — Ed25519 signing/verification for constitutions and receipts
- `src/sanna/hashing.py` — Canonical JSON, deterministic hashing
- `src/sanna/bundle.py` — Evidence bundle creation/verification (zip with receipt + constitution + keys)
- `src/sanna/mcp/server.py` — FastMCP server, 4 tools, stdio transport

### CLI entry points (registered in pyproject.toml)
`sanna`, `sanna-verify`, `sanna-keygen`, `sanna-sign-constitution`, `sanna-verify-constitution`, `sanna-init-constitution`, `sanna-create-bundle`, `sanna-verify-bundle`, `sanna-mcp`

### Schemas
- `src/sanna/spec/constitution.schema.json` — Source of truth. Root `spec/` copy must stay synced.
- `src/sanna/spec/receipt.schema.json` — Receipt validation schema.

### Key design invariants
- **Fingerprint parity:** middleware.py and verify.py MUST compute identical fingerprints. Same fields, same order.
- **Signing scope:** Constitution signature covers identity (with extensions flattened), invariants, authority_boundaries, escalation_targets, trusted_sources. Receipt signature covers everything except signature.value itself.
- **Backward compatibility:** Empty extensions produce identical hash/signature as pre-extension receipts. Plain string context still works for C1.
- **Optional dependencies:** `mcp` and `httpx` are NOT base dependencies. Any imports must be guarded with try/except ImportError or pytest.importorskip in tests.

## What Was Built in v0.7.0
- MCP server: 4 tools (verify_receipt, generate_receipt, list_checks, evaluate_action)
- Authority boundary enforcement: evaluate_authority() → AuthorityDecision
- Escalation targets: log (default), webhook (requires httpx), callback
- Trusted source tiers: tier_1/tier_2/tier_3/untrusted/unclassified, C1-aware
- Evidence bundles: zip with receipt + constitution + keys + metadata
- Golden test vectors: 19 vectors in tests/vectors/
- Hardening: zip bomb/slip protection, MCP crash guards, float crash handling, key_id selection, tier normalization, separator normalization
- Extension points: AgentIdentity.extensions dict, receipt top-level extensions field
- Pre-publish fixes: PEP 621 license, root schema sync, httpx import guard
- CI fixes: pytest.importorskip for mcp and httpx tests, --verify-only without --private-key

## Active Build: v0.7.1

### OTel bridge (primary deliverable)
- **New file:** `src/sanna/exporters/otel_exporter.py`
- **Optional dependency:** `sanna[otel]` → `opentelemetry-api>=1.20.0`, `opentelemetry-sdk>=1.20.0`
- **Class:** SannaOTelExporter (implements SpanExporter)
- **Design principle:** Spans carry pointer + integrity hash, NOT full receipt JSON
  - `sanna.artifact.uri` → where the receipt is stored
  - `sanna.artifact.content_hash` → SHA-256 of receipt JSON
- **Semantic conventions namespace:** `sanna.*`
  - `sanna.receipt.id`, `sanna.coherence_status`, `sanna.enforcement_decision`
  - `sanna.constitution.policy_hash`, `sanna.constitution.version`
  - `sanna.evaluation_coverage.pct`
  - `sanna.check.c1.status` through `sanna.check.c5.status`
  - `sanna.authority.decision`, `sanna.escalation.triggered`, `sanna.source_trust.flags`
- **Span:** name=`sanna.governance.evaluation`, kind=INTERNAL, status=OK/ERROR
- **Integration:** Works with BatchSpanProcessor and any OTel backend

### Deferred hardening items (also v0.7.1)
1. **unclassified tier context_used inconsistency** — middleware.py emits context_used=True for unclassified sources but C1 ignores them. Align context_used with actual C1 behavior.
2. **policy_hash canonicalization** — compute_constitution_hash() uses ensure_ascii=True, golden vectors imply ensure_ascii=False. Document the distinction or align.
3. **Receipt extensions fingerprint semantics** — sanna_observe() always adds execution_time_ms to extensions, making fingerprints execution-specific. Document or restructure.
4. **action_params size guard** — MCP server has no size limit on action_params dict.

## Testing Rules
- ALL 703 existing tests must pass after any change
- Optional dependency tests MUST use `pytest.importorskip()` — CI does not install extras
- Golden receipts: NEVER use `--update-golden-receipts` unless intentionally changing receipt format
- Float values in golden receipts: use integers to avoid hash instability
- New test files for new modules (e.g., `tests/test_otel_exporter.py`)

## Common Pitfalls
- **Schema drift:** If you change constitution or receipt format, update BOTH schema files and sync root spec/ from src/sanna/spec/
- **Fingerprint divergence:** Any field added to receipt fingerprint in middleware.py MUST also be added in verify.py (and vice versa)
- **Import crashes:** Never import optional packages (mcp, httpx, opentelemetry) at module level without guards
- **Signing scope changes:** If you add fields to constitution or receipt, verify they're included in the signing material
