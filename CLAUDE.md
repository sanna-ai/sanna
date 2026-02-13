# CLAUDE.md

## Project
Sanna ("Truth" in Swedish) — reasoning integrity layer for AI agents. Generates portable, offline-verifiable "reasoning receipts" bound to governance constitutions with Ed25519 cryptographic provenance.

## Current State
- **Version:** v0.7.0 (ready for PyPI publish)
- **Tests:** 646 passing, 0 failures
- **v0.7.0 scope:** MCP server, authority boundary enforcement, trusted source tiers, escalation targets, evidence bundles
- **v0.6.x series:** Complete and locked. Do not modify 6.x behavior without explicit instruction.

## Source Layout
```
src/sanna/
├── checks/              # C1-C5 heuristic check functions
├── enforcement/
│   └── constitution_engine.py  # Invariant-to-check mapping, enforcement levels
├── adapters/
│   └── langfuse/        # Langfuse trace → receipt adapter
├── receipt.py           # Receipt generation with Ed25519 signing
├── verify.py            # Offline verification (receipt + constitution chain)
├── observe.py           # @sanna_observe decorator (constitution required)
├── constitution.py      # Constitution loading, validation, schema enforcement
├── fingerprint.py       # Deterministic receipt fingerprinting
├── models.py            # Core dataclasses/models
├── exceptions.py        # SannaHaltError and others
├── cli.py               # CLI entry points
spec/
├── receipt.schema.json  # Receipt JSON schema
├── constitution.schema.json  # Constitution JSON schema
examples/
├── three_constitutions_demo.py
├── constitutions/       # Sample YAML constitutions
tests/
├── golden/              # Golden receipt fixtures
├── test_*.py            # pytest test files
```

## Key Architecture Decisions
- **Constitution is the control plane.** No constitution = no checks in @sanna_observe. The constitution drives which checks run, at what enforcement level (halt/warn/log), and what triggers halt.
- **Receipts are portable artifacts.** JSON documents that verify offline without platform access. They are the product — not traces, not logs.
- **Ed25519 signatures** use RFC 8785-style JCS canonicalization (integers only, floats rejected at signing boundary).
- **Check IDs** use `sanna.*` namespace via CHECK_REGISTRY. Each check has a `check_impl` field and `replayable` flag.
- **Fingerprint** is deterministic and covers all receipt fields including check_results, constitution_ref, halt_event, enforcement_decision. Modifying any covered field breaks verification.
- **PARTIAL status** when some invariants are NOT_CHECKED (custom invariants without registered evaluators). `evaluation_coverage` block tracks basis points.

## Invariant-to-Check Mapping
| Constitution Invariant    | Check | Default if missing |
|---------------------------|-------|--------------------|
| INV_NO_FABRICATION        | C1    | Skip               |
| INV_MARK_INFERENCE        | C2    | Skip               |
| INV_NO_FALSE_CERTAINTY    | C3    | Skip               |
| INV_PRESERVE_TENSION      | C4    | Skip               |
| INV_NO_PREMATURE_COMPRESSION | C5 | Skip               |

## CLI Tools
- `sanna` — receipt generation
- `sanna-verify` — offline verification (receipt + optional constitution chain with `--constitution --constitution-public-key`)
- `sanna-keygen --signed-by "Name"` — Ed25519 keypair generation with metadata
- `sanna-sign-constitution` — sign constitution YAML (requires `--private-key`)
- `sanna-verify-constitution` — verify constitution signature
- `sanna-hash-constitution` — hash only (no signing)
- `sanna-init-constitution` — scaffold new constitution YAML

## Rules
- Run `pytest` from repo root after every change. Zero regressions required.
- Never modify existing test assertions without explicit instruction.
- All new receipt fields must be added to: schema, fingerprint, verifier, and golden receipts.
- Golden receipts must be regenerated when receipt structure changes.
- `pyproject.toml` is the single source for version and dependencies.
- Private key files must be written with `0o600` permissions on POSIX.
- Unsigned constitutions are rejected at runtime — no auto-signing bypass.
- CLI must produce clean error messages, never raw tracebacks.
- Schema validation is `strict=True` by default on enforcement paths.

## Testing
- Framework: pytest
- Golden receipts in `tests/golden/` — fingerprint changes require regeneration
- Constitution fixtures in `tests/` — various YAML configs for enforcement scenarios
- Run: `pytest` (no flags needed)
- Coverage not enforced but new features need tests

## Style
- Python 3.10+
- Type hints on all public functions
- Dataclasses for structured data (existing pattern — don't migrate to Pydantic without instruction)
- No `print()` in library code — use `logging`
- Imports: stdlib → third-party → local, grouped with blank lines
- Constants: UPPER_CASE at module level

## Dependencies (current)
- pyyaml — constitution YAML parsing
- cryptography — Ed25519 signatures
- jsonschema — schema validation
- No runtime dependency on any LLM provider or API
