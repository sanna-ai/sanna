# Changelog

## [0.8.1] - 2026-02-13
### Added
- **LLM-as-Judge semantic evaluators** (`sanna.evaluators.llm`) — optional LLM-backed C1-C5 evaluation via Anthropic Messages API using stdlib `urllib.request`. `LLMJudge` class with `enable_llm_checks()` convenience function. Graceful ERRORED status on failure (timeout, HTTP error, malformed response). Check aliases (C1-C5) map to invariant IDs.
- **SQL-level LIMIT/OFFSET** on `ReceiptStore.query()` — pagination pushed into SQLite instead of post-fetch slicing. MCP server uses `limit+1` pattern for truncation detection.
- **Schema version guard** — `ReceiptStore` validates schema_version on open; raises `ValueError` on mismatch with clear diagnostic message.
- **Version single source of truth** — `src/sanna/version.py` imported by `__init__.py` and `receipt.py`. `TOOL_VERSION` in receipts now always matches package version.
- 990 tests (10 xfailed), 0 failures

### Fixed
- **CRITICAL: ERRORED verifier mismatch** — `verify_receipt()` now excludes ERRORED checks (alongside NOT_CHECKED) from status/count verification. Receipts with ERRORED custom evaluators pass offline verification.
- **CRITICAL: Stale TOOL_VERSION** — receipts previously hardcoded `tool_version: "0.7.2"` regardless of package version.
- **Naive timestamp crash in drift** — `_parse_ts()` handles naive timestamps (treated as UTC), "Z" suffix, and "+00:00" offset without `TypeError`.
- **Multi-report export overwrite** — `sanna-drift-report --output` with multiple `--window` flags now produces combined output (JSON array / CSV with single header) instead of overwriting.
- **SQLite WAL mode** — `ReceiptStore` enables `PRAGMA journal_mode=WAL` for concurrent read/write performance.

## [0.8.0] - 2026-02-14
### Added
- **Receipt persistence** (`ReceiptStore`) — SQLite-backed storage with indexed metadata columns for fleet-level governance queries. Thread-safe, context-manager support, combinable filters (agent_id, status, since/until, halt_event, check_status).
- **Drift analytics engine** (`DriftAnalyzer`) — per-agent, per-check failure-rate trending with pure-Python linear regression. Multi-window analysis (7/30/90/180-day), threshold breach projection, fleet health status (HEALTHY/WARNING/CRITICAL).
- **Export formats** — CSV and JSON export for enterprise reporting via `export_drift_report()` / `export_drift_report_to_file()`. CLI flags `--export json|csv` and `--output PATH` on `sanna-drift-report`.
- **`sanna_query_receipts` MCP tool** — 5th MCP tool for conversational governance posture queries. Filters by agent, status, time range, halt events. `analysis="drift"` mode runs drift analytics and returns fleet health report.
- **Custom invariant evaluators** — `@register_invariant_evaluator("INV_CUSTOM_*")` decorator for domain-specific checks. Evaluators receive `(context, output, constitution_dict, check_config_dict) -> CheckResult`. ERRORED status for evaluators that throw exceptions. Integrated with constitution engine and middleware.
- **Interactive `sanna-init` CLI** — guided constitution generator with 3 templates:
  - Enterprise IT / ServiceNow-style (strict enforcement)
  - Customer-Facing / Salesforce-style (standard enforcement)
  - General Purpose / Starter (advisory enforcement)
  - Plus blank template for fully custom constitutions
- **Fleet Governance Demo** (`examples/fleet_governance_demo.py`) — simulates 3 agents over 90 days, detects governance drift, exports evidence, verifies receipts offline
- `sanna-drift-report` CLI command for fleet governance reporting
- 934 tests (10 xfailed), 0 failures

### Fixed
- Custom evaluator receipts now pass offline verification — removed `"source"` field from check results (metadata only, not part of receipt schema)
- Receipt schema updated to allow `"ERRORED"` status on check results
- OTel exporter canonical hash uses `canonical_json_bytes()` for cross-verifier parity
- OTel exporter resolves namespaced check IDs via `NAMESPACED_TO_LEGACY` mapping

## [0.7.0] - 2026-02-13
### Added
- **MCP server** (`sanna-mcp`) — 4 tools over stdio for Claude Desktop/Cursor
  - `sanna_verify_receipt`: offline receipt verification
  - `sanna_generate_receipt`: receipt generation with constitution enforcement
  - `sanna_list_checks`: C1-C5 check metadata
  - `sanna_evaluate_action`: authority boundary enforcement
- **Authority boundary enforcement** — 3-tier action control in constitutions
  - `cannot_execute`: halt forbidden actions
  - `must_escalate`: route to log/webhook/callback escalation targets
  - `can_execute`: explicitly allow actions
- **Escalation targets** — log (Python logging), webhook (HTTP POST), callback (registry-based callable)
- **Trusted source tiers** — 4-tier source classification for C1 evaluation
  - tier_1 (grounded evidence), tier_2 (verification required), tier_3 (reference only), untrusted (excluded)
- **Evidence bundles** — self-contained zip archives for offline verification
  - `sanna-create-bundle` / `sanna-verify-bundle` CLI commands
  - 6-step verification: structure, schema, fingerprint, constitution sig, provenance chain, receipt sig
- **New receipt sections**: `authority_decisions`, `escalation_events`, `source_trust_evaluations`
- **Receipt schema** updated with AuthorityDecisionRecord, EscalationEventRecord, SourceTrustRecord definitions
- **Golden test vectors** (`tests/vectors/`) — deterministic Ed25519 + canonical JSON vectors for third-party verifiers
- **Claude Desktop integration** — config example and setup documentation
- **One More Connector demo** — 4-scenario MCP governance connector demo
- 703 tests

### Fixed
- Constitution Ed25519 signature now includes `authority_boundaries` and `trusted_sources` in signing material

## [0.6.4] - 2026-02-13
### Fixed
- Schema validation enforced on enforcement paths (middleware, adapter) — typos in constitutions now produce clear errors
- CLI commands produce clean error messages instead of Python tracebacks for all common failure modes
- Chain verification checks constitution signature value equality (not just policy_hash)
- Float values in signed payloads caught at generation boundary with clear path information
- Private key files written with 0o600 permissions on POSIX systems

## [0.6.3] - 2026-02-13
### Fixed
- Receipt schema updated to allow signature fields in constitution_ref (signed receipts now pass schema validation)
- Constitution Ed25519 signature binds full document including provenance and signer metadata
- Receipt Ed25519 signature binds signer metadata (key_id, signed_by, signed_at)
- RFC 8785-style JSON canonicalization for cross-language verifier portability
- Float elimination from signed payloads (coverage_pct replaced with coverage_basis_points as integer)
- C4 contraction handling (can/can't no longer conflated)

### Added
- `policy_hash` replaces `document_hash` (semantic rename — hashes policy content only)
- `sanna-hash-constitution` CLI command for hash-only mode
- `sanna-sign-constitution` now requires `--private-key`
- Full chain verification: `sanna-verify --constitution --constitution-public-key`
- Signature scheme versioning (constitution_sig_v1, receipt_sig_v1)

## [0.6.2] - 2026-02-13
### Fixed
- Full SHA-256 key_id (64-char hex digest, was truncated to 16 chars)
- Demo rewritten with full Ed25519 provenance flow
- `sanna-keygen --signed-by` writes metadata file alongside keypair
- Schema patterns updated to ^[a-f0-9]{64}$

## [0.6.1] - 2026-02-13
### Added
- Ed25519 cryptographic signatures on constitutions and receipts
- Receipt-to-constitution provenance bond with offline verification
- Stable check IDs (sanna.* namespace, CHECK_REGISTRY)
- Replayable flag on check results
- PARTIAL status with evaluation_coverage block

### Fixed
- Removed auto-signing of unsigned constitutions (fail closed)
- Hash verification on constitution load
- C4 word-boundary fix ("can" no longer matches "cannot")
- C5 bullet-counting fix

## [0.6.0] - 2026-02-12
### Added
- Constitution enforcement drives check engine
- Invariant-to-check mapping
- Per-check enforcement levels (halt/warn/log)
- Three Constitutions Demo
- 290 tests
