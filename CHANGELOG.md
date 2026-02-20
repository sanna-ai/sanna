# Changelog

**Note:** v0.13.x is the first public release series. Earlier version entries document internal pre-release development.

## [0.13.5] - 2026-02-20

Documentation and test hygiene release. No library code changes.

### Documentation
- CLAUDE.md brought current with v0.13.x (was 4 versions behind)
- CONTRIBUTING.md updated
- README Quick Start parameter fix

### Tests
- Stale golden receipts removed
- v13 golden receipt vectors committed
- Test count: 2489+

## [0.13.2] - 2026-02-18

### Security
- HIGH: DNS rebinding TOCTOU — re-validate webhook URLs at send time
- HIGH: Escalation webhooks now enforced with same SSRF/redirect/HTTPS protections as gateway webhooks
- HIGH: NAT64 and CGNAT IP ranges blocked in webhook validation
- HIGH: Meta-tool argument validation prevents gateway crashes
- MEDIUM: Float canonicalization fully implemented (normalize_floats no longer pass-through)
- MEDIUM: Negative zero normalized to zero in canonical JSON
- MEDIUM: NaN/Infinity rejected by safe_json_loads
- MEDIUM: Duplicate JSON key rejection extended to all security-sensitive parsing paths
- MEDIUM: YAML duplicate key rejection in config validation CLI
- MEDIUM: Redaction marker cross-validation against declared redacted_fields
- MEDIUM: Empty tool names rejected at authority boundary
- MEDIUM: Escalation arguments deep-copied at creation time
- LOW: Symlink TOCTOU eliminated via O_NOFOLLOW on escalation persistence and gateway secret
- LOW: Unicode tool name normalization via NFKC
- LOW: IPv6 loopback added to insecure webhook allowlist
- LOW: Escalation persistence permissions aligned with gateway secret

### Specification (v1.0.2)
- BLOCKING: Redaction marker schema defined
- BLOCKING: Authority normalization algorithm documented with test vectors
- IMPORTANT: HMAC token binding section corrected to match implementation
- IMPORTANT: Canonical JSON constraints for Go/Rust (no HTML escaping, float rejection)
- MINOR: Base64 variant pinned (RFC 4648 standard with padding)
- MINOR: Exit code behavior precisely documented

### Documentation
- Quick-start examples now runnable under defaults (constitution public key shown)
- Receipt persistence behavior accurately documented
- Version strings updated to 0.13.2
- Threat model and security claims tightened

## [0.13.1] - 2026-02-17

### Security
- 10 security findings remediated across enforcement, specification, and documentation paths
- 28 specification precision fixes
- 17 documentation fixes

### Tests
- 2412 tests

## [0.13.0] - 2026-02-17

Receipt format v1.0 specification, schema migration from v0.12.x field names, and security hardening across all enforcement paths.

### Security
- **CRIT-01: Approval channel hardened** — default token delivery changed to stderr-only, file delivery requires `SANNA_INSECURE_FILE_TOKENS=1`, webhook delivery with SSRF validation, TTY check on `sanna-approve`
- **CRIT-02: Constitution signature verification enforced in all paths** — middleware, MCP, gateway all require Ed25519 signature by default (`require_constitution_sig=True`), `signature_verified` field in `constitution_ref`
- **CRIT-03: PII redaction expanded** — `pattern_redact` mode now raises `ConfigError` at load time (fail-closed; full implementation deferred to future release), redacts `outputs.response` not `outputs.output`, redacted-only persistence with `_redaction_notice`
- **HIGH-01: error_policy parameter** — `fail_closed` (default) treats evaluator errors as real failures (`status=FAIL`), `fail_open` preserves legacy ERRORED behavior
- **HIGH-02: LLM evaluator prompt trust separation** — constitution in `<trusted_rules>`, untrusted I/O in `<audit_input>`/`<audit_output>`
- **HIGH-03: asyncio.Lock on EscalationStore** for thread-safe async writes
- **HIGH-04: ReceiptStore rejects /tmp paths** — resolves bare filenames to `~/.sanna/receipts/`
- **HIGH-05: sanna-verify --strict flag** — warns on signed receipts without verification key
- **HIGH-06: approve_constitution verifies author signature** before writing approval record
- **HIGH-07: Async decorator fix** — `_pre_execution_check_async` directly awaits pipeline, shared module-level `ThreadPoolExecutor` for sync path
- *(HIGH-08: consolidated into HIGH-07 during development)*
- **HIGH-09: WAL sidecar forced creation** with 0o600 permissions
- **MED-01: Docker ownership check skip** via `SANNA_SKIP_DB_OWNERSHIP_CHECK=1`
- *(MED-02: consolidated into MED-01 during development)*
- **MED-03: escape_audit_content handles None and non-string inputs**
- **MED-04: math.isfinite() guard** before float-to-int conversion in signing
- *(MED-05, MED-06: consolidated into other fixes during development)*
- **MED-07: Key generation directory** uses `ensure_secure_dir`
- **LOW-01: WAL sidecar TOCTOU fix** — `O_NOFOLLOW` + `fchmod` replaces `is_symlink()` + `chmod()`
- **LOW-02: Gateway secret symlink rejection** before file read
- **LOW-03: verify_signature catches specific exceptions** (`binascii.Error`, `ValueError`, `InvalidSignature`)

### Schema Migration
- `spec_version` "1.0" replaces `schema_version` "0.1"
- `correlation_id` replaces `trace_id` (backward-compat fallback reads retained)
- `status` replaces `coherence_status` (backward-compat fallback reads retained)
- `enforcement` replaces `halt_event` in receipt output (internal parameter name retained)
- `final_answer_provenance` removed
- All content hashes now 64-hex SHA-256 (`receipt_fingerprint` remains 16-hex truncation)
- `full_fingerprint` (64-hex) added alongside `receipt_fingerprint`
- `receipt_id` now UUID v4 with schema validation
- Fingerprint formula unified to 12 pipe-delimited fields with `EMPTY_HASH` sentinel
- `CHECKS_VERSION` bumped to "5"
- Extension keys use reverse-domain namespacing (`com.sanna.gateway`, `com.sanna.middleware`)
- `CheckResult` `additionalProperties: false` in schema
- `identity_verification` added to receipt schema

### Specification
- Published `spec/sanna-specification-v1.0.md` — 10 sections + 3 appendices covering receipt format, canonicalization, fingerprint construction, signing, constitution format, verification protocol

### Breaking Changes
- **v0.13.0 receipts use a new schema with `spec_version` field. The CLI cannot verify pre-v0.13.0 receipts.** Older receipts using `schema_version` are not forward-compatible with the v1.0 receipt schema.
- Receipt format incompatible with v0.12.x:
  - `schema_version` → `spec_version`
  - `trace_id` → `correlation_id`
  - `coherence_status` → `status`
  - `halt_event` → `enforcement` (in receipt output)
  - `final_answer_provenance` removed
  - Content hashes changed from 16-hex to 64-hex
  - Fingerprint formula changed from variable-length to fixed 12 fields
  - `receipt_id` now requires UUID v4 format
  - `require_constitution_sig=True` by default (unsigned constitutions rejected)
  - `error_policy=fail_closed` by default (evaluator errors now count as failures)
  - `ReceiptStore` rejects `/tmp` paths

### Migration from pre-v0.13.x
1. Regenerate all receipts — old receipt format is not verifiable
2. Re-sign constitutions with `sanna sign`
3. Update field references: see field mapping table above
4. Update verification scripts to use new CLI flags

### Tests
- 2211+ passed, 17 xfailed (10 heuristic limitations, 7 MCP SDK compat)

## [0.12.5] - 2026-02-17

Final security hardening from review cycle 4 (2 independent security reviews + 1 adoption review of v0.12.4).

### Security
- **LLM semantic evaluator prompts hardened** -- All _CHECK_PROMPTS in evaluators/llm.py now wrap untrusted content (context, output, constitution) in `<audit>` sub-tags with XML entity escaping, matching the reasoning client pattern. Shared `escape_audit_content` helper in `sanna.utils.sanitize`.
- **Legacy coherence client prompt injection eliminated** -- `AnthropicClient.evaluate_coherence` now wraps untrusted content (tool name, args, justification) in `<audit>` tags with XML escaping. No LLM judge paths accept unescaped untrusted input.
- **SQLite ReceiptStore hardens existing DB files** -- Existing databases are validated (regular file, correct ownership) and permissions enforced to 0o600 on open. WAL/SHM sidecar files hardened after journal mode enable. Symlinks rejected via `O_NOFOLLOW`.
- **Signature presence checks require valid Ed25519 structure** -- All enforcement points (middleware, gateway, MCP) now validate base64 encoding and 64-byte signature length via `is_valid_signature_structure()`. Whitespace, junk, and placeholder strings no longer satisfy the "signed" check.

### Reliability
- **EscalationStore thread-safe persistence** -- Dict snapshot taken in event loop thread before offloading to executor, eliminating cross-thread race on `self._pending`. Purge loop wrapped in try/except for resilience.

### Documentation
- **README Quick Start reordered** -- Library Mode now shows setup steps (keygen, init, sign) before the Python code block.
- **Receipts-per-action clarified** -- README explicitly states receipts are generated per governed action, not per conversational turn.
- **`_justification` field verified** -- Templates and examples confirmed to use correct field names.

## [0.12.4] - 2026-02-17

Final pre-launch fixes from third review cycle (2 independent security reviews + 1 adoption review of v0.12.3).

### Security
- **SannaGateway.for_single_server() now propagates policy config** — Factory method correctly wires policy_overrides, default_policy, and circuit_breaker_cooldown into DownstreamSpec. Passing policy kwargs alongside a downstreams list now raises ValueError.
- **Middleware rejects unsigned constitutions** — @sanna_observe now raises SannaConstitutionError for hashed-only constitutions, matching gateway enforcement behavior.
- **MCP receipt generation requires signed constitution** — sanna_generate_receipt MCP endpoint checks for cryptographic signature, not just policy hash.
- **SQLite store uses fd-based permission hardening** — Directory creation uses ensure_secure_dir(). DB file pre-created with 0o600 before sqlite3.connect to eliminate race window.

### Reliability
- **EscalationStore persistence path resolved at init** — Filename-only paths relocated to ~/.sanna/escalations/. No more writes to CWD.
- **EscalationStore saves offloaded to executor** — create, mark_status, and remove use run_in_executor for async safety.

### Correctness
- **LLM judge prompt structure aligned** — All untrusted data (tool name, args, justification) now inside <audit> tags, matching system prompt instructions.
- **sanna init path resolution fixed** — Gateway config references constitution filename when both files are in the same directory.
- **sanna demo persists public key** — Public key saved alongside receipt for manual verification.

### Removed
- **Langfuse adapter** (`sanna.adapters.langfuse`) — Context extraction logic folded into core `extract_trace_data()` in `receipt.py`. The `sanna[langfuse]` extras group is removed. `sanna-generate` now accepts a trace-data JSON file instead of a Langfuse trace ID.

### Documentation
- **docs/gateway-config.md** — Fixed meta-tool names and persistence default to match code.
- **docs/otel-integration.md** — OpenTelemetry integration guide: guaranteed vs experimental signal reference, configuration examples, pointer+hash architecture.
- **README** — Added Observability section for OTel integration. Removed Langfuse references.
- **cowork-team template** — Clarified description: shared governance via Git, not shared gateway infrastructure.

## [0.12.3] - 2026-02-17

### Security
- **Zip slip path traversal blocked** — `verify_bundle()` rejects archive entries containing `..` or absolute paths.
- **Atomic file writes with symlink protection** — All file write operations use `O_NOFOLLOW`/`O_EXCL` flags, randomized temp names, `fsync`, and `os.replace()`.
- **`~/.sanna` directory hardened to 0700** — Directory and file permissions enforced at creation for keys, secrets, and receipt stores.
- **SQLite receipt store permissions** — Database directory set to `0700`, database file set to `0600` on creation.
- **Escalation store path resolution** — Filename-only paths resolve to `~/.sanna/` instead of current directory, preventing chmod on cwd.
- **Per-tool escalation limits** — Per-tool caps prevent a single tool from exhausting the global escalation budget.
- **HMAC-SHA256 PII redaction** — Redaction hashes now use HMAC with gateway secret, replacing plain SHA-256.
- **Audit tag injection sanitized** — Angle brackets in untrusted content are escaped before LLM judge evaluation.
- **Constitution write-site hardening** — `save_constitution()` and `scaffold_constitution()` use safe atomic writes.

### Reliability
- **Async-safe `@sanna_observe`** — Detects `async def` functions and wraps them correctly, including `ThreadPoolExecutor` fallback for nested event loops.
- **Unused gateway config fields warn** — Unknown config fields like `transport` produce a log warning instead of being silently ignored.
- **OTel test guard fixed** — `importorskip("opentelemetry.sdk")` correctly skips when SDK is not installed.

### Correctness
- **`verify_constitution_chain` return type** — Return type annotation corrected to `tuple[list[str], list[str]]` matching actual `(errors, warnings)` return.
- **Float sanitization at signing boundary** — `sanitize_for_signing()` converts lossless floats (71.0 → 71) and rejects lossy floats with JSON path in error message.
- **sanna-verify --json output** — Verification results now available as structured JSON via `--format json`.

### Public API
- **Top-level exports trimmed to 10** — `sanna.__init__` exports only `sanna_observe`, `SannaResult`, `SannaHaltError`, `generate_receipt`, `SannaReceipt`, `verify_receipt`, `VerificationResult`, `ReceiptStore`, `DriftAnalyzer`, `__version__`. All other names import from submodules with helpful `AttributeError` migration messages.
- **Check functions made private** — `check_c1_*` through `check_c5_*` renamed to `_check_c1_*` through `_check_c5_*`. Backward-compatible aliases preserved.
- **`C3MReceipt` alias removed** — Use `SannaReceipt` from `sanna.receipt`.
- **`SannaGateway.for_single_server()` factory** — Preferred over deprecated `server_name`/`command` constructor args. Legacy path emits `DeprecationWarning`.
- **MCP tool renamed** — `check_constitution_approval` → `sanna_check_constitution_approval` for consistent `sanna_*` prefix.

### CLI
- **`sanna` unified CLI** — Top-level dispatcher for all subcommands: `sanna init`, `sanna verify`, `sanna demo`, etc.
- **`sanna demo`** — Self-contained governance demo: generates keys, constitution, receipt, and verifies — no external dependencies.
- **`sanna inspect`** — Pretty-prints receipt contents: checks, authority decisions, escalation events, signature status.
- **`sanna check-config`** — Dry-run gateway configuration validation: YAML syntax, constitution exists, keys exist with correct permissions, downstream commands specified.
- **`sanna keygen` default location** — Default output directory changed from `.` to `~/.sanna/keys/`.
- **`sanna init` gateway config** — After constitution generation, prompts to generate a `gateway.yaml` with sensible defaults.
- **Legacy CLI aliases removed** — `c3m-receipt`, `c3m-verify`, `sanna-init-constitution`, `sanna-hash-constitution` removed from entry points.
- **All existing `sanna-*` entry points preserved** — `sanna-verify`, `sanna-sign-constitution`, `sanna-keygen`, etc. remain as aliases.
- **CLI entry point count** — 16 registered commands in pyproject.toml.

### Documentation
- **README restructured** — `@sanna_observe` as first code example, Library + Gateway quick starts, Demo section, Custom Evaluators, Receipt Querying, 10-name API Reference, unified CLI table.
- **Production deployment guide** — `docs/production.md`: env vars, Docker, logging, retention, failure modes, upgrade steps.
- **Gateway config reference** — `docs/gateway-config.md`: every field documented with types, defaults, and examples.
- **Receipt format reference** — `docs/receipt-format.md`: complete JSON example, integer basis-points note, field reference tables, fingerprint construction.

### Tests
- 2076+ tests, 10 xfailed, 11 pre-existing MCP compat failures, 0 regressions

## [0.12.2] - 2026-02-16

Resolved 15 issues identified by two independent external code reviews before public launch.

### Security
- **Atomic file writes with symlink protection** — All file write operations now use a shared safe-write helper with randomized temp names, `O_NOFOLLOW`/`O_EXCL` flags, `fsync`, and `os.replace()`. Eliminates symlink-based arbitrary file overwrite attacks.
- **`~/.sanna` directory hardened** — Directory enforced `0700`, files `0600`, validated at creation. Gateway secret requires exactly 32 bytes.
- **PII redaction hashes salted** — Redaction hashes now include receipt-specific salt, preventing rainbow table reversal of low-entropy inputs.
- **Redaction no longer breaks signature verification** — Original signed receipts are persisted intact. Redacted views are written as separate, clearly-marked unsigned files.
- **Float/string hash collision eliminated** — Canonical JSON serialization now preserves numeric types. Floats and their string representations produce distinct hashes.
- **Prompt injection isolation in LLM judge** — Audited content wrapped in `<audit>` tags, separating untrusted input from judge instructions.
- **Token store hardened** — File locking prevents race conditions on concurrent writes. TTL-based pruning and size caps prevent unbounded growth.

### Reliability
- **Gateway I/O no longer blocks the async loop** — All file writes offloaded to thread pool via `run_in_executor`.
- **Downstream MCP connection serialized** — Per-connection `asyncio.Lock` prevents frame interleaving on non-concurrent-safe stdio sessions.
- **Score gating respects error_policy** — Check errors are distinguished from low scores. `error_policy` controls whether errored checks floor the overall score or are excluded.

### Correctness
- **Keyword matching uses word boundaries** — Authority condition matching uses `\b` regex instead of substring, preventing false positives ("add" no longer matches "padder").
- **Error receipts preserve reasoning evaluation** — Reasoning context survives into error receipts for complete audit trails.
- **Schema mutation handles empty args** — Tool-list-time authority evaluation marks arg-dependent conditions as runtime-evaluated rather than incorrectly resolving them.

### Configuration
- **Explicit judge provider fails loudly** — Requesting a specific judge provider (e.g., "anthropic") that can't be instantiated now raises an error instead of silently falling back to heuristic matching.
- **Judge capability logging** — Startup logs report which judge backend is active and why.
- **Redaction config warning** — Enabling redaction logs a prominent warning explaining the signed-vs-stored verification model.

### Dependencies
- Added `filelock` for token store concurrency safety.

### Tests
- 1992 tests (10 xfailed), 11 pre-existing MCP compat failures

## [0.12.1] - 2026-02-16

### Fixed
- **CI: pytest-asyncio** added to pip install in `.github/workflows/ci.yml`
- **MCP importorskip guards** added to 4 test sites that import `sanna.gateway.server` (TestPIIRedaction, TestAsyncWebhook, TestFloatFallbackRemoved, TestCLIDispatch)

## [0.12.0] - 2026-02-16

### Added
- **Receipt Triad verification in `sanna-verify`** — offline re-computation and comparison of input/reasoning/action hashes from gateway v2 receipts. Integrated as step 9 of `verify_receipt()`. `TriadVerification` dataclass with hash format validation, gateway boundary constraint check, and best-effort input hash re-computation.
- **Receipt Triad section in CLI output** — `sanna-verify` now displays a "RECEIPT TRIAD" section showing input/reasoning/action hashes, match indicators, binding status, and `gateway_boundary` context note.
- **PII redaction controls** — `RedactionConfig` in gateway config. Hash computed on full content before redaction; stored receipt is redacted with `[REDACTED — SHA-256: <hash>]`. Modes: `hash_only` (default).
- **MCP import check** — `check_mcp_available()` in gateway startup. Prints clear error message with install instructions when `mcp` package is missing.
- **Async webhook escalation** — `async_execute_escalation()` with `httpx.AsyncClient` primary path and `urllib.request` daemon-thread fallback.
- **`_justification` naming warning** — gateway logs a warning when a tool call includes `justification` but not `_justification` (the required leading-underscore form).
- **Vertical constitution templates** — `financial_analyst.yaml` (financial services with trade/PII/regulatory controls) and `healthcare_triage.yaml` (healthcare with prescription/PHI/patient communication controls) in `src/sanna/templates/`.
- **Documentation**:
  - `docs/drift-reports.md` — CLI/API examples, JSON/CSV exports, Splunk/Datadog/Grafana/Tableau integration
  - `docs/receipt-queries.md` — SQL queries, MCP query tool, Grafana dashboard examples
  - `docs/key-management.md` — key generation, storage, roles, rotation, multi-key environments
  - `docs/deployment-tiers.md` — Gateway Only, Gateway + Reasoning, Full Library tiers
  - Rewrote `README.md` for external developers
- 1912 tests (10 xfailed), 11 pre-existing MCP compat failures

### Changed
- **Downstream name validation relaxed** — gateway config now allows underscores in downstream server names (regex `^[a-zA-Z0-9_-]+$`), previously rejected.
- **Receipt store mode config** — `receipt_store_mode` field in gateway config supports `"filesystem"`, `"sqlite"`, or `"both"`.

## [0.11.1] - 2026-02-15

### Fixed
- 4 critical reasoning receipt fixes and 3 hardening passes
- 2 integration test suites added
- 1710 tests (10 xfailed), 0 failures

## [0.10.2] - 2026-02-15

### Added
- **Escalation store hardening** — TTL-based `purge_expired()`, `max_pending` capacity limit, full `uuid4().hex` escalation IDs, lifecycle status tracking
- **Receipt fidelity** — `arguments_hash`, `arguments_hash_method`, `tool_output_hash`, `downstream_is_error` in gateway receipt extensions
- **HMAC-SHA256 approval tokens** — escalation tokens bound via HMAC instead of plain UUID matching
- **Constitution Ed25519 verification on startup** — gateway verifies constitution signature when public key is available
- **Half-open circuit breaker** — probe-based recovery for downstream connections
- **Multi-downstream runtime** — gateway connects to multiple downstream MCP servers concurrently
- **`sanna-gateway migrate` CLI** — one-command migration from existing MCP client configs to governed gateway setup
- **Public API promotion** — `build_trace_data` and `generate_constitution_receipt` promoted to public API

### Fixed
- **Float arguments hash crash** — RFC 8785 canonical JSON rejects floats; gateway falls back to `json.dumps(sort_keys=True)` with `arguments_hash_method: "json_dumps_fallback"` indicator
- **Tool output content safety** — `_extract_result_text()` handles empty content, multiple items, non-text content types
- 1584 tests (10 xfailed), 11 pre-existing MCP compat failures

## [0.11.0] - 2026-02-15

### Breaking Changes
- **Constitution v1.1** with optional `reasoning` section (backward compatible — v1.0 constitutions parse without changes)
- **Receipt v2.0** with `reasoning_evaluation` field (v1.0 receipts still verify)
- **Schema mutation**: governed tools (`must_escalate`, `cannot_execute`) now include a `_justification` parameter injected at runtime

### Added
- **Reasoning Receipts** — cryptographically-signed artifacts proving an AI agent's reasoning was evaluated against governance rules before action
- **Receipt Triad** — every reasoning receipt cryptographically binds `input_hash`, `reasoning_hash`, and `action_hash`
- **Gateway-Local Checks** — three deterministic checks (presence, substance, no-parroting) plus LLM coherence for semantic alignment scoring
- **Constitution v1.1** — `reasoning:` section with `require_justification_for`, `on_missing_justification`, `on_check_error`, per-check configuration (`glc_002_minimum_substance`, `glc_003_no_parroting`, `glc_005_llm_coherence`), `evaluate_before_escalation`, `auto_deny_on_reasoning_failure`
- **Schema Mutation** — automatic `_justification` parameter injection for governed tools; justification stripped before forwarding to downstream
- **Approval Integration** — human approvers see reasoning evaluation scores and can override with documented reasons
- **Assurance Levels** — `full` / `partial` / `none` based on check results and errors
- **Reasoning receipts documentation** (`docs/reasoning-receipts.md`)
- **Example reasoning constitution** (`examples/constitutions/reasoning-example.yaml`)
- **Migration reasoning comment** — `sanna-gateway migrate` now appends a commented reasoning section to new constitutions for discoverability

### Fixed
- **Circuit breaker probe bypasses enforcement** — uses `list_tools()` protocol call, not the user's tool call [P0]
- **Namespace collision validation** — downstream names with underscores are rejected; migration sanitizes `_` to `-` [P0]
- **Receipt file permissions** — store directories get 0o700, receipt files get 0o600 on POSIX [P1]
- **Migration wires `constitution_public_key`** — generated `gateway.yaml` includes the public key path for startup verification [P1]
- **Escalation approval idempotency** — status guard prevents double-execution of approved/failed escalations [P1]
- **Multi-downstream optional flag** — `optional: true` on a downstream allows graceful degradation if it fails to connect [P1]
- **Migration atomic writes** — `_atomic_write()` uses `tempfile.mkstemp()` + `os.replace()` with symlink protection [P1]

### Documentation
- New reasoning receipts guide (`docs/reasoning-receipts.md`)
- Updated constitution examples with reasoning section
- Migration guide for v0.10.x to v0.11.0

## [0.10.0] - 2026-02-14
### Added
- **MCP enforcement gateway** (`sanna-gateway`) — proxy sits between MCP clients (Claude Desktop, Claude Code) and downstream MCP servers, enforcing constitution-based policy on every tool call
  - Spawns and manages downstream MCP server child processes via stdio
  - Discovers downstream tools and exposes them with `{server}_{tool}` namespace prefix
  - Policy cascade: per-tool override > server `default_policy` > constitution authority boundaries
  - Generates a cryptographic receipt for every tool call regardless of outcome
  - Three enforcement outcomes: `can_execute` (forward), `cannot_execute` (deny), `must_escalate` (escalation prompt)
  - `must_escalate` returns structured tool results prompting the MCP client for user approval
  - Approval/denial round-trip via `sanna_escalation_respond` meta-tool
  - Gateway signs its own receipts with a dedicated Ed25519 key (`sanna-keygen --label gateway`)
- **Gateway YAML config format** — `gateway:` section (transport, constitution, signing_key, receipt_store, escalation_timeout) + `downstream:` list (name, command, args, env with `${VAR}` interpolation, timeout, default_policy, per-tool overrides)
- **`sanna-gateway` CLI** and `python -m sanna.gateway` entry point
- **Gateway reference config** (`examples/gateway/gateway.yaml`) — Notion MCP server with 22 tools mapped: 13 reads (`can_execute`), 9 mutations (`must_escalate`)
- **Gateway demo** (`examples/gateway_demo.py`) — three-beat end-to-end demo: search (can_execute), update (must_escalate → approve), offline receipt verification
- **5 gateway test suites** — server shell, enforcement layer, escalation flow, config loading, hardening (timeout, reconnection, error handling)

### Changed
- **Tool namespace separator** — gateway uses `_` instead of `/` to comply with Claude Desktop's tool name pattern (`^[a-zA-Z0-9_-]{1,64}$`)
- **README** — added MCP Enforcement Gateway section with quickstart, Claude Desktop integration, gateway config reference, policy cascade, and constitution approval workflow
- **pyproject.toml** — added `sanna-gateway` entry point

### Fixed
- **Authority decision timestamps** — `authority_decisions` records in gateway receipts now include required `timestamp` field per receipt schema
- **Policy cascade false positives** — tools without per-tool overrides no longer fall through to constitution keyword matching; `default_policy` from config serves as intermediate fallback
- 1488 tests (10 xfailed), 0 failures

## [0.9.1] - 2026-02-14
### Added
- **`sanna-keygen --label`** — optional human-readable label stored in `.meta.json` sidecar. Key filenames use `key_id` (SHA-256 fingerprint) instead of hardcoded `sanna_ed25519`.
- **Identity Verification KYA Bridge** — `IdentityClaim`, `verify_identity_claims()`, `sanna_verify_identity_claims` MCP tool (7th tool), `identity_verification` section in receipts
- 7 post-review hardening fixes including Z-suffix timestamp parsing, strict base64 decoding, atomic sidecar writes
- 1214 tests (10 xfailed), 0 failures

## [0.9.0] - 2026-02-14
### Added
- **Constitution approval workflow** — `approve_constitution()` with Ed25519-signed approval records, `ApprovalRecord` and `ApprovalChain` data models
- **Constitution structural diffing** — `diff_constitutions()` → `DiffResult` with text/JSON/markdown output
- **`sanna-diff` and `sanna-approve-constitution`** CLI commands
- **`check_constitution_approval`** MCP tool (6th tool) with key-based signature verification
- **Evidence bundle 7-step verification** with independent key resolution by `key_id`
- 10 post-review hardening fixes
- 1163 tests (10 xfailed), 0 failures

## [0.8.2] - 2026-02-14
### Changed
- **LLM evaluator IDs renamed** — LLM semantic invariants now use distinct `INV_LLM_*` IDs (`INV_LLM_CONTEXT_GROUNDING`, `INV_LLM_FABRICATION_DETECTION`, `INV_LLM_INSTRUCTION_ADHERENCE`, `INV_LLM_FALSE_CERTAINTY`, `INV_LLM_PREMATURE_COMPRESSION`). These are separate semantic invariants, not replacements for built-in C1-C5 checks. Aliases are `LLM_C1` through `LLM_C5`.
- **LLM `evaluate()` raises on failure** — `LLMJudge.evaluate()` now raises `LLMEvaluationError` on API errors, timeouts, and malformed responses instead of returning a failed `CheckResult`. The middleware's existing exception handler produces ERRORED status, preventing false halts when the LLM API is unavailable.
- **Strict response validation** — `_parse_result()` validates that `pass` is bool, `confidence` is a number, and `evidence` is a string. Missing or wrong-typed fields raise `LLMEvaluationError`.

### Added
- **`llm_enhanced` constitution template** — new template combining built-in C1-C5 invariants with 5 LLM semantic invariants at `warn` enforcement.
- **LLM evaluator integration tests** — 8 tests covering full middleware pipeline: happy path, API failure under halt enforcement, no interference with built-in checks, multi-invariant end-to-end.

### Fixed
- **Negative limit bypass in MCP query** — `LIMIT -1` in SQLite dumps the entire database. MCP server now clamps limit to `max(1, min(int(limit), MAX_QUERY_LIMIT))`. Store adds defense in depth: negative limits treated as no-limit.
- **Non-string timestamps crash drift** — `_parse_ts()` now guards against non-string inputs (int, float, bool, None, dict) instead of crashing with `AttributeError`.
- **Drift analysis counts ERRORED as pass** — ERRORED checks are now excluded from pass/fail metrics in drift analysis, consistent with verifier and middleware behavior.
- **Schema version mismatch leaks connection** — `ReceiptStore.__init__()` now closes the SQLite connection if `_init_schema()` raises, preventing connection leaks on version mismatch errors.
- **`enable_llm_checks()` not idempotent** — `register_llm_evaluators()` now checks `get_evaluator()` before registering, silently skipping already-registered invariants. Safe to call multiple times.

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
