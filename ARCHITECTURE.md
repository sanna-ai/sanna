# Sanna Architecture Inventory

> Trust infrastructure for AI agents. Checks reasoning during execution, halts when
> constraints are violated, generates portable cryptographic receipts proving governance
> was enforced.
>
> **Version:** 0.13.4 | **Python:** 3.10, 3.11, 3.12 | **Tests:** 2489 passed + 10 xfailed

---

## Table of Contents

- [1. Project Structure](#1-project-structure)
- [2. Module Inventory](#2-module-inventory)
  - [2.1 Core Library](#21-core-library)
  - [2.2 Constitution Engine](#22-constitution-engine)
  - [2.3 Cryptographic Layer](#23-cryptographic-layer)
  - [2.4 Receipt Generation & Verification](#24-receipt-generation--verification)
  - [2.5 Coherence Checks (C1-C5)](#25-coherence-checks-c1-c5)
  - [2.6 Enforcement Engine](#26-enforcement-engine)
  - [2.7 Evaluators & Extensions](#27-evaluators--extensions)
  - [2.8 Reasoning Receipts](#28-reasoning-receipts)
  - [2.9 Gateway / MCP Proxy](#29-gateway--mcp-proxy)
  - [2.10 MCP Server](#210-mcp-server)
  - [2.11 Storage & Analytics](#211-storage--analytics)
  - [2.12 Evidence Bundles](#212-evidence-bundles)
  - [2.13 CLI](#213-cli)
  - [2.14 Integrations](#214-integrations)
  - [2.15 Utilities](#215-utilities)
- [3. Data Flow Diagrams](#3-data-flow-diagrams)
  - [3.1 Constitution Loading to Enforcement](#31-constitution-loading--validation--enforcement)
  - [3.2 Receipt Lifecycle](#32-receipt-creation--signing--verification)
  - [3.3 Gateway Proxy Flow](#33-gateway-proxy-request--governance--forwardblock)
  - [3.4 CLI Invocation](#34-cli-command-invocation)
  - [3.5 Coherence Check Pipeline](#35-coherence-check-pipeline-c1-c5)
- [4. Data Models & Schemas](#4-data-models--schemas)
  - [4.1 Dataclasses](#41-dataclasses)
  - [4.2 Constitution YAML Schema](#42-constitution-yaml-schema)
  - [4.3 Receipt JSON Schema](#43-receipt-json-schema)
  - [4.4 Gateway Configuration Schema](#44-gateway-configuration-schema)
  - [4.5 Constants & Sentinel Values](#45-constants--sentinel-values)
- [5. Public API Surface](#5-public-api-surface)
  - [5.1 Library Imports](#51-library-imports)
  - [5.2 CLI Commands](#52-cli-commands)
  - [5.3 MCP Tools](#53-mcp-tools)
  - [5.4 Extension Points](#54-extension-points)
- [6. Test Architecture](#6-test-architecture)
- [7. Integration Points](#7-integration-points)
- [8. Configuration & Environment](#8-configuration--environment)

---

## 1. Project Structure

```
sanna-repo/
├── src/sanna/                    # Core library (54 .py files)
│   ├── __init__.py               # 10 public exports, __getattr__ migration hints
│   ├── version.py                # __version__ = "0.13.4"
│   ├── receipt.py                # C1-C5 checks, receipt assembly, dataclasses
│   ├── middleware.py             # @sanna_observe decorator, receipt generation
│   ├── verify.py                 # Offline receipt verification, fingerprint parity
│   ├── constitution.py           # Constitution parsing, signing, approval, identity
│   ├── constitution_diff.py      # Structural/semantic constitution diffing
│   ├── crypto.py                 # Ed25519 signing/verification, keypair generation
│   ├── hashing.py                # Canonical JSON (RFC 8785), deterministic hashing
│   ├── bundle.py                 # Evidence bundle creation/verification (7-step)
│   ├── store.py                  # SQLite-backed receipt persistence, WAL mode
│   ├── drift.py                  # Per-agent failure-rate trending, linear regression
│   ├── cli.py                    # All CLI entry points (except sanna-init, sanna-mcp)
│   ├── init_constitution.py      # Interactive constitution generator (sanna-init)
│   ├── enforcement/              # Enforcement subsystem
│   │   ├── __init__.py           # Re-exports
│   │   ├── constitution_engine.py# Invariant-to-check mapping, configure_checks()
│   │   ├── authority.py          # Authority boundary evaluation
│   │   └── escalation.py         # Escalation targets (log, webhook, callback)
│   ├── evaluators/               # Custom evaluator subsystem
│   │   ├── __init__.py           # Evaluator registry (register, get, list, clear)
│   │   └── llm.py                # LLM-as-Judge via Anthropic API (stdlib urllib)
│   ├── reasoning/                # Reasoning receipts (v0.11.0+)
│   │   ├── __init__.py           # Public re-exports
│   │   ├── evaluator.py          # High-level reasoning evaluation facade
│   │   ├── judge.py              # Abstract BaseJudge, JudgeVerdict, JudgeResult
│   │   ├── heuristic_judge.py    # Deterministic fallback judge (no API calls)
│   │   ├── judge_factory.py      # Provider auto-detection, cross-provider
│   │   ├── pipeline.py           # GLC check orchestration pipeline
│   │   ├── llm_client.py         # AnthropicJudge, OpenAIJudge implementations
│   │   └── checks/              # Individual reasoning checks
│   │       ├── base.py           # Abstract Check base class
│   │       ├── glc_001_presence.py   # Justification presence
│   │       ├── glc_002_substance.py  # Minimum substance
│   │       ├── glc_003_parroting.py  # Anti-parroting
│   │       └── glc_005_coherence.py  # LLM coherence
│   ├── gateway/                  # MCP enforcement proxy (v0.10.0+)
│   │   ├── __init__.py           # CLI entry point: main() → run_gateway()
│   │   ├── __main__.py           # python -m sanna.gateway support
│   │   ├── server.py             # SannaGateway, EscalationStore, circuit breaker
│   │   ├── mcp_client.py         # DownstreamConnection: stdio MCP client
│   │   ├── config.py             # YAML config, env var interpolation, SSRF validation
│   │   ├── migrate.py            # One-command migration from existing MCP configs
│   │   ├── receipt_v2.py         # Receipt Triad, GatewayCheckResult models
│   │   └── schema_mutation.py    # _justification parameter injection
│   ├── mcp/                      # MCP server (7 tools)
│   │   ├── __init__.py
│   │   ├── __main__.py           # python -m sanna.mcp support
│   │   └── server.py             # FastMCP server, 7 tools, stdio transport
│   ├── exporters/                # Observability integrations
│   │   ├── __init__.py
│   │   └── otel_exporter.py      # OpenTelemetry bridge: receipt → span
│   ├── utils/                    # Shared utilities
│   │   ├── __init__.py
│   │   ├── safe_io.py            # Atomic writes, symlink protection
│   │   ├── safe_json.py          # Duplicate key / NaN rejection
│   │   ├── safe_yaml.py          # Duplicate key detection
│   │   ├── sanitize.py           # XML escape for prompt injection prevention
│   │   └── crypto_validation.py  # Ed25519 structural pre-check
│   ├── spec/                     # JSON schemas (source of truth)
│   │   ├── constitution.schema.json
│   │   └── receipt.schema.json
│   └── templates/                # Constitution templates (11 YAML)
│       ├── __init__.py
│       ├── enterprise_it.yaml
│       ├── customer_facing.yaml
│       ├── general_purpose.yaml
│       ├── llm_enhanced.yaml
│       ├── financial_analyst.yaml
│       ├── healthcare_triage.yaml
│       ├── openclaw_personal.yaml
│       ├── openclaw_developer.yaml
│       ├── cowork_personal.yaml
│       ├── cowork_team.yaml
│       └── claude_code_standard.yaml
├── tests/                        # Test suite (93 .py files, 2143 tests)
│   ├── conftest.py               # Root fixtures, sets SANNA_CONSTITUTION_PUBLIC_KEY
│   ├── vectors/                  # Deterministic test vectors (3 JSON + README)
│   ├── constitutions/            # 10 test constitution YAML files
│   ├── .test_keys/               # Pre-generated Ed25519 keypair for tests
│   ├── reasoning/                # 6 reasoning-specific test files
│   └── (87 test_*.py files)      # See §6 for full listing
├── golden/receipts/              # Golden receipt test vectors (24 JSON files)
├── spec/                         # Root schema copies (must sync with src/sanna/spec/)
│   ├── constitution.schema.json
│   ├── receipt.schema.json
│   └── sanna-specification-v1.3.md
├── docs/                         # User/developer documentation (9 .md files)
├── examples/                     # Demo scripts, constitutions, gateway configs
│   ├── *.py                      # 5 demo Python scripts
│   ├── constitutions/            # 10 example constitutions
│   ├── gateway/                  # Reference gateway.yaml
│   └── demo_receipts/            # 4 sample receipts
├── .github/workflows/ci.yml      # CI: pytest across Python 3.10-3.12
├── pyproject.toml                # Package config, 17 console_scripts
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## 2. Module Inventory

### 2.1 Core Library

#### `src/sanna/__init__.py`

**Purpose:** Public API surface with 10 exports and migration hints for relocated names.

| Export | Type | Description |
|--------|------|-------------|
| `__version__` | `str` | Package version from `version.py` |
| `sanna_observe` | function | Decorator for runtime enforcement |
| `SannaResult` | class | Wrapper: agent output + receipt |
| `SannaHaltError` | exception | Raised when enforcement halts execution |
| `generate_receipt` | function | Generate receipt from trace data |
| `SannaReceipt` | dataclass | Receipt data model |
| `verify_receipt` | function | Offline receipt verification |
| `VerificationResult` | dataclass | Verification outcome |
| `ReceiptStore` | class | SQLite receipt persistence |
| `DriftAnalyzer` | class | Governance drift analytics |

`__getattr__` provides migration hints for ~70 names that moved to submodules in v0.12.0.

**Internal deps:** `version`, `middleware`, `receipt`, `verify`, `store`, `drift`

---

#### `src/sanna/version.py`

**Purpose:** Single source of truth for `__version__ = "0.13.4"`.

---

### 2.2 Constitution Engine

#### `src/sanna/constitution.py`

**Purpose:** Constitution loading, parsing, signing, approval, and identity verification.

| Export | Type | Description |
|--------|------|-------------|
| `Constitution` | dataclass | Top-level constitution model |
| `AgentIdentity` | dataclass | Agent name, domain, extensions, identity_claims |
| `IdentityClaim` | dataclass | Verifiable assertion from external provider |
| `IdentityVerificationResult` | dataclass | Per-claim verification outcome |
| `IdentityVerificationSummary` | dataclass | Aggregate verification results |
| `Provenance` | dataclass | Authorship, approval method, signature |
| `ConstitutionSignature` | dataclass | Ed25519 signature block |
| `Boundary` | dataclass | Scope/authorization/safety boundary |
| `Invariant` | dataclass | Rule with enforcement level and optional check |
| `HaltCondition` | dataclass | Trigger → escalation target |
| `AuthorityBoundaries` | dataclass | can/cannot/must_escalate lists |
| `EscalationRule` | dataclass | Condition + target pair |
| `EscalationTargetConfig` | dataclass | log/webhook/callback target |
| `TrustedSources` | dataclass | tier_1/tier_2/tier_3/untrusted lists |
| `TrustTiers` | dataclass | autonomous/requires_approval/prohibited |
| `ApprovalRecord` | dataclass | Single approval with Ed25519 signature |
| `ApprovalChain` | dataclass | Chain of approval records |
| `ReasoningConfig` | dataclass | Governance-level reasoning checks (v1.1) |
| `GLCCheckConfig` | dataclass | Base config for reasoning check |
| `GLCMinimumSubstanceConfig` | dataclass | Minimum-substance check config |
| `GLCNoParrotingConfig` | dataclass | No-parroting check config |
| `GLCLLMCoherenceConfig` | dataclass | LLM coherence check config |
| `JudgeConfig` | dataclass | Top-level judge configuration |
| `SannaConstitutionError` | exception | Raised on integrity check failure |
| `load_constitution(path, validate=True)` | function | Load and parse YAML |
| `save_constitution(constitution, path)` | function | Serialize to YAML |
| `parse_constitution(data)` | function | Dict → Constitution dataclass |
| `sign_constitution(constitution, private_key_path)` | function | Ed25519 sign |
| `approve_constitution(constitution, approver_id, ...)` | function | Add approval record |
| `scaffold_constitution()` | function | Blank constitution dict |
| `compute_constitution_hash(constitution)` | function | SHA-256 of canonical JSON |
| `compute_content_hash(constitution)` | function | Hash for approval binding |
| `validate_constitution_data(data)` | function | Returns list of error strings |
| `validate_against_schema(data)` | function | JSON schema validation |
| `constitution_to_receipt_ref(constitution)` | function | Constitution → receipt reference dict |
| `constitution_to_signable_dict(constitution)` | function | Canonical signing material |
| `constitution_to_dict(constitution)` | function | Full serialization |
| `verify_identity_claims(identity, provider_keys)` | function | Verify claims vs provider keys |

Key internals: `_claim_to_signable_dict()` (conditionally omits `expires_at`), `_identity_dict()` (sync fallback for programmatic claims), `_approval_record_to_signable_dict()`.

**Internal deps:** `hashing`, `crypto`
**External deps:** `hashlib`, `json`, `re`, `dataclasses`, `datetime`, `pathlib`

---

#### `src/sanna/constitution_diff.py`

**Purpose:** Structural/semantic comparison of two constitutions.

| Export | Type | Description |
|--------|------|-------------|
| `DiffEntry` | dataclass | Single change: category, change_type, key, old/new |
| `DiffResult` | dataclass | List of entries + `to_text()`, `to_json()`, `to_markdown()` |
| `diff_constitutions(old, new)` | function | Compare two Constitution objects → DiffResult |
| `export_drift_report(report, fmt)` | function | Drift report → JSON or CSV string |
| `export_drift_report_to_file(report, path, fmt)` | function | Write drift report to file |

Diff categories: identity, boundary, invariant, authority, trust, halt, provenance, approval.

**Internal deps:** `constitution`
**External deps:** `json`, `dataclasses`

---

### 2.3 Cryptographic Layer

#### `src/sanna/crypto.py`

**Purpose:** Ed25519 key management, signing, and verification.

| Export | Type | Description |
|--------|------|-------------|
| `generate_keypair(output_dir, signed_by, write_metadata, label)` | function | Generate Ed25519 keypair, returns (priv_path, pub_path) |
| `load_key_metadata(key_path)` | function | Read `.meta.json` sidecar |
| `load_private_key(path)` | function | Load Ed25519 private key from PEM |
| `load_public_key(path)` | function | Load Ed25519 public key from PEM |
| `compute_key_id(public_key)` | function | SHA-256 hex fingerprint (64 chars) |
| `sign_bytes(data, private_key)` | function | Sign → base64 signature |
| `verify_signature(data, signature_b64, public_key)` | function | Verify Ed25519 signature |
| `sanitize_for_signing(obj)` | function | Sanitize dict tree for canonical JSON |
| `sign_constitution_full(constitution, private_key_path)` | function | Sign constitution document |
| `verify_constitution_full(constitution, public_key_path)` | function | Verify constitution signature |
| `sign_receipt(receipt_dict, private_key_path)` | function | Sign receipt, add signature block |
| `verify_receipt_signature(receipt, public_key_path)` | function | Verify receipt signature |

Key filenames use the SHA-256 key fingerprint (not hardcoded `sanna_ed25519`).

**Internal deps:** `hashing`, `utils.safe_json`
**External deps:** `base64`, `cryptography` (Ed25519PrivateKey, Ed25519PublicKey)

---

#### `src/sanna/hashing.py`

**Purpose:** Canonical JSON (RFC 8785) serialization and deterministic hashing.

| Export | Type | Description |
|--------|------|-------------|
| `canonical_json_bytes(obj)` | function | Sanna Canonical JSON → bytes |
| `hash_text(s, truncate=64)` | function | NFC-normalize → SHA-256 hex |
| `hash_obj(obj, truncate=64)` | function | canonical_json_bytes → SHA-256 hex |
| `canonicalize_text(s)` | function | NFC normalization for hashing |
| `normalize_floats(obj)` | function | Normalize floats for canonical hashing |
| `sha256_hex(data, truncate=64)` | function | Raw SHA-256 hex |
| `EMPTY_HASH` | constant | SHA-256 of empty bytes |

Internal: `_reject_floats(obj, path)` raises on NaN/Infinity.

**External deps:** `hashlib`, `json`, `math`, `unicodedata`

---

### 2.4 Receipt Generation & Verification

#### `src/sanna/receipt.py`

**Purpose:** C1-C5 check implementations, receipt assembly, and trace data extraction.

| Export | Type | Description |
|--------|------|-------------|
| `CheckResult` | dataclass | check_id, name, passed, severity, evidence, details |
| `SannaReceipt` | dataclass | Full receipt model (spec_version through enforcement) |
| `Enforcement` | dataclass | Top-level enforcement outcome (v0.13.0+) |
| `FinalAnswerProvenance` | dataclass | Deprecated — where final answer was selected from |
| `ConstitutionProvenance` | dataclass | document_id, policy_hash, version, source |
| `HaltEvent` | dataclass | Deprecated — replaced by Enforcement |
| `generate_receipt(trace_data, checks, ...)` | function | Assemble receipt from trace data and check results |
| `select_final_answer(trace_data)` | function | Multi-step trace: select final answer with precedence |
| `extract_context(trace_data)` | function | Extract context string from trace |
| `extract_query(trace_data)` | function | Extract query string from trace |
| `extract_trace_data(trace)` | function | Generic context extraction (replaces Langfuse adapter) |
| `find_snippet(text, keywords, max_len)` | function | Extract relevant text snippet |
| `TOOL_VERSION` | constant | `"1.3.0"` |
| `SPEC_VERSION` | constant | `"1.3"` |
| `CHECKS_VERSION` | constant | `"8"` |

Check functions (private, with public aliases at module bottom):
- `_check_c1_context_contradiction(context, output, enforcement, structured_context)`
- `_check_c2_unmarked_inference(context, output, enforcement)`
- `_check_c3_false_certainty(context, output, enforcement)`
- `_check_c4_conflict_collapse(context, output, enforcement)`
- `_check_c5_premature_compression(context, output, enforcement)`

**Internal deps:** `hashing`, `version`
**External deps:** `uuid`, `dataclasses`, `datetime`

---

#### `src/sanna/middleware.py`

**Purpose:** Runtime enforcement decorator and receipt generation pipeline.

| Export | Type | Description |
|--------|------|-------------|
| `sanna_observe(...)` | decorator | Wraps agent function with governance checks |
| `SannaResult` | class | output + receipt wrapper, `.status`, `.passed` properties |
| `SannaHaltError` | exception | Raised on enforcement halt; carries `.receipt` |
| `build_trace_data(correlation_id, query, context, output)` | function | Build trace dict for generate_receipt |
| `generate_constitution_receipt(trace_data, check_configs, ...)` | function | Generate receipt from constitution-driven configs |

Key `sanna_observe` parameters: `receipt_dir`, `store`, `constitution_path`, `constitution_public_key_path`, `private_key_path`, `identity_provider_keys`, `require_constitution_sig`, `error_policy`, `strict`, `on_violation`, `checks`, `halt_on`.

Key internals: `_resolve_inputs()` (maps function args to context/query), `_post_execution_governance()` (shared sync/async governance logic), `_run_reasoning_gate()` / `_run_reasoning_gate_async()` (pre-execution reasoning checks), `_write_receipt()` (atomic file write).

**Internal deps:** `receipt`, `hashing`, `constitution`, `enforcement`, `crypto`, `store`, `utils.safe_io`, `utils.crypto_validation`, `utils.sanitize`, `reasoning.pipeline` (optional)
**External deps:** `functools`, `inspect`, `asyncio`, `concurrent.futures`

---

#### `src/sanna/verify.py`

**Purpose:** Offline receipt verification without network access.

| Export | Type | Description |
|--------|------|-------------|
| `VerificationResult` | dataclass | valid, exit_code, errors, warnings, fingerprints, status |
| `TriadVerification` | dataclass | Receipt Triad hash verification result |
| `load_schema(schema_path)` | function | Load receipt JSON schema |
| `verify_receipt(receipt, schema, ...)` | function | Full multi-step verification |
| `verify_receipt_triad(receipt)` | function | Verify Receipt Triad hashes |
| `verify_constitution_chain(receipt, constitution_path, ...)` | function | Verify receipt→constitution binding; returns (errors, warnings) |

Verification steps (in order):
1. `verify_schema()` — JSON schema validation
2. `verify_hash_format()` — SHA-256 hex format
3. `verify_content_hashes()` — recompute context_hash + output_hash
4. `verify_fingerprint()` → dispatches to `_verify_fingerprint_v013()` or `_verify_fingerprint_legacy()`
5. `verify_status_consistency()` — PASS/WARN/FAIL logic
6. `verify_check_counts()` — passed + failed match actuals
7. `verify_constitution_hash()` — policy_hash valid hex
8. Signature verification (optional, with `--public-key`)
9. `verify_constitution_chain()` + `_verify_approval_chain()`

**Internal deps:** `hashing`, `constitution`, `crypto`, `utils.safe_json`
**External deps:** `json`, `re`, `jsonschema`

---

### 2.5 Coherence Checks (C1-C5)

All implemented as private functions in `receipt.py`. Each takes `(context, output, enforcement)` and returns `CheckResult`.

| Check | Function | What It Detects |
|-------|----------|----------------|
| C1 | `_check_c1_context_contradiction` | Output claims that contradict provided context |
| C2 | `_check_c2_unmarked_inference` | Inferences/speculation presented as fact |
| C3 | `_check_c3_false_certainty` | Certainty language exceeding evidence strength |
| C4 | `_check_c4_conflict_collapse` | Conflicting evidence collapsed into single conclusion |
| C5 | `_check_c5_premature_compression` | Nuanced input reduced to unconditional output |

C1 has two modes: `_c1_flat()` (plain string context) and `_c1_source_aware()` (structured context with trust tiers).

Note: There is no `src/sanna/checks/` directory. These functions are all in `receipt.py`.

---

### 2.6 Enforcement Engine

#### `src/sanna/enforcement/__init__.py`

**Purpose:** Re-exports from submodules. Exports: `CheckConfig`, `CustomInvariantRecord`, `configure_checks`, `INVARIANT_CHECK_MAP`, `CHECK_REGISTRY`, `AuthorityDecision`, `evaluate_authority`, `EscalationTarget`, `EscalationResult`, `execute_escalation`, `register_escalation_callback`, `clear_escalation_callbacks`, `get_escalation_callback`.

---

#### `src/sanna/enforcement/constitution_engine.py`

**Purpose:** Maps constitution invariants to check functions.

| Export | Type | Description |
|--------|------|-------------|
| `CheckConfig` | dataclass | check_id, check_fn, enforcement_level, triggered_by, check_impl, source |
| `CustomInvariantRecord` | dataclass | invariant_id, rule, enforcement, status, reason |
| `configure_checks(constitution)` | function | Returns `(list[CheckConfig], list[CustomInvariantRecord])` |
| `CHECK_REGISTRY` | dict | Maps `sanna.*` namespaced IDs → check functions |
| `INVARIANT_CHECK_MAP` | dict | Maps `INV_*` IDs → `(check_impl_id, check_fn)` tuples |

Resolution order: explicit `check:` field → `INVARIANT_CHECK_MAP` → custom evaluator registry → `NOT_CHECKED`.

Standard mappings:

| Invariant ID | Check Implementation |
|---|---|
| `INV_NO_FABRICATION` | `sanna.context_contradiction` |
| `INV_MARK_INFERENCE` | `sanna.unmarked_inference` |
| `INV_NO_FALSE_CERTAINTY` | `sanna.false_certainty` |
| `INV_PRESERVE_TENSION` | `sanna.conflict_collapse` |
| `INV_NO_PREMATURE_COMPRESSION` | `sanna.premature_compression` |

**Internal deps:** `receipt` (CheckResult + check functions), `evaluators`, `constitution`

---

#### `src/sanna/enforcement/authority.py`

**Purpose:** Authority boundary evaluation engine.

| Export | Type | Description |
|--------|------|-------------|
| `AuthorityDecision` | dataclass | decision (halt/allow/escalate), reason, boundary_type, escalation_target |
| `evaluate_authority(action, params, constitution)` | function | Evaluate action against boundaries → AuthorityDecision |
| `normalize_authority_name(name)` | function | NFKC + camelCase splitting for matching |

Evaluation order: `cannot_execute` → `must_escalate` → `can_execute` → default allow.

Key internal: `_matches_action(pattern, action)` — bidirectional substring matching with separator normalization and `_STOP_WORDS` exclusion.

**Internal deps:** `constitution`, `escalation`

---

#### `src/sanna/enforcement/escalation.py`

**Purpose:** Runtime execution of escalation actions.

| Export | Type | Description |
|--------|------|-------------|
| `EscalationTarget` | dataclass | type (log/webhook/callback), url, handler |
| `EscalationResult` | dataclass | success, target_type, details |
| `execute_escalation(target, event_details)` | function | Synchronous escalation execution |
| `async_execute_escalation(target, event_details)` | function | Async variant (httpx or threading fallback) |
| `register_escalation_callback(name, handler)` | function | Register named callback |
| `clear_escalation_callbacks()` | function | Clear all registered callbacks |
| `get_escalation_callback(name)` | function | Look up registered callback |

Key internals: `_validate_escalation_url()` (SSRF validation), `_execute_webhook()` / `_execute_webhook_async()` (HTTP POST), `_webhook_threaded_fallback()` (stdlib urllib, daemon thread, no-redirect handler).

Note: This module's webhook implementation is independent from `gateway/server.py:_deliver_token_via_webhook()`. Security hardening must be applied to both.

**External deps:** `logging`, `datetime`, `dataclasses`

---

### 2.7 Evaluators & Extensions

#### `src/sanna/evaluators/__init__.py`

**Purpose:** Global evaluator registry with decorator-based registration.

| Export | Type | Description |
|--------|------|-------------|
| `register_invariant_evaluator(invariant_id)` | decorator | Register evaluator function for an invariant ID |
| `get_evaluator(invariant_id)` | function | Look up registered evaluator |
| `list_evaluators()` | function | List all registered invariant IDs |
| `clear_evaluators()` | function | Clear registry (tests MUST call this in fixtures) |

Module-level `_EVALUATOR_REGISTRY` dict. Raises on duplicate registration unless using idempotent `register_llm_evaluators()` path.

---

#### `src/sanna/evaluators/llm.py`

**Purpose:** LLM-as-Judge semantic evaluators using Anthropic API via stdlib urllib.

| Export | Type | Description |
|--------|------|-------------|
| `LLMJudge` | class | Evaluator using Claude API; `.evaluate(check_id, context, output, constitution)` → CheckResult |
| `LLMEvaluationError` | exception | Raised on LLM evaluation failure (not false CheckResult) |
| `register_llm_evaluators(judge, checks)` | function | Idempotent registration of LLM evaluators |
| `enable_llm_checks(api_key, model, checks)` | function | Convenience factory for LLM evaluators |

LLM invariant aliases: `LLM_C1`→`INV_LLM_CONTEXT_GROUNDING`, `LLM_C2`→`INV_LLM_FABRICATION_DETECTION`, `LLM_C3`→`INV_LLM_INSTRUCTION_ADHERENCE`, `LLM_C4`→`INV_LLM_FALSE_CERTAINTY`, `LLM_C5`→`INV_LLM_PREMATURE_COMPRESSION`.

Prompts are hardened with `<audit>` tag wrapping and XML entity escaping via `escape_audit_content()`.

**Internal deps:** `receipt.CheckResult`, `evaluators`, `utils.safe_json`, `utils.sanitize`
**External deps:** `json`, `os`, `urllib.request`

---

### 2.8 Reasoning Receipts

#### `src/sanna/reasoning/judge.py`

**Purpose:** Abstract judge interface (provider-agnostic).

| Export | Type | Description |
|--------|------|-------------|
| `JudgeVerdict` | enum | PASS, FAIL, ERROR, HEURISTIC |
| `JudgeResult` | dataclass | score, verdict, method, explanation, latency_ms, error_detail |
| `BaseJudge` | ABC | Abstract: `async evaluate(tool_name, arguments, justification, invariant_id)` → JudgeResult |

---

#### `src/sanna/reasoning/heuristic_judge.py`

**Purpose:** Deterministic fallback judge with no API calls (four sub-checks).

| Export | Type | Description |
|--------|------|-------------|
| `HeuristicJudge(BaseJudge)` | class | Presence + substance + parroting + length checks |

Default `_DEFAULT_MIN_LENGTH = 20`, default `_DEFAULT_BLOCKLIST` of boilerplate phrases.

---

#### `src/sanna/reasoning/judge_factory.py`

**Purpose:** Judge instantiation with provider auto-detection and fallback.

| Export | Type | Description |
|--------|------|-------------|
| `JudgeFactory` | class (static) | `.create(provider, model, api_key, error_policy, cross_provider, agent_provider)` → BaseJudge |
| `NoProviderAvailableError` | exception | Raised when no LLM provider can be configured |

Provider detection checks `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` environment variables.

---

#### `src/sanna/reasoning/pipeline.py`

**Purpose:** Orchestrates GLC reasoning checks for tool call justifications.

| Export | Type | Description |
|--------|------|-------------|
| `ReasoningPipeline` | class | `.evaluate(tool_name, args, enforcement_level)` → ReasoningEvaluation |

Runs checks in order: GLC-001 (presence) → GLC-002 (substance) → GLC-003 (parroting) → GLC-005 (LLM coherence, conditional). Produces assurance level: `full` / `partial` / `none`.

**Internal deps:** `constitution`, `gateway.receipt_v2`, `reasoning.checks.*`, `reasoning.judge`, `reasoning.judge_factory`

---

#### `src/sanna/reasoning/evaluator.py`

**Purpose:** High-level facade for reasoning evaluation.

| Export | Type | Description |
|--------|------|-------------|
| `ReasoningEvaluator` | class | `.evaluate(tool_name, args, enforcement_level)` → ReasoningEvaluation; `.strip_justification(args)` |

---

#### `src/sanna/reasoning/llm_client.py`

**Purpose:** LLM judge implementations for Anthropic and OpenAI.

| Export | Type | Description |
|--------|------|-------------|
| `AnthropicJudge(BaseJudge)` | class | Claude API judge via httpx |
| `OpenAIJudge(BaseJudge)` | class | OpenAI API judge via httpx |
| `AnthropicClient(LLMClient)` | class | Legacy client interface |
| `create_llm_client(provider, api_key, model)` | function | Legacy factory |

Both judges use `<audit>` tag wrapping and `escape_audit_content()` for prompt hardening. System prompts have standard and thorough scrutiny levels.

**External deps:** `httpx` (optional, guarded)

---

#### `src/sanna/reasoning/checks/`

| Module | Class | Check |
|--------|-------|-------|
| `base.py` | `Check(ABC)` | Abstract base with `run(justification, tool_name, args)` |
| `glc_001_presence.py` | `JustificationPresenceCheck` | GLC-001: Justification exists and non-empty |
| `glc_002_substance.py` | `MinimumSubstanceCheck` | GLC-002: Meets minimum length/content threshold |
| `glc_003_parroting.py` | `NoParrotingCheck` | GLC-003: Not boilerplate/parroted text |
| `glc_005_coherence.py` | `LLMCoherenceCheck` | GLC-005: LLM evaluates reasoning coherence |

---

### 2.9 Gateway / MCP Proxy

#### `src/sanna/gateway/server.py`

**Purpose:** MCP enforcement proxy — transparent tool forwarding with constitution enforcement, receipt generation, escalation handling, and circuit breaker health.

| Export | Type | Description |
|--------|------|-------------|
| `SannaGateway` | class | Main gateway: FastMCP server, multi-downstream, enforcement |
| `SannaGateway.for_single_server(name, command, ...)` | classmethod | Preferred factory for single downstream |
| `DownstreamSpec` | dataclass | Per-downstream config (name, command, args, env, timeout, policies) |
| `EscalationStore` | class | Pending escalations with TTL purge, capacity limits, HMAC tokens |
| `PendingEscalation` | dataclass | Held tool call awaiting approval |
| `CircuitState` | enum | CLOSED, OPEN, HALF_OPEN |
| `DuplicateToolError` | exception | Two downstreams register same prefixed tool name |
| `run_gateway()` | function | Parse `--config` and start gateway on stdio |

Key `SannaGateway` methods:
- `async start()` — connect to downstreams, discover tools, load constitution
- `async shutdown()` — disconnect all downstreams
- `async run_stdio()` — start, serve, shutdown

Meta-tools (not prefixed):
- `sanna_escalation_respond` — user approval/denial for `must_escalate` calls
- `sanna_gateway_status` — gateway health and connection status

Key internals: `_resolve_policy()` (cascade: per-tool → default_policy → constitution), `_generate_receipt()` (signed receipt with authority decisions), `_compute_approval_token()` (HMAC-SHA256), `_extract_result_text()` (safe MCP result extraction), `_apply_redaction_markers()` (PII redaction).

**Internal deps:** `gateway.mcp_client`, `gateway.config`, `constitution`, `enforcement`, `middleware`, `crypto`, `hashing`, `utils.safe_io`, `utils.safe_json`, `utils.crypto_validation`
**External deps:** `mcp` (FastMCP, types, stdio_server), `asyncio`, `hmac`, `hashlib`

---

#### `src/sanna/gateway/mcp_client.py`

**Purpose:** MCP client for downstream stdio server connections.

| Export | Type | Description |
|--------|------|-------------|
| `DownstreamConnection` | class | Spawns child process, MCP handshake, tool discovery, call forwarding |
| `DownstreamError` | exception | Base error |
| `DownstreamConnectionError` | exception | Connection/initialization failure |
| `DownstreamTimeoutError` | exception | Operation timeout |

Key methods: `async connect()`, `async close()`, `async reconnect()`, `async list_tools()`, `async call_tool(name, arguments)`. `call_tool` never raises — errors captured in `CallToolResult`.

**External deps:** `mcp` (ClientSession, StdioServerParameters, stdio_client)

---

#### `src/sanna/gateway/config.py`

**Purpose:** Gateway YAML config loader with validation and env var interpolation.

| Export | Type | Description |
|--------|------|-------------|
| `GatewayConfig` | dataclass | Top-level parsed config |
| `DownstreamConfig` | dataclass | Per-downstream server config |
| `ToolPolicyConfig` | dataclass | Per-tool policy override |
| `RedactionConfig` | dataclass | PII redaction controls |
| `GatewayConfigError` | exception | Invalid configuration |
| `load_gateway_config(config_path)` | function | Load and validate YAML → GatewayConfig |
| `resolve_tool_policy(tool_name, downstream)` | function | Cascade policy resolution |
| `build_policy_overrides(downstream)` | function | Flat policy overrides dict |
| `validate_webhook_url(url)` | function | SSRF validation |

Supports `${VAR_NAME}` interpolation in `env` blocks. SSRF validation rejects localhost, private IPs, link-local, multicast, and cloud metadata endpoints.

**Internal deps:** `utils.safe_yaml`
**External deps:** `yaml`, `ipaddress`, `os`, `re`

---

#### `src/sanna/gateway/schema_mutation.py`

**Purpose:** Injects `_justification` parameter into downstream tool schemas.

| Export | Type | Description |
|--------|------|-------------|
| `mutate_tool_schema(tool_dict, constitution, ...)` | function | Add `_justification` param based on enforcement level |

---

#### `src/sanna/gateway/receipt_v2.py`

**Purpose:** Receipt v2.0 models: Receipt Triad and reasoning evaluation results.

| Export | Type | Description |
|--------|------|-------------|
| `ReceiptTriad` | dataclass | input_hash, reasoning_hash, action_hash, context_limitation |
| `GatewayCheckResult` | dataclass | check_id, method, passed, confidence, evidence, assurance_level |
| `RECEIPT_VERSION_2` | constant | `"2.0"` |
| `MAX_STORED_PAYLOAD_BYTES` | constant | 65536 (configurable via env) |

---

#### `src/sanna/gateway/migrate.py`

**Purpose:** One-command migration from existing MCP client configs to governed gateway.

| Export | Type | Description |
|--------|------|-------------|
| `migrate_command(args)` | function | CLI entry for `sanna-gateway migrate` |
| `ServerEntry` | dataclass | Parsed MCP server entry from client config |
| `MigrationPlan` | dataclass | Computed migration plan before execution |

Detects secrets (`sk-`, `ntn_`, `ghp_`, etc.) and replaces with `${VAR}` interpolation. Supports Claude Desktop adapter (macOS/Linux/Windows).

---

### 2.10 MCP Server

#### `src/sanna/mcp/server.py`

**Purpose:** FastMCP server exposing 7 governance tools over stdio transport.

| Tool | Parameters | Description |
|------|-----------|-------------|
| `sanna_verify_receipt` | `receipt_json` | Verify receipt offline |
| `sanna_generate_receipt` | `query`, `context`, `response`, `constitution_path?` | Generate receipt |
| `sanna_list_checks` | (none) | List C1-C5 checks with descriptions |
| `sanna_evaluate_action` | `action_name`, `action_params`, `constitution_path` | Evaluate against authority boundaries |
| `sanna_query_receipts` | `db_path?`, `agent_id?`, `status?`, `since?`, `until?`, `halt_only?`, `limit?`, `analysis?` | Query receipts or run drift analysis |
| `sanna_check_constitution_approval` | `constitution_path`, `author_public_key_path?`, `approver_public_key_path?` | Check approval status |
| `sanna_verify_identity_claims` | `constitution_path`, `provider_keys?` | Verify identity claims |

Size guards: `MAX_RECEIPT_JSON_SIZE` (1 MB), `MAX_CONTEXT_SIZE` (500 KB), `MAX_RESPONSE_SIZE` (500 KB), `MAX_ACTION_SIZE` (10 KB), `MAX_QUERY_LIMIT` (500).

**Internal deps:** `verify`, `middleware`, `constitution`, `enforcement`, `crypto`, `store`, `drift`
**External deps:** `mcp` (FastMCP), `pydantic` (BaseModel, Field)

---

### 2.11 Storage & Analytics

#### `src/sanna/store.py`

**Purpose:** SQLite-backed receipt persistence with WAL mode.

| Export | Type | Description |
|--------|------|-------------|
| `ReceiptStore` | class | SQLite receipt storage: `.save(receipt)`, `.query(filters)`, `.close()` |

Features: schema version validation, WAL mode, file permission hardening (0o600), symlink rejection, fd-based ownership check, combinable query filters, LIMIT/OFFSET.

`_SCHEMA_VERSION = 1`. Context manager support via `__enter__` / `__exit__`.

**Internal deps:** `utils.safe_json`
**External deps:** `sqlite3`, `threading`

---

#### `src/sanna/drift.py`

**Purpose:** Governance drift analytics using linear regression over stored receipts.

| Export | Type | Description |
|--------|------|-------------|
| `DriftAnalyzer` | class | `.analyze(window_days, threshold)` → DriftReport; `.analyze_multi(windows)` |
| `DriftReport` | dataclass | Fleet-level: window_days, threshold, agents, fleet_status |
| `AgentDriftSummary` | dataclass | Per-agent: total_receipts, checks, projected_breach_days |
| `CheckDriftDetail` | dataclass | Per-check: fail_rate, trend_slope, projected_breach_days |
| `calculate_slope(xs, ys)` | function | Least-squares linear regression |
| `project_breach(current_rate, slope, threshold)` | function | Days until threshold |
| `format_drift_report(report)` | function | Human-readable text output |
| `export_drift_report(report, fmt)` | function | JSON or CSV string |
| `export_drift_report_to_file(report, path, fmt)` | function | Write to file |

**Internal deps:** `store`
**External deps:** `csv`, `json`, `math`

---

### 2.12 Evidence Bundles

#### `src/sanna/bundle.py`

**Purpose:** Self-contained verification archives (zip) with 7-step verification.

| Export | Type | Description |
|--------|------|-------------|
| `BundleCheck` | dataclass | Single verification step: name, passed, detail |
| `BundleVerificationResult` | dataclass | valid, checks, receipt_summary, errors |
| `create_bundle(receipt_path, constitution_path, public_key_path, output_path, ...)` | function | Create evidence bundle zip |
| `verify_bundle(bundle_path, constitution_path?)` | function | 7-step verification |
| `BUNDLE_FORMAT_VERSION` | constant | `"1.0.0"` |

7 verification steps: (1) bundle structure, (2) receipt schema, (3) receipt fingerprint, (4) constitution signature, (5) provenance chain, (6) receipt signature, (7) approval verification.

Receipt and constitution keys are resolved independently by `key_id` from the `public_keys/` directory within the bundle.

**Internal deps:** `crypto`, `constitution`, `verify`, `utils.safe_json`, `utils.safe_yaml`
**External deps:** `zipfile`, `tempfile`

---

### 2.13 CLI

#### `src/sanna/cli.py`

**Purpose:** All CLI entry points (except `sanna-init` and `sanna-mcp`).

| Function | Command | Description |
|----------|---------|-------------|
| `main_sanna()` | `sanna` | Unified dispatcher for all subcommands |
| `main_generate()` | `sanna-generate` | Generate receipt from trace-data JSON |
| `main_verify()` | `sanna-verify` | Verify receipt integrity + signature + provenance |
| `main_keygen()` | `sanna-keygen` | Generate Ed25519 keypair (--label support) |
| `main_sign_constitution()` | `sanna-sign-constitution` | Sign constitution |
| `main_verify_constitution()` | `sanna-verify-constitution` | Verify constitution signature |
| `main_create_bundle()` | `sanna-create-bundle` | Create evidence bundle |
| `main_verify_bundle()` | `sanna-verify-bundle` | Verify evidence bundle |
| `main_drift_report()` | `sanna-drift-report` | Fleet drift analysis |
| `approve_constitution_cmd()` | `sanna-approve-constitution` | Approve signed constitution |
| `diff_cmd()` | `sanna-diff` | Diff two constitutions |
| `main_demo()` | `sanna-demo` | Self-contained governance demo |
| `main_inspect()` | `sanna-inspect` | Pretty-print receipt |
| `main_check_config()` | `sanna-check-config` | Validate gateway config (dry-run) |
| `format_receipt_summary(receipt)` | (library) | Human-readable receipt formatting |

**Internal deps:** `receipt`, `verify`, `constitution`, `crypto`, `bundle`, `store`, `drift`, `constitution_diff`, `utils.safe_json`
**External deps:** `argparse`, `json`, `sys`

---

#### `src/sanna/init_constitution.py`

**Purpose:** Interactive constitution generator with template selection.

| Export | Type | Description |
|--------|------|-------------|
| `main()` | function | Interactive wizard (sanna-init entry point) |
| `prompt_for_template()` | function | Template selection prompt |
| `generate_constitution(template_key, agent_name, ...)` | function | Generate from template |
| `load_template(template_key)` | function | Load YAML from importlib.resources |

Templates loaded via `importlib.resources` from `src/sanna/templates/`.

---

### 2.14 Integrations

#### `src/sanna/exporters/otel_exporter.py`

**Purpose:** OpenTelemetry bridge: receipt → OTel span with pointer + integrity hash.

| Export | Type | Description |
|--------|------|-------------|
| `receipt_to_span(receipt, tracer, artifact_uri?)` | function | Create OTel span from receipt metadata |
| `SannaOTelExporter(SpanExporter)` | class | Custom SpanExporter filtering for `sanna.receipt.id` attribute |

15 `sanna.*` span attributes. Span name: `sanna.governance.evaluation`. Content hash uses `canonical_json_bytes()` for cross-verifier parity.

**Internal deps:** `hashing`
**External deps:** `opentelemetry` (optional, guarded)

---

### 2.15 Utilities

#### `src/sanna/utils/safe_io.py`

| Export | Type | Description |
|--------|------|-------------|
| `atomic_write_sync(target_path, data, mode=0o600)` | function | Atomic write with symlink check, fsync, os.replace |
| `atomic_write_text_sync(target_path, text, mode=0o600)` | function | Text convenience wrapper |
| `ensure_secure_dir(dir_path, mode=0o700)` | function | Create/validate directory with symlink rejection |
| `SecurityError` | exception | Security check failure |

---

#### `src/sanna/utils/safe_json.py`

| Export | Type | Description |
|--------|------|-------------|
| `safe_json_loads(s)` | function | Rejects duplicate keys and NaN/Infinity |
| `safe_json_load(fp)` | function | File variant |

---

#### `src/sanna/utils/safe_yaml.py`

| Export | Type | Description |
|--------|------|-------------|
| `safe_yaml_load(stream)` | function | YAML parsing with duplicate key detection |

---

#### `src/sanna/utils/sanitize.py`

| Export | Type | Description |
|--------|------|-------------|
| `escape_audit_content(text)` | function | XML entity escaping (`&`, `<`, `>`) for LLM prompt injection prevention |

---

#### `src/sanna/utils/crypto_validation.py`

| Export | Type | Description |
|--------|------|-------------|
| `is_valid_signature_structure(sig)` | function | Non-empty, valid base64, exactly 64 bytes |
| `ED25519_SIGNATURE_LENGTH` | constant | `64` |

---

## 3. Data Flow Diagrams

### 3.1 Constitution Loading → Validation → Enforcement

```
User creates YAML constitution
         │
         ▼
constitution.py:load_constitution(path)
    ├── utils/safe_yaml.py:safe_yaml_load() — parse YAML, reject duplicate keys
    ├── constitution.py:validate_against_schema() — JSON schema validation
    ├── constitution.py:validate_constitution_data() — semantic validation
    └── constitution.py:parse_constitution(data) — dict → Constitution dataclass
         │
         ▼
constitution.py:sign_constitution(constitution, private_key_path)
    └── crypto.py:sign_constitution_full() — Ed25519 sign canonical JSON
         │
         ▼
enforcement/constitution_engine.py:configure_checks(constitution)
    ├── For each invariant:
    │   ├── Check explicit `check:` field → CHECK_REGISTRY lookup
    │   ├── Check INVARIANT_CHECK_MAP (INV_* → sanna.* check fn)
    │   ├── Check evaluators/__init__.py:get_evaluator() (custom)
    │   └── Fallback → CustomInvariantRecord(status="NOT_CHECKED")
    └── Returns (list[CheckConfig], list[CustomInvariantRecord])
         │
         ▼
middleware.py:sanna_observe() decorator — wraps agent function
    ├── _resolve_inputs() — extract context/query from function args
    ├── _run_reasoning_gate() — pre-execution reasoning checks (if reasoning config)
    ├── Execute wrapped function
    ├── generate_constitution_receipt() — run all configured checks
    │   ├── receipt.py:generate_receipt() — assemble receipt
    │   ├── enforcement/authority.py:evaluate_authority() — if action evaluation needed
    │   └── crypto.py:sign_receipt() — Ed25519 sign receipt
    ├── _write_receipt() — atomic write to receipt_dir
    └── Halt / warn / return SannaResult
```

### 3.2 Receipt Creation → Signing → Verification

```
Agent function returns output
         │
         ▼
middleware.py:generate_constitution_receipt()
    ├── receipt.py:extract_context(), extract_query()
    ├── hashing.py:hash_text(context) → context_hash
    ├── hashing.py:hash_text(output) → output_hash
    ├── Run each CheckConfig.check_fn(context, output, enforcement)
    │   └── Returns CheckResult per check
    ├── receipt.py:generate_receipt()
    │   ├── Compute checks_hash = hash_obj(checks list)
    │   ├── Compute constitution_hash (strip constitution_approval first)
    │   ├── Compute halt_hash, coverage_hash
    │   ├── Build fingerprint: "{trace_id}|{context_hash}|{output_hash}|..."
    │   │   └── Conditionally append authority/escalation/trust/extensions hashes
    │   ├── hashing.py:hash_text(fingerprint_input) → receipt_fingerprint
    │   └── Assemble SannaReceipt
    └── crypto.py:sign_receipt(receipt_dict, private_key_path)
         ├── Remove signature.value from signing material
         ├── hashing.py:canonical_json_bytes(receipt)
         └── crypto.py:sign_bytes(canonical_bytes, private_key) → base64 signature
              │
              ▼
         JSON receipt written to disk
              │
              ▼
verify.py:verify_receipt(receipt, schema, public_key_path)
    ├── verify_schema() — jsonschema validation
    ├── verify_hash_format() — SHA-256 hex pattern check
    ├── verify_content_hashes() — recompute context_hash + output_hash
    ├── verify_fingerprint() — recompute full fingerprint, compare
    ├── verify_status_consistency() — PASS/WARN/FAIL matches checks
    ├── verify_check_counts() — passed + failed tally
    ├── verify_constitution_hash() — policy_hash valid hex
    ├── crypto.py:verify_receipt_signature() — Ed25519 verify (optional)
    └── verify_constitution_chain() — receipt→constitution binding (optional)
         └── _verify_approval_chain() — content_hash + approval signature
```

### 3.3 Gateway Proxy: Request → Governance → Forward/Block

```
MCP Client (Claude Desktop / Claude Code)
         │ (MCP stdio)
         ▼
gateway/server.py:SannaGateway — FastMCP server
    ├── start() — connect to all downstreams, discover tools
    │   └── gateway/mcp_client.py:DownstreamConnection.connect()
    │       ├── Spawn child process (e.g., npx @notionhq/notion-mcp-server)
    │       └── MCP handshake → list_tools()
    │
    ├── Tool call arrives (e.g., "notion_API-patch-page")
    │   │
    │   ├── Strip prefix → resolve downstream + original tool name
    │   │
    │   ├── _resolve_policy(tool_name, ds_state)
    │   │   ├── Per-tool override (exact match on unprefixed name)
    │   │   ├── Server default_policy
    │   │   └── enforcement/authority.py:evaluate_authority() against constitution
    │   │
    │   ├── Policy = "cannot_execute":
    │   │   ├── _generate_receipt(tool_name, args, error_result)
    │   │   └── Return denial tool result
    │   │
    │   ├── Policy = "must_escalate":
    │   │   ├── reasoning/pipeline.py:ReasoningPipeline.evaluate() (if reasoning config)
    │   │   ├── EscalationStore.create_async() — store pending escalation
    │   │   ├── _compute_approval_token() — HMAC-SHA256
    │   │   ├── _deliver_token() — stderr / file / webhook
    │   │   ├── _generate_receipt() — escalation receipt
    │   │   └── Return structured approval prompt to client
    │   │       │
    │   │       ▼ (client sends sanna_escalation_respond)
    │   │   ├── Validate token (HMAC + expiry)
    │   │   ├── Forward to downstream: DownstreamConnection.call_tool()
    │   │   ├── _generate_receipt() — approved execution receipt
    │   │   └── Return downstream result
    │   │
    │   └── Policy = "can_execute":
    │       ├── reasoning/pipeline.py:ReasoningPipeline.evaluate() (if reasoning config)
    │       ├── Forward: DownstreamConnection.call_tool(original_name, arguments)
    │       ├── _generate_receipt() — success receipt
    │       └── Return downstream result to client
    │
    └── Circuit breaker:
        ├── Consecutive failures → OPEN state
        ├── Cooldown period → HALF_OPEN (single probe)
        └── Probe success → CLOSED
```

### 3.4 CLI Command Invocation

```
$ sanna verify receipt.json --constitution const.yaml --public-key key.pub
         │
         ▼
cli.py:main_sanna()
    └── Dispatches to: cli.py:main_verify()
         ├── argparse — parse CLI flags
         ├── utils/safe_json.py:safe_json_loads() — load receipt JSON
         ├── verify.py:load_schema() — load receipt.schema.json
         ├── verify.py:verify_receipt(receipt, schema, public_key_path)
         │   └── (see §3.2 verification steps)
         ├── verify.py:verify_constitution_chain(receipt, constitution_path, ...)
         │   ├── constitution.py:load_constitution()
         │   ├── Verify receipt→constitution document_id binding
         │   ├── crypto.py:verify_constitution_full() — check constitution signature
         │   └── _verify_approval_chain() — approval integrity
         ├── If --json: output JSON result
         └── Print human-readable verification report; sys.exit(exit_code)
```

### 3.5 Coherence Check Pipeline (C1-C5)

```
Inputs: context (str or structured list), output (str)
         │
         ▼
C1 — receipt.py:_check_c1_context_contradiction(context, output, enforcement, structured_context)
    ├── If structured_context: _c1_source_aware()
    │   ├── For each source in context:
    │   │   ├── Extract claims from source text
    │   │   ├── Check trust tier (tier_1 fully trusted, untrusted excluded)
    │   │   └── Compare against output claims
    │   └── Flag contradictions with source attribution
    └── Else: _c1_flat()
        ├── Extract key factual claims from context
        ├── Compare each claim against output
        └── Flag: output asserts opposite of context
         │
         ▼
C2 — receipt.py:_check_c2_unmarked_inference(context, output, enforcement)
    ├── Identify inference/speculation phrases in output
    ├── Check if properly hedged ("I think", "likely", "based on")
    └── Flag: assertions that extend beyond context without qualification
         │
         ▼
C3 — receipt.py:_check_c3_false_certainty(context, output, enforcement)
    ├── Detect certainty language ("definitely", "certainly", "always")
    ├── Check if evidence supports that level of certainty
    └── Flag: certainty exceeds evidence strength
         │
         ▼
C4 — receipt.py:_check_c4_conflict_collapse(context, output, enforcement)
    ├── Detect conflicting positions/data in context
    ├── Check if output acknowledges the conflict
    └── Flag: conflicting evidence collapsed into single conclusion
         │
         ▼
C5 — receipt.py:_check_c5_premature_compression(context, output, enforcement)
    ├── Detect nuanced/conditional input (mixed evidence, caveats)
    ├── Check if output preserves nuance
    └── Flag: conditional input → unconditional conclusion
         │
         ▼
Each check returns: CheckResult(check_id, name, passed, severity, evidence, details)
         │
         ▼
receipt.py:generate_receipt() — aggregate results
    ├── Count: checks_passed, checks_failed (excluding NOT_CHECKED, ERRORED)
    ├── Compute status:
    │   ├── Any failed + severity ≥ critical → "FAIL"
    │   ├── Any failed + severity < critical → "WARN"
    │   └── All passed → "PASS"
    └── Build enforcement decision (halt/warn/allow)
```

---

## 4. Data Models & Schemas

### 4.1 Dataclasses

#### Constitution Domain (`constitution.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `Constitution` | schema_version, identity, provenance, boundaries, invariants, authority_boundaries, trusted_sources, halt_conditions, approval, reasoning | Top-level model |
| `AgentIdentity` | agent_name, domain, description, extensions, identity_claims | Extensions dict is flattened for signing |
| `IdentityClaim` | provider, claim_type, credential_id, issued_at, expires_at, signature, public_key_id | Signed with canonical JSON |
| `Provenance` | authored_by, approved_by, approval_date, approval_method, change_history, signature | |
| `ConstitutionSignature` | value, key_id, signed_by, signed_at, scheme | scheme = "constitution_sig_v1" |
| `Boundary` | id (B###), description, category, severity | |
| `Invariant` | id, rule, enforcement, check | check is optional explicit check ID |
| `HaltCondition` | id (H###), trigger, escalate_to, severity, enforcement | |
| `AuthorityBoundaries` | cannot_execute, must_escalate, can_execute, default_escalation | must_escalate items are EscalationRule |
| `EscalationRule` | condition, target | Not hashable (no `set()`) |
| `EscalationTargetConfig` | type, url, handler | type: log/webhook/callback |
| `TrustedSources` | tier_1, tier_2, tier_3, untrusted | All lists of strings |
| `ApprovalRecord` | status, approver_id, approver_role, approved_at, approval_signature, constitution_version, content_hash | |
| `ApprovalChain` | records | `.current` property, `.is_approved` property |
| `ReasoningConfig` | require_justification_for, on_missing_justification, checks, judge, ... | v1.1 constitution extension |

#### Receipt Domain (`receipt.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `SannaReceipt` | spec_version, tool_version, checks_version, receipt_id, receipt_fingerprint, full_fingerprint, correlation_id, timestamp, inputs, outputs, context_hash, output_hash, checks, checks_passed, checks_failed, status, constitution_ref, enforcement | v0.13.0 format |
| `CheckResult` | check_id, name, passed, severity, evidence, details | |
| `Enforcement` | action, reason, failed_checks, enforcement_mode, timestamp | v0.13.0+ replaces HaltEvent |
| `ConstitutionProvenance` | document_id, policy_hash, version, source | |
| `HaltEvent` | halted, reason, failed_checks, timestamp, enforcement_mode | Deprecated |
| `FinalAnswerProvenance` | source, span_id, span_name, field | Deprecated |

#### Enforcement Domain (`enforcement/`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `CheckConfig` | check_id, check_fn, enforcement_level, triggered_by, check_impl, source | |
| `CustomInvariantRecord` | invariant_id, rule, enforcement, status, reason | status defaults "NOT_CHECKED" |
| `AuthorityDecision` | decision, reason, boundary_type, escalation_target | decision: halt/allow/escalate |
| `EscalationTarget` | type, url, handler | |
| `EscalationResult` | success, target_type, details | |

#### Verification Domain (`verify.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `VerificationResult` | valid, exit_code, errors, warnings, computed_fingerprint, expected_fingerprint, computed_status, expected_status | |
| `TriadVerification` | present, input_hash_valid, reasoning_hash_valid, action_hash_valid, errors, warnings | |

#### Bundle Domain (`bundle.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `BundleCheck` | name, passed, detail | Single verification step |
| `BundleVerificationResult` | valid, checks, receipt_summary, errors | |

#### Drift Domain (`drift.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `DriftReport` | window_days, threshold, generated_at, agents, fleet_status | |
| `AgentDriftSummary` | agent_id, constitution_id, status, total_receipts, checks, projected_breach_days | |
| `CheckDriftDetail` | check_id, total_evaluated, pass_count, fail_count, fail_rate, trend_slope, projected_breach_days, status | |

#### Diff Domain (`constitution_diff.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `DiffEntry` | category, change_type, key, old_value, new_value | change_type: added/removed/modified |
| `DiffResult` | entries, old_version, new_version, old_hash, new_hash | `.to_text()`, `.to_json()`, `.to_markdown()` |

#### Gateway Domain (`gateway/server.py`, `gateway/receipt_v2.py`)

| Dataclass | Key Fields | Notes |
|-----------|-----------|-------|
| `DownstreamSpec` | name, command, args, env, timeout, policy_overrides, default_policy, optional | |
| `PendingEscalation` | escalation_id, prefixed_name, original_name, arguments, server_name, reason, token_hash, status | Serializable via `.to_dict()` / `.from_dict()` |
| `ReceiptTriad` | input_hash, reasoning_hash, action_hash, context_limitation | |
| `GatewayCheckResult` | check_id, method, passed, confidence, evidence, assurance_level | |

#### Reasoning Domain (`reasoning/`)

| Type | Key Fields | Notes |
|------|-----------|-------|
| `JudgeVerdict` (enum) | PASS, FAIL, ERROR, HEURISTIC | |
| `JudgeResult` (dataclass) | score, verdict, method, explanation, latency_ms, error_detail | |
| `BaseJudge` (ABC) | `async evaluate(...)` → JudgeResult | |

---

### 4.2 Constitution YAML Schema

Source: `src/sanna/spec/constitution.schema.json`

```yaml
# Required root fields:
sanna_constitution: "1.0.0"          # Schema version (optional in schema, recommended)

identity:                             # REQUIRED
  agent_name: string (minLength: 1)   # REQUIRED — unique agent identifier
  domain: string (minLength: 1)       # REQUIRED — business domain
  description: string                 # optional
  identity_claims: []                 # optional — verifiable claims from providers
  # additionalProperties: allowed (flattened for signing)

provenance:                           # REQUIRED
  authored_by: string (minLength: 1)  # REQUIRED
  approved_by: string | string[]      # REQUIRED
  approval_date: string (YYYY-MM-DD)  # REQUIRED
  approval_method: string             # REQUIRED
  change_history: []                  # optional
  signature:                          # optional — Ed25519 signature block
    value: string | null              # base64-encoded signature
    key_id: string | null             # ^[a-f0-9]{64}$ SHA-256 fingerprint
    signed_by: string | null
    signed_at: string | null
    scheme: "constitution_sig_v1"

boundaries:                           # REQUIRED (minItems: 1)
  - id: string (^B\d{3}$)            # REQUIRED
    description: string               # REQUIRED
    category: scope|authorization|confidentiality|safety|compliance|custom  # REQUIRED
    severity: critical|high|medium|low|info  # REQUIRED

invariants: []                        # optional
  - id: string                        # REQUIRED — INV_*, custom
    rule: string                      # REQUIRED — human-readable
    enforcement: halt|warn|log        # REQUIRED
    check: string | null              # optional — explicit check implementation

halt_conditions: []                   # optional
  - id: string (^H\d{3}$)            # REQUIRED
    trigger: string                   # REQUIRED
    escalate_to: string               # REQUIRED
    severity: critical|high|medium|low|info  # REQUIRED
    enforcement: halt|warn|log        # REQUIRED

authority_boundaries:                 # optional
  cannot_execute: [string]
  must_escalate:                      # list of condition/target pairs
    - condition: string
      target: {type: log|webhook|callback, url?: string, handler?: string}
  can_execute: [string]

trusted_sources:                      # optional (or null)
  tier_1: [string]                    # full trust
  tier_2: [string]                    # evidence with verification flag
  tier_3: [string]                    # reference only
  untrusted: [string]                 # excluded from C1

escalation_targets:                   # optional
  default: log|webhook|callback

policy_hash: string | null            # ^[a-f0-9]{64}$

approval:                             # optional (or null)
  records:
    - status: approved|pending|revoked
      approver_id: string
      approver_role: string
      approved_at: string
      approval_signature: string      # base64 Ed25519 signature
      constitution_version: string
      content_hash: string            # ^[a-f0-9]{64}$
      previous_version_hash: string | null

reasoning:                            # optional (v1.1+)
  require_justification_for: [string]
  on_missing_justification: block|warn|allow
  on_check_error: block|warn|allow
  on_api_error: block|warn|allow
  checks: {glc_001: {...}, glc_002: {...}, ...}
  judge: {default_provider: string, default_model: string, cross_provider: bool}
```

---

### 4.3 Receipt JSON Schema

Source: `src/sanna/spec/receipt.schema.json`

```json
{
  "spec_version": "1.3",                     // REQUIRED
  "tool_version": "1.3.0",                   // REQUIRED
  "checks_version": "8",                     // REQUIRED
  "receipt_id": "uuid-v4",                   // REQUIRED
  "receipt_fingerprint": "hex16",            // REQUIRED — 16-char human-readable
  "full_fingerprint": "hex64",               // REQUIRED — 64-char programmatic
  "correlation_id": "string",                // REQUIRED — with path prefix
  "timestamp": "ISO 8601",                   // REQUIRED
  "inputs": {                                // REQUIRED
    "query": "string | null | RedactionMarker",
    "context": "string | null | RedactionMarker"
  },
  "outputs": {                               // REQUIRED
    "response": "string | null | RedactionMarker"
  },
  "context_hash": "hex64",                   // REQUIRED
  "output_hash": "hex64",                    // REQUIRED
  "checks": [{                               // REQUIRED
    "check_id": "^(C[1-5]|INV_.+|sanna\\..+)$",
    "name": "string",
    "passed": true|false,
    "severity": "info|warning|critical|high|medium|low",
    "evidence": "string | null",
    "details": "string | null",
    "triggered_by": "string | null",
    "enforcement_level": "halt|warn|log|null",
    "status": "NOT_CHECKED|ERRORED|FAILED|null",
    "check_impl": "string | null",
    "replayable": true|false|null
  }],
  "checks_passed": 0,                        // REQUIRED (integer >= 0)
  "checks_failed": 0,                        // REQUIRED (integer >= 0)
  "status": "PASS|WARN|FAIL|PARTIAL",        // REQUIRED

  // --- Optional fields ---
  "evaluation_coverage": {
    "total_invariants": 0,
    "evaluated": 0,
    "not_checked": 0,
    "coverage_basis_points": 0               // 0-10000 (10000 = 100%)
  },
  "constitution_ref": {
    "document_id": "string",
    "policy_hash": "hex16|hex64",
    "constitution_approval": {...} | {"status": "unapproved"} | null
  },
  "enforcement": {
    "action": "halted|warned|allowed|escalated",
    "reason": "string",
    "failed_checks": ["string"],
    "enforcement_mode": "halt|warn|log",
    "timestamp": "ISO 8601"
  },
  "receipt_signature": {
    "signature": "string",
    "key_id": "hex64",
    "signed_by": "string",
    "signed_at": "ISO 8601",
    "scheme": "receipt_sig_v1"
  },
  "authority_decisions": [{
    "action": "string",
    "params": {},
    "decision": "halt|allow|escalate",
    "reason": "string",
    "boundary_type": "cannot_execute|must_escalate|can_execute|uncategorized",
    "timestamp": "ISO 8601"                   // REQUIRED in each record
  }],
  "escalation_events": [{...}],
  "source_trust_evaluations": [{...}],
  "identity_verification": {
    "total_claims": 0,
    "verified": 0,
    "failed": 0,
    "unverified": 0,
    "all_verified": true|false,
    "claims": [...]
  },
  "input_hash": "hex64 | null",              // Receipt Triad
  "reasoning_hash": "hex64 | null",
  "action_hash": "hex64 | null",
  "assurance": "full|partial|null",
  "redacted_fields": ["inputs.context"],
  "extensions": {}                            // Reverse-domain-namespaced
}
```

**RedactionMarker:** `{"__redacted__": true, "original_hash": "hex64"}`

---

### 4.4 Gateway Configuration Schema

See `src/sanna/gateway/config.py` and full reference in `docs/gateway-config.md`.

```yaml
gateway:
  transport: stdio                              # only "stdio" supported
  constitution: <path>                          # REQUIRED
  signing_key: <path>                           # REQUIRED
  constitution_public_key: <path>               # optional
  require_constitution_sig: true                # default: true
  receipt_store: <path>                         # optional
  escalation_timeout: 300                       # seconds
  max_pending_escalations: 100
  circuit_breaker_cooldown: 60                  # seconds
  gateway_secret_path: <path>                   # HMAC key for tokens
  escalation_persist_path: <path>               # persistent escalation store
  approval_requires_reason: false
  approval_webhook_url: <url>                   # token delivery webhook
  token_expiry_seconds: 900                     # 15 minutes
  token_delivery: [stderr]                      # stderr|file|log|webhook|callback
  redaction:
    enabled: false
    mode: hash_only                             # hash_only|pattern_redact
    fields: [arguments, result_text]

downstream:
  - name: <alphanumeric+hyphens+underscores>    # REQUIRED
    command: <executable>                        # REQUIRED
    args: [<string>]                            # default: []
    env:                                         # optional
      KEY: "${ENV_VAR}"                          # interpolated from os.environ
    timeout: 30                                  # seconds
    default_policy: can_execute                  # can_execute|must_escalate|cannot_execute
    optional: false
    tools:                                       # per-tool overrides
      "tool-name":
        policy: must_escalate
        reason: "Human-readable explanation"
```

Policy cascade: per-tool override > server `default_policy` > constitution authority boundaries.

---

### 4.5 Constants & Sentinel Values

#### Version Constants

| Constant | Location | Value | Purpose |
|----------|----------|-------|---------|
| `TOOL_VERSION` | `receipt.py` | `"1.3.0"` | Package version in receipts |
| `SPEC_VERSION` | `receipt.py` | `"1.3"` | Receipt spec version |
| `CHECKS_VERSION` | `receipt.py` | `"8"` | Check algorithm version (part of fingerprint); 16-field formula at cv=8 |
| `_SCHEMA_VERSION` | `store.py` | `1` | SQLite schema version |
| `BUNDLE_FORMAT_VERSION` | `bundle.py` | `"1.0.0"` | Evidence bundle format |
| `RECEIPT_VERSION_2` | `gateway/receipt_v2.py` | `"2.0"` | Receipt v2 identifier |

#### Size Guards

| Constant | Location | Value |
|----------|----------|-------|
| `MAX_QUERY_LIMIT` | `mcp/server.py` | 500 |
| `MAX_RECEIPT_JSON_SIZE` | `mcp/server.py` | 1 MB |
| `MAX_CONTEXT_SIZE` | `mcp/server.py` | 500 KB |
| `MAX_RESPONSE_SIZE` | `mcp/server.py` | 500 KB |
| `MAX_ACTION_SIZE` | `mcp/server.py` | 10 KB |
| `MAX_STORED_PAYLOAD_BYTES` | `gateway/receipt_v2.py` | 64 KB (env-configurable) |
| `MAX_BUNDLE_MEMBERS` | `bundle.py` | 10 |
| `MAX_BUNDLE_FILE_SIZE` | `bundle.py` | 10 MB |
| `ED25519_SIGNATURE_LENGTH` | `utils/crypto_validation.py` | 64 bytes |

#### Status Enums (string-based)

| Domain | Values | Used In |
|--------|--------|---------|
| Receipt status | `PASS`, `WARN`, `FAIL`, `PARTIAL` | `SannaReceipt.status` |
| Enforcement action | `halted`, `warned`, `allowed`, `escalated` | `Enforcement.action` |
| Enforcement mode | `halt`, `warn`, `log` | `Invariant.enforcement` |
| Authority decision | `halt`, `allow`, `escalate` | `AuthorityDecision.decision` |
| Boundary type | `cannot_execute`, `must_escalate`, `can_execute`, `uncategorized` | `AuthorityDecision.boundary_type` |
| Check status | `NOT_CHECKED`, `ERRORED`, `FAILED`, `null` | `CheckResult.status` |
| Trust tier | `tier_1`, `tier_2`, `tier_3`, `untrusted`, `unclassified` | `source_trust_evaluations` |
| Identity status | `verified`, `unverified`, `failed`, `expired`, `no_key` | `IdentityVerificationResult.status` |
| Approval status | `approved`, `pending`, `revoked`, `unapproved` | `ApprovalRecord.status` |
| Signature scheme | `constitution_sig_v1`, `receipt_sig_v1` | Signature blocks |
| Escalation type | `log`, `webhook`, `callback` | `EscalationTargetConfig.type` |
| Circuit state | `CLOSED`, `OPEN`, `HALF_OPEN` | `CircuitState` enum |
| Judge verdict | `pass`, `fail`, `error`, `heuristic` | `JudgeVerdict` enum |
| Assurance level | `full`, `partial`, `none` | Receipt `assurance` field |
| Redaction mode | `hash_only`, `pattern_redact` | `RedactionConfig.mode` |

#### Behavioral Constants

| Constant | Location | Value | Meaning |
|----------|----------|-------|---------|
| `_NON_EVALUATED` | `middleware.py`, `verify.py`, `drift.py` | `("NOT_CHECKED", "ERRORED")` | Excluded from pass/fail counts |
| `_STOP_WORDS` | `enforcement/authority.py` | frozenset (a, an, the, or, ...) | Excluded from authority matching |
| `EMPTY_HASH` | `hashing.py` | SHA-256 of `b""` | Sentinel for empty content |

---

## 5. Public API Surface

### 5.1 Library Imports

**Top-level exports** (`from sanna import ...`):

```python
from sanna import (
    __version__,              # "0.13.4"
    sanna_observe,            # Decorator for runtime enforcement
    SannaResult,              # Output + receipt wrapper
    SannaHaltError,           # Exception on enforcement halt
    generate_receipt,         # Generate receipt from trace data
    SannaReceipt,             # Receipt dataclass
    verify_receipt,           # Offline verification
    VerificationResult,       # Verification outcome
    ReceiptStore,             # SQLite persistence
    DriftAnalyzer,            # Governance drift analytics
)
```

**Submodule imports** (full public API):

```python
# Constitution
from sanna.constitution import (
    Constitution, load_constitution, save_constitution, parse_constitution,
    sign_constitution, approve_constitution, scaffold_constitution,
    compute_constitution_hash, compute_content_hash,
    validate_constitution_data, validate_against_schema,
    constitution_to_receipt_ref, constitution_to_signable_dict, constitution_to_dict,
    verify_identity_claims,
    AgentIdentity, IdentityClaim, IdentityVerificationResult, IdentityVerificationSummary,
    Boundary, Invariant, Provenance, ConstitutionSignature,
    HaltCondition, AuthorityBoundaries, EscalationRule, EscalationTargetConfig,
    TrustedSources, TrustTiers, ApprovalRecord, ApprovalChain,
    ReasoningConfig, SannaConstitutionError,
)

# Crypto
from sanna.crypto import (
    generate_keypair, load_key_metadata,
    load_private_key, load_public_key, compute_key_id,
    sign_bytes, verify_signature, sanitize_for_signing,
    sign_constitution_full, verify_constitution_full,
    sign_receipt, verify_receipt_signature,
)

# Hashing
from sanna.hashing import hash_text, hash_obj, canonical_json_bytes, canonicalize_text

# Enforcement
from sanna.enforcement import (
    CheckConfig, CustomInvariantRecord, configure_checks,
    INVARIANT_CHECK_MAP, CHECK_REGISTRY,
    AuthorityDecision, evaluate_authority,
    EscalationTarget, EscalationResult, execute_escalation,
    register_escalation_callback, clear_escalation_callbacks,
)

# Evaluators
from sanna.evaluators import (
    register_invariant_evaluator, get_evaluator, list_evaluators, clear_evaluators,
)
from sanna.evaluators.llm import LLMJudge, enable_llm_checks, LLMEvaluationError

# Receipt
from sanna.receipt import (
    CheckResult, SannaReceipt, Enforcement, ConstitutionProvenance, HaltEvent,
    generate_receipt, select_final_answer, extract_context, extract_query,
    extract_trace_data, TOOL_VERSION, SPEC_VERSION, CHECKS_VERSION,
)

# Middleware
from sanna.middleware import (
    sanna_observe, SannaResult, SannaHaltError,
    build_trace_data, generate_constitution_receipt,
)

# Verification
from sanna.verify import (
    verify_receipt, VerificationResult, TriadVerification,
    load_schema, verify_receipt_triad, verify_constitution_chain,
)

# Bundle
from sanna.bundle import create_bundle, verify_bundle, BundleVerificationResult, BundleCheck

# Store & Drift
from sanna.store import ReceiptStore
from sanna.drift import (
    DriftAnalyzer, DriftReport, AgentDriftSummary, CheckDriftDetail,
    calculate_slope, project_breach, format_drift_report,
    export_drift_report, export_drift_report_to_file,
)

# Diffing
from sanna.constitution_diff import diff_constitutions, DiffResult, DiffEntry

# OTel (optional)
from sanna.exporters.otel_exporter import receipt_to_span, SannaOTelExporter
```

---

### 5.2 CLI Commands

All registered in `pyproject.toml [project.scripts]`:

| Command | Entry Point | Description |
|---------|-------------|-------------|
| `sanna` | `cli:main_sanna` | Unified CLI dispatcher |
| `sanna-init` | `init_constitution:main` | Interactive constitution generator |
| `sanna-keygen` | `cli:main_keygen` | Generate Ed25519 keypair (`--label`) |
| `sanna-sign-constitution` | `cli:main_sign_constitution` | Sign constitution |
| `sanna-verify-constitution` | `cli:main_verify_constitution` | Verify constitution signature |
| `sanna-approve-constitution` | `cli:approve_constitution_cmd` | Approve signed constitution |
| `sanna-diff` | `cli:diff_cmd` | Diff two constitutions (text/JSON/markdown) |
| `sanna-generate` | `cli:main_generate` | Generate receipt from trace-data JSON |
| `sanna-verify` | `cli:main_verify` | Verify receipt (+signature +provenance) |
| `sanna-inspect` | `cli:main_inspect` | Pretty-print receipt contents |
| `sanna-create-bundle` | `cli:main_create_bundle` | Create evidence bundle |
| `sanna-verify-bundle` | `cli:main_verify_bundle` | Verify evidence bundle (7-step) |
| `sanna-drift-report` | `cli:main_drift_report` | Fleet governance drift report |
| `sanna-mcp` | `mcp.__main__:main` | Start MCP server (stdio) |
| `sanna-gateway` | `gateway:main` | Start MCP enforcement proxy |
| `sanna-demo` | `cli:main_demo` | Self-contained governance demo |
| `sanna-check-config` | `cli:main_check_config` | Validate gateway config (dry-run) |

---

### 5.3 MCP Tools

**MCP Server** (`sanna-mcp`, 7 tools over stdio):

| Tool | Parameters |
|------|-----------|
| `sanna_verify_receipt` | `receipt_json: str` |
| `sanna_generate_receipt` | `query, context, response, constitution_path?` |
| `sanna_list_checks` | (none) |
| `sanna_evaluate_action` | `action_name, action_params, constitution_path` |
| `sanna_query_receipts` | `db_path?, agent_id?, status?, since?, until?, halt_only?, limit?, analysis?` |
| `sanna_check_constitution_approval` | `constitution_path, author_public_key_path?, approver_public_key_path?` |
| `sanna_verify_identity_claims` | `constitution_path, provider_keys?` |

**Gateway Meta-Tools** (`sanna-gateway`, 2 meta-tools + downstream passthrough):

| Tool | Purpose |
|------|---------|
| `sanna_escalation_respond` | Approve/deny `must_escalate` tool calls |
| `sanna_gateway_status` | Gateway health and downstream status |

Downstream tools are prefixed: `{server_name}_{original_tool_name}`.

---

### 5.4 Extension Points

| Extension Point | Mechanism | Location |
|----------------|-----------|----------|
| Custom evaluators | `@register_invariant_evaluator(invariant_id)` decorator | `evaluators/__init__.py` |
| LLM evaluators | `enable_llm_checks(api_key, model, checks)` | `evaluators/llm.py` |
| Escalation callbacks | `register_escalation_callback(name, handler)` | `enforcement/escalation.py` |
| Receipt extensions | `extensions` dict field (reverse-domain-namespaced) | Receipt JSON |
| Constitution extensions | `identity.extensions` dict (additionalProperties: allowed) | Constitution YAML |
| OTel exporter | `SannaOTelExporter` as `SpanExporter` delegate | `exporters/otel_exporter.py` |
| Constitution templates | YAML files in `src/sanna/templates/` loaded via `importlib.resources` | `templates/` |
| Gateway downstream configs | YAML `downstream:` entries in gateway config | `gateway/config.py` |

---

## 6. Test Architecture

### Organization

**93 test files** across `tests/` (87 top-level) and `tests/reasoning/` (6 files).

**Naming conventions:**
- `test_<subsystem>.py` — e.g., `test_bundle.py`, `test_gateway_server.py`
- `test_v<version>_<topic>.py` — version-specific regressions, e.g., `test_v125_fixes.py`
- `test_crit<N>_<topic>.py` — critical security tests, e.g., `test_crit02_constitution_sig.py`
- `test_sec<N>_<topic>.py` — security category tests

**86 of 87 top-level files use class-based organization** (`class TestFeature` with `def test_specific_case`).

### Test Fixtures (`tests/conftest.py`)

Root conftest sets `SANNA_CONSTITUTION_PUBLIC_KEY` env var pointing to pre-built test key in `tests/.test_keys/`.

**71 total @pytest.fixture declarations** across 31 test files. No subdirectory conftest files.

Common fixture patterns:
- **Keypair fixtures** — `generate_keypair(tmp_path / "keys")`
- **Signed constitution fixtures** — load → sign → save → return path
- **Database fixtures** — `ReceiptStore(tmp_path / "test.db")`; `yield s; s.close()`
- **Cleanup fixtures** — `autouse=True` calling `clear_evaluators()` to prevent registry leaks
- **Mock server scripts** — embedded Python scripts for gateway MCP client tests

### Test Data

| Directory | Contents |
|-----------|----------|
| `tests/vectors/` | 3 JSON vectors (canonicalization, constitution_signature, receipt_signature) + README |
| `tests/constitutions/` | 10 test constitution YAML files (all_halt, all_warn, with_authority, etc.) |
| `tests/.test_keys/` | Pre-generated Ed25519 keypair (deterministic across runs) |
| `golden/receipts/` | 24 golden receipt JSON files covering all check outcomes |

### Coverage by Subsystem

| Subsystem | Test Files | Approx. Tests |
|-----------|-----------|---------------|
| Gateway (server, enforcement, escalation, config, hardening, migration) | 15 | 350+ |
| Constitution (parsing, signing, approval, diffing, identity, lifecycle) | 12 | 280+ |
| Receipt & Verification (golden, vectors, schema, fingerprint, triad) | 8 | 200+ |
| Security & Hardening (SSRF, redaction, webhooks, authority, versions) | 15 | 300+ |
| Middleware & Enforcement (decorator, checks, authority) | 7 | 180+ |
| Reasoning (deterministic checks, LLM coherence, pipeline, prompt security) | 6 | 110 |
| Evaluators (registry, LLM-as-Judge) | 4 | 120+ |
| Storage & Drift (SQLite, analytics, exports) | 4 | 100+ |
| Evidence Bundles (creation, verification, approval, key independence) | 3 | 80+ |
| CLI & Examples (interactive init, demos) | 4 | 50+ |
| Utilities (safe I/O, OTel, trust, extensions) | 7 | 100+ |

### Test Infrastructure

- `pytest.importorskip("mcp")` — guards MCP/gateway tests when extra not installed
- `pytest.importorskip("opentelemetry.sdk")` — guards OTel tests
- `pytest.importorskip("httpx")` — guards gateway HTTP tests
- `@pytest.mark.asyncio` — async test support (reasoning module)
- `tests/generate_vectors.py` — deterministic vector generator (fixed seed `0x01 * 32`)
- `generate_golden.py` — golden receipt generator at project root

### pytest Configuration (`pyproject.toml`)

```ini
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

---

## 7. Integration Points

### External Systems

| System | Integration | Module | Dependency |
|--------|------------|--------|------------|
| MCP protocol | stdio transport (server + client) | `mcp/server.py`, `gateway/server.py`, `gateway/mcp_client.py` | `mcp>=1.0` (optional) |
| Anthropic API | LLM-as-Judge evaluators | `evaluators/llm.py`, `reasoning/llm_client.py` | stdlib `urllib` or `httpx` |
| OpenAI API | Cross-provider reasoning judge | `reasoning/llm_client.py` | `httpx` (optional) |
| OpenTelemetry | Receipt → OTel span bridge | `exporters/otel_exporter.py` | `opentelemetry-api/sdk>=1.20.0` (optional) |
| Claude Desktop | MCP client config integration | `gateway/migrate.py` | File system access |
| Downstream MCP servers | Notion, GitHub, filesystem, etc. | `gateway/mcp_client.py` | `mcp` (child process spawning) |

### Adapter Architecture

There is no formal plugin/adapter interface. Integration patterns:

1. **Custom evaluators** — decorator-based registration via `@register_invariant_evaluator(invariant_id)`. Evaluator functions receive `(context, output, constitution)` and return `CheckResult`. Exceptions produce `ERRORED` status.

2. **Escalation callbacks** — `register_escalation_callback(name, handler)`. Callbacks receive `(event_details, timestamp)`.

3. **OTel exporter** — `SannaOTelExporter` wraps a delegate `SpanExporter` and filters for `sanna.receipt.id` attribute. `receipt_to_span()` creates spans from receipt metadata.

4. **Gateway downstreams** — configured via YAML `downstream:` entries. Any MCP-compatible server can be proxied.

Note: The Langfuse adapter was removed in v0.12.4. Context extraction logic was folded into `extract_trace_data()` in `receipt.py`.

---

## 8. Configuration & Environment

### Environment Variables

| Variable | Default | Module | Purpose |
|----------|---------|--------|---------|
| `SANNA_CONSTITUTION_PUBLIC_KEY` | (none) | `middleware.py`, `mcp/server.py`, `gateway/server.py` | Public key for verifying constitution signature |
| `SANNA_JUDGE_PROVIDER` | auto-detect | `reasoning/judge_factory.py` | LLM provider: "anthropic" or "openai" |
| `SANNA_LLM_MODEL` | provider default | `reasoning/llm_client.py` | Model name for LLM coherence evaluation |
| `ANTHROPIC_API_KEY` | (none) | `evaluators/llm.py`, `reasoning/judge_factory.py` | Anthropic API key |
| `OPENAI_API_KEY` | (none) | `reasoning/judge_factory.py` | OpenAI API key |
| `SANNA_GATEWAY_SECRET` | (none) | `gateway/server.py` | HMAC-SHA256 secret for approval tokens (hex) |
| `SANNA_INSECURE_FILE_TOKENS` | `"0"` | `gateway/config.py` | Set `"1"` for file-based token delivery |
| `SANNA_ALLOW_INSECURE_WEBHOOK` | `"0"` | `gateway/config.py` | Set `"1"` for HTTP webhooks to localhost |
| `SANNA_ALLOW_TEMP_DB` | `"0"` | `store.py` | Set `"1"` for temporary in-memory SQLite |
| `SANNA_SKIP_DB_OWNERSHIP_CHECK` | `"0"` | `store.py` | Set `"1"` to skip SQLite ownership check |
| `SANNA_MAX_STORED_PAYLOAD_BYTES` | `65536` | `gateway/receipt_v2.py` | Max bytes for receipt payloads |

### Configuration Files

| File | Format | Purpose |
|------|--------|---------|
| `constitution.yaml` | YAML | Agent governance policy (see §4.2) |
| `gateway.yaml` | YAML | Gateway proxy configuration (see §4.4) |
| `*.key` / `*.pub` | PEM | Ed25519 private/public keys |
| `*.meta.json` | JSON | Key metadata sidecar (key_id, label, created_at) |
| `receipts.db` | SQLite | Receipt persistence database |
| `pending_tokens.json` | JSON | Escalation token delivery file |

### Override Precedence

**Gateway policy cascade:**
1. Per-tool override (exact match on unprefixed name from config `tools:` map)
2. Server `default_policy` on downstream entry
3. Constitution authority boundary matching (`evaluate_authority()`)

**Constitution signing requirement:**
1. `require_constitution_sig` in gateway config (default: `true`)
2. `require_constitution_sig` parameter on `sanna_observe()` decorator (default: `true`)
3. `SANNA_CONSTITUTION_PUBLIC_KEY` env var for runtime verification

### Package Dependencies

**Base** (`pip install sanna`):
- `jsonschema>=4.17`
- `pyyaml>=6.0`
- `cryptography>=41.0`
- `filelock>=3.0`

**Optional extras:**
- `sanna[mcp]` → `mcp>=1.0`
- `sanna[otel]` → `opentelemetry-api>=1.20.0`, `opentelemetry-sdk>=1.20.0`
- `sanna[dev]` → `pytest>=7.0`, `jsonschema>=4.17`, `pyyaml>=6.0`

---

*Generated 2026-02-19 from sanna v0.13.4 source.*
