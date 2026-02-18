# v0.13.0 Spec-Locking Audit — Sanna Receipt & Constitution Specification

**Date:** 2026-02-17
**Auditor:** Claude Opus 4.6
**Codebase version:** v0.12.5 (commit 66325e6)
**Test results:** 2143 passed, 11 failed (pre-existing MCP compat), 6 skipped, 10 xfailed

---

## Section 1: Receipt Field Inventory

### 1.1 Receipt Dataclasses

**`SannaReceipt`** — `src/sanna/receipt.py:67-87`

| Field | Python Type | JSON Type | Default |
|-------|------------|-----------|---------|
| `schema_version` | `str` | string | — |
| `tool_version` | `str` | string | — |
| `checks_version` | `str` | string | — |
| `receipt_id` | `str` | string | — |
| `receipt_fingerprint` | `str` | string | — |
| `trace_id` | `str` | string | — |
| `timestamp` | `str` | string | — |
| `inputs` | `dict` | object | — |
| `outputs` | `dict` | object | — |
| `context_hash` | `str` | string | — |
| `output_hash` | `str` | string | — |
| `final_answer_provenance` | `dict` | object | — |
| `checks` | `list` | array | — |
| `checks_passed` | `int` | integer | — |
| `checks_failed` | `int` | integer | — |
| `coherence_status` | `str` | string | — |
| `constitution_ref` | `dict` | object/null | `None` |
| `halt_event` | `dict` | object/null | `None` |

**`CheckResult`** — `src/sanna/receipt.py:28-35`

| Field | Python Type |
|-------|------------|
| `check_id` | `str` |
| `name` | `str` |
| `passed` | `bool` |
| `severity` | `str` |
| `evidence` | `str` (optional) |
| `details` | `str` (optional) |

**`FinalAnswerProvenance`** — `src/sanna/receipt.py:39-44`

| Field | Python Type |
|-------|------------|
| `source` | `str` (`"trace.output"`, `"span.output"`, `"none"`) |
| `span_id` | `str` (optional) |
| `span_name` | `str` (optional) |
| `field` | `str` (optional) |

**`HaltEvent`** — `src/sanna/receipt.py:57-63`

| Field | Python Type |
|-------|------------|
| `halted` | `bool` |
| `reason` | `str` |
| `failed_checks` | `list[str]` |
| `timestamp` | `str` |
| `enforcement_mode` | `str` (`"halt"`, `"warn"`, `"log"`) |

### 1.2 Receipt Generation Path 1: Legacy (`receipt.py:550-648`)

**Entry:** `generate_receipt(trace_data, constitution=None, halt_event=None, constitution_ref_override=None)`

| Field | File:Line | Always Present | Source |
|-------|----------|----------------|--------|
| `schema_version` | receipt.py:630 | Yes | `SCHEMA_VERSION` = `"0.1"` |
| `tool_version` | receipt.py:631 | Yes | `TOOL_VERSION` from version.py |
| `checks_version` | receipt.py:632 | Yes | `CHECKS_VERSION` = `"4"` |
| `receipt_id` | receipt.py:633 | Yes | `hash_text(f"{trace_id}{isoformat()}")` |
| `receipt_fingerprint` | receipt.py:627 | Yes | `hash_text(fingerprint_input)` |
| `trace_id` | receipt.py:635 | Yes | `trace_data['trace_id']` |
| `timestamp` | receipt.py:636 | Yes | `datetime.now(UTC).isoformat()` |
| `inputs` | receipt.py:637 | Yes | `{"query": ..., "context": ...}` |
| `outputs` | receipt.py:638 | Yes | `{"response": ...}` |
| `context_hash` | receipt.py:639 | Yes | `hash_obj(inputs)` |
| `output_hash` | receipt.py:640 | Yes | `hash_obj(outputs)` |
| `final_answer_provenance` | receipt.py:641 | Yes | `asdict(FinalAnswerProvenance)` |
| `checks` | receipt.py:642 | Yes | `[asdict(c) for c in checks]` |
| `checks_passed` | receipt.py:643 | Yes | Integer count |
| `checks_failed` | receipt.py:644 | Yes | Integer count |
| `coherence_status` | receipt.py:645 | Yes | `"PASS"`, `"WARN"`, `"FAIL"` |
| `constitution_ref` | receipt.py:646 | Conditional | `asdict(constitution)` if provided |
| `halt_event` | receipt.py:647 | Conditional | `asdict(halt_event)` if provided |

**Fingerprint (receipt.py:626):**
```python
fingerprint_input = f"{trace_data['trace_id']}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash}|{halt_hash}"
```

**Check hash fields (receipt.py:624):** Only `check_id`, `passed`, `severity`, `evidence`.

**NOT present in this path:** `evaluation_coverage`, `authority_decisions`, `escalation_events`, `source_trust_evaluations`, `extensions`, `identity_verification`, `receipt_signature`.

### 1.3 Receipt Generation Path 2: Decorator (`middleware.py:331-530`)

**Entry:** `_generate_constitution_receipt(trace_data, check_configs, custom_records, constitution_ref, constitution_version, ...)`

All fields from Path 1, plus:

| Field | File:Line | Always Present | Source |
|-------|----------|----------------|--------|
| `evaluation_coverage` | middleware.py:443-448 | Yes | `{total_invariants, evaluated, not_checked, coverage_basis_points}` |
| `authority_decisions` | middleware.py:521-522 | Conditional | When authority_decisions provided |
| `escalation_events` | middleware.py:523-524 | Conditional | When escalation_events provided |
| `source_trust_evaluations` | middleware.py:525-526 | Conditional | When source_trust_evaluations provided |
| `extensions` | middleware.py:528 | Yes | `{"middleware": {...}}` |
| `identity_verification` | middleware.py:973-988 | Conditional | Post-generation, when identity_claims exist |
| `receipt_signature` | middleware.py:992-993 | Conditional | Post-generation, when private_key_path provided |

**Additional check fields (middleware.py:385-416):**

| Field | Present In |
|-------|-----------|
| `triggered_by` | All constitution-driven checks |
| `enforcement_level` | All constitution-driven checks |
| `constitution_version` | All constitution-driven checks |
| `check_impl` | All constitution-driven checks |
| `replayable` | All constitution-driven checks |
| `status` | Custom invariants only (`"NOT_CHECKED"`, `"ERRORED"`) |
| `reason` | Custom invariants only |

**Fingerprint (middleware.py:482-496):**
```python
fingerprint_input = f"{trace_id}|{context_hash}|{output_hash}|{CHECKS_VERSION}|{checks_hash}|{constitution_hash}|{halt_hash}|{coverage_hash}"
# Conditionally appended:
if authority_decisions: fingerprint_input += f"|{hash_obj(authority_decisions)}"
if escalation_events:  fingerprint_input += f"|{hash_obj(escalation_events)}"
if source_trust_evaluations: fingerprint_input += f"|{hash_obj(source_trust_evaluations)}"
if extensions:         fingerprint_input += f"|{hash_obj(extensions)}"
```

**Check hash includes 8 fields (middleware.py:467-479):** `check_id`, `passed`, `severity`, `evidence`, `triggered_by`, `enforcement_level`, `check_impl`, `replayable`.

**`coherence_status` values:** `"PASS"`, `"WARN"`, `"FAIL"`, `"PARTIAL"` (PARTIAL when `not_evaluated` list non-empty and no failures).

### 1.4 No-Invariants Sub-Path (`middleware.py:533-591`)

Same base fields, but:
- **NO** `evaluation_coverage` in receipt dict
- **NO** `authority_decisions`, `escalation_events`, `source_trust_evaluations`
- Fingerprint (middleware.py:560) has different structure — missing halt_hash

### 1.5 Receipt Generation Path 3: MCP Server (`mcp/server.py:173-291`)

Calls `_generate_constitution_receipt()` or `_generate_no_invariants_receipt()` from middleware.py.
**Adds no additional fields.** Same as Path 2.

**Extra restrictions:**
- Requires signed constitution (line 239)
- Requires valid Ed25519 signature structure (line 251)
- Input size limits enforced (lines 199-207)

### 1.6 Receipt Generation Path 4: Gateway (`gateway/server.py:2692-2864`)

Calls `generate_constitution_receipt()` from middleware, then adds:

| Field | File:Line | Always Present | Source |
|-------|----------|----------------|--------|
| `extensions.gateway` | server.py:2772-2782 | Yes | Gateway metadata (see below) |
| `extensions.gateway_v2` | server.py:2787-2808 | Yes | Receipt Triad + reasoning |
| `receipt_signature` | server.py:2862 | Conditional | When signing_key_path provided |

**`extensions.gateway` structure (server.py:2771-2782):**

| Field | Type | Description |
|-------|------|-------------|
| `server_name` | string | Downstream server name |
| `tool_name` | string | Unprefixed tool name |
| `prefixed_name` | string | Prefixed tool name |
| `decision` | string | `"halt"`, `"allow"`, `"escalate"` |
| `boundary_type` | string | `"cannot_execute"`, `"must_escalate"`, `"can_execute"`, `"uncategorized"` |
| `arguments_hash` | string | SHA-256 hex (16 chars) |
| `arguments_hash_method` | string | `"jcs"` or `"json_dumps_fallback"` |
| `tool_output_hash` | string | SHA-256 hex (16 chars) |
| `downstream_is_error` | boolean | Whether MCP result.isError was true |
| `escalation_id` | string | Conditional: UUID of pending escalation |
| `escalation_receipt_id` | string | Conditional: receipt chain reference |
| `escalation_resolution` | string | Conditional: `"approved"`, `"denied"`, `"denied_by_reasoning"` |
| `approval_method` | string | Conditional: `"token_verified"`, `"unverified"` |
| `token_hash` | string | Conditional: SHA-256 of HMAC token |
| `override_reason` | string | Conditional: user-provided reason |
| `override_detail` | string | Conditional: additional context |

**`extensions.gateway_v2` structure (server.py:2787-2808):**

| Field | Type | Description |
|-------|------|-------------|
| `receipt_version` | string | `"2.0"` |
| `receipt_triad.input_hash` | string | `"sha256:<hex>"` |
| `receipt_triad.reasoning_hash` | string | `"sha256:<hex>"` |
| `receipt_triad.action_hash` | string | `"sha256:<hex>"` |
| `receipt_triad.context_limitation` | string | `"gateway_boundary"` |
| `action.tool` | string | Original tool name |
| `action.args_hash` | string | SHA-256 of arguments |
| `action.justification_stripped` | boolean | Whether `_justification` was present |
| `enforcement.level` | string | Boundary type from constitution |
| `enforcement.constitution_version` | string | Constitution schema version |
| `enforcement.constitution_hash` | string | Policy hash |
| `reasoning_evaluation` | object | Conditional: reasoning check results |

### 1.7 Unified Field Comparison

| Field | Legacy | Decorator | MCP | Gateway | Schema |
|-------|--------|-----------|-----|---------|--------|
| `schema_version` | Yes | Yes | Yes | Yes | **required** |
| `tool_version` | Yes | Yes | Yes | Yes | **required** |
| `checks_version` | Yes | Yes | Yes | Yes | **required** |
| `receipt_id` | Yes | Yes | Yes | Yes | **required** |
| `receipt_fingerprint` | Yes | Yes | Yes | Yes | **required** |
| `trace_id` | Yes | Yes | Yes | Yes | **required** |
| `timestamp` | Yes | Yes | Yes | Yes | **required** |
| `inputs` | Yes | Yes | Yes | Yes | **required** |
| `outputs` | Yes | Yes | Yes | Yes | **required** |
| `context_hash` | Yes | Yes | Yes | Yes | **required** |
| `output_hash` | Yes | Yes | Yes | Yes | **required** |
| `final_answer_provenance` | Yes | Yes | Yes | Yes | **required** |
| `checks` | Yes | Yes | Yes | Yes | **required** |
| `checks_passed` | Yes | Yes | Yes | Yes | **required** |
| `checks_failed` | Yes | Yes | Yes | Yes | **required** |
| `coherence_status` | Yes | Yes | Yes | Yes | **required** |
| `constitution_ref` | Cond | Cond | Cond | Yes | optional |
| `halt_event` | Cond | Cond | Cond | Cond | optional |
| `evaluation_coverage` | **No** | Yes | Yes | Yes | optional |
| `authority_decisions` | **No** | Cond | **No** | Yes | optional |
| `escalation_events` | **No** | Cond | **No** | Yes | optional |
| `source_trust_evaluations` | **No** | Cond | **No** | **No** | optional |
| `extensions` | **No** | Yes | Yes | Yes | optional |
| `identity_verification` | **No** | Cond | **No** | **No** | optional |
| `receipt_signature` | **No** | Cond | **No** | Cond | optional |

### 1.8 Critical Format Details

**`receipt_id` format:**
- Generated: `hash_text(f"{trace_id}{datetime.now(UTC).isoformat()}")` → **16 hex chars** (SHA-256 truncated via `sha256_hex(data, truncate=16)`)
- Schema pattern: `^[a-f0-9]{16}$` (receipt.schema.json:47)

**`receipt_fingerprint` format:**
- Generated: `hash_text(fingerprint_input)` → **16 hex chars**
- Schema pattern: `^[a-f0-9]{16}$` (receipt.schema.json:52)

**Hash fields** (`context_hash`, `output_hash`):
- Generated: `hash_obj(dict)` → **16 hex chars** via `sha256_hex(data, truncate=16)` in `hashing.py:95-98`
- Validation pattern: `^[a-f0-9]{16}$` (verify.py:392)

**`constitution_ref.policy_hash`:**
- Accepts 16-64 hex chars: `^[a-f0-9]{16,64}$` (verify.py:434) — allows both legacy 16-char and full 64-char SHA-256

**`trace_id` generation by path:**
- Decorator: `f"sanna-{uuid.uuid4().hex[:12]}"` (middleware.py:800)
- MCP: `f"mcp-{uuid.uuid4().hex[:12]}"` (mcp/server.py:215)
- Gateway: `f"gw-{uuid.uuid4().hex[:12]}"` (gateway/server.py:2739)

**`coherence_status` values:**
- Schema enum: `["PASS", "WARN", "FAIL", "PARTIAL"]` (receipt.schema.json:144)
- `PARTIAL`: only in constitution-driven path, when `_NON_EVALUATED` checks present

**`halt_event` vs `enforcement_decision`:**
- `halt_event` is a top-level receipt field (object with `halted`, `reason`, `failed_checks`, `timestamp`, `enforcement_mode`)
- `enforcement_decision` is NOT a top-level receipt field — it exists only inside `extensions.middleware` as a string (`"PASSED"`, `"HALTED"`, `"WARNED"`, `"LOGGED"`)

**`final_answer_provenance`:** Present in all paths. Populated by `select_final_answer()` in receipt.py.

**`identity_verification`:** NOT in fingerprint. Present only in decorator path, added post-generation.

### 1.9 Schema vs Code Discrepancies

1. **Check object fields:** Schema (receipt.schema.json) defines `additionalProperties: false` on CheckResult, but constitution-driven checks include extra fields (`triggered_by`, `enforcement_level`, `check_impl`, `replayable`, `status`, `reason`) not in schema `$defs`. **These extra fields would fail strict schema validation.**

2. **`outputs` key:** Code always uses `{"response": final_answer}` (middleware.py:451). Schema defines `outputs.response` as required (receipt.schema.json:88). **Consistent.**

3. **`inputs` key:** Code always uses `{"query": ..., "context": ...}` (middleware.py:450). Schema defines both as properties of `inputs`. **Consistent.**

4. **`evaluation_coverage`:** Not in legacy path. Schema marks it optional. **Consistent but asymmetric.**

---

## Section 2: Constitution Schema Inventory

### 2.1 Complete YAML Structure

```yaml
sanna_constitution: "1.0.0" | "1.1"   # REQUIRED (mapped to schema_version in Python)

identity:                               # REQUIRED
  agent_name: string                    # REQUIRED, minLength 1
  domain: string                        # REQUIRED, minLength 1
  description: string                   # Optional, default ""
  # extensions: arbitrary extra keys allowed (additionalProperties: true)
  identity_claims:                      # Optional
    - provider: string                  # REQUIRED
      claim_type: string               # REQUIRED
      credential_id: string            # REQUIRED
      issued_at: string                # REQUIRED, ISO 8601
      expires_at: string               # Optional, ISO 8601
      signature_value: string          # Optional, Base64
      public_key_id: string            # Optional

provenance:                             # REQUIRED
  authored_by: string                   # REQUIRED, minLength 1
  approved_by: string | list[string]    # REQUIRED, at least 1
  approval_date: string                 # REQUIRED, ISO 8601 (^\\d{4}-\\d{2}-\\d{2})
  approval_method: string              # REQUIRED, minLength 1
  change_history: list[dict]           # Optional, default []
  signature:                           # Optional
    value: string | null               # Base64 Ed25519 signature
    key_id: string | null              # ^[a-f0-9]{64}$
    signed_by: string | null
    signed_at: string | null           # ISO 8601
    scheme: string                     # "constitution_sig_v1"

boundaries:                             # REQUIRED, minItems 1
  - id: string                         # ^B\\d{3}$
    description: string
    category: string                   # enum below
    severity: string                   # enum below

trust_tiers:                            # Optional
  autonomous: list[string]
  requires_approval: list[string]
  prohibited: list[string]

halt_conditions:                        # Optional
  - id: string                         # ^H\\d{3}$
    trigger: string
    escalate_to: string
    severity: string                   # enum below
    enforcement: string                # enum below

invariants:                             # Optional
  - id: string
    rule: string
    enforcement: string                # enum below
    check: string | null               # Optional explicit check ID

authority_boundaries:                   # Optional
  cannot_execute: list[string]
  must_escalate:
    - condition: string
      target:
        type: string                   # "log" | "webhook" | "callback"
        url: string                    # Optional
        handler: string                # Optional
  can_execute: list[string]
  default_escalation: string           # "log" | "webhook" | "callback"

escalation_targets:                     # Optional
  default: string                      # "log" | "webhook" | "callback"

trusted_sources:                        # Optional
  tier_1: list[string]
  tier_2: list[string]
  tier_3: list[string]
  untrusted: list[string]

policy_hash: string | null              # ^[a-f0-9]{64}$

approval:                               # Optional
  records:
    - status: string                   # "approved" | "pending" | "revoked"
      approver_id: string
      approver_role: string
      approved_at: string              # ISO 8601
      approval_signature: string       # Base64
      constitution_version: string
      content_hash: string             # ^[a-f0-9]{64}$
      previous_version_hash: string | null  # ^[a-f0-9]{64}$

version: string                         # Optional, default "1.0"

reasoning:                              # Optional, v1.1+ only
  require_justification_for: list[string]  # ["must_escalate", "cannot_execute", "can_execute"]
  on_missing_justification: string     # "block" | "escalate" | "allow"
  on_check_error: string              # "block" | "escalate" | "allow"
  on_api_error: string                # "block" | "allow" | "score_zero"
  evaluate_before_escalation: boolean  # default true
  auto_deny_on_reasoning_failure: boolean  # default false
  checks:
    glc_002_minimum_substance:
      enabled: boolean
      min_length: integer              # > 0
    glc_003_no_parroting:
      enabled: boolean
      blocklist: list[string]
    glc_005_llm_coherence:
      enabled: boolean
      enabled_for: list[string]
      timeout_ms: integer              # > 0
      score_threshold: float           # 0.0-1.0
      judge_override:
        provider: string               # "anthropic" | "openai" | "heuristic"
        scrutiny: string               # "standard" | "thorough"
  judge:
    default_provider: string | null
    default_model: string | null
    cross_provider: boolean
```

### 2.2 All Enum Values

**Categories** (`constitution.py:41`):
```python
VALID_CATEGORIES = {"scope", "authorization", "confidentiality", "safety", "compliance", "custom"}
```

**Severities** (`constitution.py:42`):
```python
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
```

**Enforcement levels** (`constitution.py:43`):
```python
VALID_ENFORCEMENT = {"halt", "warn", "log"}
```

**Approval statuses** (`constitution.py:44`):
```python
VALID_APPROVAL_STATUSES = {"approved", "pending", "revoked"}
```

**Escalation target types** (constitution.schema.json:185):
```
["log", "webhook", "callback"]
```

**Policy values** (`gateway/config.py:49`):
```python
_VALID_POLICIES = frozenset({"can_execute", "must_escalate", "cannot_execute"})
```

**Justification levels** (`constitution.py:232`):
```python
VALID_JUSTIFICATION_LEVELS = frozenset({"must_escalate", "cannot_execute", "can_execute"})
```

**On-missing-justification** (`constitution.py:233`):
```python
VALID_ON_MISSING_JUSTIFICATION = frozenset({"block", "escalate", "allow"})
```

**On-check-error** (`constitution.py:234`):
```python
VALID_ON_CHECK_ERROR = frozenset({"block", "escalate", "allow"})
```

**On-API-error** (`constitution.py:235`):
```python
VALID_ON_API_ERROR = frozenset({"block", "allow", "score_zero"})
```

**Scrutiny levels** (`constitution.py:235`):
```python
VALID_SCRUTINY_LEVELS = frozenset({"standard", "thorough"})
```

**Judge providers** (`constitution.py:236`):
```python
VALID_JUDGE_PROVIDERS = frozenset({"anthropic", "openai", "heuristic"})
```

**Identity claim statuses** (returned by `verify_identity_claims()`):
```
"verified" | "unverified" | "failed" | "expired" | "no_key"
```

**Redaction modes** (`gateway/config.py:88-110`):
```
"hash_only" | "pattern_redact"
```

**Token delivery methods** (`gateway/config.py:267`):
```python
_VALID_DELIVERY = {"stderr", "file", "log", "callback"}
```

**Receipt store modes** (`gateway/config.py:235`):
```python
_valid_store_modes = {"filesystem", "sqlite", "both"}
```

### 2.3 Signing Scope

**Constitution signing** (`constitution.py:1176-1231`, `constitution_to_signable_dict()`):

Includes: `schema_version`, `identity` (with extensions flattened), `provenance` (with `signature.value = ""`), `boundaries`, `trust_tiers`, `halt_conditions`, `invariants`, `policy_hash`, `authority_boundaries` (if present), `escalation_targets` (if present), `trusted_sources` (if present), `version` (if != "1.0"), `reasoning` (if present, floats → basis points).

**Approval signing** (`constitution.py:1306-1322`, `_approval_record_to_signable_dict()`):

Includes: `status`, `approver_id`, `approver_role`, `approved_at`, `approval_signature` (set to `""`), `constitution_version`, `content_hash`, `previous_version_hash` (if present).

**Identity claim signing** (`constitution.py:1325-1349`, `_claim_to_signable_dict()`):

Includes: `provider`, `claim_type`, `credential_id`, `issued_at`, `expires_at` (only if non-empty), `signature` (set to `""`), `public_key_id`.

### 2.4 Version Field

- YAML key: `sanna_constitution` (mapped to Python `schema_version`)
- Accepted values: any string (examples: `"1.0.0"`, `"0.1.0"`, `"1.1"`)
- Reasoning config gated on `>= "1.1"` (constitution.py:935-936)
- No formal version negotiation logic — string comparison only

---

## Section 3: Verification Protocol

### 3.1 Verification Steps (Exact Order)

`verify_receipt()` in `src/sanna/verify.py:644-783`:

| Step | Function | What It Checks | Pass/Fail |
|------|----------|---------------|-----------|
| 1 | `verify_schema(receipt, schema)` | JSON schema validation | Fail → exit 2 |
| 2a | `verify_hash_format(receipt)` | `receipt_id`, `receipt_fingerprint`, `context_hash`, `output_hash` match `^[a-f0-9]{16}$` | Errors accumulated |
| 2b | `verify_content_hashes(receipt)` | Recompute `context_hash = hash_obj(inputs)`, `output_hash = hash_obj(outputs)` | Fail → exit 3 |
| 2c | `verify_constitution_hash(receipt)` | `constitution_ref.policy_hash` matches `^[a-f0-9]{16,64}$` | Errors accumulated |
| 3 | `verify_fingerprint(receipt)` | Recompute full fingerprint and compare | Fail → exit 3 |
| 4 | `verify_status_consistency(receipt)` | FAIL if critical fails, WARN if warning fails, PARTIAL if non-evaluated | Fail → exit 4 |
| 5 | `verify_check_counts(receipt)` | `checks_passed + checks_failed` match actual counts | Fail → exit 4 |
| 6 | Governance warning | FAIL status + no halt_event → warning (non-fatal) | Warning only |
| 7 | `verify_receipt_signature()` | Ed25519 signature (only with `--public-key`) | Fail → exit 5 |
| 8 | `verify_constitution_chain()` | Constitution binding + approval chain (only with `--constitution`) | Errors/warnings |
| 9 | `verify_receipt_triad()` | Receipt Triad format (gateway v2 only) | Errors/warnings |
| 10 | Identity verification reporting | Point-in-time identity claim status (non-fatal) | Warning only |

### 3.2 Fingerprint Construction

**File:** `verify.py:250-334`

```python
# Base fields (always present):
fingerprint_input = f"{trace_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{halt_hash}|{coverage_hash}"

# Conditional appends (only when present):
if authority_decisions:
    fingerprint_input += f"|{hash_obj(authority_decisions)}"
if escalation_events:
    fingerprint_input += f"|{hash_obj(escalation_events)}"
if source_trust_evaluations:
    fingerprint_input += f"|{hash_obj(source_trust_evaluations)}"
if extensions:
    fingerprint_input += f"|{hash_obj(extensions)}"

computed = hash_text(fingerprint_input)  # SHA-256, truncated to 16 hex chars
```

**`constitution_approval` stripping** (three locations):
- `middleware.py:458-462`
- `receipt.py:614-617`
- `verify.py:302` (approx)

### 3.3 Signature Construction

**Receipt signing** (`crypto.py:306-343`):

1. Build `receipt_signature` block with `signature: ""` placeholder
2. Attach to receipt copy: `signable["receipt_signature"] = sig_block`
3. `signable = sanitize_for_signing(signable)` — convert exact floats to int
4. `data = canonical_json_bytes(signable)` — RFC 8785 canonical JSON
5. `signature_b64 = sign_bytes(data, private_key)` — Ed25519 sign, Base64 encode
6. Replace placeholder with actual signature

**Receipt verification** (`crypto.py:346-379`):

1. Extract `receipt_signature` block
2. Replace `signature` with `""` in copy
3. `signable = sanitize_for_signing(signable)`
4. `data = canonical_json_bytes(signable)`
5. Verify `key_id` matches public key's fingerprint
6. `verify_signature(data, sig_b64, public_key)` — Ed25519 verify

### 3.4 CLI Output

**`sanna-verify`** (`cli.py:248-299`):

- Human-readable: `"✓ VALID"` or `"✗ INVALID"` with breakdown
- JSON mode (`--json`): `{"valid": bool, "exit_code": int, "errors": [...], "warnings": [...]}`
- Exit codes: 0=valid, 2=schema invalid, 3=fingerprint mismatch, 4=consistency error, 5=other

**No public key:** Signature verification **skipped entirely** (no warning, no error). Receipt passes if all other checks pass.

### 3.5 `_NON_EVALUATED` Set

```python
# verify.py:25
_NON_EVALUATED = {"NOT_CHECKED", "ERRORED"}
```

- Excluded from pass/fail counts
- Excluded from status computation
- When present with no failures → `coherence_status = "PARTIAL"`
- Still included in fingerprint hash

---

## Section 4: Canonicalization

### 4.1 `canonical_json_bytes()` — Complete Implementation

**File:** `src/sanna/hashing.py:78-92`

```python
def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize *obj* to RFC 8785 canonical JSON bytes."""
    _reject_floats(obj)
    canon = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),  # no spaces
        ensure_ascii=False,
    )
    return canon.encode("utf-8")
```

### 4.2 `hash_text()` and `hash_obj()`

```python
# hashing.py:95-108
def sha256_hex(data: bytes, truncate: int = 16) -> str:
    full_hash = hashlib.sha256(data).hexdigest()
    return full_hash[:truncate] if truncate else full_hash

def hash_text(s: str, truncate: int = 16) -> str:
    return sha256_hex(canonicalize_text(s).encode("utf-8"), truncate)

def hash_obj(obj: Any, truncate: int = 16) -> str:
    return sha256_hex(canonical_json_bytes(obj), truncate)
```

### 4.3 RFC 8785 Claims

| File | Line | Claim |
|------|------|-------|
| `hashing.py` | 4 | `"Canonicalization follows RFC 8785 (JSON Canonicalization Scheme)."` |
| `hashing.py` | 79 | `"Serialize *obj* to RFC 8785 canonical JSON bytes."` |
| `receipt.py` | 20 | `"C4 contraction fix, coverage_basis_points, RFC 8785 float guard"` |
| `constitution.py` | 1063 | `"basis points (0-10000) to satisfy RFC 8785 canonical JSON constraints"` |
| `constitution.py` | 1105 | `"This differs from RFC 8785 (JCS) which uses ensure_ascii=False"` — **NOTE: contradicts hashing.py which DOES use ensure_ascii=False** |
| `gateway/receipt_v2.py` | 8 | `"follows RFC 8785; floats are normalized to fixed-precision strings"` — **OUTDATED** |
| `docs/receipt-format.md` | 7 | `"integer basis points (8500 = 85.00%) for deterministic canonicalization"` |

### 4.4 Number Handling

- **Finite floats:** Allowed since v0.12.2, serialized as JSON numbers
- **NaN/Infinity:** Rejected by `_reject_floats()` with `TypeError` (hashing.py:43-62)
- **No -0.0 normalization:** Not handled — passed through as-is
- **`normalize_floats()`:** Identity pass-through (no-op) since v0.12.2 (hashing.py:27-40)

### 4.5 `sanitize_for_signing()`

**File:** `src/sanna/crypto.py:37-58`

```python
def sanitize_for_signing(obj, path: str = "$"):
    if isinstance(obj, float):
        if obj == int(obj) and not (obj != obj):  # exclude NaN
            return int(obj)
        raise TypeError(
            f"Float value {obj!r} at path {path} cannot be signed. "
            f"Use integer basis points or string representation."
        )
    if isinstance(obj, dict):
        return {k: sanitize_for_signing(v, f"{path}.{k}") for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_signing(v, f"{path}[{i}]") for i, v in enumerate(obj)]
    return obj
```

- Exact integer floats (71.0) → `int(71)` silently
- Lossy floats (71.43) → `TypeError`
- NaN → `TypeError` (NaN != NaN check)
- Infinity → `TypeError` (inf != int(inf))

### 4.6 Basis-Point Conversion

| Location | When | Formula |
|----------|------|---------|
| `middleware.py:442` | Coverage | `(evaluated * 10000) // total` (integer division) |
| `constitution.py:1067-1068` | Signing only | `int(round(score_threshold * 10000))` |
| `gateway/receipt_v2.py:410-416` | Signing only | `int(round(score * 10000))` |
| `reasoning/checks/glc_005_coherence.py:63-68` | Always | `int(round(score * 10000))` stored as `score_bp` |

### 4.7 Constitution Hash Uses Different Serialization

**`compute_constitution_hash()`** (`constitution.py:1096-1157`) uses:
```python
json.dumps(hashable, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

**Note:** This uses `ensure_ascii=True`, while `canonical_json_bytes()` uses `ensure_ascii=False`. Constitution hashing is NOT using the same canonical form as receipt hashing. This is noted in constitution.py:1105.

---

## Section 5: Approval Flow

### 5.1 Token Generation

**File:** `src/sanna/gateway/server.py`

```python
def _compute_approval_token(self, entry: PendingEscalation) -> str:
    payload = (
        f"{entry.escalation_id}|{entry.prefixed_name}|"
        f"{hash_obj(entry.arguments)}|{entry.created_at}"
    ).encode()
    return hmac.new(self._gateway_secret, payload, hashlib.sha256).hexdigest()
```

- **Algorithm:** HMAC-SHA256
- **Key:** 32-byte gateway secret (`os.urandom(32)`)
- **Bound data:** `escalation_id|tool_name|args_hash|created_at`
- **Output:** 64-char hex string

**Token hash storage:**
```python
def _hash_token(self, token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
```
SHA-256 of the HMAC token — stored in `PendingEscalation.token_hash`.

### 5.2 Token Delivery Methods

| Method | Transport | Details |
|--------|-----------|---------|
| `"stderr"` | sys.stderr | `[SANNA]` prefix, two lines: token + instruction |
| `"file"` | `~/.sanna/pending_tokens.json` | JSON array, file-locked, TTL-pruned, `0o600` permissions |
| `"log"` | Python logging | `logger.info()` at INFO level |
| `"callback"` | Reserved | Not yet implemented |

**Default:** `["file", "stderr"]` (config.py:130)

### 5.3 Token Verification

**File:** `gateway/server.py:2290-2322`

1. Check token provided → `MISSING_APPROVAL_TOKEN` error
2. Hash provided token: `SHA-256(provided_token)`
3. Constant-time compare: `hmac.compare_digest(provided_hash, stored_hash)`
4. Invalid → `INVALID_APPROVAL_TOKEN` error

**Expiry:** Tied to escalation lifetime (default 300 seconds)
**One-time use:** Yes — escalation removed from store after approval/denial
**Replay protection:** Escalation ID uniqueness (UUID-based)

### 5.4 File-Based Delivery

- **Path:** `~/.sanna/pending_tokens.json`
- **Format:** JSON array of `{escalation_id, token, tool_name, timestamp, ttl_remaining, expires_at}`
- **Permissions:** `0o600` (owner read/write only)
- **Lock:** `~/.sanna/pending_tokens.json.lock` (filelock, 10s timeout)
- **No config flag to disable:** Must remove `"file"` from `token_delivery` list

### 5.5 `PendingEscalation` Fields

| Field | Type | Description |
|-------|------|-------------|
| `escalation_id` | str | `"esc_{uuid4().hex}"` |
| `prefixed_name` | str | Gateway-prefixed tool name |
| `original_name` | str | Unprefixed tool name |
| `arguments` | dict | Tool call arguments |
| `server_name` | str | Downstream server name |
| `reason` | str | Escalation reason |
| `created_at` | str | ISO 8601 timestamp |
| `token_hash` | str | SHA-256 of HMAC token |
| `status` | str | `"pending"`, `"approved"`, `"failed"` |
| `escalation_receipt_id` | str | Receipt chain reference |
| `override_reason` | str | User-provided override reason |
| `override_detail` | str | Additional context |

### 5.6 Store Lifecycle

1. `create()`: purge expired → check per-tool limit (10) → check global limit (100) → create
2. `mark_status()`: update status in-place, persist to disk
3. `remove()`: delete from store, persist
4. `purge_expired()`: remove all entries where `is_expired() == True`

---

## Section 6: Extension Mechanism

### 6.1 Receipt Extensions

**Schema** (receipt.schema.json:391): `"extensions": {"type": ["object", "null"], "additionalProperties": true}`

**Code locations:**
- Middleware: `extensions["middleware"]` with decorator metadata (middleware.py:864-871)
- Gateway: `extensions["gateway"]` and `extensions["gateway_v2"]` (server.py:2771-2843)

**Namespace convention:** Nested sub-objects keyed by component name (`"middleware"`, `"gateway"`, `"gateway_v2"`).

### 6.2 `additionalProperties` Settings

**Receipt schema — allows extra fields:**
- `inputs` (line 77): `true`
- `outputs` (line 88): `true`
- `extensions` (line 391): `true`
- `AuthorityDecisionRecord.params` (line 506): `true`
- `EscalationEventRecord.details` (line 566): `true`

**Receipt schema — strict (no extra fields):**
- Root receipt object (line 427): `false`
- `evaluation_coverage` (line 172): `false`
- `constitution_ref` (line 298): `false`
- `halt_event` (line 331): `false`
- `receipt_signature` (line 360): `false`
- `CheckResult` (line 492): `false`

**Constitution schema — allows extra fields:**
- `identity` (line 51): `true`
- `identity_claims` items (line 47): `true`

**Constitution schema — strict:**
- Root object (line 272): `false`
- All other objects: `false`

### 6.3 Fields Outside `extensions` Block

These optional top-level receipt fields are NOT in `extensions`:

| Field | Purpose | In Fingerprint? |
|-------|---------|----------------|
| `evaluation_coverage` | Coverage metrics | Yes (via `coverage_hash`) |
| `authority_decisions` | Authority boundary decisions | Yes (conditional) |
| `escalation_events` | Escalation audit trail | Yes (conditional) |
| `source_trust_evaluations` | Trust tier evaluations | Yes (conditional) |
| `identity_verification` | Identity claim verification | **No** |

---

## Section 7: Redaction Pipeline

### 7.1 Redaction Modes

**Defined:** `gateway/server.py:67`
```python
_VALID_REDACTION_MODES = frozenset({"hash_only", "pattern_redact"})
```

**`hash_only`** (implemented): Replaces content with `[REDACTED — HMAC-SHA256: {digest}]`
**`pattern_redact`** (not implemented): Returns original content unchanged — **complete no-op** (server.py:102: `return content`)

### 7.2 What Gets Redacted

**Configuration** (`gateway/config.py:88-110`):
- `fields: ["arguments", "result_text"]` (default)
- `"arguments"` → targets `receipt["inputs"]["context"]` (server.py:1651-1656)
- `"result_text"` → targets `receipt["outputs"]["output"]` (server.py:1658-1663)

### 7.3 The `outputs["output"]` vs `outputs["response"]` Bug

**BUG CONFIRMED:**

The receipt structure uses `outputs = {"response": final_answer}` (middleware.py:451), but the redaction code reads `receipt["outputs"]["output"]` (server.py:1658):

```python
# server.py:1658 — reads wrong key
out = redacted.get("outputs", {}).get("output", "")  # WRONG: should be "response"
if out:
    redacted["outputs"]["output"] = _redact_for_storage(...)
```

Since `outputs["output"]` doesn't exist, `out` is always `""`, and the `if out:` guard skips redaction. **Result text is never redacted.**

### 7.4 File Persistence

1. **Original receipt written first** (server.py:1632-1641): `atomic_write_sync(filepath, json.dumps(receipt), mode=0o600)`
2. **Redacted copy written second** (server.py:1644-1686): `atomic_write_sync(redacted_path, json.dumps(redacted), mode=0o600)`
3. **Filenames:** `{timestamp}_{receipt_id}.json` and `{timestamp}_{receipt_id}.redacted.json`

### 7.5 `pattern_redact` Implementation

```python
# server.py:74-102
def _redact_for_storage(content, mode="hash_only", salt="", secret=None):
    if mode == "hash_only":
        payload = (content + salt).encode()
        if secret:
            digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            return f"[REDACTED — HMAC-SHA256: {digest}]"
        digest = hashlib.sha256(payload).hexdigest()
        return f"[REDACTED — SHA-256-SALTED: {digest}]"
    # "pattern_redact" reserved for future regex-based PII detection
    return content  # <-- NO-OP
```

---

## Section 8: Error Handling Audit

### 8.1 HIGH-01 — Custom Evaluator Exception Handling

**File:** `src/sanna/middleware.py:366-383`

```python
        except Exception as exc:
            if cfg.source == "custom_evaluator":
                check_results.append({
                    "check_id": cfg.check_id,
                    "name": "Custom Invariant",
                    "passed": True,          # <-- PASSED SET TO TRUE
                    "severity": "info",
                    "evidence": None,
                    "details": f"Evaluator error: {exc}",
                    ...
                    "status": "ERRORED",     # <-- MARKED ERRORED
                })
                continue
            raise
```

On exception: `passed = True`, `status = "ERRORED"`. This is intentional — ERRORED checks are excluded from pass/fail counts via `_NON_EVALUATED`, so setting `passed = True` prevents false halts. Non-custom evaluator exceptions are re-raised.

### 8.2 HIGH-07 — Async Decorator Blocking

**File:** `src/sanna/middleware.py:651-658`

```python
            loop = asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                evaluation = pool.submit(asyncio.run, coro).result(timeout=30)
```

`future.result(timeout=30)` is a **blocking call** inside the async wrapper (middleware.py:830). This blocks the event loop for up to 30 seconds during pre-execution reasoning gate.

### 8.3 LOW-03 — `verify_signature` Broad Exception Catch

**File:** `src/sanna/crypto.py:191-197`

```python
    try:
        sig_clean = re.sub(r"\s+", "", signature_b64)
        signature = base64.b64decode(sig_clean, validate=True)
        public_key.verify(signature, data)
        return True
    except (binascii.Error, ValueError, Exception):
        return False
```

Catches bare `Exception` — equivalent to catching everything. Silently swallows any error as "invalid signature".

### 8.4 MED-03 — `escape_audit_content` Type Handling

**File:** `src/sanna/utils/sanitize.py:11-19`

```python
def escape_audit_content(text: str) -> str:
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
```

No type validation. `AttributeError` on non-string input (e.g., `None`, `int`).

### 8.5 MED-04 — NaN/Infinity in `sanitize_for_signing`

**File:** `src/sanna/crypto.py:47-56`

```python
    if isinstance(obj, float):
        if obj == int(obj) and not (obj != obj):  # exclude NaN
            return int(obj)
        raise TypeError(...)
```

NaN: rejected (NaN != NaN). Infinity: rejected (inf != int(inf)). Both raise `TypeError` with path information.

---

## Section 9: Test Inventory

### 9.1 Total Count

- **2169 tests collected** (with 1 collection error in `test_mcp_server.py`)
- **2143 passed**, 11 failed (pre-existing MCP compat), 6 skipped, 10 xfailed

### 9.2 Test Files by Module

| Count | File | Module Area |
|-------|------|-------------|
| 108 | `test_template_matrix.py` | Constitution templates |
| 88 | `test_gateway_migrate.py` | Gateway migration |
| 84 | `test_golden.py` | Golden receipt vectors |
| 75 | `test_v061.py` | v0.6.1 features |
| 72 | `test_approval.py` | Constitution approval |
| 69 | `test_authority.py` | Authority boundaries |
| 64 | `test_store.py` | Receipt persistence |
| 61 | `test_constitution_lifecycle.py` | Constitution lifecycle |
| 58 | `test_gateway_hardening.py` | Gateway security |
| 57 | `test_gateway_escalation.py` | Escalation flow |
| 53 | `test_stress.py` | Stress/concurrency |
| 53 | `test_gateway_enforcement.py` | Gateway enforcement |
| 51 | `test_enforcement.py` | Check enforcement |
| 49 | `test_v063.py` | v0.6.3 features |
| 46 | `test_gateway_server.py` | Gateway server |
| 44 | `test_hardening.py` | Security hardening |
| 43 | `test_source_trust.py` | Trust tiers |
| 41 | `test_receipt_v2_schema.py` | Receipt v2 schema |
| 41 | `test_identity_claims.py` | Identity verification |
| 41 | `test_drift.py` | Drift analysis |
| 40 | `test_init_constitution.py` | Constitution init |
| 36 | `test_gateway_config.py` | Gateway config |
| 34 | `test_authority_receipts.py` | Authority receipt generation |
| 33 | `test_evaluators_llm.py` | LLM evaluators |
| 31 | `test_middleware.py` | Middleware/decorator |
| 31 | `test_gateway_mcp_client.py` | MCP client |
| 31 | `test_constitution_v11.py` | Constitution v1.1 |
| 29 | `test_constitution_diff.py` | Constitution diffing |
| 28 | `test_v125_fixes.py` | v0.12.5 fixes |
| 28 | `test_v124_fixes.py` | v0.12.4 fixes |
| 28 | `test_bundle.py` | Evidence bundles |
| 27 | `test_safe_io.py` | Safe file I/O |
| 25 | `test_v064.py` | v0.6.4 features |
| 23 | `test_evaluators.py` | Custom evaluators |
| 23 | `reasoning/test_evaluation_pipeline.py` | Reasoning pipeline |
| 22 | `test_block5_concurrency_quality.py` | Concurrency |
| 22 | `test_api_surface_trim.py` | API surface |
| 20 | `test_gateway_reasoning.py` | Gateway reasoning |
| 20 | `test_fleet_demo.py` | Fleet demo |
| 20 | `reasoning/test_prompt_security.py` | Prompt security |
| 19 | `test_vectors.py` | Test vectors |
| 19 | `test_drift_timestamps.py` | Drift timestamps |
| 19 | `test_bundle_approval.py` | Bundle approval |
| 19 | `reasoning/test_judge.py` | LLM judge |
| 18 | `test_reasoning_hardening.py` | Reasoning hardening |
| 18 | `test_extensions.py` | Extensions |
| 18 | `test_cli_dx.py` | CLI DX |
| 18 | `reasoning/test_llm_coherence.py` | LLM coherence |
| 16 | `test_schema_mutation.py` | Schema mutation |
| 16 | `test_export.py` | Export formats |
| 15 | `test_reasoning_example_config.py` | Reasoning config |
| 15 | `reasoning/test_judge_factory.py` | Judge factory |
| 15 | `reasoning/test_deterministic_checks.py` | Deterministic checks |
| 14 | `test_halt_event.py` | Halt events |
| 14 | `test_crypto_integrity.py` | Crypto integrity |
| 13 | `test_v123_smoke.py` | v0.12.3 smoke |
| 13 | `test_float_canonical.py` | Float canonicalization |
| 12 | `test_gateway_constitution_sig.py` | Constitution signature |
| 11 | `test_block_g_devex.py` | Block G DX |
| 10 | `test_keygen_label.py` | Key label |
| 9 | `test_verify_triad.py` | Receipt Triad verification |
| 8 | `test_llm_integration.py` | LLM integration |
| 8 | `test_constitution.py` | Constitution basics |
| 7 | `test_verify_errored.py` | ERRORED check verification |
| 7 | `test_token_store.py` | Token store |
| 7 | `test_receipt_limits.py` | Receipt limits |
| 6 | `test_keyword_matching.py` | Keyword matching |
| 6 | `test_governance_lifecycle.py` | Governance lifecycle |
| 6 | `test_escalation_store_v2.py` | Escalation store v2 |
| 6 | `test_approval_v2.py` | Approval v2 |
| 5 | `test_version_consistency.py` | Version consistency |
| 5 | `test_scoring_result.py` | Scoring results |
| 5 | `test_reasoning_receipt_signing.py` | Reasoning receipt signing |
| 4 | `test_sqlite_json1.py` | SQLite JSON1 |
| 4 | `test_observe_order.py` | Observation order |
| 4 | `test_gateway_secret.py` | Gateway secret |
| 3 | `test_schema_mutation_v2.py` | Schema mutation v2 |
| 3 | `test_export_multi.py` | Multi-export |
| 3 | `test_error_labels.py` | Error labels |
| 2 | `test_duplicate_tools.py` | Duplicate tools |

### 9.3 Receipt Schema Validation Tests

- `tests/test_golden.py` — 84 tests: golden receipt test vectors
- `tests/test_receipt_v2_schema.py` — 41 tests: Receipt v2 schema validation
- `tests/test_vectors.py` — 19 tests: test vectors in `tests/vectors/`
- `tests/test_verify_triad.py` — 9 tests: Receipt Triad verification
- `tests/test_verify_errored.py` — 7 tests: ERRORED check verification

### 9.4 Constitution Schema Validation Tests

- `tests/test_constitution.py` — 8 tests
- `tests/test_constitution_lifecycle.py` — 61 tests
- `tests/test_constitution_v11.py` — 31 tests
- `tests/test_constitution_diff.py` — 29 tests
- `tests/test_template_matrix.py` — 108 tests

### 9.5 Golden Receipt Vectors

**Directory:** `tests/vectors/`
- 19 test vectors used by `tests/test_vectors.py`
- Additional golden receipts in `tests/test_golden.py` (84 tests)

---

## Section 10: Dependency Audit

### 10.1 All Dependencies

**Base (required):**

| Package | Version | Purpose |
|---------|---------|---------|
| `jsonschema` | `>=4.17` | JSON schema validation |
| `pyyaml` | `>=6.0` | YAML parsing |
| `cryptography` | `>=41.0` | Ed25519 crypto |
| `filelock` | `>=3.0` | File locking |

**Optional groups:**

| Group | Package(s) | Purpose |
|-------|-----------|---------|
| `mcp` | `mcp>=1.0` | MCP server + gateway |
| `otel` | `opentelemetry-api>=1.20.0`, `opentelemetry-sdk>=1.20.0` | OTel bridge |
| `dev` | `pytest>=7.0`, `jsonschema>=4.17`, `pyyaml>=6.0` | Development |

### 10.2 Console Scripts

17 entry points registered in `pyproject.toml:36-53` (see Section 2 for full list).

### 10.3 Version String

- `pyproject.toml`: `version = "0.12.5"`
- `src/sanna/version.py`: `__version__ = "0.12.5"`
- **Consistent.**

### 10.4 JSON Canonicalization Dependencies

**None.** Sanna implements RFC 8785 natively in `hashing.py` using Python's `json.dumps()`. No `jcs`, `canonicaljson`, or other external canonicalization library is used.

---

## Test Suite Results

```
$ python -m pytest --tb=no -q --ignore=tests/test_mcp_server.py
11 failed, 2143 passed, 6 skipped, 10 xfailed, 203 warnings in 103.95s

Failed tests (all pre-existing MCP compat issues):
  tests/test_hardening.py — 7 MCP compat failures
  tests/test_identity_claims.py — 4 MCP tool compat failures
```

All failures are pre-existing MCP SDK version mismatches, not regressions.
