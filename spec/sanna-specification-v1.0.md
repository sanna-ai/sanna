# Sanna Reasoning Receipt Specification v1.0

**Status:** Released
**Version:** 1.0
**Date:** 2026-02-17
**Reference implementation:** sanna v0.13.0

---

## 1. Introduction

Sanna is trust infrastructure for AI agents. It checks reasoning during
execution, halts when constraints are violated, and generates portable
cryptographic receipts proving governance was enforced.

This document specifies the **Reasoning Receipt** format, the
**Constitution** format, the **fingerprint construction algorithm**,
the **canonicalization rules**, and the **verification protocol**.

Conforming implementations MUST produce receipts that validate against
the receipt JSON schema (`receipt.schema.json`) and MUST implement the
fingerprint algorithm exactly as described in Section 4.

### 1.1 Terminology

| Term | Definition |
|------|-----------|
| Receipt | Immutable artifact recording governance evaluation for a single AI action |
| Constitution | Policy document defining agent boundaries, invariants, and enforcement rules |
| Fingerprint | Deterministic SHA-256 hash of receipt content fields |
| Check | A single evaluation of one invariant against agent inputs/outputs |
| Enforcement | The action taken in response to check results (halt, warn, log, allow) |
| Correlation ID | Unique identifier linking a receipt to the originating action |

### 1.2 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

---

## 2. Receipt Format

A reasoning receipt is a JSON object. The normative schema is
`receipt.schema.json` (JSON Schema 2020-12).

### 2.1 Required Fields

Every receipt MUST contain the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `spec_version` | string | Specification version (`"1.0"`) |
| `tool_version` | string | Semver of the tool that generated this receipt |
| `checks_version` | string | Integer string; increment when check semantics change |
| `receipt_id` | string | UUID v4 (lowercase hex, dashes) |
| `receipt_fingerprint` | string | Truncated 16-hex SHA-256 (see Section 4) |
| `full_fingerprint` | string | Full 64-hex SHA-256 (see Section 4) |
| `correlation_id` | string | Unique identifier for the originating action |
| `timestamp` | string | ISO 8601 date-time when receipt was generated |
| `inputs` | object | Inputs to the AI system (`query`, `context`) |
| `outputs` | object | Outputs from the AI system (`response`) |
| `context_hash` | string | Full 64-hex SHA-256 of Sanna Canonical JSON of `inputs` |
| `output_hash` | string | Full 64-hex SHA-256 of Sanna Canonical JSON of `outputs` |
| `checks` | array | Array of `CheckResult` objects (see Section 2.3) |
| `checks_passed` | integer | Count of checks where `passed == true` |
| `checks_failed` | integer | Count of checks where `passed == false` |
| `status` | string | Overall status: `"PASS"`, `"WARN"`, `"FAIL"`, or `"PARTIAL"` |

### 2.2 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `evaluation_coverage` | object/null | Invariant coverage metrics |
| `constitution_ref` | object/null | Provenance of the governing constitution |
| `enforcement` | object/null | Enforcement outcome |
| `receipt_signature` | object/null | Ed25519 cryptographic signature |
| `authority_decisions` | array/null | Authority boundary decisions |
| `escalation_events` | array/null | Escalation audit trail |
| `source_trust_evaluations` | array/null | Trust tier evaluations |
| `input_hash` | string/null | Receipt Triad: SHA-256 of action context (see Section 7) |
| `reasoning_hash` | string/null | Receipt Triad: SHA-256 of agent justification (see Section 7) |
| `action_hash` | string/null | Receipt Triad: SHA-256 of tool call and arguments (see Section 7) |
| `assurance` | string/null | Receipt Triad assurance level (`"full"`, `"partial"`) (see Section 7) |
| `extensions` | object | Reverse-domain-namespaced vendor metadata |
| `identity_verification` | object/null | Identity claim verification results |

Receipts MUST NOT contain fields not defined in the schema
(`additionalProperties: false`).

### 2.3 CheckResult

Each element of the `checks` array MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check_id` | string | Yes | Pattern: `^(C[1-5]\|INV_.+\|sanna\\..+)$` |
| `name` | string | Yes | Human-readable check name |
| `passed` | boolean | Yes | Whether the check passed |
| `severity` | string | Yes | `"info"`, `"warning"`, `"critical"`, `"high"`, `"medium"`, `"low"` |
| `evidence` | string/null | No | Failure evidence snippets |
| `details` | string/null | No | Additional details |
| `triggered_by` | string/null | No | Invariant ID that triggered this check |
| `enforcement_level` | string/null | No | `"halt"`, `"warn"`, `"log"` |
| `constitution_version` | string/null | No | Constitution version |
| `status` | string/null | No | `"NOT_CHECKED"`, `"ERRORED"`, `"FAILED"` |
| `reason` | string/null | No | Explanation of status |
| `check_impl` | string/null | No | Namespaced implementation ID |
| `replayable` | boolean/null | No | Whether check is deterministically replayable |

### 2.4 Status Computation

The `status` field MUST be computed from `checks` as follows:

1. Partition checks into evaluated and non-evaluated. A check is
   **non-evaluated** if `status` is `"NOT_CHECKED"` or `"ERRORED"`.
2. `checks_passed` = count of evaluated checks where `passed == true`.
3. `checks_failed` = count of evaluated checks where `passed == false`.
4. If any evaluated check has `passed == false` and `severity == "critical"`:
   `status = "FAIL"`.
5. Else if any evaluated check has `passed == false` and
   `severity == "warning"`: `status = "WARN"`.
6. Else if any non-evaluated checks exist and no failures: `status = "PARTIAL"`.
7. Otherwise: `status = "PASS"`.

Non-evaluated checks (`NOT_CHECKED`, `ERRORED`) MUST NOT be counted in
`checks_passed` or `checks_failed`.

### 2.5 Enforcement Object

When a constitution is loaded, the `enforcement` field MUST be present:

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | `"halted"`, `"warned"`, `"allowed"`, `"escalated"` |
| `reason` | string | Human-readable reason |
| `failed_checks` | array | Check IDs that triggered enforcement |
| `enforcement_mode` | string | `"halt"`, `"warn"`, `"log"` |
| `timestamp` | string | ISO 8601 date-time |

### 2.6 Constitution Reference

When a constitution is loaded, `constitution_ref` SHOULD be present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `document_id` | string | Yes | `{agent_name}/{version}` |
| `policy_hash` | string | Yes | SHA-256 hex (16 or 64 chars) |
| `version` | string/null | No | Constitution version |
| `source` | string/null | No | Load path |
| `signature_verified` | boolean/string/null | No | `true`, `false`, `"no_signature"` |
| `constitution_approval` | object/null | No | Approval status (see schema) |

`constitution_approval` is mutable metadata and MUST NOT be included in
the fingerprint hash (see Section 4.2).

---

## 3. Canonicalization

Sanna uses a canonical JSON serialization derived from RFC 8785 (JSON
Canonicalization Scheme) for all hash computations.

### 3.1 Sanna Canonical JSON

The canonical form is produced by `json.dumps()` with:
- `sort_keys=True`
- `separators=(",", ":")` (no whitespace)
- `ensure_ascii=False`

The resulting string is encoded as UTF-8 bytes.

### 3.2 Number Handling

Conforming implementations MUST:
- Reject `NaN` and `Infinity` values (raise an error).
- Serialize integers as JSON integers.
- Reject non-integer floats in signing contexts (use integer basis
  points or string representation instead).

The `sanitize_for_signing()` function converts exact-integer floats
(e.g., `71.0`) to integers (`71`) and raises `TypeError` on lossy
floats, `NaN`, and `Infinity`.

### 3.3 Hash Functions

| Function | Input | Output |
|----------|-------|--------|
| `hash_text(s)` | UTF-8 string | SHA-256 hex, truncated to 16 chars |
| `hash_text(s, truncate=N)` | UTF-8 string | SHA-256 hex, truncated to N chars |
| `hash_obj(obj)` | Any JSON-serializable object | `hash_text(canonical_json_bytes(obj))` |

Full (64-char) hashes: use `hash_text(s, truncate=64)` or
`sha256_hex(data, truncate=64)`.

---

## 4. Fingerprint Construction

The receipt fingerprint is the primary tamper-evidence mechanism.
**All implementations MUST produce identical fingerprints for identical
receipt content.**

### 4.1 Algorithm

The fingerprint is computed from a pipe-delimited string of hash
components:

```
fingerprint_input = "{correlation_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}"
```

This is always exactly 12 pipe-separated fields.

| Component | Source |
|-----------|--------|
| `correlation_id` | Receipt `correlation_id` field (literal string value) |
| `context_hash` | Receipt `context_hash` field (64-hex SHA-256) |
| `output_hash` | Receipt `output_hash` field (64-hex SHA-256) |
| `checks_version` | Receipt `checks_version` field (literal string value) |
| `checks_hash` | `hash_obj()` of check data (see Section 4.3) (64-hex SHA-256) |
| `constitution_hash` | `hash_obj()` of constitution_ref (excluding `constitution_approval`) or `EMPTY_HASH` (64-hex SHA-256) |
| `enforcement_hash` | `hash_obj()` of enforcement object or `EMPTY_HASH` (64-hex SHA-256) |
| `coverage_hash` | `hash_obj()` of evaluation_coverage or `EMPTY_HASH` (64-hex SHA-256) |
| `authority_hash` | `hash_obj()` of authority_decisions or `EMPTY_HASH` (64-hex SHA-256) |
| `escalation_hash` | `hash_obj()` of escalation_events or `EMPTY_HASH` (64-hex SHA-256) |
| `trust_hash` | `hash_obj()` of source_trust_evaluations or `EMPTY_HASH` (64-hex SHA-256) |
| `extensions_hash` | `hash_obj()` of extensions or `EMPTY_HASH` (64-hex SHA-256) |

`EMPTY_HASH` is the SHA-256 digest of zero bytes, used as sentinel for
absent fields:

```
EMPTY_HASH = sha256_hex(b"") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Note: `correlation_id` and `checks_version` contribute their literal
string values to the fingerprint formula. All other components
contribute 64-character hexadecimal SHA-256 strings or `EMPTY_HASH`.

The `receipt_fingerprint` is `hash_text(fingerprint_input)` (16 hex chars).
The `full_fingerprint` is `hash_text(fingerprint_input, truncate=64)` (64 hex chars).

### 4.2 Constitution Approval Stripping

The `constitution_approval` field within `constitution_ref` is **mutable
metadata** — it can be added or revoked after the constitution is signed.
Before computing `constitution_hash`, implementations MUST remove the
`constitution_approval` key:

```python
stripped = {k: v for k, v in constitution_ref.items() if k != "constitution_approval"}
constitution_hash = hash_obj(stripped)
```

### 4.3 Checks Hash

The `checks_hash` is computed over a list of per-check dicts. Each
dict contains the following fields (in this exact set):

**Legacy path** (no constitution): `check_id`, `passed`, `severity`,
`evidence`.

**Constitution-driven path**: `check_id`, `passed`, `severity`,
`evidence`, `triggered_by`, `enforcement_level`, `check_impl`,
`replayable`.

### 4.4 checks_version

The current value of `checks_version` is `"5"`. This value is
incremented when the semantics of built-in checks change in a way that
alters check results for identical inputs.

Verifiers MUST treat `checks_version` as an opaque string. They
compare it for equality during fingerprint verification but MUST NOT
interpret its numeric value or make behavioral decisions based on it.

### 4.5 Fields NOT in Fingerprint

The following fields are NOT included in fingerprint computation:
- `receipt_id` (random)
- `timestamp` (non-deterministic)
- `receipt_fingerprint` and `full_fingerprint` (self-referential)
- `receipt_signature` (computed after fingerprint)
- `identity_verification` (verified separately)

---

## 5. Cryptographic Signing

### 5.1 Algorithm

All signatures use **Ed25519** (RFC 8032).

### 5.2 Receipt Signing

1. Construct a `receipt_signature` block with `signature: ""` (empty placeholder).
2. Attach the block to a copy of the receipt.
3. Run `sanitize_for_signing()` on the entire receipt copy.
4. Serialize with `canonical_json_bytes()`.
5. Sign the resulting bytes with the Ed25519 private key.
6. Base64-encode the 64-byte signature.
7. Replace the placeholder with the actual signature.

The `receipt_signature` object contains:

| Field | Type | Description |
|-------|------|-------------|
| `signature` | string | Base64-encoded Ed25519 signature |
| `key_id` | string | SHA-256 hex of the public key (64 chars) |
| `signed_by` | string | Human-readable signer identity |
| `signed_at` | string | ISO 8601 timestamp |
| `scheme` | string | `"receipt_sig_v1"` |

### 5.3 Constitution Signing

Constitution signatures cover:
- `schema_version`, `identity` (with extensions flattened), `provenance`
  (with `signature.value = ""`), `boundaries`, `trust_tiers`,
  `halt_conditions`, `invariants`, `policy_hash`
- Optionally: `authority_boundaries`, `escalation_targets`,
  `trusted_sources`, `version` (if != `"1.0"`), `reasoning`

The signing material is serialized with `canonical_json_bytes()` after
`sanitize_for_signing()`.

### 5.4 Approval Signing

Approval signatures cover all `ApprovalRecord` fields except
`approval_signature` (blanked to `""`). The signing material is
serialized with `canonical_json_bytes()`.

### 5.5 Key Identification

Keys are identified by their `key_id`: the SHA-256 hex digest of the
DER-encoded public key bytes. Key files use the key_id as filename:
`{key_id}.key`, `{key_id}.pub`, `{key_id}.meta.json`.

---

## 6. Constitution Format

Constitutions are YAML documents. The normative schema is
`constitution.schema.json`.

### 6.1 Required Sections

| Section | Description |
|---------|-------------|
| `sanna_constitution` | Schema version string (maps to `schema_version`) |
| `identity` | Agent name, domain, description |
| `provenance` | Author, approvers, date, method |
| `boundaries` | Operational constraints (id, description, category, severity) |

### 6.2 Optional Sections

| Section | Description |
|---------|-------------|
| `invariants` | Rules to enforce (id, rule, enforcement, check) |
| `authority_boundaries` | Cannot/must/can execute lists |
| `halt_conditions` | Triggers for enforcement halts |
| `trusted_sources` | Tier classification for data sources |
| `escalation_targets` | Escalation delivery configuration |
| `reasoning` | Reasoning evaluation configuration (v1.1+) |
| `approval` | Approval chain records |

### 6.3 Invariant-to-Check Resolution

Each invariant is resolved to a check implementation:

1. **Explicit `check` field** on the invariant: look up in the check registry.
2. **Standard `INV_*` ID**: look up in the invariant-to-check map.
3. **Custom evaluator**: look up in the evaluator registry.
4. **Fallback**: record as `NOT_CHECKED`.

Standard mappings:

| Invariant ID | Check Implementation |
|-------------|---------------------|
| `INV_NO_FABRICATION` | `sanna.context_contradiction` |
| `INV_MARK_INFERENCE` | `sanna.unmarked_inference` |
| `INV_NO_FALSE_CERTAINTY` | `sanna.false_certainty` |
| `INV_PRESERVE_TENSION` | `sanna.conflict_collapse` |
| `INV_NO_PREMATURE_COMPRESSION` | `sanna.premature_compression` |

### 6.4 Enforcement Levels

| Level | Behavior |
|-------|----------|
| `halt` | Stop execution, raise error, generate receipt with `enforcement.action = "halted"` |
| `warn` | Continue execution, generate receipt with `enforcement.action = "warned"` |
| `log` | Continue execution, generate receipt with `enforcement.action = "allowed"` |

### 6.5 Enumerated Values

**Categories:** `scope`, `authorization`, `confidentiality`, `safety`, `compliance`, `custom`

**Severities:** `critical`, `high`, `medium`, `low`, `info`

**Enforcement:** `halt`, `warn`, `log`

**Approval statuses:** `approved`, `pending`, `revoked`

---

## 7. Receipt Triad

The Receipt Triad provides end-to-end binding of the action lifecycle:
from the input context that prompted an agent action, through the
agent's reasoning, to the final tool call. It is a core mechanism for
establishing that governance evaluation covered the full decision chain.

### 7.1 Triad Fields

| Field | Type | Description |
|-------|------|-------------|
| `input_hash` | string | SHA-256 of the action context at the governance boundary |
| `reasoning_hash` | string | SHA-256 of the agent's justification for the action |
| `action_hash` | string | SHA-256 of the tool call and arguments |
| `assurance` | string | `"full"` or `"partial"` |

All three hash fields are full 64-character hexadecimal SHA-256 digests.

### 7.2 Assurance Levels

- **`"full"`**: The agent's justification is present and has been
  evaluated by reasoning checks (presence, substance, coherence).
  All three triad hashes are present.
- **`"partial"`**: The agent's justification is absent, empty, or
  reasoning evaluation was skipped. One or more triad hashes MAY be
  absent.

When any triad hash is present, `assurance` MUST also be present.

### 7.3 Absent Triad

When the Receipt Triad is not applicable (e.g., non-gateway receipts
that do not involve tool calls), the triad fields are simply not
present in the receipt. They are not set to `null` and not set to
empty strings -- they are absent from the JSON object entirely.

### 7.4 Gateway Boundary

At the gateway enforcement boundary, the gateway sees the tool call as
both the input to governance evaluation and the action being governed.
Therefore, at the gateway boundary:

```
action_hash == input_hash
```

The `reasoning_hash` captures the agent's justification (the
`_justification` parameter injected by the gateway's schema mutation),
which is evaluated independently from the tool call itself.

---

## 8. Escalation and Approval Chain

When a tool call matches a `must_escalate` policy, execution is
deferred pending human approval. This section specifies the receipt
chaining and token security mechanisms for escalation workflows.

### 8.1 Receipt Chaining

A `must_escalate` tool call produces two receipts:

1. **Escalation receipt**: Generated when the tool call is intercepted.
   The `enforcement.action` is `"escalated"`. The receipt records the
   original tool name, arguments hash, and escalation metadata in
   `extensions["com.sanna.gateway"]`.

2. **Resolution receipt**: Generated when the human approves or denies
   the escalation. This receipt references the original escalation
   receipt via `extensions["com.sanna.gateway"].escalation_receipt_id`,
   linking the two receipts into an auditable chain.

If the escalation is approved and the downstream tool call executes
successfully, the resolution receipt records the forwarded call result.
If the escalation is denied, the resolution receipt records the denial
with `enforcement.action = "halted"`.

### 8.2 HMAC-SHA256 Token Binding

Escalation approval tokens are bound to the specific tool call via
HMAC-SHA256. The token is computed as:

```
token = HMAC-SHA256(secret, escalation_id | tool_name | args_hash | created_at)
```

Where:
- `secret` is a per-gateway random secret, generated at gateway startup
  and held in memory only.
- `escalation_id` is the unique identifier for the pending escalation.
- `tool_name` is the unprefixed name of the downstream tool.
- `args_hash` is the SHA-256 hex digest of the tool arguments.
- `created_at` is the ISO 8601 timestamp when the escalation was created.
- `|` denotes string concatenation of the components.

This binding prevents an approval token for one tool call from being
used to approve a different tool call.

### 8.3 One-Time Use

Escalation tokens are consumed on approval or denial. Once a token has
been used to respond to an escalation (approve or deny), it MUST NOT
be accepted again. Implementations enforce this by removing the
pending escalation record from the escalation store after resolution.

Replay of a consumed token MUST result in an error response indicating
the escalation is no longer pending.

### 8.4 Linking Fields

The following extension fields under `extensions["com.sanna.gateway"]`
support escalation chain auditing:

| Field | Present In | Description |
|-------|-----------|-------------|
| `escalation_id` | Escalation receipt | Unique ID of the pending escalation |
| `escalation_receipt_id` | Resolution receipt | `receipt_id` of the original escalation receipt |
| `escalation_action` | Resolution receipt | `"approved"` or `"denied"` |
| `arguments_hash` | Both | SHA-256 of the tool call arguments |

---

## 9. Verification Protocol

### 9.1 Steps

Verification proceeds in order. A failure at any step MAY terminate
early with the corresponding exit code.

| Step | Check | Exit Code |
|------|-------|-----------|
| 1 | JSON schema validation | 2 |
| 2a | Hash format validation (`receipt_id`, `receipt_fingerprint`, `full_fingerprint`, `context_hash`, `output_hash`) | accumulated |
| 2b | Content hash recomputation (`context_hash`, `output_hash`) | 3 |
| 2c | Constitution hash format (if `constitution_ref` present) | accumulated |
| 3 | Fingerprint recomputation and comparison | 3 |
| 4 | Status consistency (matches check results) | 4 |
| 5 | Check count consistency | 4 |
| 6 | Governance warning (FAIL + no enforcement) | warning only |
| 7 | Receipt signature verification (optional, with public key) | 5 |
| 8 | Constitution chain verification (optional, with constitution) | errors/warnings |
| 9 | Receipt Triad verification (gateway receipts) | errors/warnings |
| 10 | Identity verification reporting | warning only |

### 9.2 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid |
| 2 | Schema validation failed |
| 3 | Fingerprint or content hash mismatch |
| 4 | Status or count consistency error |
| 5 | Other verification error |

---

## 10. Evidence Bundles

An evidence bundle is a ZIP archive containing:

1. `receipt.json` -- the reasoning receipt
2. `constitution.yaml` -- the governing constitution
3. `public_keys/{key_id}.pub` -- public key(s)
4. `metadata.json` -- bundle metadata

Bundle verification runs 7 steps:

| Step | Check |
|------|-------|
| 1 | Bundle structure (required files present) |
| 2 | Receipt schema validation |
| 3 | Receipt fingerprint match |
| 4 | Constitution signature verification |
| 5 | Provenance chain (receipt-to-constitution binding) |
| 6 | Receipt signature verification |
| 7 | Approval verification (content hash + approval signature) |

---

## 11. Correlation ID Prefixes

| Prefix | Source |
|--------|--------|
| `sanna-` | `@sanna_observe` decorator |
| `mcp-` | MCP server tool |
| `gw-` | Gateway enforcement proxy |

---

## 12. Security Considerations

This section describes the security properties and limitations of
reasoning receipts.

### 12.1 What Receipts Prove

A valid, signed reasoning receipt proves:

- That governance checks ran against the recorded inputs and outputs.
- What the inputs and outputs were at evaluation time (via content
  hashes and the fingerprint).
- What the constitution said at evaluation time (via the constitution
  reference and policy hash).
- That the receipt has not been tampered with since signing (via the
  Ed25519 signature and fingerprint).

### 12.2 What Receipts Do Not Prove

Receipts do not and cannot prove:

- That the AI system actually used the provided context when generating
  its output. The receipt records what was available, not what was
  attended to.
- That the output is factually correct. Governance checks evaluate
  structural and reasoning properties, not factual accuracy.
- That the constitution is well-written or complete. A receipt proves
  the constitution was enforced, not that the constitution is adequate
  for the use case.
- That the system behaved identically in the absence of governance.
  Receipts are observational, not counterfactual.

### 12.3 Key Management

Private keys MUST be stored securely with restricted file permissions
(0o600 or equivalent). The following key separation is RECOMMENDED:

| Role | Purpose | Key Label |
|------|---------|-----------|
| Author | Signs constitutions | `author` |
| Approver | Signs approval records | `approver` |
| Gateway | Signs gateway receipts | `gateway` |

Each role SHOULD use a separate Ed25519 keypair. Sharing keys across
roles weakens the audit trail by conflating signing authorities.

Key rotation requires re-signing: a new constitution signature with the
new author key, new approval records with the new approver key, or
reconfiguration of the gateway with the new gateway key. Old receipts
remain verifiable against the old public key.

### 12.4 Approval Channel Security

Escalation approval channels have the following security properties and
requirements:

- **Stderr channel**: The RECOMMENDED approval channel for interactive
  MCP clients. Approval prompts are displayed via stderr, which is
  visible to the user but not captured by the MCP protocol stream.
- **Webhook channel**: Webhook escalation targets MUST validate the
  destination URL to prevent SSRF (Server-Side Request Forgery).
  Implementations SHOULD reject private/internal IP ranges and
  non-HTTPS URLs.
- **HMAC token binding**: Approval tokens are bound to specific tool
  calls via HMAC-SHA256 (see Section 8.2). This prevents token forgery
  and cross-call replay.
- **Token lifetime**: Pending escalations SHOULD have a configurable
  TTL (time-to-live). Expired escalations MUST be purged and their
  tokens MUST NOT be accepted.

---

## 13. Conformance Requirements

This section defines the requirements for implementations that claim
conformance with this specification.

### 13.1 Compatible Generator

An implementation claiming to be a compatible generator MUST:

1. Produce receipts that validate against the normative receipt JSON
   schema (`receipt.schema.json`).
2. Compute fingerprints using the 12-field formula specified in
   Section 4.1, producing identical fingerprints for identical receipt
   content.
3. Use Sanna Canonical JSON (Section 3.1) for all hash computations,
   including content hashes, checks hash, and fingerprint components.
4. Generate UUID v4 `receipt_id` values (RFC 4122, lowercase hex with
   dashes).
5. Compute `status`, `checks_passed`, and `checks_failed` according to
   the rules in Section 2.4.
6. Use `EMPTY_HASH` (the SHA-256 of zero bytes) as the sentinel for
   absent fingerprint components.
7. Strip `constitution_approval` from `constitution_ref` before
   computing the constitution hash (Section 4.2).

### 13.2 Compatible Verifier

An implementation claiming to be a compatible verifier MUST:

1. Verify the receipt fingerprint by recomputing it from receipt fields
   using the 12-field formula and comparing against the stored
   `full_fingerprint`.
2. Verify content hashes (`context_hash`, `output_hash`) by
   recomputing them from the `inputs` and `outputs` fields.
3. Verify status consistency: the `status` field matches the result of
   applying the rules in Section 2.4 to the `checks` array.
4. Verify check count consistency: `checks_passed` and `checks_failed`
   match the actual counts of evaluated checks.
5. Support both v0.13.0 (12-field) and legacy fingerprint formats. When
   verifying a legacy receipt, the verifier SHOULD apply the field
   migration mapping (Appendix A) and attempt verification with the
   legacy fingerprint formula.

A compatible verifier MUST NOT:

1. Reject receipts solely because they contain unknown keys within the
   `extensions` object. The `extensions` field is designed for vendor
   metadata and forward compatibility.

A compatible verifier SHOULD:

1. Verify Ed25519 cryptographic signatures (`receipt_signature`) when
   the corresponding public key is available.
2. Verify the constitution provenance chain when the constitution file
   is available.
3. Report warnings (not errors) for unverifiable optional fields such
   as identity claims without provider keys or approval records without
   approver keys.

---

## 14. Version History

| Spec Version | Tool Version | Changes |
|-------------|-------------|---------|
| 1.0 | 0.13.0 | Initial specification. Field renames: `schema_version` to `spec_version`, `trace_id` to `correlation_id`, `coherence_status` to `status`, `halt_event` to `enforcement`. Added `full_fingerprint`. UUID v4 receipt IDs. Full 64-hex content hashes. 12-field fingerprint formula. Custom evaluator fail-closed default. |

---

## Appendix A: Field Migration from Legacy

| Legacy Field | v1.0 Field |
|-------------|-----------|
| `schema_version` | `spec_version` |
| `trace_id` | `correlation_id` |
| `coherence_status` | `status` |
| `halt_event` | `enforcement` |
| (none) | `full_fingerprint` (new) |

Legacy receipts (those with `schema_version` instead of `spec_version`)
are not valid against the v1.0 schema. Verifiers MAY implement backward
compatibility by detecting legacy field names and applying the mapping
above before validation.

## Appendix B: Enforcement Action Mapping

| Receipt status | `enforcement.action` | Meaning |
|----------------|----------------------|---------|
| FAIL (critical check failed) | `halted` | Execution blocked, output suppressed |
| WARN (warning check failed) | `warned` | Execution continued, warning logged |
| PASS (all checks pass) | `allowed` | Execution continued normally |
| -- (`must_escalate` policy) | `escalated` | Execution deferred pending human approval |

The `enforcement.action` field records the action taken by the
governance system. The mapping above describes the typical
correspondence between receipt status and enforcement action. Note that
`escalated` is a policy-driven action that occurs before check
evaluation and is independent of the receipt status.

## Appendix C: Schema References

- Receipt schema: `spec/receipt.schema.json`
- Constitution schema: `spec/constitution.schema.json`
- Golden test vectors: `golden/receipts/v13_*.json`
