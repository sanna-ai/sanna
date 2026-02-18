# Sanna Reasoning Receipt Specification v1.0

**Status:** Released
**Version:** 1.0.2
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
| `correlation_id` | string | Unique identifier for the originating action. MUST NOT contain the pipe character `|` (U+007C), as this character is used as the field delimiter in the fingerprint computation. Implementations MUST validate this constraint. |
| `timestamp` | string | ISO 8601 date-time when receipt was generated |
| `inputs` | object | Inputs to the AI system (`query`, `context`, and any additional properties) |
| `outputs` | object | Outputs from the AI system (`response` and any additional properties) |
| `context_hash` | string | Full 64-hex SHA-256 of Sanna Canonical JSON of the entire `inputs` object (including all additionalProperties) |
| `output_hash` | string | Full 64-hex SHA-256 of Sanna Canonical JSON of the entire `outputs` object (including all additionalProperties) |
| `checks` | array | Array of `CheckResult` objects (see Section 2.3) |
| `checks_passed` | integer | Count of checks where `passed == true` |
| `checks_failed` | integer | Count of checks where `passed == false` |
| `status` | string | Overall status: `"PASS"`, `"WARN"`, `"FAIL"`, or `"PARTIAL"` |

### 2.2 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `evaluation_coverage` | object/null | Invariant coverage metrics |
| `constitution_ref` | object/null | Provenance of the governing constitution (see Section 2.6) |
| `enforcement` | object/null | Enforcement outcome (see Section 2.5). Present when a constitution is loaded and enforcement is triggered. MAY be null or absent when no enforcement action was taken. |
| `receipt_signature` | object/null | Ed25519 cryptographic signature |
| `authority_decisions` | array/null | Authority boundary decisions (see Section 2.7). OPTIONAL -- present only in gateway mode. |
| `escalation_events` | array/null | Escalation audit trail (see Section 2.8). OPTIONAL -- present only in gateway mode. |
| `source_trust_evaluations` | array/null | Trust tier evaluations (see Section 2.9). OPTIONAL -- present only when structured context with trust tiers is provided. |
| `input_hash` | string/null | Receipt Triad: SHA-256 of action context (see Section 7) |
| `reasoning_hash` | string/null | Receipt Triad: SHA-256 of agent justification (see Section 7) |
| `action_hash` | string/null | Receipt Triad: SHA-256 of tool call and arguments (see Section 7) |
| `assurance` | string/null | Receipt Triad assurance level (`"full"`, `"partial"`) (see Section 7) |
| `extensions` | object | Reverse-domain-namespaced vendor metadata |
| `identity_verification` | object/null | Identity claim verification results (see Section 2.10) |

Receipts MUST NOT contain fields not defined in the schema
(`additionalProperties: false`).

### 2.3 CheckResult

Each element of the `checks` array MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check_id` | string | Yes | Pattern: `^(C[1-5]|INV_.+|sanna\..+)$` (alternation of three forms: legacy C1-C5, custom INV_ prefix, or namespaced sanna. prefix) |
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
4. If any evaluated check has `passed == false` and
   `severity` in `{"critical", "high"}`: `status = "FAIL"`.
5. Else if any evaluated check has `passed == false` and
   `severity` in `{"warning", "medium", "low"}`: `status = "WARN"`.
6. Else if any non-evaluated checks exist and no failures: `status = "PARTIAL"`.
7. Otherwise: `status = "PASS"`.

The severity hierarchy for status computation is:
- **FAIL-level severities:** `"critical"`, `"high"`
- **WARN-level severities:** `"warning"`, `"medium"`, `"low"`
- **Neutral severities:** `"info"` (does not affect status)

Non-evaluated checks (`NOT_CHECKED`, `ERRORED`) MUST NOT be counted in
`checks_passed` or `checks_failed`.

### 2.5 Enforcement Object

When a constitution is loaded and enforcement is triggered, the
`enforcement` field SHOULD be present. The `enforcement` field MAY be
null or absent when no enforcement action was taken (e.g., all checks
passed with no halt/warn enforcement configured):

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
| `approved_by` | string/array/null | No | Email(s) of constitution approver(s) |
| `approval_date` | string/null | No | ISO 8601 date of approval |
| `approval_method` | string/null | No | Method used for approval |
| `signature` | string/null | No | Base64-encoded constitution Ed25519 signature value |
| `key_id` | string/null | No | 64-hex SHA-256 key identifier |
| `signed_by` | string/null | No | Human-readable signer identity |
| `signed_at` | string/null | No | ISO 8601 date-time of signing |
| `scheme` | string/null | No | `"constitution_sig_v1"` |
| `signature_verified` | boolean/string/null | No | `true`, `false`, `"no_signature"` |
| `constitution_approval` | object/null | No | Approval status (see schema `oneOf` variants: full approved record, minimal `{"status": "unapproved"}`, or null) |

`constitution_approval` is mutable metadata and MUST NOT be included in
the fingerprint hash (see Section 4.2). However, it IS included in the
receipt signature -- the signature covers the entire receipt (including
`constitution_approval`) except the `receipt_signature.signature` value
itself.

### 2.7 Authority Decisions

OPTIONAL -- present only in gateway mode.

Each element of the `authority_decisions` array MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | Tool name or action that was evaluated |
| `params` | object/null | No | Tool parameters (additionalProperties allowed) |
| `decision` | string | Yes | `"halt"`, `"allow"`, `"escalate"` |
| `reason` | string | Yes | Human-readable reason for the decision |
| `boundary_type` | string | Yes | `"cannot_execute"`, `"must_escalate"`, `"can_execute"`, `"uncategorized"` |
| `escalation_target` | object/null | No | Target configuration with `type` field (`"log"`, `"webhook"`, `"callback"`) |
| `timestamp` | string | Yes | ISO 8601 date-time |

### 2.8 Escalation Events

OPTIONAL -- present only in gateway mode.

Each element of the `escalation_events` array MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | Tool name or action that triggered escalation |
| `condition` | string | Yes | Escalation condition from constitution |
| `target_type` | string | Yes | `"log"`, `"webhook"`, `"callback"` |
| `success` | boolean | Yes | Whether escalation delivery succeeded |
| `details` | object/null | No | Additional delivery details |
| `timestamp` | string | Yes | ISO 8601 date-time |

### 2.9 Source Trust Evaluations

OPTIONAL -- present only when structured context with trust tiers
is provided.

Each element of the `source_trust_evaluations` array MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_name` | string | Yes | Name of the data source |
| `trust_tier` | string | Yes | `"tier_1"`, `"tier_2"`, `"tier_3"`, `"untrusted"`, `"unclassified"` |
| `evaluated_at` | string | Yes | ISO 8601 date-time |
| `verification_flag` | boolean/null | No | Whether verification is recommended (true for tier_2) |
| `context_used` | boolean/null | No | Whether the source was used in check evaluation |

### 2.10 Identity Verification

OPTIONAL -- present only when the constitution has identity claims.

The `identity_verification` object contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `total_claims` | integer | Yes | Total number of identity claims |
| `verified` | integer | Yes | Number of verified claims |
| `failed` | integer | Yes | Number of failed verifications |
| `unverified` | integer | Yes | Number of unverified claims (no key or no signature) |
| `all_verified` | boolean | Yes | Whether all claims are verified |
| `claims` | array | Yes | Per-claim status records |

Each element of the `claims` array contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | Yes | Identity provider name |
| `claim_type` | string | Yes | Type of identity claim |
| `credential_id` | string | Yes | Credential identifier |
| `status` | string | Yes | `"verified"`, `"unverified"`, `"failed"`, `"expired"`, `"no_key"` |

`identity_verification` is NOT included in the receipt fingerprint. It
is verified separately and appended after fingerprint computation.

### 2.11 Redaction Markers

When a receipt field contains PII that has been redacted by the gateway,
the original value is replaced with a **Redaction Marker** object before
the receipt is signed. Because the marker is applied before signing, the
receipt's `context_hash`, `output_hash`, fingerprint, and signature all
cover the marker -- not the original content.

#### 2.11.1 Redaction Marker Schema

A redaction marker is a JSON object with the following structure:

```json
{
  "__redacted__": true,
  "original_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `__redacted__` | boolean | Yes | MUST be `true`. Identifies this object as a redaction marker. |
| `original_hash` | string | Yes | The SHA-256 hex digest of the NFC-normalized original value. Format: `[a-f0-9]{64}` (64 lowercase hexadecimal characters, bare digest with no prefix). |

The `original_hash` is computed as follows:

1. Apply Unicode NFC normalization (UAX #15) to the original string value.
2. Encode the normalized string as UTF-8 bytes.
3. Compute the SHA-256 digest of the bytes.
4. Format as 64 lowercase hexadecimal characters (bare hex digest, no `sha256:` prefix).

This allows an auditor with access to the original content to verify
provenance by recomputing the hash, without the receipt itself containing
the sensitive data.

#### 2.11.2 Redacted Fields Tracking

When one or more redaction markers are applied, the receipt MUST include
a `redacted_fields` array at the top level:

```json
{
  "redacted_fields": ["inputs.context", "outputs.response"]
}
```

Each element is a dot-separated JSON path identifying a field that was
replaced with a redaction marker. The paths use the form
`{top-level-key}.{nested-key}` (e.g., `inputs.context`,
`outputs.response`).

The `redacted_fields` array is present only when PII redaction is
enabled and at least one field was actually redacted. When no fields
are redacted, the `redacted_fields` key MUST NOT be present (or MAY
be null).

#### 2.11.3 Hash and Fingerprint Recomputation

After replacing field values with redaction markers, implementations
MUST recompute:

1. `context_hash` -- SHA-256 of Sanna Canonical JSON of the (now
   marker-bearing) `inputs` object.
2. `output_hash` -- SHA-256 of Sanna Canonical JSON of the (now
   marker-bearing) `outputs` object.
3. `receipt_fingerprint` and `full_fingerprint` -- recomputed from
   the updated `context_hash` and `output_hash` using the standard
   12-field fingerprint formula (Section 4.1).

The receipt signature (if applied) MUST be computed AFTER redaction
markers and hash recomputation are complete.

#### 2.11.4 Pre-existing Marker Injection Guard

If an input value is already a dict with `"__redacted__": true`, this
is treated as suspicious -- an attacker may have pre-populated a fake
redaction marker in the tool call arguments. Implementations MUST
handle this by:

1. Serializing the entire dict to a JSON string using
   `json.dumps(value, sort_keys=True)`.
2. Applying a fresh redaction marker to the serialized JSON string.

This prevents an attacker from injecting a crafted `original_hash`
that would appear to match some other content. The double-redaction
ensures that the marker in the persisted receipt is always generated
by the gateway, never by the agent or upstream client.

#### 2.11.5 File Naming Convention

When redaction is enabled:

- The receipt is written to disk with a `.redacted.json` suffix
  (e.g., `2026-02-17T12_00_00_gw-abc123.redacted.json`).
- No unredacted copy is persisted to disk. The unredacted receipt
  exists only in memory during the request lifecycle.
- The `.redacted.json` suffix signals to downstream systems (log
  aggregators, compliance tools) that the receipt contains markers
  in place of original content.

When redaction is disabled, receipts are persisted with the standard
`.json` suffix and no markers are applied.

---

## 3. Canonicalization

Sanna uses a canonical JSON serialization derived from RFC 8785 (JSON
Canonicalization Scheme) for all hash computations.

### 3.1 Sanna Canonical JSON

String values MUST be normalized to Unicode NFC form (UAX #15)
at the `hash_text()` boundary — i.e., immediately before the input
is passed to SHA-256. This is a deliberate design decision: Sanna
normalizes at the hashing boundary, not at ingestion. Callers are
NOT required to NFC-normalize all strings globally; the hashing
functions handle it.

The canonical form is produced by `json.dumps()` with:
- `sort_keys=True` -- keys are sorted by byte-wise comparison of their UTF-8 encoded representations, consistent with RFC 8785 section 3.2.3
- `separators=(",", ":")` (no whitespace)
- `ensure_ascii=False`

The resulting string is encoded as UTF-8 bytes.

Implementations MUST NOT HTML-escape characters in JSON strings. For
example, `<` MUST be serialized as `<`, NOT as `\u003c`. Similarly,
`>`, `&`, `'`, and `"` (when inside a JSON string value) MUST appear
as their literal characters, not as Unicode escape sequences. Python's
`json.dumps(ensure_ascii=False)` satisfies this requirement. Go's
`encoding/json` does NOT satisfy this requirement by default -- it
HTML-escapes `<`, `>`, and `&` as `\u003c`, `\u003e`, and `\u0026`.
Go implementations MUST use a custom encoder that disables HTML
escaping (e.g., `encoder.SetEscapeHTML(false)`). Rust's `serde_json`
satisfies this requirement by default.

### 3.2 Number Handling

All floats are rejected. Conforming implementations MUST reject any
JSON value that is a floating-point number in signing and hashing
contexts. Specifically:

- Integer-valued floats (e.g., `1.0`, `71.0`) MUST be converted to
  their integer equivalents (`1`, `71`) before serialization.
- Non-integer floats (e.g., `3.14`, `0.1`) MUST raise an error.
  They MUST NOT be silently rounded or truncated.
- `NaN`, `Infinity`, and `-Infinity` MUST be rejected at parse time.
  Implementations MUST use a safe JSON parser that raises an error
  on these values rather than accepting them as special tokens.

Numeric values in signed receipt fields MUST be integers after
sanitization. The `sanitize_for_signing()` function walks the entire
data structure recursively, converting exact-integer floats to
integers and raising `ValueError` on lossy floats, `NaN`, and
`Infinity`.

**Cross-language note:** Python's `float` type can represent exact
integers (e.g., `71.0`), which `sanitize_for_signing()` converts.
In Go and Rust, JSON numbers are typically parsed as `float64` by
default. Implementations in these languages MUST either parse
numbers as arbitrary-precision (e.g., Go's `json.Number`, Rust's
`serde_json::Number`) or apply the same integer-conversion logic
after parsing.

### 3.3 Hash Functions

| Function | Input | Output |
|----------|-------|--------|
| `hash_text(s)` | UTF-8 string | SHA-256 hex, default truncation 64 chars |
| `hash_text(s, truncate=N)` | UTF-8 string | SHA-256 hex, truncated to N chars |
| `hash_obj(obj)` | Any JSON-serializable object | `hash_text(canonical_json_bytes(obj))` |

`hash_text(s)` applies the following normalization steps before hashing:

1. **NFC normalization** -- Unicode NFC (UAX #15).
2. **Line-ending normalization** -- `\r\n` and `\r` are replaced with `\n`.
3. **Trailing whitespace stripping** -- trailing whitespace is removed from each line.
4. **Leading/trailing strip** -- the entire string is stripped of leading and trailing whitespace.
5. **UTF-8 encoding** -- the normalized string is encoded as UTF-8 bytes.
6. **SHA-256** -- the bytes are hashed with SHA-256.

The default truncation length is **64 characters** (full SHA-256 hex).
Use `hash_text(s, truncate=16)` for the short human-readable form.

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

The `receipt_fingerprint` is `hash_text(fingerprint_input, truncate=16)` (16 hex chars).
The `full_fingerprint` is `hash_text(fingerprint_input)` (64 hex chars).

For fingerprint computation, absent optional fields MUST be treated
identically to null. Both `"field": null` and omission of `field`
produce `EMPTY_HASH` as the component value. There is no distinction
between a null value and a missing key for fingerprint purposes.

### 4.2 Constitution Approval Stripping

The `constitution_approval` field within `constitution_ref` is **mutable
metadata** -- it can be added or revoked after the constitution is signed.
Before computing `constitution_hash`, implementations MUST remove the
`constitution_approval` key:

```python
stripped = {k: v for k, v in constitution_ref.items() if k != "constitution_approval"}
constitution_hash = hash_obj(stripped)
```

Note: `constitution_approval` is excluded from the **fingerprint** hash
but IS included in the **receipt signature**. The fingerprint covers
immutable receipt content; the signature covers the full receipt
(including mutable approval metadata). This means:
- Changing `constitution_approval` invalidates the receipt signature.
- Changing `constitution_approval` does NOT invalidate the fingerprint.
- Approval metadata integrity is verified through the signature, not the fingerprint.

### 4.3 Checks Hash

The `checks_hash` is computed over a list of per-check dicts. Each
dict contains the following fields (in this exact set):

**Legacy path** (no constitution): `check_id`, `passed`, `severity`,
`evidence`.

**Constitution-driven path**: `check_id`, `passed`, `severity`,
`evidence`, `triggered_by`, `enforcement_level`, `check_impl`,
`replayable`.

Checks MUST be hashed in insertion order (the order they appear in
the `checks` array). Implementations MUST NOT sort checks before
hashing.

When a CheckResult field is null, it MUST be included in the hash
input as the JSON literal `null`, not omitted. For example, a check
with `evidence: null` MUST produce `{"evidence":null,...}` in the
canonical JSON, not `{...}` with the key omitted.

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

All signatures use **Pure Ed25519** as defined in RFC 8032. This means
no context string and no pre-hashing (Ed25519, not Ed25519ctx or
Ed25519ph). Signatures are 64 bytes: the concatenation of R (32 bytes
compressed Edwards point) and S (32 bytes scalar).

All Base64 encoding in Sanna uses **RFC 4648 standard Base64** with
padding (alphabet: `A`-`Z`, `a`-`z`, `0`-`9`, `+`, `/`; padding:
`=`). Base64url (alphabet: `+` replaced by `-`, `/` replaced by `_`)
MUST NOT be used. Implementations that encounter Base64url-encoded
values MUST reject them as invalid.

Implementations MUST strip all ASCII whitespace characters (`\t`
U+0009, `\n` U+000A, `\r` U+000D, ` ` U+0020) from Base64 input
before decoding. The canonical form of a Base64-encoded value is a
single unbroken string with no whitespace. After stripping,
implementations MUST use strict Base64 decoding that rejects any
character not in the RFC 4648 standard alphabet (including padding).
In Python, this corresponds to `base64.b64decode(value, validate=True)`.

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
| `key_id` | string | SHA-256 hex of the public key (64 chars, see Section 5.5) |
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

Keys are identified by their `key_id`: the lowercase hex-encoded
SHA-256 hash of the **32-byte raw Ed25519 public key** (not
DER/SubjectPublicKeyInfo encoded).

In code:
```python
raw_bytes = public_key.public_bytes(encoding=Raw, format=Raw)  # 32 bytes
key_id = hashlib.sha256(raw_bytes).hexdigest()                 # 64 hex chars
```

Key files use the key_id as filename:
`{key_id}.key`, `{key_id}.pub`, `{key_id}.meta.json`.

### 5.6 Key File Encoding

Private keys MUST be stored in **PKCS#8 PEM format** (unencrypted).
Public keys MUST be stored in **SubjectPublicKeyInfo PEM format**.

The key_id is computed from the raw 32-byte Ed25519 public key (as
described in Section 5.5), NOT from the PEM or DER encoding.

Example PEM header/footer:
- Private: `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----`
- Public: `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----`

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

Each invariant is resolved to a check implementation in the following
order. The first match wins; no further resolution is attempted.

1. **Explicit `check` field** on the invariant: look up in the check registry
   (or legacy aliases for C1-C5).
2. **Standard `INV_*` ID**: look up in the invariant-to-check map.
3. **Custom evaluator**: look up in the evaluator registry.
4. **Fallback**: record as `NOT_CHECKED`.

When multiple invariants map to the same check implementation, each
invariant produces a separate check execution. The checks run in the
order invariants appear in the constitution.

Standard mappings:

| Invariant ID | Check Implementation |
|-------------|---------------------|
| `INV_NO_FABRICATION` | `sanna.context_contradiction` |
| `INV_MARK_INFERENCE` | `sanna.unmarked_inference` |
| `INV_NO_FALSE_CERTAINTY` | `sanna.false_certainty` |
| `INV_PRESERVE_TENSION` | `sanna.conflict_collapse` |
| `INV_NO_PREMATURE_COMPRESSION` | `sanna.premature_compression` |

### 6.4 Enforcement Levels

Each invariant specifies an enforcement level that determines what
happens when the check fails:

| Level | Behavior |
|-------|----------|
| `halt` | Stop execution, raise error, generate receipt with `enforcement.action = "halted"` |
| `warn` | Continue execution, generate receipt with `enforcement.action = "warned"` |
| `log` | Continue execution, generate receipt with `enforcement.action = "allowed"` |

Enforcement is applied per-check based on the invariant's enforcement
level, not the receipt-level status. A check with `enforcement_level =
"halt"` and `passed = false` triggers a halt regardless of other
checks' results.

### 6.5 Enumerated Values

**Categories:** `scope`, `authorization`, `confidentiality`, `safety`, `compliance`, `custom`

**Severities (check results):** `critical`, `high`, `medium`, `low`, `warning`, `info`

The severity enum serves two purposes:
- Status computation (see Section 2.4): `critical`/`high` produce FAIL, `warning`/`medium`/`low` produce WARN, `info` is neutral.
- Human communication: indicates the seriousness of a check failure.

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

All three hash fields are full 64-character hexadecimal SHA-256 digests
(bare hex, no prefix).

### 7.2 Triad Hash Construction

Each triad hash is computed as follows:

**`input_hash` (and `action_hash` at gateway boundary):**
```
input_obj = {"tool": tool_name, "args": args_without_justification}
input_hash = SHA-256(canonical_json_bytes(input_obj))
```
Where `args_without_justification` is the tool arguments dict with the
`_justification` key removed. The canonical JSON uses Sanna Canonical
JSON (Section 3.1).

Example:
```
tool_name = "API-post-search"
args = {"query": "test", "_justification": "looking for data"}
args_clean = {"query": "test"}
input_obj = {"args": {"query": "test"}, "tool": "API-post-search"}
canonical = '{"args":{"query":"test"},"tool":"API-post-search"}'
input_hash = SHA-256(canonical.encode("utf-8"))
         = "5f2b9d..."  (64 hex chars)
```

**`reasoning_hash`:**
```
reasoning_hash = SHA-256(justification_string.encode("utf-8"))
```
When no justification is provided, use the empty string:
```
reasoning_hash = SHA-256(b"")
             = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

**`action_hash`:**
At the gateway boundary, `action_hash` is identical to `input_hash`
(see Section 7.4).

### 7.3 Assurance Levels

- **`"full"`**: The agent's justification is present and has been
  evaluated by reasoning checks (presence, substance, coherence).
  All three triad hashes are present.
- **`"partial"`**: The agent's justification is absent, empty, or
  reasoning evaluation was skipped. One or more triad hashes MAY be
  absent.

When any triad hash is present, `assurance` MUST also be present.

### 7.4 Absent Triad

When the Receipt Triad is not applicable (e.g., non-gateway receipts
that do not involve tool calls), the triad fields are simply not
present in the receipt. They are not set to `null` and not set to
empty strings -- they are absent from the JSON object entirely.

### 7.5 Gateway Boundary

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
message = "{escalation_id}|{tool_name}|{args_digest}|{issued_at}"
token = hex(HMAC-SHA256(gateway_secret, message.encode("utf-8")))
```

Where:

- **`gateway_secret`** is a per-gateway random secret (bytes), generated
  at gateway startup and held in memory only (or loaded from a
  persistent secret file at `~/.sanna/gateway_secret`).

- **`escalation_id`** is the unique identifier for the pending
  escalation. Format: `esc_` followed by 32 lowercase hex characters
  (a UUID v4 hex string), e.g., `esc_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`.
  The prefix `esc_` distinguishes escalation IDs from other identifiers
  in logs and receipts. Total length: 36 characters.

- **`tool_name`** is the ORIGINAL (unprefixed, un-normalized) name of
  the downstream tool (the `original_name` field of the
  PendingEscalation). This is the tool name as it appears in the
  downstream MCP server, NOT the gateway-prefixed name and NOT the
  authority-normalized name. For example, `API-patch-page` (not
  `notion_API-patch-page` and not `api.patch.page`).

- **`args_digest`** is the SHA-256 hex digest of the tool arguments
  serialized with Python-default `json.dumps(arguments, sort_keys=True)`.
  **This intentionally uses Python default separators** (`(', ', ': ')`,
  i.e., with spaces after commas and colons), NOT Sanna Canonical JSON
  (`(",", ":")`). The HMAC path predates canonical JSON adoption, and
  changing it would invalidate existing tokens. Cross-language
  implementations MUST replicate this exact serialization:
  `json.dumps(arguments, sort_keys=True, ensure_ascii=True, separators=(", ", ": "))`.
  The resulting string is encoded as UTF-8 and hashed with SHA-256.

- **`issued_at`** is an integer epoch timestamp (seconds since Unix
  epoch) stored in the PendingEscalation record. This is an integer,
  not a float, for HMAC reproducibility. It is converted to a decimal
  string (e.g., `1708185600`) for inclusion in the HMAC message.

- **`|`** is the literal pipe character (U+007C) used as field
  separator.

The four message components are concatenated with pipe delimiters and
encoded as UTF-8 before HMAC computation. The result is the lowercase
hex digest of the HMAC-SHA256 (64 hex characters).

**Example:**

```
escalation_id = "esc_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
tool_name     = "API-patch-page"
args_digest   = "e3b0c442..."  (64 hex chars)
issued_at     = 1708185600

message = "esc_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6|API-patch-page|e3b0c442...|1708185600"
token   = HMAC-SHA256(gateway_secret, message.encode("utf-8")).hexdigest()
```

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

| Code | Priority | Meaning |
|------|----------|---------|
| 5 | Highest | Signature verification failure or other verification error |
| 4 | High | Status or count consistency error |
| 3 | Medium | Fingerprint or content hash mismatch |
| 2 | Low | Schema validation failed |
| 0 | None | Valid (no errors) |

The verifier MUST return the highest-priority exit code encountered
during verification. Priority order (highest to lowest): 5 (signature
failure / other error), 4 (consistency error), 3 (fingerprint
mismatch), 2 (schema invalid), 0 (valid). If multiple error types
occur, only the highest-priority code is returned.

In practice, the reference implementation uses early returns: schema
validation failure (exit code 2) terminates before fingerprint checks
(exit code 3), which terminate before consistency checks (exit code 4).
Signature and chain verification errors (exit code 5) are accumulated
and returned if no higher-priority error was found first. This
ordering means that in the common case, the first error encountered
determines the exit code. However, if an implementation defers error
reporting (e.g., to collect all errors before returning), it MUST
select the highest-priority code from all detected errors.

When verifying a single receipt, the CLI returns the exit code from
the verification result. The `sanna-verify` command operates on a
single receipt file per invocation.

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

### 12.3 Threat Model

This section describes the assumed attacker capabilities and the
security boundaries of the Sanna receipt system.

**Assumed attacker capabilities:**

- The attacker controls agent outputs (can produce arbitrary text
  responses and tool call arguments).
- The attacker can read persisted receipts, constitutions, and public
  keys from storage.
- The attacker can submit arbitrary tool call arguments through the
  MCP protocol, including prompt injection attempts.
- The attacker may attempt to replay, forge, or tamper with receipts.

**What Sanna defends against:**

- **Receipt tampering**: Ed25519 signatures and deterministic
  fingerprints detect any modification to signed receipts.
- **Unverifiable governance claims**: A receipt without a valid
  fingerprint and signature cannot be presented as proof of governance.
- **Unauthorized tool execution**: The gateway enforcement proxy
  blocks `cannot_execute` tool calls and requires human approval for
  `must_escalate` tool calls before forwarding.
- **Escalation token forgery**: HMAC-SHA256 binding prevents approval
  tokens from being forged or replayed across different tool calls.
- **Constitution tampering**: Ed25519 constitution signatures detect
  post-signing modifications.
- **Prompt injection in audit fields**: XML entity escaping
  (`escape_audit_content()`) prevents injection through agent-
  controlled content that appears in LLM evaluation prompts.

**What Sanna does NOT defend against:**

- **Compromised runtime**: If the Sanna library itself is modified or
  the process is compromised, receipts can be forged at the source.
  Sanna assumes the runtime environment is trusted.
- **Stolen signing keys**: An attacker with access to the Ed25519
  private key can produce valid signatures on arbitrary receipts.
  Key management (Section 12.4) mitigates but does not eliminate
  this risk.
- **Bypassing Sanna entirely**: If the agent can execute tool calls
  without going through the gateway or middleware, no receipt is
  generated. Sanna is an observational system, not a process
  isolation boundary.
- **Semantic completeness of checks**: The built-in C1-C5 checks are
  heuristic pattern matchers, not formal verification. They catch
  common reasoning failures but do not guarantee correctness.
- **Downstream execution fidelity**: At the gateway boundary, the
  gateway attests to what it forwarded, not what the downstream
  server actually executed.

### 12.4 Key Management

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

### 12.5 Approval Channel Security

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
8. Apply NFC Unicode normalization to all string values before
   canonicalization (Section 3.1).
9. Validate that `correlation_id` does not contain the pipe character
   `|` (Section 2.1).

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

### 13.3 Legacy Receipt Handling

This specification does not cover pre-v0.13.0 receipt formats. Legacy
receipts (those with `schema_version` instead of `spec_version`) are
not valid against the v1.0 schema.

The reference implementation includes backward-compatible verification
of legacy receipts using the variable-length fingerprint formula and
16-hex truncated hashes. Third-party implementations MAY support legacy
verification by implementing the field migration mapping (Appendix A)
and the legacy fingerprint algorithm, but this is not required for
conformance.

---

## 14. Version History

| Spec Version | Tool Version | Changes |
|-------------|-------------|---------|
| 1.0 | 0.13.0 | Initial specification. Field renames: `schema_version` to `spec_version`, `trace_id` to `correlation_id`, `coherence_status` to `status`, `halt_event` to `enforcement`. Added `full_fingerprint`. UUID v4 receipt IDs. Full 64-hex content hashes. 12-field fingerprint formula. Custom evaluator fail-closed default. |
| 1.0.1 | 0.13.0 | 28 precision fixes from cross-platform security review. Key ID uses raw Ed25519 bytes (not DER). NFC normalization documented. Float rejection in signing contexts. hash_text default truncation corrected to 64. Status computation handles all severity levels. Receipt Triad hashing byte-precise. HMAC token format documented. Threat model added. Schemas for authority_decisions, escalation_events, source_trust_evaluations, identity_verification documented. Key file encoding specified. correlation_id pipe constraint. checks_hash ordering and null key rules. |
| 1.0.2 | 0.13.1 | 7 cross-platform review fixes. Redaction Marker schema (Section 2.11): marker structure, original_hash computation, pre-existing marker injection guard, file naming convention, hash recomputation rules. Authority Name Normalization algorithm (Appendix D): NFKC + camelCase splitting + separator normalization + casefold + dot-join, with 16 test vectors, matching semantics, and separatorless fallback. HMAC token binding corrections (Section 8.2): `esc_` prefix on escalation IDs, Python-default separators for args_digest (not Sanna Canonical JSON), original tool name (not normalized). Canonical JSON cross-language guidance (Section 3.1): Go HTML-escaping warning, float rejection clarified for Go/Rust number parsing. Base64 pinned to RFC 4648 standard with padding (Section 5.1), whitespace stripping scope clarified. Exit code accumulation rule: highest-priority code wins (Section 9.2). |

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
| FAIL (critical/high check failed) | `halted` | Execution blocked, output suppressed |
| WARN (warning/medium/low check failed) | `warned` | Execution continued, warning logged |
| PASS (all checks pass) | `allowed` | Execution continued normally |
| -- (`must_escalate` policy) | `escalated` | Execution deferred pending human approval |

The `enforcement.action` field records the action taken by the
governance system. The mapping above describes the typical
correspondence between receipt status and enforcement action. Note that
`escalated` is a policy-driven action that occurs before check
evaluation and is independent of the receipt status.

The enforcement action is determined by the per-check
`enforcement_level` (from the constitution invariant), not the
receipt-level `status`. When multiple checks fail at different
enforcement levels, the most severe enforcement wins:
`halt` > `warn` > `log`. A single check with `enforcement_level =
"halt"` and `passed = false` produces `enforcement.action = "halted"`
regardless of other checks' results.

## Appendix C: Schema References

- Receipt schema: `spec/receipt.schema.json`
- Constitution schema: `spec/constitution.schema.json`
- Golden test vectors: `golden/receipts/v13_*.json`

## Appendix D: Authority Name Normalization

When matching tool/action names against constitution authority
boundaries (`can_execute`, `cannot_execute`, `must_escalate`),
implementations MUST normalize both the action name and the pattern
before comparison. This ensures that stylistic differences in naming
conventions (camelCase, snake_case, kebab-case, etc.) do not cause
false negatives or false positives in authority evaluation.

### D.1 Normalization Algorithm

Given an input name string, produce a normalized form by applying
the following steps in order:

1. **NFKC normalize:** Apply Unicode NFKC normalization (UAX #15)
   to decompose compatibility characters. This collapses fullwidth
   characters (e.g., fullwidth `Ｆ` U+FF26 becomes `F` U+0046),
   ligatures, and other compatibility equivalents into their
   canonical forms.

2. **Split camelCase:** Insert word boundaries at the following
   transitions:
   - **Lowercase to uppercase:** `deleteFile` becomes
     `delete|File`
   - **Letter to digit:** `tool2use` becomes `tool|2|use`
   - **Digit to letter:** `2fast` becomes `2|fast`
   - **Uppercase run before lowercase:** `HTTPSClient` becomes
     `HTTPS|Client`. Specifically, when a run of two or more
     uppercase letters is followed by an uppercase letter and then
     a lowercase letter, the boundary is placed before the last
     uppercase letter in the run.

   In regex terms (applied sequentially):
   ```
   s/([a-z])([A-Z])/\1 \2/g          # lowercase→uppercase
   s/([A-Z]+)([A-Z][a-z])/\1 \2/g    # uppercase run→uppercase+lowercase
   s/([a-zA-Z])(\d)/\1 \2/g          # letter→digit
   s/(\d)([a-zA-Z])/\1 \2/g          # digit→letter
   ```

3. **Split on separators:** Split on the character class
   `[_\-./:@]+` (underscore, hyphen, dot, slash, colon, at-sign).
   One or more consecutive separator characters produce a single
   split. In practice, this is implemented by replacing all
   separator runs with a single space.

4. **Casefold:** Apply Unicode casefold to all tokens. Casefold is
   NOT the same as lowercasing -- it handles special cases like
   German eszett (`ß` casefolds to `ss`). In Python, this is
   `str.casefold()`. In Go, use `strings.ToLower()` (which is
   sufficient for ASCII tool names) or a full Unicode casefold
   library. In Rust, use `.to_lowercase()` on `&str`.

5. **Join:** Strip leading and trailing whitespace from the result,
   then replace all runs of internal whitespace with a single `.`
   (dot) separator. The result is the normalized form.

### D.2 Test Vectors

| Input | Normalized |
|-------|-----------|
| `deleteFile` | `delete.file` |
| `delete_file` | `delete.file` |
| `delete-file` | `delete.file` |
| `DELETE_FILE` | `delete.file` |
| `HTTPSClient` | `https.client` |
| `tool2use` | `tool.2.use` |
| `deleteＦile` | `delete.file` |
| `XMLParser` | `xml.parser` |
| `API-patch-page` | `api.patch.page` |
| `file2delete` | `file.2.delete` |
| `2ndFile` | `2nd.file` |
| `send_email` | `send.email` |
| `send.email` | `send.email` |
| `send/email` | `send.email` |
| `send:email` | `send.email` |
| `send@email` | `send.email` |

Note: `deleteＦile` contains fullwidth `Ｆ` (U+FF26) which NFKC
normalizes to ASCII `F` (U+0046) before camelCase splitting.

### D.3 Matching Semantics

After normalizing both the action name `a` and the pattern `p`:

1. **Exact or substring match:** `a` matches `p` if `a == p` OR
   `p` is a substring of `a` OR `a` is a substring of `p`.

2. **Separatorless fallback:** If no match is found in step 1,
   strip all non-alphanumeric characters from both `a` and `p`,
   then check substring containment in both directions. This
   catches edge cases where separator placement differs between
   the action name and the pattern.

3. **Empty name rejection:** Empty action names (empty string or
   whitespace-only) MUST NOT match any pattern. Implementations
   MUST return "no match" (not "match") for empty actions.

4. **Empty pattern rejection:** Empty patterns (empty string or
   whitespace-only) MUST NOT match any action. An empty pattern
   in a constitution's authority boundaries is an invalid
   constitution and SHOULD be rejected at load time.

### D.4 Match Examples

| Action | Pattern | Match? | Reason |
|--------|---------|--------|--------|
| `deleteFile` | `delete_file` | Yes | Both normalize to `delete.file` |
| `API-patch-page` | `patch` | Yes | `patch` is substring of `api.patch.page` |
| `send_email` | `Send email or post external message` | Yes | Word-boundary matching on significant words |
| `deleteFile` | `createFile` | No | `delete.file` does not contain `create.file` or vice versa |
| `` (empty) | `delete` | No | Empty action always rejected |
| `delete` | `` (empty) | No | Empty pattern always rejected |

### D.5 Relationship to Gateway Policy Cascade

Authority name normalization applies at step 3 of the gateway policy
cascade (Section 8 of the main specification, and as described in the
reference implementation's gateway documentation):

1. **Per-tool override:** Exact match on the ORIGINAL (unprefixed)
   tool name from the gateway config `tools:` map. No normalization
   is applied at this step.
2. **Server default_policy:** The `default_policy` field on the
   downstream server entry. No name matching is involved.
3. **Constitution authority boundaries:** `evaluate_authority()` uses
   the normalization algorithm described in this appendix for
   bidirectional substring matching against `cannot_execute`,
   `must_escalate`, and `can_execute` lists.

Per-tool overrides use exact string matching on the original tool name
because the config author controls both the tool name and the override
entry. Constitution authority boundaries use normalized matching
because the constitution author may not know the exact tool naming
convention of every downstream server.
