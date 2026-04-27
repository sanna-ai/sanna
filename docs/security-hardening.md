# Security Hardening — Key Design Invariants

This document is the load-bearing safety reference for the Sanna Python SDK.
It captures the 12 invariants that are enforced at runtime and verified in
tests. Auditors reviewing the SDK should start here.

Each invariant names the affected modules, the enforcement mechanism, and the
test coverage. The invariants are not aspirational — violating any of them
breaks the product's core guarantee (receipts mean what they say).

---

## INV-1: Fingerprint parity across all emit sites

`middleware.py`, `receipt.py`, `verify.py`, and `gateway/server.py` MUST
compute identical fingerprints for the same input at a given `checks_version`.
The formula dispatches by cv: **20 fields at cv=9 (v1.4)**, 16 at cv=8 (v1.3),
14 at cv=6/7 (v1.0/v1.1), 12 at cv≤5 (pre-v1.0). Same cv-dispatch ladder,
same `constitution_approval` stripping, same `is not None` checks for
`parent_receipts` and `workflow_id`.

**Why it matters:** A verifier that recomputes a different fingerprint than the
emitter would reject legitimate receipts or accept forged ones. Divergence is
silent — the receipt passes schema validation either way.

**Enforcement:** `tests/test_fingerprint_edge_cases.py`,
`tests/test_v14_integrity.py`, `tests/test_v13_integrity.py`.

**Common failure mode:** Adding a new field to the fingerprint in one emit
site but not the other three. See "Fingerprint Construction" in ARCHITECTURE.md
for the exact field order.

---

## INV-2: constitution_approval stripped before fingerprinting

`constitution_approval` is stripped from `constitution_ref` before computing
the fingerprint hash in ALL THREE emit sites: `middleware.py`,
`receipt.py:generate_receipt()`, and `verify.py:_verify_fingerprint_v013()`.

**Why it matters:** Approval metadata is mutable — it can be added or revoked
after the constitution is signed. Including it in the fingerprint would make
receipts non-deterministic across the approval lifecycle.

**Enforcement:** Tests assert that adding or removing approval records on a
constitution does not change the fingerprint of receipts generated against it.

---

## INV-3: Signing scope integrity

- **Constitution signature** covers: identity (with extensions flattened),
  invariants, authority_boundaries, escalation_targets, trusted_sources.
- **Receipt signature** covers everything in the receipt JSON except
  `signature.value` itself.
- **Approval signature** covers all `ApprovalRecord` fields except
  `approval_signature` (blanked to `""` before signing).

**Why it matters:** Unsigned fields are not cryptographically bound. A signer
that omits required fields produces signatures that can be re-used on modified
documents.

**Enforcement:** `tests/test_crit02_constitution_sig.py`,
`tests/test_crypto_integrity.py`.

---

## INV-4: Approval is mutable metadata, verified separately

`constitution_approval` can be added or revoked after constitution signing. It
is NOT part of the fingerprint hash. It is verified by:
1. Recomputing `content_hash` over the constitution body.
2. Verifying the `approval_signature` against the approver's public key.

`constitution_ref.constitution_approval` is always present in receipts: either
`{"status": "unapproved"}` for unsigned/unapproved constitutions, or the full
record.

**Why it matters:** A receipt that silently omits approval status can be used to
hide that the constitution was never formally approved.

**Enforcement:** `tests/test_approval.py`, `tests/test_bundle_approval.py`.

---

## INV-5: Bundle key independence

Receipt and constitution keys are resolved independently by `key_id` in
`verify_bundle()`. The `constitution_public_key_path` parameter on
`create_bundle()` exists precisely for the case where the constitution was
signed by a different key than the receipt.

**Why it matters:** A bundle verifier that assumes one key covers both receipt
and constitution silently skips constitution signature verification when a
different key is used.

**Enforcement:** `tests/test_bundle.py`.

---

## INV-6: Optional dependencies must be guarded at import time

`mcp`, `httpx`, and `opentelemetry` are NOT base dependencies. Any import of
these packages at module level will cause an `ImportError` for users who
installed `pip install sanna` without extras. All imports must be guarded with
`try/except ImportError` (in production code) or `pytest.importorskip()` (in
tests).

**Why it matters:** An unguarded import in a module that ships in the base
package would break `import sanna` for all users who haven't installed extras.

**Enforcement:** CI runs the full test suite without installing extras. Any
unguarded import is caught immediately.

---

## INV-7: Non-evaluated checks excluded consistently

`_NON_EVALUATED = ("NOT_CHECKED", "ERRORED")` — this constant is used
consistently in `middleware.py`, `verify.py`, and `drift.py`. ERRORED and
NOT_CHECKED checks are excluded from pass/fail counts and status computation
everywhere.

**Why it matters:** Counting ERRORED checks as failures would cause false
enforcement halts when a custom evaluator encounters a transient error.
Counting them as passes would silently drop checks from the audit trail.

**Enforcement:** `tests/test_verify_errored.py`.

---

## INV-8: LLM evaluator independence

LLM semantic invariants (`INV_LLM_*`) are distinct from built-in C1-C5. They
use separate IDs, separate aliases (`LLM_C1`–`LLM_C5`), and evaluate different
semantic properties. They must never be conflated with the built-in checks.

LLM evaluators **must raise exceptions** on failure — they must NOT return a
failed `CheckResult`. The middleware exception handler catches exceptions from
`source="custom_evaluator"` and produces `ERRORED` status with `passed=True`.
Returning a failed `CheckResult` would cause false halts.

**Enforcement:** `tests/test_evaluators_llm.py`.

---

## INV-9: Approval verification severity

- Pending or revoked approval statuses → **warnings**, not errors.
- Missing approver key with a valid signature → **warning** ("signature not
  verified").
- `content_hash` mismatches, forged/empty signatures, failed key verification
  → **errors**.

**Why it matters:** Treating pending approval as an error would reject
receipts from constitutions in the process of being approved — a false
positive. Treating a forged signature as a warning would silently accept
tampered approval records.

**Enforcement:** `tests/test_approval_v2.py`.

---

## INV-10: Identity verification is separate from fingerprint

`identity_verification` in receipts is NOT included in the fingerprint hash.
It is always present when the constitution has `identity_claims`, regardless
of whether provider keys are supplied. When no keys are supplied, the
`verified` count is 0 — not absent.

**Why it matters:** Identity verification depends on external provider keys
that may not be available at every verification site. Including it in the
fingerprint would make receipts non-deterministic across key availability.

**Enforcement:** `tests/test_identity_claims.py`.

---

## INV-11: Two separate webhook implementations must both be hardened

`enforcement/escalation.py` has `_execute_webhook()`, `_execute_webhook_async()`,
and `_webhook_threaded_fallback()` for constitution-level escalations.
`gateway/server.py` has `_deliver_token_via_webhook()` for gateway
approval-token delivery. These are **independent code paths** — hardening one
does NOT harden the other.

Any webhook security fix (SSRF validation via `validate_webhook_url()`,
redirect blocking, response size limits) must be applied to **both** files.

**Why it matters:** A partial fix creates the illusion of security while
leaving an active exploit path open.

**Enforcement:** `tests/test_v132_webhook.py`, `tests/test_v132_ssrf.py`.

---

## INV-12: File writes use safe_io exclusively

All file write operations must use `atomic_write_text_sync()` from
`sanna.utils.safe_io` for symlink protection and crash safety. Never use raw
`open()` for writes in production code.

**Why it matters:** A direct `open(path, "w")` call on a path that resolves
through a symlink is a TOCTOU vulnerability — an attacker can swap the symlink
between the existence check and the write. The atomic writer uses `O_NOFOLLOW`
and `os.replace()` to eliminate this window.

**Enforcement:** `tests/test_safe_io.py`, `tests/test_crit03_redaction.py`.

---

## Claim signing canonical form

`_claim_to_signable_dict()` in `constitution.py` conditionally omits
`expires_at` when falsy, ensuring canonical representation for Ed25519
verification. The signed payload uses `canonical_json_bytes()` (RFC 8785).

Python 3.10 `datetime.fromisoformat()` does NOT accept "Z" suffix — always
normalize with `.replace("Z", "+00:00")` before parsing ISO 8601 timestamps.

---

*See ARCHITECTURE.md §4 for data model details and §3 for data flow diagrams.*
*See docs/conventions.md for testing rules and common pitfalls.*
