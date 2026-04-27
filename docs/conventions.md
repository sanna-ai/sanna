# Conventions — Environment, Testing, Pitfalls, Release

## Environment Variables

| Variable | Default | Module | Purpose |
|----------|---------|--------|---------|
| `SANNA_CONSTITUTION_PUBLIC_KEY` | (none) | `middleware.py`, `mcp/server.py`, `gateway/server.py` | Public key for verifying constitution signature |
| `SANNA_JUDGE_PROVIDER` | auto-detect | `reasoning/judge_factory.py` | LLM judge provider: `"anthropic"`, `"openai"`, or `"heuristic"` |
| `SANNA_LLM_MODEL` | provider default | `reasoning/llm_client.py`, `reasoning/checks/glc_005_coherence.py` | Model name for LLM coherence evaluation |
| `ANTHROPIC_API_KEY` | (none) | `evaluators/llm.py`, `reasoning/judge_factory.py` | Anthropic API key (auto-detected by JudgeFactory) |
| `OPENAI_API_KEY` | (none) | `reasoning/judge_factory.py` | OpenAI API key (auto-detected by JudgeFactory) |
| `SANNA_GATEWAY_SECRET` | (none) | `gateway/server.py` | HMAC-SHA256 secret for approval tokens (hex, exactly 32 bytes) |
| `SANNA_INSECURE_FILE_TOKENS` | `"0"` | `gateway/config.py` | Set `"1"` for file-based token delivery |
| `SANNA_ALLOW_INSECURE_WEBHOOK` | `"0"` | `gateway/config.py` | Set `"1"` for HTTP webhooks to localhost/127.0.0.1 only |
| `SANNA_ALLOW_TEMP_DB` | `"0"` | `store.py` | Set `"1"` for temporary in-memory SQLite (test use) |
| `SANNA_SKIP_DB_OWNERSHIP_CHECK` | `"0"` | `store.py` | Set `"1"` to skip SQLite ownership check (Docker containers) |
| `SANNA_MAX_STORED_PAYLOAD_BYTES` | `65536` | `gateway/receipt_v2.py` | Max bytes for stored receipt payloads before truncation |

### JudgeFactory provider resolution cascade

1. Explicit `provider` / `model` / `api_key` arguments
2. Constitution `judge` config (`default_provider`, `cross_provider`)
3. `SANNA_JUDGE_PROVIDER` environment variable
4. Auto-detect: check `ANTHROPIC_API_KEY`, then `OPENAI_API_KEY`
5. Fall back to `HeuristicJudge` (no API needed)

---

## Testing Rules

- Run `pytest` for current pass/fail counts. `docs/state.md` tracks test file count.
- Optional dependency tests MUST use `pytest.importorskip()` — CI does not install extras (`mcp`, `httpx`, `opentelemetry`).
- Golden receipts: NEVER use `--update-golden-receipts` unless intentionally changing receipt format.
- Float values in golden receipts: use integers to avoid hash instability.
- Tests using custom evaluators MUST call `clear_evaluators()` in fixtures to avoid registry leaks (`_EVALUATOR_REGISTRY` in `evaluators/__init__.py` is module-level).
- New test files for new modules (e.g., `tests/test_otel_exporter.py`).
- Gateway tests require `mcp` extra — use `pytest.importorskip("mcp")` at top of gateway test files.
- `tests/reasoning/` — 6 files covering deterministic checks, LLM coherence, pipeline, prompt security.
- Golden vectors: `tests/vectors/`; golden receipts: `golden/receipts/`.
- Follow conventions in CONTRIBUTING.md for all new code, checks, adapters, and schema changes.

---

## Common Pitfalls

**Schema drift:** If you change constitution or receipt format, update BOTH schema files (`src/sanna/spec/`) and sync the root `spec/` copies.

**Fingerprint divergence:** Any field added to receipt fingerprint in `middleware.py` MUST also be added in `receipt.py` AND `verify.py` AND `gateway/server.py`. `constitution_approval` must be stripped in ALL FOUR locations. See "Fingerprint Construction" in ARCHITECTURE.md for exact field order.

**Import crashes:** Never import optional packages (`mcp`, `httpx`, `opentelemetry`) at module level without `try/except ImportError` guards.

**Signing scope changes:** If you add fields to constitution or receipt, verify they're included in the signing material. Approval signatures cover all `ApprovalRecord` fields except `approval_signature` itself (blanked to `""`).

**LLM evaluator errors:** LLM evaluators MUST raise exceptions on failure (not return failed `CheckResult`). Returning a failed `CheckResult` would cause false halts.

**Evaluator registry is global:** Tests MUST use `clear_evaluators()` in fixtures to avoid cross-test contamination. `register_invariant_evaluator()` raises on duplicate registration unless using the idempotent `register_llm_evaluators()` path.

**Version bump:** Update `version.py`, `pyproject.toml`, and all test files that assert the version string (search for the old version in `tests/`).

**Store schema version:** If the receipts table schema changes, increment `_SCHEMA_VERSION` in `store.py`. Existing databases with a different version will raise `ValueError` on open.

**Approval chain return types:** `_verify_approval_chain()` and `verify_constitution_chain()` return `(errors, warnings)` tuples, not flat lists. All callers must unpack both values.

**EscalationRule is not hashable:** `EscalationRule` dataclass instances cannot be used in `set()`. Use `item.condition` for set-based comparisons.

**constitution_approval always present:** Since v0.9.0, `constitution_to_receipt_ref()` always includes `constitution_approval`. Tests that check for absence must check for `{"status": "unapproved"}` instead.

**Identity claims dual representation:** `AgentIdentity.identity_claims` (structured list) must stay in sync with `AgentIdentity.extensions["identity_claims"]` (raw dicts for signing). `_identity_dict()` has a sync fallback.

**Z-suffix timestamps:** Python 3.10 `datetime.fromisoformat()` does NOT accept "Z" suffix. Always normalize with `.replace("Z", "+00:00")` before parsing.

**identity_verification is NOT in fingerprint:** Always present when the constitution has identity_claims. Assert `verified == 0` when no provider keys given — not field absence.

**Key filenames use key_id:** Since v0.9.1, `generate_keypair()` uses the SHA-256 key fingerprint as the filename (not `sanna_ed25519`).

**Gateway receipt signing key:** The gateway signs its own receipts with a dedicated key (`sanna-keygen --label gateway`). Do not reuse constitution keys.

**MCP client vs server:** The gateway is BOTH — a FastMCP server facing upstream (Claude) and an MCP client facing downstream (Notion, GitHub, etc.). Keep these roles cleanly separated.

**Policy evaluation before forwarding:** Enforcement happens BEFORE the tool call is forwarded. A `cannot_execute` policy never touches the downstream server. A receipt is still generated.

**Authority boundary evaluation order:** `cannot_execute` (tool names only) → `must_escalate` (full action context) → `can_execute` (tool names only). First match wins. Command patterns (`sudo`, `rm -rf`) belong in `must_escalate` conditions, not `cannot_execute`.

**Tool namespace separator is underscore:** Gateway uses `_` (not `/`) to separate `{server}_{tool}`. Slashes are rejected by Claude Desktop's tool name pattern `^[a-zA-Z0-9_-]{1,64}$`.

**Policy cascade order matters:** Per-tool override > `default_policy` > constitution keyword matching. Without `default_policy`, tools fall through to constitution keyword matching, which can produce false positives.

**Authority decisions need timestamps:** Every `authority_decisions` record in gateway receipts MUST include a `timestamp` field. Omitting it causes schema validation failure.

**Notion MCP uses `OPENAPI_MCP_HEADERS`:** NOT `NOTION_API_KEY`. Format: `{"Authorization":"Bearer ntn_TOKEN","Notion-Version":"2022-06-28"}`.

**MCP SDK env merging:** `stdio_client` does NOT inherit full `os.environ`. All required env vars must be explicitly passed.

**Float arguments in gateway receipts:** RFC 8785 canonical JSON rejects floats. Gateway catches `TypeError` and falls back to `json.dumps(sort_keys=True)`. The `arguments_hash_method` extension field records which path was used.

**Tool output extraction:** Never access `.content[0].text` directly on MCP `CallToolResult`. Use `_extract_result_text()`.

**Escalation approve-then-execute:** `_handle_approve()` marks status "approved" before executing, then removes on success or marks "failed" on exception. Never remove before execution.

**Unsigned constitutions rejected at runtime:** Since v0.12.4, `@sanna_observe` raises `SannaConstitutionError` for hashed-only (not Ed25519 signed) constitutions. Tests that use constitutions must sign them first.

**`parent_receipts` uses `is not None`, not truthiness:** `[]` (explicitly no parents) and `None` (field absent) produce different hashes. This is intentional.

**`content_mode` and `content_mode_source` are NOT in the fingerprint:** Metadata-only fields for Cloud attestation; excluded from hash.

**`correlation_id` replaces `trace_id` in fingerprint (v0.13.0):** Fingerprint field 1 is `correlation_id`. Legacy receipts still use `trace_id`.

**`enforcement_hash` replaces `halt_hash` in fingerprint (v0.13.0):** Field 7. `Enforcement` dataclass replaces `HaltEvent`.

**Two webhook implementations must both be hardened:** `enforcement/escalation.py` and `gateway/server.py` are independent code paths. See docs/security-hardening.md INV-11.

**README examples must work under defaults:** Never disable a security default to make an example shorter. Show the correct configuration (e.g., `public_key_path=...`).

**Spec text must match code behavior exactly:** When editing spec text, read the implementation first. Third-party Go/Rust implementers will build to the spec text, not the Python source.

**`SPEC_VERSION` field:** `receipt.py` constant is now `SPEC_VERSION = "1.4"`. Receipt JSON uses `spec_version` field, not `schema_version`. See `sanna-protocol/VERSIONING.md` for skip-version policy.

**CloudHTTPSink retry semantics:** 400/401/403 are never retried (client errors). 409 is treated as success (duplicate). 429/503/5xx are retried with exponential backoff.

**Golden receipt generators:** `golden/generate_golden.py` is the primary generator (produces UUID receipt_ids). The root `generate_golden.py` produces hash-based receipt_ids that fail UUID schema validation — do not use it.

---

## Execution Discipline (agents and batch remediation)

These rules exist because of documented failures in the v0.13.2 audit:

1. **File-level verification:** When a prompt names a specific file, grep that exact file AFTER making changes. Sanna has multiple modules with overlapping concerns (`enforcement/escalation.py` vs `gateway/server.py` both handle webhooks).

2. **Per-fix verification:** When a prompt contains N numbered fixes, verify each one individually. A fix is not done until `grep` confirms the specific change.

3. **Never weaken security defaults:** If a prompt says "make this example work under defaults" and the default is a security check, show the user how to satisfy the check — not how to disable it.

4. **Spec claims must be scoped to code reality:** If the code normalizes at one boundary, say "at this boundary" — not "everywhere."

5. **Cross-file hardening completeness:** Security fixes that apply to a pattern require grepping the entire codebase. Use `grep -rn "urlopen\|httpx.Client\|httpx.AsyncClient" src/` to find all instances.

---

## Post-Release Checklist

After every version bump and successful publish to PyPI:

1. Update `src/sanna/version.py` (single source of truth).
2. Update `pyproject.toml` version field.
3. Update all test files that assert the version string (search for old version in `tests/`).
4. Update `CHANGELOG.md` with a new entry.
5. Regenerate `docs/state.md`: `python3 tools/generate_state_doc.py`.
6. Verify `--check` mode exits 0: `python3 tools/generate_state_doc.py --check`.
7. Do NOT update `ARCHITECTURE.md` version literals manually — extend it when functionality changes.

**The PyPI test:** If `pip install sanna==X.Y.Z` would have returned the pre-fix code to a real user, the fix MUST be a new version. If not, fold it in.

**Git discipline:** Even when folding pre-publish fixes, commit them separately. Git history is the internal audit trail; PyPI versions are the public contract.

**Versioning rules** (normative): See `sanna-protocol/VERSIONING.md`.

---

## Commit Style

- Use the conventional commits format: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`.
- Reference the ticket ID in the commit message: `[SAN-NNN]`.
- Do not embed notion.so URLs in commit messages — repos are public.
- Do not use `--no-verify`. If a hook fails, diagnose and fix before committing.
