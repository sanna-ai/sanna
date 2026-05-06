## [Unreleased] -- 2026-05-06 (SAN-406)

### Added
- `src/sanna/anomaly.py`: `redact_attempted_field(value, content_mode)` helper
  implementing Section 2.22.5 single-value redaction for com.sanna.anomaly
  extension emissions. Three modes: "full"/None (raw, current behavior
  preserved), "redacted" (literal `<redacted>`), "hashes_only" (SHA-256 hex
  lowercase via canonical `hash_text`). Empty/falsy `content_mode` treated as
  "full" (defensive permissive behavior for sentinel values).
- Verifier semantic check `redaction_markers_correct` in
  `src/sanna/verify_manifest.py`. Runs from both
  `verify_session_manifest_receipt` and `verify_invocation_anomaly_receipt`.
  Under `content_mode=redacted`, every list value (manifest) and every
  `attempted_*` value (anomaly) MUST equal `<redacted>`; under
  `hashes_only`, every value MUST match 64-hex-lowercase. Subsumes
  SAN-439 scope; that ticket is superseded by SAN-406.
- Tests: `tests/test_anomaly_redaction.py` (9 helper unit tests),
  `TestRedactionMarkersCorrect` in `tests/test_verify_manifest.py` (11 tests),
  gateway redaction integration tests in `test_session_manifest_parent_chain.py`
  (4 tests for redacted + hashes_only modes via _make_gateway stub).

### Fixed
- `subprocess_interceptor.py:1917`, `http_interceptor.py:1047`, and
  `gateway/server.py:2611`: `attempted_command` / `attempted_endpoint` /
  `attempted_tool` now apply Section 2.22.5 field-level redaction at
  emission time. Closes AUDIT-008 (CRITICAL): `content_mode=redacted` was
  silently emitting raw capability names, leaking the very strings
  operators configured the mode to suppress.

### Changed
- Removed "spec-ahead-of-impl" comments at `subprocess_interceptor.py:1930`
  and the analogous block in `http_interceptor.py` (Section 2.22.5
  is no longer spec-ahead-of-impl in this SDK).
- Verifier check named `redaction_markers_correct` (not
  `manifest_redaction_markers_correct` per SAN-439's original spec) since
  the implementation covers both com.sanna.manifest and com.sanna.anomaly
  extensions; the neutral name is more accurate.
- Helper `redact_attempted_field` accepts empty/falsy `content_mode` as raw
  mode (treated identically to None/"full"). Defensive permissive behavior
  for sentinel values used by some test stubs (gateway server.py constructor
  sets `self._content_mode = ""` when not configured).
- `_make_gateway` test helper adds `_content_mode_source = None` so tests
  can override `_content_mode` post-construction without tripping
  AttributeError.
- 6 integration tests in `TestCliAnomalyRedaction` (test_cli_anomaly.py)
  and `TestHttpAnomalyRedaction` (test_http_anomaly.py) are skipped with
  cite to SAN-487. Discovery during SAN-406 PR 1: under
  `content_mode=redacted`, CLI/HTTP interceptors populate
  `_state["suppressed_patterns"]` from the redacted manifest, so
  `"rm" in {"<redacted>"}` returns False and enforcement silently fails.
  This is an authority bypass (more severe than the original AUDIT-008
  leak); SAN-487 is the design-gap fix. SAN-406's emission redaction
  still ships and works for the gateway path; the CLI/HTTP integration
  coverage waits on SAN-487. Test code is preserved (skip, not delete) so
  SAN-487 can re-enable by removing the decorator.

### Security
- Closes the AUDIT-008 emission gap on the Python side. The TS mirror
  lands in PR 2; cross-SDK fixture in PR 3; CI consumption in PRs 4 + 5.
- `hashes_only` mode is for audit-time deterministic comparison, NOT
  privacy. SHA-256 of short capability names ("ls", "/api/users", etc.)
  is rainbow-table reversible. Operators relying on strong privacy MUST
  use `redacted`.
- Receipts emitted under `redacted` or `hashes_only` modes will have
  different `extensions_hash` (Field 12 of the fingerprint formula) than
  pre-SAN-406 receipts of the same observation. This is correct semantics
  (different content, different fingerprint); operators upgrading should
  expect new fingerprints on re-emission.

### Tickets
- SAN-406 PR 1 of 5 (this entry; sanna-repo emission + verifier check).
  PR 2 (sanna-ts mirror), PR 3 (sanna-protocol fixture), PR 4 (sanna-repo
  fixture consumption), PR 5 (sanna-ts fixture consumption) follow.
- Supersedes SAN-439 (verifier check ticket).
- Discovered SAN-487 (CRITICAL authority bypass): CLI/HTTP interceptors
  populate `_state["suppressed_patterns"]` from the post-redaction manifest
  when `content_mode` is set, rendering anomaly enforcement inoperative.
  Separate ticket; separate fix.

## [Unreleased] -- 2026-05-06 (SAN-485)

### Added
- `tests/test_bundle_trust_anchor_vectors.py`: consumes the cross-SDK fixture
  `spec/fixtures/bundle-trust-vectors.json` (added to sanna-protocol in SAN-403
  PR 3 of 3 at commit 6795979). Asserts every vector's expected `valid` and
  `trust_anchored` against the actual `verify_bundle()` verdict. 12 tests:
  fixture-presence canary, well-formedness, bidirectional vector-ID-set
  contract, 2 bundle internal-reference sanity assertions, and 7 parametrized
  vector cases.

### Changed
- Bumped `spec` submodule pin from baa517f to 6795979. The bump pulls in
  sanna-protocol commits SAN-381 (R1 aggregate_suppression_reasons schema
  rule), SAN-383 (A1' cv<10 forbids agent_identity schema rule), SAN-372
  (archive escalated.json regression guard), SAN-373 (spec Section 2.17.2 ->
  2.18.4 cross-reference), in addition to SAN-403 PR 3. Runtime already
  implements these rules; the bump is a schema-resync, not a behavior change.
  Verified by full test suite green post-bump with no new failures vs
  pre-bump baseline.
- Synced operational schema copies in `src/sanna/spec/` to match the bumped
  submodule.
- `tests/test_wire_format_no_nulls.py::test_plain_asdict_includes_agent_identity_null_regression`:
  relaxed the `pytest.raises(ValidationError, match=...)` regex from the
  old jsonschema phrasing ("None is not of type 'object'") to a stable
  substring match ("None") that holds across the SAN-383 A1' rule's
  if/then/false restructuring. Semantic enforcement is unchanged
  (cv<10 + agent_identity=null is still rejected); only the library's error
  message format changed. The relaxed match is also robust to future
  jsonschema phrasing drift.

### Tickets
- SAN-485 (this entry). Closes the "run by both SDK CIs" acceptance criterion
  of SAN-403 on the Python side. SAN-486 lands the same consumption in
  TypeScript.

## [Unreleased] -- 2026-05-05 (SAN-403)

### Added
- `verify_bundle(..., trusted_key_ids=...)` parameter. When provided, the
  bundle's receipt key_id and every constitution signature key_id must
  appear in the supplied set or verification fails closed. Empty set is
  the explicit "trust nothing" signal.
- `--trusted-key-ids <FILE>` CLI flag and `SANNA_TRUSTED_KEY_IDS`
  environment variable on `sanna bundle-verify`. File format:
  newline-separated 64-hex key_ids, lowercase, `#` comments allowed.
  Malformed lines reject with line number; empty file rejects.
- `BundleVerificationResult.trust_anchored` boolean indicating whether the
  verdict was evaluated against an external anchor (regardless of pass/fail).
- Warning banner printed to stderr when no anchor is supplied (and
  `trust_anchored: false` in `--json` output). Operators see that the
  verdict is self-consistent only -- the bundle internally agrees but no
  external authority confirms the key_id's identity claim.

### Security
- Closes the bundle-forge attack vector at the verifier level. An adversary
  who re-signs a genuine receipt + constitution with their own key and
  repackages the bundle would, prior to this change, get a `valid=true`
  verdict. With a trust anchor, the forgery is now caught. Without an
  anchor, the warning makes the limitation visible. Approval signature
  key_ids are NOT yet checked against the trust anchor (known limitation).

### Tickets
- SAN-403 PR 1 of 3 (this entry). PR 2 (TypeScript SDK in sanna-ts) and
  PR 3 (sanna-protocol cross-SDK forged-bundle fixture + spec/SECURITY.md
  updates) follow.

## [Unreleased] -- 2026-05-03 (SAN-396)

### Added
- Bidirectional emission-verifier integration: test_session_manifest_
  parent_chain.py now runs SAN-358 verify_session_manifest_receipt and
  verify_invocation_anomaly_receipt on captured gateway emission outputs.
  Asserts zero FAIL checks. Catches emission-shape drift that hand-
  crafted fixtures would miss.

### Tickets
- SAN-396 (this entry).

## [Unreleased] -- 2026-05-03 (SAN-380)

### Fixed
- Gateway handle_list_tools: session_manifest emission protected by
  asyncio.Lock with double-checked locking. Fixes race condition
  where concurrent tools/list calls could emit duplicate manifests.
  Second concurrent call now WAITS for emission to complete before
  returning tools (no TOCTOU gap).

### Tickets
- SAN-380 Prompt A (this entry; Python half).

## [Unreleased] -- 2026-05-03 (SAN-379)

### Fixed
- CLI + HTTP interceptors: enforcement.enforcement_mode now emits
  schema-conformant values (halt/warn/log) instead of interceptor
  mode values (enforce/audit/passthrough). Mapping: enforce->halt,
  audit->warn, passthrough->log.
- Added jsonschema validation to interceptor tests (regression gate).

### Tickets
- SAN-379 (this entry).

## [Unreleased] -- 2026-05-02 (SAN-397)

### Added
- `AnomalyTracking` dataclass + `AuthorityBoundaries.anomaly_tracking` field
  (per-surface opt-in for CLI/HTTP invocation_anomaly emission). Default: both
  false (backward compat).
- CLI interceptor: when `anomaly_tracking.cli == True`, suppressed-command
  attempts emit `cli_invocation_anomaly` receipt (substitutes for
  `cli_invocation_halted`). Extensions: `com.sanna.anomaly.attempted_command`.
  parent_receipts chains to active CLI session_manifest.
- HTTP interceptor: when `anomaly_tracking.http == True`, suppressed-endpoint
  attempts emit `api_invocation_anomaly` receipt (substitutes for standard
  halted receipt). Extensions: `com.sanna.anomaly.attempted_endpoint`.
  parent_receipts chains to active HTTP session_manifest.
- Spec submodule bumped to SAN-397 Prompt A (constitution.schema.json
  gains anomaly_tracking field).

### Hash backward-compat
- `constitution_to_signable_dict` omits `anomaly_tracking` when at defaults
  (both false). Pre-v1.5 constitutions hash IDENTICALLY without re-signing.

### Cross-SDK
- Extension shape matches SAN-395 Section 2.22.2 reserved field names.
- content_mode set on receipt envelope only (Section 2.22.5 field-level
  redaction is spec-ahead-of-impl, consistent with gateway server.py:2508).
- Prompt C (TS mirror) will replicate byte-for-byte.

### Tickets
- SAN-397 Prompt B (this entry; Python half).
- Companion: SAN-397 Prompt A (protocol, PR #27 merged), Prompt C (TS).

## [Unreleased] -- 2026-05-02 (SAN-359)

### Fixed
- Gateway `handle_list_tools` now returns empty tools list when
  `_emit_session_manifest` fails (generation or persistence). Previously
  the gateway caught manifest failures silently and still returned the
  full filtered tool list -- a governance leak where the agent could
  discover and invoke tools without a valid manifest on record.
- `_manifest_failed` state is sticky: once manifest fails, ALL subsequent
  `tools/list` calls return empty for the gateway lifecycle. Gateway must
  be restarted with a working constitution/sink to recover.
- FAIL-status session_manifest receipt still emitted on best-effort basis
  (audit trail of the failure), but the agent-facing response is empty.
- Belt-and-suspenders: `handle_list_tools` wraps `_emit_session_manifest`
  in try/except as catch-all for unexpected failures.

### Security
- Per PRD CT-7 (fail-closed) and Codex addendum: 'If manifest persistence
  fails in enforce mode, fail closed.' No tool-name data leaks to the agent
  on manifest failure; the response is an empty tools array.

### Tickets
- SAN-359 Prompt A (this entry; Python half).
- Companion: SAN-359 Prompt B (TypeScript mirror).

## [Unreleased] -- 2026-05-02 (SAN-358)

### Added
- New module `src/sanna/verify_manifest.py` with `verify_session_manifest_receipt()` (9 checks) and `verify_invocation_anomaly_receipt()` (3 checks). Implements verifier-side semantic enforcement of v1.5 Section 2.20 (com.sanna.manifest extension shape + determinism), Section 2.21 (suppression_reason enum), and Section 2.12 (parent_receipts binding for invocation_anomaly).
- New public function `verify_receipt_set(receipts, schema, public_key) -> dict[receipt_id, VerificationResult]` in `src/sanna/verify.py`. Per-receipt verification + cross-receipt parent-resolution for anomaly receipts. Backward-compat: existing `verify_receipt()` signature unchanged.
- `verify_receipt()` dispatches on `event_type` to invoke session_manifest checks. Receipts without event_type (cv=9 / pre-v1.5) skip the new dispatch entirely.
- CLI: `sanna verify --receipt-set <pattern>` invokes verify_receipt_set. `--json-detailed` flag emits per-check machine-actionable verdict output for customer-equipping reproducibility.

### Compatibility
- `verify_receipt(receipt)` signature unchanged; external callers continue to work.
- cv=9 receipts: no behavior change (no event_type field, dispatch skipped).
- AARM report (`aggregate_aarm_report` from SAN-368) unchanged. SAN-358 checks are downstream of AARM Core (R1-R6) and live in verify_receipt(), preserving the public AARM Conformance claim boundary per spec Section 14.

### Cross-SDK
- Check.message text is stable and intended for byte-equal mirror in TS verifier (companion ticket SAN-358 Prompt B).
- Cross-language verdict fixture authored in companion ticket SAN-358 Prompt C (sanna-protocol).

### Tickets
- SAN-358 Prompt A (this entry; Python half).
- Companion: SAN-358 Prompt B (TS mirror), SAN-358 Prompt C (sanna-protocol verdict fixture).
- Adjacent: SAN-394 (TS schema-validator gap; orthogonal; tracked separately).

## [Unreleased] -- 2026-05-02 (SAN-368)

### Added
- **`sanna-verify aarm` CLI subcommand** mechanically verifies AARM Core (R1-R6) conformance on a receipt set. Per spec Section 14, this CLI makes the public conformance claim mechanically verifiable: `sanna-verify aarm <files-glob> [--format json|human] [--public-key <path>]`. Exit 0 on PASS or PARTIAL, exit 1 on FAIL.
- **`src/sanna/aarm.py`** module with: `SANNA_TO_AARM` decision-enum mapping table (code primitive per SAN-356 G2); six per-requirement check functions (`check_r1_pre_execution_interception`, `check_r2_context_accumulation`, `check_r3_policy_evaluation`, `check_r4_decisions` with STEP_UP chain check, `check_r5_tamper_evident` with redacted-receipt acceptance, `check_r6_identity_binding` with cv-aware PASS/PARTIAL/FAIL dispatch); `aggregate_aarm_report` aggregator; `format_aarm_report` for JSON and human-readable output.
- **R6 dispatch** per SAN-371 + SAN-370: cv=10 receipts with `agent_identity.agent_session_id` -> PASS contribution; cv=9 receipts -> PARTIAL contribution (consistent with the CV9_LEGACY warning); cv=10 receipts missing `agent_identity` -> FAIL (hard error).
- New tests in `tests/test_san368_aarm_verifier.py` covering per-check unit tests for PASS/FAIL/PARTIAL/N/A cases, STEP_UP chain check, R6 dispatch, redacted-receipt R5 acceptance, fixture-set integration, and CLI smoke test.

### Out of scope
- **TypeScript parity.** Lands in sanna-ts SAN-368 portion (separate Opus prompt).
- **Spec section 'How to verify AARM conformance with sanna-verify aarm'.** Lands in sanna-protocol SAN-368 portion.
- **SARIF output format.** Marked optional in SAN-368 ACs; deferred.
- **Cross-language fixture parity test.** Achievable once TS parity ships; deferred to TS portion.

### Tickets
- SAN-368 (this entry; sanna-repo Python portion)
- Predecessor: SAN-361 (Section 14 AARM Conformance and Mapping spec section, MERGED)
- Companions: sanna-ts SAN-368 (TypeScript parity, separate PR), sanna-protocol SAN-368 (operational docs, separate PR)
- Cross-references: SAN-356 G2 (locked decision-enum mapping), SAN-369 (MODIFY recording infrastructure), SAN-371 (CV9_LEGACY warning + cv-aware dispatch)

## [Unreleased] -- 2026-05-02 (SAN-369)

### Added
- **MODIFY authority decision recording infrastructure (Python).** `sanna.enforcement.authority.build_modify_authority_decision(action, original, transformed, transformations, ...)` constructs a dict matching `AuthorityDecisionRecord` with `decision=modify_with_constraints` and the three required MODIFY recording fields (`tool_input_original`, `tool_input_transformed`, `transformations_applied`) per spec Section 2.7. Helper validates at construction time: transformations is a non-empty list of `{type, target_field, rationale}` dicts; `original` and `transformed` are string or dict. Records produced by the helper satisfy the A1' conditional rule in `receipt.schema.json` (decision=modify_with_constraints requires the three fields).
- New test coverage in `tests/test_san369_modify_recording.py` validating: helper output schema-validates inside a full receipt; receipts missing any of the three MODIFY fields are schema-rejected; transformation items with missing/extra keys are construction-rejected; non-string-non-dict `original`/`transformed` raise ValueError; deterministic construction (two calls with identical inputs produce byte-equal records).

### Out of scope
- **Constitution-rule-driven MODIFY emission.** `evaluate_authority` does NOT yet return `modify_with_constraints`. The rule engine (constitution boundary type for transformations + dispatch in `evaluate_authority`) is conceptually a separate ticket; SAN-369 ships only the recording-infrastructure half.
- **Cross-SDK fixture (SAN-369 AC #4).** Lands in the sanna-protocol SAN-369 portion (hand-constructed + signed with the committed e58ed3e keypair). Not generated via `generate_fixtures.py` until SAN-391 lands.

### Tickets
- SAN-369 (this entry; sanna-repo Python portion)
- Predecessor: SAN-204 (schema text + A1' conditional rule, MERGED)
- Companions: sanna-ts SAN-369 portion (TypeScript parity, separate Opus prompt) + sanna-protocol SAN-369 portion (implementer's guide example + cross-SDK fixture, separate Opus prompt)
- Verifier rejection of MODIFY receipts missing the three fields: SAN-368 (sanna-verify aarm)

## [Unreleased] -- 2026-05-01 (SAN-371)

### Added
- **Verifier emits CV9_LEGACY-prefixed warning on cv=9 receipts.** When `verify_receipt(...)` processes a receipt with `checks_version=9`, the warnings list now includes a string starting with `CV9_LEGACY:` indicating partial R6 conformance only (agent_identity is absent at cv<10 per spec Section 2.19). Receipt remains valid; the warning is informational. Existing signed cv=9 receipts continue to verify successfully without re-emission.
- New test coverage in `tests/test_san371_cv9_legacy.py` validating: cv=9 receipts emit exactly one CV9_LEGACY warning; cv=10 receipts emit no CV9_LEGACY warning; pre-v1.5 archive cv=9 fixtures verify cleanly with the warning.

### Compatibility
- **No-action-required for existing signed cv=9 receipts.** Pre-v1.5 receipts remain cryptographically valid; their 20-field fingerprints continue to verify. Verification output now includes the CV9_LEGACY informational warning.
- **Warning format:** flat string with `CV9_LEGACY:` prefix in `VerificationResult.warnings`. Pattern matches existing pre-v1.3 legacy warnings at `verify.py:1093-1103`.

### Tickets
- SAN-371 (this entry; sanna-repo Python portion)
- Predecessor: SAN-371 sanna-protocol portion (migration memo at `docs/migration/cv9-to-cv10.md`, MERGED at sanna-protocol a684a33)
- Companion: sanna-ts SAN-371 portion (TS verifier parity, separate PR)

## [Unreleased] -- 2026-05-01 (SAN-392)

### Changed
- **Bumped `spec/` submodule pin** from 9ee7527 (pre-SAN-389) to e58ed3e (post-SAN-389 sanna-protocol self-consistency fix). Brings sanna-repo's bundled keypair (`fixtures/keypairs/test-author.pub` key_id = 6edb993...) into lockstep with sanna-ts at the same pin.
- **Synced operational schema copies** (`src/sanna/spec/receipt.schema.json`, `src/sanna/spec/constitution.schema.json`) from the new submodule snapshot per SAN-374 drift gate. Schema content unchanged (no v1.5 schema edits between 9ee7527 and e58ed3e); files refreshed for byte-identical match with submodule.

### Compatibility
- **Cross-SDK keypair lockstep restored.** Pre-SAN-392, sanna-repo and sanna-ts at v1.5 bundled different keypairs; cross-SDK signature verification failed for receipts crossing the SDK boundary. Post-SAN-392, both repos pin spec/ at e58ed3e; bundled keypairs match.
- **Receipt fingerprints unchanged** (formula uses pipe-joined receipt fields, not signing key). Existing tests pass without modification.
- **Receipt signatures from cv=10 fixtures** in the new submodule snapshot were rotated by SAN-389 (re-signed with the bundled keypair). cv=9 archive signatures unchanged.
- **No code changes.** Pure submodule + operational schema sync.

### Tickets
- SAN-392 (this entry)
- Predecessor: SAN-389 (sanna-protocol e58ed3e + sanna-ts 8e769ec, MERGED) -- only bumped sanna-protocol + sanna-ts; missed sanna-repo
- Unblocks: SAN-386 (v1.5 release-gate verification matrix)
- Cross-SDK contract: SAN-355

## [Unreleased] -- 2026-04-30 (SAN-385)

### Fixed
- **Wire-format regression (SAN-370 Prompt B fallout):** cv=9 legacy receipts emitted via the Python SDK now correctly OMIT the `agent_identity` field instead of emitting `agent_identity: null`. Per spec Section 2.19 line 780, `agent_identity` MUST be absent at cv<=9; the schema (per SAN-204) defines the field as `type: "object"` (non-nullable). SAN-370 Prompt B's `asdict(SannaReceipt)` produced `null` due to the new `Optional[dict] = None` field default. Fix: introduced `receipt_to_dict()` helper that strips `agent_identity` when None; replaced 3 production `asdict(receipt)` callers (cli.py, subprocess_interceptor.py, http_interceptor.py) plus test sites in test_pem_bytes_api, test_constitution, test_halt_event, test_constitution_lifecycle, test_v15_integrity.
- **Verifier returned to strict schema validation:** SAN-370 Prompt B added a `None`-stripping pre-pass in `verify_schema` (verify.py:250-253) to mask the wire-format regression. SAN-385 reverts this to plain `validate(receipt, schema)`. Per CLAUDE.md governance principle, verifier-side enforcement is non-negotiable; the verifier should reject what the schema rejects.

### Added
- `src/sanna/receipt.py:receipt_to_dict(receipt)` -- convert `SannaReceipt` to wire dict, omitting `agent_identity` when None. Exported from `sanna` package (`sanna.__all__` grows from 21 to 22). Used at all 3 production emit sites (sanna-generate CLI, subprocess interceptor, http interceptor).
- `tests/test_wire_format_no_nulls.py` -- asserts cv=9 wire JSON has no `agent_identity` key; cv=10 has the dict; both pass strict schema validation; cv=9 wire shape matches `spec/fixtures/receipts/archive/v1.4/`.

### Compatibility
- **Wire format alignment with TS Prompt C:** Python now emits `agent_identity` ABSENT for cv=9 (matching TS's natural `JSON.stringify` behavior for unset optional fields). Cross-SDK byte-equal contract for wire JSON restored ahead of SAN-370 Prompt C.
- **Pre-Prompt-B receipts (deployed pre-2026-04-30):** unaffected. They never had `agent_identity` field at all (cv=9 archive shape).
- **Receipt fingerprints unchanged:** the cv-dispatch fingerprint formula (SAN-370 Prompt B) computes from pipe-joined fields, not from canonical JSON of the receipt body. Wire-format change does not affect fingerprint values; existing signed receipts continue to verify their fingerprints.

### Tickets
- SAN-385 (this entry)
- Predecessor: SAN-370 Prompt B (sanna-repo a0ee706, MERGED) -- introduced the regression
- Unblocks: SAN-370 Prompt C (sanna-ts) -- TS Prompt C will mirror Python's now-correct wire shape
- Cross-SDK contract: SAN-355 G1

## [Unreleased] -- 2026-04-30 (SAN-370 Prompt B)

### Changed
- `src/sanna/version.py`: `__version__` 1.4.0 -> 1.5.0 (TOOL_VERSION; v1.5 SHIPPED moment for Python SDK runtime).
- `src/sanna/receipt.py`: SPEC_VERSION 1.4 -> 1.5; CHECKS_VERSION 9 -> 10. Added `agent_identity` field to `SannaReceipt` dataclass. `generate_receipt()` adds `agent_identity` keyword argument with cv-dispatch: when present (and non-empty `agent_session_id`), emits cv=10 with 21-field fingerprint formula adding `agent_identity_hash` at field 21 = `hash_obj(agent_identity)`; when None (library middleware path), emits cv=9 legacy with 20-field formula and hardcoded "1.4"/"9" overrides for byte-equal compatibility with archive fixtures.
- `src/sanna/middleware.py`: same cv-dispatch in `_generate_constitution_receipt()` and `_generate_no_invariants_receipt()`. Both paths take `agent_identity` keyword.
- `src/sanna/gateway/server.py`: added `MCPGateway._agent_session_id` (uuid4 hex, stable for instance lifetime). `_generate_receipt()` builds `agent_identity = {agent_session_id: self._agent_session_id}` and passes to `generate_constitution_receipt()`. `_apply_redaction_markers()` adds cv>=10 branch with 21-field fingerprint formula.
- `src/sanna/interceptors/subprocess_interceptor.py`: lazy-init `_state['agent_session_id']` on first invocation; `_emit_receipt()` builds and passes agent_identity to generate_receipt.
- `src/sanna/interceptors/http_interceptor.py`: same pattern with `_http_state['agent_session_id']` and `_emit_http_receipt()`.
- `src/sanna/verify.py`: added cv>=10 branch in `_verify_fingerprint_v013()` (21-field formula with agent_identity_hash). `verify_receipt()` adds cv>=10 required-field check (`agent_identity` and sub-field `agent_session_id`). `verify_schema()` strips None-valued optional fields before jsonschema validation (prevents cv=9 legacy receipts from failing schema validation on absent `agent_identity`).
- `spec/` submodule: bumped from 03160f1 (post-SAN-378 Prompt A) to 9ee7527 (post-SAN-370 Prompt A; v1.5 protocol artifact).
- `src/sanna/spec/receipt.schema.json`: synced from spec/schemas/receipt.schema.json (operational copy; SAN-374 drift gate). Schema $id is now https://sanna.dev/schemas/receipt/v1.5.json.
- `ARCHITECTURE.md`: v1.4 -> v1.5 references; cv=10 / 21-field row added to formula table; SannaReceipt field count 28 -> 29.
- Tests: SDK constant assertions flipped to '10'/'1.5.0'; receipt-field assertions case-by-case per emission path; new `tests/test_v15_integrity.py` for cv=10 emission + verification + agent_identity round-trip; new `tests/test_cross_language_fixture_parity.py` validates Python recomputes spec/fixtures cv=10 fingerprint byte-equal.

### Per-emission-site cv discipline (SAN-370 Issue Y)
- gateway / cli_interceptor / http_interceptor surfaces emit cv=10 with populated agent_identity.
- middleware surface (sanna-generate CLI, sanna_generate_receipt MCP tool, @sanna_observe decorator path) emits cv=9 legacy with no agent_identity, per spec Section 2.19 line 781-782.

### Compatibility
- **Receipt fingerprint compatibility:** Existing signed cv=9 receipts continue to verify via the 20-field formula; the verifier dispatches on `checks_version`. Re-emission post-upgrade from gateway/interceptor surfaces produces cv=10 receipts with new field 21; library middleware re-emission preserves cv=9 byte-equal output.
- **TOOL_VERSION bumps to 1.5.0 globally** (no per-callsite override). All Python SDK emissions report tool_version=1.5.0 even when emitting cv=9 legacy receipts. The receipt's spec_version/checks_version reflect the per-emission cv decision; tool_version reflects the SDK runtime.
- **pyproject.toml stays at 1.3.0** (PyPI publication is gated by a separate release ticket; pre-existing convention per CHANGELOG history).

### Tickets
- SAN-370 Prompt B (this entry)
- Predecessor: SAN-370 Prompt A (sanna-protocol 9ee7527; v1.5 fixtures + schema $id flip).
- Successor: SAN-370 Prompt C (sanna-ts mirror).
- Forward-pointers: SAN-383 (cv<10 -> agent_identity-absent negative schema rule, Backlog), SAN-384 (apply content_mode redaction to agent_identity sub-fields, Backlog).
- Out-of-scope: SAN-368 (AARM verifier R6 PASS/PARTIAL), SAN-369 (MODIFY parameter recording), SAN-371 (cv=10 cascade legacy warnings + customer notification).

## [Unreleased] -- 2026-04-30 (SAN-378 Prompt B)

### Changed
- `src/sanna/manifest.py`: `_generate_cli_surface` and `_generate_http_surface` now emit `suppression_reasons: dict[str, str]` per v1.5 spec Section 2.20.2. Empty dict when no suppressions; populated when the constitution's commands/endpoints declare `cannot_execute` or `must_escalate` with `escalation_visibility=suppressed`. Mirrors the mcp surface's existing `suppression_reasons` algorithm.
- `spec/` submodule pin bumped from sanna-protocol `f89c8c9` to `03160f1` (SAN-378 Prompt A merge: MC-006 + MC-007 fixture vectors updated to include `suppression_reasons`).
- Existing tests updated where they asserted cli/http surface output shape (Issue 14-equivalent for SAN-378). Each updated assertion now includes the new `suppression_reasons` field.

### Compatibility
- **Receipt fingerprint compatibility:** post-SAN-378 receipts include `suppression_reasons` in cli/http surfaces (per v1.5 Section 2.20.2). This changes the canonical JSON shape and therefore the receipt fingerprint when cli/http surfaces have suppressed entries. Existing signed receipts remain valid (signature is over what was emitted). Re-emission of the same input post-upgrade produces a different fingerprint than pre-upgrade. Verifiers should accept receipts as-emitted; cross-version fingerprint replay is not a conformance test.
- **Cross-SDK lockstep:** sanna-ts SDK is updated in SAN-378 Prompt C (in flight). Until Prompt C merges, sanna-ts emits cli/http surfaces WITHOUT `suppression_reasons` while sanna-repo emits them WITH the field. Cross-SDK divergence during this window is bounded; no fingerprint compatibility implication beyond the per-SDK note above.

### Tickets
- SAN-378 Prompt B (this entry)
- Companion: SAN-378 Prompt A (sanna-protocol fixture update, MERGED at 03160f1), SAN-378 Prompt C (sanna-ts mirror, in flight). SAN-376 (cross-SDK fixture origin), SAN-202 (Python manifest origin, will be annotated post-done on full SAN-378 close), SAN-377 (spec clarification, MERGED), SAN-382 (R1 schema-rule enforcement gap, deferred Backlog).

## [Unreleased] -- 2026-04-30 (SAN-206)

### Added
- `manifest.py`: `generate_manifest` gains `surfaces` and `content_mode` params. Surfaces filter restricts the returned `surfaces` dict to listed surfaces. content_mode applies v1.5 Section 2.14 (post-SAN-377) redaction.
- Gateway `_emit_session_manifest`: passes `surfaces=['mcp']` + `content_mode=self._content_mode or None`. Sets receipt content_mode + content_mode_source. Captures `_manifest_full_fingerprint` BEFORE persistence.
- Gateway `_suppressed_tool_names: set[str]` populated by `_build_tool_list`.
- Gateway `_emit_invocation_anomaly`: emits `invocation_anomaly` receipt per v1.5 Section 2.12 + 2.16.3.
- CLI + HTTP interceptors emit per-surface session_manifest at patch time. Mode-aware fail-closed/fail-open.
- New tests: content vectors, content_mode redaction shapes with schema validation, parent-chain integrity.

### Changed
- `spec/` submodule pin bumped from `5bfee54` to `f89c8c9` (post-SAN-376 + SAN-377).

### Compatibility
- `generate_manifest` signature backwards-compatible.
- Gateway session_manifest receipts now include only `surfaces.mcp` (resolves SAN-202/203 multi-surface defect).
- Gateway session_manifest receipts under `content_mode=redacted/hashes_only` apply spec-conformant redaction (resolves SAN-202/203 content_mode defect).
- New invocation_anomaly receipts on calls to suppressed tools.
- Interceptors emit session_manifest at patch time; enforce mode raises if sink rejects manifest.

### Out of scope (follow-ups)
- TS mirror: SAN-209.
- Existing CLI/HTTP interceptor enforcement_mode schema bug: SAN-379.
- Cross-SDK redacted/hashes_only fixtures: SAN-380 post-SAN-209.

### Tickets
- SAN-206 (this entry)
- Companion: SAN-209, SAN-202 (annotated x2), SAN-203 (annotated x2), SAN-204, SAN-205, SAN-376, SAN-377 (merged), SAN-378/379/380 (deferred).

## [Unreleased] -- 2026-04-30 (SAN-202)

### Added
- New module `src/sanna/manifest.py` with `generate_manifest(constitution, mcp_tools=None) -> dict`. Reads the constitution's `authority_boundaries`, `cli_permissions`, and `api_permissions` and produces the `com.sanna.manifest` extension dict per v1.5 spec Section 2.20. snake_case keys; deterministic sorted lists; stable suppression_reason enum (Section 2.21).
- Gateway `_build_tool_list()` applies authority filtering: suppress `cannot_execute` tools; suppress `must_escalate` tools when `constitution.authority_boundaries.escalation_visibility == 'suppressed'`; deliver `can_execute` and (default) `must_escalate` tools. Suppressed tools are absent from `tools/list` (anti-enumeration).
- Gateway `handle_list_tools` emits a `session_manifest` receipt on the FIRST tools/list call per gateway lifecycle. State-tracked via `self._manifest_emitted: bool`. Subsequent calls return the filtered list without emitting another manifest. Receipt has `event_type="session_manifest"`, `invariants_scope="none"`, `enforcement` absent (per v1.5 Section 2.16.3).

### Compatibility
- Pre-Manifest gateway behavior preserved when no constitution is loaded: tools pass through unfiltered, no manifest receipt emitted.
- v1.4-era constitutions (no `escalation_visibility`) default to `"visible"` per SAN-205. must_escalate tools remain in tools/list as before.

### Tickets
- SAN-202 (this entry)
- Companion: SAN-203 (TS gateway filtering, mirror of this), SAN-206 (Python interceptor manifest emission), SAN-209 (TS interceptor manifest emission), SAN-205 (constitution authority enum support, already merged), SAN-374 (sanna-repo schema sync, already merged), SAN-204 (v1.5 protocol schema, already merged).

## [Unreleased] -- 2026-04-30 (SAN-205)

### Added
- `AuthorityBoundaries.escalation_visibility` field (v1.5+, default `"visible"`). Backward-compatible: pre-v1.5 constitutions without the field validate cleanly with the default.
- `Composition` dataclass + optional `Constitution.composition` field. Phase 1 contains only `escalation_visibility`. Phase 2 will add a composition rule engine. Optional; absent in pre-v1.5 constitutions.
- `AuthorityDecision.decision` legal values extended with `modify` and `defer` (v1.5+). Reserved for future runtime evaluators (SAN-369 emits MODIFY first). evaluate_authority does not return either value in v1.5.
- `AuthorityDecision.boundary_type` legal values extended with `modify_with_constraints` and `defer_for_context` (v1.5+, reserved).

### Compatibility
- v1.4-era constitutions WITHOUT escalation_visibility or composition validate cleanly; defaults applied. No migration needed for existing customers.
- AuthorityDecision shape unchanged at the field level; only the documented legal values for `decision` and `boundary_type` expanded.

### Tickets
- SAN-205 Python half (this entry; companion TS PR also incoming under same ticket).
- Companion: SAN-202 (Python manifest.py + gateway filtering, depends on this), SAN-204 (v1.5 protocol schema), SAN-374 (sanna-repo schema sync, already merged).

## [Unreleased] -- 2026-04-30

### Changed
- Submodule `spec/` bumped from sanna-protocol commit `72097f2` to `5bfee54` (post-SAN-204; sanna-protocol v1.5 release). v1.5 introduces 10 new event_type values, the `mixed` enforcement_surface, agent_identity field (required at cv=10), the com.sanna.manifest extension namespace, the suppression_reason enum, and the modify_with_constraints + defer_for_context authority decisions.
- Operational schema copies `src/sanna/spec/receipt.schema.json` and `src/sanna/spec/constitution.schema.json` synchronized to match the bumped submodule's contents.

### Added (governance)
- CI drift gate in `.github/workflows/ci.yml`: every push and pull request runs `diff -q spec/schemas/<file>.json src/sanna/spec/<file>.json` for both schemas. Fails CI if the operational copy ever drifts from the submodule. Prevents silent re-drift on future protocol updates.
- CONTRIBUTING.md: dual-location pattern documented; sync recipe included for future protocol bumps.

### Compatibility
- cv=9 receipts continue to validate against the new schema (SAN-204 used CONDITIONAL cv=10 rules so the new requirements are no-ops at cv<10). All existing golden receipts pass.
- This bump alone does NOT activate cv=10 in the SDK. SDK code flips CHECKS_VERSION 9 -> 10 in SAN-370.

### Tickets
- SAN-374 (this entry)
- Companion: SAN-375 (sanna-ts schema sync), SAN-205 (constitution authority enum + escalation_visibility), SAN-202/203/209/370/371 (SDK feature work that depends on this sync).

# Changelog

**Note:** v0.13.x is the first public release series. Earlier version entries document internal pre-release development.

## [Unreleased] - SAN-215

### Added — SAN-215

- `sanna.cloud.load_constitution_from_cloud(...)` — fetches a Cloud-managed
  constitution, verifies its Ed25519 signature, and returns a `Constitution`
  dataclass. Includes in-memory cache (60s TTL default), opt-in disk cache,
  fail-closed-on-unreachable semantics with explicit `allow_cached_startup`
  override, and ETag protocol support (server-side ETag emission deferred to
  a Cloud follow-up).
- New subpackage `src/sanna/cloud/` for future Cloud client modules
  (DVR resolvers, agent registry, etc.).
- Internal `parse_constitution_from_yaml_bytes(yaml_bytes, validate)` helper
  factored out of `load_constitution(path)`. Public API of `load_constitution`
  is unchanged.

### Notes

- TS SDK equivalent (`packages/core/src/cloud/constitution.ts`) is deferred to
  Sprint 16 per Gate 1 status. Python and TS Cloud fetch will be at parity
  after that ticket lands.
- The Cloud `GET /v1/constitutions/{id}/export` endpoint does not currently
  emit `ETag` headers. The SDK is protocol-ready (sends `If-None-Match` if
  cached, handles `304 Not Modified`); a Cloud follow-up ticket adds the
  server-side header. Until then, every fetch returns 200 with full body.

## [1.4.0] - 2026-04-20

### Added
- `verify_receipt()` accepts `public_key_pem: bytes | str | None` for in-memory
  key material, alongside the existing `public_key_path` parameter. Enables
  server-side callers (e.g., Sanna Cloud ingestion verifier, SAN-223) to pass
  keys retrieved from a database or other runtime source without writing to
  disk. Mutually exclusive with `public_key_path`.
- `sign_receipt_from_pem()` accepts `private_key_pem: bytes | str` for in-memory
  private key material. Equivalent to `sign_receipt()` for server-side callers.
- Internal: `sanna.crypto.load_public_key_from_pem(bytes | str)`,
  `load_private_key_from_pem(bytes | str)`, `verify_receipt_signature_from_pem()`.

  Additive, no breaking changes. No protocol / wire format / fingerprint changes.
  Version stays at 1.4.0 pending publication.
- New required top-level field `tool_name` (v1.4+, required at cv>=9).
  Canonical SDK identity constant `"sanna"` in Python reference.
  Participates in fingerprint as position 17.
- New optional nullable fields `agent_model`, `agent_model_provider`,
  `agent_model_version`. Capture LLM model identity at receipt
  generation. Null = opt-out; absent = not captured. Fingerprint
  positions 18-20.
- Verifier v1.4 required-field check: rejects cv>=9 receipts
  missing `tool_name`. Error text: "v1.4+ receipt (checks_version >= 9) is missing required field: tool_name".
- Verifier 20-field fingerprint dispatch for cv>=9.

### Changed
- `SPEC_VERSION` bumped to `"1.4"`.
- `CHECKS_VERSION` bumped to `"9"`.
- Package version `1.3.0` → `1.4.0`.
- Fingerprint algorithm extended from 16 to 20 fields at cv=9.
  Legacy receipts (cv=8, cv=6/7, cv=5) unchanged.
- Goldens regenerated for v1.4; v1.3 goldens archived under
  `golden/receipts/archive/v1.3/`.
- Authority name matching (`_matches_action`) changed from bidirectional substring
  to exact-match + opt-in glob (SAN-224). ``"delete"`` no longer matches
  ``"delete_user"``; use ``"delete_*"`` for prefix-glob. Aligns with
  sanna-protocol Appendix D errata-A. Cross-SDK contract:
  ``spec/fixtures/authority-matching-vectors.json`` (21 vectors).

## [1.3.0] - 2026-04-18

Receipt format v1.3: enforcement surface attestation and invariants scope fields (SAN-213, SAN-216).

### Added
- `enforcement_surface` field on `SannaReceipt` — records the SDK component that generated the receipt (`middleware`, `gateway`, `cli_interceptor`, `http_interceptor`).
- `invariants_scope` field on `SannaReceipt` — records which invariants were evaluated (`full`, `authority_only`, `limited`, `none`).
- `skip_default_checks` parameter on `generate_receipt()` — interceptor path derives status from `enforcement.action` without running C1-C5 checks.
- 16-field fingerprint formula (`CHECKS_VERSION` bumped to `"8"`, `SPEC_VERSION` bumped to `"1.3"`): fields 15-16 are `enforcement_surface_hash` and `invariants_scope_hash`.
- Schema `allOf` cross-field consistency rules: `enforcement.action=halted` requires `status=FAIL`, `warned` requires `status=WARN`, `allowed` requires `status=PASS`.

### Changed
- `verify_status_consistency` applies enforcement-action override (parity with emit-time logic) so halted receipts with all-pass checks verify correctly.
- `_apply_redaction_markers` in gateway updated to 16-field fingerprint recomputation.
- All emit paths (`middleware.py`, `receipt.py`, `gateway/server.py`, `interceptors/`) updated to supply the two new fields.
- `receipt.schema.json` synced from sanna-protocol v1.3 (both `src/sanna/spec/` and root `spec/`).
- Golden receipts regenerated at `CHECKS_VERSION="8"`, previous goldens archived to `golden/receipts/archive/pre-v1.3/`.

### Tests
- 2862 passed, 1 skipped, 10 xfailed

## [1.1.0] - 2026-03-24

Security hardening release for the subprocess interceptor and cross-SDK fingerprint alignment.

### Security
- Shell metacharacter bypass fix in subprocess interceptor (SAN-35)
- `os.exec*/os.spawn*/os.popen` patching in subprocess interceptor (SAN-42)
- TOCTOU race mitigation with binary path resolution (SAN-44)
- Wrapper script bypass detection in subprocess interceptor (SAN-45)
- Thread-safe restore for subprocess interceptor (SAN-46)
- Env var manipulation bypass prevention in subprocess interceptor (SAN-47)

### Fixed
- Fingerprint edge cases aligned with TypeScript SDK and spec (SAN-27)

### Improved
- Broad `except Exception` replaced with specific exception types across the codebase (SAN-1)

### Tests
- 2834 passed, 10 xfailed

## [1.0.0] - 2026-03-05

See README for full v1.0.0 feature list.

## [0.13.7] - 2026-02-25

Gateway constitution template standardization. No library code changes.

### Documentation
- All five gateway constitution templates (`examples/constitutions/`) updated with:
  - Evaluation order documentation header explaining boundary priority, common mistakes, and rules of thumb
  - YAML key order matching evaluation priority (`cannot_execute` → `must_escalate` → `can_execute`)
  - Audit for command patterns incorrectly placed in `cannot_execute` (none found)
- README: Authority Boundaries description updated with evaluation order
- README: Constitution Format example reordered to match evaluation priority
- README: Constitution Templates section notes inline evaluation order documentation

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
