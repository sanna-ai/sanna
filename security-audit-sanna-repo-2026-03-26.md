# Sanna SDK Security Audit Report

**Date:** 2026-03-26
**Auditor:** Claude Code (automated deep audit)
**Scope:** Full source tree (`src/sanna/`), tests, dependencies
**Version Audited:** v1.1.1 (commit 1d2e17f)
**Classification:** AUDIT ONLY -- no changes made

---

## Executive Summary

The Sanna SDK demonstrates strong security engineering overall, with comprehensive protections for file I/O (symlink, atomic writes), SQL injection prevention, safe YAML/JSON parsing, and modern cryptographic primitives (Ed25519, SHA-256). However, the audit identified **4 CRITICAL**, **7 HIGH**, **20 MEDIUM**, and **14 LOW** findings across 10 audit domains.

The most significant findings are:
1. Receipt `status` and `details` fields are not cryptographically bound to the fingerprint, allowing post-generation tampering
2. Private keys stored unencrypted on disk with no passphrase option
3. Reasoning gate failures silently pass without enforcement
4. Inconsistent use of `safe_json_loads()` vs stdlib `json.loads()` in security-sensitive paths

---

## Findings by Severity

### CRITICAL

#### C-1: Receipt `status` Field Not Cryptographically Protected
- **File:Line:** `src/sanna/receipt.py:705`, `src/sanna/verify.py:432-464`
- **Description:** The receipt `status` field ("PASS"/"WARN"/"FAIL"/"PARTIAL") is derived from check results but is NOT included in the 14-field fingerprint formula. An attacker with access to receipt data can change `status` from "FAIL" to "PASS" without invalidating the fingerprint or signature.
- **Impact:** Systems relying on receipt `status` for access control decisions will be bypassed. The `verify_status_consistency()` function exists but is a separate optional check, not part of standard fingerprint verification.
- **Exploitability:** HIGH -- requires post-generation receipt access, but the `status` field is the primary governance signal.

#### C-2: Receipt `details` Field Excluded from Fingerprint
- **File:Line:** `src/sanna/receipt.py:673`, `src/sanna/verify.py:298`
- **Description:** The `details` field from `CheckResult` is stored in the receipt but NOT included in `checks_data` used for fingerprint computation (only `check_id`, `passed`, `severity`, `evidence` are included). An attacker can rewrite `details` (which contains governance-critical explanations like "Output contradicts tier_1 source") without changing the fingerprint.
- **Impact:** Misleading audit trail -- users cannot trust that check details match what was originally evaluated.
- **Exploitability:** HIGH -- straightforward post-generation field modification.

#### C-3: Private Keys Stored Unencrypted on Disk
- **File:Line:** `src/sanna/crypto.py:110-114, 164`
- **Description:** Private keys are serialized with `serialization.NoEncryption()` and written to disk unencrypted. When loading, `password=None` is hardcoded, meaning encrypted key files cannot be loaded. No option for passphrase-protected key storage exists.
- **Impact:** Disk compromise, backup exposure, or physical access immediately exposes all private keys. Only filesystem permissions (0o600) protect them.
- **Exploitability:** HIGH -- simple filesystem access, stolen backups, or root compromise.

#### C-4: YAML Loading Uses `yaml.load()` Instead of `yaml.safe_load()`
- **File:Line:** `src/sanna/utils/safe_yaml.py:52`
- **Description:** `safe_yaml_load()` uses `yaml.load(stream, Loader=_DuplicateKeyCheckLoader)` instead of `yaml.safe_load()`. While the custom loader extends `yaml.SafeLoader` (mitigating the worst deserialization attacks), it uses the lower-level API which increases complexity and attack surface.
- **Impact:** Theoretical -- SafeLoader foundation prevents arbitrary code execution, but custom loader subclassing widens the trust surface for future regressions.
- **Exploitability:** LOW in practice (SafeLoader foundation is secure), but CRITICAL from defense-in-depth perspective.

---

### HIGH

#### H-1: Receipt `name` Field Excluded from Fingerprint
- **File:Line:** `src/sanna/receipt.py:673`, `src/sanna/verify.py:298, 393`
- **Description:** The `name` field (human-readable check name like "Context Contradiction") from `CheckResult` is stored in the receipt but not included in fingerprint computation. An attacker can rename checks without invalidating the fingerprint.
- **Impact:** Misleading governance UI -- users see modified check names. Lower impact than C-1/C-2 because `check_id` is still protected.
- **Exploitability:** MEDIUM -- requires post-generation receipt access.

#### H-2: Inconsistent Check Data Format Between Generation and Verification
- **File:Line:** `src/sanna/receipt.py:673` (simple: 4 fields), `src/sanna/verify.py:284-296` (conditional: up to 8 fields), `src/sanna/middleware.py:549-571` (conditional)
- **Description:** Fingerprint `checks_hash` computation varies: `receipt.py` always uses 4 fields (`check_id`, `passed`, `severity`, `evidence`), while `verify.py` and `middleware.py` conditionally include `triggered_by`, `enforcement_level`, `check_impl`, `replayable` when enforcement fields are present. Detection logic relies on presence of `triggered_by`.
- **Impact:** Format mismatch can cause verification failures or unexpected passes depending on which code path generated vs verified.
- **Exploitability:** MEDIUM -- primarily a compatibility/correctness issue.

#### H-3: Unsafe `json.loads()` in CloudHTTPSink Buffer Drain
- **File:Line:** `src/sanna/sinks/cloud.py:255`
- **Description:** `_drain_buffer()` uses stdlib `json.loads(line)` instead of `safe_json_loads()` when parsing buffered receipts from JSONL buffer file. Bypasses duplicate key detection and non-finite float rejection.
- **Impact:** Corrupted or malicious buffer files could inject duplicate keys causing receipt validation bypass.
- **Exploitability:** MEDIUM -- requires write access to buffer_path.

#### H-4: Unsafe `json.load()` in Escalation Store
- **File:Line:** `src/sanna/gateway/server.py:671`
- **Description:** Escalation store loader uses stdlib `json.load(f)` instead of `safe_json_load()` for persistent escalation records. Bypasses duplicate key detection.
- **Impact:** Tampered escalation JSON could cause records to be misinterpreted, potentially bypassing governance.
- **Exploitability:** MEDIUM -- requires write access to escalation persistence file.

#### H-5: Unsafe `json.loads()` in CLI Verify Flow
- **File:Line:** `src/sanna/cli.py:343`
- **Description:** `main_verify()` re-parses `format_verify_json()` output with stdlib `json.loads()` instead of `safe_json_loads()`.
- **Impact:** Verification output could contain duplicate keys if internal state is corrupted.
- **Exploitability:** LOW -- requires corrupted internal state.

#### H-6: TOCTOU Between Governance Check and Tool Execution (Gateway)
- **File:Line:** `src/sanna/gateway/server.py:2329-2443, 2490, 2681`
- **Description:** Governance check (`evaluate_authority()`) and tool execution are separated by reasoning evaluation logic. Between the authority decision and actual tool forwarding, the `_justification` parameter is stripped but no re-validation occurs.
- **Impact:** Policy bypass if governance state changes between check and execution.
- **Exploitability:** LOW -- requires control of reasoning evaluator or internal state mutation.

#### H-7: Unencrypted Private Key Serialization
- **File:Line:** `src/sanna/crypto.py:110-114`
- **Description:** `encryption_algorithm=serialization.NoEncryption()` used for all key generation. No option for passphrase-encrypted keys.
- **Impact:** All generated keys are immediately readable by anyone with file access. Related to C-3 but specifically about the serialization API choice.
- **Exploitability:** HIGH -- combined with C-3.

---

### MEDIUM

#### M-1: No Private Key Memory Cleanup
- **File:Line:** `src/sanna/crypto.py:103-114, 239-280, 337-357`
- **Description:** Private key material loaded from disk persists in Python memory without explicit zeroing. `private_bytes` serialization creates bytes that are never securely wiped.
- **Impact:** Long-running processes or memory dumps could leak private key material.
- **Exploitability:** MEDIUM -- requires process memory access or core dump analysis. Limited by Python's immutable bytes.

#### M-2: No Permission Validation on Key File Read
- **File:Line:** `src/sanna/crypto.py:160, 172`
- **Description:** `load_private_key()` does not verify that the private key file has proper permissions (0o600). An attacker could modify permissions to 0o644 without detection.
- **Impact:** No warning if private key permissions are too permissive.
- **Exploitability:** MEDIUM -- requires filesystem access.

#### M-3: Exception Chains Leak Cryptographic Library Details
- **File:Line:** `src/sanna/crypto.py:165-166, 177-178`
- **Description:** `raise ValueError(...) from e` preserves original cryptography library exception in `__cause__`, which could leak information about key structure or system state through tracebacks.
- **Impact:** Information leakage about internal crypto operations.
- **Exploitability:** LOW-MEDIUM -- requires exception access at caller.

#### M-4: No Key Format Pre-Validation on Load
- **File:Line:** `src/sanna/crypto.py:160-181`
- **Description:** `load_private_key()` and `load_public_key()` accept raw PEM data without validating format before deserialization. No PEM header/footer validation.
- **Impact:** Malformed key files may produce confusing errors that leak information.
- **Exploitability:** LOW.

#### M-5: Reasoning Gate Failures Silently Pass (Sync)
- **File:Line:** `src/sanna/middleware.py:801`
- **Description:** `except Exception as e:` in `_run_reasoning_gate_sync()` silently returns `None` on any failure. Enforcement is skipped when the reasoning gate crashes.
- **Impact:** Security evaluation failures silently ignored -- fail-open behavior for reasoning checks.
- **Exploitability:** MEDIUM -- any exception in reasoning pipeline bypasses enforcement.

#### M-6: Reasoning Gate Failures Silently Pass (Async)
- **File:Line:** `src/sanna/middleware.py:839`
- **Description:** Same as M-5 for async path.
- **Impact:** Same as M-5.
- **Exploitability:** MEDIUM.

#### M-7: Broad Exception Swallows Crypto Verification (MCP Constitution)
- **File:Line:** `src/sanna/mcp/server.py:772`
- **Description:** `except Exception:` swallows all exceptions from `verify_constitution_full()` and silently sets `author_sig_verified = False`. Legitimate errors (file not found, parse errors) are indistinguishable from signature mismatches.
- **Impact:** Cryptographic verification errors masked as simple verification failures.
- **Exploitability:** MEDIUM.

#### M-8: Broad Exception Swallows Crypto Verification (MCP Approval)
- **File:Line:** `src/sanna/mcp/server.py:859`
- **Description:** Same as M-7 for approval signature verification.
- **Impact:** Same as M-7.
- **Exploitability:** MEDIUM.

#### M-9: Custom Evaluator Exception Messages Unsanitized in Receipts
- **File:Line:** `src/sanna/middleware.py:412, 422, 438`
- **Description:** `except Exception as exc:` catches custom evaluator errors and includes unsanitized `str(exc)` in receipt details.
- **Impact:** Malicious custom evaluators could inject arbitrary content into governance receipts.
- **Exploitability:** MEDIUM -- requires malicious evaluator registration.

#### M-10: PII Redaction Incomplete -- Missing Fields
- **File:Line:** `src/sanna/gateway/server.py:144-201`
- **Description:** `_apply_redaction_markers()` only redacts `inputs.context` ("arguments") and `outputs.response` ("result_text"). Receipt fields like `extensions["gateway"]["override_detail"]`, `authority_decisions[].reason`, and custom records are NOT redacted.
- **Impact:** PII leakage through non-redacted receipt fields despite redaction being "enabled".
- **Exploitability:** MEDIUM -- configuration leads to false sense of PII protection.

#### M-11: Escalation Token Race Condition
- **File:Line:** `src/sanna/gateway/server.py:2867-2954`
- **Description:** In `_handle_approve()`, escalation entry is retrieved, checked for expiry/status, then token validated. If the escalation store is modified concurrently (cleanup task), token validation operates on stale entry.
- **Impact:** Token mismatch or approval of modified escalations.
- **Exploitability:** LOW -- requires concurrent modification and tight timing.

#### M-12: Tool Name Validation Insufficient at Runtime
- **File:Line:** `src/sanna/gateway/server.py:1759`, `src/sanna/gateway/config.py:507-510`
- **Description:** Tool names are validated at config parse time via regex, but downstream-reported tool names at runtime bypass config-time validation. MCP protocol doesn't validate tool names.
- **Impact:** Tool name injection or confusion if downstream MCP server is compromised.
- **Exploitability:** LOW-MEDIUM -- requires malicious downstream.

#### M-13: Environment Variable Interpolation Without Content Validation
- **File:Line:** `src/sanna/gateway/config.py:592-612`
- **Description:** `_interpolate_env()` replaces `${VAR_NAME}` from `os.environ` without validating interpolated values. Special characters or commands pass through.
- **Impact:** Code injection via attacker-controlled environment variables.
- **Exploitability:** MEDIUM -- depends on env var control.

#### M-14: SSRF Protection Gap with SANNA_ALLOW_INSECURE_WEBHOOK
- **File:Line:** `src/sanna/gateway/config.py:715, 732`
- **Description:** HTTP localhost is allowed when `SANNA_ALLOW_INSECURE_WEBHOOK=1`. Returns early, skipping further IP validation. Any `http://localhost:*` URL accepted.
- **Impact:** SSRF via localhost if env var is set.
- **Exploitability:** MEDIUM -- requires env var control.

#### M-15: CloudHTTPSink Buffer File I/O Lacks Symlink Protection
- **File:Line:** `src/sanna/sinks/cloud.py:229, 241, 268, 282`
- **Description:** Buffer file operations use raw `open()` without symlink protection or O_NOFOLLOW. Parent directory created with `mkdir(parents=True)` without `ensure_secure_dir()`.
- **Impact:** Symlink attack could redirect receipt writes to attacker-controlled location.
- **Exploitability:** MEDIUM -- requires local filesystem access and pre-creation of symlink.

#### M-16: TOCTOU in Subprocess Interceptor (Check-Then-Execute)
- **File:Line:** `src/sanna/interceptors/subprocess_interceptor.py:302-355, 869-878`
- **Description:** Window between authority check and actual subprocess execution where binary could be replaced on filesystem. Documented as "cannot be prevented in userspace."
- **Impact:** Filesystem-level attacker could replace binary between governance evaluation and execution.
- **Exploitability:** MODERATE -- requires filesystem write and precise timing.

#### M-17: Shell Metacharacter Splitting Incomplete
- **File:Line:** `src/sanna/interceptors/subprocess_interceptor.py:431, 298-299`
- **Description:** Shell chaining detection regex `r'\s*(?:;|\|\||&&|\|)\s*'` misses: nested command substitution `$(echo $(whoami))`, here-docs, process substitution `<(cmd)`, pipe within substitution.
- **Impact:** Chained blocked commands could bypass detection when `shell=True`.
- **Exploitability:** MODERATE -- depends on constitution rules.

#### M-18: URL Glob Pattern Bypass (fnmatch)
- **File:Line:** `src/sanna/interceptors/api_authority.py:51`, `src/sanna/interceptors/http_interceptor.py:214`
- **Description:** URL pattern matching uses `fnmatch.fnmatch()` which treats `[`, `]`, `?` as glob metacharacters. IPv6 URLs like `http://[::1]` could fail matching.
- **Impact:** Specially-crafted URLs could bypass constitution access controls.
- **Exploitability:** LOW-MEDIUM -- depends on constitution patterns.

#### M-19: Overly Permissive Dependency Version Constraints
- **File:Line:** `pyproject.toml:30-40`
- **Description:** All dependencies use `>=` without upper bounds: `cryptography>=41.0`, `pyyaml>=6.0`, etc.
- **Impact:** Future major versions could introduce breaking changes or security regressions.
- **Exploitability:** LOW.

#### M-20: Pipe Delimiter Validation Asymmetry
- **File:Line:** `src/sanna/receipt.py:671-672` (validated), `src/sanna/verify.py:276-353` (not validated)
- **Description:** Pipe characters in `correlation_id` are validated at receipt generation but NOT during fingerprint verification. Mitigated by fingerprint mismatch catching tampering.
- **Impact:** Asymmetric validation -- implicit rather than explicit protection.
- **Exploitability:** LOW -- fingerprint mismatch catches tampering.

---

### LOW

#### L-1: Key ID Comparison Not Constant-Time
- **File:Line:** `src/sanna/crypto.py:311, 395`
- **Description:** `key_id` comparison uses `!=` operator instead of `hmac.compare_digest()`.
- **Impact:** Theoretical timing side-channel on key_id (which is public metadata).
- **Exploitability:** Very Low -- key_id is not secret.

#### L-2: Key ID Logged in Warning Messages
- **File:Line:** `src/sanna/crypto.py:405-408`
- **Description:** Warning messages log key_id and error context. Key_id is public metadata.
- **Impact:** Minimal -- key_id is not sensitive.
- **Exploitability:** Very Low.

#### L-3: Silent Env Var Key Auto-Detection Failure (Middleware)
- **File:Line:** `src/sanna/middleware.py:954`
- **Description:** `except Exception:` with no logging during env var public key validation. Best-effort design but no indication of why env var wasn't used.
- **Impact:** Debugging difficulty.
- **Exploitability:** LOW.

#### L-4: Silent Env Var Key Auto-Detection Failure (Gateway)
- **File:Line:** `src/sanna/gateway/server.py:1809`
- **Description:** Same as L-3 for gateway.
- **Impact:** Same as L-3.
- **Exploitability:** LOW.

#### L-5: Receipt Persistence Silent Failure (Store)
- **File:Line:** `src/sanna/middleware.py:1278`
- **Description:** `except Exception:` when saving to store. Logged with `exc_info=True` but execution continues.
- **Impact:** Receipt persistence failures don't block function. Intentional but could miss governance gaps.
- **Exploitability:** LOW.

#### L-6: Receipt Persistence Silent Failure (Sink)
- **File:Line:** `src/sanna/middleware.py:1285`
- **Description:** Same as L-5 for sink.
- **Impact:** Same as L-5.
- **Exploitability:** LOW.

#### L-7: HTTP Header Values Not Included in Input Hash
- **File:Line:** `src/sanna/interceptors/http_interceptor.py:247-248`
- **Description:** HTTP interceptor hashes only header **keys**, not values. Different header values for same keys produce identical `input_hash`.
- **Impact:** Weakened audit trail -- requests with different header values appear identical.
- **Exploitability:** LOW.

#### L-8: Script Content Inspection Limited to 8KB
- **File:Line:** `src/sanna/interceptors/subprocess_interceptor.py:471, 474-567`
- **Description:** Script inspection reads only first 8KB. Commands beyond 8KB, in variables, or in binary executables are not detected. Documented limitation.
- **Impact:** Wrapper scripts can invoke blocked commands beyond the inspection limit.
- **Exploitability:** LOW -- requires writing wrapper scripts.

#### L-9: shlex Fallback on Malformed Quoting
- **File:Line:** `src/sanna/interceptors/subprocess_interceptor.py:329-331, 378-380, 443-445, 1240-1242`
- **Description:** When `shlex.split()` raises `ValueError`, fallback to simple `split()` changes parsing semantics.
- **Impact:** Malformed commands may be parsed differently than the shell, though execution still uses original command string.
- **Exploitability:** LOW.

#### L-10: Justification Type Confusion Bypass
- **File:Line:** `src/sanna/gateway/server.py:3434-3437`
- **Description:** Non-string `_justification` (dict, list, number) is silently coerced to `None`. Agent could bypass justification requirement by providing non-string value.
- **Impact:** Justification requirement bypass via type confusion.
- **Exploitability:** LOW -- MCP schema declares string type.

#### L-11: Escalation Receipt Chain Not Cryptographically Validated
- **File:Line:** `src/sanna/gateway/server.py:3515-3521`
- **Description:** `parent_receipts_list` references prior receipt IDs without verifying existence, ownership, or authenticity.
- **Impact:** Invalid receipt chain records; audit trail confusion.
- **Exploitability:** LOW.

#### L-12: Symlink Race in CloudHTTPSink mkdir
- **File:Line:** `src/sanna/sinks/cloud.py:227-228`
- **Description:** Buffer directory creation uses `mkdir(parents=True)` without `ensure_secure_dir()`, bypassing symlink protections in safe_io.
- **Impact:** Potential to write buffer to attacker-controlled location.
- **Exploitability:** LOW -- requires temp directory symlink setup.

#### L-13: URL Scheme Normalization Missing
- **File:Line:** `src/sanna/interceptors/http_interceptor.py:491, 521, 550`
- **Description:** URLs converted via `str(url)` without case normalization or encoding normalization.
- **Impact:** Constitution patterns might not consistently match equivalent URLs.
- **Exploitability:** LOW.

#### L-14: No SSRF Mitigation in HTTP Interceptor
- **File:Line:** `src/sanna/interceptors/api_authority.py:31-98`
- **Description:** HTTP interceptor does not check for private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.0.0/16). SSRF protection is delegated to constitution configuration.
- **Impact:** SSRF possible if constitution allows broad HTTP access.
- **Exploitability:** LOW -- constitution responsibility.

---

### INFO (Positive Findings)

#### I-1: Modern Cryptographic Primitives
- Ed25519 (EDDSA), SHA-256, proper PEM serialization. No deprecated algorithms.

#### I-2: Base64 Validation Correct
- `base64.b64decode(sig_clean, validate=True)` with proper error handling.

#### I-3: Key File Permissions Set Correctly at Generation
- Private: 0o600, Public: 0o644, Directory: 0o700.

#### I-4: Atomic Writes with Symlink Protection (safe_io.py)
- `tempfile.mkstemp()`, `os.fsync()`, `os.replace()`, O_NOFOLLOW.

#### I-5: SQLite Hardening Comprehensive (store.py)
- Symlink rejection, O_NOFOLLOW, ownership validation, fchmod, WAL sidecar hardening, /tmp rejection.

#### I-6: Bundle Extraction Path Traversal Protected
- `is_relative_to()` check, size limits (10 members, 10MB each).

#### I-7: SQL Injection Prevention
- All queries use parameterized `?` placeholders.

#### I-8: No Unsafe Deserialization
- No pickle, marshal, eval, exec on untrusted input.

#### I-9: No Hardcoded Credentials
- Only placeholder examples in documentation. Test keys have no production value.

#### I-10: Secure Temp File Patterns
- No `tempfile.mktemp()`. Uses `mkstemp()` and `mkdtemp()` properly.

#### I-11: Subprocess Interceptor Documented Threat Model
- Clearly states monkeypatching is not a security boundary; directs to SannaGateway.

---

## Summary Table

| Severity | Count | Key Areas |
|----------|-------|-----------|
| CRITICAL | 4 | Receipt integrity (status/details not in fingerprint), unencrypted keys, YAML loader |
| HIGH | 7 | Check data format inconsistency, unsafe json.loads, TOCTOU, key serialization |
| MEDIUM | 20 | Memory cleanup, exception handling, PII redaction, SSRF, interceptor gaps |
| LOW | 14 | Timing attacks, silent failures, type confusion, URL normalization |
| INFO | 11 | Positive findings confirming good practices |

---

## Methodology

This audit was conducted by reading source code across all 10 scope areas simultaneously:
1. **Crypto module** -- full review of `crypto.py`
2. **Exception handling** -- grep + manual review of all try/except in security-critical modules
3. **Input validation** -- YAML/JSON parsing, CLI args, public API entry points
4. **Subprocess interceptor** -- race conditions, bypass vectors, shell parsing
5. **HTTP interceptor** -- SSRF, header injection, URL parsing
6. **Gateway** -- MCP injection, TOCTOU, PII redaction, receipt signing
7. **Receipt integrity** -- fingerprint manipulation, hash collision, signature coverage
8. **Dependencies** -- version constraints, known CVEs
9. **Secrets/credentials** -- hardcoded values, logging, test fixtures
10. **File operations** -- path traversal, symlink attacks, temp files

---

*This report documents findings only. No code changes were made.*
