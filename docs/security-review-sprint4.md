# Security Review: Sprint 4 (SAN-35)

**Date:** 2026-03-23
**Scope:** Commits `6877fff` (feature/patch-subprocess merge), `9f532da` (SAN-1 exception narrowing), `467faa5` (SAN-27 fingerprint edge cases)
**Reviewer:** Claude Code (automated security audit)

---

## Executive Summary

Sprint 4 introduced a subprocess interceptor for CLI governance, narrowed exception handling across 18 files, and fixed fingerprint edge cases for TypeScript/spec alignment. The audit found **1 critical vulnerability** (shell metacharacter bypass in the subprocess interceptor) that was fixed in this commit. Several HIGH/MEDIUM findings are documented for remediation in future sprints.

---

## 1. Subprocess Interceptor (feature/patch-subprocess)

### CRITICAL-1: Shell metacharacter bypass via `shell=True` (FIXED)

**Location:** `src/sanna/interceptors/subprocess_interceptor.py`, `_resolve_command()`

When `shell=True` is passed to `subprocess.run()` (or `call`, `check_call`, `check_output`, `Popen`), the kernel's `/bin/sh` interprets shell metacharacters (`;`, `|`, `&&`, `||`, `` ` ``, `$()`) for command chaining. The interceptor was parsing the command with `str.split()`, which only sees whitespace — it evaluated authority on the first command only.

**Exploit example:**
```python
subprocess.run("echo hello; rm -rf /", shell=True)
# Interceptor sees: binary="echo", argv=["hello;", "rm", "-rf", "/"]
# Authority check: "echo" -> can_execute -> allowed
# Shell executes: echo hello AND rm -rf /
```

**Fix applied:** Added `_check_shell_chaining()` which splits command strings on shell operators (`;`, `|`, `||`, `&&`) and also extracts `$()` and backtick substitutions. Each sub-command is independently evaluated against the constitution's authority boundaries. Uses `shlex.split()` instead of `str.split()` for proper tokenization. Applied to all 6 patched entry points (`subprocess.run`, `.call`, `.check_call`, `.check_output`, `Popen`, `os.system`).

### CRITICAL-2: Unpatched execution surfaces (DOCUMENTED — not fixed)

**Severity:** CRITICAL (design limitation)

The interceptor patches 6 entry points but the following allow unrestricted execution:

| Surface | Risk |
|---------|------|
| `os.execl/execle/execlp/execlpe/execv/execve/execvp/execvpe` | Replace current process entirely |
| `os.spawnl/spawnle/spawnlp/spawnlpe/spawnv/spawnve/spawnvp/spawnvpe` | Spawn new processes |
| `os.popen()` | Pipe to/from a command |
| `os.posix_spawn/posix_spawnp` | POSIX spawn |
| `ctypes` → `libc.system()` / `execve()` | Direct C library calls |

**Recommendation:** Future sprint should either (a) patch `os.exec*`, `os.spawn*`, and `os.popen`, or (b) document this explicitly in the interceptor's threat model as a known boundary. Option (b) is acceptable if the threat model assumes the governed agent does not have arbitrary code execution — the interceptor protects against tool-use agents, not full code execution.

### CRITICAL-3: Trivial unpatch by governed code (DOCUMENTED — not fixed)

**Severity:** CRITICAL (design limitation)

`unpatch_subprocess()` is a public API in `__init__.py`. Governed code can:
```python
from sanna.interceptors import unpatch_subprocess
unpatch_subprocess()  # All governance removed
```

Also, `_originals` dict is accessible:
```python
from sanna.interceptors.subprocess_interceptor import _originals
_originals["subprocess.run"](["rm", "-rf", "/"])
```

**Recommendation:** This is a fundamental Python limitation (monkeypatching is always reversible). Document in threat model. If stronger isolation is needed, the gateway architecture (separate process) is the correct approach.

### HIGH-1: TOCTOU between authority check and execution

**Location:** All patched functions (e.g., `_patched_run()` lines 542-555)

A window exists between the authority check and `_originals[...](*args, **kwargs)`. If caller passes a mutable list and another thread mutates it, the executed command could differ from what was checked. Mitigated by Python's GIL in CPython.

### HIGH-2: Path traversal in binary name

The interceptor uses `os.path.basename(binary)` which correctly strips path components, but an agent can create wrapper scripts on disk:
```python
# Write malicious script, then execute it
subprocess.run(["./innocent_name.sh"])  # binary_name="innocent_name.sh" → not in deny list
```

### HIGH-3: Thread-unsafe `_restore_originals` context manager

`_restore_originals` temporarily restores original subprocess functions for the duration of the real call. During this window, concurrent calls from other threads execute without interception.

### HIGH-4: Environment variable manipulation not governed

An agent can manipulate execution through env vars:
```python
subprocess.run(["git", "push"], env={**os.environ, "GIT_SSH_COMMAND": "rm -rf /"})
```

### MEDIUM-1: `fnmatch` argv matching has edge cases

Double spaces in arguments (`["git", "push", " --force"]`) produce `"push  --force origin"` which doesn't match `"push --force*"`.

### MEDIUM-2: Invalid regex patterns in invariants silently skipped

`cli_authority.py` catches `re.error` and skips malformed regex patterns without warning. Constitution authors get no feedback that their rule is ineffective.

---

## 2. Fingerprint Edge Cases (SAN-27)

### MEDIUM-3: Empty checks hash change without CHECKS_VERSION bump

**Location:** `receipt.py`, `middleware.py`, `verify.py`, `gateway/server.py`

Empty checks array changed from `hash_obj([])` to `EMPTY_HASH`. This is a semantic change: any `checks_version: "6"` receipt with zero checks generated before this commit will fail verification after it. The verifier has no way to distinguish pre-fix vs post-fix receipts.

**Impact:** Low in practice — the empty-checks path (`_generate_no_invariants_receipt`) is rarely exercised, and no golden receipts were affected. However, any production receipts from this path are now unverifiable.

**Recommendation:** Either bump `CHECKS_VERSION` to `"7"` with a fallback, or document as known incompatibility.

### INFO: All 4 fingerprint sites remain in parity

Verified field-by-field: `receipt.py`, `middleware.py`, `verify.py`, and `gateway/server.py` all use the same 14-field formula with identical logic for `EMPTY_HASH`, `is not None` checks, and `constitution_approval` stripping.

### INFO: No fingerprint collision attack surface

The pipe-delimited formula prevents field-shifting. `EMPTY_HASH` is deterministic. The conditional 4-field vs 8-field check hashing auto-detects correctly based on `triggered_by` presence.

---

## 3. Exception Narrowing (SAN-1)

### MEDIUM-4: Missing `UnsupportedAlgorithm` in crypto catches

**Location:** `bundle.py` (lines 514, 560, 667), `constitution.py` (line 1687), `verify.py` (line 789)

`cryptography.exceptions.UnsupportedAlgorithm` inherits from `Exception`, not from `ValueError`/`TypeError`/`OSError`. The narrowed catches miss this exception. In practice, `load_public_key()` checks `isinstance` first and raises `ValueError` for non-Ed25519 keys, so this only fires for truly unsupported backend algorithms — rare but possible.

**Impact:** Uncaught exception crashes verification instead of recording a failed check (fail-closed, which is safe but not graceful).

### MEDIUM-5: Threaded webhook fallback misses `TypeError`

**Location:** `enforcement/escalation.py` (line 372)

Narrowed from `except Exception` to `except (OSError, urllib.error.URLError)`. If `payload` contains non-serializable objects, `json.dumps()` raises `TypeError` which is now uncaught. Since this runs in a daemon thread, the exception silently kills the thread.

### LOW-1: MCP server crypto catches left broad (inconsistency)

`mcp/server.py` (lines 772, 859) retains `except Exception` while equivalent blocks in `bundle.py`/`verify.py` were narrowed. Not a bug (outer MCP handler catches all), but inconsistent.

### INFO: No sensitive information leakage detected

All narrowed catches follow safe patterns: no stack traces to users, no key material in error messages, crypto errors produce generic "verification failed" messages.

---

## Summary

| ID | Severity | Area | Status |
|----|----------|------|--------|
| CRITICAL-1 | CRITICAL | Shell metacharacter bypass | **FIXED** |
| CRITICAL-2 | CRITICAL | Unpatched os.exec*/spawn*/popen | Documented (design limitation) |
| CRITICAL-3 | CRITICAL | Trivial unpatch | Documented (design limitation) |
| HIGH-1 | HIGH | TOCTOU race | Documented |
| HIGH-2 | HIGH | Path traversal via wrapper scripts | Documented |
| HIGH-3 | HIGH | Thread-unsafe _restore_originals | Documented |
| HIGH-4 | HIGH | Env var manipulation | Documented |
| MEDIUM-1 | MEDIUM | fnmatch edge cases | Documented |
| MEDIUM-2 | MEDIUM | Silent regex errors | Documented |
| MEDIUM-3 | MEDIUM | Empty checks hash change | Documented |
| MEDIUM-4 | MEDIUM | Missing UnsupportedAlgorithm | Documented |
| MEDIUM-5 | MEDIUM | Webhook TypeError | Documented |
| LOW-1 | LOW | MCP catch inconsistency | Documented |
