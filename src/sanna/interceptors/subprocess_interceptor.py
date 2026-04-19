"""Subprocess interceptor — patches Python's subprocess module at runtime.

Enforces governance on CLI subprocess invocations by intercepting calls to
subprocess.run, subprocess.Popen, subprocess.call, subprocess.check_call,
subprocess.check_output, os.system, os.exec*, os.spawn*, and os.popen.

Each intercepted call:
1. Extracts binary name and argv
2. Resolves binary to absolute path (TOCTOU mitigation)
3. Evaluates against constitution cli_permissions (using basename)
4. Computes receipt triad (input_hash, reasoning_hash, action_hash)
5. Generates and persists a governance receipt
6. Passes resolved absolute path to the actual subprocess call
7. Either allows, halts (FileNotFoundError), or escalates (PermissionError)

SECURITY MODEL — DEFENSE-IN-DEPTH FOR TRUSTED CODE ONLY:

This interceptor provides defense-in-depth governance for cooperative,
trusted code running in the same Python process. It is NOT a security
boundary against adversarial or untrusted code.

Because the interceptor works via Python monkeypatching (replacing
subprocess.run, os.system, etc. with governed wrappers), any code running
in the same process can reverse the patches:

    from sanna.interceptors import unpatch_subprocess
    unpatch_subprocess()  # All governance removed

    # Or access originals directly:
    from sanna.interceptors.subprocess_interceptor import _originals
    _originals["subprocess.run"](["cmd"])  # Bypass governance

This is a fundamental limitation of in-process monkeypatching in Python,
not a bug. The unpatch_subprocess() function exists intentionally — it is
required for clean teardown, testing, and legitimate operational use.

For untrusted or adversarial code, the correct architecture is the
SannaGateway (out-of-process MCP enforcement proxy), which provides
process-level isolation that cannot be bypassed by the governed code.
See docs/deployment-tiers.md for guidance on choosing the right tier.

BINARY PATH RESOLUTION NOTE: Binary path resolution mitigates PATH-based
TOCTOU attacks by resolving the binary to an absolute path before authority
evaluation and passing the resolved path to the actual subprocess call.
However, filesystem-level attacks (replacing the binary file at the resolved
path between check and exec) cannot be prevented in userspace.
"""

from __future__ import annotations

import errno
import logging
import os
import shlex
import shutil
import subprocess
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..constitution import load_constitution, constitution_to_receipt_ref
from ..hashing import hash_obj, hash_text, EMPTY_HASH
from ..receipt import (
    generate_receipt,
    SannaReceipt,
    SPEC_VERSION,
    TOOL_VERSION,
    CHECKS_VERSION,
)
from ..sinks.sink import ReceiptSink, SinkResult, FailurePolicy
from .cli_authority import evaluate_cli_authority, CliAuthorityDecision

logger = logging.getLogger("sanna.interceptor.subprocess")


# =============================================================================
# MODULE STATE
# =============================================================================

_state: dict = {}
_originals: dict = {}
_patched: bool = False
_patched_os_funcs: dict = {}  # Maps "os.<name>" to patched function for re-application

# Thread-safety for _restore_originals: RLock prevents concurrent ungoverned
# access during the restore window; thread-local flag prevents recursion when
# subprocess.run internally calls Popen (both patched).
_restore_lock = threading.RLock()
_thread_local = threading.local()


class _restore_originals:
    """Context manager that temporarily restores all original subprocess functions.

    The original subprocess functions internally reference each other by name
    from the subprocess module. When we've patched them, calling an original
    would still use our patched versions for internal calls, causing double
    interception. This context manager swaps everything back for the duration.

    Thread-safe: acquires _restore_lock on __enter__ and releases on __exit__,
    preventing another thread from seeing ungoverned functions during the window.
    Sets a thread-local flag so that internal call chains (e.g., subprocess.run
    calling Popen) skip governance instead of deadlocking.
    """

    def __enter__(self):
        _restore_lock.acquire()
        _thread_local.restoring = True
        for key, orig in _originals.items():
            mod_name, attr_name = key.rsplit(".", 1)
            mod = subprocess if mod_name == "subprocess" else os
            setattr(mod, attr_name, orig)
        return self

    def __exit__(self, *args):
        try:
            if _patched:
                subprocess.run = _patched_run
                subprocess.call = _patched_call
                subprocess.check_call = _patched_check_call
                subprocess.check_output = _patched_check_output
                subprocess.Popen = _PatchedPopen
                os.system = _patched_os_system
                # Re-apply os.exec*/spawn*/popen patches
                for key in _originals:
                    if key.startswith("os.") and key != "os.system":
                        attr_name = key.split(".", 1)[1]
                        patched_fn = _patched_os_funcs.get(key)
                        if patched_fn is not None:
                            setattr(os, attr_name, patched_fn)
        finally:
            _thread_local.restoring = False
            _restore_lock.release()
        return False


# =============================================================================
# PUBLIC API
# =============================================================================

def patch_subprocess(
    constitution_path: str,
    sink: ReceiptSink,
    agent_id: str,
    mode: str = "enforce",
    signing_key: Optional[bytes] = None,
    content_mode: Optional[str] = None,
    workflow_id: Optional[str] = None,
    parent_fingerprint: Optional[str] = None,
) -> None:
    """Patch Python's subprocess module to enforce governance.

    Args:
        constitution_path: Path to the constitution YAML/JSON file.
        sink: ReceiptSink implementation for persisting receipts.
        agent_id: Agent identifier for receipts.
        mode: Enforcement mode — "enforce", "audit", or "passthrough".
        signing_key: Optional Ed25519 private key bytes for receipt signing.
        content_mode: Optional content mode attestation (e.g., "full").
        workflow_id: Optional workflow identifier for receipt chaining.
        parent_fingerprint: Optional parent receipt fingerprint for chaining.
    """
    global _patched

    # Idempotent: second call is a no-op
    if _patched:
        return

    if mode not in ("enforce", "audit", "passthrough"):
        raise ValueError(f"Invalid mode: {mode!r}. Must be 'enforce', 'audit', or 'passthrough'.")

    constitution = load_constitution(constitution_path)

    _state.update({
        "constitution": constitution,
        "constitution_path": constitution_path,
        "sink": sink,
        "agent_id": agent_id,
        "mode": mode,
        "signing_key": signing_key,
        "content_mode": content_mode,
        "workflow_id": workflow_id,
        "parent_fingerprint": parent_fingerprint,
    })

    # Store originals
    _originals["subprocess.run"] = subprocess.run
    _originals["subprocess.Popen"] = subprocess.Popen
    _originals["subprocess.call"] = subprocess.call
    _originals["subprocess.check_call"] = subprocess.check_call
    _originals["subprocess.check_output"] = subprocess.check_output
    _originals["os.system"] = os.system

    # Apply patches
    subprocess.run = _patched_run
    subprocess.call = _patched_call
    subprocess.check_call = _patched_check_call
    subprocess.check_output = _patched_check_output
    subprocess.Popen = _PatchedPopen
    os.system = _patched_os_system

    # Patch os.exec* family (platform-aware)
    _exec_names = [
        "execv", "execve", "execvp", "execvpe",
        "execl", "execle", "execlp", "execlpe",
    ]
    for name in _exec_names:
        if hasattr(os, name):
            _originals[f"os.{name}"] = getattr(os, name)
            patched_fn = _make_patched_exec(name)
            _patched_os_funcs[f"os.{name}"] = patched_fn
            setattr(os, name, patched_fn)

    # Patch os.spawn* family (platform-aware)
    _spawn_names = [
        "spawnl", "spawnle", "spawnlp", "spawnlpe",
        "spawnv", "spawnve", "spawnvp", "spawnvpe",
    ]
    for name in _spawn_names:
        if hasattr(os, name):
            _originals[f"os.{name}"] = getattr(os, name)
            patched_fn = _make_patched_spawn(name)
            _patched_os_funcs[f"os.{name}"] = patched_fn
            setattr(os, name, patched_fn)

    # Patch os.popen
    if hasattr(os, "popen"):
        _originals["os.popen"] = os.popen
        _patched_os_funcs["os.popen"] = _patched_os_popen
        os.popen = _patched_os_popen

    _patched = True


def unpatch_subprocess() -> None:
    """Restore all original subprocess, os.system, os.exec*, os.spawn*, and os.popen functions.

    This function intentionally removes all governance patches, restoring the
    original unpatched functions. This is a design limitation of in-process
    monkeypatching, not a bug — any code in the same Python process can call
    this function to remove governance.

    Intended use cases:
    - Clean teardown in test fixtures
    - Operational scenarios where governance must be temporarily disabled
    - Application shutdown

    This function is NOT a security concern in the intended threat model:
    the subprocess interceptor is defense-in-depth for trusted code only.
    For untrusted code isolation, use the SannaGateway architecture
    (out-of-process MCP enforcement proxy) instead.
    """
    global _patched

    if not _patched:
        return

    subprocess.run = _originals["subprocess.run"]
    subprocess.Popen = _originals["subprocess.Popen"]
    subprocess.call = _originals["subprocess.call"]
    subprocess.check_call = _originals["subprocess.check_call"]
    subprocess.check_output = _originals["subprocess.check_output"]
    os.system = _originals["os.system"]

    # Restore os.exec*, os.spawn*, os.popen
    for key, orig in _originals.items():
        if key.startswith("os.") and key != "os.system":
            attr_name = key.split(".", 1)[1]
            setattr(os, attr_name, orig)

    _originals.clear()
    _state.clear()
    _patched_os_funcs.clear()
    _patched = False


# =============================================================================
# COMMAND PARSING
# =============================================================================

def _is_shell_mode(args, kwargs):
    """Detect if the subprocess call uses shell=True."""
    return kwargs.get("shell", False)


# Shell metacharacters that indicate command chaining or injection.
_SHELL_METACHAR_RE = None


def _get_shell_metachar_re():
    global _SHELL_METACHAR_RE
    if _SHELL_METACHAR_RE is None:
        import re
        # Matches: ; | & ` $( ) || && and backticks
        _SHELL_METACHAR_RE = re.compile(r'[;|&`$]')
    return _SHELL_METACHAR_RE


def _resolve_command(args, kwargs, env=None):
    """Extract binary name, resolve to absolute path, and return argv.

    Returns (binary_name, argv, raw_cmd, resolved_path).

    ``binary_name`` is the basename used for authority evaluation.
    ``resolved_path`` is the absolute path from shutil.which() used for the
    actual subprocess call (TOCTOU mitigation).  If the binary cannot be
    resolved (not on PATH), ``resolved_path`` is None and the original
    command is used as-is (letting the actual call fail naturally).

    When shell=True with a string command, uses shlex.split() for proper
    tokenization that respects quoting, and detects shell metacharacters
    (pipes, semicolons, &&, ||, backticks, $()) that could chain commands.

    If env is provided and contains a PATH key, shutil.which() uses that
    PATH for resolution — ensuring the interceptor evaluates authority for
    the same binary the subprocess will actually execute.
    """
    cmd = args[0] if args else kwargs.get("args", [])
    shell_mode = _is_shell_mode(args, kwargs)

    if isinstance(cmd, str):
        if shell_mode:
            # Use shlex for proper shell tokenization
            try:
                parts = shlex.split(cmd)
            except ValueError:
                # Malformed quoting — treat entire string as the command
                parts = [cmd]
        else:
            parts = cmd.split()
        binary = parts[0] if parts else ""
        argv = parts[1:]
    else:
        cmd = list(cmd)
        binary = cmd[0] if cmd else ""
        argv = cmd[1:]

    binary_name = os.path.basename(binary)

    # Resolve binary to absolute path to prevent PATH-based TOCTOU attacks.
    # If already absolute, resolve symlinks; otherwise use shutil.which().
    # When env is provided with a PATH key, use that PATH for resolution
    # to match what the subprocess will actually execute.
    if binary and os.path.isabs(binary):
        resolved_path = os.path.realpath(binary)
    elif binary:
        which_path = env.get("PATH") if env else None
        resolved_path = shutil.which(binary, path=which_path)
    else:
        resolved_path = None

    return binary_name, argv, cmd, resolved_path


def _substitute_resolved_path(args, kwargs, resolved_path):
    """Replace the binary in subprocess args with the resolved absolute path.

    Returns (new_args, new_kwargs) suitable for passing to the original
    subprocess function.  When resolved_path is None (binary not found),
    returns the original args/kwargs unchanged.
    """
    if resolved_path is None:
        return args, kwargs

    cmd = args[0] if args else kwargs.get("args", [])
    shell_mode = _is_shell_mode(args, kwargs)

    if isinstance(cmd, str):
        if shell_mode:
            # For shell=True strings, replace the first token with the
            # resolved path.  We cannot simply do string replacement because
            # the binary might appear elsewhere in the command; instead we
            # find the first token boundary.
            try:
                parts = shlex.split(cmd)
            except ValueError:
                parts = cmd.split()
            if parts:
                # Replace first token, preserve rest of the original string
                # by finding where the first token ends.
                stripped = cmd.lstrip()
                first_token = parts[0]
                # Handle quoted first token
                if stripped.startswith(("'", '"')):
                    quote = stripped[0]
                    end = stripped.index(quote, 1) + 1
                else:
                    end = len(first_token)
                prefix_ws = cmd[:len(cmd) - len(stripped)]
                new_cmd = prefix_ws + resolved_path + stripped[end:]
            else:
                new_cmd = cmd
        else:
            # Non-shell string: split, replace first, rejoin
            parts = cmd.split()
            if parts:
                parts[0] = resolved_path
            new_cmd = " ".join(parts) if parts else cmd
    else:
        # List/tuple form: replace first element
        cmd_list = list(cmd)
        if cmd_list:
            cmd_list[0] = resolved_path
        new_cmd = cmd_list

    # Rebuild args/kwargs
    if args:
        new_args = (new_cmd,) + args[1:]
        return new_args, kwargs
    else:
        new_kwargs = dict(kwargs)
        new_kwargs["args"] = new_cmd
        return args, new_kwargs


def _check_shell_chaining(cmd_str: str, constitution) -> None:
    """Detect shell command chaining and evaluate each chained command.

    When shell=True, the shell interprets metacharacters like ;, |, &&, ||,
    backticks, and $() which can chain multiple commands. We split on these
    operators and evaluate each sub-command against the constitution.

    Raises FileNotFoundError if any chained command would be halted.
    """
    import re
    # Split on shell operators: ;, |, ||, &&, `, $()
    # This is conservative — we split and check each piece
    sub_commands = re.split(r'\s*(?:;|\|\||&&|\|)\s*', cmd_str)
    # Also handle $() and backtick substitutions
    subst_re = re.compile(r'\$\(([^)]+)\)|`([^`]+)`')
    for match in subst_re.finditer(cmd_str):
        inner = match.group(1) or match.group(2)
        sub_commands.append(inner.strip())

    for sub_cmd in sub_commands:
        sub_cmd = sub_cmd.strip()
        if not sub_cmd:
            continue
        try:
            parts = shlex.split(sub_cmd)
        except ValueError:
            parts = sub_cmd.split()
        if not parts:
            continue
        sub_binary = os.path.basename(parts[0])
        sub_argv = parts[1:]
        decision = evaluate_cli_authority(sub_binary, sub_argv, constitution)
        if decision.decision == "halt":
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                sub_binary,
            )
        if decision.decision == "escalate":
            raise PermissionError(
                f"Escalation required for chained command '{sub_binary}': "
                f"{decision.reason}"
            )


# Script file extensions that indicate interpretable scripts.
_SCRIPT_EXTENSIONS = frozenset({
    ".sh", ".bash", ".zsh", ".fish",
    ".py", ".rb", ".pl", ".perl",
})

# Maximum bytes to read from a script file for inspection.
_SCRIPT_INSPECT_LIMIT = 8192


def _inspect_script_content(
    resolved_path: Optional[str],
    constitution,
) -> list[str]:
    """Best-effort script content inspection for wrapper script bypass detection.

    Reads the first 8KB of a script file and checks for blocked command patterns
    from the constitution's cannot_execute list.

    Best-effort detection. Will NOT catch: obfuscated commands, variable expansion
    ($CMD), aliases, dynamically constructed commands, commands beyond the 8KB
    inspection window, or binary executables that invoke blocked commands.

    Args:
        resolved_path: Absolute path to the binary being executed.
        constitution: Loaded constitution object.

    Returns:
        List of blocked command basenames found in the script, or empty list if
        the file is clean, not a script, or cannot be read.
    """
    if resolved_path is None:
        return []

    cli_perms = getattr(constitution, "cli_permissions", None)
    if cli_perms is None:
        return []

    if not cli_perms.inspect_scripts:
        return []

    # Determine if the target is a script by extension or shebang.
    path_obj = Path(resolved_path)

    # Check extension first (cheapest check).
    is_script = path_obj.suffix.lower() in _SCRIPT_EXTENSIONS

    if not is_script:
        # Check for shebang: read first 2 bytes.
        try:
            fd = os.open(resolved_path, os.O_RDONLY | os.O_NOFOLLOW)
        except (OSError, IOError):
            return []
        try:
            header = os.read(fd, 2)
        finally:
            os.close(fd)
        if header == b"#!":
            is_script = True

    if not is_script:
        return []

    # Read script content (up to limit).
    try:
        fd = os.open(resolved_path, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, IOError):
        return []
    try:
        content_bytes = os.read(fd, _SCRIPT_INSPECT_LIMIT)
    finally:
        os.close(fd)

    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        return []

    # Build set of blocked basenames from cannot_execute commands.
    blocked_basenames: set[str] = set()
    for cmd in cli_perms.commands:
        if cmd.authority == "cannot_execute":
            blocked_basenames.add(cmd.binary)

    if not blocked_basenames:
        return []

    # Tokenize script content: split on whitespace, semicolons, pipes,
    # ampersands, parentheses, backticks, quotes, and newlines.
    import re
    tokens = re.split(r'[\s;|&()`\n"\']+', content)

    # Check each token's basename against blocked commands.
    found: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if not token:
            continue
        basename = os.path.basename(token)
        if basename in blocked_basenames and basename not in seen:
            found.append(basename)
            seen.add(basename)

    return found


def _build_input_obj(binary_name: str, argv: list, kwargs: dict) -> dict:
    """Build the canonical input object for input_hash computation.

    Keys in alphabetical order per protocol v1.2 Section 7.6.
    """
    env = kwargs.get("env", os.environ)
    env_keys = sorted(env.keys()) if env else []

    cwd = kwargs.get("cwd", os.getcwd())
    if isinstance(cwd, Path):
        cwd = str(cwd)

    return {
        "args": argv,
        "command": binary_name,
        "cwd": cwd,
        "env_keys": env_keys,
    }


# =============================================================================
# RECEIPT EMISSION
# =============================================================================

def _emit_receipt(
    *,
    event_type: str,
    context_limitation: str,
    input_hash: str,
    reasoning_hash: str,
    action_hash: str,
    decision: CliAuthorityDecision,
    binary_name: str,
    argv: list,
    cwd: str,
    justification: Optional[str],
    exit_code: Optional[int] = None,
    extensions: Optional[dict] = None,
) -> Optional[str]:
    """Generate and persist a CLI governance receipt.

    Returns the receipt fingerprint on success, None on failure.
    """
    correlation_id = f"{binary_name}-{uuid.uuid4()}"

    inputs = {
        "query": f"{binary_name} {' '.join(str(a) for a in argv)}",
        "context": justification or None,
    }
    outputs = {
        "response": f"decision={decision.decision}, reason={decision.reason}"
        + (f", exit_code={exit_code}" if exit_code is not None else ""),
    }

    # Map decision to enforcement action
    action_map = {
        "halt": "halted",
        "escalate": "escalated",
        "allow": "allowed",
    }
    enforcement_action = action_map.get(decision.decision, "allowed")

    # In audit mode, the action actually taken is "allowed" (we let it through)
    if _state["mode"] == "audit" and decision.decision in ("halt", "escalate"):
        enforcement_action = "warned"

    enforcement_dict = {
        "action": enforcement_action,
        "reason": decision.reason,
        "failed_checks": [],
        "enforcement_mode": _state["mode"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Build constitution_ref
    constitution_ref = None
    try:
        constitution_ref = constitution_to_receipt_ref(_state["constitution"])
    except Exception:
        logger.debug("Could not build constitution_ref", exc_info=True)

    # Build receipt extensions
    receipt_extensions = {
        "com.sanna.interceptor": {
            "surface": "cli",
            "binary": binary_name,
            "rule_id": decision.rule_id,
            "input_hash": input_hash,
            "reasoning_hash": reasoning_hash,
            "action_hash": action_hash,
        },
    }
    if extensions:
        receipt_extensions["com.sanna.interceptor"].update(extensions)

    # Build trace_data for generate_receipt
    trace_data = {
        "correlation_id": correlation_id,
        "observations": [],
        "output": {"final_answer": outputs["response"]},
        "input": inputs.get("query", ""),
        "metadata": {},
    }

    receipt = generate_receipt(
        trace_data=trace_data,
        constitution_ref_override=constitution_ref,
        parent_receipts=[_state["parent_fingerprint"]] if _state.get("parent_fingerprint") else None,
        workflow_id=_state.get("workflow_id"),
        content_mode=_state.get("content_mode"),
        event_type=event_type,
        context_limitation=context_limitation,
        skip_default_checks=True,
        enforcement=enforcement_dict,
        enforcement_surface="cli_interceptor",
        invariants_scope="authority_only",
    )

    # Convert to dict for sink
    receipt_dict = asdict(receipt)
    receipt_dict["enforcement"] = enforcement_dict
    receipt_dict["extensions"] = receipt_extensions

    # Store receipt triad fields
    receipt_dict["input_hash"] = input_hash
    receipt_dict["reasoning_hash"] = reasoning_hash
    receipt_dict["action_hash"] = action_hash
    receipt_dict["event_type"] = event_type
    receipt_dict["context_limitation"] = context_limitation

    # Persist
    try:
        result = _state["sink"].store(receipt_dict)
        if not result.ok:
            logger.warning("Receipt sink reported failures: %s", result.errors)
    except Exception:
        logger.warning("Failed to persist CLI receipt", exc_info=True)

    return receipt.receipt_fingerprint


# =============================================================================
# ENFORCEMENT HELPERS
# =============================================================================

def _enforce_decision(
    decision: CliAuthorityDecision,
    binary_name: str,
    argv: list,
    cwd: str,
    input_hash: str,
    reasoning_hash: str,
    justification: Optional[str],
) -> None:
    """Apply enforcement decision. Raises on halt/escalate in enforce mode.

    In audit or passthrough mode, returns without raising.
    """
    if _state["mode"] == "passthrough":
        return

    if decision.decision == "halt" and _state["mode"] == "enforce":
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)

        _emit_receipt(
            event_type="cli_invocation_halted",
            context_limitation="cli_no_justification" if not justification else "cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary_name,
            argv=argv,
            cwd=cwd,
            justification=justification,
        )

        raise FileNotFoundError(
            errno.ENOENT,
            os.strerror(errno.ENOENT),
            binary_name,
        )

    elif decision.decision == "escalate" and _state["mode"] == "enforce":
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)

        _emit_receipt(
            event_type="cli_invocation_escalated",
            context_limitation="cli_no_justification" if not justification else "cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary_name,
            argv=argv,
            cwd=cwd,
            justification=justification,
        )

        raise PermissionError(f"Escalation required: {decision.reason}")


def _compute_action_hash(result) -> str:
    """Compute action_hash from a CompletedProcess result."""
    stdout_str = ""
    stderr_str = ""
    if result.stdout is not None:
        stdout_str = (
            result.stdout.decode("utf-8", errors="replace")
            if isinstance(result.stdout, bytes)
            else str(result.stdout)
        )
    if result.stderr is not None:
        stderr_str = (
            result.stderr.decode("utf-8", errors="replace")
            if isinstance(result.stderr, bytes)
            else str(result.stderr)
        )

    action_obj = {
        "exit_code": result.returncode,
        "stderr": stderr_str,
        "stdout": stdout_str,
    }
    return hash_obj(action_obj)


def _maybe_inspect_script(
    decision: CliAuthorityDecision,
    resolved_path: Optional[str],
) -> CliAuthorityDecision:
    """If authority allows, inspect script content for blocked commands.

    Returns the original decision if inspection is disabled, the file is not
    a script, or no blocked commands are found. Returns a halt decision if
    blocked commands are detected inside the script.
    """
    if decision.decision != "allow":
        return decision

    found = _inspect_script_content(resolved_path, _state["constitution"])
    if not found:
        return decision

    return CliAuthorityDecision(
        decision="halt",
        reason=(
            f"Script '{os.path.basename(resolved_path or '')}' contains "
            f"blocked command(s): {', '.join(found)}"
        ),
        rule_id="script_content_inspection",
    )


def _determine_event_type(decision: CliAuthorityDecision) -> str:
    """Determine the event_type for a completed (non-halted) invocation."""
    mode = _state["mode"]
    if mode == "audit" and decision.decision == "halt":
        return "cli_invocation_halted"
    elif mode == "audit" and decision.decision == "escalate":
        return "cli_invocation_escalated"
    return "cli_invocation_allowed"


# =============================================================================
# PATCHED SUBPROCESS.RUN
# =============================================================================

def _patched_run(*args, **kwargs):
    """Intercepted subprocess.run with governance enforcement."""
    # Internal call chain (e.g., subprocess.run -> Popen): skip governance
    if getattr(_thread_local, 'restoring', False):
        return _originals["subprocess.run"](*args, **kwargs)

    # 1. Pop justification before forwarding
    justification = kwargs.pop("justification", None)

    # 2. Resolve command (use subprocess env's PATH if provided)
    binary_name, argv, raw_cmd, resolved_path = _resolve_command(args, kwargs, env=kwargs.get("env"))

    # 3. Build input object and compute hashes
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH

    cwd = input_obj["cwd"]

    # 4. Evaluate authority (uses basename, not resolved path)
    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])

    # 4a. Shell chaining check: when shell=True with a string command,
    # evaluate each chained sub-command (;, |, &&, ||, $(), backticks)
    if _is_shell_mode(args, kwargs) and isinstance(raw_cmd, str):
        _check_shell_chaining(raw_cmd, _state["constitution"])

    # 4b. Script content inspection (opt-in via inspect_scripts)
    decision = _maybe_inspect_script(decision, resolved_path)

    # 5. Enforce (may raise)
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    # 6. Execute with resolved absolute path (TOCTOU mitigation)
    resolved_args, resolved_kwargs = _substitute_resolved_path(args, kwargs, resolved_path)

    capture_for_hash = False
    if "stdout" not in resolved_kwargs and "stderr" not in resolved_kwargs and not resolved_kwargs.get("capture_output"):
        resolved_kwargs["capture_output"] = True
        capture_for_hash = True

    with _restore_originals():
        result = _originals["subprocess.run"](*resolved_args, **resolved_kwargs)

    # 7. Compute action_hash
    action_hash = _compute_action_hash(result)

    # 8. Determine event_type
    event_type = _determine_event_type(decision)
    ctx_limit = "cli_no_justification" if not justification else "cli_execution"

    # 9. Emit receipt
    _emit_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        binary_name=binary_name,
        argv=argv,
        cwd=cwd,
        justification=justification,
        exit_code=result.returncode,
    )

    # 10. Strip forced capture
    if capture_for_hash:
        result.stdout = None
        result.stderr = None

    return result


# =============================================================================
# PATCHED SUBPROCESS.CALL
# =============================================================================

def _patched_call(*args, **kwargs):
    """Intercepted subprocess.call with governance enforcement."""
    if getattr(_thread_local, 'restoring', False):
        return _originals["subprocess.call"](*args, **kwargs)

    justification = kwargs.pop("justification", None)
    binary_name, argv, raw_cmd, resolved_path = _resolve_command(args, kwargs, env=kwargs.get("env"))
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH
    cwd = input_obj["cwd"]

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])
    if _is_shell_mode(args, kwargs) and isinstance(raw_cmd, str):
        _check_shell_chaining(raw_cmd, _state["constitution"])
    decision = _maybe_inspect_script(decision, resolved_path)
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    resolved_args, resolved_kwargs = _substitute_resolved_path(args, kwargs, resolved_path)
    with _restore_originals():
        retcode = _originals["subprocess.call"](*resolved_args, **resolved_kwargs)

    # call() doesn't capture output
    action_obj = {"exit_code": retcode, "stderr": "", "stdout": ""}
    action_hash = hash_obj(action_obj)

    event_type = _determine_event_type(decision)
    ctx_limit = "cli_no_justification" if not justification else "cli_execution"

    _emit_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        binary_name=binary_name,
        argv=argv,
        cwd=cwd,
        justification=justification,
        exit_code=retcode,
    )

    return retcode


# =============================================================================
# PATCHED SUBPROCESS.CHECK_CALL
# =============================================================================

def _patched_check_call(*args, **kwargs):
    """Intercepted subprocess.check_call with governance enforcement."""
    if getattr(_thread_local, 'restoring', False):
        return _originals["subprocess.check_call"](*args, **kwargs)

    justification = kwargs.pop("justification", None)
    binary_name, argv, raw_cmd, resolved_path = _resolve_command(args, kwargs, env=kwargs.get("env"))
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH
    cwd = input_obj["cwd"]

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])
    if _is_shell_mode(args, kwargs) and isinstance(raw_cmd, str):
        _check_shell_chaining(raw_cmd, _state["constitution"])
    decision = _maybe_inspect_script(decision, resolved_path)
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    resolved_args, resolved_kwargs = _substitute_resolved_path(args, kwargs, resolved_path)
    with _restore_originals():
        retcode = _originals["subprocess.check_call"](*resolved_args, **resolved_kwargs)

    action_obj = {"exit_code": retcode, "stderr": "", "stdout": ""}
    action_hash = hash_obj(action_obj)

    event_type = _determine_event_type(decision)
    ctx_limit = "cli_no_justification" if not justification else "cli_execution"

    _emit_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        binary_name=binary_name,
        argv=argv,
        cwd=cwd,
        justification=justification,
        exit_code=retcode,
    )

    return retcode


# =============================================================================
# PATCHED SUBPROCESS.CHECK_OUTPUT
# =============================================================================

def _patched_check_output(*args, **kwargs):
    """Intercepted subprocess.check_output with governance enforcement."""
    if getattr(_thread_local, 'restoring', False):
        return _originals["subprocess.check_output"](*args, **kwargs)

    justification = kwargs.pop("justification", None)
    binary_name, argv, raw_cmd, resolved_path = _resolve_command(args, kwargs, env=kwargs.get("env"))
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH
    cwd = input_obj["cwd"]

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])
    if _is_shell_mode(args, kwargs) and isinstance(raw_cmd, str):
        _check_shell_chaining(raw_cmd, _state["constitution"])
    decision = _maybe_inspect_script(decision, resolved_path)
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    resolved_args, resolved_kwargs = _substitute_resolved_path(args, kwargs, resolved_path)
    with _restore_originals():
        output = _originals["subprocess.check_output"](*resolved_args, **resolved_kwargs)

    stdout_str = (
        output.decode("utf-8", errors="replace")
        if isinstance(output, bytes)
        else str(output)
    )
    action_obj = {"exit_code": 0, "stderr": "", "stdout": stdout_str}
    action_hash = hash_obj(action_obj)

    event_type = _determine_event_type(decision)
    ctx_limit = "cli_no_justification" if not justification else "cli_execution"

    _emit_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        binary_name=binary_name,
        argv=argv,
        cwd=cwd,
        justification=justification,
        exit_code=0,
    )

    return output


# =============================================================================
# PATCHED SUBPROCESS.POPEN
# =============================================================================

class _PatchedPopen:
    """Intercepted Popen that enforces governance at creation time.

    Wraps communicate() and wait() to capture output for action_hash.
    """

    _is_passthrough = False

    def __init__(self, *args, **kwargs):
        # Internal call chain: delegate to original Popen without governance
        if getattr(_thread_local, 'restoring', False):
            self._is_passthrough = True
            self._proc = _originals["subprocess.Popen"](*args, **kwargs)
            return

        self._justification = kwargs.pop("justification", None)
        self._binary_name, self._argv, self._raw_cmd, resolved_path = _resolve_command(args, kwargs, env=kwargs.get("env"))
        self._input_obj = _build_input_obj(self._binary_name, self._argv, kwargs)
        self._input_hash = hash_obj(self._input_obj)
        self._reasoning_hash = (
            hash_text(self._justification) if self._justification else EMPTY_HASH
        )
        self._cwd = self._input_obj["cwd"]
        self._receipt_emitted = False

        decision = evaluate_cli_authority(
            self._binary_name, self._argv, _state["constitution"]
        )
        self._decision = decision

        # Shell chaining check for Popen(shell=True)
        if _is_shell_mode(args, kwargs) and isinstance(self._raw_cmd, str):
            _check_shell_chaining(self._raw_cmd, _state["constitution"])

        # Script content inspection (opt-in via inspect_scripts)
        decision = _maybe_inspect_script(decision, resolved_path)
        self._decision = decision

        # Enforce (may raise FileNotFoundError or PermissionError)
        _enforce_decision(
            decision, self._binary_name, self._argv, self._cwd,
            self._input_hash, self._reasoning_hash, self._justification,
        )

        # Create real Popen with resolved path (TOCTOU mitigation)
        resolved_args, resolved_kwargs = _substitute_resolved_path(args, kwargs, resolved_path)
        self._proc = _originals["subprocess.Popen"](*resolved_args, **resolved_kwargs)

    def communicate(self, input=None, timeout=None):
        stdout, stderr = self._proc.communicate(input=input, timeout=timeout)
        if not self._is_passthrough:
            self._emit_post_execution(stdout, stderr, self._proc.returncode)
        return stdout, stderr

    def wait(self, timeout=None):
        retcode = self._proc.wait(timeout=timeout)
        if not self._is_passthrough and not self._receipt_emitted:
            self._emit_post_execution(None, None, retcode)
        return retcode

    def _emit_post_execution(self, stdout, stderr, returncode):
        """Generate receipt after process execution."""
        if self._receipt_emitted:
            return
        self._receipt_emitted = True

        stdout_str = ""
        stderr_str = ""
        if stdout is not None:
            stdout_str = (
                stdout.decode("utf-8", errors="replace")
                if isinstance(stdout, bytes)
                else str(stdout)
            )
        if stderr is not None:
            stderr_str = (
                stderr.decode("utf-8", errors="replace")
                if isinstance(stderr, bytes)
                else str(stderr)
            )

        action_obj = {
            "exit_code": returncode,
            "stderr": stderr_str,
            "stdout": stdout_str,
        }
        action_hash = hash_obj(action_obj)

        event_type = _determine_event_type(self._decision)
        ctx_limit = (
            "cli_no_justification" if not self._justification else "cli_execution"
        )

        _emit_receipt(
            event_type=event_type,
            context_limitation=ctx_limit,
            input_hash=self._input_hash,
            reasoning_hash=self._reasoning_hash,
            action_hash=action_hash,
            decision=self._decision,
            binary_name=self._binary_name,
            argv=self._argv,
            cwd=self._cwd,
            justification=self._justification,
            exit_code=returncode,
        )

    def poll(self):
        return self._proc.poll()

    def kill(self):
        return self._proc.kill()

    def terminate(self):
        return self._proc.terminate()

    def send_signal(self, signal):
        return self._proc.send_signal(signal)

    @property
    def stdin(self):
        return self._proc.stdin

    @property
    def stdout(self):
        return self._proc.stdout

    @property
    def stderr(self):
        return self._proc.stderr

    @property
    def pid(self):
        return self._proc.pid

    @property
    def returncode(self):
        return self._proc.returncode

    @returncode.setter
    def returncode(self, value):
        self._proc.returncode = value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._is_passthrough and not self._receipt_emitted and self._proc.returncode is not None:
            self._emit_post_execution(None, None, self._proc.returncode)
        self._proc.__exit__(exc_type, exc_val, exc_tb)
        return False

    def __del__(self):
        if self._is_passthrough:
            return
        if not self._receipt_emitted and hasattr(self, "_proc"):
            rc = getattr(self._proc, "returncode", None)
            if rc is not None:
                self._emit_post_execution(None, None, rc)


# =============================================================================
# PATCHED OS.SYSTEM
# =============================================================================

def _patched_os_system(command):
    """Intercepted os.system with governance enforcement."""
    if getattr(_thread_local, 'restoring', False):
        return _originals["os.system"](command)

    # os.system always invokes shell — parse with shlex and check chaining
    if isinstance(command, str):
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        binary = parts[0] if parts else ""
        argv = parts[1:]
    else:
        binary = str(command)
        argv = []

    binary_name = os.path.basename(binary)

    # Resolve binary to absolute path (TOCTOU mitigation)
    if binary and os.path.isabs(binary):
        resolved_path = os.path.realpath(binary)
    elif binary:
        resolved_path = shutil.which(binary)
    else:
        resolved_path = None

    env_keys = sorted(os.environ.keys())
    cwd = os.getcwd()

    input_obj = {
        "args": argv,
        "command": binary_name,
        "cwd": cwd,
        "env_keys": env_keys,
    }
    input_hash = hash_obj(input_obj)
    reasoning_hash = EMPTY_HASH  # os.system has no justification mechanism

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])

    # os.system always uses shell — check all chained commands
    if isinstance(command, str):
        _check_shell_chaining(command, _state["constitution"])

    # Script content inspection (opt-in via inspect_scripts)
    decision = _maybe_inspect_script(decision, resolved_path)

    if decision.decision == "halt" and _state["mode"] == "enforce":
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)
        _emit_receipt(
            event_type="cli_invocation_halted",
            context_limitation="cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary_name,
            argv=argv,
            cwd=cwd,
            justification=None,
            extensions={"capture_limitation": "os.system"},
        )
        raise FileNotFoundError(
            errno.ENOENT,
            os.strerror(errno.ENOENT),
            binary_name,
        )

    if decision.decision == "escalate" and _state["mode"] == "enforce":
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)
        _emit_receipt(
            event_type="cli_invocation_escalated",
            context_limitation="cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary_name,
            argv=argv,
            cwd=cwd,
            justification=None,
            extensions={"capture_limitation": "os.system"},
        )
        raise PermissionError(f"Escalation required: {decision.reason}")

    # Execute with resolved path (TOCTOU mitigation)
    resolved_command = command
    if resolved_path is not None and isinstance(command, str):
        try:
            cmd_parts = shlex.split(command)
        except ValueError:
            cmd_parts = command.split()
        if cmd_parts:
            stripped = command.lstrip()
            first_token = cmd_parts[0]
            if stripped.startswith(("'", '"')):
                quote = stripped[0]
                end = stripped.index(quote, 1) + 1
            else:
                end = len(first_token)
            prefix_ws = command[:len(command) - len(stripped)]
            resolved_command = prefix_ws + resolved_path + stripped[end:]

    retcode = _originals["os.system"](resolved_command)

    # os.system cannot capture stdout/stderr
    action_obj = {"exit_code": retcode, "stderr": "", "stdout": ""}
    action_hash = hash_obj(action_obj)

    event_type = _determine_event_type(decision)

    _emit_receipt(
        event_type=event_type,
        context_limitation="cli_execution",
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        binary_name=binary_name,
        argv=argv,
        cwd=cwd,
        justification=None,
        extensions={"capture_limitation": "os.system"},
    )

    return retcode


# =============================================================================
# PATCHED OS.EXEC* FAMILY
# =============================================================================

def _parse_exec_args(name: str, args):
    """Parse os.exec* arguments into (binary, argv).

    The "l" variants pass args as individual parameters.
    The "v" variants pass args as a list.
    The "e" variants have an env dict as the last arg (for "l") or third arg (for "v").
    The "p" variants use PATH lookup (no effect on parsing).

    Returns (binary, argv).
    """
    # All exec variants: first positional arg is the path/file
    path_or_file = args[0]

    if "v" in name:
        # execv(path, args), execve(path, args, env), execvp(file, args), execvpe(file, args, env)
        argv = list(args[1])
    else:
        # execl(path, arg0, ...), execle(path, arg0, ..., env),
        # execlp(file, arg0, ...), execlpe(file, arg0, ..., env)
        remaining = args[1:]
        if name.endswith("e"):
            # Last argument is the env dict
            argv = list(remaining[:-1])
        else:
            argv = list(remaining)

    binary = os.path.basename(str(path_or_file))
    return binary, argv


def _make_patched_exec(name: str):
    """Create a patched version of os.exec* function.

    os.exec* replaces the current process — receipt MUST be generated before
    calling the original. There is no return value to capture.
    """

    def patched_exec(*args, **kwargs):
        binary, argv = _parse_exec_args(name, args)

        input_obj = {
            "args": argv,
            "command": binary,
            "cwd": os.getcwd(),
            "env_keys": sorted(os.environ.keys()),
        }
        input_hash = hash_obj(input_obj)
        reasoning_hash = EMPTY_HASH  # exec has no justification mechanism

        decision = evaluate_cli_authority(binary, argv, _state["constitution"])

        # Enforce (may raise)
        if decision.decision == "halt" and _state["mode"] == "enforce":
            action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
            action_hash = hash_obj(action_obj)
            _emit_receipt(
                event_type="cli_invocation_halted",
                context_limitation="cli_execution",
                input_hash=input_hash,
                reasoning_hash=reasoning_hash,
                action_hash=action_hash,
                decision=decision,
                binary_name=binary,
                argv=argv,
                cwd=os.getcwd(),
                justification=None,
                extensions={"capture_limitation": f"os.{name}"},
            )
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                binary,
            )

        if decision.decision == "escalate" and _state["mode"] == "enforce":
            action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
            action_hash = hash_obj(action_obj)
            _emit_receipt(
                event_type="cli_invocation_escalated",
                context_limitation="cli_execution",
                input_hash=input_hash,
                reasoning_hash=reasoning_hash,
                action_hash=action_hash,
                decision=decision,
                binary_name=binary,
                argv=argv,
                cwd=os.getcwd(),
                justification=None,
                extensions={"capture_limitation": f"os.{name}"},
            )
            raise PermissionError(f"Escalation required: {decision.reason}")

        # Emit receipt BEFORE exec (process will be replaced, no return)
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)
        event_type = _determine_event_type(decision)

        _emit_receipt(
            event_type=event_type,
            context_limitation="cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary,
            argv=argv,
            cwd=os.getcwd(),
            justification=None,
            extensions={"capture_limitation": f"os.{name}", "pre_exec_receipt": True},
        )

        # Call original — this replaces the process on success and never returns
        with _restore_originals():
            return _originals[f"os.{name}"](*args, **kwargs)

    patched_exec.__name__ = f"_patched_os_{name}"
    patched_exec.__qualname__ = f"_patched_os_{name}"
    return patched_exec


# =============================================================================
# PATCHED OS.SPAWN* FAMILY
# =============================================================================

def _parse_spawn_args(name: str, args):
    """Parse os.spawn* arguments into (mode, binary, argv).

    All spawn variants: first arg is mode (P_WAIT/P_NOWAIT), second is path/file.
    The "l" variants pass args as individual parameters after path.
    The "v" variants pass args as a list.
    The "e" variants have an env dict.

    Returns (mode, binary, argv).
    """
    mode = args[0]
    path_or_file = args[1]

    if "v" in name:
        # spawnv(mode, path, args), spawnve(mode, path, args, env), etc.
        argv = list(args[2])
    else:
        # spawnl(mode, path, arg0, ...), spawnle(mode, path, arg0, ..., env), etc.
        remaining = args[2:]
        if name.endswith("e"):
            # Last argument is the env dict
            argv = list(remaining[:-1])
        else:
            argv = list(remaining)

    binary = os.path.basename(str(path_or_file))
    return mode, binary, argv


def _make_patched_spawn(name: str):
    """Create a patched version of os.spawn* function.

    os.spawn* runs a child process and returns exit status (P_WAIT) or PID (P_NOWAIT).
    """

    def patched_spawn(*args, **kwargs):
        mode, binary, argv = _parse_spawn_args(name, args)

        input_obj = {
            "args": argv,
            "command": binary,
            "cwd": os.getcwd(),
            "env_keys": sorted(os.environ.keys()),
        }
        input_hash = hash_obj(input_obj)
        reasoning_hash = EMPTY_HASH  # spawn has no justification mechanism
        cwd = os.getcwd()

        decision = evaluate_cli_authority(binary, argv, _state["constitution"])

        # Enforce (may raise)
        if decision.decision == "halt" and _state["mode"] == "enforce":
            action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
            action_hash = hash_obj(action_obj)
            _emit_receipt(
                event_type="cli_invocation_halted",
                context_limitation="cli_execution",
                input_hash=input_hash,
                reasoning_hash=reasoning_hash,
                action_hash=action_hash,
                decision=decision,
                binary_name=binary,
                argv=argv,
                cwd=cwd,
                justification=None,
                extensions={"capture_limitation": f"os.{name}"},
            )
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                binary,
            )

        if decision.decision == "escalate" and _state["mode"] == "enforce":
            action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
            action_hash = hash_obj(action_obj)
            _emit_receipt(
                event_type="cli_invocation_escalated",
                context_limitation="cli_execution",
                input_hash=input_hash,
                reasoning_hash=reasoning_hash,
                action_hash=action_hash,
                decision=decision,
                binary_name=binary,
                argv=argv,
                cwd=cwd,
                justification=None,
                extensions={"capture_limitation": f"os.{name}"},
            )
            raise PermissionError(f"Escalation required: {decision.reason}")

        # Execute
        with _restore_originals():
            result = _originals[f"os.{name}"](*args, **kwargs)

        # result is exit status (P_WAIT) or PID (P_NOWAIT)
        # For P_WAIT, treat as exit_code; for P_NOWAIT, it's a PID (not an exit code)
        exit_code = result if mode == getattr(os, "P_WAIT", 0) else None
        action_obj = {"exit_code": exit_code, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)

        event_type = _determine_event_type(decision)

        _emit_receipt(
            event_type=event_type,
            context_limitation="cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary,
            argv=argv,
            cwd=cwd,
            justification=None,
            extensions={"capture_limitation": f"os.{name}"},
        )

        return result

    patched_spawn.__name__ = f"_patched_os_{name}"
    patched_spawn.__qualname__ = f"_patched_os_{name}"
    return patched_spawn


# =============================================================================
# PATCHED OS.POPEN
# =============================================================================

def _patched_os_popen(cmd, mode="r", buffering=-1):
    """Intercepted os.popen with governance enforcement.

    os.popen runs a shell command and returns a file object.
    Similar to os.system: cmd is always a string, always uses shell.
    """
    if isinstance(cmd, str):
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
        binary = parts[0] if parts else ""
        argv = parts[1:]
    else:
        binary = str(cmd)
        argv = []

    binary_name = os.path.basename(binary)

    input_obj = {
        "args": argv,
        "command": binary_name,
        "cwd": os.getcwd(),
        "env_keys": sorted(os.environ.keys()),
    }
    input_hash = hash_obj(input_obj)
    reasoning_hash = EMPTY_HASH  # os.popen has no justification mechanism
    cwd = os.getcwd()

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])

    if decision.decision == "halt" and _state["mode"] == "enforce":
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)
        _emit_receipt(
            event_type="cli_invocation_halted",
            context_limitation="cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary_name,
            argv=argv,
            cwd=cwd,
            justification=None,
            extensions={"capture_limitation": "os.popen"},
        )
        raise FileNotFoundError(
            errno.ENOENT,
            os.strerror(errno.ENOENT),
            binary_name,
        )

    if decision.decision == "escalate" and _state["mode"] == "enforce":
        action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
        action_hash = hash_obj(action_obj)
        _emit_receipt(
            event_type="cli_invocation_escalated",
            context_limitation="cli_execution",
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            binary_name=binary_name,
            argv=argv,
            cwd=cwd,
            justification=None,
            extensions={"capture_limitation": "os.popen"},
        )
        raise PermissionError(f"Escalation required: {decision.reason}")

    # os.popen always uses shell — check chained commands after primary enforcement
    if isinstance(cmd, str):
        _check_shell_chaining(cmd, _state["constitution"])

    # Execute
    with _restore_originals():
        result = _originals["os.popen"](cmd, mode, buffering)

    # os.popen returns a file object — we can't capture output without consuming it
    action_obj = {"exit_code": None, "stderr": "", "stdout": ""}
    action_hash = hash_obj(action_obj)

    event_type = _determine_event_type(decision)

    _emit_receipt(
        event_type=event_type,
        context_limitation="cli_execution",
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        binary_name=binary_name,
        argv=argv,
        cwd=cwd,
        justification=None,
        extensions={"capture_limitation": "os.popen"},
    )

    return result
