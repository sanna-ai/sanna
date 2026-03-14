"""Subprocess interceptor — patches Python's subprocess module at runtime.

Enforces governance on CLI subprocess invocations by intercepting calls to
subprocess.run, subprocess.Popen, subprocess.call, subprocess.check_call,
subprocess.check_output, and os.system.

Each intercepted call:
1. Extracts binary name and argv
2. Evaluates against constitution cli_permissions
3. Computes receipt triad (input_hash, reasoning_hash, action_hash)
4. Generates and persists a governance receipt
5. Either allows, halts (FileNotFoundError), or escalates (PermissionError)
"""

from __future__ import annotations

import errno
import logging
import os
import subprocess
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


class _restore_originals:
    """Context manager that temporarily restores all original subprocess functions.

    The original subprocess functions internally reference each other by name
    from the subprocess module. When we've patched them, calling an original
    would still use our patched versions for internal calls, causing double
    interception. This context manager swaps everything back for the duration.
    """

    def __enter__(self):
        for key, orig in _originals.items():
            mod_name, attr_name = key.rsplit(".", 1)
            mod = subprocess if mod_name == "subprocess" else os
            setattr(mod, attr_name, orig)
        return self

    def __exit__(self, *args):
        if _patched:
            subprocess.run = _patched_run
            subprocess.call = _patched_call
            subprocess.check_call = _patched_check_call
            subprocess.check_output = _patched_check_output
            subprocess.Popen = _PatchedPopen
            os.system = _patched_os_system
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

    _patched = True


def unpatch_subprocess() -> None:
    """Restore all original subprocess and os.system functions."""
    global _patched

    if not _patched:
        return

    subprocess.run = _originals["subprocess.run"]
    subprocess.Popen = _originals["subprocess.Popen"]
    subprocess.call = _originals["subprocess.call"]
    subprocess.check_call = _originals["subprocess.check_call"]
    subprocess.check_output = _originals["subprocess.check_output"]
    os.system = _originals["os.system"]

    _originals.clear()
    _state.clear()
    _patched = False


# =============================================================================
# COMMAND PARSING
# =============================================================================

def _resolve_command(args, kwargs):
    """Extract binary name and argv from subprocess arguments.

    Returns (binary_name, argv, raw_cmd).
    """
    cmd = args[0] if args else kwargs.get("args", [])
    if isinstance(cmd, str):
        parts = cmd.split()
        binary = parts[0] if parts else ""
        argv = parts[1:]
    else:
        cmd = list(cmd)
        binary = cmd[0] if cmd else ""
        argv = cmd[1:]

    binary_name = os.path.basename(binary)
    return binary_name, argv, cmd


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
    # 1. Pop justification before forwarding
    justification = kwargs.pop("justification", None)

    # 2. Resolve command
    binary_name, argv, raw_cmd = _resolve_command(args, kwargs)

    # 3. Build input object and compute hashes
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH

    cwd = input_obj["cwd"]

    # 4. Evaluate authority
    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])

    # 5. Enforce (may raise)
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    # 6. Execute
    capture_for_hash = False
    if "stdout" not in kwargs and "stderr" not in kwargs and not kwargs.get("capture_output"):
        kwargs["capture_output"] = True
        capture_for_hash = True

    with _restore_originals():
        result = _originals["subprocess.run"](*args, **kwargs)

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
    justification = kwargs.pop("justification", None)
    binary_name, argv, raw_cmd = _resolve_command(args, kwargs)
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH
    cwd = input_obj["cwd"]

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    with _restore_originals():
        retcode = _originals["subprocess.call"](*args, **kwargs)

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
    justification = kwargs.pop("justification", None)
    binary_name, argv, raw_cmd = _resolve_command(args, kwargs)
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH
    cwd = input_obj["cwd"]

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    with _restore_originals():
        retcode = _originals["subprocess.check_call"](*args, **kwargs)

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
    justification = kwargs.pop("justification", None)
    binary_name, argv, raw_cmd = _resolve_command(args, kwargs)
    input_obj = _build_input_obj(binary_name, argv, kwargs)
    input_hash = hash_obj(input_obj)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH
    cwd = input_obj["cwd"]

    decision = evaluate_cli_authority(binary_name, argv, _state["constitution"])
    _enforce_decision(decision, binary_name, argv, cwd, input_hash, reasoning_hash, justification)

    with _restore_originals():
        output = _originals["subprocess.check_output"](*args, **kwargs)

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

    def __init__(self, *args, **kwargs):
        self._justification = kwargs.pop("justification", None)
        self._binary_name, self._argv, self._raw_cmd = _resolve_command(args, kwargs)
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

        # Enforce (may raise FileNotFoundError or PermissionError)
        _enforce_decision(
            decision, self._binary_name, self._argv, self._cwd,
            self._input_hash, self._reasoning_hash, self._justification,
        )

        # Create real Popen (must use original to avoid recursion)
        self._proc = _originals["subprocess.Popen"](*args, **kwargs)

    def communicate(self, input=None, timeout=None):
        stdout, stderr = self._proc.communicate(input=input, timeout=timeout)
        self._emit_post_execution(stdout, stderr, self._proc.returncode)
        return stdout, stderr

    def wait(self, timeout=None):
        retcode = self._proc.wait(timeout=timeout)
        if not self._receipt_emitted:
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
        if not self._receipt_emitted and self._proc.returncode is not None:
            self._emit_post_execution(None, None, self._proc.returncode)
        self._proc.__exit__(exc_type, exc_val, exc_tb)
        return False

    def __del__(self):
        if not self._receipt_emitted and hasattr(self, "_proc"):
            rc = getattr(self._proc, "returncode", None)
            if rc is not None:
                self._emit_post_execution(None, None, rc)


# =============================================================================
# PATCHED OS.SYSTEM
# =============================================================================

def _patched_os_system(command):
    """Intercepted os.system with governance enforcement."""
    # os.system takes a string command
    if isinstance(command, str):
        parts = command.split()
        binary = parts[0] if parts else ""
        argv = parts[1:]
    else:
        binary = str(command)
        argv = []

    binary_name = os.path.basename(binary)

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

    # Execute
    retcode = _originals["os.system"](command)

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
