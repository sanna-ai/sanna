"""Tests for sanna.interceptors.subprocess_interceptor — CLI governance."""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import jsonschema

import pytest

from sanna.constitution import (
    load_constitution,
    CliCommand,
    CliInvariant,
    CliPermissions,
)
from sanna.hashing import hash_obj, hash_text, EMPTY_HASH
from sanna.interceptors import patch_subprocess, unpatch_subprocess
from sanna.interceptors.cli_authority import (
    evaluate_cli_authority,
    CliAuthorityDecision,
)
from sanna.sinks.sink import ReceiptSink, SinkResult


# =============================================================================
# HELPERS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
CLI_TEST_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-test.yaml")
CLI_PERMISSIVE_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-permissive.yaml")

RECEIPT_SCHEMA = json.loads(
    (Path(__file__).parent.parent / "src" / "sanna" / "spec" / "receipt.schema.json").read_text()
)

# A constitution with no cli_permissions block
NO_CLI_CONSTITUTION = str(CONSTITUTIONS_DIR / "with_authority.yaml")


class CaptureSink(ReceiptSink):
    """Sink that captures receipts for inspection."""

    def __init__(self):
        self.receipts: list[dict] = []

    def store(self, receipt: dict) -> SinkResult:
        self.receipts.append(receipt)
        return SinkResult(stored=1)

    @property
    def last(self) -> dict:
        return self.receipts[-1]

    @property
    def count(self) -> int:
        return len(self.receipts)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
def cleanup():
    """Ensure subprocess is unpatched after every test."""
    yield
    unpatch_subprocess()


@pytest.fixture
def sink():
    return CaptureSink()


@pytest.fixture
def patched(sink):
    """Patch subprocess with cli-test constitution in enforce mode."""
    patch_subprocess(
        constitution_path=CLI_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    # SAN-206: patch_subprocess now emits a session_manifest receipt; clear it
    # so per-test assertions remain relative to invocation receipts only.
    sink.receipts.clear()
    return sink


@pytest.fixture
def patched_audit(sink):
    """Patch subprocess with cli-test constitution in audit mode."""
    patch_subprocess(
        constitution_path=CLI_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="audit",
    )
    sink.receipts.clear()  # SAN-206: clear session_manifest receipt from setup
    return sink


@pytest.fixture
def patched_passthrough(sink):
    """Patch subprocess with cli-test constitution in passthrough mode."""
    patch_subprocess(
        constitution_path=CLI_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="passthrough",
    )
    sink.receipts.clear()  # SAN-206: clear session_manifest receipt from setup
    return sink


@pytest.fixture
def patched_permissive(sink):
    """Patch subprocess with permissive constitution."""
    patch_subprocess(
        constitution_path=CLI_PERMISSIVE_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    sink.receipts.clear()  # SAN-206: clear session_manifest receipt from setup
    return sink


# =============================================================================
# 1. INTERCEPTION COVERAGE
# =============================================================================

class TestInterceptionCoverage:
    """Verify all 6 subprocess interfaces are intercepted."""

    def test_subprocess_run_intercepted(self, patched):
        result = subprocess.run(["echo", "hello"])
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_allowed"

    def test_subprocess_call_intercepted(self, patched):
        retcode = subprocess.call(["echo", "hello"])
        assert retcode == 0
        assert patched.count == 1

    def test_subprocess_check_call_intercepted(self, patched):
        retcode = subprocess.check_call(["echo", "hello"])
        assert retcode == 0
        assert patched.count == 1

    def test_subprocess_check_output_intercepted(self, patched):
        output = subprocess.check_output(["echo", "hello"])
        assert b"hello" in output
        assert patched.count == 1

    def test_subprocess_popen_intercepted(self, patched):
        proc = subprocess.Popen(["echo", "hello"], stdout=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        assert b"hello" in stdout
        assert patched.count == 1

    def test_os_system_intercepted(self, patched):
        retcode = os.system("echo hello")
        assert retcode == 0
        assert patched.count == 1


# =============================================================================
# 2. JUSTIFICATION HANDLING
# =============================================================================

class TestJustificationHandling:
    """Verify justification kwarg is stripped and recorded."""

    def test_justification_kwarg_stripped(self, patched):
        # If justification reaches real subprocess.run, it would raise TypeError
        result = subprocess.run(
            ["echo", "hello"],
            justification="test reason",
        )
        # No error means justification was properly stripped
        assert patched.count == 1

    def test_justification_in_receipt(self, patched):
        subprocess.run(["echo", "hello"], justification="test reason")
        receipt = patched.last
        expected_hash = hash_text("test reason")
        assert receipt["reasoning_hash"] == expected_hash

    def test_no_justification_empty_hash(self, patched):
        subprocess.run(["echo", "hello"])
        receipt = patched.last
        assert receipt["reasoning_hash"] == EMPTY_HASH

    def test_no_justification_context_limitation(self, patched):
        subprocess.run(["echo", "hello"])
        receipt = patched.last
        assert receipt["context_limitation"] == "cli_no_justification"


# =============================================================================
# 3. AUTHORITY ENFORCEMENT
# =============================================================================

class TestAuthorityEnforcement:
    """Verify authority decisions are enforced correctly."""

    def test_can_execute_allowed(self, patched):
        result = subprocess.run(["echo", "hello"])
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_allowed"

    def test_cannot_execute_halted(self, patched):
        with pytest.raises(FileNotFoundError) as exc_info:
            subprocess.run(["rm", "-rf", "/"])
        assert exc_info.value.errno == errno.ENOENT

    def test_must_escalate_blocked(self, patched):
        with pytest.raises(PermissionError, match="Escalation required"):
            subprocess.run(["docker", "run", "nginx"])

    def test_strict_mode_unlisted_denied(self, patched):
        with pytest.raises(FileNotFoundError) as exc_info:
            subprocess.run(["curl", "http://example.com"])
        assert exc_info.value.errno == errno.ENOENT

    def test_permissive_mode_unlisted_allowed(self, patched_permissive):
        result = subprocess.run(["echo", "hello"])
        assert patched_permissive.count == 1
        assert patched_permissive.last["event_type"] == "cli_invocation_allowed"

    def test_argv_pattern_matching(self, patched):
        # git push (matches argv_pattern "push*") should be allowed
        # We can't actually run git push, but we can verify the authority decision
        # by checking that it doesn't raise
        result = subprocess.run(["git", "push", "origin", "main"], capture_output=True)
        assert patched.count == 1

        # git push --force should be blocked (cli-006 matches first)
        with pytest.raises(FileNotFoundError):
            subprocess.run(["git", "push", "--force", "origin", "main"])


# =============================================================================
# 4. RECEIPT TRIAD
# =============================================================================

class TestReceiptTriad:
    """Verify input_hash, reasoning_hash, action_hash computation."""

    def test_input_hash_determinism(self, sink):
        """Same command produces same input_hash across runs."""
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        subprocess.run(["echo", "hello"])
        hash1 = sink.last["input_hash"]

        subprocess.run(["echo", "hello"])
        hash2 = sink.last["input_hash"]

        # Same command from same cwd with same env should produce same hash
        assert hash1 == hash2

    def test_input_hash_canonical_order(self, patched):
        """Verify input object has keys in alphabetical order."""
        subprocess.run(["echo", "hello"])
        receipt = patched.last

        # Reconstruct expected input_hash
        cwd = os.getcwd()
        env_keys = sorted(os.environ.keys())
        input_obj = {
            "args": ["hello"],
            "command": "echo",
            "cwd": cwd,
            "env_keys": env_keys,
        }
        expected = hash_obj(input_obj)
        assert receipt["input_hash"] == expected

    def test_action_hash_from_output(self, patched):
        """Verify action_hash is computed from actual stdout/stderr/exit_code."""
        subprocess.run(["echo", "hello"], capture_output=True)
        receipt = patched.last

        # action_hash should NOT be EMPTY_HASH for a successful command
        null_action = {"exit_code": None, "stderr": "", "stdout": ""}
        null_hash = hash_obj(null_action)
        assert receipt["action_hash"] != null_hash

    def test_action_hash_halted(self, patched):
        """Halted invocations produce action_hash of null exit_code."""
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "something"])

        receipt = patched.last
        expected = hash_obj({"exit_code": None, "stderr": "", "stdout": ""})
        assert receipt["action_hash"] == expected

    def test_action_hash_differs_from_input_hash(self, patched):
        """For allowed invocations, action_hash != input_hash."""
        subprocess.run(["echo", "hello"], capture_output=True)
        receipt = patched.last
        assert receipt["action_hash"] != receipt["input_hash"]


# =============================================================================
# 5. RECEIPT FIELDS
# =============================================================================

class TestReceiptFields:
    """Verify receipt metadata fields are set correctly."""

    def test_event_type_allowed(self, patched):
        subprocess.run(["echo", "hello"])
        assert patched.last["event_type"] == "cli_invocation_allowed"

    def test_event_type_halted(self, patched):
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "something"])
        assert patched.last["event_type"] == "cli_invocation_halted"

    def test_context_limitation_set(self, patched):
        subprocess.run(["echo", "hello"], justification="reason")
        assert patched.last["context_limitation"] == "cli_execution"

    def test_receipt_persisted_to_sink(self, patched):
        subprocess.run(["echo", "hello"])
        assert patched.count == 1

        subprocess.run(["echo", "world"])
        assert patched.count == 2


# =============================================================================
# 6. AUDIT MODE
# =============================================================================

class TestAuditMode:
    """Verify audit mode executes but records violations."""

    def test_audit_mode_executes_despite_halt(self, patched_audit):
        # rm is cannot_execute, but audit mode should still run
        result = subprocess.run(["rm", "--version"], capture_output=True)
        assert patched_audit.count == 1

    def test_audit_mode_receipt_shows_would_have_halted(self, patched_audit):
        subprocess.run(["rm", "--version"], capture_output=True)
        receipt = patched_audit.last
        assert receipt["event_type"] == "cli_invocation_halted"

    def test_passthrough_mode_no_enforcement(self, patched_passthrough):
        # Even blocked commands should run in passthrough mode
        result = subprocess.run(["echo", "hello"])
        assert patched_passthrough.count == 1
        assert patched_passthrough.last["event_type"] == "cli_invocation_allowed"


# =============================================================================
# 7. ANTI-ENUMERATION
# =============================================================================

class TestAntiEnumeration:
    """Verify blocked invocations look like missing binaries."""

    def test_halted_returns_enoent(self, patched):
        with pytest.raises(FileNotFoundError) as exc_info:
            subprocess.run(["rm", "something"])
        assert exc_info.value.errno == errno.ENOENT
        # Should look like a missing binary, not a governance error
        assert "rm" in str(exc_info.value)

    def test_halted_receipt_not_visible_to_caller(self, patched):
        """Caller gets FileNotFoundError; receipt is in the sink."""
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "something"])

        # Receipt was stored despite the exception to the caller
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_halted"


# =============================================================================
# 8. EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Verify edge case behaviors."""

    def test_patch_idempotent(self, sink):
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        # Second call should be a no-op
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        # SAN-206: clear session_manifest receipt from first patch; second patch is no-op
        sink.receipts.clear()
        # Should still work correctly
        subprocess.run(["echo", "hello"])
        assert sink.count == 1

    def test_unpatch_restores_originals(self, sink):
        original_run = subprocess.run
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        assert subprocess.run is not original_run

        unpatch_subprocess()
        assert subprocess.run is original_run

    def test_no_cli_permissions_allows_all(self, sink):
        """Constitution with no cli_permissions block allows everything."""
        patch_subprocess(
            constitution_path=NO_CLI_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        sink.receipts.clear()  # SAN-206: clear session_manifest receipt from setup
        result = subprocess.run(["echo", "hello"])
        assert sink.count == 1
        assert sink.last["event_type"] == "cli_invocation_allowed"


# =============================================================================
# 9. CONSTITUTION PARSING
# =============================================================================

class TestConstitutionParsing:
    """Verify cli_permissions parsing in constitution loader."""

    def test_parse_cli_permissions(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        assert c.cli_permissions is not None
        assert c.cli_permissions.mode == "strict"
        assert c.cli_permissions.justification_required is True
        assert len(c.cli_permissions.commands) == 6

        echo_cmd = c.cli_permissions.commands[0]
        assert echo_cmd.id == "cli-001"
        assert echo_cmd.binary == "echo"
        assert echo_cmd.authority == "can_execute"

    def test_parse_cli_permissions_with_invariants(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        assert len(c.cli_permissions.invariants) == 1

        inv = c.cli_permissions.invariants[0]
        assert inv.id == "cli-inv-001"
        assert inv.verdict == "halt"
        assert inv.pattern == "rm\\s+-rf"

    def test_parse_constitution_without_cli_permissions(self):
        c = load_constitution(NO_CLI_CONSTITUTION)
        assert c.cli_permissions is None


# =============================================================================
# 10. CROSS-SURFACE
# =============================================================================

class TestCrossSurface:
    """Verify CLI and MCP use different authority evaluators."""

    def test_single_constitution_governs_mcp_and_cli(self):
        """Same constitution, different evaluators for MCP vs CLI."""
        c = load_constitution(CLI_TEST_CONSTITUTION)

        # CLI authority evaluation
        cli_decision = evaluate_cli_authority("echo", ["hello"], c)
        assert cli_decision.decision == "allow"

        # MCP authority evaluation uses the separate evaluate_authority()
        from sanna.enforcement.authority import evaluate_authority
        mcp_decision = evaluate_authority("echo", {}, c)
        # MCP evaluate_authority matches against authority_boundaries
        # which has "echo" in can_execute
        assert mcp_decision.decision == "allow"

    def test_receipt_has_14_field_fingerprint(self, patched):
        """CLI receipts should have valid fingerprints."""
        subprocess.run(["echo", "hello"])
        receipt = patched.last

        # Receipt should have spec_version and full_fingerprint from generate_receipt
        assert "spec_version" in receipt
        assert "full_fingerprint" in receipt
        assert "receipt_fingerprint" in receipt
        assert len(receipt["full_fingerprint"]) == 64
        assert len(receipt["receipt_fingerprint"]) == 16


# =============================================================================
# CLI AUTHORITY UNIT TESTS
# =============================================================================

class TestCliAuthorityUnit:
    """Unit tests for evaluate_cli_authority."""

    def test_no_cli_permissions_allows(self):
        """Constitution without cli_permissions allows everything."""
        c = load_constitution(NO_CLI_CONSTITUTION)
        decision = evaluate_cli_authority("anything", [], c)
        assert decision.decision == "allow"
        assert "No cli_permissions" in decision.reason

    def test_binary_exact_match(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        # "echo" matches exactly
        d = evaluate_cli_authority("echo", ["hello"], c)
        assert d.decision == "allow"
        assert d.rule_id == "cli-001"

    def test_binary_case_sensitive(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        # "Echo" should NOT match "echo" (case-sensitive)
        d = evaluate_cli_authority("Echo", ["hello"], c)
        assert d.decision == "halt"  # strict mode: unlisted

    def test_argv_glob_matching(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        # git push should match cli-006 first (push --force*) but "push origin"
        # doesn't match "push --force*", so falls to cli-005 (push*)
        d = evaluate_cli_authority("git", ["push", "origin", "main"], c)
        assert d.decision == "allow"
        assert d.rule_id == "cli-005"

    def test_argv_glob_force_push_blocked(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        # git push --force should match cli-006 (cannot_execute, push --force*)
        d = evaluate_cli_authority("git", ["push", "--force", "origin", "main"], c)
        assert d.decision == "halt"
        assert d.rule_id == "cli-006"

    def test_strict_mode_unlisted(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        d = evaluate_cli_authority("wget", ["http://example.com"], c)
        assert d.decision == "halt"
        assert "strict mode" in d.reason

    def test_permissive_mode_unlisted(self):
        c = load_constitution(CLI_PERMISSIVE_CONSTITUTION)
        d = evaluate_cli_authority("wget", ["http://example.com"], c)
        assert d.decision == "allow"
        assert "permissive" in d.reason

    def test_escalation_target(self):
        c = load_constitution(CLI_TEST_CONSTITUTION)
        d = evaluate_cli_authority("docker", ["run", "nginx"], c)
        assert d.decision == "escalate"
        assert d.rule_id == "cli-004"


# =============================================================================
# 11. OS.EXEC* INTERCEPTION
# =============================================================================

class TestOsExecInterception:
    """Verify os.exec* family is intercepted."""

    def test_execv_blocked_in_enforce_mode(self, patched):
        """os.execv with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            os.execv("/usr/bin/rm", ["rm", "-rf", "/"])
        assert exc_info.value.errno == errno.ENOENT
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_halted"

    def test_execve_blocked(self, patched):
        """os.execve with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            os.execve("/usr/bin/rm", ["rm", "something"], os.environ.copy())
        assert exc_info.value.errno == errno.ENOENT

    def test_execl_blocked(self, patched):
        """os.execl with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            os.execl("/usr/bin/rm", "rm", "something")
        assert exc_info.value.errno == errno.ENOENT

    def test_exec_escalation(self, patched):
        """os.execv with must_escalate command raises PermissionError."""
        with pytest.raises(PermissionError, match="Escalation required"):
            os.execv("/usr/bin/docker", ["docker", "run", "nginx"])
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_escalated"

    def test_exec_allowed_generates_receipt(self, patched):
        """os.execvp with allowed command generates pre-exec receipt then calls original.

        Since exec replaces the process, we mock the original to prevent that.
        """
        from unittest.mock import patch as mock_patch
        from sanna.interceptors.subprocess_interceptor import _originals

        # Mock the original so we don't actually replace the process
        if "os.execvp" in _originals:
            orig = _originals["os.execvp"]
            _originals["os.execvp"] = MagicMock(return_value=None)
            try:
                os.execvp("echo", ["echo", "hello"])
            finally:
                _originals["os.execvp"] = orig
        elif hasattr(os, "execvp"):
            # execvp might not be patched if not available
            pytest.skip("os.execvp not patched")
        else:
            pytest.skip("os.execvp not available")

        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_allowed"
        ext = patched.last["extensions"]["com.sanna.interceptor"]
        assert ext["pre_exec_receipt"] is True

    def test_exec_audit_mode_generates_receipt(self, patched_audit):
        """os.execv in audit mode generates receipt but doesn't raise for blocked commands."""
        from sanna.interceptors.subprocess_interceptor import _originals

        # Mock the original to prevent process replacement
        if "os.execv" in _originals:
            orig = _originals["os.execv"]
            _originals["os.execv"] = MagicMock(return_value=None)
            try:
                os.execv("/usr/bin/rm", ["rm", "something"])
            finally:
                _originals["os.execv"] = orig
        else:
            pytest.skip("os.execv not patched")

        assert patched_audit.count == 1
        assert patched_audit.last["event_type"] == "cli_invocation_halted"

    @pytest.mark.skipif(not hasattr(os, "execlp"), reason="os.execlp not available")
    def test_execlp_blocked(self, patched):
        """os.execlp with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            os.execlp("rm", "rm", "something")

    @pytest.mark.skipif(not hasattr(os, "execle"), reason="os.execle not available")
    def test_execle_blocked(self, patched):
        """os.execle with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            os.execle("/usr/bin/rm", "rm", "something", os.environ.copy())


# =============================================================================
# 12. OS.SPAWN* INTERCEPTION
# =============================================================================

class TestOsSpawnInterception:
    """Verify os.spawn* family is intercepted."""

    @pytest.mark.skipif(not hasattr(os, "spawnv"), reason="os.spawnv not available")
    def test_spawnv_blocked(self, patched):
        """os.spawnv with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            os.spawnv(os.P_WAIT, "/usr/bin/rm", ["rm", "something"])
        assert exc_info.value.errno == errno.ENOENT
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_halted"

    @pytest.mark.skipif(not hasattr(os, "spawnv"), reason="os.spawnv not available")
    def test_spawnv_allowed_generates_receipt(self, patched):
        """os.spawnv with allowed command generates receipt."""
        result = os.spawnv(os.P_WAIT, "/bin/echo", ["echo", "hello"])
        assert result == 0
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_allowed"

    @pytest.mark.skipif(not hasattr(os, "spawnve"), reason="os.spawnve not available")
    def test_spawnve_blocked(self, patched):
        """os.spawnve with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            os.spawnve(os.P_WAIT, "/usr/bin/rm", ["rm", "something"], os.environ.copy())

    @pytest.mark.skipif(not hasattr(os, "spawnl"), reason="os.spawnl not available")
    def test_spawnl_blocked(self, patched):
        """os.spawnl with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            os.spawnl(os.P_WAIT, "/usr/bin/rm", "rm", "something")

    @pytest.mark.skipif(not hasattr(os, "spawnv"), reason="os.spawnv not available")
    def test_spawn_escalation(self, patched):
        """os.spawnv with must_escalate command raises PermissionError."""
        with pytest.raises(PermissionError, match="Escalation required"):
            os.spawnv(os.P_WAIT, "/usr/bin/docker", ["docker", "run", "nginx"])
        assert patched.count == 1

    @pytest.mark.skipif(not hasattr(os, "spawnlp"), reason="os.spawnlp not available")
    def test_spawnlp_platform_conditional(self, patched):
        """os.spawnlp (Unix-only) is patched when available."""
        with pytest.raises(FileNotFoundError):
            os.spawnlp(os.P_WAIT, "rm", "rm", "something")


# =============================================================================
# 13. OS.POPEN INTERCEPTION
# =============================================================================

class TestOsPopenInterception:
    """Verify os.popen is intercepted."""

    def test_popen_blocked(self, patched):
        """os.popen with blocked command raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            os.popen("rm something")
        assert exc_info.value.errno == errno.ENOENT
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_halted"

    def test_popen_allowed(self, patched):
        """os.popen with allowed command generates receipt."""
        f = os.popen("echo hello")
        output = f.read()
        f.close()
        assert "hello" in output
        assert patched.count == 1
        assert patched.last["event_type"] == "cli_invocation_allowed"

    def test_popen_escalation(self, patched):
        """os.popen with must_escalate command raises PermissionError."""
        with pytest.raises(PermissionError, match="Escalation required"):
            os.popen("docker run nginx")

    def test_popen_shell_chaining_blocked(self, patched):
        """os.popen detects shell chaining with blocked commands."""
        with pytest.raises(FileNotFoundError):
            os.popen("echo hello; rm something")


# =============================================================================
# 14. UNPATCH RESTORES ALL NEW FUNCTIONS
# =============================================================================

class TestUnpatchRestoresNewFunctions:
    """Verify unpatch_subprocess restores os.exec*, os.spawn*, os.popen."""

    def test_unpatch_restores_exec(self, sink):
        original_execv = os.execv
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        assert os.execv is not original_execv
        unpatch_subprocess()
        assert os.execv is original_execv

    @pytest.mark.skipif(not hasattr(os, "spawnv"), reason="os.spawnv not available")
    def test_unpatch_restores_spawn(self, sink):
        original_spawnv = os.spawnv
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        assert os.spawnv is not original_spawnv
        unpatch_subprocess()
        assert os.spawnv is original_spawnv

    def test_unpatch_restores_popen(self, sink):
        original_popen = os.popen
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        assert os.popen is not original_popen
        unpatch_subprocess()
        assert os.popen is original_popen

    @pytest.mark.skipif(not hasattr(os, "spawnlp"), reason="os.spawnlp not available (Windows)")
    def test_platform_specific_functions_handled(self, sink):
        """Functions that don't exist on the platform are skipped gracefully."""
        patch_subprocess(
            constitution_path=CLI_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        # If we get here without error, platform-aware patching worked
        unpatch_subprocess()


# =============================================================================
# TOCTOU MITIGATION — BINARY PATH RESOLUTION [SAN-44]
# =============================================================================

class TestTOCTOUMitigation:
    """Verify binary path resolution mitigates PATH-based TOCTOU attacks."""

    def test_resolve_command_returns_absolute_path(self):
        """_resolve_command resolves binaries to absolute paths via shutil.which."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        binary_name, argv, raw_cmd, resolved_path = _resolve_command(
            (["echo", "hello"],), {}
        )
        assert binary_name == "echo"
        assert argv == ["hello"]
        # echo exists on all POSIX systems — should resolve to absolute path
        assert resolved_path is not None
        assert os.path.isabs(resolved_path)
        assert os.path.basename(resolved_path) == "echo"

    def test_resolve_command_nonexistent_binary(self):
        """Non-existent binary returns None for resolved_path."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        binary_name, argv, raw_cmd, resolved_path = _resolve_command(
            (["nonexistent_binary_xyz_12345", "arg1"],), {}
        )
        assert binary_name == "nonexistent_binary_xyz_12345"
        assert resolved_path is None

    def test_authority_uses_basename_not_full_path(self, patched):
        """Authority evaluation uses the basename, not the resolved full path."""
        # "echo" should be allowed by its basename, not by /usr/bin/echo
        result = subprocess.run(["echo", "hello"])
        assert patched.count == 1
        receipt = patched.last
        # The binary in the receipt extension should be the basename
        ext = receipt.get("extensions", {}).get("com.sanna.interceptor", {})
        assert ext.get("binary") == "echo"

    def test_subprocess_run_passes_resolved_path(self, patched):
        """The actual subprocess call receives the resolved absolute path."""
        import shutil
        from unittest.mock import patch as mock_patch

        resolved = shutil.which("echo")
        if resolved is None:
            pytest.skip("echo not found on PATH")

        calls = []
        original_run = subprocess.run.__wrapped__ if hasattr(subprocess.run, '__wrapped__') else None

        # We need to intercept what the original subprocess.run receives.
        # Temporarily capture the args passed to the real subprocess.run
        # by wrapping the original stored in _originals.
        from sanna.interceptors.subprocess_interceptor import _originals
        real_run = _originals["subprocess.run"]

        def spy_run(*args, **kwargs):
            calls.append((args, kwargs))
            return real_run(*args, **kwargs)

        _originals["subprocess.run"] = spy_run
        try:
            subprocess.run(["echo", "hello"])
        finally:
            _originals["subprocess.run"] = real_run

        assert len(calls) == 1
        spy_args, spy_kwargs = calls[0]
        # The first positional arg should be a list with the resolved path
        cmd = spy_args[0] if spy_args else spy_kwargs.get("args", [])
        if isinstance(cmd, (list, tuple)):
            assert os.path.isabs(cmd[0]), f"Expected absolute path, got {cmd[0]}"
            assert cmd[0] == resolved, f"Expected {resolved}, got {cmd[0]}"

    def test_popen_passes_resolved_path(self, patched):
        """Popen receives the resolved absolute path."""
        import shutil
        from sanna.interceptors.subprocess_interceptor import _originals

        resolved = shutil.which("echo")
        if resolved is None:
            pytest.skip("echo not found on PATH")

        calls = []
        real_popen = _originals["subprocess.Popen"]

        class SpyPopen(real_popen.__class__ if isinstance(real_popen, type) else type(real_popen)):
            pass

        def spy_popen(*args, **kwargs):
            calls.append((args, kwargs))
            return real_popen(*args, **kwargs)

        _originals["subprocess.Popen"] = spy_popen
        try:
            proc = subprocess.Popen(["echo", "hello"], stdout=subprocess.PIPE)
            proc.communicate()
        finally:
            _originals["subprocess.Popen"] = real_popen

        assert len(calls) == 1
        spy_args, spy_kwargs = calls[0]
        cmd = spy_args[0] if spy_args else spy_kwargs.get("args", [])
        if isinstance(cmd, (list, tuple)):
            assert os.path.isabs(cmd[0])

    def test_os_system_passes_resolved_path(self, patched):
        """os.system receives command with the resolved absolute path."""
        import shutil
        from sanna.interceptors.subprocess_interceptor import _originals

        resolved = shutil.which("echo")
        if resolved is None:
            pytest.skip("echo not found on PATH")

        calls = []
        real_system = _originals["os.system"]

        def spy_system(cmd):
            calls.append(cmd)
            return real_system(cmd)

        _originals["os.system"] = spy_system
        try:
            os.system("echo hello")
        finally:
            _originals["os.system"] = real_system

        assert len(calls) == 1
        # The command string should start with the resolved absolute path
        assert calls[0].startswith(resolved), (
            f"Expected command to start with {resolved}, got {calls[0]}"
        )

    def test_resolve_command_already_absolute(self):
        """Already-absolute paths are resolved via realpath (symlink resolution)."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        binary_name, argv, raw_cmd, resolved_path = _resolve_command(
            (["/usr/bin/echo", "hello"],), {}
        )
        assert binary_name == "echo"
        assert resolved_path is not None
        assert os.path.isabs(resolved_path)
        # realpath resolves symlinks, so the resolved path may differ
        assert os.path.basename(resolved_path) == "echo" or resolved_path == os.path.realpath("/usr/bin/echo")

    def test_resolve_command_shell_mode_string(self):
        """shell=True string commands also get path resolution."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        binary_name, argv, raw_cmd, resolved_path = _resolve_command(
            ("echo hello world",), {"shell": True}
        )
        assert binary_name == "echo"
        if resolved_path is not None:
            assert os.path.isabs(resolved_path)

    def test_substitute_resolved_path_list_form(self):
        """_substitute_resolved_path correctly replaces in list-form args."""
        from sanna.interceptors.subprocess_interceptor import _substitute_resolved_path

        new_args, new_kwargs = _substitute_resolved_path(
            (["echo", "hello"],), {}, "/usr/bin/echo"
        )
        assert new_args[0] == ["/usr/bin/echo", "hello"]

    def test_substitute_resolved_path_none(self):
        """_substitute_resolved_path is a no-op when resolved_path is None."""
        from sanna.interceptors.subprocess_interceptor import _substitute_resolved_path

        orig_args = (["echo", "hello"],)
        orig_kwargs = {}
        new_args, new_kwargs = _substitute_resolved_path(orig_args, orig_kwargs, None)
        assert new_args is orig_args
        assert new_kwargs is orig_kwargs


# =============================================================================
# ENV-BASED PATH RESOLUTION (SAN-47)
# =============================================================================

class TestEnvPathResolution:
    """Verify that _resolve_command uses the subprocess env's PATH."""

    def test_resolve_uses_custom_env_path(self, tmp_path):
        """When env has a PATH, shutil.which resolves against that PATH."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        # Create a fake binary in a temp directory
        fake_bin = tmp_path / "echo"
        fake_bin.write_text("#!/bin/sh\necho fake")
        fake_bin.chmod(0o755)

        custom_env = {"PATH": str(tmp_path)}
        _, _, _, resolved = _resolve_command(
            (["echo", "hello"],), {}, env=custom_env
        )
        assert resolved is not None
        assert resolved == str(fake_bin)

    def test_resolve_without_env_uses_default_path(self):
        """Without env parameter, resolution uses the current process PATH."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        _, _, _, resolved = _resolve_command((["echo", "hello"],), {})
        # echo should resolve to the system echo
        assert resolved is not None
        assert "echo" in resolved

    def test_resolve_env_without_path_key_falls_back(self):
        """When env is provided but has no PATH key, falls back to default."""
        from sanna.interceptors.subprocess_interceptor import _resolve_command

        custom_env = {"HOME": "/tmp"}  # No PATH key
        _, _, _, resolved = _resolve_command(
            (["echo", "hello"],), {}, env=custom_env
        )
        # shutil.which(path=None) uses os.environ PATH
        assert resolved is not None

    def test_patched_run_resolves_with_env_path(self, tmp_path, sink):
        """subprocess.run with env= resolves binary using that env's PATH."""
        # Create a temp dir with a fake "mybin" script
        fake_bin = tmp_path / "mybin"
        fake_bin.write_text("#!/bin/sh\nexit 0")
        fake_bin.chmod(0o755)

        # Use permissive constitution so arbitrary binaries are allowed
        patch_subprocess(
            constitution_path=CLI_PERMISSIVE_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        custom_env = {"PATH": str(tmp_path)}
        result = subprocess.run(
            ["mybin"], env=custom_env, capture_output=True
        )
        assert result.returncode == 0

        # Verify a receipt was emitted
        assert sink.count >= 1

    def test_patched_popen_resolves_with_env_path(self, tmp_path, sink):
        """Popen with env= resolves binary using that env's PATH."""
        fake_bin = tmp_path / "mybin"
        fake_bin.write_text("#!/bin/sh\nexit 0")
        fake_bin.chmod(0o755)

        patch_subprocess(
            constitution_path=CLI_PERMISSIVE_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )

        custom_env = {"PATH": str(tmp_path)}
        proc = subprocess.Popen(
            ["mybin"], env=custom_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        proc.communicate()
        assert proc.returncode == 0


# =============================================================================
# 15. RECEIPT SCHEMA CONFORMANCE (SAN-379)
# =============================================================================

class TestReceiptSchemaConformance:
    """All CLI interceptor receipts validate against receipt.schema.json."""

    def test_enforce_mode_allowed_receipt_validates(self, patched):
        """Allowed receipt in enforce mode passes full schema validation."""
        subprocess.run(["echo", "hello"])
        receipt = patched.last
        jsonschema.validate(receipt, RECEIPT_SCHEMA)

    def test_enforce_mode_halted_receipt_validates(self, patched):
        """Halted receipt in enforce mode passes full schema validation."""
        with pytest.raises(FileNotFoundError):
            subprocess.run(["rm", "something"])
        receipt = patched.last
        jsonschema.validate(receipt, RECEIPT_SCHEMA)

    def test_audit_mode_receipt_validates(self, patched_audit):
        """Receipt from audit mode passes full schema validation."""
        subprocess.run(["rm", "--version"], capture_output=True)
        receipt = patched_audit.last
        jsonschema.validate(receipt, RECEIPT_SCHEMA)

    def test_passthrough_mode_receipt_validates(self, patched_passthrough):
        """Receipt from passthrough mode passes full schema validation."""
        subprocess.run(["echo", "hello"])
        receipt = patched_passthrough.last
        jsonschema.validate(receipt, RECEIPT_SCHEMA)

    def test_enforcement_mode_mapping_enforce(self, patched):
        """enforce mode -> enforcement_mode='halt'."""
        subprocess.run(["echo", "hello"])
        assert patched.last["enforcement"]["enforcement_mode"] == "halt"

    def test_enforcement_mode_mapping_audit(self, patched_audit):
        """audit mode -> enforcement_mode='warn'."""
        subprocess.run(["echo", "hello"])
        assert patched_audit.last["enforcement"]["enforcement_mode"] == "warn"

    def test_enforcement_mode_mapping_passthrough(self, patched_passthrough):
        """passthrough mode -> enforcement_mode='log'."""
        subprocess.run(["echo", "hello"])
        assert patched_passthrough.last["enforcement"]["enforcement_mode"] == "log"

    def test_enforcement_mode_is_schema_conformant_all_modes(self, sink):
        """enforcement_mode is in ['halt','warn','log'] for all three modes."""
        valid = {"halt", "warn", "log"}
        for mode in ("enforce", "audit", "passthrough"):
            unpatch_subprocess()
            patch_subprocess(
                constitution_path=CLI_TEST_CONSTITUTION,
                sink=sink,
                agent_id="test-agent",
                mode=mode,
            )
            sink.receipts.clear()
            subprocess.run(["echo", "hello"])
            em = sink.last["enforcement"]["enforcement_mode"]
            assert em in valid, f"mode={mode!r} produced enforcement_mode={em!r}"
        unpatch_subprocess()
