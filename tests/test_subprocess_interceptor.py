"""Tests for sanna.interceptors.subprocess_interceptor — CLI governance."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

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
