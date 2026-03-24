"""Tests for wrapper script bypass detection in subprocess interceptor [SAN-45].

Verifies that the optional script content inspection feature detects blocked
commands inside shell/Python/Ruby/Perl scripts when inspect_scripts: true is
set in the constitution's cli_permissions.
"""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sanna.constitution import load_constitution, CliPermissions, CliCommand
from sanna.interceptors import patch_subprocess, unpatch_subprocess
from sanna.interceptors.subprocess_interceptor import (
    _inspect_script_content,
    _SCRIPT_EXTENSIONS,
    _SCRIPT_INSPECT_LIMIT,
)
from sanna.sinks.sink import ReceiptSink, SinkResult


# =============================================================================
# HELPERS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
CLI_INSPECT_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-inspect-scripts.yaml")
CLI_TEST_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-test.yaml")


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
def patched_inspect(sink):
    """Patch subprocess with inspect-scripts constitution in enforce mode."""
    patch_subprocess(
        constitution_path=CLI_INSPECT_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    return sink


@pytest.fixture
def patched_no_inspect(sink):
    """Patch subprocess with standard constitution (inspect_scripts=false)."""
    patch_subprocess(
        constitution_path=CLI_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    return sink


# =============================================================================
# 1. DIRECT _inspect_script_content TESTS
# =============================================================================

class TestInspectScriptContentDirect:
    """Test _inspect_script_content() function directly."""

    def test_returns_empty_for_none_path(self):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        result = _inspect_script_content(None, constitution)
        assert result == []

    def test_returns_empty_when_inspect_disabled(self):
        constitution = load_constitution(CLI_TEST_CONSTITUTION)
        # cli-test.yaml does not have inspect_scripts: true
        assert not constitution.cli_permissions.inspect_scripts
        result = _inspect_script_content("/usr/bin/bash", constitution)
        assert result == []

    def test_returns_empty_for_no_cli_permissions(self, tmp_path):
        """Constitution without cli_permissions returns empty."""
        from unittest.mock import MagicMock
        constitution = MagicMock()
        constitution.cli_permissions = None
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert result == []

    def test_detects_blocked_command_in_sh_script(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\necho hello\nrm -rf /tmp/stuff\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert "rm" in result

    def test_clean_script_returns_empty(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "good.sh"
        script.write_text("#!/bin/bash\necho hello world\ncat /etc/hosts\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert result == []

    def test_detects_by_extension_without_shebang(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "evil.sh"
        # No shebang line
        script.write_text("rm -rf /\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert "rm" in result

    def test_detects_by_shebang_without_extension(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "wrapper"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert "rm" in result

    def test_no_shebang_no_extension_skipped(self, tmp_path):
        """Binary-like file without shebang or script extension is skipped."""
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        binary = tmp_path / "mybinary"
        # Write ELF-like header (not a shebang)
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        result = _inspect_script_content(str(binary), constitution)
        assert result == []

    def test_python_script_detected(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "evil.py"
        script.write_text('import os\nos.system("rm -rf /")\n')
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert "rm" in result

    def test_ruby_script_detected(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "evil.rb"
        script.write_text('system("rm -rf /")\n')
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert "rm" in result

    def test_perl_script_detected(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "evil.pl"
        script.write_text('system("rm -rf /");\n')
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert "rm" in result

    def test_unreadable_script_returns_empty(self, tmp_path):
        """Unreadable script fails open (returns empty, not error)."""
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "secret.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o000)
        try:
            result = _inspect_script_content(str(script), constitution)
            assert result == []
        finally:
            script.chmod(0o644)  # Restore for cleanup

    def test_nonexistent_path_returns_empty(self):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        result = _inspect_script_content("/nonexistent/path/to/script.sh", constitution)
        assert result == []

    def test_respects_inspect_limit(self, tmp_path):
        """Commands beyond the 8KB window are not detected."""
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "big.sh"
        # Put blocked command after the inspection limit
        padding = "echo ok\n" * (_SCRIPT_INSPECT_LIMIT // 8 + 100)
        script.write_text("#!/bin/bash\n" + padding + "rm -rf /\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        # rm should NOT be found because it's beyond the 8KB window
        assert "rm" not in result

    def test_deduplicates_findings(self, tmp_path):
        constitution = load_constitution(CLI_INSPECT_CONSTITUTION)
        script = tmp_path / "multi.sh"
        script.write_text("#!/bin/bash\nrm foo\nrm bar\nrm baz\n")
        script.chmod(0o755)
        result = _inspect_script_content(str(script), constitution)
        assert result.count("rm") == 1

    def test_all_script_extensions_recognized(self):
        """Verify the expected set of script extensions."""
        expected = {".sh", ".bash", ".zsh", ".fish", ".py", ".rb", ".pl", ".perl"}
        assert _SCRIPT_EXTENSIONS == expected


# =============================================================================
# 2. INTEGRATION TESTS — ENFORCEMENT
# =============================================================================

class TestScriptInspectionEnforcement:
    """Test that script inspection integrates with enforcement flow."""

    def test_sh_script_with_blocked_command_halted(self, tmp_path, patched_inspect):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /tmp/stuff\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError) as exc_info:
            subprocess.run([str(script)])
        assert exc_info.value.errno == errno.ENOENT

    def test_sh_script_with_allowed_commands_passes(self, tmp_path, patched_inspect):
        script = tmp_path / "good.sh"
        script.write_text("#!/bin/bash\necho hello world\n")
        script.chmod(0o755)

        result = subprocess.run([str(script)], capture_output=True)
        assert result.returncode == 0
        assert patched_inspect.count == 1
        assert patched_inspect.last["event_type"] == "cli_invocation_allowed"

    def test_py_script_with_blocked_command_halted(self, tmp_path, patched_inspect):
        script = tmp_path / "evil.py"
        script.write_text('#!/usr/bin/env python3\nimport os\nos.system("rm -rf /")\n')
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.run([str(script)])

    def test_inspection_skipped_when_disabled(self, tmp_path, patched_no_inspect):
        """Scripts pass through when inspect_scripts is false (default)."""
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /tmp/stuff\n")
        script.chmod(0o755)

        # The script itself is allowed (it's not named "rm"), and since
        # inspect_scripts is false, the content is not checked.
        # In strict mode with cli-test.yaml, the script basename won't match
        # any can_execute rule, so it will be halted for being unlisted.
        # Use a script named to match an allowed binary.
        script2 = tmp_path / "echo_wrapper.sh"
        script2.write_text("#!/bin/bash\nrm -rf /\n")
        script2.chmod(0o755)

        # strict mode halts unlisted binaries, so this still raises —
        # but for the right reason (unlisted, not script content)
        with pytest.raises(FileNotFoundError):
            subprocess.run([str(script2)])
        receipt = patched_no_inspect.last
        # The halt reason should mention "not listed" (strict mode), not script content
        assert "not listed" in receipt["enforcement"]["reason"]

    def test_non_script_binary_not_inspected(self, tmp_path, patched_inspect):
        """ELF-like binary is not inspected even with inspect_scripts=true."""
        binary = tmp_path / "mybinary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)

        # This will fail because the binary isn't a real executable,
        # but the failure should be from the OS, not from script inspection
        # In permissive mode, unlisted binaries are allowed
        try:
            subprocess.run([str(binary)], capture_output=True)
        except (OSError, FileNotFoundError):
            pass  # Expected — not a real binary

        # If a receipt was emitted, it should NOT be a script inspection halt
        if patched_inspect.count > 0:
            receipt = patched_inspect.last
            assert receipt.get("enforcement", {}).get("reason", "").find("script_content_inspection") == -1

    def test_subprocess_call_inspects_scripts(self, tmp_path, patched_inspect):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.call([str(script)])

    def test_subprocess_check_call_inspects_scripts(self, tmp_path, patched_inspect):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.check_call([str(script)])

    def test_subprocess_check_output_inspects_scripts(self, tmp_path, patched_inspect):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.check_output([str(script)])

    def test_popen_inspects_scripts(self, tmp_path, patched_inspect):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.Popen([str(script)])

    def test_receipt_has_script_inspection_rule_id(self, tmp_path, patched_inspect):
        """Halted receipt from script inspection has correct rule_id."""
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.run([str(script)])

        receipt = patched_inspect.last
        ext = receipt.get("extensions", {}).get("com.sanna.interceptor", {})
        assert ext.get("rule_id") == "script_content_inspection"

    def test_receipt_reason_lists_blocked_commands(self, tmp_path, patched_inspect):
        """Halt reason mentions the specific blocked commands found."""
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nrm -rf /\ndocker run nginx\n")
        script.chmod(0o755)

        with pytest.raises(FileNotFoundError):
            subprocess.run([str(script)])

        receipt = patched_inspect.last
        reason = receipt["enforcement"]["reason"]
        assert "rm" in reason
