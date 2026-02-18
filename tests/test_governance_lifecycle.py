"""Tests for governance lifecycle demo.

Verifies the demo script runs end-to-end, produces expected output,
creates valid receipts, and detects tampering correctly.
Updated for v0.13.0 schema migration (spec_version, correlation_id,
status, enforcement, full_fingerprint).
"""

import sys
from pathlib import Path

import pytest

# Ensure examples/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "examples"))


class TestGovernanceLifecycleDemo:
    def test_demo_runs_without_errors(self):
        """Demo script completes all 8 steps without exceptions."""
        from governance_lifecycle_demo import run_demo
        results = run_demo()
        assert results["steps_completed"] == 8

    def test_demo_generates_receipts(self):
        """Demo generates the expected number of receipts."""
        from governance_lifecycle_demo import run_demo
        results = run_demo()
        assert results["receipts_generated"] == 3

    def test_demo_detects_tampering(self):
        """Demo correctly detects tampered constitution."""
        from governance_lifecycle_demo import run_demo
        results = run_demo()
        assert results["tamper_detected"] is True

    def test_demo_detects_diff_changes(self):
        """Demo finds changes between v1 and v2 constitutions."""
        from governance_lifecycle_demo import run_demo
        results = run_demo()
        assert results["diff_changes"] > 0

    def test_demo_creates_valid_bundle(self):
        """Demo creates and verifies a valid evidence bundle."""
        from governance_lifecycle_demo import run_demo
        results = run_demo()
        assert results["bundle_valid"] is True

    def test_demo_cleans_up_temporary_files(self, tmp_path):
        """Demo uses tempdir context manager so files are cleaned up."""
        import tempfile
        # The demo uses TemporaryDirectory which auto-cleans.
        # Verify no leftover sanna_lifecycle_ dirs in temp
        from governance_lifecycle_demo import run_demo
        run_demo()
        # Check no lingering dirs (they're created with prefix sanna_lifecycle_)
        temp_base = Path(tempfile.gettempdir())
        leftover = list(temp_base.glob("sanna_lifecycle_*"))
        assert len(leftover) == 0
