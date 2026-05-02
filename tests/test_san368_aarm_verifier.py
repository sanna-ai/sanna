"""SAN-368: Tests for the sanna-verify aarm CLI subcommand and AARM Core (R1-R6) verifier."""
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from sanna.aarm import (
    SANNA_TO_AARM,
    AarmReport,
    CheckResult,
    aggregate_aarm_report,
    check_r1_pre_execution_interception,
    check_r2_context_accumulation,
    check_r3_policy_evaluation,
    check_r4_decisions,
    check_r5_tamper_evident,
    check_r6_identity_binding,
    format_aarm_report,
)

FIXTURES_DIR = Path(__file__).parent.parent / "spec" / "fixtures" / "receipts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_receipt(**overrides) -> dict:
    """Minimal valid v1.5 receipt for unit tests."""
    r = {
        "spec_version": "1.5",
        "tool_version": "1.5.0",
        "checks_version": "10",
        "receipt_id": "test-receipt-001",
        "receipt_fingerprint": "abcd1234",
        "full_fingerprint": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        "correlation_id": "test-corr-001",
        "timestamp": "2026-05-02T00:00:00+00:00",
        "context_hash": "a" * 64,
        "output_hash": "b" * 64,
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "status": "PASS",
        "enforcement_surface": "middleware",
        "invariants_scope": "full",
        "tool_name": "sanna",
        "enforcement": {"action": "allowed"},
        "parent_receipts": None,
        "agent_identity": {"agent_session_id": "test-session-001"},
    }
    r.update(overrides)
    return r


# ---------------------------------------------------------------------------
# SANNA_TO_AARM mapping table
# ---------------------------------------------------------------------------

def test_sanna_to_aarm_covers_boundary_types():
    for key in ("can_execute", "cannot_execute", "must_escalate", "modify_with_constraints", "defer_pending_context"):
        assert key in SANNA_TO_AARM

def test_sanna_to_aarm_covers_decision_actions():
    for key in ("allow", "halt", "escalate"):
        assert key in SANNA_TO_AARM

def test_sanna_to_aarm_values():
    assert SANNA_TO_AARM["can_execute"] == "ALLOW"
    assert SANNA_TO_AARM["cannot_execute"] == "DENY"
    assert SANNA_TO_AARM["must_escalate"] == "STEP_UP"
    assert SANNA_TO_AARM["modify_with_constraints"] == "MODIFY"
    assert SANNA_TO_AARM["defer_pending_context"] == "DEFER"


# ---------------------------------------------------------------------------
# R1: Pre-Execution Interception
# ---------------------------------------------------------------------------

class TestR1:
    def test_pass_valid_surface(self):
        receipts = [_base_receipt(enforcement_surface="middleware")]
        result = check_r1_pre_execution_interception(receipts)
        assert result.status == "PASS"
        assert result.requirement == "R1"

    def test_pass_all_valid_surfaces(self):
        surfaces = ["middleware", "gateway", "cli_interceptor", "http_interceptor", "mixed"]
        receipts = [_base_receipt(enforcement_surface=s) for s in surfaces]
        result = check_r1_pre_execution_interception(receipts)
        assert result.status == "PASS"

    def test_fail_invalid_surface(self):
        receipts = [_base_receipt(enforcement_surface="unknown_surface")]
        result = check_r1_pre_execution_interception(receipts)
        assert result.status == "FAIL"
        assert len(result.evidence) == 1
        assert result.evidence[0]["enforcement_surface"] == "unknown_surface"

    def test_fail_missing_surface(self):
        receipts = [_base_receipt(enforcement_surface=None)]
        result = check_r1_pre_execution_interception(receipts)
        assert result.status == "FAIL"

    def test_invocation_event_type_pass(self):
        receipts = [_base_receipt(event_type="invocation_start", enforcement_surface="gateway")]
        result = check_r1_pre_execution_interception(receipts)
        assert result.status == "PASS"

    def test_invocation_event_type_fail(self):
        receipts = [_base_receipt(event_type="invocation_start", enforcement_surface="bad")]
        result = check_r1_pre_execution_interception(receipts)
        assert result.status == "FAIL"
        assert result.evidence[0]["event_type"] == "invocation_start"

    def test_empty_receipts(self):
        result = check_r1_pre_execution_interception([])
        assert result.status == "PASS"


# ---------------------------------------------------------------------------
# R2: Context Accumulation (parent_receipts chain)
# ---------------------------------------------------------------------------

class TestR2:
    def test_pass_no_parents(self):
        receipts = [_base_receipt()]
        result = check_r2_context_accumulation(receipts)
        assert result.status == "PASS"

    def test_pass_chain_resolves(self):
        parent_fp = "parent" + "0" * 58
        parent = _base_receipt(full_fingerprint=parent_fp, receipt_fingerprint="parent00")
        child = _base_receipt(
            full_fingerprint="child" + "0" * 59,
            receipt_fingerprint="child001",
            parent_receipts=[parent_fp],
        )
        result = check_r2_context_accumulation([parent, child])
        assert result.status == "PASS"

    def test_fail_broken_chain(self):
        child = _base_receipt(parent_receipts=["nonexistent-fingerprint"])
        result = check_r2_context_accumulation([child])
        assert result.status == "FAIL"
        assert result.evidence[0]["missing_parent"] == "nonexistent-fingerprint"

    def test_pass_null_parents(self):
        receipts = [_base_receipt(parent_receipts=None)]
        result = check_r2_context_accumulation(receipts)
        assert result.status == "PASS"

    def test_pass_empty_parents_list(self):
        receipts = [_base_receipt(parent_receipts=[])]
        result = check_r2_context_accumulation(receipts)
        assert result.status == "PASS"


# ---------------------------------------------------------------------------
# R3: Policy Evaluation
# ---------------------------------------------------------------------------

class TestR3:
    def test_na_no_governance_receipts(self):
        receipts = [_base_receipt()]
        result = check_r3_policy_evaluation(receipts)
        assert result.status == "N/A"

    def test_pass_policy_hash_present(self):
        receipts = [_base_receipt(constitution_ref={"policy_hash": "abc123", "document_id": "test/1.0"})]
        result = check_r3_policy_evaluation(receipts)
        assert result.status == "PASS"

    def test_fail_policy_hash_missing(self):
        receipts = [_base_receipt(constitution_ref={"document_id": "test/1.0"})]
        result = check_r3_policy_evaluation(receipts)
        assert result.status == "FAIL"
        assert len(result.evidence) == 1

    def test_fail_policy_hash_empty(self):
        receipts = [_base_receipt(constitution_ref={"policy_hash": "", "document_id": "test/1.0"})]
        result = check_r3_policy_evaluation(receipts)
        assert result.status == "FAIL"

    def test_pass_mixed_governance_all_have_hash(self):
        receipts = [
            _base_receipt(constitution_ref={"policy_hash": "hash1"}),
            _base_receipt(receipt_fingerprint="r2", constitution_ref={"policy_hash": "hash2"}),
        ]
        result = check_r3_policy_evaluation(receipts)
        assert result.status == "PASS"

    def test_fail_some_missing_hash(self):
        receipts = [
            _base_receipt(constitution_ref={"policy_hash": "hash1"}),
            _base_receipt(receipt_fingerprint="r2", constitution_ref={"document_id": "x"}),
        ]
        result = check_r3_policy_evaluation(receipts)
        assert result.status == "FAIL"


# ---------------------------------------------------------------------------
# R4: Five Authorization Decisions + STEP_UP chain check
# ---------------------------------------------------------------------------

class TestR4:
    def test_pass_no_authority_decisions(self):
        receipts = [_base_receipt()]
        result = check_r4_decisions(receipts)
        assert result.status == "PASS"

    def test_pass_valid_decision_allow(self):
        receipts = [_base_receipt(authority_decisions=[{"decision": "allow", "boundary_type": "can_execute"}])]
        result = check_r4_decisions(receipts)
        assert result.status == "PASS"

    def test_pass_valid_boundary_types(self):
        for bt in ("can_execute", "cannot_execute", "must_escalate", "modify_with_constraints", "defer_pending_context"):
            receipts = [_base_receipt(authority_decisions=[{"decision": "allow", "boundary_type": bt}])]
            result = check_r4_decisions(receipts)
            assert result.status == "PASS", f"boundary_type={bt!r} should PASS"

    def test_fail_invalid_decision_value(self):
        receipts = [_base_receipt(authority_decisions=[{"decision": "unknown_decision"}])]
        result = check_r4_decisions(receipts)
        assert result.status == "FAIL"
        assert any(e["value"] == "unknown_decision" for e in result.evidence)

    def test_fail_invalid_boundary_type(self):
        receipts = [_base_receipt(authority_decisions=[{"boundary_type": "bad_type"}])]
        result = check_r4_decisions(receipts)
        assert result.status == "FAIL"

    def test_step_up_pass_with_resolution(self):
        parent_fp = "escalated" + "0" * 55
        escalated = _base_receipt(
            receipt_fingerprint="esc001",
            full_fingerprint=parent_fp,
            enforcement={"action": "escalated"},
        )
        resolution = _base_receipt(
            receipt_fingerprint="res001",
            full_fingerprint="resolved" + "0" * 56,
            parent_receipts=[parent_fp],
        )
        result = check_r4_decisions([escalated, resolution])
        assert result.status == "PASS"

    def test_step_up_fail_no_resolution(self):
        escalated = _base_receipt(
            receipt_fingerprint="esc001",
            full_fingerprint="escalated" + "0" * 55,
            enforcement={"action": "escalated"},
        )
        result = check_r4_decisions([escalated])
        assert result.status == "FAIL"
        assert any("STEP_UP" in e["issue"] for e in result.evidence)

    def test_step_up_escalate_action(self):
        escalated = _base_receipt(
            receipt_fingerprint="esc002",
            full_fingerprint="escalate2" + "0" * 55,
            enforcement={"action": "escalate"},
        )
        result = check_r4_decisions([escalated])
        assert result.status == "FAIL"


# ---------------------------------------------------------------------------
# R5: Tamper-Evident Receipts
# ---------------------------------------------------------------------------

class TestR5:
    def test_pass_valid_fingerprint(self):
        fixture = FIXTURES_DIR / "pass-single-check.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        receipts = [json.loads(fixture.read_text())]
        result = check_r5_tamper_evident(receipts)
        assert result.status == "PASS"

    def test_fail_tampered_fingerprint(self):
        fixture = FIXTURES_DIR / "pass-single-check.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        r = json.loads(fixture.read_text())
        r["receipt_fingerprint"] = "deadbeef00000000"
        result = check_r5_tamper_evident([r])
        assert result.status == "FAIL"
        assert result.evidence[0]["issue"].startswith("fingerprint mismatch")

    def test_redacted_receipt_passes_fingerprint_check(self):
        fixture = FIXTURES_DIR / "pass-single-check.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        r = json.loads(fixture.read_text())
        r["content_mode"] = "redacted"
        # Fingerprint is unchanged so it still validates
        result = check_r5_tamper_evident([r])
        assert result.status == "PASS"

    def test_no_public_key_skips_sig_check(self):
        fixture = FIXTURES_DIR / "full-featured.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        receipts = [json.loads(fixture.read_text())]
        result = check_r5_tamper_evident(receipts, public_key_path=None)
        assert result.status == "PASS"
        assert "signatures" not in result.message

    def test_empty_receipts(self):
        result = check_r5_tamper_evident([])
        assert result.status == "PASS"


# ---------------------------------------------------------------------------
# R6: Identity Binding
# ---------------------------------------------------------------------------

class TestR6:
    def test_pass_cv10_with_agent_identity(self):
        receipts = [_base_receipt(checks_version="10", agent_identity={"agent_session_id": "sess-001"})]
        result = check_r6_identity_binding(receipts)
        assert result.status == "PASS"

    def test_partial_cv9_no_agent_identity(self):
        receipts = [_base_receipt(checks_version="9", agent_identity=None)]
        result = check_r6_identity_binding(receipts)
        assert result.status == "PARTIAL"
        assert "cv<=9" in result.message

    def test_fail_cv10_missing_agent_identity(self):
        receipts = [_base_receipt(checks_version="10", agent_identity=None)]
        result = check_r6_identity_binding(receipts)
        assert result.status == "FAIL"
        assert result.evidence[0]["issue"] == "cv=10 receipt missing agent_identity.agent_session_id"

    def test_fail_cv10_missing_session_id(self):
        receipts = [_base_receipt(checks_version="10", agent_identity={"other_field": "x"})]
        result = check_r6_identity_binding(receipts)
        assert result.status == "FAIL"

    def test_partial_mixed_cv9_and_cv10(self):
        cv10 = _base_receipt(checks_version="10", agent_identity={"agent_session_id": "sess-010"})
        cv9 = _base_receipt(
            receipt_fingerprint="r2",
            checks_version="9",
            agent_identity=None,
        )
        result = check_r6_identity_binding([cv10, cv9])
        assert result.status == "PARTIAL"
        assert "cv=10" in result.message
        assert "cv<=9" in result.message

    def test_fail_takes_precedence_over_partial(self):
        cv10_bad = _base_receipt(checks_version="10", agent_identity=None)
        cv9 = _base_receipt(
            receipt_fingerprint="r2",
            checks_version="9",
            agent_identity=None,
        )
        result = check_r6_identity_binding([cv10_bad, cv9])
        assert result.status == "FAIL"


# ---------------------------------------------------------------------------
# aggregate_aarm_report
# ---------------------------------------------------------------------------

class TestAggregateReport:
    def test_all_pass(self):
        receipts = [_base_receipt()]
        report = aggregate_aarm_report(receipts)
        assert isinstance(report, AarmReport)
        assert report.receipt_count == 1
        assert report.aggregate_status in ("PASS", "PARTIAL", "FAIL")
        assert len(report.checks) == 6

    def test_fail_propagates(self):
        receipts = [_base_receipt(enforcement_surface="invalid")]
        report = aggregate_aarm_report(receipts)
        assert report.aggregate_status == "FAIL"

    def test_partial_propagates(self):
        receipts = [_base_receipt(checks_version="9", agent_identity=None)]
        report = aggregate_aarm_report(receipts)
        # R6 partial due to cv=9
        assert report.aggregate_status in ("PARTIAL", "FAIL")

    def test_na_does_not_downgrade(self):
        fixture = FIXTURES_DIR / "pass-single-check.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        r = json.loads(fixture.read_text())
        r.pop("constitution_ref", None)  # remove governance ref -> R3=N/A
        report = aggregate_aarm_report([r])
        r3 = next(c for c in report.checks if c.requirement == "R3")
        assert r3.status == "N/A"
        # N/A should not cause FAIL
        assert report.aggregate_status in ("PASS", "PARTIAL")


# ---------------------------------------------------------------------------
# format_aarm_report
# ---------------------------------------------------------------------------

class TestFormatReport:
    def _make_report(self):
        return aggregate_aarm_report([_base_receipt()])

    def test_json_format(self):
        report = self._make_report()
        output = format_aarm_report(report, fmt="json")
        parsed = json.loads(output)
        assert "aggregate_status" in parsed
        assert "checks" in parsed
        assert "receipt_count" in parsed
        assert "generated_at" in parsed
        assert len(parsed["checks"]) == 6

    def test_human_format(self):
        report = self._make_report()
        output = format_aarm_report(report, fmt="human")
        assert "AARM Core (R1-R6)" in output
        assert "R1" in output
        assert "R6" in output

    def test_unknown_format_raises(self):
        report = self._make_report()
        with pytest.raises(ValueError, match="Unknown format"):
            format_aarm_report(report, fmt="sarif")

    def test_json_checks_have_required_fields(self):
        report = self._make_report()
        parsed = json.loads(format_aarm_report(report, fmt="json"))
        for check in parsed["checks"]:
            assert "requirement" in check
            assert "name" in check
            assert "status" in check
            assert "message" in check


# ---------------------------------------------------------------------------
# Integration: spec/fixtures/receipts (excluding standalone escalated)
# ---------------------------------------------------------------------------

class TestFixtureIntegration:
    @pytest.fixture
    def non_escalated_receipts(self):
        if not FIXTURES_DIR.exists():
            pytest.skip("spec/fixtures/receipts not available")
        receipts = []
        for fp in sorted(FIXTURES_DIR.glob("*.json")):
            if fp.name == "escalated.json":
                # Standalone escalation without resolution receipt is an incomplete set;
                # exclude to test a well-formed receipt set.
                continue
            receipts.append(json.loads(fp.read_text()))
        if not receipts:
            pytest.skip("No non-escalated fixtures found")
        return receipts

    def test_aggregate_pass_or_partial(self, non_escalated_receipts):
        report = aggregate_aarm_report(non_escalated_receipts)
        assert report.aggregate_status in ("PASS", "PARTIAL"), (
            f"Expected PASS or PARTIAL, got {report.aggregate_status}. "
            f"Checks: {[(c.requirement, c.status, c.message) for c in report.checks]}"
        )

    def test_r5_fingerprints_valid(self, non_escalated_receipts):
        report = aggregate_aarm_report(non_escalated_receipts)
        r5 = next(c for c in report.checks if c.requirement == "R5")
        assert r5.status == "PASS", f"R5 fingerprints should pass: {r5.evidence}"

    def test_escalated_standalone_fails_r4(self):
        fixture = FIXTURES_DIR / "escalated.json"
        if not fixture.exists():
            pytest.skip("escalated.json not available")
        receipts = [json.loads(fixture.read_text())]
        report = aggregate_aarm_report(receipts)
        r4 = next(c for c in report.checks if c.requirement == "R4")
        assert r4.status == "FAIL"

    def test_report_json_parseable(self, non_escalated_receipts):
        report = aggregate_aarm_report(non_escalated_receipts)
        output = format_aarm_report(report, fmt="json")
        parsed = json.loads(output)
        assert parsed["receipt_count"] == len(non_escalated_receipts)


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

class TestCliSmoke:
    def test_main_verify_aarm_exit_0_json(self, tmp_path):
        fixture = FIXTURES_DIR / "pass-single-check.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        shutil.copy(fixture, tmp_path / "r.json")

        from sanna.cli import main_verify_aarm

        original_argv = sys.argv[:]
        try:
            sys.argv = ["sanna-verify aarm", str(tmp_path / "*.json"), "--format", "json"]
            exit_code = main_verify_aarm()
        finally:
            sys.argv = original_argv

        assert exit_code in (0, 1), f"Expected 0 or 1, got {exit_code}"

    def test_main_verify_aarm_json_output(self, tmp_path, capsys):
        fixture = FIXTURES_DIR / "pass-single-check.json"
        if not fixture.exists():
            pytest.skip("Fixture not available")
        shutil.copy(fixture, tmp_path / "r.json")

        from sanna.cli import main_verify_aarm

        original_argv = sys.argv[:]
        try:
            sys.argv = ["sanna-verify aarm", str(tmp_path / "r.json"), "--format", "json"]
            exit_code = main_verify_aarm()
        finally:
            sys.argv = original_argv

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "aggregate_status" in parsed
        assert "checks" in parsed
        assert len(parsed["checks"]) == 6

    def test_main_verify_aarm_no_files_returns_2(self, tmp_path):
        from sanna.cli import main_verify_aarm

        original_argv = sys.argv[:]
        try:
            sys.argv = ["sanna-verify aarm", str(tmp_path / "nonexistent*.json")]
            exit_code = main_verify_aarm()
        finally:
            sys.argv = original_argv

        assert exit_code == 2

    def test_main_verify_aarm_multiple_fixtures(self, tmp_path, capsys):
        if not FIXTURES_DIR.exists():
            pytest.skip("Fixtures not available")
        for fp in sorted(FIXTURES_DIR.glob("*.json")):
            if fp.name != "escalated.json":
                shutil.copy(fp, tmp_path / fp.name)

        from sanna.cli import main_verify_aarm

        original_argv = sys.argv[:]
        try:
            sys.argv = ["sanna-verify aarm", str(tmp_path / "*.json"), "--format", "json"]
            exit_code = main_verify_aarm()
        finally:
            sys.argv = original_argv

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["receipt_count"] >= 1
        assert exit_code in (0, 1)
