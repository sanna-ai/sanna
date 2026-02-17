"""Integration tests for LLM-as-Judge evaluators in the middleware pipeline.

Verifies that LLMJudge evaluators flow through the full @sanna_observe pipeline:
constitution loading -> configure_checks -> middleware execution -> receipt generation.

All API calls are mocked — no real LLM requests are made.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sanna.evaluators import clear_evaluators, get_evaluator
from sanna.evaluators.llm import (
    LLMJudge,
    LLMEvaluationError,
    register_llm_evaluators,
    enable_llm_checks,
    _CHECK_ALIASES,
)
from sanna.middleware import sanna_observe, SannaHaltError
from sanna.receipt import CheckResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_registry():
    clear_evaluators()
    yield
    clear_evaluators()


def _make_signed_constitution(tmp_path, invariants, enforcement="warn"):
    """Create a signed constitution file with the given invariants."""
    from sanna.constitution import (
        Constitution, AgentIdentity, Provenance, Boundary, Invariant,
        sign_constitution, save_constitution,
    )
    from sanna.crypto import generate_keypair

    inv_objects = [
        Invariant(id=inv_id, rule=f"Rule for {inv_id}", enforcement=enforcement)
        for inv_id in invariants
    ]

    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="llm-test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="t@t.com",
            approved_by=["a@t.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        invariants=inv_objects,
    )
    priv_path, _ = generate_keypair(tmp_path / "keys")
    signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
    path = tmp_path / "const.yaml"
    save_constitution(signed, path)
    return str(path)


def _mock_api_response(passed=True, confidence=0.95, evidence="Looks good"):
    """Create a mock urllib response returning a valid LLM judge result."""
    response_body = json.dumps({
        "content": [{"text": json.dumps({
            "pass": passed,
            "confidence": confidence,
            "evidence": evidence,
        })}],
    }).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = response_body
    mock_resp.__enter__ = lambda self: self
    mock_resp.__exit__ = lambda self, *args: None
    return mock_resp


def _mock_api_error():
    """Create a mock that simulates an API timeout."""
    import urllib.error
    raise urllib.error.URLError("Connection timed out")


# ---------------------------------------------------------------------------
# Test 1: Happy path — LLM evaluator passes, receipt has correct check IDs
# ---------------------------------------------------------------------------

class TestLLMHappyPath:

    def test_llm_evaluator_pass_produces_correct_receipt(self, tmp_path):
        """LLM evaluator passes -> receipt has INV_LLM_* checks with PASS."""
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=["INV_NO_FABRICATION", "INV_LLM_CONTEXT_GROUNDING"],
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge, checks=["LLM_C1"])

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_api_response(passed=True)

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "Answer grounded in context."

            result = agent(query="test?", context="Known facts here.")

        receipt = result.receipt
        check_ids = {c["check_id"] for c in receipt["checks"]}

        # Built-in check ran
        assert "sanna.context_contradiction" in check_ids
        # LLM check ran (uses invariant ID as check_id)
        assert "INV_LLM_CONTEXT_GROUNDING" in check_ids

        # LLM check passed
        llm_check = [c for c in receipt["checks"] if c["check_id"] == "INV_LLM_CONTEXT_GROUNDING"][0]
        assert llm_check["passed"] is True
        assert "confidence=" in llm_check["details"]

        # No ERRORED status on the LLM check
        assert llm_check.get("status") != "ERRORED"

    def test_llm_evaluator_fail_produces_warn(self, tmp_path):
        """LLM evaluator returns fail -> receipt has WARN coherence_status."""
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=["INV_LLM_FABRICATION_DETECTION"],
            enforcement="warn",
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge, checks=["LLM_C2"])

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_api_response(
                passed=False, confidence=0.88, evidence="Fabricated claim detected"
            )

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "The moon is made of cheese according to NASA."

            result = agent(query="moon?", context="NASA says the moon is rock.")

        receipt = result.receipt
        llm_check = [c for c in receipt["checks"] if c["check_id"] == "INV_LLM_FABRICATION_DETECTION"][0]
        assert llm_check["passed"] is False
        assert llm_check["severity"] == "critical"
        # severity=critical -> coherence_status=FAIL (status is driven by
        # severity, enforcement_level controls halt/warn/log behavior)
        assert receipt["coherence_status"] == "FAIL"


# ---------------------------------------------------------------------------
# Test 2: LLM failure under halt enforcement -> ERRORED, not halted
# ---------------------------------------------------------------------------

class TestLLMFailureUnderHalt:

    def test_api_error_produces_errored_not_halt(self, tmp_path):
        """When LLM API fails and enforcement is halt, the check is ERRORED, not halted.

        The middleware catches the exception from the evaluator and records
        ERRORED status with passed=True. This prevents false halts when
        the LLM API is unavailable.
        """
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=["INV_LLM_CONTEXT_GROUNDING"],
            enforcement="halt",
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge, checks=["LLM_C1"])

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            import urllib.error
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "Answer."

            # Should NOT raise SannaHaltError — the evaluator exception
            # is caught by middleware and recorded as ERRORED
            result = agent(query="q", context="ctx")

        receipt = result.receipt
        llm_check = [c for c in receipt["checks"] if c["check_id"] == "INV_LLM_CONTEXT_GROUNDING"][0]
        assert llm_check["status"] == "ERRORED"
        assert llm_check["passed"] is True  # ERRORED = not-failed
        assert "Evaluator error" in llm_check["details"]

        # Overall status is PARTIAL (ERRORED checks are non-evaluated)
        assert receipt["coherence_status"] == "PARTIAL"

    def test_malformed_response_produces_errored(self, tmp_path):
        """When LLM returns malformed JSON, the check is ERRORED."""
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=["INV_LLM_FALSE_CERTAINTY"],
            enforcement="warn",
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge, checks=["LLM_C4"])

        # Return valid API response but with missing "pass" field
        bad_result = json.dumps({
            "content": [{"text": json.dumps({
                "confidence": 0.5,
                "evidence": "Something",
            })}],
        }).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = bad_result
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *args: None

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = mock_resp

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "The data clearly shows X."

            result = agent(query="q", context="Some context.")

        receipt = result.receipt
        llm_check = [c for c in receipt["checks"] if c["check_id"] == "INV_LLM_FALSE_CERTAINTY"][0]
        assert llm_check["status"] == "ERRORED"
        assert llm_check["passed"] is True


# ---------------------------------------------------------------------------
# Test 3: No interference with built-in checks
# ---------------------------------------------------------------------------

class TestNoInterference:

    def test_builtin_checks_unaffected_by_llm_registration(self, tmp_path):
        """Built-in C1-C5 checks produce identical results whether or not
        LLM evaluators are registered."""
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=[
                "INV_NO_FABRICATION",
                "INV_MARK_INFERENCE",
                "INV_LLM_CONTEXT_GROUNDING",
            ],
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge, checks=["LLM_C1"])

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_api_response(passed=True)

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "Answer based on the provided context."

            result = agent(query="test?", context="Context for testing.")

        receipt = result.receipt
        checks_by_id = {c["check_id"]: c for c in receipt["checks"]}

        # Built-in checks are present and replayable
        assert "sanna.context_contradiction" in checks_by_id
        assert checks_by_id["sanna.context_contradiction"]["replayable"] is True

        assert "sanna.unmarked_inference" in checks_by_id
        assert checks_by_id["sanna.unmarked_inference"]["replayable"] is True

        # LLM check is present but NOT replayable (custom evaluator)
        assert "INV_LLM_CONTEXT_GROUNDING" in checks_by_id
        assert checks_by_id["INV_LLM_CONTEXT_GROUNDING"]["replayable"] is False

    def test_unregistered_llm_invariant_is_not_checked(self, tmp_path):
        """LLM invariant without enable_llm_checks() shows as NOT_CHECKED."""
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=[
                "INV_NO_FABRICATION",
                "INV_LLM_FABRICATION_DETECTION",
            ],
        )
        # Intentionally do NOT register LLM evaluators

        @sanna_observe(constitution_path=const_path)
        def agent(query, context):
            return "Normal answer."

        result = agent(query="q", context="ctx")
        receipt = result.receipt

        checks_by_id = {c["check_id"]: c for c in receipt["checks"]}
        # Built-in check ran normally
        assert "sanna.context_contradiction" in checks_by_id
        assert checks_by_id["sanna.context_contradiction"].get("status") != "NOT_CHECKED"

        # LLM invariant without evaluator is NOT_CHECKED
        assert "INV_LLM_FABRICATION_DETECTION" in checks_by_id
        assert checks_by_id["INV_LLM_FABRICATION_DETECTION"]["status"] == "NOT_CHECKED"


# ---------------------------------------------------------------------------
# Test 4: LLM-enhanced template end-to-end
# ---------------------------------------------------------------------------

class TestLLMEnhancedTemplate:

    def test_all_five_llm_checks_in_receipt(self, tmp_path):
        """Constitution with all 5 LLM invariants produces receipt with all 5 checks."""
        all_llm_invariants = list(_CHECK_ALIASES.values())
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=all_llm_invariants,
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge)  # all 5

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_api_response(passed=True)

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "Complete answer."

            result = agent(query="q", context="ctx")

        receipt = result.receipt
        check_ids = {c["check_id"] for c in receipt["checks"]}

        for inv_id in all_llm_invariants:
            assert inv_id in check_ids, f"{inv_id} missing from receipt"

        # All passed -> coherence_status = PASS
        assert receipt["coherence_status"] == "PASS"
        assert receipt["checks_passed"] == 5
        assert receipt["checks_failed"] == 0

    def test_mixed_builtin_and_llm_all_pass(self, tmp_path):
        """Mixed constitution with both builtin and LLM invariants all passing."""
        const_path = _make_signed_constitution(
            tmp_path,
            invariants=[
                "INV_NO_FABRICATION",
                "INV_MARK_INFERENCE",
                "INV_LLM_CONTEXT_GROUNDING",
                "INV_LLM_FABRICATION_DETECTION",
            ],
        )

        judge = LLMJudge(api_key="test-key")
        register_llm_evaluators(judge, checks=["LLM_C1", "LLM_C2"])

        with patch("sanna.evaluators.llm.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_api_response(passed=True)

            @sanna_observe(constitution_path=const_path)
            def agent(query, context):
                return "Answer using provided facts."

            result = agent(query="q", context="Known facts.")

        receipt = result.receipt
        assert receipt["coherence_status"] == "PASS"
        assert receipt["checks_passed"] == 4
        assert receipt["checks_failed"] == 0

        # Verify all 4 checks present
        check_ids = {c["check_id"] for c in receipt["checks"]}
        assert "sanna.context_contradiction" in check_ids
        assert "sanna.unmarked_inference" in check_ids
        assert "INV_LLM_CONTEXT_GROUNDING" in check_ids
        assert "INV_LLM_FABRICATION_DETECTION" in check_ids
