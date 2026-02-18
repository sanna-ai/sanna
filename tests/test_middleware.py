"""
Sanna middleware test suite — @sanna_observe decorator tests.

Tests cover: happy path, halt/warn/log modes, check subsets, receipt
file output, input mapping, and receipt validity.

v0.6.0: Tests updated to use constitution-driven enforcement.
Without a constitution_path, no checks run (receipts have empty checks).
"""

import json
import warnings
import pytest
from pathlib import Path

from sanna.middleware import sanna_observe, SannaResult, SannaHaltError
from sanna.verify import verify_receipt, load_schema

SCHEMA = load_schema()

# =============================================================================
# TEST CONSTITUTION PATHS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
ALL_HALT_CONST = str(CONSTITUTIONS_DIR / "all_halt.yaml")
ALL_WARN_CONST = str(CONSTITUTIONS_DIR / "all_warn.yaml")
ALL_LOG_CONST = str(CONSTITUTIONS_DIR / "all_log.yaml")
C1_C3_CONST = str(CONSTITUTIONS_DIR / "c1_c3_only.yaml")
C1_HALT_REST_LOG = str(CONSTITUTIONS_DIR / "c1_halt_rest_log.yaml")
C1_WARN_ONLY = str(CONSTITUTIONS_DIR / "c1_warn_only.yaml")

# =============================================================================
# FIXTURES — Simulated agent functions
# =============================================================================

# Context and output from golden receipt 001 (C1 failure scenario)
REFUND_CONTEXT = (
    "Our refund policy: Physical products can be returned within 30 days. "
    "Digital products are non-refundable once downloaded. "
    "Subscriptions can be cancelled anytime."
)

REFUND_BAD_OUTPUT = (
    "Based on your purchase history, you are eligible to request a refund. "
    "However, since the software was downloaded, processing may take 5-7 "
    "business days."
)

SIMPLE_CONTEXT = "Paris is the capital of France."
SIMPLE_OUTPUT = "The capital of France is Paris."


def make_passing_agent(constitution_path=ALL_HALT_CONST):
    """Create a simple agent that passes all checks."""
    @sanna_observe(require_constitution_sig=False, constitution_path=constitution_path)
    def agent(query: str, context: str) -> str:
        return SIMPLE_OUTPUT
    return agent


def make_failing_agent_with_constitution(constitution_path=ALL_HALT_CONST):
    """Create an agent that triggers C1 (critical) failure with a constitution."""
    @sanna_observe(require_constitution_sig=False, constitution_path=constitution_path)
    def agent(query: str, context: str) -> str:
        return REFUND_BAD_OUTPUT
    return agent


# =============================================================================
# 1. Happy path — all checks pass
# =============================================================================

class TestHappyPath:
    def test_passes_all_checks(self):
        agent = make_passing_agent()
        result = agent(query="capital of France?", context=SIMPLE_CONTEXT)

        assert isinstance(result, SannaResult)
        assert result.passed
        assert result.status == "PASS"
        assert result.output == SIMPLE_OUTPUT

    def test_receipt_has_required_fields(self):
        agent = make_passing_agent()
        result = agent(query="test", context=SIMPLE_CONTEXT)

        required = [
            "spec_version", "tool_version", "checks_version",
            "receipt_id", "receipt_fingerprint", "correlation_id",
            "full_fingerprint",
            "timestamp", "inputs", "outputs", "context_hash",
            "output_hash", "checks",
            "checks_passed", "checks_failed", "status",
        ]
        for field in required:
            assert field in result.receipt, f"Missing field: {field}"

    def test_receipt_has_extensions(self):
        agent = make_passing_agent()
        result = agent(query="test", context=SIMPLE_CONTEXT)

        assert "extensions" in result.receipt
        mw = result.receipt["extensions"]["com.sanna.middleware"]
        assert mw["decorator"] == "@sanna_observe"
        assert mw["function_name"] == "agent"
        assert mw["enforcement_decision"] == "PASSED"
        assert isinstance(mw["execution_time_ms"], int)

    def test_bare_decorator(self):
        """@sanna_observe without parentheses should work."""
        @sanna_observe
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert isinstance(result, SannaResult)

    def test_no_constitution_runs_no_checks(self):
        """Without constitution_path, no checks run and receipt passes."""
        @sanna_observe(on_violation="halt")
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        result = agent(query="refund policy", context=REFUND_CONTEXT)
        assert isinstance(result, SannaResult)
        assert result.receipt["status"] == "PASS"
        assert result.receipt["checks"] == []
        assert result.receipt["checks_passed"] == 0
        assert result.receipt["checks_failed"] == 0


# =============================================================================
# 2. Violation with halt — C1 critical failure raises SannaHaltError
# =============================================================================

class TestHalt:
    def test_halt_on_critical_failure(self):
        agent = make_failing_agent_with_constitution(ALL_HALT_CONST)

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund policy software", context=REFUND_CONTEXT)

        assert exc_info.value.receipt is not None
        assert exc_info.value.receipt["status"] == "FAIL"
        assert "context_contradiction" in str(exc_info.value)

    def test_halt_receipt_has_enforcement_decision(self):
        agent = make_failing_agent_with_constitution(ALL_HALT_CONST)

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund policy", context=REFUND_CONTEXT)

        mw = exc_info.value.receipt["extensions"]["com.sanna.middleware"]
        assert mw["enforcement_decision"] == "HALTED"
        assert mw["on_violation"] == "halt"


# =============================================================================
# 3. Violation with warn — returns SannaResult, emits warning
# =============================================================================

class TestWarn:
    def test_warn_returns_result(self):
        agent = make_failing_agent_with_constitution(ALL_WARN_CONST)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = agent(query="refund policy", context=REFUND_CONTEXT)

        assert isinstance(result, SannaResult)
        assert result.output == REFUND_BAD_OUTPUT
        assert result.receipt["status"] == "FAIL"
        assert not result.passed

        # Should have emitted a warning
        sanna_warnings = [x for x in w if "Sanna" in str(x.message)]
        assert len(sanna_warnings) >= 1

    def test_warn_receipt_has_enforcement_decision(self):
        agent = make_failing_agent_with_constitution(ALL_WARN_CONST)

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="refund policy", context=REFUND_CONTEXT)

        mw = result.receipt["extensions"]["com.sanna.middleware"]
        assert mw["enforcement_decision"] == "WARNED"


# =============================================================================
# 4. Violation with log — returns SannaResult, no warning
# =============================================================================

class TestLog:
    def test_log_returns_result_no_warning(self):
        agent = make_failing_agent_with_constitution(ALL_LOG_CONST)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = agent(query="refund policy", context=REFUND_CONTEXT)

        assert isinstance(result, SannaResult)
        assert result.output == REFUND_BAD_OUTPUT
        assert result.receipt["status"] == "FAIL"

        # Should NOT have emitted a warning
        sanna_warnings = [x for x in w if "Sanna" in str(x.message)]
        assert len(sanna_warnings) == 0

    def test_log_receipt_has_enforcement_decision(self):
        agent = make_failing_agent_with_constitution(ALL_LOG_CONST)

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="refund policy", context=REFUND_CONTEXT)

        mw = result.receipt["extensions"]["com.sanna.middleware"]
        assert mw["enforcement_decision"] == "LOGGED"


# =============================================================================
# 5. Custom check subset — only run C1 and C3 via constitution
# =============================================================================

class TestCheckSubset:
    def test_subset_only_runs_requested_checks(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=C1_C3_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)

        check_ids = [c["check_id"] for c in result.receipt["checks"]]
        assert check_ids == ["sanna.context_contradiction", "sanna.false_certainty"]
        assert len(result.receipt["checks"]) == 2

    def test_subset_counts_match(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=C1_C3_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)

        total = result.receipt["checks_passed"] + result.receipt["checks_failed"]
        assert total == 2


# =============================================================================
# 6. Receipt file output
# =============================================================================

class TestReceiptFileOutput:
    def test_writes_receipt_json(self, tmp_path):
        receipt_dir = str(tmp_path / "receipts")

        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST, receipt_dir=receipt_dir)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)

        # Should have written a file
        files = list(Path(receipt_dir).glob("*.json"))
        assert len(files) == 1

        # File should contain valid JSON matching the receipt
        with open(files[0]) as f:
            written = json.load(f)
        assert written["correlation_id"] == result.receipt["correlation_id"]
        assert written["status"] == result.receipt["status"]

    def test_no_file_when_receipt_dir_none(self, tmp_path):
        @sanna_observe(on_violation="log", receipt_dir=None)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        agent(query="test", context=SIMPLE_CONTEXT)
        # No files should be created in tmp_path
        assert len(list(tmp_path.glob("**/*.json"))) == 0

    def test_receipt_file_on_halt(self, tmp_path):
        """Receipt should be written even when halting."""
        receipt_dir = str(tmp_path / "receipts")

        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST, receipt_dir=receipt_dir)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError):
            agent(query="refund policy", context=REFUND_CONTEXT)

        files = list(Path(receipt_dir).glob("*.json"))
        assert len(files) == 1


# =============================================================================
# 7. Input mapping — explicit context_param and query_param
# =============================================================================

class TestInputMappingExplicit:
    def test_explicit_param_mapping(self):
        @sanna_observe(
            on_violation="log",
            context_param="retrieved_docs",
            query_param="user_input",
        )
        def pipeline(user_input: str, retrieved_docs: str) -> str:
            return SIMPLE_OUTPUT

        result = pipeline(user_input="capital?", retrieved_docs=SIMPLE_CONTEXT)

        assert isinstance(result, SannaResult)
        assert result.receipt["inputs"]["context"] == SIMPLE_CONTEXT
        assert result.receipt["inputs"]["query"] == "capital?"

    def test_explicit_overrides_convention(self):
        """Explicit mapping should take precedence over convention."""
        @sanna_observe(
            on_violation="log",
            context_param="data",
            query_param="q",
        )
        def pipeline(q: str, context: str, data: str) -> str:
            return SIMPLE_OUTPUT

        result = pipeline(
            q="from explicit",
            context="should be ignored",
            data="explicit context",
        )

        assert result.receipt["inputs"]["context"] == "explicit context"
        assert result.receipt["inputs"]["query"] == "from explicit"


# =============================================================================
# 8. Input mapping — convention-based
# =============================================================================

class TestInputMappingConvention:
    def test_convention_context_and_query(self):
        @sanna_observe(on_violation="log")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test query", context="test context")

        assert result.receipt["inputs"]["query"] == "test query"
        assert result.receipt["inputs"]["context"] == "test context"

    def test_convention_prompt_and_documents(self):
        @sanna_observe(on_violation="log")
        def agent(prompt: str, documents: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(prompt="test prompt", documents="test docs")

        assert result.receipt["inputs"]["query"] == "test prompt"
        assert result.receipt["inputs"]["context"] == "test docs"

    def test_single_dict_arg(self):
        @sanna_observe(on_violation="log")
        def agent(data: dict) -> str:
            return SIMPLE_OUTPUT

        result = agent({"query": "dict query", "context": "dict context"})

        assert result.receipt["inputs"]["query"] == "dict query"
        assert result.receipt["inputs"]["context"] == "dict context"


# =============================================================================
# 9. Halt severity filtering — constitution-driven
# =============================================================================

class TestHaltSeverityFiltering:
    def test_halt_only_on_critical(self):
        """C1 at warn enforcement should NOT halt."""
        @sanna_observe(require_constitution_sig=False, constitution_path=C1_WARN_ONLY)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = agent(query="refund policy", context=REFUND_CONTEXT)

        # Should NOT raise — enforcement is warn, not halt
        assert isinstance(result, SannaResult)
        sanna_warnings = [x for x in w if "Sanna" in str(x.message)]
        assert len(sanna_warnings) >= 1

    def test_halt_on_c1_halt_enforcement(self):
        """C1 at halt enforcement SHOULD halt."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError):
            agent(query="refund policy", context=REFUND_CONTEXT)

    def test_critical_failure_halts_with_constitution(self):
        """C1 critical failure halts when constitution says halt."""
        agent = make_failing_agent_with_constitution(ALL_HALT_CONST)

        with pytest.raises(SannaHaltError):
            agent(query="refund policy", context=REFUND_CONTEXT)


# =============================================================================
# 10. SannaHaltError contains valid receipt
# =============================================================================

class TestHaltErrorReceipt:
    def test_halt_receipt_passes_verification(self):
        """Receipt attached to SannaHaltError should pass verify_receipt()."""
        agent = make_failing_agent_with_constitution(ALL_HALT_CONST)

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund policy", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        vr = verify_receipt(receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"
        assert vr.exit_code == 0

    def test_halt_receipt_has_correct_status(self):
        agent = make_failing_agent_with_constitution(ALL_HALT_CONST)

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund policy", context=REFUND_CONTEXT)

        assert exc_info.value.receipt["status"] == "FAIL"

    def test_halt_receipt_has_check_evidence(self):
        agent = make_failing_agent_with_constitution(ALL_HALT_CONST)

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund policy", context=REFUND_CONTEXT)

        c1 = next(
            c for c in exc_info.value.receipt["checks"]
            if c["check_id"] == "sanna.context_contradiction"
        )
        assert not c1["passed"]
        assert c1["severity"] == "critical"
        assert c1["evidence"] is not None


# =============================================================================
# ADDITIONAL EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_invalid_on_violation_raises(self):
        with pytest.raises(ValueError, match="on_violation"):
            @sanna_observe(on_violation="invalid")
            def agent(query: str, context: str) -> str:
                return "test"

    def test_preserves_function_name(self):
        @sanna_observe(on_violation="log")
        def my_special_agent(query: str, context: str) -> str:
            return "test"

        assert my_special_agent.__name__ == "my_special_agent"

    def test_pass_receipt_also_passes_verification(self):
        """A passing receipt from the middleware should verify cleanly."""
        @sanna_observe(on_violation="log")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)

        vr = verify_receipt(result.receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"

    def test_execution_time_recorded(self):
        @sanna_observe(on_violation="log")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)

        ms = result.receipt["extensions"]["com.sanna.middleware"]["execution_time_ms"]
        assert isinstance(ms, int)
        assert ms >= 0
