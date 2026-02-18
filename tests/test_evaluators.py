"""Tests for the custom invariant evaluator registry and integration."""

import warnings
from pathlib import Path

import pytest

from sanna.receipt import CheckResult
from sanna.evaluators import (
    register_invariant_evaluator,
    get_evaluator,
    list_evaluators,
    clear_evaluators,
)
from sanna.enforcement import (
    CheckConfig,
    CustomInvariantRecord,
    configure_checks,
)
from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    TrustTiers,
    Invariant,
    load_constitution,
    sign_constitution,
    constitution_to_dict,
)
from sanna.middleware import sanna_observe, SannaResult, SannaHaltError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear the evaluator registry before and after each test."""
    clear_evaluators()
    yield
    clear_evaluators()


CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
WITH_CUSTOM_CONST = str(CONSTITUTIONS_DIR / "with_custom.yaml")

SIMPLE_CONTEXT = "Paris is the capital of France."
SIMPLE_OUTPUT = "According to the provided context, Paris is the capital of France."


def _make_constitution(invariants):
    """Build a minimal signed Constitution object."""
    const = Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
            change_history=[],
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        trust_tiers=TrustTiers(),
        halt_conditions=[],
        invariants=invariants,
    )
    return sign_constitution(const)


def _passing_evaluator(context, output, constitution, check_config):
    return CheckResult(
        check_id=check_config["id"],
        name="Custom PII Check",
        passed=True,
        severity="info",
        details="No PII found",
    )


def _failing_evaluator(context, output, constitution, check_config):
    return CheckResult(
        check_id=check_config["id"],
        name="Custom PII Check",
        passed=False,
        severity="critical",
        details="PII detected in output",
    )


def _warning_evaluator(context, output, constitution, check_config):
    return CheckResult(
        check_id=check_config["id"],
        name="Custom Tone Check",
        passed=False,
        severity="warning",
        details="Tone slightly aggressive",
    )


def _raising_evaluator(context, output, constitution, check_config):
    raise RuntimeError("Something broke inside the evaluator")


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_register_and_get(self):
        @register_invariant_evaluator("INV_CUSTOM_FOO")
        def my_eval(ctx, out, const, cfg):
            pass

        assert get_evaluator("INV_CUSTOM_FOO") is my_eval

    def test_get_unregistered_returns_none(self):
        assert get_evaluator("INV_NONEXISTENT") is None

    def test_list_evaluators_empty(self):
        assert list_evaluators() == []

    def test_list_evaluators_with_entries(self):
        register_invariant_evaluator("INV_A")(lambda *a: None)
        register_invariant_evaluator("INV_B")(lambda *a: None)
        ids = list_evaluators()
        assert "INV_A" in ids
        assert "INV_B" in ids
        assert len(ids) == 2

    def test_clear_evaluators(self):
        register_invariant_evaluator("INV_X")(lambda *a: None)
        assert len(list_evaluators()) == 1
        clear_evaluators()
        assert list_evaluators() == []

    def test_duplicate_raises_value_error(self):
        register_invariant_evaluator("INV_DUP")(lambda *a: None)
        with pytest.raises(ValueError, match="already registered"):
            register_invariant_evaluator("INV_DUP")(lambda *a: None)

    def test_decorator_returns_original_function(self):
        def my_func(ctx, out, const, cfg):
            return "original"

        decorated = register_invariant_evaluator("INV_ORIG")(my_func)
        assert decorated is my_func


# ---------------------------------------------------------------------------
# configure_checks integration
# ---------------------------------------------------------------------------

class TestConfigureChecksIntegration:
    def test_evaluator_produces_check_config(self):
        """Registered evaluator → CheckConfig instead of CustomInvariantRecord."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_passing_evaluator)
        const = _make_constitution([
            Invariant(id="INV_CUSTOM_NO_PII", rule="No PII", enforcement="halt"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 1
        assert len(customs) == 0
        assert configs[0].check_id == "INV_CUSTOM_NO_PII"
        assert configs[0].source == "custom_evaluator"
        assert configs[0].check_impl == "custom_evaluator"

    def test_unregistered_still_not_checked(self):
        """No evaluator registered → still falls through to NOT_CHECKED."""
        const = _make_constitution([
            Invariant(id="INV_CUSTOM_UNKNOWN", rule="Mystery", enforcement="log"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 0
        assert len(customs) == 1
        assert customs[0].status == "NOT_CHECKED"

    def test_builtin_takes_precedence(self):
        """Standard INV_* IDs use built-in checks even if evaluator registered."""
        register_invariant_evaluator("INV_NO_FABRICATION")(_passing_evaluator)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 1
        assert configs[0].source == "builtin"  # Built-in took precedence

    def test_mixed_builtin_and_custom(self):
        """Built-in + custom evaluator + unregistered all coexist."""
        register_invariant_evaluator("INV_CUSTOM_PII")(_passing_evaluator)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_CUSTOM_PII", rule="No PII", enforcement="warn"),
            Invariant(id="INV_CUSTOM_UNKNOWN", rule="Mystery", enforcement="log"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 2  # built-in + custom evaluator
        assert len(customs) == 1  # unregistered
        sources = {c.check_id: c.source for c in configs}
        assert sources["sanna.context_contradiction"] == "builtin"
        assert sources["INV_CUSTOM_PII"] == "custom_evaluator"

    def test_evaluator_receives_correct_args(self):
        """Evaluator wrapper passes correct arguments."""
        captured = {}

        def capturing_evaluator(context, output, constitution, check_config):
            captured["context"] = context
            captured["output"] = output
            captured["constitution"] = constitution
            captured["check_config"] = check_config
            return CheckResult(
                check_id=check_config["id"],
                name="Capture", passed=True, severity="info",
            )

        register_invariant_evaluator("INV_CAPTURE")(capturing_evaluator)
        const = _make_constitution([
            Invariant(id="INV_CAPTURE", rule="Capture args", enforcement="log"),
        ])
        configs, _ = configure_checks(const)
        # Call the wrapper directly
        result = configs[0].check_fn("my context", "my output", enforcement="log")
        assert result.passed is True
        assert captured["context"] == "my context"
        assert captured["output"] == "my output"
        assert isinstance(captured["constitution"], dict)
        assert captured["check_config"]["id"] == "INV_CAPTURE"
        assert captured["check_config"]["rule"] == "Capture args"
        assert captured["check_config"]["enforcement"] == "log"


# ---------------------------------------------------------------------------
# Full @sanna_observe integration
# ---------------------------------------------------------------------------

class TestSannaObserveIntegration:
    def test_passing_evaluator_in_receipt(self, tmp_path):
        """Custom evaluator returning PASS appears in receipt."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_passing_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        checks = result.receipt["checks"]
        custom = [c for c in checks if c.get("check_impl") == "custom_evaluator"]
        assert len(custom) == 1
        assert custom[0]["check_id"] == "INV_CUSTOM_NO_PII"
        assert custom[0]["passed"] is True
        assert custom[0]["details"] == "No PII found"

    def test_failing_evaluator_in_receipt(self, tmp_path):
        """Custom evaluator returning FAIL appears in receipt."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_failing_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        # INV_CUSTOM_NO_PII has enforcement=halt in with_custom.yaml
        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="test", context=SIMPLE_CONTEXT)
        receipt = exc_info.value.receipt
        custom = [c for c in receipt["checks"] if c.get("check_impl") == "custom_evaluator"]
        assert len(custom) == 1
        assert custom[0]["passed"] is False
        assert custom[0]["severity"] == "critical"

    def test_warning_evaluator_in_receipt(self):
        """Custom evaluator returning WARNING (severity=warning) triggers warn."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_warning_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        # INV_CUSTOM_NO_PII has enforcement=halt → severity=warning + halt level = halted
        with pytest.raises(SannaHaltError):
            agent(query="test", context=SIMPLE_CONTEXT)

    def test_errored_evaluator_fail_open(self):
        """fail_open: exception produces ERRORED status, passed=True."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_raising_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST, error_policy="fail_open")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        checks = result.receipt["checks"]
        errored = [c for c in checks if c.get("status") == "ERRORED"]
        assert len(errored) == 1
        assert errored[0]["check_id"] == "INV_CUSTOM_NO_PII"
        assert "Something broke" in errored[0]["details"]
        assert errored[0]["check_impl"] == "custom_evaluator"

    def test_errored_fail_open_does_not_halt(self):
        """fail_open: ERRORED evaluator doesn't halt even with halt enforcement."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_raising_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST, error_policy="fail_open")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        checks = result.receipt["checks"]
        # Built-in checks should still have run
        builtin = [c for c in checks if c.get("check_impl") != "custom_evaluator" and c.get("status") != "ERRORED"]
        assert len(builtin) >= 2  # INV_NO_FABRICATION + INV_PRESERVE_TENSION

    def test_errored_fail_open_not_counted_as_failure(self):
        """fail_open: ERRORED checks should not count in checks_failed."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_raising_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST, error_policy="fail_open")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        # ERRORED is like NOT_CHECKED — not counted as failure
        standard = [
            c for c in result.receipt["checks"]
            if c.get("status") not in ("NOT_CHECKED", "ERRORED")
        ]
        assert result.receipt["checks_failed"] == len([c for c in standard if not c["passed"]])

    def test_errored_fail_closed_halts(self):
        """fail_closed (default): evaluator error → halt enforcement fires."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_raising_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        with pytest.raises(SannaHaltError):
            agent(query="test", context=SIMPLE_CONTEXT)

    def test_errored_fail_closed_produces_failed_status(self):
        """fail_closed: evaluator error → FAILED status, passed=False in halt receipt."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_raising_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="test", context=SIMPLE_CONTEXT)

        receipt = exc_info.value.receipt
        checks = receipt["checks"]
        failed_custom = [c for c in checks if c["check_id"] == "INV_CUSTOM_NO_PII"]
        assert len(failed_custom) == 1
        assert failed_custom[0]["passed"] is False
        assert failed_custom[0]["status"] == "FAILED"
        assert "fail_closed" in failed_custom[0]["details"]

    def test_default_error_policy_is_fail_closed(self):
        """The default error_policy should be fail_closed."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_raising_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        # Default is fail_closed → halt enforcement fires for errored evaluator
        with pytest.raises(SannaHaltError):
            agent(query="test", context=SIMPLE_CONTEXT)

    def test_custom_evaluator_replayable_false(self):
        """Custom evaluator results should have replayable=False."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_passing_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        custom = [c for c in result.receipt["checks"] if c.get("check_impl") == "custom_evaluator"]
        assert custom[0]["replayable"] is False

    def test_builtin_checks_still_replayable(self):
        """Built-in checks should still be replayable=True."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_passing_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        builtin = [
            c for c in result.receipt["checks"]
            if c.get("check_impl") != "custom_evaluator" and c.get("status") not in ("NOT_CHECKED", "ERRORED")
        ]
        assert all(c["replayable"] is True for c in builtin)


# ---------------------------------------------------------------------------
# Multiple custom evaluators
# ---------------------------------------------------------------------------

class TestMultipleEvaluators:
    def test_two_custom_evaluators(self):
        """Two custom evaluators for different invariants both run."""
        register_invariant_evaluator("INV_A")(_passing_evaluator)
        register_invariant_evaluator("INV_B")(_failing_evaluator)

        const = _make_constitution([
            Invariant(id="INV_A", rule="Check A", enforcement="log"),
            Invariant(id="INV_B", rule="Check B", enforcement="log"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 2
        assert len(customs) == 0
        assert all(c.source == "custom_evaluator" for c in configs)

    def test_evaluator_plus_builtin_plus_not_checked(self):
        """All three types coexist in one receipt."""
        register_invariant_evaluator("INV_CUSTOM_NO_PII")(_passing_evaluator)

        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        checks = result.receipt["checks"]
        sources = set()
        for c in checks:
            if c.get("check_impl") == "custom_evaluator":
                sources.add("custom")
            elif c.get("status") == "NOT_CHECKED":
                sources.add("not_checked")
            else:
                sources.add("builtin")
        # with_custom.yaml has: INV_NO_FABRICATION (builtin), INV_PRESERVE_TENSION (builtin),
        # INV_CUSTOM_NO_PII (now custom evaluator). All should be present.
        assert "custom" in sources
        assert "builtin" in sources


# ---------------------------------------------------------------------------
# Type validation
# ---------------------------------------------------------------------------

class TestTypeValidation:
    def test_wrong_return_type_produces_errored(self):
        """Evaluator returning non-CheckResult → ERRORED."""
        def bad_evaluator(ctx, out, const, cfg):
            return {"passed": True}  # dict, not CheckResult

        register_invariant_evaluator("INV_BAD")(bad_evaluator)
        const = _make_constitution([
            Invariant(id="INV_BAD", rule="Bad return", enforcement="log"),
        ])
        configs, _ = configure_checks(const)
        # The wrapper should raise TypeError, caught by middleware
        with pytest.raises(TypeError, match="must return CheckResult"):
            configs[0].check_fn("ctx", "out", enforcement="log")
