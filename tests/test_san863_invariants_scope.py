"""SAN-863: invariants_scope must be DERIVED from observed execution, never
supplied by the party being assured.

Before this fix, the receipt-generation functions in middleware.py defaulted
invariants_scope to "full" and emitted whatever value the caller passed
unchanged — while the SDK already computed, and discarded, the list of
invariants that did NOT run. A caller-declared "full" was cryptographically
signed even when a declared invariant never executed.

Ground truth for the fix: coverage is judged against the invariants DECLARED
in the constitution, not against whatever happened to land in check_results.
An invariant dropped before ever producing a check entry must still make
coverage "limited". The join key is `triggered_by` (set to the originating
invariant ID on every check_results entry, both for configured checks and
for NOT_CHECKED custom records) — never `check_id` (which is the check
implementation ID, e.g. "sanna.context_contradiction", not the invariant
ID) and never `passed` (an ERRORED entry has passed=True; only `status`
distinguishes evaluated from non-evaluated).
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from sanna.crypto import generate_keypair, verify_receipt_signature
from sanna.enforcement import CheckConfig, CustomInvariantRecord
from sanna.middleware import (
    SannaHaltError,
    _generate_constitution_receipt,
    _generate_no_invariants_receipt,
    sanna_observe,
)
from sanna.receipt import check_c1_context_contradiction
from sanna.verify import verify_fingerprint, verify_receipt, load_schema

SCHEMA = load_schema()

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
ALL_HALT_CONST = str(CONSTITUTIONS_DIR / "all_halt.yaml")
WITH_CUSTOM_CONST = str(CONSTITUTIONS_DIR / "with_custom.yaml")
NO_INVARIANTS_CONST = str(CONSTITUTIONS_DIR / "no_invariants.yaml")

SIMPLE_CONTEXT = "Paris is the capital of France."
SIMPLE_OUTPUT = "The capital of France is Paris."


def make_trace(correlation_id="san863-corr"):
    return {
        "correlation_id": correlation_id,
        "name": "test",
        "input": {"query": "test query"},
        "output": {"final_answer": "test response"},
        "metadata": {},
        "observations": [],
    }


# =============================================================================
# End-to-end via @sanna_observe (the flagship path the defect was found on)
# =============================================================================

class TestFlagshipPathDerivation:
    def test_unclassified_custom_invariant_gives_limited(self):
        """with_custom.yaml declares INV_CUSTOM_NO_PII with no registered
        evaluator -> it lands in custom_records (status=NOT_CHECKED), never
        executes. invariants_scope must be "limited", not "full", and the
        extensions object must describe exactly which invariant was skipped
        and why."""
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        receipt = result.receipt
        assert receipt["invariants_scope"] == "limited"
        assert receipt["invariants_scope"] != "full"

        cov = receipt["extensions"]["com.sanna.coverage"]
        assert cov["invariants_declared"] == 3
        assert cov["invariants_executed"] == 2
        assert cov["skipped"] == [
            {"id": "INV_CUSTOM_NO_PII", "reason": "NOT_CHECKED"},
        ]

        # Status derivation is unaffected (spec 2.16.3: full/limited derive
        # status from check results as normal; only authority_only/none use
        # the alternate enforcement.action mapping).
        assert receipt["status"] == "PARTIAL"

    def test_all_declared_invariants_execute_gives_full(self):
        """all_halt.yaml's 5 invariants all map to INVARIANT_CHECK_MAP and
        all execute -> "full", with no coverage extension emitted."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt = result.receipt
        assert receipt["invariants_scope"] == "full"
        assert "com.sanna.coverage" not in receipt["extensions"]

    def test_zero_invariants_constitution_observed_scope(self):
        """Constitution declares zero invariants. Documents (does not
        prescribe) the current no-invariants-path behavior per SAN-863
        scope note: do not change its semantics here."""
        @sanna_observe(require_constitution_sig=False, constitution_path=NO_INVARIANTS_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt = result.receipt
        # Observed value: "full" (vacuously true -- zero declared, zero
        # missing). Flagged in the SAN-863 report per ticket instruction;
        # whether "none" would be more correct is a separate decision.
        assert receipt["invariants_scope"] == "full"
        assert "com.sanna.coverage" not in receipt["extensions"]


# =============================================================================
# Direct-function tests: caller-declared scope handling
# =============================================================================

class TestCallerDeclaredScopeHandling:
    def test_explicit_full_downgraded_when_not_checked(self):
        """A caller explicitly passing invariants_scope="full" is downgraded
        to "limited" when a declared invariant did not execute -- proving
        the caller's claim is never honored as-is, only ever lowered."""
        custom = CustomInvariantRecord(
            invariant_id="INV_CUSTOM_X",
            rule="Some custom rule.",
            enforcement="warn",
        )
        receipt = _generate_constitution_receipt(
            make_trace("san863-explicit-full-downgrade"),
            check_configs=[],
            custom_records=[custom],
            constitution_ref=None,
            constitution_version="1.0",
            invariants_scope="full",
            declared_invariant_ids=["INV_CUSTOM_X"],
        )
        assert receipt["invariants_scope"] == "limited"
        cov = receipt["extensions"]["com.sanna.coverage"]
        assert cov["skipped"] == [{"id": "INV_CUSTOM_X", "reason": "NOT_CHECKED"}]

    def test_authority_only_never_upgraded_or_downgraded(self):
        """A caller passing "authority_only" is honored unchanged, even
        though check coverage is incomplete -- it is never upgraded to
        "full"/"limited" and never further downgraded."""
        custom = CustomInvariantRecord(
            invariant_id="INV_CUSTOM_X",
            rule="Some custom rule.",
            enforcement="warn",
        )
        receipt = _generate_constitution_receipt(
            make_trace("san863-authority-only"),
            check_configs=[],
            custom_records=[custom],
            constitution_ref=None,
            constitution_version="1.0",
            invariants_scope="authority_only",
            declared_invariant_ids=["INV_CUSTOM_X"],
        )
        assert receipt["invariants_scope"] == "authority_only"
        assert "com.sanna.coverage" not in receipt["extensions"]

    def test_none_scope_never_upgraded_or_downgraded(self):
        """Same as authority_only: "none" is a caller-asserted floor for
        pure authority-decision records and must not be re-derived."""
        receipt = _generate_no_invariants_receipt(
            make_trace("san863-none-scope"),
            constitution_ref=None,
            invariants_scope="none",
            declared_invariant_ids=["INV_SOMETHING"],
        )
        assert receipt["invariants_scope"] == "none"
        assert "com.sanna.coverage" not in receipt["extensions"]


# =============================================================================
# The case a naive "not_evaluated" derivation would miss
# =============================================================================

class TestDroppedInvariant:
    def test_dropped_invariant_never_reaching_check_results_gives_limited(self):
        """An invariant declared in the constitution but that never
        produced ANY check_results entry (dropped upstream of
        configure_checks, e.g. by a future bug) must still downgrade scope
        to "limited" with reason="DROPPED". A derivation keyed only off
        check_results' own NOT_CHECKED entries would miss this -- it must
        be judged against the constitution's declared invariant IDs."""
        receipt = _generate_constitution_receipt(
            make_trace("san863-dropped"),
            check_configs=[],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0",
            declared_invariant_ids=["INV_DROPPED"],
        )
        assert receipt["invariants_scope"] == "limited"
        cov = receipt["extensions"]["com.sanna.coverage"]
        assert cov["invariants_declared"] == 1
        assert cov["invariants_executed"] == 0
        assert cov["skipped"] == [{"id": "INV_DROPPED", "reason": "DROPPED"}]

    def test_errored_custom_evaluator_reason_is_errored_not_dropped(self):
        """A custom evaluator that raises under fail_open produces a
        status=ERRORED check_results entry (SAN-863 explicitly leaves that
        fail-open behavior untouched -- separate P0 ticket). The coverage
        extension must report reason="ERRORED" for it, distinguishing an
        entry that WAS attempted-but-errored from one that was DROPPED
        (never attempted at all) or NOT_CHECKED (no evaluator registered)."""
        def _raising_evaluator(context, output, enforcement="log", **kwargs):
            raise RuntimeError("boom")

        cfg = CheckConfig(
            check_id="INV_CUSTOM_ERR",
            check_fn=_raising_evaluator,
            enforcement_level="warn",
            triggered_by="INV_CUSTOM_ERR",
            check_impl="custom_evaluator",
            source="custom_evaluator",
        )
        receipt = _generate_constitution_receipt(
            make_trace("san863-errored"),
            check_configs=[cfg],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0",
            error_policy="fail_open",
            declared_invariant_ids=["INV_CUSTOM_ERR"],
        )
        assert receipt["invariants_scope"] == "limited"
        cov = receipt["extensions"]["com.sanna.coverage"]
        assert cov["skipped"] == [{"id": "INV_CUSTOM_ERR", "reason": "ERRORED"}]

    def test_passed_key_is_never_used_for_derivation(self):
        """An ERRORED entry has passed=True (fail-open, middleware.py
        ~436-451) -- if derivation keyed off `passed` instead of `status`
        it would silently treat this as executed. This test locks the
        actual behavior: it must still count as skipped."""
        def _raising_evaluator(context, output, enforcement="log", **kwargs):
            raise RuntimeError("boom")

        cfg = CheckConfig(
            check_id="INV_ERR_PASSED_TRUE",
            check_fn=_raising_evaluator,
            enforcement_level="log",
            triggered_by="INV_ERR_PASSED_TRUE",
            check_impl="custom_evaluator",
            source="custom_evaluator",
        )
        receipt = _generate_constitution_receipt(
            make_trace("san863-passed-true-errored"),
            check_configs=[cfg],
            custom_records=[],
            constitution_ref=None,
            constitution_version="1.0",
            error_policy="fail_open",
            declared_invariant_ids=["INV_ERR_PASSED_TRUE"],
        )
        errored_entry = next(
            c for c in receipt["checks"] if c.get("triggered_by") == "INV_ERR_PASSED_TRUE"
        )
        assert errored_entry["passed"] is True  # confirms the fail-open contract
        assert errored_entry["status"] == "ERRORED"
        assert receipt["invariants_scope"] == "limited"


# =============================================================================
# Negative control: no path can emit "full" when missing is non-empty
# =============================================================================

class TestNegativeControlNeverFullWhenMissing:
    @pytest.mark.parametrize("requested_scope", [None, "full"])
    def test_constitution_receipt_never_full_when_missing(self, requested_scope):
        custom = CustomInvariantRecord(
            invariant_id="INV_GAP", rule="x", enforcement="log",
        )
        receipt = _generate_constitution_receipt(
            make_trace(f"san863-negctrl-{requested_scope}"),
            check_configs=[],
            custom_records=[custom],
            constitution_ref=None,
            constitution_version="1.0",
            invariants_scope=requested_scope,
            declared_invariant_ids=["INV_GAP"],
        )
        assert receipt["invariants_scope"] != "full"
        assert receipt["invariants_scope"] == "limited"

    def test_flagship_decorator_never_full_when_missing(self):
        """End-to-end: the @sanna_observe path (no way for a caller to
        inject invariants_scope at all) must never emit "full" for a
        constitution with unexecuted declared invariants."""
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        assert result.receipt["invariants_scope"] != "full"


# =============================================================================
# Self-consistency: fingerprint sequencing must be correct
# =============================================================================

class TestFingerprintSelfConsistency:
    """The derived invariants_scope and coverage extension MUST be present
    in the receipt dict BEFORE fingerprints are computed. If either were
    set after fingerprint computation, the receipt's stated fingerprint
    would not cover its own content and the self-consistency checks below
    would fail."""

    def test_full_case_fingerprint_and_signature_self_consistent(self, tmp_path):
        priv, pub = generate_keypair(tmp_path, signed_by="test-signer")

        @sanna_observe(
            require_constitution_sig=False,
            constitution_path=ALL_HALT_CONST,
            private_key_path=str(priv),
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt = result.receipt
        assert receipt["invariants_scope"] == "full"

        match, computed, expected = verify_fingerprint(receipt)
        assert match, f"fingerprint mismatch: computed={computed} expected={expected}"
        assert verify_receipt_signature(receipt, str(pub))

        vr = verify_receipt(receipt, SCHEMA)
        assert vr.valid, f"schema validation failed: {vr.errors}"

    def test_limited_case_fingerprint_and_signature_self_consistent(self, tmp_path):
        priv, pub = generate_keypair(tmp_path, signed_by="test-signer")

        @sanna_observe(
            require_constitution_sig=False,
            constitution_path=WITH_CUSTOM_CONST,
            private_key_path=str(priv),
        )
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        receipt = result.receipt
        assert receipt["invariants_scope"] == "limited"
        assert "com.sanna.coverage" in receipt["extensions"]

        match, computed, expected = verify_fingerprint(receipt)
        assert match, f"fingerprint mismatch: computed={computed} expected={expected}"
        assert verify_receipt_signature(receipt, str(pub))

        vr = verify_receipt(receipt, SCHEMA)
        assert vr.valid, f"schema validation failed: {vr.errors}"

    def test_direct_call_limited_fingerprint_self_consistent(self):
        """Same guarantee via the lower-level function directly (covers
        gateway/mcp/interceptor callers that invoke
        _generate_constitution_receipt without the decorator)."""
        custom = CustomInvariantRecord(
            invariant_id="INV_CUSTOM_X", rule="x", enforcement="warn",
        )
        cfg = CheckConfig(
            check_id="sanna.context_contradiction",
            check_fn=check_c1_context_contradiction,
            enforcement_level="warn",
            triggered_by="INV_NO_FABRICATION",
            check_impl="sanna.context_contradiction",
        )
        receipt = _generate_constitution_receipt(
            make_trace("san863-direct-limited-fp"),
            check_configs=[cfg],
            custom_records=[custom],
            constitution_ref=None,
            constitution_version="1.0",
            declared_invariant_ids=["INV_NO_FABRICATION", "INV_CUSTOM_X"],
        )
        assert receipt["invariants_scope"] == "limited"
        match, computed, expected = verify_fingerprint(receipt)
        assert match, f"fingerprint mismatch: computed={computed} expected={expected}"
