"""
Sanna v0.6.0 enforcement engine test suite — 40+ tests.

Tests cover:
- Constitution engine: configure_checks with various invariant combinations
- Per-check enforcement levels: halt/warn/log per individual check
- Custom invariants: NOT_CHECKED status and handling
- Constitution-driven @sanna_observe decorator
- Three Constitutions behavior (same input, different outcomes)
- Receipt schema validation for v0.6.0 format
- Fingerprint verification with new fields
- Edge cases and error handling
"""

import json
import tempfile
import warnings
import pytest
from pathlib import Path
from dataclasses import asdict

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    TrustTiers,
    Invariant,
    load_constitution,
    parse_constitution,
    validate_constitution_data,
    compute_constitution_hash,
    sign_constitution,
    save_constitution,
    constitution_to_receipt_ref,
    constitution_to_dict,
)
from sanna.enforcement import (
    CheckConfig,
    CustomInvariantRecord,
    configure_checks,
    INVARIANT_CHECK_MAP,
)
from sanna.middleware import sanna_observe, SannaResult, SannaHaltError
from sanna.verify import verify_receipt, load_schema, verify_fingerprint
from sanna.receipt import TOOL_VERSION, CHECKS_VERSION

SCHEMA = load_schema()

# =============================================================================
# TEST PATHS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
EXAMPLE_CONSTITUTIONS_DIR = Path(__file__).parent.parent / "examples" / "constitutions"

ALL_HALT_CONST = str(CONSTITUTIONS_DIR / "all_halt.yaml")
ALL_WARN_CONST = str(CONSTITUTIONS_DIR / "all_warn.yaml")
ALL_LOG_CONST = str(CONSTITUTIONS_DIR / "all_log.yaml")
C1_C3_CONST = str(CONSTITUTIONS_DIR / "c1_c3_only.yaml")
C1_HALT_REST_LOG = str(CONSTITUTIONS_DIR / "c1_halt_rest_log.yaml")
C1_WARN_ONLY = str(CONSTITUTIONS_DIR / "c1_warn_only.yaml")
WITH_CUSTOM_CONST = str(CONSTITUTIONS_DIR / "with_custom.yaml")
NO_INVARIANTS_CONST = str(CONSTITUTIONS_DIR / "no_invariants.yaml")

# Example constitutions from the Three Constitutions Demo
# These are unsigned on disk; sign to temp files for test use.
_EXAMPLE_TMPDIR = tempfile.mkdtemp(prefix="sanna_test_examples_")

def _sign_example(name: str) -> str:
    """Load an unsigned example constitution, sign it, save to temp dir."""
    source = str(EXAMPLE_CONSTITUTIONS_DIR / f"{name}.yaml")
    const = load_constitution(source)
    signed = sign_constitution(const)
    dest = Path(_EXAMPLE_TMPDIR) / f"{name}.yaml"
    save_constitution(signed, dest)
    return str(dest)

STRICT_FINANCIAL = _sign_example("strict_financial_analyst")
PERMISSIVE_SUPPORT = _sign_example("permissive_support_agent")
RESEARCH_ASSISTANT = _sign_example("research_assistant")

# =============================================================================
# TEST DATA
# =============================================================================

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


# =============================================================================
# HELPERS
# =============================================================================

def _make_constitution_with_invariants(invariants: list[Invariant]) -> Constitution:
    """Build a minimal Constitution object with given invariants."""
    return Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="tester@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="test-approval",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        trust_tiers=TrustTiers(),
        invariants=invariants,
    )


# =============================================================================
# 1. INVARIANT_CHECK_MAP tests
# =============================================================================

class TestInvariantCheckMap:
    def test_all_five_standard_invariants_mapped(self):
        """All 5 standard invariant IDs should be in the map."""
        expected = {
            "INV_NO_FABRICATION", "INV_MARK_INFERENCE",
            "INV_NO_FALSE_CERTAINTY", "INV_PRESERVE_TENSION",
            "INV_NO_PREMATURE_COMPRESSION",
        }
        assert set(INVARIANT_CHECK_MAP.keys()) == expected

    def test_map_values_are_tuples(self):
        for inv_id, mapping in INVARIANT_CHECK_MAP.items():
            assert isinstance(mapping, tuple), f"{inv_id} mapping is not a tuple"
            assert len(mapping) == 2
            check_id, check_fn = mapping
            assert isinstance(check_id, str)
            assert callable(check_fn)

    def test_check_ids_are_namespaced(self):
        check_ids = sorted(v[0] for v in INVARIANT_CHECK_MAP.values())
        assert check_ids == [
            "sanna.conflict_collapse",
            "sanna.context_contradiction",
            "sanna.false_certainty",
            "sanna.premature_compression",
            "sanna.unmarked_inference",
        ]


# =============================================================================
# 2. configure_checks tests
# =============================================================================

class TestConfigureChecks:
    def test_all_standard_invariants(self):
        """5 standard invariants → 5 CheckConfigs, 0 custom records."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_MARK_INFERENCE", rule="Mark inferences", enforcement="warn"),
            Invariant(id="INV_NO_FALSE_CERTAINTY", rule="No false certainty", enforcement="log"),
            Invariant(id="INV_PRESERVE_TENSION", rule="Preserve tensions", enforcement="halt"),
            Invariant(id="INV_NO_PREMATURE_COMPRESSION", rule="No compression", enforcement="log"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 5
        assert len(customs) == 0

    def test_check_config_fields(self):
        """CheckConfig should have correct fields from the invariant."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="warn"),
        ])
        configs, _ = configure_checks(const)
        assert len(configs) == 1
        cfg = configs[0]
        assert cfg.check_id == "sanna.context_contradiction"
        assert cfg.enforcement_level == "warn"
        assert cfg.triggered_by == "INV_NO_FABRICATION"
        assert cfg.check_impl == "sanna.context_contradiction"
        assert callable(cfg.check_fn)

    def test_custom_invariant_becomes_record(self):
        """Custom invariant → CustomInvariantRecord with NOT_CHECKED."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_CUSTOM_NO_PII", rule="No PII", enforcement="halt"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 0
        assert len(customs) == 1
        rec = customs[0]
        assert rec.invariant_id == "INV_CUSTOM_NO_PII"
        assert rec.status == "NOT_CHECKED"
        assert rec.enforcement == "halt"
        assert "no evaluator" in rec.reason

    def test_mixed_standard_and_custom(self):
        """Mix of standard and custom invariants."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_CUSTOM_NO_PII", rule="No PII", enforcement="warn"),
            Invariant(id="INV_PRESERVE_TENSION", rule="Preserve tensions", enforcement="log"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 2
        assert len(customs) == 1
        assert configs[0].check_id == "sanna.context_contradiction"
        assert configs[1].check_id == "sanna.conflict_collapse"
        assert customs[0].invariant_id == "INV_CUSTOM_NO_PII"

    def test_no_invariants_empty_results(self):
        """Constitution with no invariants → empty configs and customs."""
        const = _make_constitution_with_invariants([])
        configs, customs = configure_checks(const)
        assert configs == []
        assert customs == []

    def test_enforcement_levels_preserved(self):
        """Each invariant's enforcement level should be preserved in config."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_MARK_INFERENCE", rule="Mark inferences", enforcement="warn"),
            Invariant(id="INV_NO_FALSE_CERTAINTY", rule="No false certainty", enforcement="log"),
        ])
        configs, _ = configure_checks(const)
        levels = {cfg.check_id: cfg.enforcement_level for cfg in configs}
        assert levels == {
            "sanna.context_contradiction": "halt",
            "sanna.unmarked_inference": "warn",
            "sanna.false_certainty": "log",
        }

    def test_single_invariant_produces_single_check(self):
        """Only one invariant → only one check runs."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 1
        assert configs[0].check_id == "sanna.context_contradiction"


# =============================================================================
# 3. Constitution loading and invariant parsing
# =============================================================================

class TestConstitutionInvariants:
    def test_load_all_halt_constitution(self):
        const = load_constitution(ALL_HALT_CONST)
        assert len(const.invariants) == 5
        for inv in const.invariants:
            assert inv.enforcement == "halt"

    def test_load_all_warn_constitution(self):
        const = load_constitution(ALL_WARN_CONST)
        assert len(const.invariants) == 5
        for inv in const.invariants:
            assert inv.enforcement == "warn"

    def test_load_c1_c3_constitution(self):
        const = load_constitution(C1_C3_CONST)
        assert len(const.invariants) == 2
        inv_ids = [inv.id for inv in const.invariants]
        assert "INV_NO_FABRICATION" in inv_ids
        assert "INV_NO_FALSE_CERTAINTY" in inv_ids

    def test_load_with_custom_invariant(self):
        const = load_constitution(WITH_CUSTOM_CONST)
        inv_ids = [inv.id for inv in const.invariants]
        assert "INV_CUSTOM_NO_PII" in inv_ids

    def test_load_no_invariants_constitution(self):
        const = load_constitution(NO_INVARIANTS_CONST)
        assert const.invariants == []

    def test_invariants_in_hash(self):
        """Changing invariants should change the constitution hash."""
        const1 = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
        ])
        const2 = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="warn"),
        ])
        hash1 = compute_constitution_hash(const1)
        hash2 = compute_constitution_hash(const2)
        assert hash1 != hash2

    def test_invariants_preserved_in_serialization(self):
        """Invariants should survive constitution_to_dict → parse round-trip."""
        const = _make_constitution_with_invariants([
            Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt"),
            Invariant(id="INV_CUSTOM_FOO", rule="Custom foo", enforcement="warn"),
        ])
        data = constitution_to_dict(const)
        assert "invariants" in data
        assert len(data["invariants"]) == 2

    def test_invariant_validation_rejects_invalid_enforcement(self):
        """Invariant with invalid enforcement should fail validation."""
        data = {
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariants": [
                {"id": "INV_NO_FABRICATION", "rule": "No fabrication", "enforcement": "invalid"},
            ],
        }
        errors = validate_constitution_data(data)
        assert any("enforcement" in e for e in errors)

    def test_invariant_validation_rejects_duplicate_ids(self):
        """Duplicate invariant IDs should fail validation."""
        data = {
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariants": [
                {"id": "INV_NO_FABRICATION", "rule": "No fabrication", "enforcement": "halt"},
                {"id": "INV_NO_FABRICATION", "rule": "Duplicate", "enforcement": "warn"},
            ],
        }
        errors = validate_constitution_data(data)
        assert any("Duplicate" in e for e in errors)


# =============================================================================
# 4. Per-check enforcement via middleware
# =============================================================================

class TestPerCheckEnforcement:
    def test_halt_enforcement_raises(self):
        """C1 at halt enforcement → SannaHaltError raised."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError):
            agent(query="refund?", context=REFUND_CONTEXT)

    def test_warn_enforcement_warns(self):
        """C1 at warn enforcement → warning emitted, no exception."""
        @sanna_observe(constitution_path=ALL_WARN_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        assert isinstance(result, SannaResult)
        sanna_warnings = [x for x in w if "Sanna" in str(x.message)]
        assert len(sanna_warnings) >= 1

    def test_log_enforcement_silent(self):
        """C1 at log enforcement → no exception, no warning."""
        @sanna_observe(constitution_path=ALL_LOG_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        assert isinstance(result, SannaResult)
        sanna_warnings = [x for x in w if "Sanna" in str(x.message)]
        assert len(sanna_warnings) == 0

    def test_mixed_enforcement_c1_halt_rest_log(self):
        """C1 at halt, rest at log → halts on C1 failure."""
        @sanna_observe(constitution_path=C1_HALT_REST_LOG)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        # Should have all 5 checks in receipt
        assert len(receipt["checks"]) == 5
        # Context contradiction check should have halt enforcement
        c1 = next(c for c in receipt["checks"] if c["check_id"] == "sanna.context_contradiction")
        assert c1["enforcement_level"] == "halt"
        assert not c1["passed"]

    def test_c1_warn_does_not_halt(self):
        """C1 at warn enforcement should NOT raise."""
        @sanna_observe(constitution_path=C1_WARN_ONLY)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        assert isinstance(result, SannaResult)
        assert result.receipt["coherence_status"] == "FAIL"


# =============================================================================
# 5. Receipt format for v0.6.0
# =============================================================================

class TestReceiptFormat:
    def test_receipt_has_triggered_by(self):
        """Each check in receipt should have triggered_by field."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        for check in result.receipt["checks"]:
            assert "triggered_by" in check
            assert check["triggered_by"].startswith("INV_")

    def test_receipt_has_enforcement_level(self):
        """Each check in receipt should have enforcement_level field."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        for check in result.receipt["checks"]:
            assert "enforcement_level" in check
            assert check["enforcement_level"] in ("halt", "warn", "log")

    def test_receipt_has_constitution_version(self):
        """Each check should have constitution_version."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        for check in result.receipt["checks"]:
            assert "constitution_version" in check

    def test_receipt_version_constants(self):
        """Receipt should use v0.6.2 version constants."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert result.receipt["tool_version"] == "0.7.0"
        assert result.receipt["checks_version"] == "4"

    def test_receipt_has_constitution_ref(self):
        """Receipt should include constitution_ref from constitution."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert result.receipt["constitution_ref"] is not None
        ref = result.receipt["constitution_ref"]
        assert "document_id" in ref
        assert "policy_hash" in ref
        assert "version" in ref
        assert "approved_by" in ref

    def test_receipt_passes_schema_validation(self):
        """Receipt from constitution-driven middleware should pass schema."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        vr = verify_receipt(result.receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"

    def test_halt_receipt_passes_schema_validation(self):
        """Halt receipt should also pass schema validation."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        vr = verify_receipt(exc_info.value.receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"


# =============================================================================
# 6. Custom invariants in receipts
# =============================================================================

class TestCustomInvariants:
    def test_custom_invariant_appears_in_receipt(self):
        """Custom invariants should appear as NOT_CHECKED in receipt."""
        @sanna_observe(constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        checks = result.receipt["checks"]
        custom = [c for c in checks if c.get("status") == "NOT_CHECKED"]
        assert len(custom) == 1
        assert custom[0]["check_id"] == "INV_CUSTOM_NO_PII"
        assert "no evaluator" in custom[0].get("reason", "")

    def test_custom_invariant_not_counted_as_failure(self):
        """Custom invariants should not count in checks_failed."""
        @sanna_observe(constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        # Custom invariant should not be in the passed/failed count
        standard = [c for c in result.receipt["checks"] if c.get("status") != "NOT_CHECKED"]
        assert result.receipt["checks_passed"] == len([c for c in standard if c["passed"]])
        assert result.receipt["checks_failed"] == len([c for c in standard if not c["passed"]])

    def test_custom_invariant_receipt_validates(self):
        """Receipt with custom invariants should pass schema validation."""
        @sanna_observe(constitution_path=WITH_CUSTOM_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        vr = verify_receipt(result.receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"


# =============================================================================
# 7. No-invariants constitution
# =============================================================================

class TestNoInvariants:
    def test_no_invariants_runs_no_checks(self):
        """Constitution with no invariants → empty checks array."""
        @sanna_observe(constitution_path=NO_INVARIANTS_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        result = agent(query="refund?", context=REFUND_CONTEXT)
        assert result.receipt["checks"] == []
        assert result.receipt["checks_passed"] == 0
        assert result.receipt["checks_failed"] == 0
        assert result.receipt["coherence_status"] == "PASS"

    def test_no_invariants_never_halts(self):
        """Without invariants, even contradictory output should not halt."""
        @sanna_observe(constitution_path=NO_INVARIANTS_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        result = agent(query="refund?", context=REFUND_CONTEXT)
        assert isinstance(result, SannaResult)
        assert result.passed

    def test_no_invariants_receipt_validates(self):
        """Receipt from no-invariants constitution should pass schema."""
        @sanna_observe(constitution_path=NO_INVARIANTS_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        vr = verify_receipt(result.receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"


# =============================================================================
# 8. Three Constitutions Demo behavior
# =============================================================================

class TestThreeConstitutions:
    """Same input, three different constitutions, three different outcomes."""

    def test_strict_halts(self):
        """Strict financial analyst: all halt → HALTED."""
        @sanna_observe(constitution_path=STRICT_FINANCIAL)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        assert receipt["coherence_status"] == "FAIL"
        assert receipt["halt_event"]["halted"] is True

    def test_permissive_warns(self):
        """Permissive support agent: warn enforcement → WARNED, not halted."""
        @sanna_observe(constitution_path=PERMISSIVE_SUPPORT)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        assert isinstance(result, SannaResult)
        assert result.receipt["coherence_status"] == "FAIL"
        assert result.receipt.get("halt_event") is None
        mw = result.receipt["extensions"]["middleware"]
        assert mw["enforcement_decision"] == "WARNED"

    def test_research_halts_on_c1(self):
        """Research assistant: C1=halt, rest=log → HALTED on C1."""
        @sanna_observe(constitution_path=RESEARCH_ASSISTANT)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        receipt = exc_info.value.receipt
        assert receipt["coherence_status"] == "FAIL"
        assert receipt["halt_event"]["halted"] is True
        # Context contradiction should be the failed halt check
        assert "sanna.context_contradiction" in receipt["halt_event"]["failed_checks"]

    def test_all_three_have_different_check_counts(self):
        """The three constitutions should run different numbers of checks."""
        strict = load_constitution(STRICT_FINANCIAL)
        permissive = load_constitution(PERMISSIVE_SUPPORT)
        research = load_constitution(RESEARCH_ASSISTANT)

        strict_configs, strict_customs = configure_checks(strict)
        perm_configs, perm_customs = configure_checks(permissive)
        res_configs, res_customs = configure_checks(research)

        assert len(strict_configs) == 5
        assert len(perm_configs) == 2
        assert len(perm_customs) == 1  # INV_CUSTOM_NO_COMPETITORS
        assert len(res_configs) == 5

    def test_same_input_different_enforcement_decisions(self):
        """Same input produces HALTED/WARNED/HALTED for the three constitutions."""
        decisions = []

        # Strict: HALTED
        @sanna_observe(constitution_path=STRICT_FINANCIAL)
        def strict_agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        try:
            strict_agent(query="refund?", context=REFUND_CONTEXT)
            decisions.append("PASSED")
        except SannaHaltError as e:
            decisions.append(e.receipt["extensions"]["middleware"]["enforcement_decision"])

        # Permissive: WARNED
        @sanna_observe(constitution_path=PERMISSIVE_SUPPORT)
        def perm_agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = perm_agent(query="refund?", context=REFUND_CONTEXT)
            decisions.append(result.receipt["extensions"]["middleware"]["enforcement_decision"])

        # Research: HALTED
        @sanna_observe(constitution_path=RESEARCH_ASSISTANT)
        def research_agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        try:
            research_agent(query="refund?", context=REFUND_CONTEXT)
            decisions.append("PASSED")
        except SannaHaltError as e:
            decisions.append(e.receipt["extensions"]["middleware"]["enforcement_decision"])

        assert decisions == ["HALTED", "WARNED", "HALTED"]


# =============================================================================
# 9. Fingerprint verification for v0.6.0 receipts
# =============================================================================

class TestFingerprintVerification:
    def test_pass_receipt_fingerprint_verifies(self):
        """Passing receipt fingerprint should verify."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        match, computed, expected = verify_fingerprint(result.receipt)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_halt_receipt_fingerprint_verifies(self):
        """Halt receipt fingerprint should verify."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        match, computed, expected = verify_fingerprint(exc_info.value.receipt)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_warn_receipt_fingerprint_verifies(self):
        """Warn receipt fingerprint should verify."""
        @sanna_observe(constitution_path=ALL_WARN_CONST)
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="refund?", context=REFUND_CONTEXT)

        match, computed, expected = verify_fingerprint(result.receipt)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_tampered_triggered_by_invalidates_fingerprint(self):
        """Modifying triggered_by after generation should fail verification."""
        @sanna_observe(constitution_path=ALL_HALT_CONST)
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt = result.receipt
        receipt["checks"][0]["triggered_by"] = "TAMPERED"
        match, _, _ = verify_fingerprint(receipt)
        assert not match


# =============================================================================
# 10. No-constitution behavior (legacy fallback)
# =============================================================================

class TestNoConstitution:
    def test_no_constitution_no_checks(self):
        """Without constitution_path, no checks run."""
        @sanna_observe(on_violation="halt")
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        result = agent(query="refund?", context=REFUND_CONTEXT)
        assert result.receipt["checks"] == []
        assert result.receipt["coherence_status"] == "PASS"

    def test_no_constitution_never_halts(self):
        """Without constitution, even bad output doesn't halt."""
        @sanna_observe(on_violation="halt")
        def agent(query: str, context: str) -> str:
            return REFUND_BAD_OUTPUT

        result = agent(query="refund?", context=REFUND_CONTEXT)
        assert isinstance(result, SannaResult)

    def test_no_constitution_receipt_validates(self):
        """No-constitution receipt should still pass schema validation."""
        @sanna_observe(on_violation="log")
        def agent(query: str, context: str) -> str:
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        vr = verify_receipt(result.receipt, SCHEMA)
        assert vr.valid, f"Receipt verification failed: {vr.errors}"


# =============================================================================
# 11. Version constants
# =============================================================================

class TestVersionConstants:
    def test_tool_version(self):
        assert TOOL_VERSION == "0.7.0"

    def test_checks_version(self):
        assert CHECKS_VERSION == "4"
