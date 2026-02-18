"""
Sanna v0.6.3 test suite — Constitution Integrity + Cryptographic Provenance.

60+ new tests covering:
- Constitution integrity (hash verification, unsigned rejection)
- C4 substring fix ("can"/"cannot" word boundary)
- C5 bullet-point fix (hyphens in words don't count)
- Ed25519 keygen, constitution signing, verification
- Receipt signing and verification
- Provenance bond (receipt → constitution)
- Stable check IDs (sanna.* namespace, CHECK_REGISTRY, check field)
- check_impl field in receipts
- Replayable flag
- PARTIAL status and evaluation_coverage
- Scaffold invariants
- Constitution schema validation
"""

import json
import tempfile
import warnings
from pathlib import Path

import pytest
import yaml

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    TrustTiers,
    Invariant,
    SannaConstitutionError,
    load_constitution,
    sign_constitution,
    save_constitution,
    compute_constitution_hash,
    constitution_to_receipt_ref,
    scaffold_constitution,
    parse_constitution,
)
from sanna.enforcement import (
    CheckConfig,
    CustomInvariantRecord,
    configure_checks,
    INVARIANT_CHECK_MAP,
    CHECK_REGISTRY,
)
from sanna.enforcement.constitution_engine import _LEGACY_CHECK_ALIASES
from sanna.middleware import sanna_observe, SannaResult, SannaHaltError
from sanna.receipt import (
    check_c1_context_contradiction,
    check_c4_conflict_collapse,
    check_c5_premature_compression,
    TOOL_VERSION,
    CHECKS_VERSION,
)
from sanna.verify import verify_receipt, load_schema, verify_fingerprint
from sanna.crypto import (
    generate_keypair,
    sign_constitution_full,
    verify_constitution_full,
    sign_receipt,
    verify_receipt_signature,
    load_private_key,
    load_public_key,
    compute_key_id,
)

SCHEMA = load_schema()

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
ALL_HALT_CONST = str(CONSTITUTIONS_DIR / "all_halt.yaml")
WITH_CUSTOM_CONST = str(CONSTITUTIONS_DIR / "with_custom.yaml")
NO_INVARIANTS_CONST = str(CONSTITUTIONS_DIR / "no_invariants.yaml")

SIMPLE_CONTEXT = "Paris is the capital of France."
SIMPLE_OUTPUT = "The capital of France is Paris."

REFUND_CONTEXT = (
    "Our refund policy: Physical products can be returned within 30 days. "
    "Digital products are non-refundable once downloaded."
)
REFUND_BAD_OUTPUT = (
    "Based on your purchase history, you are eligible to request a refund."
)


def _make_constitution(invariants=None):
    return Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="t@t.com", approved_by=["a@t.com"],
            approval_date="2026-01-01", approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        invariants=invariants or [],
    )


def _signed_constitution_path(tmp_path, invariants=None, **kwargs):
    """Create a signed constitution YAML in tmp_path and return its path."""
    const = _make_constitution(invariants)
    tmp_path.mkdir(parents=True, exist_ok=True)
    if "private_key_path" not in kwargs:
        priv_path, _ = generate_keypair(tmp_path / "keys")
        kwargs["private_key_path"] = str(priv_path)
        kwargs.setdefault("signed_by", "test-signer")
    signed = sign_constitution(const, **kwargs)
    path = tmp_path / "constitution.yaml"
    save_constitution(signed, path)
    return str(path)


# =============================================================================
# 1. Constitution Integrity
# =============================================================================

class TestConstitutionIntegrity:
    def test_load_signed_constitution_verifies_hash(self, tmp_path):
        """Loading a signed constitution should verify its hash."""
        path = _signed_constitution_path(tmp_path, [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        const = load_constitution(path)
        assert const.policy_hash is not None

    def test_tampered_constitution_raises(self, tmp_path):
        """Modifying a signed constitution should raise SannaConstitutionError."""
        path = _signed_constitution_path(tmp_path, [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        # Tamper with the file
        with open(path) as f:
            data = yaml.safe_load(f)
        data["identity"]["agent_name"] = "tampered-agent"
        with open(path, "w") as f:
            yaml.dump(data, f)

        with pytest.raises(SannaConstitutionError, match="hash mismatch"):
            load_constitution(path)

    def test_unsigned_constitution_loads_ok(self, tmp_path):
        """Unsigned constitution (null hash) should load without error."""
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        path = tmp_path / "unsigned.yaml"
        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "t@t.com", "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01", "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariants": [{"id": "INV_NO_FABRICATION", "rule": "test", "enforcement": "halt"}],
            "policy_hash": None,
        }
        with open(path, "w") as f:
            yaml.dump(data, f)
        loaded = load_constitution(path)
        assert loaded.policy_hash is None

    def test_unsigned_constitution_rejected_by_middleware(self, tmp_path):
        """Middleware should reject unsigned constitutions."""
        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "t@t.com", "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01", "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariants": [{"id": "INV_NO_FABRICATION", "rule": "test", "enforcement": "halt"}],
            "policy_hash": None,
        }
        path = tmp_path / "unsigned.yaml"
        with open(path, "w") as f:
            yaml.dump(data, f)

        with pytest.raises(SannaConstitutionError, match="not signed"):
            @sanna_observe(require_constitution_sig=False, constitution_path=str(path))
            def agent(query, context):
                return "test"


# =============================================================================
# 2. C4 Substring Fix
# =============================================================================

class TestC4SubstringFix:
    def test_cannot_does_not_trigger_permissive(self):
        """'cannot' should not match as 'can' (word boundary fix)."""
        context = "You cannot return digital products. They are non-refundable."
        output = "The product is non-refundable."
        result = check_c4_conflict_collapse(context, output)
        # "cannot" is only restrictive, not permissive — should pass
        assert result.passed, f"C4 should pass (no tension): {result.evidence}"

    def test_can_and_cannot_both_present_detects_tension(self):
        """When both 'can' and 'cannot' are present, tension should be detected."""
        context = "You can return physical products. You cannot return digital products."
        output = "The product is non-refundable."  # Doesn't acknowledge tension
        result = check_c4_conflict_collapse(context, output)
        assert not result.passed, "C4 should fail: conflicting 'can'/'cannot' not acknowledged"

    def test_eligible_and_prohibited_detected(self):
        """'eligible' and 'prohibited' should still be detected."""
        context = "You are eligible for a refund. However, returns are prohibited after 30 days."
        output = "You can get a refund."
        result = check_c4_conflict_collapse(context, output)
        assert not result.passed

    def test_no_conflict_passes(self):
        """Context without conflicting terms should pass."""
        context = "Paris is the capital of France."
        output = "The capital of France is Paris."
        result = check_c4_conflict_collapse(context, output)
        assert result.passed


# =============================================================================
# 3. C5 Bullet Fix
# =============================================================================

class TestC5BulletFix:
    def test_hyphens_in_words_not_counted_as_bullets(self):
        """Hyphens in 'non-refundable' should not count as bullet points."""
        context = "Digital products are non-refundable. State-of-the-art technology."
        output = "Products are non-refundable."
        result = check_c5_premature_compression(context, output)
        # No bullet points, just 2 sentences — should pass
        assert result.passed, f"C5 should pass: {result.evidence}"

    def test_actual_bullets_still_counted(self):
        """Real bullet-point lists should still be detected."""
        context = "- Item one\n- Item two\n- Item three\n- Item four"
        output = "Yes."
        result = check_c5_premature_compression(context, output)
        # 4 bullet points compressed to 1 sentence — should fail
        assert not result.passed

    def test_bullet_points_with_dots(self):
        """Dot-style lists should be detected."""
        context = "Policy A applies. Policy B applies. Policy C applies. Policy D applies."
        output = "OK."
        result = check_c5_premature_compression(context, output)
        assert not result.passed


# =============================================================================
# 4. Ed25519 Keygen
# =============================================================================

class TestEd25519Keygen:
    def test_generate_keypair_creates_files(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        assert priv_path.exists()
        assert pub_path.exists()
        assert priv_path.suffix == ".key"
        assert pub_path.suffix == ".pub"
        # Filenames are key_id-based (64-char hex stem)
        assert len(priv_path.stem) == 64
        assert priv_path.stem == pub_path.stem

    def test_load_generated_keys(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        priv = load_private_key(priv_path)
        pub = load_public_key(pub_path)
        assert priv is not None
        assert pub is not None

    def test_key_id_is_64_hex(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        pub = load_public_key(pub_path)
        kid = compute_key_id(pub)
        assert len(kid) == 64
        assert all(c in "0123456789abcdef" for c in kid)

    def test_key_id_deterministic(self, tmp_path):
        """Same key should produce same key_id."""
        priv_path, pub_path = generate_keypair(tmp_path)
        pub = load_public_key(pub_path)
        assert compute_key_id(pub) == compute_key_id(pub)


# =============================================================================
# 5. Ed25519 Constitution Signing
# =============================================================================

class TestEd25519ConstitutionSigning:
    def test_sign_constitution_with_key(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="test@test.com")
        assert signed.provenance.signature.value is not None
        assert signed.provenance.signature.key_id is not None
        assert signed.provenance.signature.signed_by == "test@test.com"

    def test_verify_constitution_signature_valid(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path))
        valid = verify_constitution_full(signed, str(pub_path))
        assert valid

    def test_tampered_constitution_fails_full_verification(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path))
        # Tamper: change agent name after signing
        from sanna.constitution import Constitution, Provenance, AgentIdentity
        tampered = Constitution(
            schema_version=signed.schema_version,
            identity=AgentIdentity(agent_name="tampered-agent", domain="testing"),
            provenance=signed.provenance,
            boundaries=signed.boundaries,
            invariants=signed.invariants,
            policy_hash=signed.policy_hash,
        )
        valid = verify_constitution_full(tampered, str(pub_path))
        assert not valid

    def test_wrong_key_fails_verification(self, tmp_path):
        priv_path1, pub_path1 = generate_keypair(tmp_path / "keys1")
        _, pub_path2 = generate_keypair(tmp_path / "keys2")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path1))
        valid = verify_constitution_full(signed, str(pub_path2))
        assert not valid

    def test_constitution_ref_includes_signature_fields(self, tmp_path):
        priv_path, _ = generate_keypair(tmp_path)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="signer@co.com")
        ref = constitution_to_receipt_ref(signed)
        assert "signature" in ref
        assert "key_id" in ref
        assert "signed_by" in ref

    def test_unsigned_constitution_ref_has_no_signature(self):
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const)  # hash-only, no Ed25519
        ref = constitution_to_receipt_ref(signed)
        assert "signature" not in ref


# =============================================================================
# 6. Receipt Signing
# =============================================================================

class TestReceiptSigning:
    def test_sign_and_verify_receipt(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        signed = sign_receipt(result.receipt, str(priv_path), signed_by="signer@co.com")
        assert "receipt_signature" in signed
        assert signed["receipt_signature"]["signed_by"] == "signer@co.com"

        valid = verify_receipt_signature(signed, str(pub_path))
        assert valid

    def test_tampered_receipt_fails_verification(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        signed = sign_receipt(result.receipt, str(priv_path))

        # Tamper
        signed["status"] = "FAIL"
        valid = verify_receipt_signature(signed, str(pub_path))
        assert not valid

    def test_middleware_private_key_signs_receipt(self, tmp_path):
        priv_path, pub_path = generate_keypair(tmp_path)
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path, private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert "receipt_signature" in result.receipt
        valid = verify_receipt_signature(result.receipt, str(pub_path))
        assert valid


# =============================================================================
# 7. Provenance Bond
# =============================================================================

class TestProvenanceBond:
    def test_receipt_signature_covers_constitution_ref(self, tmp_path):
        """Tampering with constitution_ref should invalidate receipt signature."""
        priv_path, pub_path = generate_keypair(tmp_path)
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path, private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt = result.receipt

        # Tamper with constitution_ref
        receipt["constitution_ref"]["policy_hash"] = "a" * 64
        valid = verify_receipt_signature(receipt, str(pub_path))
        assert not valid

    def test_verifier_checks_receipt_signature(self, tmp_path):
        """verify_receipt with public_key_path should check receipt signature."""
        priv_path, pub_path = generate_keypair(tmp_path)
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path, private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        vr = verify_receipt(result.receipt, SCHEMA, public_key_path=str(pub_path))
        assert vr.valid, f"Verification failed: {vr.errors}"


# =============================================================================
# 8. Stable Check IDs
# =============================================================================

class TestStableCheckIDs:
    def test_check_registry_has_five_entries(self):
        assert len(CHECK_REGISTRY) == 5

    def test_check_registry_keys_are_namespaced(self):
        for key in CHECK_REGISTRY:
            assert key.startswith("sanna."), f"Key {key} not namespaced"

    def test_legacy_aliases_map_to_registry(self):
        for legacy, namespaced in _LEGACY_CHECK_ALIASES.items():
            assert namespaced in CHECK_REGISTRY

    def test_invariant_check_map_uses_namespaced_ids(self):
        for inv_id, (check_impl, check_fn) in INVARIANT_CHECK_MAP.items():
            assert check_impl.startswith("sanna."), f"{inv_id} maps to non-namespaced {check_impl}"

    def test_check_field_on_invariant_overrides_default(self, tmp_path):
        """Invariant with check: field should use that check instead of default."""
        const = _make_constitution([
            Invariant(id="INV_CUSTOM_MY_CHECK", rule="test", enforcement="halt",
                      check="sanna.context_contradiction"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 1
        assert len(customs) == 0
        assert configs[0].check_impl == "sanna.context_contradiction"
        assert configs[0].triggered_by == "INV_CUSTOM_MY_CHECK"

    def test_check_field_with_unknown_check_becomes_custom(self):
        """Invariant with unknown check: field should become NOT_CHECKED."""
        const = _make_constitution([
            Invariant(id="INV_CUSTOM_FOO", rule="test", enforcement="halt",
                      check="sanna.nonexistent"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 0
        assert len(customs) == 1
        assert "not found" in customs[0].reason.lower()

    def test_check_field_legacy_alias(self):
        """check: 'C1' should resolve via legacy alias."""
        const = _make_constitution([
            Invariant(id="INV_CUSTOM_ALIAS", rule="test", enforcement="warn",
                      check="C1"),
        ])
        configs, customs = configure_checks(const)
        assert len(configs) == 1
        assert configs[0].check_impl == "sanna.context_contradiction"


# =============================================================================
# 9. check_impl in Receipts
# =============================================================================

class TestCheckImpl:
    def test_standard_check_has_check_impl(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        for check in result.receipt["checks"]:
            assert "check_impl" in check
            assert check["check_impl"].startswith("sanna.")

    def test_custom_check_has_null_check_impl(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        customs = [c for c in result.receipt["checks"] if c.get("status") == "NOT_CHECKED"]
        for c in customs:
            assert c["check_impl"] is None


# =============================================================================
# 10. Replayable Flag
# =============================================================================

class TestReplayable:
    def test_builtin_checks_are_replayable(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        for check in result.receipt["checks"]:
            assert check.get("replayable") is True

    def test_custom_invariants_are_not_replayable(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        customs = [c for c in result.receipt["checks"] if c.get("status") == "NOT_CHECKED"]
        for c in customs:
            assert c.get("replayable") is False


# =============================================================================
# 11. PARTIAL Status
# =============================================================================

class TestPartialStatus:
    def test_partial_when_not_checked_and_all_pass(self):
        """PARTIAL when all evaluated checks pass but some are NOT_CHECKED."""
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        assert result.receipt["status"] == "PARTIAL"

    def test_fail_overrides_partial(self):
        """FAIL takes priority over PARTIAL — halt enforcement raises SannaHaltError."""
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return REFUND_BAD_OUTPUT

        with pytest.raises(SannaHaltError) as exc_info:
            agent(query="refund?", context=REFUND_CONTEXT)

        # The receipt from the halt should show FAIL, not PARTIAL
        assert exc_info.value.receipt["status"] == "FAIL"

    def test_no_custom_invariants_gives_pass(self):
        """Without NOT_CHECKED invariants, status is PASS."""
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert result.receipt["status"] == "PASS"

    def test_partial_receipt_passes_schema(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        vr = verify_receipt(result.receipt, SCHEMA)
        assert vr.valid, f"Verification failed: {vr.errors}"

    def test_partial_receipt_fingerprint_verifies(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        match, _, _ = verify_fingerprint(result.receipt)
        assert match


# =============================================================================
# 12. Evaluation Coverage
# =============================================================================

class TestEvaluationCoverage:
    def test_full_coverage(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=ALL_HALT_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        cov = result.receipt["evaluation_coverage"]
        assert cov["total_invariants"] == 5
        assert cov["evaluated"] == 5
        assert cov["not_checked"] == 0
        assert cov["coverage_basis_points"] == 10000

    def test_partial_coverage(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        cov = result.receipt["evaluation_coverage"]
        assert cov["total_invariants"] == 3
        assert cov["evaluated"] == 2
        assert cov["not_checked"] == 1
        assert cov["coverage_basis_points"] == 6666

    def test_no_invariants_coverage(self):
        @sanna_observe(require_constitution_sig=False, constitution_path=NO_INVARIANTS_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        # No invariants = no evaluation_coverage in no-invariants path
        # (evaluation_coverage is only in constitution-driven path)

    def test_coverage_in_fingerprint(self):
        """Tampering with evaluation_coverage should invalidate fingerprint."""
        @sanna_observe(require_constitution_sig=False, constitution_path=WITH_CUSTOM_CONST)
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        receipt = result.receipt
        receipt["evaluation_coverage"]["coverage_basis_points"] = 9999
        match, _, _ = verify_fingerprint(receipt)
        assert not match


# =============================================================================
# 13. Scaffold Invariants
# =============================================================================

class TestScaffoldInvariants:
    def test_scaffold_includes_invariants(self):
        content = scaffold_constitution()
        assert "invariants:" in content
        assert "INV_NO_FABRICATION" in content
        assert "INV_MARK_INFERENCE" in content

    def test_scaffold_has_enforcement(self):
        content = scaffold_constitution()
        assert 'enforcement: "halt"' in content or "enforcement: halt" in content

    def test_scaffold_file_loads_without_error(self, tmp_path):
        path = tmp_path / "scaffold.yaml"
        scaffold_constitution(path)
        # Should load (unsigned, no hash)
        const = load_constitution(path)
        assert len(const.invariants) >= 1


# =============================================================================
# 14. Constitution Schema
# =============================================================================

class TestConstitutionSchema:
    def test_schema_file_exists(self):
        schema_path = Path(__file__).parent.parent / "src" / "sanna" / "spec" / "constitution.schema.json"
        assert schema_path.exists()

    def test_schema_is_valid_json(self):
        schema_path = Path(__file__).parent.parent / "src" / "sanna" / "spec" / "constitution.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        assert schema["title"] == "Sanna Constitution"
        assert "identity" in schema["properties"]
        assert "invariants" in schema["properties"]
        assert "policy_hash" in schema["properties"]

    def test_valid_constitution_passes_schema(self):
        from jsonschema import validate
        schema_path = Path(__file__).parent.parent / "src" / "sanna" / "spec" / "constitution.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)

        data = {
            "sanna_constitution": "1.0.0",
            "identity": {"agent_name": "test", "domain": "test"},
            "provenance": {
                "authored_by": "t@t.com",
                "approved_by": ["a@t.com"],
                "approval_date": "2026-01-01",
                "approval_method": "test",
            },
            "boundaries": [{"id": "B001", "description": "Test", "category": "scope", "severity": "medium"}],
            "invariants": [{"id": "INV_NO_FABRICATION", "rule": "test", "enforcement": "halt"}],
            "policy_hash": None,
        }
        validate(data, schema)  # Should not raise


# =============================================================================
# 15. Version Constants
# =============================================================================

class TestV061Versions:
    def test_tool_version(self):
        assert TOOL_VERSION == "0.13.3"

    def test_checks_version(self):
        assert CHECKS_VERSION == "5"

    def test_init_version(self):
        import sanna
        assert sanna.__version__ == "0.13.3"


# =============================================================================
# 16. Full SHA-256 key_id (v0.6.2)
# =============================================================================

class TestFullKeyId:
    def test_key_id_is_64_hex_chars(self, tmp_path):
        """key_id should be a full 64-char SHA-256 hex digest."""
        priv_path, pub_path = generate_keypair(tmp_path)
        pub = load_public_key(pub_path)
        kid = compute_key_id(pub)
        assert len(kid) == 64
        assert all(c in "0123456789abcdef" for c in kid)

    def test_different_keys_different_key_ids(self, tmp_path):
        """Different keypairs should produce different key_ids."""
        _, pub1 = generate_keypair(tmp_path / "k1")
        _, pub2 = generate_keypair(tmp_path / "k2")
        kid1 = compute_key_id(load_public_key(pub1))
        kid2 = compute_key_id(load_public_key(pub2))
        assert kid1 != kid2

    def test_same_key_same_key_id(self, tmp_path):
        """Same key should always produce the same key_id."""
        _, pub_path = generate_keypair(tmp_path)
        pub = load_public_key(pub_path)
        assert compute_key_id(pub) == compute_key_id(pub)

    def test_constitution_signature_has_64_char_key_id(self, tmp_path):
        """Ed25519-signed constitution should have a 64-char key_id."""
        priv_path, _ = generate_keypair(tmp_path)
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        assert len(signed.provenance.signature.key_id) == 64

    def test_receipt_signature_has_64_char_key_id(self, tmp_path):
        """Signed receipt should have a 64-char key_id."""
        priv_path, _ = generate_keypair(tmp_path)
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path, private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        sig_block = result.receipt.get("receipt_signature", {})
        assert len(sig_block["key_id"]) == 64


# =============================================================================
# 17. Keygen Metadata (v0.6.2)
# =============================================================================

class TestKeygenMetadata:
    def test_metadata_written_with_signed_by(self, tmp_path):
        """generate_keypair with signed_by should create meta.json with signed_by."""
        _, pub_path = generate_keypair(tmp_path, signed_by="compliance-team")
        meta_path = pub_path.with_suffix(".meta.json")
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["signed_by"] == "compliance-team"
        assert "key_id" in meta
        assert len(meta["key_id"]) == 64
        assert "created_at" in meta
        assert meta["algorithm"] == "Ed25519"

    def test_metadata_always_created(self, tmp_path):
        """meta.json is always created, even without signed_by or label."""
        _, pub_path = generate_keypair(tmp_path)
        meta_path = pub_path.with_suffix(".meta.json")
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert "key_id" in meta
        assert "created_at" in meta
        assert meta["algorithm"] == "Ed25519"
        assert "signed_by" not in meta
        assert "label" not in meta

    def test_metadata_with_label(self, tmp_path):
        """meta.json includes label when provided."""
        _, pub_path = generate_keypair(tmp_path, label="approver")
        meta_path = pub_path.with_suffix(".meta.json")
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["label"] == "approver"

    def test_metadata_key_id_matches_pubkey(self, tmp_path):
        """meta.json key_id should match the actual public key."""
        _, pub_path = generate_keypair(tmp_path)
        meta_path = pub_path.with_suffix(".meta.json")
        meta = json.loads(meta_path.read_text())
        pub = load_public_key(pub_path)
        assert meta["key_id"] == compute_key_id(pub)


# =============================================================================
# 18. Demo Ed25519 Flow (v0.6.2)
# =============================================================================

EXAMPLE_CONSTITUTIONS_DIR = Path(__file__).parent.parent / "examples" / "constitutions"

class TestDemoEd25519Flow:
    def test_sign_load_verify_cycle(self, tmp_path):
        """The demo's sign-load-verify cycle should work end-to-end."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")

        # Load unsigned example constitution
        source = str(EXAMPLE_CONSTITUTIONS_DIR / "strict_financial_analyst.yaml")
        const = load_constitution(source)
        assert const.policy_hash is None

        # Sign with Ed25519
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="demo-test")
        assert signed.policy_hash is not None
        assert signed.provenance.signature.value is not None
        assert signed.provenance.signature.key_id is not None
        assert signed.provenance.signature.signed_by == "demo-test"

        # Save and reload
        signed_path = tmp_path / "signed.yaml"
        save_constitution(signed, signed_path)
        reloaded = load_constitution(str(signed_path))
        assert reloaded.policy_hash == signed.policy_hash

        # Verify signature
        valid = verify_constitution_full(reloaded, str(pub_path))
        assert valid

    def test_demo_receipt_signing(self, tmp_path):
        """sanna_observe with private_key_path should produce a signed receipt."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")

        source = str(EXAMPLE_CONSTITUTIONS_DIR / "strict_financial_analyst.yaml")
        const = load_constitution(source)
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="demo-test")
        signed_path = tmp_path / "signed.yaml"
        save_constitution(signed, signed_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(signed_path), private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        sig_block = result.receipt.get("receipt_signature")
        assert sig_block is not None
        assert verify_receipt_signature(result.receipt, str(pub_path))

    def test_provenance_bond_in_demo_flow(self, tmp_path):
        """Receipt's constitution_ref.document_hash should match the signed constitution."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")

        source = str(EXAMPLE_CONSTITUTIONS_DIR / "permissive_support_agent.yaml")
        const = load_constitution(source)
        signed = sign_constitution(const, private_key_path=str(priv_path))
        signed_path = tmp_path / "signed.yaml"
        save_constitution(signed, signed_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(signed_path), private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = agent(query="test", context=SIMPLE_CONTEXT)

        const_ref = result.receipt.get("constitution_ref", {})
        assert const_ref["policy_hash"] == signed.policy_hash


# =============================================================================
# 19. Tamper Detection (v0.6.2)
# =============================================================================

class TestTamperDetection:
    def test_tampered_constitution_fails_hash_verify(self, tmp_path):
        """Modifying a signed constitution should cause hash mismatch on load."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path))
        path = tmp_path / "const.yaml"
        save_constitution(signed, path)

        # Tamper: modify the file
        content = path.read_text()
        content = content.replace("test-agent", "evil-agent")
        path.write_text(content)

        with pytest.raises(SannaConstitutionError, match="hash mismatch"):
            load_constitution(str(path))

    def test_tampered_constitution_fails_signature_verify(self, tmp_path):
        """Tampering with a signed constitution should fail full verification."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path))
        # Tamper: change agent name after signing
        from sanna.constitution import Constitution, Provenance, AgentIdentity
        tampered = Constitution(
            schema_version=signed.schema_version,
            identity=AgentIdentity(agent_name="tampered-agent", domain="testing"),
            provenance=signed.provenance,
            boundaries=signed.boundaries,
            invariants=signed.invariants,
            policy_hash=signed.policy_hash,
        )
        valid = verify_constitution_full(tampered, str(pub_path))
        assert not valid

    def test_tampered_receipt_fails_signature_verify(self, tmp_path):
        """Modifying a signed receipt should cause signature verification failure."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path, private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt = result.receipt

        # Verify before tampering
        assert verify_receipt_signature(receipt, str(pub_path))

        # Tamper: change a field to a clearly different value
        receipt["status"] = "FAIL"
        assert not verify_receipt_signature(receipt, str(pub_path))

    def test_wrong_key_fails_receipt_verify(self, tmp_path):
        """Verifying a receipt with the wrong public key should fail."""
        priv_path, _ = generate_keypair(tmp_path / "keys1")
        _, wrong_pub = generate_keypair(tmp_path / "keys2")

        path = _signed_constitution_path(tmp_path / "const", [
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])

        @sanna_observe(require_constitution_sig=False, constitution_path=path, private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        assert not verify_receipt_signature(result.receipt, str(wrong_pub))

    def test_wrong_key_fails_constitution_verify(self, tmp_path):
        """Verifying a constitution with the wrong public key should fail."""
        priv_path, _ = generate_keypair(tmp_path / "keys1")
        _, wrong_pub = generate_keypair(tmp_path / "keys2")

        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path))
        valid = verify_constitution_full(signed, str(wrong_pub))
        assert not valid


# =============================================================================
# 20. Provenance Chain Verification (v0.6.2)
# =============================================================================

class TestProvenanceChainVerification:
    def test_key_ids_match_across_constitution_and_receipt(self, tmp_path):
        """key_id in constitution and receipt signatures should match when same key is used."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="chain-test")
        signed_path = tmp_path / "const.yaml"
        save_constitution(signed, signed_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(signed_path), private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        receipt_sig = result.receipt["receipt_signature"]

        # Same key → same key_id
        assert signed.provenance.signature.key_id == receipt_sig["key_id"]

    def test_full_provenance_chain_verification(self, tmp_path):
        """Both constitution and receipt should verify with the same public key."""
        priv_path, pub_path = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path))
        signed_path = tmp_path / "const.yaml"
        save_constitution(signed, signed_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(signed_path), private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)

        # Verify constitution signature
        assert verify_constitution_full(signed, str(pub_path))
        # Verify receipt signature
        assert verify_receipt_signature(result.receipt, str(pub_path))
        # Verify provenance bond
        const_ref = result.receipt["constitution_ref"]
        assert const_ref["policy_hash"] == signed.policy_hash

    def test_constitution_ref_includes_key_id(self, tmp_path):
        """constitution_ref in receipt should include the key_id from constitution."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _make_constitution([
            Invariant(id="INV_NO_FABRICATION", rule="test", enforcement="halt"),
        ])
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="ref-test")
        signed_path = tmp_path / "const.yaml"
        save_constitution(signed, signed_path)

        @sanna_observe(require_constitution_sig=False, constitution_path=str(signed_path), private_key_path=str(priv_path))
        def agent(query, context):
            return SIMPLE_OUTPUT

        result = agent(query="test", context=SIMPLE_CONTEXT)
        const_ref = result.receipt["constitution_ref"]
        assert const_ref.get("key_id") == signed.provenance.signature.key_id
        assert const_ref.get("signed_by") == "ref-test"
