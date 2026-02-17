"""
Tests for the full Sanna Constitution lifecycle:
validate → parse → sign → bind → receipt → verify

Covers:
  - Data validation (happy + error paths)
  - Parse from dict (sanna_constitution → schema_version mapping)
  - Hash computation (deterministic, provenance-independent)
  - Signing (hash + timestamp)
  - Receipt ref conversion
  - File I/O (YAML round-trip, JSON round-trip)
  - Scaffolding
  - Middleware integration with constitution_path
  - Verification of receipts with rich constitution_ref (64-char hashes)
  - Fingerprint integrity through the constitution_ref_override pipeline
"""

import json
import re
import tempfile
from dataclasses import asdict
from pathlib import Path

import pytest

from sanna.constitution import (
    Boundary,
    HaltCondition,
    TrustTiers,
    Provenance,
    AgentIdentity,
    Constitution,
    validate_constitution_data,
    parse_constitution,
    compute_constitution_hash,
    sign_constitution,
    constitution_to_receipt_ref,
    load_constitution,
    constitution_to_dict,
    save_constitution,
    scaffold_constitution,
    CONSTITUTION_SCHEMA_VERSION,
)
from sanna.crypto import generate_keypair
from sanna.receipt import generate_receipt, ConstitutionProvenance, SannaReceipt
from sanna.hashing import hash_text, hash_obj
from sanna.verify import verify_receipt, load_schema, verify_fingerprint
from sanna.middleware import sanna_observe, SannaResult, SannaHaltError


RECEIPT_SCHEMA = load_schema()

_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_HEX16 = re.compile(r"^[a-f0-9]{16}$")


# =============================================================================
# FIXTURES
# =============================================================================

def _sample_constitution_data() -> dict:
    """Minimal valid constitution dict (as from YAML)."""
    return {
        "sanna_constitution": "0.1.0",
        "identity": {
            "agent_name": "test-agent",
            "domain": "testing",
            "description": "Unit-test agent",
        },
        "provenance": {
            "authored_by": "dev@example.com",
            "approved_by": ["lead@example.com", "compliance@example.com"],
            "approval_date": "2026-01-15",
            "approval_method": "github-pr-review",
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Only answer questions about testing",
                "category": "scope",
                "severity": "high",
            },
            {
                "id": "B002",
                "description": "Never expose internal system details",
                "category": "confidentiality",
                "severity": "critical",
            },
        ],
        "trust_tiers": {
            "autonomous": ["Answer domain questions"],
            "requires_approval": ["Escalate to specialist"],
            "prohibited": ["Make binding commitments"],
        },
        "halt_conditions": [
            {
                "id": "H001",
                "trigger": "Agent contradicts verified information",
                "escalate_to": "team-lead@example.com",
                "severity": "critical",
                "enforcement": "halt",
            }
        ],
    }


def _sample_constitution() -> Constitution:
    """Parsed Constitution object."""
    return parse_constitution(_sample_constitution_data())


def _signed_constitution() -> Constitution:
    """Signed Constitution object."""
    return sign_constitution(_sample_constitution())


def _make_trace(**overrides):
    """Build a minimal trace dict for receipt generation."""
    trace = {
        "trace_id": "test-lifecycle-001",
        "name": "lifecycle-test",
        "timestamp": "2026-01-01T00:00:00Z",
        "input": {"query": "How do I run tests?"},
        "output": {"final_answer": "Use pytest to run your test suite."},
        "metadata": {},
        "observations": [
            {
                "id": "obs-ret",
                "name": "retrieval",
                "type": "SPAN",
                "input": {"query": "run tests"},
                "output": {"context": "pytest is the standard Python testing tool."},
                "metadata": {},
                "start_time": "2026-01-01T00:00:01Z",
                "end_time": "2026-01-01T00:00:02Z",
            }
        ],
    }
    trace.update(overrides)
    return trace


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestValidation:
    def test_valid_data(self):
        errors = validate_constitution_data(_sample_constitution_data())
        assert errors == []

    def test_missing_identity(self):
        data = _sample_constitution_data()
        del data["identity"]
        errors = validate_constitution_data(data)
        assert any("identity" in e for e in errors)

    def test_missing_provenance(self):
        data = _sample_constitution_data()
        del data["provenance"]
        errors = validate_constitution_data(data)
        assert any("provenance" in e for e in errors)

    def test_missing_boundaries(self):
        data = _sample_constitution_data()
        del data["boundaries"]
        errors = validate_constitution_data(data)
        assert any("boundaries" in e for e in errors)

    def test_empty_boundaries(self):
        data = _sample_constitution_data()
        data["boundaries"] = []
        errors = validate_constitution_data(data)
        assert any("at least one" in e for e in errors)

    def test_invalid_boundary_id(self):
        data = _sample_constitution_data()
        data["boundaries"][0]["id"] = "X99"
        errors = validate_constitution_data(data)
        assert any("B###" in e for e in errors)

    def test_duplicate_boundary_id(self):
        data = _sample_constitution_data()
        data["boundaries"][1]["id"] = "B001"
        errors = validate_constitution_data(data)
        assert any("Duplicate" in e for e in errors)

    def test_invalid_category(self):
        data = _sample_constitution_data()
        data["boundaries"][0]["category"] = "invalid-cat"
        errors = validate_constitution_data(data)
        assert any("category" in e for e in errors)

    def test_invalid_severity(self):
        data = _sample_constitution_data()
        data["boundaries"][0]["severity"] = "extreme"
        errors = validate_constitution_data(data)
        assert any("severity" in e for e in errors)

    def test_invalid_halt_id(self):
        data = _sample_constitution_data()
        data["halt_conditions"][0]["id"] = "Z001"
        errors = validate_constitution_data(data)
        assert any("H###" in e for e in errors)

    def test_invalid_enforcement(self):
        data = _sample_constitution_data()
        data["halt_conditions"][0]["enforcement"] = "crash"
        errors = validate_constitution_data(data)
        assert any("enforcement" in e for e in errors)

    def test_approved_by_string_coercion(self):
        data = _sample_constitution_data()
        data["provenance"]["approved_by"] = "single@example.com"
        errors = validate_constitution_data(data)
        assert errors == []

    def test_invalid_approval_date(self):
        data = _sample_constitution_data()
        data["provenance"]["approval_date"] = "not-a-date"
        errors = validate_constitution_data(data)
        assert any("ISO 8601" in e for e in errors)


# =============================================================================
# PARSING TESTS
# =============================================================================

class TestParsing:
    def test_parse_maps_sanna_constitution_to_schema_version(self):
        c = _sample_constitution()
        assert c.schema_version == "0.1.0"

    def test_parse_identity(self):
        c = _sample_constitution()
        assert c.identity.agent_name == "test-agent"
        assert c.identity.domain == "testing"

    def test_parse_provenance(self):
        c = _sample_constitution()
        assert c.provenance.authored_by == "dev@example.com"
        assert len(c.provenance.approved_by) == 2
        assert c.provenance.approval_method == "github-pr-review"

    def test_parse_boundaries(self):
        c = _sample_constitution()
        assert len(c.boundaries) == 2
        assert c.boundaries[0].id == "B001"
        assert c.boundaries[1].category == "confidentiality"

    def test_parse_halt_conditions(self):
        c = _sample_constitution()
        assert len(c.halt_conditions) == 1
        assert c.halt_conditions[0].enforcement == "halt"

    def test_parse_trust_tiers(self):
        c = _sample_constitution()
        assert "Answer domain questions" in c.trust_tiers.autonomous
        assert "Make binding commitments" in c.trust_tiers.prohibited

    def test_parse_string_approved_by_becomes_list(self):
        data = _sample_constitution_data()
        data["provenance"]["approved_by"] = "single@example.com"
        c = parse_constitution(data)
        assert c.provenance.approved_by == ["single@example.com"]

    def test_parse_invalid_data_raises(self):
        with pytest.raises(ValueError, match="Invalid constitution"):
            parse_constitution({"identity": {}})


# =============================================================================
# HASHING TESTS
# =============================================================================

class TestHashing:
    def test_hash_is_64_hex_chars(self):
        c = _sample_constitution()
        h = compute_constitution_hash(c)
        assert _HEX64.match(h), f"Expected 64 hex chars, got '{h}'"

    def test_hash_is_deterministic(self):
        c1 = _sample_constitution()
        c2 = _sample_constitution()
        assert compute_constitution_hash(c1) == compute_constitution_hash(c2)

    def test_hash_ignores_provenance(self):
        """Same policy content with different approvers should produce the same hash."""
        c1 = _sample_constitution()
        data2 = _sample_constitution_data()
        data2["provenance"]["authored_by"] = "other@example.com"
        data2["provenance"]["approved_by"] = ["different@example.com"]
        c2 = parse_constitution(data2)
        assert compute_constitution_hash(c1) == compute_constitution_hash(c2)

    def test_hash_changes_with_boundaries(self):
        c1 = _sample_constitution()
        data2 = _sample_constitution_data()
        data2["boundaries"][0]["description"] = "Completely different boundary"
        c2 = parse_constitution(data2)
        assert compute_constitution_hash(c1) != compute_constitution_hash(c2)

    def test_hash_changes_with_halt_conditions(self):
        c1 = _sample_constitution()
        data2 = _sample_constitution_data()
        data2["halt_conditions"][0]["trigger"] = "Different trigger condition"
        c2 = parse_constitution(data2)
        assert compute_constitution_hash(c1) != compute_constitution_hash(c2)

    def test_hash_changes_with_identity(self):
        c1 = _sample_constitution()
        data2 = _sample_constitution_data()
        data2["identity"]["agent_name"] = "different-agent"
        c2 = parse_constitution(data2)
        assert compute_constitution_hash(c1) != compute_constitution_hash(c2)


# =============================================================================
# SIGNING TESTS
# =============================================================================

class TestSigning:
    def test_sign_sets_hash(self):
        signed = _signed_constitution()
        assert signed.policy_hash is not None
        assert _HEX64.match(signed.policy_hash)

    def test_sign_without_key_has_no_signature(self):
        signed = _signed_constitution()
        assert signed.provenance.signature is None

    def test_sign_preserves_content(self):
        original = _sample_constitution()
        signed = sign_constitution(original)
        assert signed.identity.agent_name == original.identity.agent_name
        assert len(signed.boundaries) == len(original.boundaries)

    def test_sign_returns_new_object(self):
        original = _sample_constitution()
        signed = sign_constitution(original)
        assert original.policy_hash is None
        assert signed.policy_hash is not None

    def test_sign_hash_matches_compute(self):
        signed = _signed_constitution()
        assert signed.policy_hash == compute_constitution_hash(signed)


# =============================================================================
# RECEIPT REF TESTS
# =============================================================================

class TestReceiptRef:
    def test_receipt_ref_structure(self):
        ref = constitution_to_receipt_ref(_signed_constitution())
        assert "document_id" in ref
        assert "policy_hash" in ref
        assert "version" in ref
        assert "approved_by" in ref
        assert "approval_date" in ref
        assert "approval_method" in ref
        assert "constitution_approval" in ref

    def test_receipt_ref_document_id_format(self):
        ref = constitution_to_receipt_ref(_signed_constitution())
        assert ref["document_id"] == "test-agent/0.1.0"

    def test_receipt_ref_hash_is_64_chars(self):
        ref = constitution_to_receipt_ref(_signed_constitution())
        assert _HEX64.match(ref["policy_hash"])

    def test_receipt_ref_unsigned_raises(self):
        with pytest.raises(ValueError, match="must be signed"):
            constitution_to_receipt_ref(_sample_constitution())

    def test_receipt_ref_approved_by_is_list(self):
        ref = constitution_to_receipt_ref(_signed_constitution())
        assert isinstance(ref["approved_by"], list)
        assert len(ref["approved_by"]) == 2


# =============================================================================
# FILE I/O TESTS
# =============================================================================

class TestFileIO:
    def test_yaml_round_trip(self, tmp_path):
        original = _signed_constitution()
        path = tmp_path / "constitution.yaml"
        save_constitution(original, path)
        loaded = load_constitution(path)
        assert loaded.identity.agent_name == original.identity.agent_name
        assert loaded.policy_hash == original.policy_hash
        assert loaded.schema_version == original.schema_version

    def test_json_round_trip(self, tmp_path):
        original = _signed_constitution()
        path = tmp_path / "constitution.json"
        save_constitution(original, path)
        loaded = load_constitution(path)
        assert loaded.identity.agent_name == original.identity.agent_name
        assert loaded.policy_hash == original.policy_hash

    def test_dict_round_trip(self):
        original = _signed_constitution()
        d = constitution_to_dict(original)
        # sanna_constitution key should be present, not schema_version
        assert "sanna_constitution" in d
        assert "schema_version" not in d
        reparsed = parse_constitution(d)
        assert reparsed.schema_version == original.schema_version
        assert reparsed.identity.agent_name == original.identity.agent_name

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_constitution("/nonexistent/path.yaml")

    def test_load_unsupported_format_raises(self, tmp_path):
        path = tmp_path / "constitution.txt"
        path.write_text("content")
        with pytest.raises(ValueError, match="Unsupported"):
            load_constitution(path)


# =============================================================================
# SCAFFOLDING TESTS
# =============================================================================

class TestScaffolding:
    def test_scaffold_returns_string(self):
        content = scaffold_constitution()
        assert isinstance(content, str)
        assert "sanna_constitution" in content

    def test_scaffold_contains_today(self):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        content = scaffold_constitution()
        assert today in content

    def test_scaffold_writes_file(self, tmp_path):
        path = tmp_path / "test_constitution.yaml"
        scaffold_constitution(path)
        assert path.exists()
        content = path.read_text()
        assert "sanna_constitution" in content

    def test_scaffold_is_valid_yaml(self, tmp_path):
        import yaml
        content = scaffold_constitution()
        data = yaml.safe_load(content)
        assert data["sanna_constitution"] == "0.1.0"
        assert "identity" in data
        assert "boundaries" in data


# =============================================================================
# RECEIPT GENERATION WITH constitution_ref_override
# =============================================================================

class TestReceiptRefOverride:
    def test_override_used_in_receipt(self):
        """constitution_ref_override should appear directly in receipt body."""
        signed = _signed_constitution()
        ref = constitution_to_receipt_ref(signed)
        receipt = generate_receipt(_make_trace(), constitution_ref_override=ref)
        assert receipt.constitution_ref == ref
        assert receipt.constitution_ref["document_id"] == "test-agent/0.1.0"

    def test_override_takes_precedence_over_legacy(self):
        """constitution_ref_override should take precedence over constitution param."""
        legacy = ConstitutionProvenance(
            document_id="legacy-doc",
            policy_hash=hash_text("legacy content"),
        )
        signed = _signed_constitution()
        ref = constitution_to_receipt_ref(signed)
        receipt = generate_receipt(
            _make_trace(),
            constitution=legacy,
            constitution_ref_override=ref,
        )
        assert receipt.constitution_ref["document_id"] == "test-agent/0.1.0"
        assert _HEX64.match(receipt.constitution_ref["policy_hash"])

    def test_override_fingerprint_verifies(self):
        """Fingerprint should verify when constitution_ref_override is used."""
        signed = _signed_constitution()
        ref = constitution_to_receipt_ref(signed)
        receipt = generate_receipt(_make_trace(), constitution_ref_override=ref)
        receipt_dict = asdict(receipt)
        match, computed, expected = verify_fingerprint(receipt_dict)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_override_receipt_validates_schema(self):
        """Receipt with rich constitution_ref should pass schema validation."""
        signed = _signed_constitution()
        ref = constitution_to_receipt_ref(signed)
        receipt = generate_receipt(_make_trace(), constitution_ref_override=ref)
        receipt_dict = asdict(receipt)
        result = verify_receipt(receipt_dict, RECEIPT_SCHEMA)
        assert result.valid, f"Validation failed: {result.errors}"

    def test_override_changes_fingerprint(self):
        """Adding constitution_ref_override should change the fingerprint."""
        trace = _make_trace()
        r_without = generate_receipt(trace)
        signed = _signed_constitution()
        ref = constitution_to_receipt_ref(signed)
        r_with = generate_receipt(trace, constitution_ref_override=ref)
        assert r_without.receipt_fingerprint != r_with.receipt_fingerprint

    def test_tampering_override_invalidates_fingerprint(self):
        """Modifying constitution_ref after generation should fail verification."""
        signed = _signed_constitution()
        ref = constitution_to_receipt_ref(signed)
        receipt = generate_receipt(_make_trace(), constitution_ref_override=ref)
        receipt_dict = asdict(receipt)
        receipt_dict["constitution_ref"]["policy_hash"] = "a" * 64
        match, _, _ = verify_fingerprint(receipt_dict)
        assert not match


# =============================================================================
# MIDDLEWARE INTEGRATION WITH constitution_path
# =============================================================================

class TestMiddlewareConstitutionPath:
    def _write_constitution(self, tmp_path) -> Path:
        """Write a signed constitution YAML to tmp_path and return path."""
        priv_path, _ = generate_keypair(tmp_path / "keys")
        const = _sample_constitution()
        signed = sign_constitution(const, private_key_path=str(priv_path), signed_by="tester")
        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)
        return path

    def test_constitution_path_loads_and_binds(self, tmp_path):
        """constitution_path should load, sign, and bind to receipt."""
        const_path = self._write_constitution(tmp_path)

        @sanna_observe(on_violation="log", constitution_path=str(const_path))
        def my_agent(query, context):
            return "Use pytest to run tests."

        result = my_agent(
            query="How do I run tests?",
            context="pytest is the standard Python testing tool.",
        )
        assert isinstance(result, SannaResult)
        ref = result.receipt["constitution_ref"]
        assert ref is not None
        assert ref["document_id"] == "test-agent/0.1.0"
        assert _HEX64.match(ref["policy_hash"])
        assert ref["approved_by"] == ["lead@example.com", "compliance@example.com"]
        assert ref["approval_date"] == "2026-01-15"
        assert ref["approval_method"] == "github-pr-review"

    def test_constitution_path_fingerprint_verifies(self, tmp_path):
        """Receipt from constitution_path should have verifiable fingerprint."""
        const_path = self._write_constitution(tmp_path)

        @sanna_observe(on_violation="log", constitution_path=str(const_path))
        def my_agent(query, context):
            return "Use pytest to run tests."

        result = my_agent(
            query="How do I run tests?",
            context="pytest is the standard Python testing tool.",
        )
        match, computed, expected = verify_fingerprint(result.receipt)
        assert match, f"Fingerprint mismatch: {computed} != {expected}"

    def test_constitution_path_receipt_validates(self, tmp_path):
        """Receipt from constitution_path should pass full verification."""
        const_path = self._write_constitution(tmp_path)

        @sanna_observe(on_violation="log", constitution_path=str(const_path))
        def my_agent(query, context):
            return "Use pytest to run tests."

        result = my_agent(
            query="How do I run tests?",
            context="pytest is the standard Python testing tool.",
        )
        vr = verify_receipt(result.receipt, RECEIPT_SCHEMA)
        assert vr.valid, f"Validation failed: {vr.errors}"

    def test_constitution_path_with_check_subset(self, tmp_path):
        """constitution_path should work with a subset of checks too."""
        const_path = self._write_constitution(tmp_path)

        @sanna_observe(
            on_violation="log",
            checks=["C1", "C3"],
            constitution_path=str(const_path),
        )
        def my_agent(query, context):
            return "Use pytest."

        result = my_agent(query="test?", context="pytest")
        ref = result.receipt["constitution_ref"]
        assert ref is not None
        assert _HEX64.match(ref["policy_hash"])
        # Fingerprint should still verify
        match, _, _ = verify_fingerprint(result.receipt)
        assert match

    def test_constitution_path_unsigned_raises(self, tmp_path):
        """An unsigned constitution file should raise SannaConstitutionError."""
        from sanna.constitution import SannaConstitutionError

        # Write an unsigned constitution
        data = _sample_constitution_data()
        data["policy_hash"] = None
        import yaml
        path = tmp_path / "unsigned.yaml"
        with open(path, "w") as f:
            yaml.dump(data, f)

        with pytest.raises(SannaConstitutionError, match="not signed"):
            @sanna_observe(on_violation="log", constitution_path=str(path))
            def my_agent(query, context):
                return "Response."


# =============================================================================
# VERIFY: 64-char hash acceptance
# =============================================================================

class TestVerify64CharHash:
    def test_verify_accepts_64_char_hash(self):
        """verify_constitution_hash should accept 64-char hashes."""
        from sanna.verify import verify_constitution_hash
        receipt = {"constitution_ref": {"policy_hash": "a" * 64}}
        errors = verify_constitution_hash(receipt)
        assert errors == []

    def test_verify_accepts_16_char_hash(self):
        """verify_constitution_hash should still accept legacy 16-char hashes."""
        from sanna.verify import verify_constitution_hash
        receipt = {"constitution_ref": {"policy_hash": "a" * 16}}
        errors = verify_constitution_hash(receipt)
        assert errors == []

    def test_verify_rejects_invalid_hash_length(self):
        """verify_constitution_hash should reject hashes outside 16-64 range."""
        from sanna.verify import verify_constitution_hash
        receipt = {"constitution_ref": {"policy_hash": "abc"}}
        errors = verify_constitution_hash(receipt)
        assert len(errors) == 1
        assert "invalid format" in errors[0]

    def test_verify_rejects_non_hex(self):
        """verify_constitution_hash should reject non-hex characters."""
        from sanna.verify import verify_constitution_hash
        receipt = {"constitution_ref": {"policy_hash": "g" * 64}}
        errors = verify_constitution_hash(receipt)
        assert len(errors) == 1
