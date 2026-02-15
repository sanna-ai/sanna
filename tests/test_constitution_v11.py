"""
Tests for Constitution v1.1 schema with reasoning configuration.
"""

import pytest
from dataclasses import asdict

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    ReasoningConfig,
    GLCCheckConfig,
    GLCMinimumSubstanceConfig,
    GLCNoParrotingConfig,
    GLCLLMCoherenceConfig,
    parse_constitution,
    validate_constitution_data,
    sign_constitution,
    save_constitution,
    load_constitution,
    compute_constitution_hash,
    constitution_to_dict,
)
from sanna.crypto import generate_keypair, verify_constitution_full


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_constitution_data(**overrides):
    """Build minimal valid constitution data dict."""
    data = {
        "sanna_constitution": "0.1.0",
        "identity": {
            "agent_name": "test-agent",
            "domain": "testing",
        },
        "provenance": {
            "authored_by": "dev@example.com",
            "approved_by": ["approver@example.com"],
            "approval_date": "2026-01-01",
            "approval_method": "manual-sign-off",
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Test boundary",
                "category": "scope",
                "severity": "high",
            },
        ],
    }
    data.update(overrides)
    return data


def _v11_reasoning_data(**overrides):
    """Build a full v1.1 reasoning config dict."""
    reasoning = {
        "require_justification_for": ["must_escalate", "cannot_execute"],
        "on_missing_justification": "block",
        "on_check_error": "escalate",
        "evaluate_before_escalation": True,
        "auto_deny_on_reasoning_failure": False,
        "checks": {
            "glc_minimum_substance": {
                "enabled": True,
                "min_length": 30,
            },
            "glc_no_parroting": {
                "enabled": True,
                "blocklist": ["because you asked", "you told me to"],
            },
            "glc_llm_coherence": {
                "enabled": True,
                "enabled_for": ["must_escalate"],
                "timeout_ms": 3000,
                "score_threshold": 0.7,
            },
        },
    }
    reasoning.update(overrides)
    return reasoning


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

class TestV10BackwardCompat:
    def test_v10_constitution_no_reasoning(self):
        """v1.0 constitution without version/reasoning parses with reasoning=None."""
        data = _minimal_constitution_data()
        constitution = parse_constitution(data)
        assert constitution.version == "1.0"
        assert constitution.reasoning is None

    def test_missing_version_defaults_to_v10(self):
        """Constitution without 'version' field defaults to '1.0'."""
        data = _minimal_constitution_data()
        assert "version" not in data
        constitution = parse_constitution(data)
        assert constitution.version == "1.0"

    def test_v10_hash_unchanged(self):
        """v1.0 constitutions produce the same hash with or without new fields."""
        data = _minimal_constitution_data()
        c_old = parse_constitution(data)
        # Explicitly set version="1.0" and reasoning=None (the defaults)
        assert c_old.version == "1.0"
        assert c_old.reasoning is None
        hash_old = compute_constitution_hash(c_old)

        # Parse again — should be identical
        c_new = parse_constitution(data)
        hash_new = compute_constitution_hash(c_new)
        assert hash_old == hash_new

    def test_v10_with_reasoning_section_ignored(self):
        """v1.0 constitution with reasoning section → reasoning=None (ignored)."""
        data = _minimal_constitution_data(
            version="1.0",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)
        assert constitution.version == "1.0"
        assert constitution.reasoning is None


# ---------------------------------------------------------------------------
# v1.1 full parsing
# ---------------------------------------------------------------------------

class TestV11FullParsing:
    def test_v11_constitution_full_reasoning(self):
        """v1.1 constitution with full reasoning config parses all fields."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)

        assert constitution.version == "1.1"
        assert constitution.reasoning is not None

        r = constitution.reasoning
        assert r.require_justification_for == ["must_escalate", "cannot_execute"]
        assert r.on_missing_justification == "block"
        assert r.on_check_error == "escalate"
        assert r.evaluate_before_escalation is True
        assert r.auto_deny_on_reasoning_failure is False

        # Check configs
        assert "glc_minimum_substance" in r.checks
        ms = r.checks["glc_minimum_substance"]
        assert isinstance(ms, GLCMinimumSubstanceConfig)
        assert ms.enabled is True
        assert ms.min_length == 30

        assert "glc_no_parroting" in r.checks
        np_check = r.checks["glc_no_parroting"]
        assert isinstance(np_check, GLCNoParrotingConfig)
        assert np_check.blocklist == ["because you asked", "you told me to"]

        assert "glc_llm_coherence" in r.checks
        llm = r.checks["glc_llm_coherence"]
        assert isinstance(llm, GLCLLMCoherenceConfig)
        assert llm.enabled_for == ["must_escalate"]
        assert llm.timeout_ms == 3000
        assert llm.score_threshold == 0.7

    def test_v11_without_reasoning_section(self):
        """v1.1 constitution without reasoning section → reasoning=None."""
        data = _minimal_constitution_data(version="1.1")
        constitution = parse_constitution(data)
        assert constitution.version == "1.1"
        assert constitution.reasoning is None

    def test_v11_reasoning_changes_hash(self):
        """Adding reasoning to a constitution changes the policy hash."""
        data_no_reasoning = _minimal_constitution_data(version="1.1")
        data_with_reasoning = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        c1 = parse_constitution(data_no_reasoning)
        c2 = parse_constitution(data_with_reasoning)
        assert compute_constitution_hash(c1) != compute_constitution_hash(c2)

    def test_v11_defaults(self):
        """v1.1 reasoning with minimal config uses correct defaults."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={},
        )
        constitution = parse_constitution(data)
        r = constitution.reasoning
        assert r is not None
        assert r.require_justification_for == ["must_escalate", "cannot_execute"]
        assert r.on_missing_justification == "block"
        assert r.on_check_error == "block"
        assert r.checks == {}
        assert r.evaluate_before_escalation is True
        assert r.auto_deny_on_reasoning_failure is False


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

class TestValidationErrors:
    def test_invalid_require_justification_for(self):
        """Validation error for invalid enforcement level in require_justification_for."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "require_justification_for": ["must_escalate", "invalid_level"],
            },
        )
        errors = validate_constitution_data(data)
        assert any("invalid_level" in e for e in errors)

    def test_score_threshold_out_of_range(self):
        """Validation error for score_threshold > 1.0."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_llm_coherence": {
                        "score_threshold": 1.5,
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("score_threshold" in e for e in errors)

    def test_score_threshold_negative(self):
        """Validation error for score_threshold < 0.0."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_llm_coherence": {
                        "score_threshold": -0.1,
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("score_threshold" in e for e in errors)

    def test_negative_min_length(self):
        """Validation error for min_length < 0."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_minimum_substance": {
                        "min_length": -5,
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("min_length" in e for e in errors)

    def test_zero_min_length(self):
        """Validation error for min_length == 0."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_minimum_substance": {
                        "min_length": 0,
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("min_length" in e for e in errors)

    def test_invalid_on_missing_justification(self):
        """Validation error for invalid on_missing_justification value."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "on_missing_justification": "invalid",
            },
        )
        errors = validate_constitution_data(data)
        assert any("on_missing_justification" in e for e in errors)

    def test_invalid_on_check_error(self):
        """Validation error for invalid on_check_error value."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "on_check_error": "crash",
            },
        )
        errors = validate_constitution_data(data)
        assert any("on_check_error" in e for e in errors)

    def test_empty_blocklist_item(self):
        """Validation error for empty string in blocklist."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_no_parroting": {
                        "blocklist": ["valid", ""],
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("blocklist" in e for e in errors)

    def test_invalid_enabled_for(self):
        """Validation error for invalid enforcement level in enabled_for."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_llm_coherence": {
                        "enabled_for": ["must_escalate", "bogus"],
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("enabled_for" in e for e in errors)

    def test_negative_timeout_ms(self):
        """Validation error for timeout_ms <= 0."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning={
                "checks": {
                    "glc_llm_coherence": {
                        "timeout_ms": -100,
                    },
                },
            },
        )
        errors = validate_constitution_data(data)
        assert any("timeout_ms" in e for e in errors)

    def test_reasoning_not_a_dict(self):
        """Validation error when reasoning is not a dict."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning="not a dict",
        )
        errors = validate_constitution_data(data)
        assert any("reasoning must be a dict" in e for e in errors)


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------

class TestSerializationRoundTrip:
    def test_v11_to_dict_and_back(self):
        """v1.1 constitution survives dict round-trip."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)
        d = constitution_to_dict(constitution)

        assert d["version"] == "1.1"
        assert "reasoning" in d
        assert d["reasoning"]["on_check_error"] == "escalate"
        assert d["reasoning"]["checks"]["glc_minimum_substance"]["min_length"] == 30

    def test_v10_to_dict_no_version_key(self):
        """v1.0 constitution dict does not include 'version' key."""
        data = _minimal_constitution_data()
        constitution = parse_constitution(data)
        d = constitution_to_dict(constitution)
        assert "version" not in d
        assert "reasoning" not in d

    def test_v11_yaml_round_trip(self, tmp_path):
        """v1.1 constitution survives save→load YAML round-trip."""
        data = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)
        signed = sign_constitution(constitution)

        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)
        loaded = load_constitution(str(path))

        assert loaded.version == "1.1"
        assert loaded.reasoning is not None
        assert loaded.reasoning.on_check_error == "escalate"
        assert isinstance(
            loaded.reasoning.checks["glc_minimum_substance"],
            GLCMinimumSubstanceConfig,
        )
        assert loaded.reasoning.checks["glc_minimum_substance"].min_length == 30


# ---------------------------------------------------------------------------
# Signing & verification
# ---------------------------------------------------------------------------

class TestV11Signing:
    def test_constitution_v11_signature_verification(self, tmp_path):
        """v1.1 constitution with reasoning signs and verifies correctly."""
        keys_dir = tmp_path / "keys"
        private_key_path, public_key_path = generate_keypair(str(keys_dir))

        data = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)
        signed = sign_constitution(
            constitution,
            private_key_path=str(private_key_path),
            signed_by="test@example.com",
        )

        assert signed.policy_hash is not None
        assert signed.provenance.signature is not None
        assert signed.provenance.signature.value is not None

        # Verify signature
        valid = verify_constitution_full(signed, str(public_key_path))
        assert valid, "Ed25519 signature verification failed for v1.1 constitution"

    def test_v11_signing_preserves_reasoning(self, tmp_path):
        """sign_constitution() preserves version and reasoning fields."""
        keys_dir = tmp_path / "keys"
        private_key_path, _ = generate_keypair(str(keys_dir))

        data = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)
        signed = sign_constitution(
            constitution,
            private_key_path=str(private_key_path),
        )

        assert signed.version == "1.1"
        assert signed.reasoning is not None
        assert signed.reasoning.on_check_error == "escalate"

    def test_v10_signature_not_broken(self, tmp_path):
        """Existing v1.0 constitutions still sign and verify correctly."""
        keys_dir = tmp_path / "keys"
        private_key_path, public_key_path = generate_keypair(str(keys_dir))

        data = _minimal_constitution_data()
        constitution = parse_constitution(data)
        signed = sign_constitution(
            constitution,
            private_key_path=str(private_key_path),
        )

        valid = verify_constitution_full(signed, str(public_key_path))
        assert valid, "v1.0 constitution signature broke after v1.1 changes"

    def test_v11_save_load_verify(self, tmp_path):
        """Full lifecycle: parse → sign → save → load → verify."""
        keys_dir = tmp_path / "keys"
        private_key_path, public_key_path = generate_keypair(str(keys_dir))

        data = _minimal_constitution_data(
            version="1.1",
            reasoning=_v11_reasoning_data(),
        )
        constitution = parse_constitution(data)
        signed = sign_constitution(
            constitution,
            private_key_path=str(private_key_path),
            signed_by="test@example.com",
        )

        path = tmp_path / "constitution.yaml"
        save_constitution(signed, path)
        loaded = load_constitution(str(path))

        # Hash integrity check passes (load_constitution verifies hash)
        assert loaded.policy_hash == signed.policy_hash

        # Ed25519 signature still valid after round-trip
        valid = verify_constitution_full(loaded, str(public_key_path))
        assert valid


# ---------------------------------------------------------------------------
# Dataclass defaults
# ---------------------------------------------------------------------------

class TestDataclassDefaults:
    def test_reasoning_config_defaults(self):
        """ReasoningConfig has correct defaults when constructed directly."""
        r = ReasoningConfig()
        assert r.require_justification_for == ["must_escalate", "cannot_execute"]
        assert r.on_missing_justification == "block"
        assert r.on_check_error == "block"
        assert r.checks == {}
        assert r.evaluate_before_escalation is True
        assert r.auto_deny_on_reasoning_failure is False

    def test_glc_minimum_substance_defaults(self):
        """GLCMinimumSubstanceConfig has correct defaults."""
        c = GLCMinimumSubstanceConfig()
        assert c.enabled is True
        assert c.min_length == 20

    def test_glc_no_parroting_defaults(self):
        """GLCNoParrotingConfig has correct defaults."""
        c = GLCNoParrotingConfig()
        assert c.enabled is True
        assert c.blocklist == ["because you asked", "you told me to", "you requested"]

    def test_glc_llm_coherence_defaults(self):
        """GLCLLMCoherenceConfig has correct defaults."""
        c = GLCLLMCoherenceConfig()
        assert c.enabled is True
        assert c.enabled_for == ["must_escalate"]
        assert c.timeout_ms == 2000
        assert c.score_threshold == 0.6

    def test_constitution_defaults(self):
        """Constitution has version='1.0' and reasoning=None by default."""
        c = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="test", domain="test"),
            provenance=Provenance(
                authored_by="dev@example.com",
                approved_by=["approver@example.com"],
                approval_date="2026-01-01",
                approval_method="manual-sign-off",
            ),
            boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        )
        assert c.version == "1.0"
        assert c.reasoning is None
