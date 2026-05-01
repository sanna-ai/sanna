"""SAN-385: wire-format tests for cv=9 vs cv=10 emission shape.

Asserts that:
- cv=9 emission via generate_receipt(trace) + receipt_to_dict has no agent_identity key
- cv=10 emission via generate_receipt(trace, agent_identity={...}) + receipt_to_dict
  has agent_identity key with non-null dict value
- Both pass strict schema validation (no verifier-side None-strip)
- Wire JSON for cv=9 emissions matches the spec/fixtures/receipts/archive/v1.4/ shape
  (agent_identity absent, not null)
"""
import json
from pathlib import Path
import pytest
from jsonschema import validate as jsonschema_validate, ValidationError
from sanna.receipt import generate_receipt, receipt_to_dict


SCHEMA = json.loads(Path(__file__).parent.parent.joinpath("src/sanna/spec/receipt.schema.json").read_text())


def _trace():
    return {
        "correlation_id": "wire-format-test",
        "observations": [],
        "output": {"final_answer": "test"},
        "input": "",
    }


def test_cv9_emission_omits_agent_identity():
    """cv=9 wire JSON must NOT contain agent_identity key (spec Section 2.19 line 780)."""
    receipt = generate_receipt(_trace(), enforcement_surface="middleware", invariants_scope="full")
    d = receipt_to_dict(receipt)
    assert "agent_identity" not in d, (
        "cv=9 wire JSON contains agent_identity key; "
        "spec Section 2.19 requires field to be absent at cv<=9"
    )
    assert d["checks_version"] == "9"
    assert d["spec_version"] == "1.4"


def test_cv10_emission_includes_agent_identity():
    """cv=10 wire JSON MUST contain agent_identity dict (spec Section 2.19, SAN-204 schema rule)."""
    ai = {"agent_session_id": "test-session-cv10"}
    receipt = generate_receipt(
        _trace(),
        agent_identity=ai,
        enforcement_surface="gateway",
        invariants_scope="full",
    )
    d = receipt_to_dict(receipt)
    assert "agent_identity" in d
    assert d["agent_identity"] == ai
    assert d["checks_version"] == "10"
    assert d["spec_version"] == "1.5"


def test_cv9_strict_schema_validation():
    """cv=9 wire JSON via receipt_to_dict passes strict jsonschema validation."""
    receipt = generate_receipt(_trace(), enforcement_surface="middleware", invariants_scope="full")
    d = receipt_to_dict(receipt)
    jsonschema_validate(d, SCHEMA)  # raises if invalid


def test_cv10_strict_schema_validation():
    """cv=10 wire JSON via receipt_to_dict passes strict jsonschema validation."""
    ai = {"agent_session_id": "test-session-strict"}
    receipt = generate_receipt(_trace(), agent_identity=ai, enforcement_surface="gateway", invariants_scope="full")
    d = receipt_to_dict(receipt)
    jsonschema_validate(d, SCHEMA)


def test_cv9_emission_matches_archive_shape():
    """Post-SAN-385 cv=9 wire format must mirror pre-Prompt-B archive cv=9 fixtures.

    Specifically: agent_identity absent (not null), checks_version=9, spec_version=1.4.
    Other Optional fields may be null per schema's nullable type (existing pattern).
    """
    receipt = generate_receipt(_trace(), enforcement_surface="middleware", invariants_scope="full")
    d = receipt_to_dict(receipt)
    archive = json.loads(Path("spec/fixtures/receipts/archive/v1.4/full-featured.json").read_text())

    # Both must lack agent_identity at the wire level
    assert "agent_identity" not in d
    assert "agent_identity" not in archive
    # Both must be cv=9
    assert d["checks_version"] == "9"
    assert archive["checks_version"] == "9"


def test_plain_asdict_includes_agent_identity_null_regression():
    """Document the SAN-370 Prompt B regression: plain asdict(receipt) DOES include agent_identity:null.

    receipt_to_dict() exists to fix this. This test asserts the regression is real
    and that receipt_to_dict() is required for cv=9 emissions.
    """
    from dataclasses import asdict
    receipt = generate_receipt(_trace(), enforcement_surface="middleware", invariants_scope="full")
    d_plain = asdict(receipt)
    d_via_helper = receipt_to_dict(receipt)
    # Plain asdict has the null
    assert "agent_identity" in d_plain
    assert d_plain["agent_identity"] is None
    # Helper strips
    assert "agent_identity" not in d_via_helper
    # Strict schema rejects the plain version
    with pytest.raises(ValidationError, match="None is not of type 'object'"):
        jsonschema_validate(d_plain, SCHEMA)
    # Strict schema accepts the helper version
    jsonschema_validate(d_via_helper, SCHEMA)
