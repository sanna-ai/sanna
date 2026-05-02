"""SAN-369: MODIFY authority_decisions[i] recording infrastructure.

Tests the build_modify_authority_decision helper and schema validation
of MODIFY records (decision=modify_with_constraints requires the three
recording fields per A1' conditional rule).
"""
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

from sanna.enforcement.authority import build_modify_authority_decision
from sanna.enforcement import configure_checks
from sanna.constitution import load_constitution, constitution_to_receipt_ref
from sanna.hashing import hash_obj
from sanna.middleware import _build_trace_data, _generate_constitution_receipt
from sanna.verify import load_schema


SCHEMA = load_schema()
CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"


def _full_receipt_with_authority_decision(authority_decision: dict) -> dict:
    """Embed a single authority_decisions entry in an otherwise valid cv=10 receipt."""
    constitution = load_constitution(
        str(CONSTITUTIONS_DIR / "with_authority.yaml"), validate=True
    )
    constitution_ref = constitution_to_receipt_ref(constitution)
    check_configs, custom_records = configure_checks(constitution)
    trace_data = _build_trace_data(
        correlation_id="san-369-test",
        query="test query",
        context="test context",
        output="modified-output",
    )
    return _generate_constitution_receipt(
        trace_data,
        check_configs=check_configs,
        custom_records=custom_records,
        constitution_ref=constitution_ref,
        constitution_version=constitution.schema_version,
        authority_decisions=[authority_decision],
        enforcement_surface="gateway",
        invariants_scope="full",
        agent_identity={"agent_session_id": "san-369-session"},
    )


def test_helper_produces_schema_valid_modify_record():
    record = build_modify_authority_decision(
        action="search-api",
        original={"query": "find user@example.com records"},
        transformed={"query": "find <REDACTED-EMAIL> records"},
        transformations=[
            {"type": "redact_pii", "target_field": "query", "rationale": "PII per AUTH-PII-01"}
        ],
        reason="PII redacted from query parameter",
    )
    assert record["decision"] == "modify_with_constraints"
    assert record["boundary_type"] == "can_execute"
    assert record["tool_input_original"] == {"query": "find user@example.com records"}
    assert record["tool_input_transformed"] == {"query": "find <REDACTED-EMAIL> records"}
    assert len(record["transformations_applied"]) == 1

    full = _full_receipt_with_authority_decision(record)
    validate(instance=full, schema=SCHEMA)


def test_modify_record_missing_tool_input_original_rejected():
    record = build_modify_authority_decision(
        action="x", original="orig", transformed="trans",
        transformations=[{"type": "redact", "target_field": "f", "rationale": "r"}],
    )
    record.pop("tool_input_original")
    full = _full_receipt_with_authority_decision(record)
    with pytest.raises(ValidationError):
        validate(instance=full, schema=SCHEMA)


def test_modify_record_missing_tool_input_transformed_rejected():
    record = build_modify_authority_decision(
        action="x", original="orig", transformed="trans",
        transformations=[{"type": "redact", "target_field": "f", "rationale": "r"}],
    )
    record.pop("tool_input_transformed")
    full = _full_receipt_with_authority_decision(record)
    with pytest.raises(ValidationError):
        validate(instance=full, schema=SCHEMA)


def test_modify_record_missing_transformations_applied_rejected():
    record = build_modify_authority_decision(
        action="x", original="orig", transformed="trans",
        transformations=[{"type": "redact", "target_field": "f", "rationale": "r"}],
    )
    record.pop("transformations_applied")
    full = _full_receipt_with_authority_decision(record)
    with pytest.raises(ValidationError):
        validate(instance=full, schema=SCHEMA)


def test_helper_rejects_empty_transformations():
    with pytest.raises(ValueError, match="non-empty list"):
        build_modify_authority_decision(
            action="x", original="orig", transformed="trans", transformations=[],
        )


def test_helper_rejects_transformation_missing_rationale():
    with pytest.raises(ValueError, match="missing required keys"):
        build_modify_authority_decision(
            action="x", original="orig", transformed="trans",
            transformations=[{"type": "redact", "target_field": "f"}],
        )


def test_helper_rejects_transformation_with_extra_key():
    with pytest.raises(ValueError, match="unexpected keys"):
        build_modify_authority_decision(
            action="x", original="orig", transformed="trans",
            transformations=[{"type": "redact", "target_field": "f", "rationale": "r", "extra": "x"}],
        )


def test_helper_rejects_non_string_non_dict_original():
    with pytest.raises(ValueError, match="string or dict"):
        build_modify_authority_decision(
            action="x", original=123, transformed="trans",
            transformations=[{"type": "redact", "target_field": "f", "rationale": "r"}],
        )


def test_helper_produces_byte_identical_records_for_identical_inputs():
    """Two separate construction calls with identical inputs produce byte-equal records.

    Precondition for cross-SDK fixture byte-equal parity: Python and TypeScript
    helpers must produce identical authority_decisions[i] dicts for the same
    inputs. Validates deterministic construction within Python; cross-SDK
    parity is validated separately when the sanna-ts SAN-369 portion ships.
    """
    common = dict(
        action="api-search",
        original={"q": "x"},
        transformed={"q": "y"},
        transformations=[{"type": "t1", "target_field": "q", "rationale": "r1"}],
        reason="deterministic test",
        timestamp="2026-05-02T00:00:00+00:00",
    )
    record1 = build_modify_authority_decision(**common)
    record2 = build_modify_authority_decision(**common)
    assert record1 == record2, "Helper produced different records for identical inputs"
    assert hash_obj(record1) == hash_obj(record2), "Hash diverged for identical records"
