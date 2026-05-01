"""v1.5 integrity tests -- SAN-370 cv-dispatch + agent_identity emission."""
import pytest
from dataclasses import asdict
from sanna.receipt import (
    SPEC_VERSION, CHECKS_VERSION, TOOL_NAME, EMPTY_HASH,
    generate_receipt,
)
from sanna import __version__
from sanna.verify import verify_receipt, load_schema

RECEIPT_SCHEMA = load_schema()

TRACE = {
    "correlation_id": "v15-test-01",
    "observations": [],
    "output": {"final_answer": "ok"},
    "input": "test",
}
AGENT_IDENTITY = {"agent_session_id": "test-session-abc123"}


def test_sdk_constants():
    assert SPEC_VERSION == "1.5"
    assert CHECKS_VERSION == "10"
    assert __version__ == "1.5.0"


def test_cv10_receipt_emitted_with_agent_identity():
    """generate_receipt with agent_identity emits cv=10/sv=1.5 with agent_identity field."""
    receipt = generate_receipt(
        TRACE,
        agent_identity=AGENT_IDENTITY,
        enforcement_surface="gateway",
        invariants_scope="full",
    )
    d = asdict(receipt)
    assert d["checks_version"] == "10"
    assert d["spec_version"] == "1.5"
    assert d["agent_identity"] == AGENT_IDENTITY
    assert d["tool_version"] == "1.5.0"


def test_cv10_receipt_verifies():
    """cv=10 receipt passes verifier fingerprint + required-field checks."""
    receipt = generate_receipt(
        TRACE,
        agent_identity=AGENT_IDENTITY,
        enforcement_surface="gateway",
        invariants_scope="full",
    )
    d = asdict(receipt)
    result = verify_receipt(d, RECEIPT_SCHEMA)
    assert result.valid, result.errors


def test_cv9_legacy_emitted_without_agent_identity():
    """generate_receipt without agent_identity emits cv=9/sv=1.4 legacy."""
    receipt = generate_receipt(
        TRACE,
        enforcement_surface="middleware",
        invariants_scope="full",
    )
    d = asdict(receipt)
    assert d["checks_version"] == "9"
    assert d["spec_version"] == "1.4"
    assert d.get("agent_identity") is None


def test_cv9_legacy_verifies():
    """cv=9 legacy receipt passes verifier (20-field formula preserved)."""
    receipt = generate_receipt(
        TRACE,
        enforcement_surface="middleware",
        invariants_scope="full",
    )
    d = asdict(receipt)
    result = verify_receipt(d, RECEIPT_SCHEMA)
    assert result.valid, result.errors


def test_verifier_rejects_cv10_missing_agent_identity():
    """cv=10 receipt missing agent_identity fails with exact error text."""
    receipt = generate_receipt(
        TRACE,
        agent_identity=AGENT_IDENTITY,
        enforcement_surface="gateway",
        invariants_scope="full",
    )
    d = asdict(receipt)
    d.pop("agent_identity")
    result = verify_receipt(d, RECEIPT_SCHEMA)
    assert not result.valid
    all_errors = " ".join(result.errors)
    assert "agent_identity" in all_errors, f"Expected agent_identity error, got: {result.errors}"


def test_verifier_rejects_cv10_missing_agent_session_id():
    """cv=10 receipt with agent_identity missing agent_session_id fails."""
    receipt = generate_receipt(
        TRACE,
        agent_identity=AGENT_IDENTITY,
        enforcement_surface="gateway",
        invariants_scope="full",
    )
    d = asdict(receipt)
    d["agent_identity"] = {"role": "test-role"}
    result = verify_receipt(d, RECEIPT_SCHEMA)
    assert not result.valid
    all_errors = " ".join(result.errors)
    assert "agent_session_id" in all_errors, f"Expected agent_session_id error, got: {result.errors}"


def test_generate_receipt_raises_if_agent_identity_missing_session_id():
    """ValueError raised when agent_identity lacks agent_session_id."""
    with pytest.raises(ValueError, match="agent_session_id"):
        generate_receipt(
            TRACE,
            agent_identity={},
            enforcement_surface="gateway",
            invariants_scope="full",
        )


def test_generate_receipt_raises_if_agent_identity_session_id_empty():
    """ValueError raised when agent_identity has empty agent_session_id."""
    with pytest.raises(ValueError, match="agent_session_id"):
        generate_receipt(
            TRACE,
            agent_identity={"role": "x"},
            enforcement_surface="gateway",
            invariants_scope="full",
        )


def test_cv_dispatch_parity():
    """Verifier accepts both cv=9 (legacy) and cv=10 (modern) receipts."""
    r10 = asdict(generate_receipt(
        TRACE, agent_identity=AGENT_IDENTITY,
        enforcement_surface="gateway", invariants_scope="full",
    ))
    r9 = asdict(generate_receipt(
        TRACE, enforcement_surface="middleware", invariants_scope="full",
    ))
    assert verify_receipt(r10, RECEIPT_SCHEMA).valid
    assert verify_receipt(r9, RECEIPT_SCHEMA).valid
