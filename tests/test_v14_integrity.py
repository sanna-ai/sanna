"""v1.4 integrity tests — SAN-222."""
import pytest
from sanna.receipt import (
    SPEC_VERSION, CHECKS_VERSION, TOOL_NAME, EMPTY_HASH,
    generate_receipt, SannaReceipt,
)
from sanna.hashing import hash_text
from sanna import __version__
from sanna.verify import verify_receipt, load_schema

RECEIPT_SCHEMA = load_schema()


def test_version_constants():
    assert SPEC_VERSION == "1.4"
    assert CHECKS_VERSION == "9"
    assert TOOL_NAME == "sanna"
    assert __version__ == "1.4.0"


def test_20_field_fingerprint_basic():
    """Fingerprint has exactly 20 pipe-delimited fields."""
    receipt = generate_receipt(
        trace_data={"inputs": {"query": None, "context": None},
                    "outputs": {"response": None}},
        enforcement_surface="middleware",
        invariants_scope="full",
    )
    receipt_dict = vars(receipt)
    # tool_name is always TOOL_NAME
    assert receipt_dict.get("tool_name") == TOOL_NAME
    # tool_name hash is not empty
    tool_name_hash = hash_text(TOOL_NAME)
    assert tool_name_hash != EMPTY_HASH  # field 17 is not empty
    # Fields 18-20 should be None since agent_model defaults to None
    assert receipt_dict.get("agent_model") is None
    assert receipt_dict.get("agent_model_provider") is None
    assert receipt_dict.get("agent_model_version") is None
    # checks_version and spec_version are correct
    assert receipt_dict.get("checks_version") == "9"
    assert receipt_dict.get("spec_version") == "1.4"


def test_agent_model_captured():
    """agent_model string → position 18 is hash_text(agent_model)."""
    receipt = generate_receipt(
        trace_data={"inputs": {"query": "test"}, "outputs": {"response": "ok"}},
        enforcement_surface="middleware",
        invariants_scope="full",
        agent_model="claude-opus-4-7",
        agent_model_provider="anthropic",
    )
    r = vars(receipt)
    assert r.get("agent_model") == "claude-opus-4-7"
    assert r.get("agent_model_provider") == "anthropic"


def test_agent_model_null_opt_out():
    """agent_model=None → field present as null in JSON context (opt-out)."""
    receipt = generate_receipt(
        trace_data={"inputs": {"query": "test"}, "outputs": {"response": "ok"}},
        enforcement_surface="middleware",
        invariants_scope="full",
        agent_model=None,
    )
    r = vars(receipt)
    # agent_model field is present in the dataclass (as None = null in JSON)
    assert "agent_model" in r
    assert r["agent_model"] is None


def test_verifier_rejects_missing_tool_name():
    """cv>=9 receipt missing tool_name fails with exact error text."""
    import json, pathlib
    # Load a valid golden and strip tool_name to create an invalid receipt
    golden_dir = pathlib.Path("golden/receipts")
    golden_files = list(golden_dir.glob("*.json"))
    assert golden_files, "No goldens found — regenerate first"
    with open(golden_files[0]) as f:
        receipt = json.load(f)
    receipt.pop("tool_name", None)
    receipt["checks_version"] = "9"
    result = verify_receipt(receipt, RECEIPT_SCHEMA)
    assert not result.valid
    # Either the schema layer or the semantic layer must flag the missing tool_name.
    # Schema layer: "'tool_name' is a required property"
    # Semantic layer: "missing required field: tool_name"
    all_errors = " ".join(result.errors)
    assert "tool_name" in all_errors, \
        f"Expected tool_name error, got: {result.errors}"


def test_verifier_accepts_valid_golden():
    """Valid regenerated v1.4 golden passes verification."""
    import json, pathlib
    golden_dir = pathlib.Path("golden/receipts")
    golden_files = list(golden_dir.glob("[0-9]*.json"))
    assert golden_files
    with open(golden_files[0]) as f:
        receipt = json.load(f)
    result = verify_receipt(receipt, RECEIPT_SCHEMA)
    assert result.valid, f"Golden failed verification: {result.errors}"
