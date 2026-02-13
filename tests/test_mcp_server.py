"""
Sanna MCP server test suite.

Tests cover: receipt verification (valid + tampered), receipt generation
(with and without constitution), check listing, and the evaluate_action stub.

Tools are invoked directly as Python functions — no transport layer needed.
"""

import json
from pathlib import Path

import pytest

from sanna.mcp.server import (
    sanna_verify_receipt,
    sanna_generate_receipt,
    sanna_list_checks,
    sanna_evaluate_action,
    mcp,
)

# =============================================================================
# PATHS
# =============================================================================

GOLDEN_DIR = Path(__file__).parent.parent / "golden" / "receipts"
CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
ALL_WARN_CONST = str(CONSTITUTIONS_DIR / "all_warn.yaml")
WITH_AUTHORITY_CONST = str(CONSTITUTIONS_DIR / "with_authority.yaml")


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def valid_receipt_json() -> str:
    """Load golden receipt 002 (PASS) as JSON string."""
    path = GOLDEN_DIR / "002_pass_simple_qa.json"
    return path.read_text()


@pytest.fixture()
def tampered_receipt_json() -> str:
    """Load golden receipt 999 (tampered output) as JSON string."""
    path = GOLDEN_DIR / "999_tampered.json"
    return path.read_text()


# =============================================================================
# 1. sanna_verify_receipt — valid receipt
# =============================================================================

class TestVerifyReceiptValid:
    def test_valid_receipt_returns_valid(self, valid_receipt_json: str):
        result_json = sanna_verify_receipt(receipt_json=valid_receipt_json)
        result = json.loads(result_json)

        assert result["valid"] is True
        assert result["exit_code"] == 0
        assert result["errors"] == []

    def test_valid_receipt_has_matching_fingerprints(self, valid_receipt_json: str):
        result = json.loads(sanna_verify_receipt(receipt_json=valid_receipt_json))

        assert result["computed_fingerprint"] is not None
        assert result["computed_fingerprint"] == result["expected_fingerprint"]


# =============================================================================
# 2. sanna_verify_receipt — tampered receipt
# =============================================================================

class TestVerifyReceiptTampered:
    def test_tampered_receipt_returns_invalid(self, tampered_receipt_json: str):
        result_json = sanna_verify_receipt(receipt_json=tampered_receipt_json)
        result = json.loads(result_json)

        assert result["valid"] is False
        assert result["exit_code"] != 0
        assert len(result["errors"]) > 0

    def test_tampered_receipt_detects_content_hash_mismatch(self, tampered_receipt_json: str):
        result = json.loads(sanna_verify_receipt(receipt_json=tampered_receipt_json))

        # Tampered receipt has modified outputs, so output_hash or fingerprint won't match
        error_text = " ".join(result["errors"]).lower()
        assert "mismatch" in error_text or "tamper" in error_text

    def test_invalid_json_returns_error(self):
        result = json.loads(sanna_verify_receipt(receipt_json="not valid json"))

        assert result["valid"] is False
        assert result["exit_code"] == 5
        assert any("Invalid JSON" in e for e in result["errors"])


# =============================================================================
# 3. sanna_generate_receipt — without constitution
# =============================================================================

class TestGenerateReceipt:
    def test_returns_parseable_receipt_json(self):
        result_json = sanna_generate_receipt(
            query="What is the capital of France?",
            context="France is a country in Europe. Its capital is Paris.",
            response="The capital of France is Paris.",
        )
        receipt = json.loads(result_json)

        assert isinstance(receipt, dict)
        assert "receipt_id" in receipt
        assert "receipt_fingerprint" in receipt
        assert "coherence_status" in receipt
        assert "trace_id" in receipt
        assert receipt["trace_id"].startswith("mcp-")

    def test_no_constitution_produces_empty_checks(self):
        result_json = sanna_generate_receipt(
            query="test query",
            context="test context",
            response="test response",
        )
        receipt = json.loads(result_json)

        assert receipt["checks"] == []
        assert receipt["checks_passed"] == 0
        assert receipt["checks_failed"] == 0
        assert receipt["coherence_status"] == "PASS"
        assert receipt["constitution_ref"] is None

    def test_generated_receipt_verifies(self):
        """A freshly generated receipt should pass verification."""
        from sanna.verify import verify_receipt, load_schema

        result_json = sanna_generate_receipt(
            query="What is the capital of France?",
            context="France is a country in Europe. Its capital is Paris.",
            response="The capital of France is Paris.",
        )
        receipt = json.loads(result_json)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Generated receipt failed verification: {result.errors}"


# =============================================================================
# 4. sanna_generate_receipt — with constitution
# =============================================================================

class TestGenerateReceiptWithConstitution:
    def test_constitution_driven_checks_run(self):
        result_json = sanna_generate_receipt(
            query="What is the capital of France?",
            context="France is a country in Europe. Its capital is Paris.",
            response="The capital of France is Paris.",
            constitution_path=ALL_WARN_CONST,
        )
        receipt = json.loads(result_json)

        # all_warn.yaml has 5 invariants → 5 checks
        assert len(receipt["checks"]) == 5
        assert receipt["constitution_ref"] is not None
        assert receipt["constitution_ref"]["policy_hash"] is not None

    def test_constitution_checks_have_enforcement_fields(self):
        result_json = sanna_generate_receipt(
            query="query",
            context="context",
            response="response",
            constitution_path=ALL_WARN_CONST,
        )
        receipt = json.loads(result_json)

        for check in receipt["checks"]:
            assert "triggered_by" in check
            assert "enforcement_level" in check
            assert check["enforcement_level"] == "warn"
            assert check["triggered_by"].startswith("INV_")

    def test_constitution_receipt_verifies(self):
        """A constitution-driven receipt should pass verification."""
        from sanna.verify import verify_receipt, load_schema

        result_json = sanna_generate_receipt(
            query="What is the capital of France?",
            context="France is a country in Europe. Its capital is Paris.",
            response="The capital of France is Paris.",
            constitution_path=ALL_WARN_CONST,
        )
        receipt = json.loads(result_json)
        schema = load_schema()
        result = verify_receipt(receipt, schema)

        assert result.valid, f"Constitution receipt failed verification: {result.errors}"

    def test_invalid_constitution_path_returns_error(self):
        result_json = sanna_generate_receipt(
            query="q",
            context="c",
            response="r",
            constitution_path="/nonexistent/constitution.yaml",
        )
        result = json.loads(result_json)

        assert "error" in result
        assert result["receipt"] is None


# =============================================================================
# 5. sanna_list_checks
# =============================================================================

class TestListChecks:
    def test_returns_all_five_checks(self):
        result_json = sanna_list_checks()
        checks = json.loads(result_json)

        assert isinstance(checks, list)
        assert len(checks) == 5

    def test_check_ids_are_c1_through_c5(self):
        checks = json.loads(sanna_list_checks())
        check_ids = [c["check_id"] for c in checks]

        assert check_ids == ["C1", "C2", "C3", "C4", "C5"]

    def test_each_check_has_required_fields(self):
        checks = json.loads(sanna_list_checks())

        for check in checks:
            assert "check_id" in check
            assert "name" in check
            assert "invariant" in check
            assert "check_impl" in check
            assert "description" in check
            assert "default_severity" in check
            assert "default_enforcement" in check

    def test_check_invariant_mapping(self):
        checks = json.loads(sanna_list_checks())
        mapping = {c["check_id"]: c["invariant"] for c in checks}

        assert mapping["C1"] == "INV_NO_FABRICATION"
        assert mapping["C2"] == "INV_MARK_INFERENCE"
        assert mapping["C3"] == "INV_NO_FALSE_CERTAINTY"
        assert mapping["C4"] == "INV_PRESERVE_TENSION"
        assert mapping["C5"] == "INV_NO_PREMATURE_COMPRESSION"

    def test_c1_is_critical_severity(self):
        checks = json.loads(sanna_list_checks())
        c1 = next(c for c in checks if c["check_id"] == "C1")

        assert c1["default_severity"] == "critical"
        assert c1["default_enforcement"] == "halt"


# =============================================================================
# 6. sanna_evaluate_action — real authority enforcement
# =============================================================================

class TestEvaluateAction:
    def test_forbidden_action_returns_halt(self):
        result = json.loads(sanna_evaluate_action(
            action_name="delete_database",
            action_params={},
            constitution_path=WITH_AUTHORITY_CONST,
        ))

        assert result["decision"] == "halt"
        assert result["boundary_type"] == "cannot_execute"
        assert result["action_name"] == "delete_database"

    def test_allowed_action_returns_allow(self):
        result = json.loads(sanna_evaluate_action(
            action_name="query_database",
            action_params={},
            constitution_path=WITH_AUTHORITY_CONST,
        ))

        assert result["decision"] == "allow"
        assert result["boundary_type"] == "can_execute"

    def test_escalation_action_returns_escalate(self):
        result = json.loads(sanna_evaluate_action(
            action_name="refund",
            action_params={"amount": 5000, "threshold": 1000},
            constitution_path=WITH_AUTHORITY_CONST,
        ))

        assert result["decision"] == "escalate"
        assert result["boundary_type"] == "must_escalate"
        assert result["escalation_target"] is not None
        assert result["escalation_target"]["type"] == "log"

    def test_uncategorized_action_returns_allow(self):
        result = json.loads(sanna_evaluate_action(
            action_name="some_unknown_action",
            action_params={},
            constitution_path=WITH_AUTHORITY_CONST,
        ))

        assert result["decision"] == "allow"
        assert result["boundary_type"] == "uncategorized"

    def test_invalid_constitution_path_returns_error(self):
        result = json.loads(sanna_evaluate_action(
            action_name="anything",
            action_params={},
            constitution_path="/nonexistent/constitution.yaml",
        ))

        assert "error" in result
        assert result["decision"] is None

    def test_no_authority_boundaries_returns_allow(self):
        """Constitution without authority_boundaries allows everything."""
        result = json.loads(sanna_evaluate_action(
            action_name="delete_database",
            action_params={},
            constitution_path=ALL_WARN_CONST,
        ))

        assert result["decision"] == "allow"
        assert result["boundary_type"] == "uncategorized"

    def test_result_includes_constitution_path(self):
        result = json.loads(sanna_evaluate_action(
            action_name="query_database",
            action_params={},
            constitution_path=WITH_AUTHORITY_CONST,
        ))

        assert result["constitution_path"] == WITH_AUTHORITY_CONST


# =============================================================================
# 7. Server object
# =============================================================================

class TestServerObject:
    def test_server_name(self):
        assert mcp.name == "sanna_mcp"
