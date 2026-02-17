"""
Sanna MCP server test suite.

Tests cover: receipt verification (valid + tampered), receipt generation
(with and without constitution), check listing, and the evaluate_action stub.

Tools are invoked directly as Python functions — no transport layer needed.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.mcp.server import (
    sanna_verify_receipt,
    sanna_generate_receipt,
    sanna_list_checks,
    sanna_evaluate_action,
    sanna_check_constitution_approval,
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

    def test_oversized_action_params_rejected(self):
        """action_params over 100KB should be rejected."""
        big_params = {"data": "x" * 100_001}
        result = json.loads(sanna_evaluate_action(
            action_name="test",
            action_params=big_params,
            constitution_path=WITH_AUTHORITY_CONST,
        ))
        assert "error" in result
        assert "too large" in result["error"].lower()
        assert result["decision"] is None


# =============================================================================
# 7. Server object
# =============================================================================

class TestServerObject:
    def test_server_name(self):
        assert mcp.name == "sanna_mcp"


# =============================================================================
# 8. sanna_query_receipts
# =============================================================================

from sanna.mcp.server import sanna_query_receipts
from sanna.store import ReceiptStore


def _store_receipt(store, agent_name, status="PASS", ts_offset_h=0):
    """Build and save a minimal receipt to the store."""
    from datetime import datetime, timedelta, timezone
    ts = datetime.now(timezone.utc) - timedelta(hours=ts_offset_h)
    receipt = {
        "receipt_id": f"r-{agent_name}-{ts_offset_h}-{status}",
        "trace_id": f"t-{ts_offset_h}",
        "timestamp": ts.isoformat(),
        "coherence_status": status,
        "constitution_ref": {
            "document_id": f"{agent_name}/v1",
            "policy_hash": "abc123",
        },
        "checks": [
            {
                "check_id": "C1",
                "name": "Context Contradiction",
                "passed": status == "PASS",
                "status": status,
                "severity": "critical",
                "evidence": {},
                "details": "",
            }
        ],
    }
    store.save(receipt)


class TestQueryReceipts:
    def test_missing_db_returns_error(self):
        result = json.loads(sanna_query_receipts(db_path="/nonexistent/db.sqlite"))
        assert "error" in result
        assert "not found" in result["error"]

    def test_query_returns_receipts(self, tmp_path):
        db = str(tmp_path / "test.db")
        store = ReceiptStore(db)
        _store_receipt(store, "test-agent")
        store.close()

        result = json.loads(sanna_query_receipts(db_path=db))
        assert result["count"] == 1
        assert len(result["receipts"]) == 1

    def test_query_filter_by_agent(self, tmp_path):
        db = str(tmp_path / "test.db")
        store = ReceiptStore(db)
        _store_receipt(store, "agent-a")
        _store_receipt(store, "agent-b")
        store.close()

        result = json.loads(sanna_query_receipts(db_path=db, agent_id="agent-a"))
        assert result["count"] == 1
        assert result["receipts"][0]["constitution_ref"]["document_id"].startswith("agent-a")

    def test_query_filter_by_status(self, tmp_path):
        db = str(tmp_path / "test.db")
        store = ReceiptStore(db)
        _store_receipt(store, "agent-a", status="PASS")
        _store_receipt(store, "agent-a", status="FAIL", ts_offset_h=1)
        store.close()

        result = json.loads(sanna_query_receipts(db_path=db, status="FAIL"))
        assert result["count"] == 1
        assert result["receipts"][0]["coherence_status"] == "FAIL"

    def test_query_limit(self, tmp_path):
        db = str(tmp_path / "test.db")
        store = ReceiptStore(db)
        for i in range(10):
            _store_receipt(store, "agent-a", ts_offset_h=i)
        store.close()

        result = json.loads(sanna_query_receipts(db_path=db, limit=3))
        assert result["count"] == 3
        assert result["truncated"] is True

    def test_query_drift_analysis(self, tmp_path):
        db = str(tmp_path / "test.db")
        store = ReceiptStore(db)
        for i in range(6):
            _store_receipt(store, "agent-a", status="PASS" if i % 2 == 0 else "FAIL", ts_offset_h=i)
        store.close()

        result = json.loads(sanna_query_receipts(db_path=db, analysis="drift"))
        assert result["analysis"] == "drift"
        assert "report" in result
        assert "fleet_status" in result["report"]

    def test_query_halt_only(self, tmp_path):
        db = str(tmp_path / "test.db")
        store = ReceiptStore(db)
        # Save a non-halt receipt
        _store_receipt(store, "agent-a")
        # Save a halt receipt
        halt_receipt = {
            "receipt_id": "r-halt-1",
            "trace_id": "t-halt",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "coherence_status": "FAIL",
            "constitution_ref": {
                "document_id": "agent-a/v1",
                "policy_hash": "abc123",
            },
            "halt_event": {"halted": True, "reason": "test"},
            "checks": [],
        }
        store.save(halt_receipt)
        store.close()

        result = json.loads(sanna_query_receipts(db_path=db, halt_only=True))
        assert result["count"] == 1


# =============================================================================
# 9. sanna_check_constitution_approval
# =============================================================================

from sanna.constitution import (
    Constitution,
    AgentIdentity,
    Provenance,
    Boundary,
    Invariant,
    sign_constitution,
    save_constitution,
    approve_constitution,
)
from sanna.crypto import generate_keypair


@pytest.fixture()
def approved_constitution(tmp_path):
    """Create a signed and approved constitution for MCP tests."""
    author_priv, author_pub = generate_keypair(tmp_path / "author_keys")
    approver_priv, approver_pub = generate_keypair(tmp_path / "approver_keys")

    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="mcp-test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="alice@corp.com",
            approved_by=["bob@corp.com"],
            approval_date="2026-01-15",
            approval_method="manual",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
    )
    signed = sign_constitution(const, private_key_path=str(author_priv))
    const_path = tmp_path / "approved.yaml"
    save_constitution(signed, const_path)
    approve_constitution(const_path, approver_priv, "bob@corp.com", "VP Compliance", "1.0")

    return {
        "const_path": str(const_path),
        "author_priv": author_priv,
        "author_pub": author_pub,
        "approver_priv": approver_priv,
        "approver_pub": approver_pub,
        "tmp_path": tmp_path,
    }


@pytest.fixture()
def unapproved_constitution(tmp_path):
    """Create a signed but NOT approved constitution for MCP tests."""
    author_priv, author_pub = generate_keypair(tmp_path / "keys")
    const = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="unapproved-agent", domain="testing"),
        provenance=Provenance(
            authored_by="alice@corp.com",
            approved_by=["bob@corp.com"],
            approval_date="2026-01-15",
            approval_method="manual",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="high")],
        invariants=[Invariant(id="INV_NO_FABRICATION", rule="No fabrication", enforcement="halt")],
    )
    signed = sign_constitution(const, private_key_path=str(author_priv))
    const_path = tmp_path / "unapproved.yaml"
    save_constitution(signed, const_path)

    return {"const_path": str(const_path), "tmp_path": tmp_path}


class TestCheckConstitutionApproval:
    def test_approved_constitution_returns_approved_true(self, approved_constitution):
        """Tool returns approved=true for valid approved constitution."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
        ))
        assert result["approved"] is True
        assert result["approver_id"] == "bob@corp.com"
        assert result["approver_role"] == "VP Compliance"
        assert result["constitution_version"] == "1.0"

    def test_unapproved_constitution_returns_approved_false(self, unapproved_constitution):
        """Tool returns approved=false for unapproved constitution."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=unapproved_constitution["const_path"],
        ))
        assert result["approved"] is False
        assert "no approval record" in result["reason"].lower()

    def test_content_hash_valid_when_untampered(self, approved_constitution):
        """Tool returns content_hash_valid=true when content matches."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
        ))
        assert result["content_hash_valid"] is True

    def test_content_hash_invalid_when_tampered(self, approved_constitution):
        """Tool returns content_hash_valid=false when content modified."""
        import yaml
        const_path = Path(approved_constitution["const_path"])
        data = yaml.safe_load(const_path.read_text())
        # Tamper: change the agent name
        data["identity"]["agent_name"] = "tampered-agent"
        const_path.write_text(yaml.dump(data, default_flow_style=False))

        result = json.loads(sanna_check_constitution_approval(
            constitution_path=str(const_path),
        ))
        assert result["approved"] is False
        assert "modified" in result["reason"].lower() or "mismatch" in result["reason"].lower()

    def test_missing_constitution_returns_error(self):
        """Tool handles missing constitution gracefully."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path="/nonexistent/constitution.yaml",
        ))
        assert result["approved"] is False
        assert "not found" in result["reason"].lower()

    def test_author_signature_present(self, approved_constitution):
        """Tool reports author signature present/verified structure."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
        ))
        assert result["author_signature"]["present"] is True
        # No key provided → verified is null
        assert result["author_signature"]["verified"] is None

    def test_approved_at_is_iso8601(self, approved_constitution):
        """Approval timestamp is a valid ISO 8601 string."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
        ))
        assert result["approved"] is True
        from datetime import datetime
        datetime.fromisoformat(result["approved_at"])

    def test_tool_output_is_valid_json(self, approved_constitution):
        """Tool output is valid JSON with expected keys."""
        raw = sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
        )
        result = json.loads(raw)
        for key in ("approved", "approver_id", "approver_role", "approved_at",
                     "constitution_version", "content_hash_valid",
                     "author_signature", "approval_signature"):
            assert key in result, f"Missing key: {key}"

    def test_tool_registered_in_server(self):
        """Tool is registered in the MCP server tool list."""
        assert callable(sanna_check_constitution_approval)

    def test_unapproved_still_reports_author_signature(self, unapproved_constitution):
        """Unapproved constitution still reports author signature status."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=unapproved_constitution["const_path"],
        ))
        assert result["approved"] is False
        assert "author_signature" in result
        assert result["author_signature"]["present"] is True

    # --- CRITICAL-2: Signature verification tests ---

    def test_no_keys_verified_is_null(self, approved_constitution):
        """With no keys provided, verified fields are null."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
        ))
        assert result["approved"] is True
        assert result["author_signature"]["verified"] is None
        assert result["approval_signature"]["verified"] is None

    def test_author_key_verifies_author_signature(self, approved_constitution):
        """With author key, author signature is verified."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
            author_public_key_path=str(approved_constitution["author_pub"]),
        ))
        assert result["approved"] is True
        assert result["author_signature"]["verified"] is True

    def test_approver_key_verifies_approval_signature(self, approved_constitution):
        """With approver key, approval signature is verified."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
            approver_public_key_path=str(approved_constitution["approver_pub"]),
        ))
        assert result["approved"] is True
        assert result["approval_signature"]["verified"] is True

    def test_both_keys_full_verification(self, approved_constitution):
        """With both keys, full verification."""
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
            author_public_key_path=str(approved_constitution["author_pub"]),
            approver_public_key_path=str(approved_constitution["approver_pub"]),
        ))
        assert result["approved"] is True
        assert result["author_signature"]["verified"] is True
        assert result["approval_signature"]["verified"] is True

    def test_forged_approval_empty_sig_returns_false(self, approved_constitution):
        """Forged approval with empty signature returns approved=false."""
        import yaml
        const_path = Path(approved_constitution["const_path"])
        data = yaml.safe_load(const_path.read_text())
        data["approval"]["records"][0]["approval_signature"] = ""
        const_path.write_text(yaml.dump(data, default_flow_style=False))

        result = json.loads(sanna_check_constitution_approval(
            constitution_path=str(const_path),
        ))
        assert result["approved"] is False
        assert "missing" in result["reason"].lower() or "empty" in result["reason"].lower()

    def test_wrong_approver_key_fails_verification(self, approved_constitution):
        """Wrong approver key fails approval signature verification."""
        # Use author key as approver key (wrong key)
        result = json.loads(sanna_check_constitution_approval(
            constitution_path=approved_constitution["const_path"],
            approver_public_key_path=str(approved_constitution["author_pub"]),
        ))
        assert result["approved"] is False
        assert result["approval_signature"]["verified"] is False
