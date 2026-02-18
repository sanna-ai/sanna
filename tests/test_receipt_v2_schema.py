"""Tests for Receipt v2.0 schema — Receipt Triad and reasoning evaluation.

Covers: v2 receipt generation, triad determinism, hashing, signing,
backward compatibility with v1 receipts, validation, and canonical JSON.

Updated for v0.13.0 schema migration:
- Receipt Triad hashes are bare 64-hex strings (no ``sha256:`` prefix).
- ``schema_version`` → ``spec_version``
- ``correlation_id`` field (renamed from legacy trace_id)
- field renamed to ``status``
- ``enforcement`` field
- ``CHECKS_VERSION`` is now ``"5"``
- ``receipt_id`` is UUID v4
- ``full_fingerprint`` is new required field
- Extensions use reverse-domain notation (``com.sanna.gateway``).
"""

import asyncio
import hashlib
import json
import re
import sys
import textwrap

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.receipt_v2 import (
    ReceiptTriad,
    GatewayCheckResult,
    ReasoningEvaluation,
    ActionRecord,
    EnforcementRecord,
    GatewayApprovalRecord,
    SignatureRecord,
    GatewayReceiptV2,
    compute_receipt_triad,
    receipt_triad_to_dict,
    reasoning_evaluation_to_dict,
    gateway_receipt_v2_to_dict,
    validate_check_result,
    validate_reasoning_evaluation,
    validate_approval_record,
    RECEIPT_VERSION_2,
    VALID_CHECK_METHODS,
    VALID_ASSURANCE_LEVELS,
    VALID_OVERRIDE_REASONS,
    _canonical_json_for_triad,
)
from sanna.gateway.server import SannaGateway
from sanna.hashing import canonical_json_bytes


# =============================================================================
# MOCK SERVER SCRIPT
# =============================================================================

MOCK_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mock_downstream")

    @mcp.tool()
    def get_status() -> str:
        \"\"\"Get the current server status.\"\"\"
        return json.dumps({"status": "ok", "version": "1.0"})

    @mcp.tool()
    def search(query: str, limit: int = 10) -> str:
        \"\"\"Search for items matching a query.\"\"\"
        return json.dumps({"query": query, "limit": limit, "results": ["a", "b"]})

    @mcp.tool()
    def update_item(item_id: str, name: str) -> str:
        \"\"\"Update an item.\"\"\"
        return json.dumps({"updated": True, "item_id": item_id, "name": name})

    @mcp.tool()
    def delete_item(item_id: str) -> str:
        \"\"\"Delete an item by ID.\"\"\"
        return json.dumps({"deleted": True, "item_id": item_id})

    mcp.run(transport="stdio")
""")


# =============================================================================
# HELPERS
# =============================================================================

def _create_signed_constitution(
    tmp_path,
    authority_boundaries=None,
):
    """Create a signed constitution and keypair for testing."""
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution,
        AgentIdentity,
        Provenance,
        Boundary,
        sign_constitution,
        save_constitution,
    )

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    constitution = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@example.com",
            approved_by=["approver@example.com"],
            approval_date="2024-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope", severity="high"),
        ],
        authority_boundaries=authority_boundaries,
    )

    signed = sign_constitution(constitution, private_key_path=str(private_key_path))
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)

    return str(const_path), str(private_key_path), str(public_key_path)


@pytest.fixture()
def mock_server_path(tmp_path):
    """Write the mock server script to a temp file."""
    path = tmp_path / "mock_server.py"
    path.write_text(MOCK_SERVER_SCRIPT)
    return str(path)


@pytest.fixture()
def signed_constitution(tmp_path):
    """Create a signed constitution with authority boundaries."""
    from sanna.constitution import AuthorityBoundaries, EscalationRule

    ab = AuthorityBoundaries(
        cannot_execute=["delete_item"],
        must_escalate=[EscalationRule(condition="update")],
        can_execute=["get_status", "search"],
    )
    return _create_signed_constitution(tmp_path, authority_boundaries=ab)


# =============================================================================
# 1. RECEIPT TRIAD COMPUTATION
# =============================================================================

class TestReceiptTriad:
    def test_receipt_triad_deterministic(self):
        """Same input produces same triad hashes."""
        triad1 = compute_receipt_triad(
            "search", {"query": "hello", "limit": 10}, None,
        )
        triad2 = compute_receipt_triad(
            "search", {"query": "hello", "limit": 10}, None,
        )
        assert triad1.input_hash == triad2.input_hash
        assert triad1.reasoning_hash == triad2.reasoning_hash
        assert triad1.action_hash == triad2.action_hash

    def test_input_hash_equals_action_hash(self):
        """At gateway boundary, input_hash == action_hash."""
        triad = compute_receipt_triad(
            "search", {"query": "hello"}, "because it's relevant",
        )
        assert triad.input_hash == triad.action_hash
        assert triad.context_limitation == "gateway_boundary"

    def test_reasoning_hash_changes(self):
        """Different justification produces different reasoning_hash."""
        triad1 = compute_receipt_triad(
            "search", {"query": "hello"}, "reason A",
        )
        triad2 = compute_receipt_triad(
            "search", {"query": "hello"}, "reason B",
        )
        assert triad1.reasoning_hash != triad2.reasoning_hash
        # But input/action hashes unchanged
        assert triad1.input_hash == triad2.input_hash
        assert triad1.action_hash == triad2.action_hash

    def test_no_justification_hashes_empty_string(self):
        """None justification hashes as empty string."""
        triad_none = compute_receipt_triad("search", {"query": "x"}, None)
        triad_empty = compute_receipt_triad("search", {"query": "x"}, "")
        # Both None and "" should produce the same reasoning hash (bare 64-hex)
        expected = hashlib.sha256(b"").hexdigest()
        assert triad_none.reasoning_hash == expected
        assert triad_empty.reasoning_hash == expected

    def test_justification_stripped_from_input_hash(self):
        """_justification key is excluded from input/action hash."""
        args_with = {"query": "hello", "_justification": "because I said so"}
        args_without = {"query": "hello"}

        triad_with = compute_receipt_triad("search", args_with, "because I said so")
        triad_without = compute_receipt_triad("search", args_without, None)

        assert triad_with.input_hash == triad_without.input_hash

    def test_triad_hashes_are_bare_hex(self):
        """All triad hashes are bare 64-hex strings (no sha256: prefix)."""
        triad = compute_receipt_triad("tool", {"a": 1}, "reason")
        hex_pattern = re.compile(r"^[a-f0-9]{64}$")
        assert hex_pattern.match(triad.input_hash), f"input_hash not bare hex: {triad.input_hash}"
        assert hex_pattern.match(triad.reasoning_hash), f"reasoning_hash not bare hex: {triad.reasoning_hash}"
        assert hex_pattern.match(triad.action_hash), f"action_hash not bare hex: {triad.action_hash}"

    def test_triad_hashes_are_full_length(self):
        """Triad hashes are full SHA-256 (64 hex chars, bare)."""
        triad = compute_receipt_triad("tool", {"a": 1}, "reason")
        for h in [triad.input_hash, triad.reasoning_hash, triad.action_hash]:
            assert len(h) == 64, f"Expected 64 hex chars, got {len(h)}: {h}"

    def test_different_tools_different_hashes(self):
        """Different tool names produce different input hashes."""
        triad1 = compute_receipt_triad("tool_a", {"x": 1}, None)
        triad2 = compute_receipt_triad("tool_b", {"x": 1}, None)
        assert triad1.input_hash != triad2.input_hash

    def test_float_args_handled(self):
        """Float arguments don't crash triad computation."""
        triad = compute_receipt_triad(
            "search", {"threshold": 0.7, "query": "test"}, None,
        )
        assert re.match(r"^[a-f0-9]{64}$", triad.input_hash)


# =============================================================================
# 2. CANONICAL JSON
# =============================================================================

class TestCanonicalJson:
    def test_canonical_json_ordering(self):
        """JSON key order is deterministic regardless of insertion order."""
        obj1 = {"z": 1, "a": 2, "m": 3}
        obj2 = {"a": 2, "m": 3, "z": 1}
        assert _canonical_json_for_triad(obj1) == _canonical_json_for_triad(obj2)

    def test_canonical_json_no_whitespace(self):
        """Canonical JSON has no unnecessary whitespace."""
        result = _canonical_json_for_triad({"key": "value", "num": 42})
        assert " " not in result
        assert "\n" not in result

    def test_canonical_json_sorted_keys(self):
        """Keys are lexicographically sorted."""
        result = _canonical_json_for_triad({"c": 3, "a": 1, "b": 2})
        assert result == '{"a":1,"b":2,"c":3}'

    def test_canonical_json_float_normalization(self):
        """Float values are serialized as JSON numbers, still deterministic."""
        result1 = _canonical_json_for_triad({"score": 0.7, "name": "test"})
        result2 = _canonical_json_for_triad({"name": "test", "score": 0.7})
        assert result1 == result2
        # Floats are now JSON numbers (v0.12.2+), not fixed-precision strings
        assert "0.7" in result1


# =============================================================================
# 3. VALIDATION
# =============================================================================

class TestValidation:
    def test_check_result_score_range(self):
        """Score must be 0.0-1.0."""
        errors = validate_check_result({"score": 1.5, "method": "llm_coherence"})
        assert any("score" in e for e in errors)

    def test_check_result_score_negative(self):
        """Negative score rejected."""
        errors = validate_check_result({"score": -0.1})
        assert any("score" in e for e in errors)

    def test_check_result_valid_score(self):
        """Valid score accepted."""
        errors = validate_check_result({"score": 0.5, "method": "llm_coherence"})
        assert not errors

    def test_check_result_boundary_scores(self):
        """Boundary scores 0.0 and 1.0 are valid."""
        assert not validate_check_result({"score": 0.0})
        assert not validate_check_result({"score": 1.0})

    def test_check_result_invalid_method(self):
        """Invalid method rejected."""
        errors = validate_check_result({"method": "magic_8_ball"})
        assert any("method" in e for e in errors)

    def test_check_result_valid_methods(self):
        """All valid methods accepted."""
        for method in VALID_CHECK_METHODS:
            errors = validate_check_result({"method": method, "score": 0.5})
            assert not errors, f"Method {method} should be valid"

    def test_assurance_validation(self):
        """Only full/partial/none accepted."""
        errors = validate_reasoning_evaluation({"assurance": "maybe"})
        assert any("assurance" in e for e in errors)

    def test_assurance_valid_values(self):
        """All valid assurance levels accepted."""
        for level in VALID_ASSURANCE_LEVELS:
            errors = validate_reasoning_evaluation({"assurance": level})
            assert not errors, f"Assurance '{level}' should be valid"

    def test_override_reason_validation(self):
        """Only valid enum values accepted."""
        errors = validate_approval_record({"override_reason": "just_because"})
        assert any("override_reason" in e for e in errors)

    def test_override_reason_valid_values(self):
        """All valid override reasons accepted."""
        for reason in VALID_OVERRIDE_REASONS:
            errors = validate_approval_record({"override_reason": reason})
            assert not errors, f"Override reason '{reason}' should be valid"

    def test_override_reason_none_is_valid(self):
        """None override_reason is valid (not required)."""
        errors = validate_approval_record({"override_reason": None})
        assert not errors

    def test_overall_score_range(self):
        """Overall score must be 0.0-1.0."""
        errors = validate_reasoning_evaluation({"overall_score": 2.0})
        assert any("overall_score" in e for e in errors)

    def test_negative_latency_rejected(self):
        """Negative latency_ms rejected."""
        errors = validate_check_result({"latency_ms": -1})
        assert any("latency_ms" in e for e in errors)


# =============================================================================
# 4. DATACLASS CONSTRUCTION AND SERIALIZATION
# =============================================================================

class TestDataclasses:
    def test_receipt_triad_to_dict(self):
        """ReceiptTriad serializes to dict correctly."""
        triad = ReceiptTriad(
            input_hash="a" * 64,
            reasoning_hash="b" * 64,
            action_hash="a" * 64,
        )
        d = receipt_triad_to_dict(triad)
        assert d["input_hash"] == "a" * 64
        assert d["context_limitation"] == "gateway_boundary"

    def test_reasoning_evaluation_to_dict(self):
        """ReasoningEvaluation serializes with float scores."""
        check = GatewayCheckResult(
            check_id="glc_minimum_substance",
            method="deterministic_presence",
            passed=True,
            score=0.8,
            latency_ms=5,
        )
        evaluation = ReasoningEvaluation(
            assurance="full",
            checks=[check],
            overall_score=0.8,
            passed=True,
        )
        d = reasoning_evaluation_to_dict(evaluation)
        assert d["overall_score"] == 0.8
        assert d["checks"][0]["score"] == 0.8

    def test_reasoning_evaluation_to_dict_for_signing(self):
        """For signing, floats are converted to basis points."""
        check = GatewayCheckResult(
            check_id="glc_llm_coherence",
            method="llm_coherence",
            passed=True,
            score=0.75,
            latency_ms=100,
        )
        evaluation = ReasoningEvaluation(
            assurance="full",
            checks=[check],
            overall_score=0.75,
            passed=True,
        )
        d = reasoning_evaluation_to_dict(evaluation, for_signing=True)
        assert d["overall_score"] == 7500
        assert d["checks"][0]["score"] == 7500

    def test_gateway_receipt_v2_to_dict(self):
        """Full GatewayReceiptV2 serializes correctly."""
        triad = ReceiptTriad(
            input_hash="a" * 64,
            reasoning_hash="b" * 64,
            action_hash="a" * 64,
        )
        receipt = GatewayReceiptV2(
            receipt_version="2.0",
            receipt_id="abc123",
            timestamp_utc="2026-01-01T00:00:00Z",
            receipt_triad=triad,
            action=ActionRecord(tool="search", args_hash="abc123"),
            enforcement=EnforcementRecord(
                level="can_execute",
                constitution_version="0.1.0",
                constitution_hash="deadbeef",
            ),
        )
        d = gateway_receipt_v2_to_dict(receipt)
        assert d["receipt_version"] == "2.0"
        assert d["receipt_triad"]["input_hash"] == "a" * 64
        assert d["action"]["tool"] == "search"
        assert d["action"]["args_hash"] == "abc123"
        assert d["enforcement"]["level"] == "can_execute"
        assert "reasoning_evaluation" not in d
        assert "approval" not in d

    def test_gateway_receipt_v2_with_all_fields(self):
        """GatewayReceiptV2 with all optional fields."""
        triad = ReceiptTriad(
            input_hash="a" * 64,
            reasoning_hash="b" * 64,
            action_hash="a" * 64,
        )
        check = GatewayCheckResult(
            check_id="glc_minimum_substance",
            method="deterministic_presence",
            passed=True,
            score=1.0,
            latency_ms=2,
        )
        receipt = GatewayReceiptV2(
            receipt_version="2.0",
            receipt_id="abc123",
            timestamp_utc="2026-01-01T00:00:00Z",
            receipt_triad=triad,
            action=ActionRecord(tool="search", args_hash="abc123"),
            enforcement=EnforcementRecord(
                level="can_execute",
                constitution_version="0.1.0",
                constitution_hash="deadbeef",
            ),
            reasoning_evaluation=ReasoningEvaluation(
                assurance="full",
                checks=[check],
                overall_score=1.0,
                passed=True,
            ),
            approval=GatewayApprovalRecord(
                required=True,
                approved=True,
                approved_at="2026-01-01T00:00:00Z",
                override_reason="accepted_risk",
            ),
            signature=SignatureRecord(
                public_key="abc123",
                signature="sig_value",
            ),
        )
        d = gateway_receipt_v2_to_dict(receipt)
        assert d["reasoning_evaluation"]["assurance"] == "full"
        assert d["approval"]["override_reason"] == "accepted_risk"
        assert d["signature"]["algorithm"] == "ed25519"

    def test_action_record_defaults(self):
        """ActionRecord default for justification_stripped is False."""
        ar = ActionRecord(tool="test")
        assert ar.justification_stripped is False

    def test_signature_record_defaults(self):
        """SignatureRecord has correct defaults."""
        sr = SignatureRecord()
        assert sr.algorithm == "ed25519"
        assert sr.canonical_form == "rfc8785"


# =============================================================================
# 5. GATEWAY RECEIPT V2 GENERATION (integration)
# =============================================================================

class TestGatewayReceiptV2Generation:
    def test_generate_v2_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """v2 gateway receipt has all required fields."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "hello", "limit": 10},
                )
                receipt = gw.last_receipt
                assert receipt is not None

                # v0.13.0 field names
                assert "receipt_id" in receipt
                assert "receipt_fingerprint" in receipt
                assert "full_fingerprint" in receipt
                assert "correlation_id" in receipt
                assert "spec_version" in receipt
                assert "status" in receipt
                assert "extensions" in receipt

                # v2 extensions present under reverse-domain key
                gw_ext = receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["receipt_version"] == "2.0"

                # Receipt triad present (bare 64-hex hashes)
                triad = gw_ext["receipt_triad"]
                hex_pat = re.compile(r"^[a-f0-9]{64}$")
                assert hex_pat.match(triad["input_hash"]), f"input_hash not bare hex: {triad['input_hash']}"
                assert hex_pat.match(triad["reasoning_hash"]), f"reasoning_hash not bare hex: {triad['reasoning_hash']}"
                assert hex_pat.match(triad["action_hash"]), f"action_hash not bare hex: {triad['action_hash']}"
                assert triad["context_limitation"] == "gateway_boundary"
                assert triad["input_hash"] == triad["action_hash"]

                # Action record present
                action = gw_ext["action"]
                assert action["tool"] == "search"
                assert action["args_hash"]  # non-empty hash
                assert action["justification_stripped"] is False

                # Enforcement record present
                enforcement = gw_ext["enforcement"]
                assert enforcement["level"] == "can_execute"
                assert enforcement["constitution_version"] == "0.1.0"
                assert len(enforcement["constitution_hash"]) == 64
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_v2_receipt_with_justification(
        self, mock_server_path, signed_constitution,
    ):
        """Justification is extracted and hashed separately."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search",
                    {
                        "query": "hello",
                        "limit": 10,
                        "_justification": "User needs search results",
                    },
                )
                receipt = gw.last_receipt
                gw_ext = receipt["extensions"]["com.sanna.gateway"]

                # Justification stripped flag set
                assert gw_ext["action"]["justification_stripped"] is True

                # Action uses args_hash (raw args not stored)
                assert "args_hash" in gw_ext["action"]

                # Reasoning hash is NOT the empty-string hash (bare 64-hex)
                empty_hash = hashlib.sha256(b"").hexdigest()
                assert gw_ext["receipt_triad"]["reasoning_hash"] != empty_hash
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_v2_halt_receipt(
        self, mock_server_path, signed_constitution,
    ):
        """cannot_execute generates v2 receipt with halt enforcement."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_delete_item", {"item_id": "123"},
                )
                receipt = gw.last_receipt
                assert receipt is not None
                gw_ext = receipt["extensions"]["com.sanna.gateway"]
                assert gw_ext["enforcement"]["level"] == "cannot_execute"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_v2_triad_deterministic_across_calls(
        self, mock_server_path, signed_constitution,
    ):
        """Same tool+args produces same triad hashes across calls."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "test", "limit": 5},
                )
                triad1 = gw.last_receipt["extensions"]["com.sanna.gateway"]["receipt_triad"]

                await gw._forward_call(
                    "mock_search", {"query": "test", "limit": 5},
                )
                triad2 = gw.last_receipt["extensions"]["com.sanna.gateway"]["receipt_triad"]

                assert triad1["input_hash"] == triad2["input_hash"]
                assert triad1["reasoning_hash"] == triad2["reasoning_hash"]
                assert triad1["action_hash"] == triad2["action_hash"]
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 6. SIGNATURE VERIFICATION
# =============================================================================

class TestSignatureVerification:
    def test_signature_verification_v2(
        self, mock_server_path, signed_constitution,
    ):
        """Ed25519 signature verifies for v2 receipt."""
        const_path, key_path, pub_key_path = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                receipt = gw.last_receipt
                assert receipt is not None
                assert "receipt_signature" in receipt

                # Verify using the crypto module
                from sanna.crypto import verify_receipt_signature
                valid = verify_receipt_signature(receipt, pub_key_path)
                assert valid, "Ed25519 signature verification failed for v2 receipt"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_v2_receipt_fingerprint_verifies(
        self, mock_server_path, signed_constitution,
    ):
        """v2 receipt fingerprint can be recomputed and verified."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            from sanna.verify import verify_receipt, load_schema
            schema = load_schema()

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                receipt = gw.last_receipt
                result = verify_receipt(receipt, schema)
                assert result.valid, f"Verification failed: {result.errors}"
            finally:
                await gw.shutdown()

        asyncio.run(_test())


# =============================================================================
# 7. BACKWARD COMPATIBILITY
# =============================================================================

class TestBackwardCompatibility:
    def test_v1_receipt_verification(
        self, mock_server_path, signed_constitution,
    ):
        """v1 receipt (pre-v2 format) still verifies correctly.

        The v2 changes only add to extensions — the core receipt
        structure is unchanged, so existing verification still works.
        """
        const_path, key_path, pub_key_path = signed_constitution

        async def _test():
            from sanna.verify import verify_receipt, load_schema
            schema = load_schema()

            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                receipt = gw.last_receipt

                # v0.13.0 field names
                assert receipt["spec_version"] == "1.0"
                assert "receipt_id" in receipt
                assert "receipt_fingerprint" in receipt
                assert "full_fingerprint" in receipt
                assert "correlation_id" in receipt
                assert "context_hash" in receipt
                assert "output_hash" in receipt
                assert "status" in receipt

                # Gateway extensions under reverse-domain key
                assert "com.sanna.gateway" in receipt["extensions"]
                assert receipt["extensions"]["com.sanna.gateway"]["tool_name"] == "search"

                # Full verification passes
                result = verify_receipt(receipt, schema)
                assert result.valid, f"v1 verification failed: {result.errors}"

                # Signature verification passes
                from sanna.crypto import verify_receipt_signature
                valid = verify_receipt_signature(receipt, pub_key_path)
                assert valid, "v1 signature verification failed"
            finally:
                await gw.shutdown()

        asyncio.run(_test())

    def test_v2_extensions_additive(
        self, mock_server_path, signed_constitution,
    ):
        """v2 extensions are additive — v1 extensions unchanged."""
        const_path, key_path, _ = signed_constitution

        async def _test():
            gw = SannaGateway(
                server_name="mock",
                command=sys.executable,
                args=[mock_server_path],
                constitution_path=const_path,
                require_constitution_sig=False,
                signing_key_path=key_path,
            )
            await gw.start()
            try:
                await gw._forward_call(
                    "mock_search", {"query": "test"},
                )
                receipt = gw.last_receipt
                extensions = receipt["extensions"]

                # v0.13.0: gateway and gateway_v2 merged into com.sanna.gateway
                assert "com.sanna.gateway" in extensions
                gw_ext = extensions["com.sanna.gateway"]

                # v1 fields intact (merged into same namespace)
                assert "server_name" in gw_ext
                assert "arguments_hash" in gw_ext
                assert "tool_output_hash" in gw_ext

                # v2 fields present (merged into same namespace)
                assert "receipt_triad" in gw_ext
                assert "action" in gw_ext
                assert "enforcement" in gw_ext
            finally:
                await gw.shutdown()

        asyncio.run(_test())
