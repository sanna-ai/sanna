"""SAN-358: verify_receipt_set() and production-shape manifest fixture tests.

Asserts that:
1. Real production-shape session_manifest receipts (with constitution_ref,
   correct enforcement_surface, sorted surfaces) produce NO FAIL manifest
   checks -- verifies no false-FAIL on well-formed receipts.
2. verify_receipt_set() performs cross-receipt anomaly checks (parent resolution).
3. verify_receipt_set() merges anomaly checks into the correct VerificationResult.

Receipt dicts are hand-crafted to match what the SDK emits in production
(with valid constitution_ref.policy_hash, agent_identity, etc.). Fingerprint
and content-hash validity is not asserted here -- that is covered by existing
verify test suites. These tests focus solely on SAN-358 manifest/anomaly checks.
"""
import uuid

import pytest

from sanna.verify import verify_receipt, verify_receipt_set, load_schema, VerificationResult
from sanna.verify_manifest import verify_session_manifest_receipt, verify_invocation_anomaly_receipt

SCHEMA = load_schema()

_HASH_64 = "a" * 64
_POLICY_HASH = "c" * 64
_MANIFEST_FP = "e" * 64
_ANOMALY_FP = "f" * 64


# ===========================================================================
# Production-shape manifest extension builders
# (test the manifest semantic checks in isolation from fingerprint validity)
# ===========================================================================

def _mcp_surface(
    tools_delivered=None,
    tools_suppressed=None,
    suppression_reasons=None,
) -> dict:
    if tools_delivered is None:
        tools_delivered = ["read_data"]
    if tools_suppressed is None:
        tools_suppressed = ["delete_all"]
    if suppression_reasons is None:
        suppression_reasons = {t: "cannot_execute" for t in tools_suppressed}
    return {
        "tools_delivered": sorted(tools_delivered),
        "tools_suppressed": sorted(tools_suppressed),
        "suppression_reasons": suppression_reasons,
    }


def _cli_surface(patterns_delivered=None, patterns_suppressed=None) -> dict:
    if patterns_delivered is None:
        patterns_delivered = ["git", "ls"]
    if patterns_suppressed is None:
        patterns_suppressed = ["rm"]
    return {
        "patterns_delivered": sorted(patterns_delivered),
        "patterns_suppressed": sorted(patterns_suppressed),
        "suppression_reasons": {t: "cannot_execute" for t in patterns_suppressed},
        "mode": "strict",
    }


def _http_surface(patterns_delivered=None, patterns_suppressed=None) -> dict:
    if patterns_delivered is None:
        patterns_delivered = ["/api/read"]
    if patterns_suppressed is None:
        patterns_suppressed = ["/api/delete"]
    return {
        "patterns_delivered": sorted(patterns_delivered),
        "patterns_suppressed": sorted(patterns_suppressed),
        "suppression_reasons": {t: "cannot_execute" for t in patterns_suppressed},
        "mode": "strict",
    }


def _production_manifest_receipt(
    enforcement_surface="gateway",
    surfaces=None,
    full_fingerprint=None,
) -> dict:
    """Build a receipt matching SDK production shape for session_manifest."""
    if surfaces is None:
        surfaces = {"mcp": _mcp_surface()}
    manifest_ext = {
        "version": "0.1",
        "composition_basis": "static",
        "surfaces": surfaces,
    }
    from sanna.hashing import hash_obj
    inputs = {"query": "session_manifest"}
    outputs = {"response": ""}
    return {
        "spec_version": "1.5",
        "tool_version": "1.5.0",
        "tool_name": "sanna",
        "checks_version": "10",
        "receipt_id": str(uuid.uuid4()),
        "receipt_fingerprint": "b" * 16,
        "full_fingerprint": full_fingerprint or _MANIFEST_FP,
        "correlation_id": f"manifest-{uuid.uuid4().hex[:12]}",
        "timestamp": "2026-05-02T12:00:00Z",
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": hash_obj(inputs),
        "output_hash": hash_obj(outputs),
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "status": "PASS",
        "invariants_scope": "none",
        "event_type": "session_manifest",
        "enforcement": None,
        "enforcement_surface": enforcement_surface,
        "extensions": {"com.sanna.manifest": manifest_ext},
        "constitution_ref": {
            "policy_hash": _POLICY_HASH,
            "document_id": "test-agent/0.1.0",
            "version": "0.1.0",
        },
        "agent_identity": {"agent_session_id": "sess-prod-001"},
    }


def _production_anomaly_receipt(
    parent_fp=_MANIFEST_FP,
    attempted_tool="delete_all",
    full_fingerprint=None,
) -> dict:
    """Build a receipt matching SDK production shape for invocation_anomaly."""
    from sanna.hashing import hash_obj
    inputs = {"query": f"tools/call name={attempted_tool}"}
    outputs = {"response": ""}
    return {
        "spec_version": "1.5",
        "tool_version": "1.5.0",
        "tool_name": "sanna",
        "checks_version": "10",
        "receipt_id": str(uuid.uuid4()),
        "receipt_fingerprint": "d" * 16,
        "full_fingerprint": full_fingerprint or _ANOMALY_FP,
        "correlation_id": f"anomaly-{uuid.uuid4().hex[:12]}",
        "timestamp": "2026-05-02T12:01:00Z",
        "inputs": inputs,
        "outputs": outputs,
        "context_hash": hash_obj(inputs),
        "output_hash": hash_obj(outputs),
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 1,
        "status": "FAIL",
        "invariants_scope": "authority_only",
        "event_type": "invocation_anomaly",
        "enforcement": {
            "action": "halted",
            "halted": True,
            "reason": "tool_suppressed_by_constitution",
            "failed_checks": [],
            "enforcement_mode": "halt",
            "timestamp": "2026-05-02T12:01:00Z",
        },
        "enforcement_surface": "gateway",
        "extensions": {
            "com.sanna.anomaly": {
                "attempted_tool": attempted_tool,
                "suppression_basis": "session_manifest",
            }
        },
        "parent_receipts": [parent_fp],
        "constitution_ref": {"policy_hash": _POLICY_HASH},
        "agent_identity": {"agent_session_id": "sess-prod-001"},
    }


# ===========================================================================
# Production-shape manifest receipts produce no false FAIL manifest checks
# (tests verify_session_manifest_receipt() directly on production-shape dicts)
# ===========================================================================

class TestProductionShapeManifestVerifiesClean:
    def test_gateway_manifest_passes_all_checks(self):
        receipt = _production_manifest_receipt(enforcement_surface="gateway")
        checks = verify_session_manifest_receipt(receipt)

        assert len(checks) == 9
        fail_checks = [c for c in checks if c.status == "FAIL"]
        assert not fail_checks, f"Unexpected FAIL on production gateway receipt: {fail_checks}"

    def test_cli_interceptor_manifest_passes(self):
        receipt = _production_manifest_receipt(
            enforcement_surface="cli_interceptor",
            surfaces={"cli": _cli_surface()},
        )
        checks = verify_session_manifest_receipt(receipt)
        fail_checks = [c for c in checks if c.status == "FAIL"]
        assert not fail_checks, f"Unexpected FAIL on cli_interceptor receipt: {fail_checks}"

    def test_http_interceptor_manifest_passes(self):
        receipt = _production_manifest_receipt(
            enforcement_surface="http_interceptor",
            surfaces={"http": _http_surface()},
        )
        checks = verify_session_manifest_receipt(receipt)
        fail_checks = [c for c in checks if c.status == "FAIL"]
        assert not fail_checks, f"Unexpected FAIL on http_interceptor receipt: {fail_checks}"

    def test_mixed_enforcement_with_two_surfaces_passes(self):
        receipt = _production_manifest_receipt(
            enforcement_surface="mixed",
            surfaces={"mcp": _mcp_surface(), "cli": _cli_surface()},
        )
        checks = verify_session_manifest_receipt(receipt)
        fail_checks = [c for c in checks if c.status == "FAIL"]
        assert not fail_checks, f"Unexpected FAIL on mixed receipt: {fail_checks}"

    def test_empty_delivered_and_suppressed_passes(self):
        """Gateway receipt with no tools declared passes."""
        receipt = _production_manifest_receipt(
            enforcement_surface="gateway",
            surfaces={"mcp": _mcp_surface(tools_delivered=[], tools_suppressed=[])},
        )
        checks = verify_session_manifest_receipt(receipt)
        fail_checks = [c for c in checks if c.status == "FAIL"]
        assert not fail_checks

    def test_all_9_checks_present(self):
        receipt = _production_manifest_receipt()
        checks = verify_session_manifest_receipt(receipt)
        expected_names = {
            "manifest_extension_present",
            "manifest_version_supported",
            "manifest_has_at_least_one_surface",
            "manifest_lists_sorted",
            "manifest_suppression_reasons_in_enum",
            "manifest_no_overlap_delivered_suppressed",
            "manifest_suppression_reasons_keys_match",
            "manifest_constitution_ref_present",
            "manifest_enforcement_surface_consistent",
        }
        found = {c.name for c in checks}
        assert expected_names == found, f"Missing checks: {expected_names - found}"


# ===========================================================================
# verify_receipt_set cross-receipt anomaly checks
# ===========================================================================

class TestVerifyReceiptSetCrossReceiptChecks:
    def test_anomaly_parent_resolved_check_11_passes(self):
        manifest = _production_manifest_receipt(
            surfaces={"mcp": _mcp_surface(tools_suppressed=["delete_all"])},
            full_fingerprint=_MANIFEST_FP,
        )
        anomaly = _production_anomaly_receipt(
            parent_fp=_MANIFEST_FP,
            attempted_tool="delete_all",
        )
        results = verify_receipt_set([manifest, anomaly], schema=SCHEMA)

        anomaly_result = results[anomaly["receipt_id"]]
        check_11 = next(
            (c for c in anomaly_result.checks
             if c.name == "anomaly_parent_receipts_resolves_to_session_manifest"),
            None
        )
        assert check_11 is not None
        assert check_11.status == "PASS", f"check_11 status: {check_11}"

    def test_anomaly_capability_in_suppressed_passes_check_12(self):
        manifest = _production_manifest_receipt(
            surfaces={"mcp": _mcp_surface(
                tools_delivered=["read_data"],
                tools_suppressed=["delete_all"],
            )},
            full_fingerprint=_MANIFEST_FP,
        )
        anomaly = _production_anomaly_receipt(
            parent_fp=_MANIFEST_FP,
            attempted_tool="delete_all",
        )
        results = verify_receipt_set([manifest, anomaly], schema=SCHEMA)
        anomaly_result = results[anomaly["receipt_id"]]

        check_12 = next(
            (c for c in anomaly_result.checks
             if c.name == "anomaly_attempted_capability_in_parent_suppressed_or_absent"),
            None
        )
        assert check_12 is not None
        assert check_12.status == "PASS", f"check_12 status: {check_12}"

    def test_anomaly_with_unresolvable_parent_fails_check_11(self):
        manifest = _production_manifest_receipt(full_fingerprint=_MANIFEST_FP)
        anomaly = _production_anomaly_receipt(parent_fp="9" * 64)
        results = verify_receipt_set([manifest, anomaly], schema=SCHEMA)

        anomaly_result = results[anomaly["receipt_id"]]
        check_11 = next(
            (c for c in anomaly_result.checks
             if c.name == "anomaly_parent_receipts_resolves_to_session_manifest"),
            None
        )
        assert check_11 is not None
        assert check_11.status == "FAIL"

    def test_anomaly_delivered_capability_fails_check_12(self):
        manifest = _production_manifest_receipt(
            surfaces={"mcp": _mcp_surface(
                tools_delivered=["read_data"],
                tools_suppressed=["delete_all"],
            )},
            full_fingerprint=_MANIFEST_FP,
        )
        # anomaly claims read_data was blocked, but it's delivered
        anomaly = _production_anomaly_receipt(
            parent_fp=_MANIFEST_FP,
            attempted_tool="read_data",
        )
        results = verify_receipt_set([manifest, anomaly], schema=SCHEMA)
        anomaly_result = results[anomaly["receipt_id"]]

        check_12 = next(
            (c for c in anomaly_result.checks
             if c.name == "anomaly_attempted_capability_in_parent_suppressed_or_absent"),
            None
        )
        assert check_12 is not None
        assert check_12.status == "FAIL"
        assert "DELIVERED" in check_12.message

    def test_cross_receipt_warnings_not_in_final_result(self):
        """After verify_receipt_set merges checks, the skip-WARN placeholder is gone."""
        from sanna.verify_manifest import _CROSS_RECEIPT_SKIP_MSG
        manifest = _production_manifest_receipt(full_fingerprint=_MANIFEST_FP)
        anomaly = _production_anomaly_receipt(parent_fp=_MANIFEST_FP)
        results = verify_receipt_set([manifest, anomaly], schema=SCHEMA)

        anomaly_result = results[anomaly["receipt_id"]]
        assert _CROSS_RECEIPT_SKIP_MSG not in anomaly_result.warnings

    def test_manifest_receipt_has_9_check_names_in_result(self):
        manifest = _production_manifest_receipt()
        results = verify_receipt_set([manifest], schema=SCHEMA)
        result = list(results.values())[0]

        expected = {
            "manifest_extension_present",
            "manifest_version_supported",
            "manifest_has_at_least_one_surface",
            "manifest_lists_sorted",
            "manifest_suppression_reasons_in_enum",
            "manifest_no_overlap_delivered_suppressed",
            "manifest_suppression_reasons_keys_match",
            "manifest_constitution_ref_present",
            "manifest_enforcement_surface_consistent",
        }
        found = {c.name for c in result.checks}
        for name in expected:
            assert name in found, f"Missing check '{name}'"

    def test_receipt_without_event_type_has_no_manifest_checks(self):
        """Backward compat: receipts without event_type produce no manifest checks."""
        from sanna.middleware import generate_constitution_receipt, build_trace_data
        trace = build_trace_data(
            correlation_id="legacy-001",
            query="test",
            context="ctx",
            output="out",
        )
        receipt = generate_constitution_receipt(
            trace,
            check_configs=[],
            custom_records=[],
            constitution_ref=None,
            constitution_version="",
        )
        receipt.pop("event_type", None)

        results = verify_receipt_set([receipt], schema=SCHEMA)
        result = list(results.values())[0]
        manifest_names = {
            "manifest_extension_present",
            "manifest_version_supported",
            "manifest_has_at_least_one_surface",
        }
        for chk in result.checks:
            assert chk.name not in manifest_names, (
                f"Unexpected manifest check '{chk.name}' on receipt without event_type"
            )
