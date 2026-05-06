"""SAN-358: Tests for verify_manifest.py -- session_manifest and invocation_anomaly checks.

Positive + negative cases for each of the 12 checks. Each assertion on Check.message
uses the exact string from verify_manifest.py so that Prompt B (TS mirror) can assert
byte-equal equivalence.

cv=9 legacy posture: receipts without 'event_type' field skip the dispatch entirely
(tested via verify_receipt integration path, not verify_manifest.py directly since
verify_manifest.py functions require the caller to know which function to invoke).
"""
import uuid
import pytest

from sanna.verify_manifest import (
    Check,
    verify_session_manifest_receipt,
    verify_invocation_anomaly_receipt,
)

# ===========================================================================
# Helpers
# ===========================================================================

_HASH_64 = "a" * 64
_HASH_16 = "b" * 16
_POLICY_HASH = "c" * 64


def _base_manifest_ext(
    surfaces=None,
    version="0.1",
    composition_basis="static",
) -> dict:
    if surfaces is None:
        surfaces = {
            "mcp": {
                "tools_delivered": ["read_data"],
                "tools_suppressed": ["delete_all"],
                "suppression_reasons": {"delete_all": "cannot_execute"},
            }
        }
    return {
        "version": version,
        "composition_basis": composition_basis,
        "surfaces": surfaces,
    }


def _base_receipt(
    manifest_ext=None,
    enforcement_surface="gateway",
    event_type="session_manifest",
    constitution_ref=None,
    content_mode=None,
) -> dict:
    if manifest_ext is None:
        manifest_ext = _base_manifest_ext()
    r = {
        "spec_version": "1.5",
        "tool_version": "1.5.0",
        "tool_name": "sanna",
        "checks_version": "10",
        "receipt_id": str(uuid.uuid4()),
        "receipt_fingerprint": _HASH_16,
        "full_fingerprint": _HASH_64,
        "correlation_id": "test-001",
        "timestamp": "2026-05-02T12:00:00Z",
        "inputs": {"query": "session_manifest"},
        "outputs": {"response": ""},
        "context_hash": _HASH_64,
        "output_hash": _HASH_64,
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "status": "PASS",
        "invariants_scope": "none",
        "event_type": event_type,
        "enforcement": None,
        "enforcement_surface": enforcement_surface,
        "extensions": {"com.sanna.manifest": manifest_ext},
        "constitution_ref": constitution_ref or {"policy_hash": _POLICY_HASH},
        "agent_identity": {"agent_session_id": "sess-001"},
    }
    if content_mode:
        r["content_mode"] = content_mode
        r["content_mode_source"] = "local_config"
    return r


def _check(checks: list[Check], name: str) -> Check:
    """Return the first Check with the given name, or raise."""
    matches = [c for c in checks if c.name == name]
    if not matches:
        raise AssertionError(
            f"No check named '{name}' found. Got: {[c.name for c in checks]}"
        )
    return matches[0]


# ===========================================================================
# Check 1: manifest_extension_present
# ===========================================================================

class TestManifestExtensionPresent:
    def test_pass_when_extension_is_dict(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_extension_present")
        assert c.status == "PASS"

    def test_fail_when_extension_absent(self):
        receipt = _base_receipt()
        del receipt["extensions"]["com.sanna.manifest"]
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_extension_present")
        assert c.status == "FAIL"
        assert c.message == "session_manifest receipt missing required extension 'com.sanna.manifest'"

    def test_fail_when_extensions_key_missing(self):
        receipt = _base_receipt()
        del receipt["extensions"]
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_extension_present")
        assert c.status == "FAIL"
        assert c.message == "session_manifest receipt missing required extension 'com.sanna.manifest'"

    def test_fail_when_extension_not_dict(self):
        receipt = _base_receipt()
        receipt["extensions"]["com.sanna.manifest"] = "not-a-dict"
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_extension_present")
        assert c.status == "FAIL"


# ===========================================================================
# Check 2: manifest_version_supported
# ===========================================================================

class TestManifestVersionSupported:
    def test_pass_on_0_1(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_version_supported")
        assert c.status == "PASS"

    def test_fail_on_unknown_version(self):
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(version="9.9"))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_version_supported")
        assert c.status == "FAIL"
        assert c.message == "manifest version '9.9' not in supported set {'0.1'}"

    def test_fail_on_none_version(self):
        ext = _base_manifest_ext()
        del ext["version"]
        receipt = _base_receipt(manifest_ext=ext)
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_version_supported")
        assert c.status == "FAIL"
        assert c.message == "manifest version 'None' not in supported set {'0.1'}"


# ===========================================================================
# Check 3: manifest_has_at_least_one_surface
# ===========================================================================

class TestManifestHasAtLeastOneSurface:
    def test_pass_with_mcp_surface(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_has_at_least_one_surface")
        assert c.status == "PASS"

    def test_fail_on_empty_surfaces(self):
        ext = _base_manifest_ext(surfaces={})
        receipt = _base_receipt(manifest_ext=ext)
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_has_at_least_one_surface")
        assert c.status == "FAIL"
        assert c.message == "manifest 'surfaces' must contain at least one of {'mcp', 'cli', 'http'}"

    def test_fail_on_missing_surfaces_key(self):
        ext = _base_manifest_ext()
        del ext["surfaces"]
        receipt = _base_receipt(manifest_ext=ext)
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_has_at_least_one_surface")
        assert c.status == "FAIL"


# ===========================================================================
# Check 4: manifest_lists_sorted
# ===========================================================================

class TestManifestListsSorted:
    def test_pass_when_sorted(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_lists_sorted")
        assert c.status == "PASS"

    def test_fail_when_delivered_unsorted(self):
        surfaces = {
            "mcp": {
                "tools_delivered": ["z_tool", "a_tool"],
                "tools_suppressed": [],
                "suppression_reasons": {},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_lists_sorted")
        assert c.status == "FAIL"
        assert c.message == (
            "manifest surface 'mcp' field 'tools_delivered' "
            "is not sorted alphabetically (determinism violated)"
        )

    def test_fail_when_suppressed_unsorted(self):
        surfaces = {
            "mcp": {
                "tools_delivered": ["a_tool"],
                "tools_suppressed": ["z_suppress", "a_suppress"],
                "suppression_reasons": {"z_suppress": "cannot_execute", "a_suppress": "policy_denied"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_lists_sorted")
        assert c.status == "FAIL"
        assert "tools_suppressed" in c.message

    def test_pass_for_cli_patterns(self):
        surfaces = {
            "cli": {
                "patterns_delivered": ["git", "ls"],
                "patterns_suppressed": ["rm"],
                "suppression_reasons": {"rm": "cannot_execute"},
                "mode": "strict",
            }
        }
        receipt = _base_receipt(
            manifest_ext=_base_manifest_ext(surfaces=surfaces),
            enforcement_surface="cli_interceptor",
        )
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_lists_sorted")
        assert c.status == "PASS"


# ===========================================================================
# Check 5: manifest_suppression_reasons_in_enum
# ===========================================================================

class TestManifestSuppressionReasonsInEnum:
    def test_pass_on_valid_reasons(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_in_enum")
        assert c.status == "PASS"

    def test_fail_on_invalid_reason(self):
        surfaces = {
            "mcp": {
                "tools_delivered": [],
                "tools_suppressed": ["bad_tool"],
                "suppression_reasons": {"bad_tool": "not_a_real_reason"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_in_enum")
        assert c.status == "FAIL"
        assert c.message == (
            "manifest surface 'mcp' suppression_reason 'not_a_real_reason' "
            "not in stable enum (Section 2.21)"
        )

    def test_warn_on_unknown_reason(self):
        surfaces = {
            "mcp": {
                "tools_delivered": [],
                "tools_suppressed": ["some_tool"],
                "suppression_reasons": {"some_tool": "unknown"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_in_enum")
        assert c.status == "WARN"
        assert c.message == (
            "manifest surface 'mcp' uses 'unknown' suppression_reason "
            "(documented fallback per Section 2.21)"
        )

    def test_pass_when_suppression_reasons_absent_redacted_mode(self):
        surfaces = {
            "mcp": {
                "tools_delivered": ["<redacted>"],
                "tools_suppressed": ["<redacted>"],
                "aggregate_suppression_reasons": ["cannot_execute"],
            }
        }
        receipt = _base_receipt(
            manifest_ext=_base_manifest_ext(surfaces=surfaces),
            content_mode="redacted",
        )
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_in_enum")
        assert c.status == "PASS"


# ===========================================================================
# Check 6: manifest_no_overlap_delivered_suppressed
# ===========================================================================

class TestManifestNoOverlapDeliveredSuppressed:
    def test_pass_when_disjoint(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_no_overlap_delivered_suppressed")
        assert c.status == "PASS"

    def test_fail_when_overlap(self):
        surfaces = {
            "mcp": {
                "tools_delivered": ["shared_tool"],
                "tools_suppressed": ["shared_tool"],
                "suppression_reasons": {"shared_tool": "cannot_execute"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_no_overlap_delivered_suppressed")
        assert c.status == "FAIL"
        assert c.message == (
            "manifest surface 'mcp' has 'shared_tool' in BOTH "
            "delivered and suppressed (anti-enumeration integrity violated)"
        )

    def test_skip_overlap_check_in_redacted_mode(self):
        surfaces = {
            "mcp": {
                "tools_delivered": ["<redacted>"],
                "tools_suppressed": ["<redacted>"],
                "aggregate_suppression_reasons": ["cannot_execute"],
            }
        }
        receipt = _base_receipt(
            manifest_ext=_base_manifest_ext(surfaces=surfaces),
            content_mode="redacted",
        )
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_no_overlap_delivered_suppressed")
        assert c.status == "PASS"


# ===========================================================================
# Check 7: manifest_suppression_reasons_keys_match
# ===========================================================================

class TestManifestSuppressionReasonsKeysMatch:
    def test_pass_when_keys_match(self):
        receipt = _base_receipt()
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_keys_match")
        assert c.status == "PASS"

    def test_fail_when_extra_key(self):
        surfaces = {
            "mcp": {
                "tools_delivered": [],
                "tools_suppressed": ["tool_a"],
                "suppression_reasons": {"tool_a": "cannot_execute", "ghost_tool": "policy_denied"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_keys_match")
        assert c.status == "FAIL"
        assert "ghost_tool" in c.message
        assert c.message.startswith("manifest surface 'mcp' suppression_reasons keys")

    def test_fail_when_missing_key(self):
        surfaces = {
            "mcp": {
                "tools_delivered": [],
                "tools_suppressed": ["tool_a", "tool_b"],
                "suppression_reasons": {"tool_a": "cannot_execute"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_keys_match")
        assert c.status == "FAIL"
        assert "tool_b" in c.message

    def test_fail_message_format(self):
        surfaces = {
            "mcp": {
                "tools_delivered": [],
                "tools_suppressed": ["beta"],
                "suppression_reasons": {"alpha": "cannot_execute"},
            }
        }
        receipt = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_suppression_reasons_keys_match")
        assert c.status == "FAIL"
        assert c.message == (
            "manifest surface 'mcp' suppression_reasons keys ['alpha'] "
            "do not match suppressed names ['beta']"
        )


# ===========================================================================
# Check 8: manifest_constitution_ref_present
# ===========================================================================

class TestManifestConstitutionRefPresent:
    def test_pass_when_policy_hash_present(self):
        receipt = _base_receipt(constitution_ref={"policy_hash": _POLICY_HASH})
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_constitution_ref_present")
        assert c.status == "PASS"

    def test_fail_when_constitution_ref_absent(self):
        receipt = _base_receipt()
        del receipt["constitution_ref"]
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_constitution_ref_present")
        assert c.status == "FAIL"
        assert c.message == (
            "session_manifest receipt requires constitution_ref.policy_hash "
            "(manifest is meaningless without constitution binding)"
        )

    def test_fail_when_policy_hash_empty(self):
        receipt = _base_receipt(constitution_ref={"policy_hash": ""})
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_constitution_ref_present")
        assert c.status == "FAIL"

    def test_fail_when_constitution_ref_none(self):
        receipt = _base_receipt()
        receipt["constitution_ref"] = None
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_constitution_ref_present")
        assert c.status == "FAIL"


# ===========================================================================
# Check 9: manifest_enforcement_surface_consistent
# ===========================================================================

class TestManifestEnforcementSurfaceConsistent:
    def test_pass_gateway_with_mcp(self):
        receipt = _base_receipt(enforcement_surface="gateway")
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "PASS"

    def test_fail_invalid_enforcement_surface(self):
        receipt = _base_receipt(enforcement_surface="middleware")
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "FAIL"
        assert c.message == (
            "session_manifest enforcement_surface 'middleware' "
            "not in valid set {gateway, cli_interceptor, http_interceptor, mixed}"
        )

    def test_fail_gateway_missing_mcp_surface(self):
        surfaces = {
            "cli": {
                "patterns_delivered": [],
                "patterns_suppressed": [],
                "suppression_reasons": {},
                "mode": "strict",
            }
        }
        receipt = _base_receipt(
            manifest_ext=_base_manifest_ext(surfaces=surfaces),
            enforcement_surface="gateway",
        )
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "FAIL"
        assert c.message == "session_manifest with enforcement_surface='gateway' missing 'mcp' surface"

    def test_fail_mixed_needs_two_surfaces(self):
        receipt = _base_receipt(enforcement_surface="mixed")
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "FAIL"
        assert c.message == (
            "session_manifest with enforcement_surface='mixed' requires "
            "surfaces dict with at least 2 entries; got 1"
        )

    def test_pass_mixed_with_two_surfaces(self):
        surfaces = {
            "mcp": {
                "tools_delivered": [],
                "tools_suppressed": [],
                "suppression_reasons": {},
            },
            "cli": {
                "patterns_delivered": [],
                "patterns_suppressed": [],
                "suppression_reasons": {},
                "mode": "strict",
            },
        }
        receipt = _base_receipt(
            manifest_ext=_base_manifest_ext(surfaces=surfaces),
            enforcement_surface="mixed",
        )
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "PASS"

    def test_fail_cli_interceptor_missing_cli_surface(self):
        receipt = _base_receipt(enforcement_surface="cli_interceptor")
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "FAIL"
        assert c.message == "session_manifest with enforcement_surface='cli_interceptor' missing 'cli' surface"

    def test_fail_http_interceptor_missing_http_surface(self):
        receipt = _base_receipt(enforcement_surface="http_interceptor")
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "FAIL"
        assert c.message == "session_manifest with enforcement_surface='http_interceptor' missing 'http' surface"

    def test_pass_cli_interceptor_with_cli_surface(self):
        surfaces = {
            "cli": {
                "patterns_delivered": [],
                "patterns_suppressed": [],
                "suppression_reasons": {},
                "mode": "strict",
            }
        }
        receipt = _base_receipt(
            manifest_ext=_base_manifest_ext(surfaces=surfaces),
            enforcement_surface="cli_interceptor",
        )
        checks = verify_session_manifest_receipt(receipt)
        c = _check(checks, "manifest_enforcement_surface_consistent")
        assert c.status == "PASS"


# ===========================================================================
# Check 10: anomaly_event_type_in_valid_set
# ===========================================================================

def _base_anomaly_receipt(
    event_type="invocation_anomaly",
    parent_receipts=None,
    attempted_tool="delete_all",
) -> dict:
    return {
        "spec_version": "1.5",
        "tool_version": "1.5.0",
        "tool_name": "sanna",
        "checks_version": "10",
        "receipt_id": str(uuid.uuid4()),
        "receipt_fingerprint": _HASH_16,
        "full_fingerprint": "d" * 64,
        "correlation_id": "anomaly-001",
        "timestamp": "2026-05-02T12:01:00Z",
        "inputs": {"query": f"tools/call name={attempted_tool}"},
        "outputs": {"response": ""},
        "context_hash": _HASH_64,
        "output_hash": _HASH_64,
        "checks": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "status": "FAIL",
        "invariants_scope": "authority_only",
        "event_type": event_type,
        "enforcement": {"action": "halted", "halted": True,
                        "reason": "tool_suppressed_by_constitution",
                        "failed_checks": [], "enforcement_mode": "halt",
                        "timestamp": "2026-05-02T12:01:00Z"},
        "enforcement_surface": "gateway",
        "extensions": {
            "com.sanna.anomaly": {
                "attempted_tool": attempted_tool,
                "suppression_basis": "session_manifest",
            }
        },
        "parent_receipts": parent_receipts if parent_receipts is not None else [_HASH_64],
        "constitution_ref": {"policy_hash": _POLICY_HASH},
        "agent_identity": {"agent_session_id": "sess-001"},
    }


class TestAnomalyEventTypeInValidSet:
    def test_pass_for_invocation_anomaly(self):
        receipt = _base_anomaly_receipt()
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        c = _check(checks, "anomaly_event_type_in_valid_set")
        assert c.status == "PASS"

    def test_pass_for_cli_invocation_anomaly(self):
        receipt = _base_anomaly_receipt(event_type="cli_invocation_anomaly")
        receipt["extensions"] = {"com.sanna.anomaly": {"attempted_command": "rm -rf /"}}
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        c = _check(checks, "anomaly_event_type_in_valid_set")
        assert c.status == "PASS"

    def test_pass_for_api_invocation_anomaly(self):
        receipt = _base_anomaly_receipt(event_type="api_invocation_anomaly")
        receipt["extensions"] = {"com.sanna.anomaly": {"attempted_endpoint": "/api/delete"}}
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        c = _check(checks, "anomaly_event_type_in_valid_set")
        assert c.status == "PASS"

    def test_fail_for_unknown_event_type(self):
        receipt = _base_anomaly_receipt(event_type="bad_event")
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        c = _check(checks, "anomaly_event_type_in_valid_set")
        assert c.status == "FAIL"
        assert c.message == "anomaly receipt event_type 'bad_event' not in valid set"


# ===========================================================================
# Check 11: anomaly_parent_receipts_resolves_to_session_manifest
# ===========================================================================

class TestAnomalyParentReceiptsResolvesToSessionManifest:
    def _manifest_receipt_for(self, fp: str) -> dict:
        r = _base_receipt()
        r["full_fingerprint"] = fp
        return r

    def test_warn_in_single_receipt_mode(self):
        receipt = _base_anomaly_receipt()
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        c = _check(checks, "anomaly_parent_receipts_resolves_to_session_manifest")
        assert c.status == "WARN"
        assert c.message == "Cross-receipt parent resolution requires receipt set; use verify_receipt_set"

    def test_fail_when_parent_receipts_empty(self):
        receipt = _base_anomaly_receipt(parent_receipts=[])
        manifest = self._manifest_receipt_for(_HASH_64)
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=[manifest])
        c = _check(checks, "anomaly_parent_receipts_resolves_to_session_manifest")
        assert c.status == "FAIL"
        assert c.message == (
            "anomaly receipt requires non-empty parent_receipts containing "
            "the active session_manifest's full_fingerprint (spec Section 2.12)"
        )

    def test_fail_when_no_matching_manifest_in_set(self):
        receipt = _base_anomaly_receipt(parent_receipts=["aaaa" + "0" * 60])
        manifest = self._manifest_receipt_for(_HASH_64)
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=[manifest])
        c = _check(checks, "anomaly_parent_receipts_resolves_to_session_manifest")
        assert c.status == "FAIL"
        assert "do not resolve to a session_manifest" in c.message

    def test_pass_when_parent_resolves(self):
        manifest_fp = "e" * 64
        receipt = _base_anomaly_receipt(parent_receipts=[manifest_fp])
        manifest = self._manifest_receipt_for(manifest_fp)
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=[manifest, receipt])
        c = _check(checks, "anomaly_parent_receipts_resolves_to_session_manifest")
        assert c.status == "PASS"


# ===========================================================================
# Check 12: anomaly_attempted_capability_in_parent_suppressed_or_absent
# ===========================================================================

class TestAnomalyAttemptedCapabilityInParentSuppressedOrAbsent:
    _MANIFEST_FP = "f" * 64

    def _manifest_with_mcp(self, tools_delivered, tools_suppressed) -> dict:
        surfaces = {
            "mcp": {
                "tools_delivered": sorted(tools_delivered),
                "tools_suppressed": sorted(tools_suppressed),
                "suppression_reasons": {t: "cannot_execute" for t in tools_suppressed},
            }
        }
        r = _base_receipt(manifest_ext=_base_manifest_ext(surfaces=surfaces))
        r["full_fingerprint"] = self._MANIFEST_FP
        return r

    def _anomaly(self, tool: str) -> dict:
        return _base_anomaly_receipt(
            parent_receipts=[self._MANIFEST_FP],
            attempted_tool=tool,
        )

    def test_warn_in_single_receipt_mode(self):
        receipt = _base_anomaly_receipt()
        checks = verify_invocation_anomaly_receipt(receipt, receipt_set=None)
        c = _check(checks, "anomaly_attempted_capability_in_parent_suppressed_or_absent")
        assert c.status == "WARN"
        assert c.message == "Cross-receipt parent resolution requires receipt set; use verify_receipt_set"

    def test_pass_when_capability_in_suppressed(self):
        manifest = self._manifest_with_mcp(
            tools_delivered=["read_data"],
            tools_suppressed=["delete_all"],
        )
        anomaly = self._anomaly("delete_all")
        checks = verify_invocation_anomaly_receipt(anomaly, receipt_set=[manifest, anomaly])
        c = _check(checks, "anomaly_attempted_capability_in_parent_suppressed_or_absent")
        assert c.status == "PASS"
        assert c.message == (
            "anomaly capability 'delete_all' was suppressed in parent "
            "session_manifest (spec-conformant anti-enumeration signal)"
        )

    def test_fail_when_capability_in_delivered(self):
        manifest = self._manifest_with_mcp(
            tools_delivered=["read_data"],
            tools_suppressed=[],
        )
        anomaly = self._anomaly("read_data")
        checks = verify_invocation_anomaly_receipt(anomaly, receipt_set=[manifest, anomaly])
        c = _check(checks, "anomaly_attempted_capability_in_parent_suppressed_or_absent")
        assert c.status == "FAIL"
        assert c.message == (
            "anomaly receipt for capability 'read_data' that parent "
            "session_manifest declares as DELIVERED -- inconsistent receipt set"
        )

    def test_pass_informational_when_capability_absent(self):
        manifest = self._manifest_with_mcp(
            tools_delivered=["read_data"],
            tools_suppressed=["delete_all"],
        )
        anomaly = self._anomaly("completely_unknown_tool")
        checks = verify_invocation_anomaly_receipt(anomaly, receipt_set=[manifest, anomaly])
        c = _check(checks, "anomaly_attempted_capability_in_parent_suppressed_or_absent")
        assert c.status == "PASS"
        assert "was not declared in constitution at all" in c.message


# ===========================================================================
# Integration: verify_receipt dispatch (cv=9 without event_type skips)
# ===========================================================================

class TestVerifyReceiptDispatch:
    """Verify that verify_receipt() dispatches correctly to manifest checks."""

    def test_legacy_receipt_without_event_type_skips_manifest_checks(self):
        """A receipt lacking event_type (cv=9 / pre-v1.5 legacy) produces no manifest checks."""
        from sanna.verify import verify_receipt, load_schema
        from sanna.middleware import generate_constitution_receipt, build_trace_data
        schema = load_schema()

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
        # Legacy receipt: no event_type
        receipt.pop("event_type", None)

        result = verify_receipt(receipt, schema)
        # No manifest Check objects -- the dispatch was skipped
        manifest_names = {
            "manifest_extension_present", "manifest_version_supported",
            "manifest_has_at_least_one_surface", "manifest_lists_sorted",
            "manifest_suppression_reasons_in_enum", "manifest_no_overlap_delivered_suppressed",
            "manifest_suppression_reasons_keys_match", "manifest_constitution_ref_present",
            "manifest_enforcement_surface_consistent",
        }
        for chk in result.checks:
            assert chk.name not in manifest_names, (
                f"Unexpected manifest check '{chk.name}' on legacy receipt without event_type"
            )


class TestRedactionMarkersCorrect:
    """SAN-406: redaction_markers_correct check coverage.

    Extends SAN-439 scope to com.sanna.anomaly (this ticket absorbed SAN-439).
    Verifier check covers BOTH com.sanna.manifest lists and com.sanna.anomaly
    attempted_* fields under content_mode=redacted/hashes_only.
    """

    def _make_anomaly_receipt(self, content_mode, attempted_value, event_type="invocation_anomaly"):
        field = {
            "invocation_anomaly": "attempted_tool",
            "cli_invocation_anomaly": "attempted_command",
            "api_invocation_anomaly": "attempted_endpoint",
        }[event_type]
        return {
            "event_type": event_type,
            "content_mode": content_mode,
            "extensions": {"com.sanna.anomaly": {field: attempted_value, "suppression_basis": "constitution"}},
        }

    def test_full_mode_no_constraint(self):
        receipt = self._make_anomaly_receipt("full", "rm")
        checks = verify_invocation_anomaly_receipt(receipt)
        names = [c.name for c in checks]
        assert "redaction_markers_correct" not in names

    def test_none_mode_no_constraint(self):
        receipt = self._make_anomaly_receipt(None, "rm")
        checks = verify_invocation_anomaly_receipt(receipt)
        names = [c.name for c in checks]
        assert "redaction_markers_correct" not in names

    def test_redacted_correct_passes(self):
        receipt = self._make_anomaly_receipt("redacted", "<redacted>")
        checks = verify_invocation_anomaly_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "PASS"

    def test_redacted_with_raw_value_fails(self):
        receipt = self._make_anomaly_receipt("redacted", "rm")  # leaks raw
        checks = verify_invocation_anomaly_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "FAIL"

    def test_hashes_only_64_hex_passes(self):
        from sanna.hashing import hash_text
        hashed = hash_text("rm")
        receipt = self._make_anomaly_receipt("hashes_only", hashed)
        checks = verify_invocation_anomaly_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "PASS"

    def test_hashes_only_with_raw_value_fails(self):
        receipt = self._make_anomaly_receipt("hashes_only", "rm")
        checks = verify_invocation_anomaly_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "FAIL"

    def test_cli_anomaly_redacted_correct(self):
        receipt = self._make_anomaly_receipt("redacted", "<redacted>", event_type="cli_invocation_anomaly")
        checks = verify_invocation_anomaly_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "PASS"

    def test_api_anomaly_redacted_correct(self):
        receipt = self._make_anomaly_receipt("redacted", "<redacted>", event_type="api_invocation_anomaly")
        checks = verify_invocation_anomaly_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "PASS"

    def test_manifest_extension_redacted_correct(self):
        receipt = {
            "event_type": "session_manifest",
            "content_mode": "redacted",
            "extensions": {
                "com.sanna.manifest": {
                    "surfaces": {
                        "cli": {
                            "tools_delivered": ["<redacted>"],
                            "tools_suppressed": ["<redacted>", "<redacted>"],
                            "aggregate_suppression_reasons": ["constitution", "constitution"],
                        }
                    }
                }
            },
        }
        checks = verify_session_manifest_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "PASS"

    def test_manifest_extension_redacted_with_raw_value_fails(self):
        receipt = {
            "event_type": "session_manifest",
            "content_mode": "redacted",
            "extensions": {
                "com.sanna.manifest": {
                    "surfaces": {
                        "cli": {
                            "tools_delivered": ["bash"],  # raw leaks
                            "tools_suppressed": [],
                        }
                    }
                }
            },
        }
        checks = verify_session_manifest_receipt(receipt)
        marker_check = next(c for c in checks if c.name == "redaction_markers_correct")
        assert marker_check.status == "FAIL"

    def test_redaction_check_runs_without_receipt_set(self):
        """SAN-406 placement: marker check runs in verify_invocation_anomaly_receipt
        BEFORE the receipt_set=None early-return branch. This regression test
        guards the placement (Phase 3.3 of SAN-406 PR 1)."""
        receipt = self._make_anomaly_receipt("redacted", "rm")  # mode set + raw value
        # No receipt_set passed -> early-return branch fires for cross-receipt
        # checks (11, 12) but the redaction marker check MUST still run.
        checks = verify_invocation_anomaly_receipt(receipt)
        names = [c.name for c in checks]
        assert "redaction_markers_correct" in names, (
            "redaction_markers_correct must run before receipt_set early-return; "
            "found checks: " + ", ".join(names)
        )
