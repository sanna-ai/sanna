"""SAN-406 PR 4: consume cross-SDK redaction-vectors fixture from sanna-protocol.

The fixture (added to sanna-protocol in SAN-406 PR 3 at commit 95e87e5) is the
load-bearing cross-SDK conformance contract for com.sanna.anomaly extension
field-level redaction (spec Section 2.22.5). Both Python (this file) and
TypeScript (sanna-ts under SAN-406 PR 5) MUST produce verdict matches for every
vector.

These tests are INDEPENDENT of SAN-487. They call the helper + verifier
DIRECTLY without traversing the interceptor's emission path. The 6 end-to-end
interceptor tests in TestCliAnomalyRedaction + TestHttpAnomalyRedaction (PR 1)
remain skipped with their existing SAN-487 cite.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sanna.anomaly import redact_attempted_field
from sanna.verify_manifest import verify_invocation_anomaly_receipt


VECTORS_PATH = Path("spec/fixtures/redaction-vectors.json")

# Bidirectional contract: SDK locks down the expected vector ID sets. If sanna-protocol
# later adds, renames, or removes a vector, this set goes stale and the
# test_fixture_vector_ids_match_expected_sets canary fires. Update both sides
# (these lists and the spec) under the same SAN ticket.
EXPECTED_HELPER_VECTOR_IDS = [
    "helper-cli-full",
    "helper-cli-redacted",
    "helper-cli-hashes-only",
    "helper-mcp-full",
    "helper-mcp-redacted",
    "helper-mcp-hashes-only",
    "helper-http-full",
    "helper-http-redacted",
    "helper-http-hashes-only",
]
EXPECTED_VERIFIER_VECTOR_IDS = [
    "verifier-cli-redacted-leaks-raw",
    "verifier-cli-hashes-only-leaks-raw",
    "verifier-mcp-redacted-leaks-raw",
    "verifier-mcp-hashes-only-leaks-raw",
    "verifier-http-redacted-leaks-raw",
    "verifier-http-hashes-only-leaks-raw",
]


def _load_fixture() -> dict:
    if not VECTORS_PATH.exists():
        pytest.skip(f"Vectors file not found at {VECTORS_PATH}; spec submodule may be uninitialized")
    return json.loads(VECTORS_PATH.read_text())


def _build_anomaly_receipt(event_type: str, field_name: str, content_mode: str, field_value: str) -> dict:
    """Minimal receipt structure exercising the redaction_markers_correct check.

    The receipt has only the fields the verifier's marker-check entry path
    requires:
    - event_type: read by Check 10 (anomaly_event_type_in_valid_set) and by
      ANOMALY_FIELD_BY_EVENT_TYPE in the marker check helper.
    - content_mode: read by the marker check (early-return on full/null;
      otherwise validates markers).
    - extensions["com.sanna.anomaly"][field_name]: the value the marker
      check inspects.
    - extensions["com.sanna.anomaly"]["suppression_basis"]: required by the
      anomaly extension schema; included for forward-compat even though the
      marker check does not read it.

    No receipt_signature, fingerprint, correlation_id, etc. The verifier's
    invocation-anomaly entry point does NOT do full schema validation; it
    runs Check 10 + the marker check + Checks 11/12 (cross-receipt). With
    receipt_set=None, Checks 11/12 emit WARN early-return; the marker check
    fires before the early-return per PR 1 placement.
    """
    return {
        "event_type": event_type,
        "content_mode": content_mode,
        "extensions": {
            "com.sanna.anomaly": {
                field_name: field_value,
                "suppression_basis": "constitution",
            },
        },
    }


def test_fixture_file_exists():
    """Hard canary: the fixture file MUST be present (CI invariant; submodule init).

    This is the only test in this module that does NOT skip on missing file. In CI
    (submodules: recursive in workflow) the file IS present; if this test fails, CI
    is misconfigured or the submodule pin is broken.
    """
    assert VECTORS_PATH.exists(), (
        f"{VECTORS_PATH} not found. Ensure the spec submodule is initialized: "
        f"`git submodule update --init --recursive`. CI workflow uses "
        f"`submodules: recursive` in actions/checkout."
    )


def test_fixture_well_formed():
    """The fixture has the documented top-level fields and counts."""
    d = _load_fixture()
    assert d["spec_section"] == "2.22.5"
    assert d["san_ticket"] == "SAN-406"
    assert d["expected_check_name"] == "redaction_markers_correct"  # cross-SDK Check.name parity
    assert len(d["helper_vectors"]) == 9
    assert len(d["verifier_vectors"]) == 6


def test_fixture_vector_ids_match_expected_sets():
    """Bidirectional contract: spec vector IDs match SDK's known sets exactly.

    Catches drift in either direction (spec adds/renames/drops; SDK falls behind).
    """
    d = _load_fixture()
    actual_helper = sorted(v["id"] for v in d["helper_vectors"])
    expected_helper = sorted(EXPECTED_HELPER_VECTOR_IDS)
    assert actual_helper == expected_helper, (
        f"helper_vectors ID drift: expected {expected_helper}, got {actual_helper}. "
        f"If sanna-protocol added/removed/renamed vectors, update EXPECTED_HELPER_VECTOR_IDS."
    )
    actual_verifier = sorted(v["id"] for v in d["verifier_vectors"])
    expected_verifier = sorted(EXPECTED_VERIFIER_VECTOR_IDS)
    assert actual_verifier == expected_verifier, (
        f"verifier_vectors ID drift: expected {expected_verifier}, got {actual_verifier}."
    )


@pytest.mark.parametrize("vector_id", EXPECTED_HELPER_VECTOR_IDS)
def test_helper_vector(vector_id: str):
    """Each helper_vector: redact_attempted_field(input, content_mode) == expected.

    Cross-SDK byte-equal anchor: hashes_only-mode vectors assert the SHA-256 hex
    matches the canonical pasted value in the fixture (which Phase 2 of PR 3
    verified equals hashlib.sha256(input.encode("utf-8")).hexdigest() for ASCII
    inputs). PR 5 will re-verify the same hex via TypeScript's hashContent.
    """
    d = _load_fixture()
    matching = [v for v in d["helper_vectors"] if v["id"] == vector_id]
    assert matching, f"Vector '{vector_id}' missing from fixture (canary should have caught)"
    vector = matching[0]
    result = redact_attempted_field(vector["input"], vector["content_mode"])
    assert result == vector["expected"], (
        f"helper {vector_id}: input={vector['input']!r}, content_mode={vector['content_mode']!r}, "
        f"expected={vector['expected']!r}, got={result!r}"
    )


@pytest.mark.parametrize("vector_id", EXPECTED_VERIFIER_VECTOR_IDS)
def test_verifier_vector_negative(vector_id: str):
    """Each verifier_vector (NEGATIVE case): receipt with raw value under
    redacted/hashes_only mode -> redaction_markers_correct check FAILS.
    """
    d = _load_fixture()
    matching = [v for v in d["verifier_vectors"] if v["id"] == vector_id]
    assert matching, f"Vector '{vector_id}' missing from fixture (canary should have caught)"
    vector = matching[0]
    receipt = _build_anomaly_receipt(
        event_type=vector["event_type"],
        field_name=vector["field_name"],
        content_mode=vector["content_mode"],
        field_value=vector["field_value"],
    )
    checks = verify_invocation_anomaly_receipt(receipt)
    marker_check = next((c for c in checks if c.name == d["expected_check_name"]), None)
    assert marker_check is not None, (
        f"verifier {vector_id}: marker check ({d['expected_check_name']!r}) not emitted; "
        f"actual checks: {[c.name for c in checks]}"
    )
    assert marker_check.status == vector["expected_check_status"], (
        f"verifier {vector_id}: expected status={vector['expected_check_status']!r}, "
        f"got {marker_check.status!r}; detail={marker_check.message!r}"
    )


@pytest.mark.parametrize("vector_id", EXPECTED_HELPER_VECTOR_IDS)
def test_helper_vector_positive_verifier_derivation(vector_id: str):
    """Derived positive verifier case: each non-full helper_vector's `expected` value,
    when used as a receipt's field_value with the same content_mode, MUST produce a
    marker check with status=PASS. Full mode emits NO marker check (verifier returns
    early on full/null content_mode).

    This test materializes the derivation rule documented in the fixture's
    `verifier_vectors_doc` field. Together with test_verifier_vector_negative,
    coverage is complete: every (mode, surface, value) tuple has an explicit
    assertion.
    """
    d = _load_fixture()
    matching = [v for v in d["helper_vectors"] if v["id"] == vector_id]
    vector = matching[0]
    receipt = _build_anomaly_receipt(
        event_type=vector["event_type"],
        field_name=vector["field_name"],
        content_mode=vector["content_mode"],
        field_value=vector["expected"],  # the COMPLIANT value per helper output
    )
    checks = verify_invocation_anomaly_receipt(receipt)
    marker_check = next((c for c in checks if c.name == d["expected_check_name"]), None)
    if vector["content_mode"] == "full":
        # Full mode: verifier emits NO marker check (returns early before the check).
        assert marker_check is None, (
            f"helper {vector_id} (full mode): marker check should NOT be emitted; "
            f"got {marker_check}"
        )
    else:
        assert marker_check is not None, (
            f"helper {vector_id} ({vector['content_mode']} mode): marker check expected"
        )
        assert marker_check.status == "PASS", (
            f"helper {vector_id} ({vector['content_mode']} mode): expected PASS, "
            f"got {marker_check.status} (detail: {marker_check.message})"
        )
