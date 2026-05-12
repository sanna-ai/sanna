"""SAN-516 PR 2 of 3: consume cross-SDK gateway-redaction-vectors fixture from sanna-protocol.

The fixture (added to sanna-protocol in SAN-516 PR 1 of 3 at commit
d69977132ba3be4f7a144c8e43a2ff1c65019c91) is the load-bearing cross-SDK
conformance contract for spec section 2.11.1 marker objects. Both the
Python SDK (this file) and the TypeScript SDK (sanna-ts under SAN-516
PR 3 of 3) MUST produce byte-identical output for the marker_vectors /
fix12 / apply_redaction vectors AND reject the verifier_rejection_vectors
with the stable umbrella error code REDACTION_CLAIM_WITHOUT_MARKER.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from sanna.redaction import apply_redaction, _make_redaction_marker, RedactionConfig
from sanna.verify import _check_gateway_redaction_markers_correct

VECTORS_PATH = Path("spec/fixtures/gateway-redaction-vectors.json")

EXPECTED_MARKER_VECTOR_IDS = [
    "marker-ascii-simple",
    "marker-empty-string",
    "marker-multiline-text",
    "marker-unicode-nfc-vs-nfd",
]
EXPECTED_FIX12_VECTOR_IDS = [
    "fix12-pre-existing-marker-simple",
]
EXPECTED_APPLY_REDACTION_VECTOR_IDS = [
    "apply-arguments-only",
    "apply-result-text-only",
    "apply-default-both-fields",
    "apply-disabled-no-op",
    "apply-empty-content",
]
EXPECTED_VERIFIER_REJECTION_VECTOR_IDS = [
    "reject-content-mode-redacted-no-markers",
    "reject-marker-missing-original-hash",
    "reject-content-mode-full-with-markers",
]


def _load_vectors() -> dict:
    if not VECTORS_PATH.exists():
        pytest.skip(f"Vectors file not found at {VECTORS_PATH}; spec submodule may be uninitialized")
    return json.loads(VECTORS_PATH.read_text())


def test_fixture_file_exists():
    """Hard canary: the fixture file MUST be present. CI sets submodules: recursive."""
    assert VECTORS_PATH.exists(), (
        f"Fixture file missing at {VECTORS_PATH}. "
        f"Run `git submodule update --init --recursive` if testing locally."
    )


def test_fixture_vector_ids_match_expected_sets():
    """Canary: if sanna-protocol adds/renames/removes a vector, update both sides under the same SAN ticket."""
    data = _load_vectors()
    assert [v["vector_id"] for v in data["marker_vectors"]] == EXPECTED_MARKER_VECTOR_IDS
    assert [v["vector_id"] for v in data["fix12_injection_guard_vectors"]] == EXPECTED_FIX12_VECTOR_IDS
    assert [v["vector_id"] for v in data["apply_redaction_vectors"]] == EXPECTED_APPLY_REDACTION_VECTOR_IDS
    assert [v["vector_id"] for v in data["verifier_rejection_vectors"]] == EXPECTED_VERIFIER_REJECTION_VECTOR_IDS


@pytest.mark.parametrize("vector_id", EXPECTED_MARKER_VECTOR_IDS)
def test_marker_vector(vector_id):
    """Cross-SDK byte parity: _make_redaction_marker MUST produce the fixture's expected marker."""
    data = _load_vectors()
    vector = next(v for v in data["marker_vectors"] if v["vector_id"] == vector_id)

    if vector_id == "marker-unicode-nfc-vs-nfd":
        marker_nfc = _make_redaction_marker(vector["input_nfc"])
        marker_nfd = _make_redaction_marker(vector["input_nfd"])
        expected = vector["expected_marker_for_both"]
        assert marker_nfc == expected
        assert marker_nfd == expected
        assert marker_nfc == marker_nfd
    else:
        marker = _make_redaction_marker(vector["input"])
        assert marker == vector["expected_marker"], f"Marker mismatch for {vector_id}"


@pytest.mark.parametrize("vector_id", EXPECTED_FIX12_VECTOR_IDS)
def test_fix12_injection_guard_vector(vector_id):
    """spec section 2.11.4 FIX-12: pre-existing marker dict re-redacted via Python json.dumps(sort_keys=True)."""
    data = _load_vectors()
    vector = next(v for v in data["fix12_injection_guard_vectors"] if v["vector_id"] == vector_id)

    receipt = {
        "inputs": {"context": copy.deepcopy(vector["pre_existing_marker_input"])},
        "outputs": {"response": "raw"},
    }
    config = RedactionConfig(enabled=True, mode="hash_only", fields=["arguments"])
    out_receipt, redacted_paths = apply_redaction(receipt, config)

    expected_marker = vector["expected_marker_after_re_redaction"]
    assert out_receipt["inputs"]["context"] == expected_marker
    assert "inputs.context" in redacted_paths


@pytest.mark.parametrize("vector_id", EXPECTED_APPLY_REDACTION_VECTOR_IDS)
def test_apply_redaction_vector(vector_id):
    """apply_redaction wrapper MUST produce the fixture's expected post-redaction state."""
    data = _load_vectors()
    vector = next(v for v in data["apply_redaction_vectors"] if v["vector_id"] == vector_id)

    config_dict = vector["redaction_config"]
    config = RedactionConfig(
        enabled=config_dict["enabled"],
        mode=config_dict.get("mode", "hash_only"),
        fields=config_dict.get("fields", ["arguments", "result_text"]),
    )
    input_receipt = copy.deepcopy(vector["input_receipt_partial"])
    out_receipt, redacted_paths = apply_redaction(input_receipt, config)

    expected_ctx = vector["expected_inputs_context_after_redaction"]
    expected_resp = vector["expected_outputs_response_after_redaction"]
    expected_paths = vector["expected_redacted_fields"]

    assert out_receipt["inputs"]["context"] == expected_ctx, f"inputs.context mismatch for {vector_id}"
    assert out_receipt["outputs"]["response"] == expected_resp, f"outputs.response mismatch for {vector_id}"
    assert sorted(redacted_paths) == sorted(expected_paths), f"redacted_paths mismatch for {vector_id}"


@pytest.mark.parametrize("vector_id", EXPECTED_VERIFIER_REJECTION_VECTOR_IDS)
def test_verifier_rejection_vector(vector_id):
    """Verifier MUST reject incomplete-state receipts with the stable umbrella error code."""
    data = _load_vectors()
    vector = next(v for v in data["verifier_rejection_vectors"] if v["vector_id"] == vector_id)

    receipt = copy.deepcopy(vector["input_receipt_partial"])
    errors = _check_gateway_redaction_markers_correct(receipt)

    assert len(errors) > 0, f"Verifier should have rejected {vector_id} but returned no errors"
    expected_code = vector["expected_error_code"]
    assert any(expected_code in err for err in errors), (
        f"Verifier rejected {vector_id} but errors do not contain stable code '{expected_code}'. "
        f"Got: {errors}"
    )
