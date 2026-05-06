"""SAN-485: consume cross-SDK bundle-trust-vectors fixture from sanna-protocol.

The fixture (added to sanna-protocol in SAN-403 PR 3 of 3 at commit 6795979) is the
load-bearing cross-SDK conformance contract for the bundle verifier trust anchor. Both
the Python SDK (this file) and the TypeScript SDK (sanna-ts under SAN-486) MUST produce
verdict matches for every vector.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from sanna.bundle import verify_bundle


VECTORS_PATH = Path("spec/fixtures/bundle-trust-vectors.json")

# Bidirectional contract: SDK locks down the expected vector ID set. If sanna-protocol
# later adds, renames, or removes a vector, this set goes stale and the
# test_fixture_vector_ids_match_expected_set canary fires. Update both sides
# (this list and the spec) under the same SAN ticket.
EXPECTED_VECTOR_IDS = [
    "genuine_no_anchor",
    "genuine_anchor_match",
    "genuine_anchor_excluding",
    "genuine_empty_anchor_fails_closed",
    "forged_no_anchor_self_consistent",
    "forged_anchored_genuine_only_caught",
    "forged_anchored_attacker_passes_sanity",
]


def _load_vectors() -> dict:
    if not VECTORS_PATH.exists():
        pytest.skip(f"Vectors file not found at {VECTORS_PATH}; spec submodule may be uninitialized")
    return json.loads(VECTORS_PATH.read_text())


def test_fixture_file_exists():
    """Hard canary: the fixture file must be present (CI invariant; submodule init).

    This is the only test in this module that does NOT skip on missing file. In CI
    (submodules: recursive in workflow) the file IS present; if this test fails, CI
    is misconfigured or the submodule pin is broken. In local dev without submodule
    init, this test fails too -- run `git submodule update --init --recursive`.
    """
    assert VECTORS_PATH.exists(), (
        f"{VECTORS_PATH} not found. Ensure the spec submodule is initialized: "
        f"`git submodule update --init --recursive`. CI workflow uses "
        f"`submodules: recursive` in actions/checkout."
    )


def test_vectors_file_well_formed():
    """The fixture file has the documented top-level fields and 7 vectors."""
    data = _load_vectors()
    assert data["spec_version"] == "1.5"
    assert data["san_ticket"] == "SAN-403"
    assert len(data["vectors"]) == 7
    assert len(data["genuine_key_id"]) == 64
    assert len(data["attacker_key_id"]) == 64
    assert data["genuine_key_id"] != data["attacker_key_id"]
    assert data["bundles"]["genuine"].endswith("genuine.bundle.zip")
    assert data["bundles"]["forged"].endswith("forged.bundle.zip")


def test_fixture_vector_ids_match_expected_set():
    """Bidirectional contract: spec vector IDs match SDK's known set exactly.

    Catches drift in either direction:
    - Spec adds a vector -> SDK CI fails until EXPECTED_VECTOR_IDS is updated AND a
      corresponding test handler lands.
    - Spec renames/drops a vector -> SDK CI fails clearly with the diff.

    This is governance-load-bearing: the SDK is the consumer of the spec contract,
    and CI failures here are the right place to discover drift, not silently passing.
    """
    data = _load_vectors()
    actual_ids = sorted(v["id"] for v in data["vectors"])
    expected_ids = sorted(EXPECTED_VECTOR_IDS)
    assert actual_ids == expected_ids, (
        f"Vector ID drift: expected {expected_ids}, got {actual_ids}. "
        f"If sanna-protocol added/removed/renamed vectors, update EXPECTED_VECTOR_IDS "
        f"in this test under the same SAN ticket as the spec change."
    )


def test_genuine_bundle_internally_references_genuine_key_id():
    """Sanity: the genuine bundle's pubkey path and receipt sig key_id match genuine_key_id."""
    data = _load_vectors()
    bundle_path = Path("spec") / data["bundles"]["genuine"]
    with zipfile.ZipFile(bundle_path) as z:
        receipt = json.loads(z.read("receipt.json"))
        assert receipt["receipt_signature"]["key_id"] == data["genuine_key_id"]
        pub_entries = [n for n in z.namelist() if n.startswith("public_keys/") and n.endswith(".pub")]
        assert len(pub_entries) == 1
        assert data["genuine_key_id"] in pub_entries[0]


def test_forged_bundle_internally_references_attacker_key_id():
    """Sanity: the forged bundle's pubkey path and receipt sig key_id match attacker_key_id."""
    data = _load_vectors()
    bundle_path = Path("spec") / data["bundles"]["forged"]
    with zipfile.ZipFile(bundle_path) as z:
        receipt = json.loads(z.read("receipt.json"))
        assert receipt["receipt_signature"]["key_id"] == data["attacker_key_id"]
        pub_entries = [n for n in z.namelist() if n.startswith("public_keys/") and n.endswith(".pub")]
        assert len(pub_entries) == 1
        assert data["attacker_key_id"] in pub_entries[0]


@pytest.mark.parametrize("vector_id", EXPECTED_VECTOR_IDS)
def test_vector(vector_id: str):
    """Each cross-SDK vector: verify_bundle produces the expected (valid, trust_anchored).

    Parametrized over EXPECTED_VECTOR_IDS (constant); pytest always generates 7 test
    cases regardless of fixture file presence. If the fixture is missing,
    _load_vectors() pytest.skip()s the case; in CI the fixture IS present.
    """
    data = _load_vectors()
    matching = [v for v in data["vectors"] if v["id"] == vector_id]
    assert matching, (
        f"Vector '{vector_id}' missing from fixture; the test_fixture_vector_ids_"
        f"match_expected_set canary should have caught this earlier"
    )
    vector = matching[0]
    bundle_path = Path("spec") / data["bundles"][vector["bundle"]]

    if vector["trusted_key_ids"] is None:
        trusted = None
    else:
        trusted = set(vector["trusted_key_ids"])

    result = verify_bundle(str(bundle_path), trusted_key_ids=trusted)

    assert result.valid == vector["expect"]["valid"], (
        f"vector {vector_id}: valid mismatch -- expected {vector['expect']['valid']}, "
        f"got {result.valid}; failing checks: "
        f"{[(c.name, c.detail) for c in result.checks if not c.passed]}"
    )
    assert result.trust_anchored == vector["expect"]["trust_anchored"], (
        f"vector {vector_id}: trust_anchored mismatch -- expected "
        f"{vector['expect']['trust_anchored']}, got {result.trust_anchored}"
    )
