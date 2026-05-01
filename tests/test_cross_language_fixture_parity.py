"""Cross-language fixture parity: Python SDK must recompute spec/fixtures fingerprints.

This file is the Python side of the cross-SDK parity contract. Prompt C (sanna-ts)
adds the TS mirror. Together they prove the two SDKs agree on fingerprint computation.
"""
import json
from pathlib import Path

import pytest


def _load_fixture(name: str) -> dict:
    path = Path("spec/fixtures/receipts") / name
    if not path.exists():
        pytest.skip(f"Fixture not found: {path}")
    return json.loads(path.read_text())


def test_full_featured_cv10_fingerprint_parity():
    """Python verifier recomputes full-featured.json (cv=10) fingerprint byte-equal."""
    from sanna.verify import verify_receipt, load_schema, _verify_fingerprint_v013

    fixture = _load_fixture("full-featured.json")
    assert fixture.get("checks_version") == "10", "Fixture must be cv=10 (post-Prompt-A)"
    assert fixture.get("agent_identity"), "Fixture must have agent_identity"

    matches, computed_short, expected_short = _verify_fingerprint_v013(fixture)
    assert matches, (
        f"Fingerprint mismatch: computed={computed_short!r} expected={expected_short!r}"
    )

    expected_full = fixture.get("full_fingerprint", "")
    if expected_full:
        from sanna.hashing import hash_text
        from sanna.verify import _verify_fingerprint_v013
        matches2, short2, _ = _verify_fingerprint_v013(fixture)
        assert matches2

    result = verify_receipt(fixture, load_schema())
    assert result.valid, result.errors


def test_pass_single_check_cv10_fingerprint_parity():
    """Python verifier recomputes pass-single-check.json (cv=10) fingerprint byte-equal."""
    from sanna.verify import verify_receipt, load_schema, _verify_fingerprint_v013

    fixture = _load_fixture("pass-single-check.json")
    assert fixture.get("checks_version") == "10", "Fixture must be cv=10 (post-Prompt-A)"

    matches, computed_short, expected_short = _verify_fingerprint_v013(fixture)
    assert matches, (
        f"Fingerprint mismatch: computed={computed_short!r} expected={expected_short!r}"
    )

    result = verify_receipt(fixture, load_schema())
    assert result.valid, result.errors
