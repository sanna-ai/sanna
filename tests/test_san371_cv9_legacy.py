"""SAN-371: cv=9 receipts emit CV9_LEGACY-prefixed informational warning.

Receipts at cv=9 are valid (verifier returns valid=True) but the warnings list
contains a string starting with 'CV9_LEGACY:' to signal partial R6 conformance.
"""
import json
from pathlib import Path

import pytest

from sanna.receipt import generate_receipt, receipt_to_dict
from sanna.verify import verify_receipt, load_schema


SCHEMA = load_schema()


def _trace():
    return {
        "correlation_id": "san-371-cv9-test",
        "observations": [],
        "output": {"final_answer": "test"},
        "input": "",
    }


def test_cv9_receipt_emits_cv9_legacy_warning():
    """cv=9 emission via library middleware -> verifier emits CV9_LEGACY warning."""
    receipt = generate_receipt(
        _trace(), enforcement_surface="middleware", invariants_scope="full"
    )
    d = receipt_to_dict(receipt)
    assert d["checks_version"] == "9"

    result = verify_receipt(d, SCHEMA)
    assert result.valid, result.errors
    legacy_warnings = [w for w in result.warnings if w.startswith("CV9_LEGACY:")]
    assert len(legacy_warnings) == 1, (
        f"Expected exactly one CV9_LEGACY warning, got {len(legacy_warnings)}: "
        f"{result.warnings}"
    )


def test_cv10_receipt_does_not_emit_cv9_legacy_warning():
    """cv=10 emission -> verifier does NOT emit CV9_LEGACY warning."""
    ai = {"agent_session_id": "san-371-cv10-test"}
    receipt = generate_receipt(
        _trace(),
        agent_identity=ai,
        enforcement_surface="gateway",
        invariants_scope="full",
    )
    d = receipt_to_dict(receipt)
    assert d["checks_version"] == "10"

    result = verify_receipt(d, SCHEMA)
    assert result.valid, result.errors
    legacy_warnings = [w for w in result.warnings if w.startswith("CV9_LEGACY:")]
    assert len(legacy_warnings) == 0, (
        f"Expected no CV9_LEGACY warning on cv=10 receipt, got: {legacy_warnings}"
    )


def test_cv9_archive_fixture_emits_cv9_legacy_warning():
    """Pre-Prompt-A archive cv=9 fixture verifies cleanly and emits CV9_LEGACY."""
    archive = json.loads(
        Path("spec/fixtures/receipts/archive/v1.4/full-featured.json").read_text()
    )
    assert archive["checks_version"] == "9"

    result = verify_receipt(archive, SCHEMA)
    assert result.valid, result.errors
    legacy_warnings = [w for w in result.warnings if w.startswith("CV9_LEGACY:")]
    assert len(legacy_warnings) == 1, result.warnings
